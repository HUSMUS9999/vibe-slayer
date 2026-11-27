//! `vs-3d`: Spec-compliant glTF 2.0 scene ingestion, server-side PBR rendering, anti-3DGS
//! defense, and multi-SKU asset catalog (`#![forbid(unsafe_code)]`).
//!
//! Hardened v2 engine:
//! - Full recursive glTF 2.0 scene-graph TRS transforms with negative-determinant winding flips,
//!   singular-matrix guards, deduplicated root traversal, and `TriangleStrip`/`TriangleFan` support.
//! - Multi-material Khronos metallic-roughness PBR with IEC 61966-2-1 sRGB-to-linear texture
//!   decoding, `baseColorTexture`, `metallicRoughnessTexture`, `emissiveTexture`, and `double_sided`.
//! - `NaN`/`±Infinity`-hardened camera, bounding-box (`f64`), rasterizer, and texture sampler.
//! - Smooth continuous session-seeded harmonic anti-3DGS camera-intrinsics perturbation with
//!   sign-verified off-axis target compensation + 192-bin equal-area spherical view-coverage budget.
//! - Bounded multi-SKU `AssetCatalog` (LRU-evicted scenes & cached SSR posters).

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::f32::consts::PI;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use glam::{Mat3, Mat4, Quat, Vec2, Vec3, Vec4};
use image::codecs::jpeg::JpegEncoder;
use image::ExtendedColorType;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vs_crypto::{hmac_sha256_parts, SecretKey32};
use vs_watermark::{embed_frame_rgb, EmbedConfig, WatermarkEngine};

#[derive(Debug, Error)]
pub enum ThreeDError {
    #[error("failed to parse glTF/GLB asset: {0}")]
    Gltf(String),
    #[error("asset '{0}' not found in catalog")]
    AssetNotFound(String),
    #[error("view coverage budget exceeded ({visited}/{max_bins} spherical bins)")]
    ViewBudgetExceeded { visited: usize, max_bins: usize },
    #[error("invalid camera parameters")]
    InvalidCamera,
    #[error("image encoding failed: {0}")]
    Encode(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// 256-entry IEC 61966-2-1 sRGB byte -> linear f32 lookup table.
fn srgb_to_linear_byte(b: u8) -> f32 {
    let s = (b as f32) / 255.0;
    if s <= 0.04045 {
        s / 12.92
    } else {
        ((s + 0.055) / 1.055).powf(2.4)
    }
}

#[derive(Debug, Clone)]
pub struct Texture2D {
    pub width: u32,
    pub height: u32,
    /// RGBA8 pixels.
    pub rgba: Vec<u8>,
}

impl Texture2D {
    fn sample_inner(&self, u: f32, v: f32, decode_srgb: bool) -> Vec4 {
        let w = self.width as usize;
        let h = self.height as usize;
        let needed = match w.checked_mul(h).and_then(|n| n.checked_mul(4)) {
            Some(n) if w > 0 && h > 0 && self.rgba.len() >= n => n,
            _ => return Vec4::ONE,
        };
        let _ = needed;
        let u = if u.is_finite() { u.rem_euclid(1.0) } else { 0.0 };
        let v = if v.is_finite() { v.rem_euclid(1.0) } else { 0.0 };
        let fx = (u as f64) * (w as f64) - 0.5;
        let fy = (v as f64) * (h as f64) - 0.5;
        let x0 = (fx.floor() as i64).rem_euclid(w as i64) as usize;
        let y0 = (fy.floor() as i64).rem_euclid(h as i64) as usize;
        let x1 = (x0 + 1) % w;
        let y1 = (y0 + 1) % h;
        let tx = (fx - fx.floor()) as f32;
        let ty = (fy - fy.floor()) as f32;

        let p = |x: usize, y: usize| -> Vec4 {
            let i = (y * w + x) * 4;
            if decode_srgb {
                Vec4::new(
                    srgb_to_linear_byte(self.rgba[i]),
                    srgb_to_linear_byte(self.rgba[i + 1]),
                    srgb_to_linear_byte(self.rgba[i + 2]),
                    self.rgba[i + 3] as f32 / 255.0,
                )
            } else {
                Vec4::new(
                    self.rgba[i] as f32 / 255.0,
                    self.rgba[i + 1] as f32 / 255.0,
                    self.rgba[i + 2] as f32 / 255.0,
                    self.rgba[i + 3] as f32 / 255.0,
                )
            }
        };
        let c00 = p(x0, y0);
        let c10 = p(x1, y0);
        let c01 = p(x0, y1);
        let c11 = p(x1, y1);
        c00.lerp(c10, tx).lerp(c01.lerp(c11, tx), ty)
    }

    /// Bilinear filtered RGBA sample (linear values, e.g. metallicRoughnessTexture).
    #[inline]
    pub fn sample_bilinear(&self, u: f32, v: f32) -> Vec4 {
        self.sample_inner(u, v, false)
    }

    /// Bilinear filtered RGBA sample with sRGB->linear decoding on RGB channels (`baseColor`/`emissive`).
    #[inline]
    pub fn sample_bilinear_srgb(&self, u: f32, v: f32) -> Vec4 {
        self.sample_inner(u, v, true)
    }
}

#[derive(Debug, Clone)]
pub struct MaterialPbr {
    pub base_color_factor: Vec4,
    pub metallic_factor: f32,
    pub roughness_factor: f32,
    pub emissive_factor: Vec3,
    pub base_color_texture: Option<usize>,
    pub metallic_roughness_texture: Option<usize>,
    pub emissive_texture: Option<usize>,
    pub double_sided: bool,
}

impl Default for MaterialPbr {
    fn default() -> Self {
        Self {
            base_color_factor: Vec4::new(0.82, 0.84, 0.88, 1.0),
            metallic_factor: 0.15,
            roughness_factor: 0.45,
            emissive_factor: Vec3::ZERO,
            base_color_texture: None,
            metallic_roughness_texture: None,
            emissive_texture: None,
            double_sided: true,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Triangle {
    pub pos: [Vec3; 3],
    pub norm: [Vec3; 3],
    pub uv: [Vec2; 3],
    pub material_idx: usize,
}

/// Normalized, scene-graph-resolved glTF 2.0 3D asset ready for server-side rendering.
#[derive(Debug, Clone)]
pub struct Scene3D {
    pub id: String,
    pub triangles: Vec<Triangle>,
    pub materials: Vec<MaterialPbr>,
    pub textures: Vec<Texture2D>,
    pub bbox_min: Vec3,
    pub bbox_max: Vec3,
}

impl Scene3D {
    /// Load any glTF 2.0 `.glb` binary from bytes with full recursive node transforms,
    /// negative-determinant winding correction, multi-material PBR textures, and `f64`
    /// NaN-safe unit-sphere normalization.
    pub fn from_glb_bytes(id: impl Into<String>, glb_bytes: &[u8]) -> Result<Self, ThreeDError> {
        let (doc, buffers, images) =
            gltf::import_slice(glb_bytes).map_err(|e| ThreeDError::Gltf(e.to_string()))?;

        let mut textures = Vec::with_capacity(images.len());
        for img in &images {
            if img.width == 0 || img.height == 0 {
                textures.push(Texture2D {
                    width: 1,
                    height: 1,
                    rgba: vec![200, 200, 200, 255],
                });
                continue;
            }
            let px_count = (img.width as usize)
                .checked_mul(img.height as usize)
                .ok_or_else(|| ThreeDError::Gltf("texture dimensions overflow".into()))?;
            let rgba_bytes = px_count
                .checked_mul(4)
                .ok_or_else(|| ThreeDError::Gltf("texture byte size overflow".into()))?;
            if rgba_bytes > 64 * 1024 * 1024 {
                return Err(ThreeDError::Gltf("texture exceeds 64 MiB limit".into()));
            }
            let rgba = match img.format {
                gltf::image::Format::R8G8B8A8 if img.pixels.len() >= rgba_bytes => {
                    img.pixels[..rgba_bytes].to_vec()
                }
                gltf::image::Format::R8G8B8 if img.pixels.len() >= px_count * 3 => {
                    let mut out = Vec::with_capacity(rgba_bytes);
                    for c in img.pixels[..px_count * 3].as_chunks::<3>().0 {
                        out.extend_from_slice(&[c[0], c[1], c[2], 255]);
                    }
                    out
                }
                gltf::image::Format::R8 if img.pixels.len() >= px_count => {
                    let mut out = Vec::with_capacity(rgba_bytes);
                    for &v in &img.pixels[..px_count] {
                        out.extend_from_slice(&[v, v, v, 255]);
                    }
                    out
                }
                gltf::image::Format::R8G8 if img.pixels.len() >= px_count * 2 => {
                    let mut out = Vec::with_capacity(rgba_bytes);
                    for c in img.pixels[..px_count * 2].as_chunks::<2>().0 {
                        out.extend_from_slice(&[c[0], c[0], c[0], c[1]]);
                    }
                    out
                }
                _ => vec![200u8; rgba_bytes],
            };
            textures.push(Texture2D {
                width: img.width,
                height: img.height,
                rgba,
            });
        }

        let mut materials: Vec<MaterialPbr> = doc
            .materials()
            .map(|m| {
                let pbr = m.pbr_metallic_roughness();
                MaterialPbr {
                    base_color_factor: Vec4::from_array(pbr.base_color_factor()),
                    metallic_factor: pbr.metallic_factor().clamp(0.0, 1.0),
                    roughness_factor: pbr.roughness_factor().clamp(0.04, 1.0),
                    emissive_factor: Vec3::from_array(m.emissive_factor()),
                    base_color_texture: pbr
                        .base_color_texture()
                        .map(|t| t.texture().source().index()),
                    metallic_roughness_texture: pbr
                        .metallic_roughness_texture()
                        .map(|t| t.texture().source().index()),
                    emissive_texture: m
                        .emissive_texture()
                        .map(|t| t.texture().source().index()),
                    double_sided: m.double_sided(),
                }
            })
            .collect();
        let default_mat_idx = materials.len();
        materials.push(MaterialPbr::default());

        let mut triangles = Vec::new();

        fn node_local_mat(node: &gltf::Node) -> Mat4 {
            match node.transform() {
                gltf::scene::Transform::Matrix { matrix } => Mat4::from_cols_array_2d(&matrix),
                gltf::scene::Transform::Decomposed {
                    translation,
                    rotation,
                    scale,
                } => {
                    let q = Quat::from_xyzw(rotation[0], rotation[1], rotation[2], rotation[3]);
                    let len_sq = q.length_squared();
                    let qn = if q.is_finite() && len_sq.is_finite() && len_sq > 1e-12 {
                        q.normalize()
                    } else {
                        Quat::IDENTITY
                    };
                    Mat4::from_scale_rotation_translation(
                        Vec3::from_array(scale),
                        qn,
                        Vec3::from_array(translation),
                    )
                }
            }
        }

        fn visit_node(
            node: &gltf::Node,
            parent_world: Mat4,
            buffers: &[gltf::buffer::Data],
            default_mat_idx: usize,
            out: &mut Vec<Triangle>,
        ) {
            let world = parent_world * node_local_mat(node);
            let m3 = Mat3::from_mat4(world);
            let det = m3.determinant();
            if det.is_finite() && det.abs() >= 1e-12 {
                let normal_mat = m3.inverse().transpose();
                let flip_winding = det < 0.0;

                if let Some(mesh) = node.mesh() {
                    for prim in mesh.primitives() {
                        let mode = prim.mode();
                        if !matches!(
                            mode,
                            gltf::mesh::Mode::Triangles
                                | gltf::mesh::Mode::TriangleStrip
                                | gltf::mesh::Mode::TriangleFan
                        ) {
                            continue;
                        }
                        let reader = prim.reader(|b| Some(&buffers[b.index()]));
                        let Some(pos_iter) = reader.read_positions() else {
                            continue;
                        };
                        let positions: Vec<Vec3> = pos_iter.map(Vec3::from_array).collect();
                        let normals: Option<Vec<Vec3>> = reader
                            .read_normals()
                            .map(|it| it.map(Vec3::from_array).collect());
                        let uvs: Vec<Vec2> = reader
                            .read_tex_coords(0)
                            .map(|tc| tc.into_f32().map(Vec2::from_array).collect())
                            .unwrap_or_else(|| vec![Vec2::ZERO; positions.len()]);
                        let raw_indices: Vec<u32> = match reader.read_indices() {
                            Some(ind) => ind.into_u32().collect(),
                            None => (0..positions.len() as u32).collect(),
                        };
                        let mat_idx = prim.material().index().unwrap_or(default_mat_idx);

                        let mut push_tri = |a: u32, b: u32, c: u32| {
                            let (i0, mut i1, mut i2) = (a as usize, b as usize, c as usize);
                            if flip_winding {
                                std::mem::swap(&mut i1, &mut i2);
                            }
                            if i0 >= positions.len()
                                || i1 >= positions.len()
                                || i2 >= positions.len()
                            {
                                return;
                            }
                            let p0 = world.transform_point3(positions[i0]);
                            let p1 = world.transform_point3(positions[i1]);
                            let p2 = world.transform_point3(positions[i2]);
                            if !(p0.is_finite() && p1.is_finite() && p2.is_finite()) {
                                return;
                            }
                            let face_n = (p1 - p0).cross(p2 - p0).normalize_or_zero();
                            let n_at = |idx: usize| -> Vec3 {
                                normals
                                    .as_ref()
                                    .and_then(|ns| ns.get(idx))
                                    .map(|&n| (normal_mat * n).normalize_or_zero())
                                    .filter(|v| v.is_finite() && v.length_squared() > 1e-6)
                                    .unwrap_or(face_n)
                            };
                            let uv_at = |idx: usize| -> Vec2 {
                                let v = uvs.get(idx).copied().unwrap_or(Vec2::ZERO);
                                if v.is_finite() { v } else { Vec2::ZERO }
                            };
                            out.push(Triangle {
                                pos: [p0, p1, p2],
                                norm: [n_at(i0), n_at(i1), n_at(i2)],
                                uv: [uv_at(i0), uv_at(i1), uv_at(i2)],
                                material_idx: mat_idx,
                            });
                        };

                        match mode {
                            gltf::mesh::Mode::Triangles => {
                                for tri in raw_indices.as_chunks::<3>().0 {
                                    push_tri(tri[0], tri[1], tri[2]);
                                }
                            }
                            gltf::mesh::Mode::TriangleStrip => {
                                for i in 0..raw_indices.len().saturating_sub(2) {
                                    if i % 2 == 0 {
                                        push_tri(raw_indices[i], raw_indices[i + 1], raw_indices[i + 2]);
                                    } else {
                                        push_tri(raw_indices[i + 1], raw_indices[i], raw_indices[i + 2]);
                                    }
                                }
                            }
                            gltf::mesh::Mode::TriangleFan => {
                                for i in 1..raw_indices.len().saturating_sub(1) {
                                    push_tri(raw_indices[0], raw_indices[i], raw_indices[i + 1]);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            for child in node.children() {
                visit_node(&child, world, buffers, default_mat_idx, out);
            }
        }

        if let Some(scene) = doc.default_scene().or_else(|| doc.scenes().next()) {
            for root in scene.nodes() {
                visit_node(&root, Mat4::IDENTITY, &buffers, default_mat_idx, &mut triangles);
            }
        } else {
            // Deduplicate root nodes when glTF omits `scenes` array (MED-14)
            let mut children: HashSet<usize> = HashSet::new();
            for n in doc.nodes() {
                for ch in n.children() {
                    children.insert(ch.index());
                }
            }
            for node in doc.nodes() {
                if !children.contains(&node.index()) {
                    visit_node(&node, Mat4::IDENTITY, &buffers, default_mat_idx, &mut triangles);
                }
            }
        }

        if triangles.is_empty() {
            return Err(ThreeDError::Gltf("glTF asset contains 0 valid triangles".into()));
        }

        // Compute bounding box & normalization in f64 to prevent f32 overflow on large coordinates
        let mut bmin = [f64::INFINITY; 3];
        let mut bmax = [f64::NEG_INFINITY; 3];
        for t in &triangles {
            for p in &t.pos {
                for axis in 0..3 {
                    let v = p[axis] as f64;
                    if v < bmin[axis] {
                        bmin[axis] = v;
                    }
                    if v > bmax[axis] {
                        bmax[axis] = v;
                    }
                }
            }
        }
        let center = [
            (bmin[0] + bmax[0]) * 0.5,
            (bmin[1] + bmax[1]) * 0.5,
            (bmin[2] + bmax[2]) * 0.5,
        ];
        let extent = (bmax[0] - bmin[0])
            .max(bmax[1] - bmin[1])
            .max(bmax[2] - bmin[2])
            .max(1e-6);
        let scale = 1.7 / extent;
        if !(scale.is_finite() && center.iter().all(|v| v.is_finite())) {
            return Err(ThreeDError::Gltf("degenerate non-finite scene bounds".into()));
        }

        for t in &mut triangles {
            for p in &mut t.pos {
                *p = Vec3::new(
                    ((p.x as f64 - center[0]) * scale) as f32,
                    ((p.y as f64 - center[1]) * scale) as f32,
                    ((p.z as f64 - center[2]) * scale) as f32,
                );
            }
        }

        let bbox_min = Vec3::new(
            ((bmin[0] - center[0]) * scale) as f32,
            ((bmin[1] - center[1]) * scale) as f32,
            ((bmin[2] - center[2]) * scale) as f32,
        );
        let bbox_max = Vec3::new(
            ((bmax[0] - center[0]) * scale) as f32,
            ((bmax[1] - center[1]) * scale) as f32,
            ((bmax[2] - center[2]) * scale) as f32,
        );

        Ok(Self {
            id: id.into(),
            triangles,
            materials,
            textures,
            bbox_min,
            bbox_max,
        })
    }

    pub fn from_glb_file(id: impl Into<String>, path: &Path) -> Result<Self, ThreeDError> {
        let raw = std::fs::read(path)?;
        Self::from_glb_bytes(id, &raw)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct OrbitCamera {
    pub yaw: f32,
    pub pitch: f32,
    pub zoom: f32,
    pub pan_y: f32,
}

impl Default for OrbitCamera {
    fn default() -> Self {
        Self {
            yaw: 0.45,
            pitch: 0.28,
            zoom: 2.8,
            pan_y: 0.0,
        }
    }
}

impl OrbitCamera {
    pub fn is_finite(self) -> bool {
        self.yaw.is_finite()
            && self.pitch.is_finite()
            && self.zoom.is_finite()
            && self.pan_y.is_finite()
    }

    pub fn clamped(self) -> Self {
        let d = Self::default();
        Self {
            yaw: if self.yaw.is_finite() {
                self.yaw.rem_euclid(2.0 * PI)
            } else {
                d.yaw
            },
            pitch: if self.pitch.is_finite() {
                self.pitch.clamp(-1.35, 1.35)
            } else {
                d.pitch
            },
            zoom: if self.zoom.is_finite() {
                self.zoom.clamp(1.25, 6.5)
            } else {
                d.zoom
            },
            pan_y: if self.pan_y.is_finite() {
                self.pan_y.clamp(-0.8, 0.8)
            } else {
                d.pan_y
            },
        }
    }
}

/// Anti-3DGS / Anti-VGGT defense: smooth continuous compensated camera-intrinsics perturbation
/// and 192-bin equal-area spherical solid-angle view-coverage budget.
pub mod anti_3dgs {
    use super::*;

    #[derive(Debug, Clone, Copy)]
    pub struct PerturbedCamera {
        pub view_proj: Mat4,
        pub eye: Vec3,
        pub key_light_dir: Vec3,
    }

    /// Build a UX-safe compensated perspective matrix with smooth continuous session-seeded
    /// harmonic focal drift (`±4%`), sign-verified compensated off-axis principal-point tilt-shift
    /// (`±2.2%`), and subtle view-dependent specular light-phase drift (zero step jitter).
    pub fn build_perturbed_camera(
        cam: OrbitCamera,
        width: usize,
        height: usize,
        session_seed: &[u8; 32],
        enable_perturbation: bool,
    ) -> PerturbedCamera {
        let cam = cam.clamped();
        let aspect = (width.max(1) as f32) / (height.max(1) as f32);

        // Smooth continuous session-seeded phases (eliminates quantized angle step jitter)
        let h = hmac_sha256_parts(session_seed, &[b"VS3D_HARMONIC_PHASES"]);
        let p0 = (u32::from_le_bytes([h[0], h[1], h[2], h[3]]) as f32) / (u32::MAX as f32) * 2.0 * PI;
        let p1 = (u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as f32) / (u32::MAX as f32) * 2.0 * PI;
        let p2 = (u32::from_le_bytes([h[8], h[9], h[10], h[11]]) as f32) / (u32::MAX as f32) * 2.0 * PI;
        let p3 = (u32::from_le_bytes([h[12], h[13], h[14], h[15]]) as f32) / (u32::MAX as f32) * 2.0 * PI;

        let (fov_y, cx_shift, cy_shift, light_phase) = if enable_perturbation {
            let base_fov = 42.0f32.to_radians();
            let df = 1.0 + 0.04 * (cam.yaw * 2.0 + p0).sin() * (0.75 + 0.25 * (cam.pitch + p1).cos());
            (
                (base_fov / df).clamp(32.0f32.to_radians(), 54.0f32.to_radians()),
                0.022 * (cam.yaw * 3.0 + p1).cos(),
                0.022 * (cam.pitch * 3.0 + p2).sin(),
                0.18 * (cam.yaw * 1.5 + p3).sin(),
            )
        } else {
            (42.0f32.to_radians(), 0.0, 0.0, 0.0)
        };

        let base_tan = (42.0f32.to_radians() * 0.5).tan();
        let cur_tan = (fov_y * 0.5).tan();
        let r = cam.zoom * (base_tan / cur_tan);

        let cp = cam.pitch.cos();
        let sp = cam.pitch.sin();
        let cy = cam.yaw.cos();
        let sy = cam.yaw.sin();
        let target = Vec3::new(0.0, cam.pan_y, 0.0);
        let eye = target + Vec3::new(r * cp * sy, r * sp, r * cp * cy);

        let mut proj = Mat4::perspective_rh(fov_y, aspect, 0.05, 50.0);
        proj.z_axis.x += cx_shift;
        proj.z_axis.y += cy_shift;

        // Right-handed projection (`w_clip = -z_v`): `+cx_shift` shifts target NDC by `-cx_shift`.
        // Moving `comp_target` by `-right * (r * cx_shift / fx)` shifts object `+cx_shift` in NDC,
        // cancelling viewport drift to ~0 px while changing view ray geometry! (HIGH-11 fix)
        let forward = (target - eye).normalize();
        let right = forward.cross(Vec3::Y).normalize_or_zero();
        let up = right.cross(forward).normalize_or_zero();
        let fx = proj.x_axis.x;
        let fy = proj.y_axis.y;
        let comp_target = target - right * (r * cx_shift / fx) - up * (r * cy_shift / fy);
        let comp_view = Mat4::look_at_rh(eye, comp_target, Vec3::Y);

        let key_light_dir = Vec3::new(
            (0.65 + light_phase).sin(),
            0.82,
            (0.65 + light_phase).cos(),
        )
        .normalize();

        PerturbedCamera {
            view_proj: proj * comp_view,
            eye,
            key_light_dir,
        }
    }

    /// Equal-area 192-bin spherical solid-angle view coverage budget (12 lat bands × 16 azimuth bins).
    #[derive(Debug, Clone)]
    pub struct ViewCoverageBudget {
        visited: [u64; 3], // 192 bits
        pub max_bins_allowed: usize,
    }

    impl ViewCoverageBudget {
        pub fn new(max_fraction: f32) -> Self {
            let safe_frac = if max_fraction.is_finite() {
                max_fraction.clamp(0.10, 1.0)
            } else {
                0.35
            };
            let max_bins = (192.0 * safe_frac).round() as usize;
            Self {
                visited: [0; 3],
                max_bins_allowed: max_bins.clamp(12, 192),
            }
        }

        pub fn bin_for(cam: OrbitCamera) -> Option<usize> {
            if !cam.is_finite() {
                return None;
            }
            let cam = cam.clamped();
            let lat_t = ((cam.pitch.sin() + 1.0) * 0.5).clamp(0.0, 0.9999);
            let lat_bin = (lat_t * 12.0).floor() as usize;
            let az_t = (cam.yaw / (2.0 * PI)).clamp(0.0, 0.9999);
            let az_bin = (az_t * 16.0).floor() as usize;
            Some((lat_bin.min(11) * 16 + az_bin.min(15)).min(191))
        }

        pub fn visited_bins(&self) -> usize {
            (self.visited[0].count_ones()
                + self.visited[1].count_ones()
                + self.visited[2].count_ones()) as usize
        }

        pub fn record(&mut self, cam: OrbitCamera) -> Result<usize, ThreeDError> {
            let bin = Self::bin_for(cam).ok_or(ThreeDError::InvalidCamera)?;
            let word = bin / 64;
            let bit = 1u64 << (bin % 64);
            let already = (self.visited[word] & bit) != 0;
            if !already {
                let current = self.visited_bins();
                if current >= self.max_bins_allowed {
                    return Err(ThreeDError::ViewBudgetExceeded {
                        visited: current,
                        max_bins: self.max_bins_allowed,
                    });
                }
                self.visited[word] |= bit;
            }
            Ok(self.visited_bins())
        }
    }
}

#[inline]
fn aces_tonemap(x: Vec3) -> Vec3 {
    let a = 2.51;
    let b = 0.03;
    let c = 2.43;
    let d = 0.59;
    let e = 0.14;
    ((x * (a * x + Vec3::splat(b))) / (x * (c * x + Vec3::splat(d)) + Vec3::splat(e)))
        .clamp(Vec3::ZERO, Vec3::ONE)
}

/// Software metallic-roughness PBR rasterizer producing an RGB8 frame (`width * height * 3` bytes).
pub fn render_scene_rgb(
    scene: &Scene3D,
    cam: OrbitCamera,
    width: usize,
    height: usize,
    session_seed: &[u8; 32],
    enable_perturbation: bool,
) -> Vec<u8> {
    if width == 0 || height == 0 {
        return Vec::new();
    }
    let Some(px_total) = width.checked_mul(height) else {
        return Vec::new();
    };
    let Some(rgb_len) = px_total.checked_mul(3) else {
        return Vec::new();
    };
    let mut rgb = vec![0u8; rgb_len];
    let mut zbuf = vec![f32::INFINITY; px_total];

    // Obsidian-studio vertical gradient backdrop
    for y in 0..height {
        let t = (y as f32) / (height.max(1) as f32);
        let r = (10.0 + 10.0 * (1.0 - t)) as u8;
        let g = (13.0 + 13.0 * (1.0 - t)) as u8;
        let b = (18.0 + 18.0 * (1.0 - t)) as u8;
        for x in 0..width {
            let i = (y * width + x) * 3;
            rgb[i] = r;
            rgb[i + 1] = g;
            rgb[i + 2] = b;
        }
    }

    let pc = anti_3dgs::build_perturbed_camera(cam, width, height, session_seed, enable_perturbation);
    let fill_dir = Vec3::new(-0.7, 0.35, -0.55).normalize();
    let rim_dir = Vec3::new(0.1, 0.6, -0.9).normalize();
    let w_f = width as f32;
    let h_f = height as f32;
    let fallback_mat = MaterialPbr::default();

    for tri in &scene.triangles {
        let mut clip = [Vec4::ZERO; 3];
        let mut behind = false;
        for (k, slot) in clip.iter_mut().enumerate() {
            let c = pc.view_proj * Vec4::from((tri.pos[k], 1.0));
            if !c.is_finite() || c.w <= 0.05 {
                behind = true;
                break;
            }
            *slot = c;
        }
        if behind {
            continue;
        }

        let mut sx = [0.0f32; 3];
        let mut sy = [0.0f32; 3];
        let mut sz = [0.0f32; 3];
        let mut inv_w = [0.0f32; 3];
        for k in 0..3 {
            let iw = 1.0 / clip[k].w;
            inv_w[k] = iw;
            sx[k] = (clip[k].x * iw * 0.5 + 0.5) * w_f;
            sy[k] = (0.5 - clip[k].y * iw * 0.5) * h_f;
            sz[k] = clip[k].z * iw;
        }

        let mat = scene
            .materials
            .get(tri.material_idx)
            .or_else(|| scene.materials.last())
            .unwrap_or(&fallback_mat);

        // Screen-space signed area (Y-down): CCW front-facing triangles have negative area
        let area = (sx[1] - sx[0]) * (sy[2] - sy[0]) - (sx[2] - sx[0]) * (sy[1] - sy[0]);
        if !area.is_finite() || area.abs() < 1e-4 {
            continue;
        }
        if !mat.double_sided && area > 0.0 {
            continue;
        }
        let inv_area = 1.0 / area;

        // Off-screen bounding box rejection + integer-space upper clamp (defeats f32 precision OOB — Loop 3 MED-17)
        let fmin_x = sx[0].min(sx[1]).min(sx[2]);
        let fmax_x = sx[0].max(sx[1]).max(sx[2]);
        let fmin_y = sy[0].min(sy[1]).min(sy[2]);
        let fmax_y = sy[0].max(sy[1]).max(sy[2]);
        if !fmin_x.is_finite()
            || !fmax_x.is_finite()
            || !fmin_y.is_finite()
            || !fmax_y.is_finite()
            || fmax_x < 0.0
            || fmin_x >= w_f
            || fmax_y < 0.0
            || fmin_y >= h_f
        {
            continue;
        }
        let min_x = (fmin_x.floor().max(0.0) as usize).min(width - 1);
        let max_x = (fmax_x.ceil().max(0.0) as usize).min(width - 1);
        let min_y = (fmin_y.floor().max(0.0) as usize).min(height - 1);
        let max_y = (fmax_y.ceil().max(0.0) as usize).min(height - 1);
        if min_x > max_x || min_y > max_y {
            continue;
        }

        let base_tex = mat.base_color_texture.and_then(|ti| scene.textures.get(ti));
        let mr_tex = mat
            .metallic_roughness_texture
            .and_then(|ti| scene.textures.get(ti));
        let em_tex = mat.emissive_texture.and_then(|ti| scene.textures.get(ti));

        for py in min_y..=max_y {
            let fy = py as f32 + 0.5;
            for px in min_x..=max_x {
                let fx = px as f32 + 0.5;
                let w0 = ((sx[1] - fx) * (sy[2] - fy) - (sx[2] - fx) * (sy[1] - fy)) * inv_area;
                let w1 = ((sx[2] - fx) * (sy[0] - fy) - (sx[0] - fx) * (sy[2] - fy)) * inv_area;
                let w2 = 1.0 - w0 - w1;
                if !(w0 >= 0.0 && w1 >= 0.0 && w2 >= 0.0) {
                    continue;
                }

                let depth = w0 * sz[0] + w1 * sz[1] + w2 * sz[2];
                let pidx = py * width + px;
                if !depth.is_finite() || depth >= zbuf[pidx] {
                    continue;
                }

                let pw0 = w0 * inv_w[0];
                let pw1 = w1 * inv_w[1];
                let pw2 = w2 * inv_w[2];
                let inv_pw = 1.0 / (pw0 + pw1 + pw2).max(1e-8);
                let b0 = pw0 * inv_pw;
                let b1 = pw1 * inv_pw;
                let b2 = pw2 * inv_pw;

                let world_p = tri.pos[0] * b0 + tri.pos[1] * b1 + tri.pos[2] * b2;
                let mut n = (tri.norm[0] * b0 + tri.norm[1] * b1 + tri.norm[2] * b2).normalize_or_zero();
                let vdir = (pc.eye - world_p).normalize_or_zero();
                if mat.double_sided && n.dot(vdir) < 0.0 {
                    n = -n;
                }

                let uv = tri.uv[0] * b0 + tri.uv[1] * b1 + tri.uv[2] * b2;
                let mut albedo = Vec3::new(
                    mat.base_color_factor.x,
                    mat.base_color_factor.y,
                    mat.base_color_factor.z,
                );
                if let Some(t) = base_tex {
                    let s = t.sample_bilinear_srgb(uv.x, uv.y);
                    if s.w < 0.1 {
                        continue;
                    }
                    albedo *= Vec3::new(s.x, s.y, s.z);
                }
                let (mut metallic, mut roughness) = (mat.metallic_factor, mat.roughness_factor);
                if let Some(t) = mr_tex {
                    let s = t.sample_bilinear(uv.x, uv.y);
                    roughness = (roughness * s.y).clamp(0.04, 1.0);
                    metallic = (metallic * s.z).clamp(0.0, 1.0);
                }
                let mut emissive = mat.emissive_factor;
                if let Some(t) = em_tex {
                    let s = t.sample_bilinear_srgb(uv.x, uv.y);
                    emissive *= Vec3::new(s.x, s.y, s.z);
                }

                zbuf[pidx] = depth;

                let f0 = Vec3::splat(0.04).lerp(albedo, metallic);
                let diff_albedo = albedo * (1.0 - metallic);
                let spec_pow = (2.0 / (roughness * roughness + 1e-4) - 2.0).clamp(4.0, 256.0);

                let ndl_key = n.dot(pc.key_light_dir).max(0.0);
                let h_key = (pc.key_light_dir + vdir).normalize_or_zero();
                let ndh_key = n.dot(h_key).max(0.0);
                let fresnel = f0 + (Vec3::ONE - f0) * (1.0 - n.dot(vdir).clamp(0.0, 1.0)).powi(5);
                let spec_key = fresnel * ndh_key.powf(spec_pow) * ((spec_pow + 8.0) / (8.0 * PI));

                let ndl_fill = n.dot(fill_dir).max(0.0);
                let ndl_rim = n.dot(rim_dir).max(0.0);
                let hemi = Vec3::new(0.16, 0.19, 0.24).lerp(
                    Vec3::new(0.32, 0.36, 0.42),
                    (n.y * 0.5 + 0.5).clamp(0.0, 1.0),
                );

                let color = diff_albedo * (hemi + Vec3::splat(ndl_key * 1.15) + Vec3::new(0.35, 0.42, 0.55) * ndl_fill * 0.55)
                    + spec_key * 1.3
                    + fresnel * ndl_rim * 0.25
                    + emissive;

                let mapped = aces_tonemap(color);
                let o = pidx * 3;
                rgb[o] = (mapped.x.powf(1.0 / 2.2) * 255.0).round().clamp(0.0, 255.0) as u8;
                rgb[o + 1] = (mapped.y.powf(1.0 / 2.2) * 255.0).round().clamp(0.0, 255.0) as u8;
                rgb[o + 2] = (mapped.z.powf(1.0 / 2.2) * 255.0).round().clamp(0.0, 255.0) as u8;
            }
        }
    }

    rgb
}

/// Encode an RGB8 frame to standard baseline JPEG (quality clamped to `50..=98`).
pub fn encode_jpeg_rgb(
    rgb: &[u8],
    width: usize,
    height: usize,
    quality: u8,
) -> Result<Vec<u8>, ThreeDError> {
    if width == 0 || height == 0 {
        return Err(ThreeDError::Encode("zero image dimension".into()));
    }
    let w32 = u32::try_from(width).map_err(|_| ThreeDError::Encode("width exceeds u32".into()))?;
    let h32 =
        u32::try_from(height).map_err(|_| ThreeDError::Encode("height exceeds u32".into()))?;
    let pixels = width
        .checked_mul(height)
        .ok_or_else(|| ThreeDError::Encode("dimension multiplication overflow".into()))?;
    let expected = pixels
        .checked_mul(3)
        .ok_or_else(|| ThreeDError::Encode("buffer length overflow".into()))?;
    if rgb.len() != expected {
        return Err(ThreeDError::Encode(format!(
            "RGB buffer length mismatch: got {}, expected {}",
            rgb.len(),
            expected
        )));
    }
    let mut buf = Vec::with_capacity((pixels / 4).min(4 * 1024 * 1024));
    let mut enc = JpegEncoder::new_with_quality(Cursor::new(&mut buf), quality.clamp(50, 98));
    enc.encode(rgb, w32, h32, ExtendedColorType::Rgb8)
        .map_err(|e| ThreeDError::Encode(e.to_string()))?;
    Ok(buf)
}

/// Render a scene, embed the crop/scale-resilient forensic watermark using a precomputed engine,
/// and JPEG-encode.
#[allow(clippy::too_many_arguments)]
pub fn render_watermarked_jpeg_with_engine(
    scene: &Scene3D,
    cam: OrbitCamera,
    width: usize,
    height: usize,
    wm_engine: &WatermarkEngine,
    buyer_id: u64,
    session_seed: &[u8; 32],
    enable_perturbation: bool,
    jpeg_quality: u8,
) -> Result<Vec<u8>, ThreeDError> {
    let mut rgb = render_scene_rgb(scene, cam, width, height, session_seed, enable_perturbation);
    wm_engine
        .embed_frame_rgb(&mut rgb, width, height, buyer_id, EmbedConfig::default())
        .map_err(|e| ThreeDError::Encode(e.to_string()))?;
    encode_jpeg_rgb(&rgb, width, height, jpeg_quality)
}

/// Convenience wrapper rendering + watermarking + JPEG-encoding with a one-shot key.
#[allow(clippy::too_many_arguments)]
pub fn render_watermarked_jpeg(
    scene: &Scene3D,
    cam: OrbitCamera,
    width: usize,
    height: usize,
    wm_key: &SecretKey32,
    buyer_id: u64,
    session_seed: &[u8; 32],
    enable_perturbation: bool,
    jpeg_quality: u8,
) -> Result<Vec<u8>, ThreeDError> {
    let mut rgb = render_scene_rgb(scene, cam, width, height, session_seed, enable_perturbation);
    embed_frame_rgb(&mut rgb, width, height, wm_key, buyer_id, EmbedConfig::default())
        .map_err(|e| ThreeDError::Encode(e.to_string()))?;
    encode_jpeg_rgb(&rgb, width, height, jpeg_quality)
}

/// Bounded multi-SKU 3D asset catalog supporting lazy loading, LRU eviction, and cached SSR posters.
#[derive(Clone)]
pub struct AssetCatalog {
    inner: Arc<RwLock<CatalogInner>>,
}

struct CatalogInner {
    paths: HashMap<String, PathBuf>,
    loaded: HashMap<String, Arc<Scene3D>>,
    loaded_order: VecDeque<String>,
    posters: HashMap<String, Arc<Vec<u8>>>,
    poster_order: VecDeque<String>,
    max_loaded: usize,
    max_posters: usize,
}

impl AssetCatalog {
    pub fn new() -> Self {
        Self::with_limits(64, 256)
    }

    pub fn with_limits(max_loaded: usize, max_posters: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(CatalogInner {
                paths: HashMap::new(),
                loaded: HashMap::new(),
                loaded_order: VecDeque::new(),
                posters: HashMap::new(),
                poster_order: VecDeque::new(),
                max_loaded: max_loaded.max(1),
                max_posters: max_posters.max(1),
            })),
        }
    }

    pub fn register_file(&self, asset_id: impl Into<String>, path: impl Into<PathBuf>) {
        if let Ok(mut guard) = self.inner.write() {
            guard.paths.insert(asset_id.into(), path.into());
        }
    }

    pub fn insert_loaded(&self, scene: Scene3D) {
        if let Ok(mut guard) = self.inner.write() {
            let id = scene.id.clone();
            let existed = guard.loaded.contains_key(&id);
            if !existed {
                if guard.loaded.len() >= guard.max_loaded {
                    if let Some(evict) = guard.loaded_order.pop_front() {
                        guard.loaded.remove(&evict);
                    }
                }
                guard.loaded_order.push_back(id.clone());
            }
            guard.loaded.insert(id, Arc::new(scene));
        }
    }

    pub fn register_dir(&self, dir: &Path) -> Result<usize, ThreeDError> {
        let mut count = 0;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path
                .extension()
                .and_then(|e| e.to_str())
                .map(|s| s.eq_ignore_ascii_case("glb"))
                .unwrap_or(false)
            {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    self.register_file(stem.to_string(), path);
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    pub fn list_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .inner
            .read()
            .map(|g| {
                let mut set: HashSet<String> = g.paths.keys().cloned().collect();
                set.extend(g.loaded.keys().cloned());
                set.into_iter().collect()
            })
            .unwrap_or_default();
        ids.sort();
        ids
    }

    pub fn contains(&self, asset_id: &str) -> bool {
        self.inner
            .read()
            .map(|g| g.loaded.contains_key(asset_id) || g.paths.contains_key(asset_id))
            .unwrap_or(false)
    }

    pub fn get_scene(&self, asset_id: &str) -> Result<Arc<Scene3D>, ThreeDError> {
        if let Ok(guard) = self.inner.read() {
            if let Some(s) = guard.loaded.get(asset_id) {
                return Ok(Arc::clone(s));
            }
        }
        let path = {
            let guard = self
                .inner
                .read()
                .map_err(|_| ThreeDError::AssetNotFound(asset_id.into()))?;
            guard
                .paths
                .get(asset_id)
                .cloned()
                .ok_or_else(|| ThreeDError::AssetNotFound(asset_id.into()))?
        };
        let scene = Arc::new(Scene3D::from_glb_file(asset_id, &path)?);
        if let Ok(mut guard) = self.inner.write() {
            let existed = guard.loaded.contains_key(asset_id);
            if !existed {
                if guard.loaded.len() >= guard.max_loaded {
                    if let Some(evict) = guard.loaded_order.pop_front() {
                        guard.loaded.remove(&evict);
                    }
                }
                guard.loaded_order.push_back(asset_id.to_string());
            }
            guard.loaded.insert(asset_id.to_string(), Arc::clone(&scene));
        }
        Ok(scene)
    }

    /// Get or lazily render a CDN-cacheable SSR poster JPEG (`640×400`) for `0 CLS` embeds.
    pub fn get_poster_jpeg(&self, asset_id: &str) -> Result<Arc<Vec<u8>>, ThreeDError> {
        if let Ok(guard) = self.inner.read() {
            if let Some(p) = guard.posters.get(asset_id) {
                return Ok(Arc::clone(p));
            }
        }
        let scene = self.get_scene(asset_id)?;
        let rgb = render_scene_rgb(&scene, OrbitCamera::default(), 640, 400, &[0u8; 32], false);
        let jpg = Arc::new(encode_jpeg_rgb(&rgb, 640, 400, 86)?);
        if let Ok(mut guard) = self.inner.write() {
            let existed = guard.posters.contains_key(asset_id);
            if !existed {
                if guard.posters.len() >= guard.max_posters {
                    if let Some(evict) = guard.poster_order.pop_front() {
                        guard.posters.remove(&evict);
                    }
                }
                guard.poster_order.push_back(asset_id.to_string());
            }
            guard.posters.insert(asset_id.to_string(), Arc::clone(&jpg));
        }
        Ok(jpg)
    }
}

impl Default for AssetCatalog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use image::ImageReader;
    use vs_watermark::decode_frame_rgb_blind;

    #[test]
    fn loads_fixture_glb_renders_and_survives_jpeg_q70_crop_scale_torture() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vibeslayer-native-core/tests/fixtures/sample_mesh.glb");
        if !fixture.exists() {
            return;
        }
        let scene = Scene3D::from_glb_file("sample", &fixture).unwrap();
        assert!(!scene.triangles.is_empty());

        let wm_key = SecretKey32::generate().unwrap();
        let buyer_id = 0xDEAD_BEEF_4242_9999u64;
        let jpg_q70 = render_watermarked_jpeg(
            &scene,
            OrbitCamera {
                yaw: 0.9,
                pitch: 0.15,
                zoom: 2.6,
                pan_y: 0.0,
            },
            640,
            480,
            &wm_key,
            buyer_id,
            &[9u8; 32],
            true,
            70,
        )
        .unwrap();
        let img70 = ImageReader::new(Cursor::new(&jpg_q70))
            .with_guessed_format()
            .unwrap()
            .decode()
            .unwrap()
            .to_rgb8();
        let cropped = image::imageops::crop_imm(&img70, 53, 41, 512, 384).to_image();
        let resized = image::imageops::resize(
            &cropped,
            435,
            326,
            image::imageops::FilterType::Triangle,
        );
        let wm_torture = decode_frame_rgb_blind(
            resized.as_raw(),
            resized.width() as usize,
            resized.height() as usize,
            &wm_key,
        )
        .unwrap();
        assert_eq!(wm_torture.buyer_id, buyer_id);
        assert!(wm_torture.verified_mac);
    }

    #[test]
    fn anti_3dgs_tilt_shift_compensation_keeps_origin_optically_centered() {
        let cam = OrbitCamera {
            yaw: 0.7,
            pitch: 0.25,
            zoom: 2.8,
            pan_y: 0.0,
        };
        let pc = anti_3dgs::build_perturbed_camera(cam, 640, 480, &[42u8; 32], true);
        let clip_origin = pc.view_proj * Vec4::new(0.0, 0.0, 0.0, 1.0);
        let ndc_x = clip_origin.x / clip_origin.w;
        let ndc_y = clip_origin.y / clip_origin.w;
        // With HIGH-11 sign fix, origin stays within < 0.002 NDC (< 1 px on 640px)!
        assert!(ndc_x.abs() < 0.005, "tilt-shift drifted X: ndc_x={ndc_x}");
        assert!(ndc_y.abs() < 0.005, "tilt-shift drifted Y: ndc_y={ndc_y}");
    }

    #[test]
    fn nan_camera_and_zero_dim_texture_never_panic_or_bypass_budget() {
        let mut budget = anti_3dgs::ViewCoverageBudget::new(f32::NAN);
        assert_eq!(budget.max_bins_allowed, 67);
        assert!(budget
            .record(OrbitCamera {
                yaw: f32::NAN,
                pitch: f32::INFINITY,
                zoom: f32::NAN,
                pan_y: 0.0,
            })
            .is_err());

        let bad_tex = Texture2D {
            width: 0,
            height: 0,
            rgba: Vec::new(),
        };
        assert_eq!(bad_tex.sample_bilinear(f32::NAN, f32::INFINITY), Vec4::ONE);
    }

    #[test]
    fn spherical_view_coverage_budget_throttles_sweeps() {
        let mut budget = anti_3dgs::ViewCoverageBudget::new(0.25);
        let mut accepted = 0;
        let mut rejected = 0;
        for band in 0..12 {
            let sin_p = -0.92 + (band as f32) * (1.84 / 11.0);
            let pitch = sin_p.asin();
            for az in 0..16 {
                let yaw = (az as f32) * (2.0 * PI / 16.0);
                match budget.record(OrbitCamera {
                    yaw,
                    pitch,
                    zoom: 2.8,
                    pan_y: 0.0,
                }) {
                    Ok(_) => accepted += 1,
                    Err(_) => rejected += 1,
                }
            }
        }
        assert_eq!(budget.visited_bins(), budget.max_bins_allowed);
        assert!(accepted >= budget.max_bins_allowed);
        assert!(rejected > 100);
    }
}
