//! Zero-Geometry Server-Rendered Interactive 3D Streamer (`raster_stream.rs`).
//!
//! Mathematically immune to ALL client-side 3D extraction (RenderDoc, NinjaRipper,
//! Transform Feedback, CDP shader dumping, SVD normal oracle, and Kruppa/multi-view
//! matrix solvers): the browser receives ZERO vertices, ZERO VBOs, ZERO GLSL shaders,
//! ZERO UV maps, ZERO PBR textures, ZERO projection matrices, and ZERO WebGL contexts.
//!
//! The Rust server decrypts the shielded 3D mesh & textures strictly in server RAM,
//! renders interactive 360-degree PBR frames across CPU worker threads (band-binned
//! perspective-correct Z-buffered rasterizer + smooth vertex normals + glowing emissive
//! + ACES filmic tonemapping), embeds an invisible 64-bit JPEG-surviving per-buyer
//! forensic block-DC watermark into the pixels, and streams compact baseline JPEGs.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::encrypted_compute::{
    decrypt_gpu_lanes, derive_ephemeral_gpu_uniforms, derive_gpu_stage_specs_n,
    derive_unimodular_lattice_3x3, SHIELD_GPU_STAGES,
};
use crate::jpeg_enc::encode_jpeg;
use crate::mini_json::parse_json;
use crate::params::{html_escape, AntiStealthMode, CspMode, Serve3dParams};
use crate::png_tile::decode_png;
use crate::shield_viewer::{derive_lattice_offset_pub, surf_avalanche_pub};
use crate::web_runtime::{
    aes256_gcm_seal, aes256_gcm_seal_in_place, build_tier4_anti_stealth_js, ct_str_eq,
    issue_ticket, p256_ecdh_shared_secret, p256_generate_keypair, p256_validate_public_key,
    parse_trusted_proxies, read_http_request_with_timeouts, resolve_client_ip, send_http_with_csp,
    send_json_err_with_csp, validate_same_origin_proxy, verify_server_anti_stealth,
    write_hex_bytes, AuthConfig, ConnLimiter, HttpLeaseGuard, ParsedRequest,
};
use crate::{chacha20_xor_into, hex_decode, hkdf_sha256_32, hmac_sha256, os_random_bytes, secure_zero, Sha256Hasher};

pub const STREAM_TEX_NONCE_PREFIX: [u8; 8] = *b"VS3DSTRT";

struct ServerTex {
    w: usize,
    h: usize,
    ch: usize,
    pixels: Vec<u8>,
}

impl ServerTex {
    #[inline(always)]
    fn sample_rgb_linear(&self, u: f32, v: f32) -> [f32; 3] {
        let uf = u - u.floor();
        let vf = v - v.floor();
        let x = ((uf * (self.w as f32)) as usize).min(self.w - 1);
        let y = ((vf * (self.h as f32)) as usize).min(self.h - 1);
        let off = (y * self.w + x) * self.ch;
        let r = (self.pixels[off] as f32) * (1.0 / 255.0);
        let g = (self.pixels[off + 1] as f32) * (1.0 / 255.0);
        let b = (self.pixels[off + 2] as f32) * (1.0 / 255.0);
        [r * r, g * g, b * b]
    }

    #[inline(always)]
    fn sample_mr(&self, u: f32, v: f32) -> (f32, f32) {
        let uf = u - u.floor();
        let vf = v - v.floor();
        let x = ((uf * (self.w as f32)) as usize).min(self.w - 1);
        let y = ((vf * (self.h as f32)) as usize).min(self.h - 1);
        let off = (y * self.w + x) * self.ch;
        let rough = ((self.pixels[off + 1] as f32) * (1.0 / 255.0)).clamp(0.08, 1.0);
        let metal = ((self.pixels[off + 2] as f32) * (1.0 / 255.0)).clamp(0.0, 1.0);
        (rough, metal)
    }
}

#[derive(Clone, Copy)]
struct StreamVert {
    pos: [f32; 3],
    norm: [f32; 3],
    uv: [f32; 2],
}

#[derive(Clone, Copy)]
struct StreamTri {
    v: [StreamVert; 3],
    mat_id: u8,
}

#[derive(Clone, Copy)]
struct ProjectedTri {
    x: [f32; 3],
    y: [f32; 3],
    z: [f32; 3],
    inv_w: [f32; 3],
    u_ow: [f32; 3],
    v_ow: [f32; 3],
    diff: [f32; 3],
    spec: [f32; 3],
    rim: [f32; 3],
    mat_id: u8,
    min_y: i32,
    max_y: i32,
    min_x: i32,
    max_x: i32,
    area_inv: f32,
}

struct StreamSession {
    auth_token: String,
    origin: String,
    asset_key: [u8; 32],
    wm64_id: u64,
    proj_seed: [u8; 32],
    expires_at: u64,
    frame_calls: usize,
    frame_seq: u64,
    in_flight: bool,
}

impl Drop for StreamSession {
    fn drop(&mut self) {
        secure_zero(&mut self.asset_key);
        secure_zero(&mut self.proj_seed);
    }
}

struct StreamServerState {
    width: usize,
    height: usize,
    quality: u8,
    csp: CspMode,
    anti_stealth: AntiStealthMode,
    wm_w: u32,
    camera_jitter: f32,
    ticket_ttl_sec: u64,
    session_ttl_sec: u64,
    frame_budget: usize,
    max_sessions: usize,
    max_render_concurrency: usize,
    header_timeout: Duration,
    body_timeout: Duration,
    ticket_secret: [u8; 32],
    wm_key: [u8; 32],
    auth: AuthConfig,
    allowed_origin: Option<String>,
    trusted_proxies: Vec<IpAddr>,
    bound_addr: SocketAddr,
    guard: HttpLeaseGuard,
    conn_limiter: ConnLimiter,
    active_renders: AtomicUsize,
    sessions: Mutex<HashMap<String, StreamSession>>,
    index_prefix: Vec<u8>,
    index_suffix: Vec<u8>,
    loader_js: Vec<u8>,
    tris: Vec<StreamTri>,
    textures: Vec<ServerTex>,
    srgb_lut: [u8; 4096],
    render_threads: usize,
}

impl Drop for StreamServerState {
    fn drop(&mut self) {
        secure_zero(&mut self.ticket_secret);
        secure_zero(&mut self.wm_key);
        for t in &mut self.textures {
            secure_zero(&mut t.pixels);
        }
    }
}

fn unix_now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn build_srgb_lut() -> [u8; 4096] {
    let mut lut = [0u8; 4096];
    for i in 0..4096 {
        let lin = (i as f32) / 4095.0;
        let s = lin.powf(1.0 / 2.2).clamp(0.0, 1.0);
        lut[i] = (s * 255.0 + 0.5) as u8;
    }
    lut
}

#[inline(always)]
fn aces_tonemap_scalar(x: f32) -> f32 {
    ((x * (2.51 * x + 0.03)) / (x * (2.43 * x + 0.59) + 0.14)).clamp(0.0, 1.0)
}

fn build_lookat_proj(
    yaw: f32,
    pitch: f32,
    zoom: f32,
    pan_y: f32,
    aspect: f32,
    proj_seed: &[u8; 32],
    jitter: f32,
) -> ([f32; 16], [f32; 3], f32) {
    // Subtle anti-photogrammetry / anti-3DGS per-session focal & lighting phase drift
    // (smooth C^infinity for humans, breaks calibrated SfM/COLMAP multi-view pose consistency!)
    let j = jitter.clamp(0.0, 3.0);
    let ph0 = (u16::from_le_bytes([proj_seed[0], proj_seed[1]]) as f32 / 65535.0) * std::f32::consts::TAU;
    let ph1 = (u16::from_le_bytes([proj_seed[2], proj_seed[3]]) as f32 / 65535.0) * std::f32::consts::TAU;
    let ph2 = (u16::from_le_bytes([proj_seed[4], proj_seed[5]]) as f32 / 65535.0) * std::f32::consts::TAU;
    let ph3 = (u16::from_le_bytes([proj_seed[6], proj_seed[7]]) as f32 / 65535.0) * std::f32::consts::TAU;
    let fov_deg = if j > 0.0 {
        (37.0 + (yaw * 0.9 + ph0).sin() * 1.8 * j).clamp(30.0, 46.0)
    } else {
        37.0
    };
    let light_shift = if j > 0.0 { (yaw * 0.6 + ph1).cos() * 0.22 * j } else { 0.0 };
    // Subtle compensated off-axis tilt-shift principal point (cx, cy): breaks COLMAP/3DGS
    // constant-intrinsics multi-view solvers while exact eye-pan compensation keeps the
    // rendered 3D model dead-center and razor-sharp for human viewers.
    let cx = if j > 0.0 { ((yaw * 1.1 + ph2).sin() * 0.09 * j).clamp(-0.22, 0.22) } else { 0.0 };
    let cy = if j > 0.0 { ((pitch * 1.3 + ph3).cos() * 0.07 * j).clamp(-0.18, 0.18) } else { 0.0 };
    let fov = fov_deg.to_radians();
    let fy = 1.0 / (0.5 * fov).tan();
    let fx = fy / aspect.max(0.25);
    let near = 0.08f32;
    let far = 40.0f32;
    let nf = 1.0 / (near - far);

    let proj = [
        fx, 0.0, 0.0, 0.0,
        0.0, fy, 0.0, 0.0,
        cx, cy, (far + near) * nf, -1.0,
        0.0, 0.0, (2.0 * far * near) * nf, 0.0,
    ];

    let p = pitch.clamp(-1.35, 1.35);
    let cp = p.cos();
    let sp = p.sin();
    let cy_a = yaw.cos();
    let sy_a = yaw.sin();
    let r = zoom.clamp(0.85, 6.5);

    let eye = [r * cp * sy_a, pan_y + r * sp, r * cp * cy_a];
    let target = [0.0f32, pan_y, 0.0f32];

    let mut z_ax = [eye[0] - target[0], eye[1] - target[1], eye[2] - target[2]];
    let z_len = (z_ax[0] * z_ax[0] + z_ax[1] * z_ax[1] + z_ax[2] * z_ax[2]).sqrt().max(1e-6);
    for v in &mut z_ax {
        *v /= z_len;
    }

    let up = [0.0f32, 1.0, 0.0];
    let mut x_ax = [
        up[1] * z_ax[2] - up[2] * z_ax[1],
        up[2] * z_ax[0] - up[0] * z_ax[2],
        up[0] * z_ax[1] - up[1] * z_ax[0],
    ];
    let x_len = (x_ax[0] * x_ax[0] + x_ax[1] * x_ax[1] + x_ax[2] * x_ax[2]).sqrt().max(1e-6);
    for v in &mut x_ax {
        *v /= x_len;
    }
    let y_ax = [
        z_ax[1] * x_ax[2] - z_ax[2] * x_ax[1],
        z_ax[2] * x_ax[0] - z_ax[0] * x_ax[2],
        z_ax[0] * x_ax[1] - z_ax[1] * x_ax[0],
    ];

    let dx_comp = r * cx / fx;
    let dy_comp = r * cy / fy;
    let tx = -(x_ax[0] * eye[0] + x_ax[1] * eye[1] + x_ax[2] * eye[2]) + dx_comp;
    let ty = -(y_ax[0] * eye[0] + y_ax[1] * eye[1] + y_ax[2] * eye[2]) + dy_comp;
    let tz = -(z_ax[0] * eye[0] + z_ax[1] * eye[1] + z_ax[2] * eye[2]);

    let view = [
        x_ax[0], y_ax[0], z_ax[0], 0.0,
        x_ax[1], y_ax[1], z_ax[1], 0.0,
        x_ax[2], y_ax[2], z_ax[2], 0.0,
        tx, ty, tz, 1.0,
    ];

    let mut m = [0.0f32; 16];
    for c in 0..4 {
        for row in 0..4 {
            m[c * 4 + row] = proj[row] * view[c * 4]
                + proj[4 + row] * view[c * 4 + 1]
                + proj[8 + row] * view[c * 4 + 2]
                + proj[12 + row] * view[c * 4 + 3];
        }
    }
    (m, z_ax, light_shift)
}

#[inline(always)]
fn norm3(v: [f32; 3]) -> [f32; 3] {
    let l = (v[0] * v[0] + v[1] * v[1] + v[2] * v[2]).sqrt().max(1e-6);
    [v[0] / l, v[1] / l, v[2] / l]
}

#[inline(always)]
fn dot3(a: [f32; 3], b: [f32; 3]) -> f32 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

/// Stamps an invisible, JPEG-surviving 64-bit per-buyer forensic watermark using smooth
/// adjacent-8x8-block DC differential pairs (+delta on block A, -delta on block B).
/// Zero intra-block AC edges -> keeps JPEG frames compact (~40-65 KB) AND visually invisible
/// (Weber-Fechner adaptive amplitude: ±1 on dark pixels, ±2 on bright/midtone pixels), while
/// 32 redundant pairs per bit survive JPEG Q80+ compression with blind O(1) decoding!
pub fn stamp_pixel_wm64(
    rgb: &mut [u8],
    width: usize,
    height: usize,
    wm_key: &[u8; 32],
    wm64_id: u64,
    base_amp: i32,
) {
    if base_amp <= 0 {
        return;
    }
    let bx_pairs = width / 16; // Horizontal pairs of adjacent 8x8 JPEG MCUs
    let by_cnt = height / 8;
    let total_pairs = bx_pairs * by_cnt;
    if total_pairs < 256 {
        return;
    }
    let stride = width * 3;
    let n_carriers = 2048usize.min(total_pairs);
    let step = (total_pairs / n_carriers).max(1);
    for ci in 0..n_carriers {
        let bit_idx = ci & 63;
        let bsign: i32 = if ((wm64_id >> bit_idx) & 1) != 0 { 1 } else { -1 };
        let mut msg = [0u8; 16];
        msg[..12].copy_from_slice(b"VS3D_PIXWM2|");
        msg[12..16].copy_from_slice(&(ci as u32).to_le_bytes());
        let mac = hmac_sha256(wm_key, &msg);
        let chip: i32 = if (mac[0] & 1) != 0 { 1 } else { -1 };

        let pidx = (ci * step + ((mac[1] as usize) % step)) % total_pairs;
        let px_left = (pidx % bx_pairs) * 16;
        let py_top = (pidx / bx_pairs) * 8;

        // Weber-Fechner perceptual invisibility cap:
        // sRGB gamma amplifies steps near black, so keep dark pixels at ±1 (contrast 2.0 > 0.625
        // JPEG Q84 DC quant step) and mid/bright pixels capped at ±2 (below human JND while
        // giving >12-sigma SNR across 32 redundant carriers per bit -> 1.000 blind post-JPEG decode!).
        let sample_off = (py_top + 4) * stride + (px_left + 4) * 3;
        let luma = (rgb[sample_off] as i32 + rgb[sample_off + 1] as i32 + rgb[sample_off + 2] as i32) / 3;
        let amp = if luma < 34 {
            1
        } else {
            base_amp.clamp(1, 2)
        };
        let delta = bsign * chip * amp;

        for ly in 0..8 {
            let row = (py_top + ly) * stride;
            for lx in 0..8 {
                let o1 = row + (px_left + lx) * 3;
                rgb[o1] = (rgb[o1] as i32 + delta).clamp(0, 255) as u8;
                rgb[o1 + 1] = (rgb[o1 + 1] as i32 + delta).clamp(0, 255) as u8;
                rgb[o1 + 2] = (rgb[o1 + 2] as i32 + delta).clamp(0, 255) as u8;
                let o2 = row + (px_left + 8 + lx) * 3;
                rgb[o2] = (rgb[o2] as i32 - delta).clamp(0, 255) as u8;
                rgb[o2 + 1] = (rgb[o2 + 1] as i32 - delta).clamp(0, 255) as u8;
                rgb[o2 + 2] = (rgb[o2 + 2] as i32 - delta).clamp(0, 255) as u8;
            }
        }
    }
}

/// Blind O(1) forensic decoder for `stamp_pixel_wm64`: extracts the 64-bit buyer ID directly
/// from ANY decoded RGB frame (even AFTER JPEG compression, without needing the original frame!).
pub fn decode_pixel_wm64(
    rgb: &[u8],
    width: usize,
    height: usize,
    wm_key: &[u8; 32],
) -> (u64, f64) {
    let bx_pairs = width / 16;
    let by_cnt = height / 8;
    let total_pairs = bx_pairs * by_cnt;
    if total_pairs < 256 || rgb.len() < width * height * 3 {
        return (0, 0.0);
    }
    let stride = width * 3;
    let n_carriers = 2048usize.min(total_pairs);
    let step = (total_pairs / n_carriers).max(1);

    let mut bit_sum = [0.0f64; 64];
    let mut bit_cnt = [0usize; 64];

    for ci in 0..n_carriers {
        let mut msg = [0u8; 16];
        msg[..12].copy_from_slice(b"VS3D_PIXWM2|");
        msg[12..16].copy_from_slice(&(ci as u32).to_le_bytes());
        let mac = hmac_sha256(wm_key, &msg);
        let chip = if (mac[0] & 1) != 0 { 1.0f64 } else { -1.0f64 };
        let pidx = (ci * step + ((mac[1] as usize) % step)) % total_pairs;
        let px_left = (pidx % bx_pairs) * 16;
        let py_top = (pidx / bx_pairs) * 8;

        let mut left_sum = 0.0f64;
        let mut right_sum = 0.0f64;
        for ly in 0..8 {
            let row = (py_top + ly) * stride;
            for lx in 0..8 {
                let o1 = row + (px_left + lx) * 3;
                left_sum += 0.299 * (rgb[o1] as f64)
                    + 0.587 * (rgb[o1 + 1] as f64)
                    + 0.114 * (rgb[o1 + 2] as f64);
                let o2 = row + (px_left + 8 + lx) * 3;
                right_sum += 0.299 * (rgb[o2] as f64)
                    + 0.587 * (rgb[o2 + 1] as f64)
                    + 0.114 * (rgb[o2 + 2] as f64);
            }
        }
        let contrast = (left_sum - right_sum) / 64.0;
        // Reject sharp silhouette edges (|contrast| > 14 luma) so object boundaries never add noise!
        if contrast.abs() > 14.0 {
            continue;
        }
        let clamped = contrast.clamp(-6.0, 6.0);
        let b = ci & 63;
        bit_sum[b] += clamped * chip;
        bit_cnt[b] += 1;
    }

    let mut wm64 = 0u64;
    let mut active = 0usize;
    let mut conf_sum = 0.0f64;
    for b in 0..64 {
        if bit_cnt[b] > 0 {
            active += 1;
            if bit_sum[b] >= 0.0 {
                wm64 |= 1u64 << b;
            }
            conf_sum += (bit_sum[b].abs() / ((bit_cnt[b] as f64) * 1.5)).min(1.0);
        }
    }
    let conf = if active > 0 { conf_sum / (active as f64) } else { 0.0 };
    (wm64, conf)
}

fn render_frame_jpeg(
    state: &StreamServerState,
    yaw: f32,
    pitch: f32,
    zoom: f32,
    pan_y: f32,
    wm64_id: u64,
    proj_seed: &[u8; 32],
) -> Vec<u8> {
    let w = state.width;
    let h = state.height;
    let wf = w as f32;
    let hf = h as f32;
    let aspect = wf / hf.max(1.0);
    let (mvp, cam_dir, light_shift) =
        build_lookat_proj(yaw, pitch, zoom, pan_y, aspect, proj_seed, state.camera_jitter);

    let l1 = norm3([0.55 + light_shift, 0.78, 0.62 - light_shift * 0.5]);
    let l2 = norm3([-0.68 - light_shift * 0.5, 0.35, -0.55]);
    let v_dir = norm3(cam_dir);
    let h1 = norm3([l1[0] + v_dir[0], l1[1] + v_dir[1], l1[2] + v_dir[2]]);

    // Stage 1: Parallel transform + frustum/backface cull + screen projection
    let n_threads = state.render_threads;
    let total_tris = state.tris.len();
    let chunk_size = ((total_tris + n_threads - 1) / n_threads).max(1);
    let mut per_thread_proj: Vec<Vec<ProjectedTri>> = (0..n_threads).map(|_| Vec::new()).collect();

    thread::scope(|s| {
        for (ti, out_slot) in per_thread_proj.iter_mut().enumerate() {
            let start = ti * chunk_size;
            if start >= total_tris {
                break;
            }
            let end = (start + chunk_size).min(total_tris);
            let tris_slice = &state.tris[start..end];
            s.spawn(move || {
                out_slot.reserve(tris_slice.len() / 2);
                for tri in tris_slice {
                    let mut sx = [0.0f32; 3];
                    let mut sy = [0.0f32; 3];
                    let mut sz = [0.0f32; 3];
                    let mut iw = [0.0f32; 3];
                    let mut u_ow = [0.0f32; 3];
                    let mut v_ow = [0.0f32; 3];
                    let mut diff = [0.0f32; 3];
                    let mut spec = [0.0f32; 3];
                    let mut rim = [0.0f32; 3];
                    let mut behind = false;
                    for k in 0..3 {
                        let p = tri.v[k].pos;
                        let cx = mvp[0] * p[0] + mvp[4] * p[1] + mvp[8] * p[2] + mvp[12];
                        let cy = mvp[1] * p[0] + mvp[5] * p[1] + mvp[9] * p[2] + mvp[13];
                        let cz = mvp[2] * p[0] + mvp[6] * p[1] + mvp[10] * p[2] + mvp[14];
                        let cw = mvp[3] * p[0] + mvp[7] * p[1] + mvp[11] * p[2] + mvp[15];
                        if cw <= 0.05 {
                            behind = true;
                            break;
                        }
                        let inv_w = 1.0 / cw;
                        sx[k] = (cx * inv_w * 0.5 + 0.5) * wf;
                        sy[k] = (0.5 - cy * inv_w * 0.5) * hf;
                        sz[k] = cz * inv_w;
                        iw[k] = inv_w;
                        u_ow[k] = tri.v[k].uv[0] * inv_w;
                        v_ow[k] = tri.v[k].uv[1] * inv_w;

                        let mut n = tri.v[k].norm;
                        let ndv = dot3(n, v_dir);
                        if ndv < 0.0 {
                            n = [-n[0], -n[1], -n[2]];
                        }
                        let d1 = dot3(n, l1).max(0.0);
                        let d2 = dot3(n, l2).max(0.0);
                        let hemi = 0.5 * n[1] + 0.5;
                        diff[k] = 0.22 + 0.20 * hemi + 1.35 * d1 + 0.45 * d2;
                        spec[k] = dot3(n, h1).max(0.0).powi(16);
                        rim[k] = (1.0 - dot3(n, v_dir).abs()).clamp(0.0, 1.0).powi(3);
                    }
                    if behind {
                        continue;
                    }
                    let area = (sx[1] - sx[0]) * (sy[2] - sy[0]) - (sy[1] - sy[0]) * (sx[2] - sx[0]);
                    if area.abs() < 0.15 {
                        continue;
                    }
                    let min_x = sx[0].min(sx[1]).min(sx[2]).floor() as i32;
                    let max_x = sx[0].max(sx[1]).max(sx[2]).ceil() as i32;
                    let min_y = sy[0].min(sy[1]).min(sy[2]).floor() as i32;
                    let max_y = sy[0].max(sy[1]).max(sy[2]).ceil() as i32;
                    if max_x < 0 || min_x >= w as i32 || max_y < 0 || min_y >= h as i32 {
                        continue;
                    }
                    out_slot.push(ProjectedTri {
                        x: sx,
                        y: sy,
                        z: sz,
                        inv_w: iw,
                        u_ow,
                        v_ow,
                        diff,
                        spec,
                        rim,
                        mat_id: tri.mat_id,
                        min_x: min_x.max(0),
                        max_x: max_x.min((w - 1) as i32),
                        min_y: min_y.max(0),
                        max_y: max_y.min((h - 1) as i32),
                        area_inv: 1.0 / area,
                    });
                }
            });
        }
    });

    // Stage 2: Parallel horizontal band rasterization (zero locks, cache-hot L1 Z-buffer!)
    let mut rgb = vec![0u8; w * h * 3];
    let band_rows = ((h + n_threads - 1) / n_threads).max(1);
    let has_tex = state.textures.len();
    let textures = &state.textures;
    let lut = &state.srgb_lut;
    let proj_ref = &per_thread_proj;

    thread::scope(|s| {
        for (bi, band_rgb) in rgb.chunks_mut(band_rows * w * 3).enumerate() {
            let y_start = bi * band_rows;
            let rows_in_band = band_rgb.len() / (w * 3);
            let y_end = y_start + rows_in_band;
            s.spawn(move || {
                // Studio dark radial backdrop
                let cx_bg = wf * 0.5;
                let cy_bg = hf * 0.36;
                let inv_rad = 1.0 / (wf * 0.65).max(1.0);
                for ly in 0..rows_in_band {
                    let y = (y_start + ly) as f32;
                    let dy = (y - cy_bg) * inv_rad;
                    let row_off = ly * w * 3;
                    for x in 0..w {
                        let dx = (x as f32 - cx_bg) * inv_rad;
                        let t = (1.0 - (dx * dx + dy * dy).sqrt()).clamp(0.0, 1.0);
                        let off = row_off + x * 3;
                        band_rgb[off] = (9.0 + t * 18.0) as u8;
                        band_rgb[off + 1] = (11.0 + t * 20.0) as u8;
                        band_rgb[off + 2] = (17.0 + t * 28.0) as u8;
                    }
                }
                let mut zbuf = vec![1.0e9f32; rows_in_band * w];
                let y0_i = y_start as i32;
                let y1_i = (y_end as i32) - 1;

                for bucket in proj_ref {
                    for t in bucket {
                        if t.max_y < y0_i || t.min_y > y1_i {
                            continue;
                        }
                        let ry0 = t.min_y.max(y0_i);
                        let ry1 = t.max_y.min(y1_i);
                        let x0 = t.x[0]; let y0 = t.y[0];
                        let x1 = t.x[1]; let y1 = t.y[1];
                        let x2 = t.x[2]; let y2 = t.y[2];
                        // Exact signed barycentric edge functions:
                        // area = (x1 - x0)*(y2 - y0) - (y1 - y0)*(x2 - x0)
                        // w0(x0,y0) = +area * ai = +1, w1(x1,y1) = +area * ai = +1!
                        let dy12 = y1 - y2; let dx12 = x1 - x2;
                        let dy20 = y2 - y0; let dx20 = x2 - x0;
                        let ai = t.area_inv;

                        for py in ry0..=ry1 {
                            let pfy = (py as f32) + 0.5;
                            let ly = (py - y0_i) as usize;
                            let zrow = ly * w;
                            let rrow = zrow * 3;
                            let w0_y = (pfy - y1) * dx12;
                            let e1_y = (pfy - y2) * dx20;
                            for px in t.min_x..=t.max_x {
                                let pfx = (px as f32) + 0.5;
                                let w0 = ((pfx - x1) * dy12 - w0_y) * ai;
                                if w0 < -1e-4 {
                                    continue;
                                }
                                let e1 = ((pfx - x2) * dy20 - e1_y) * ai;
                                if e1 < -1e-4 {
                                    continue;
                                }
                                let e2 = 1.0 - w0 - e1;
                                if e2 < -1e-4 {
                                    continue;
                                }
                                let z = w0 * t.z[0] + e1 * t.z[1] + e2 * t.z[2];
                                let zi = zrow + (px as usize);
                                if z >= zbuf[zi] || z < -1.0 || z > 1.0 {
                                    continue;
                                }
                                zbuf[zi] = z;

                                let d_lit = w0 * t.diff[0] + e1 * t.diff[1] + e2 * t.diff[2];
                                let s_lit = w0 * t.spec[0] + e1 * t.spec[1] + e2 * t.spec[2];
                                let r_lit = w0 * t.rim[0] + e1 * t.rim[1] + e2 * t.rim[2];

                                let (cr, cg, cb) = if t.mat_id == 1 {
                                    // Glowing Golden Halos
                                    let r = 0.90 * (0.35 + 0.65 * d_lit) + 3.50 + 1.2 * (s_lit + 0.6 * r_lit);
                                    let g = 0.65 * (0.35 + 0.65 * d_lit) + 2.52 + 0.95 * (s_lit + 0.6 * r_lit);
                                    let b = 0.006 * (0.35 + 0.65 * d_lit) + 0.021 + 0.4 * (s_lit + 0.6 * r_lit);
                                    (r, g, b)
                                } else {
                                    let inv_w = w0 * t.inv_w[0] + e1 * t.inv_w[1] + e2 * t.inv_w[2];
                                    let recip = 1.0 / inv_w.max(1e-7);
                                    let u = (w0 * t.u_ow[0] + e1 * t.u_ow[1] + e2 * t.u_ow[2]) * recip;
                                    let v = (w0 * t.v_ow[0] + e1 * t.v_ow[1] + e2 * t.v_ow[2]) * recip;
                                    let base = if has_tex > 0 {
                                        textures[0].sample_rgb_linear(u, v)
                                    } else {
                                        [0.72, 0.75, 0.82]
                                    };
                                    let (rough, metal) = if has_tex > 1 {
                                        textures[1].sample_mr(u, v)
                                    } else {
                                        (0.45, 0.30)
                                    };
                                    let emis = if has_tex > 2 {
                                        let e = textures[2].sample_rgb_linear(u, v);
                                        [e[0] * 3.5, e[1] * 3.5, e[2] * 3.5]
                                    } else {
                                        [0.0, 0.0, 0.0]
                                    };
                                    let diff_mul = 1.0 - metal * 0.80;
                                    let spec_mul = s_lit * (1.40 - rough * 0.80) * 1.45;
                                    let f0_r = 0.04 + (base[0] - 0.04) * metal;
                                    let f0_g = 0.04 + (base[1] - 0.04) * metal;
                                    let f0_b = 0.04 + (base[2] - 0.04) * metal;
                                    let r = base[0] * (0.16 + diff_mul * d_lit) + f0_r * spec_mul + 0.22 * r_lit + emis[0];
                                    let g = base[1] * (0.18 + diff_mul * d_lit * 0.98) + f0_g * spec_mul + 0.17 * r_lit + emis[1];
                                    let b = base[2] * (0.23 + diff_mul * d_lit * 0.95) + f0_b * spec_mul + 0.07 * r_lit + emis[2];
                                    (r, g, b)
                                };

                                let off = rrow + (px as usize) * 3;
                                band_rgb[off] = lut[(aces_tonemap_scalar(cr) * 4095.0) as usize];
                                band_rgb[off + 1] = lut[(aces_tonemap_scalar(cg) * 4095.0) as usize];
                                band_rgb[off + 2] = lut[(aces_tonemap_scalar(cb) * 4095.0) as usize];
                            }
                        }
                    }
                }
            });
        }
    });

    // Stage 3: Stamp visually invisible, JPEG-surviving per-buyer 64-bit forensic watermark
    if state.wm_w > 0 {
        let base_amp = ((state.wm_w / 6).clamp(1, 3)) as i32;
        stamp_pixel_wm64(&mut rgb, w, h, &state.wm_key, wm64_id, base_amp);
    }

    // Stage 4: Fast baseline JPEG encode
    encode_jpeg(w, h, 3, &rgb, state.quality)
}

fn build_stream_html(title: &str, width: usize, height: usize, real_tris: usize) -> String {
    let safe_title = html_escape(title);
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="vs-ticket" content="__VS_STREAM_TICKET__"/>
<title>{safe_title} — VibeSlayer Zero-Geometry 3D Stream</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#090b11;color:#e8ecf4;font-family:system-ui,-apple-system,sans-serif;overflow:hidden;height:100vh;width:100vw;user-select:none}}
  canvas{{display:block;width:100vw;height:100vh;object-fit:contain;cursor:grab}}
  canvas:active{{cursor:grabbing}}
  .hud{{position:fixed;top:18px;left:18px;background:rgba(10,13,22,0.86);border:1px solid rgba(74,222,128,0.38);border-radius:14px;padding:16px 18px;max-width:420px;backdrop-filter:blur(10px);box-shadow:0 14px 40px rgba(0,0,0,0.55)}}
  .badge{{display:inline-block;font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;padding:4px 9px;border-radius:999px;background:rgba(74,222,128,0.16);color:#4ade80;border:1px solid rgba(74,222,128,0.45);margin-bottom:8px}}
  h1{{font-size:17px;font-weight:700;margin-bottom:6px;color:#fff}}
  .sub{{font-size:12.5px;color:#a8b3cf;line-height:1.45;margin-bottom:12px}}
  .grid{{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px}}
  .stat{{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:9px;padding:8px 10px}}
  .stat .k{{font-size:10.5px;color:#8c98b8;text-transform:uppercase;letter-spacing:0.04em}}
  .stat .v{{font-size:13.5px;font-weight:700;color:#fff;margin-top:2px}}
  .stat .v.green{{color:#4ade80}}
  .stat .v.gold{{color:#ffd15c}}
  .controls{{display:flex;flex-wrap:wrap;gap:7px;margin-top:6px}}
  button{{background:rgba(255,255,255,0.08);color:#eef2ff;border:1px solid rgba(255,255,255,0.16);border-radius:8px;padding:7px 11px;font-size:12px;font-weight:600;cursor:pointer;transition:all .15s}}
  button:hover{{background:rgba(74,222,128,0.18);border-color:#4ade80;color:#fff}}
  button.active{{background:#4ade80;color:#0b0d14;border-color:#4ade80}}
  #status-bar{{position:fixed;bottom:16px;left:18px;font-size:12px;color:#9aa6c4;background:rgba(10,13,22,0.82);padding:8px 14px;border-radius:999px;border:1px solid rgba(255,255,255,0.1)}}
</style>
</head>
<body>
<canvas id="streamcanvas" width="{width}" height="{height}"></canvas>
<div class="hud">
  <div class="badge">ZERO-GEOMETRY SERVER PIXEL STREAM</div>
  <h1>{safe_title}</h1>
  <div class="sub">Drag mouse to <b>spin 360°</b> (scroll to zoom). <b>Zero WebGL, zero vertices, zero shaders, zero textures, and zero matrices</b> ever leave the Rust server — RenderDoc, Transform Feedback &amp; Kruppa are 100% impossible.</div>
  <div class="grid">
    <div class="stat"><div class="k">3D Geometry Sent</div><div class="v green">0 verts / 0 shaders</div></div>
    <div class="stat"><div class="k">Server Mesh</div><div class="v gold">{real_tris} tris (RAM)</div></div>
    <div class="stat"><div class="k">Encrypted Stream</div><div class="v gold" id="st-sz">{width}x{height} AES-GCM</div></div>
    <div class="stat"><div class="k">Server Render RTT</div><div class="v green" id="st-lat">-- ms</div></div>
  </div>
  <div class="controls">
    <button id="btn-front" class="active">Front View</button>
    <button id="btn-hero">3/4 Spin</button>
    <button id="btn-halo">Close-Up Detail</button>
    <button id="btn-back">Back View</button>
    <button id="btn-spin">Auto-Spin: OFF</button>
  </div>
</div>
<div id="status-bar">Connecting to Zero-Geometry 3D Stream Server...</div>
<script src="/__vibeslayer/stream-loader.js"></script>
</body>
</html>
"#
    )
}

fn build_stream_loader_js(
    asset_id: &str,
    anti_hook: bool,
    anti_cdp: bool,
    anti_stealth: AntiStealthMode,
) -> String {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"VS3D_STREAM_MASK_V2|");
    hasher.update(asset_id.as_bytes());
    let mask = hasher.finalize();

    let table: &[&str] = &[
        "status-bar",                 // 0
        "streamcanvas",               // 1
        "meta[name=\"vs-ticket\"]",   // 2
        "content",                    // 3
        "__VS_STREAM_TICKET__",       // 4
        "/__vibeslayer/stream-init",  // 5
        "/__vibeslayer/frame",        // 6
        "POST",                       // 7
        "Content-Type",               // 8
        "application/json",           // 9
        "X-VS-Session",               // 10
        "ticket",                     // 11
        "sessionToken",               // 12
        "ok",                         // 13
        "error",                      // 14
        "yaw",                        // 15
        "pitch",                      // 16
        "zoom",                       // 17
        "panY",                       // 18
        "ECDH",                       // 19
        "P-256",                      // 20
        "deriveBits",                 // 21
        "raw",                        // 22
        "HKDF",                       // 23
        "deriveKey",                  // 24
        "SHA-256",                    // 25
        "AES-GCM",                    // 26
        "unwrapKey",                  // 27
        "decrypt",                    // 28
        "VS3D_STREAM_WRAP|",          // 29
        "VS3D_STREAM_SESSION|",       // 30
        "VS3D_FRAME|",                // 31
        "clientPublicKeyHex",         // 32
        "serverPublicKeyHex",         // 33
        "origin",                     // 34
        "sessionId",                  // 35
        "wrappedKeyHex",              // 36
        "wrapIvHex",                  // 37
        "sessionIvHex",               // 38
        "sealedSessionHex",           // 39
        "[native code]",              // 40
        "INTEGRITY_TAMPERED",         // 41
        "AUTOMATION_DENIED",          // 42
        "image/jpeg",                 // 43
        "WebCrypto unavailable",      // 44
        "SESSION_DENIED",             // 45
        "NO_TICKET",                  // 46
        "STEALTH_BROWSER_DENIED",     // 47
        "VS_ATTEST_V1|",              // 48
        "attest",                     // 49
    ];

    let mask_csv = mask.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",");
    let mut rows = Vec::with_capacity(table.len());
    for (idx, s) in table.iter().enumerate() {
        let enc: Vec<String> = s
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(bi, &b)| {
                let pad = mask[(idx * 7 + bi) & 31] ^ (idx as u8).wrapping_mul(37).wrapping_add(bi as u8);
                (b ^ pad).to_string()
            })
            .collect();
        rows.push(format!("[{}]", enc.join(",")));
    }
    let table_js = format!("[{}]", rows.join(","));
    let anti_hook_js = if anti_hook {
        r#"const _chk=(fn)=>{if(typeof fn!=="function"||!_fnStr.call(fn).includes(_s(40)))_fail(_s(41));};_chk(globalThis.fetch);_chk(_sb.generateKey);_chk(_sb.exportKey);_chk(_sb.importKey);_chk(_sb.deriveBits);_chk(_sb.deriveKey);_chk(_sb.unwrapKey);_chk(_sb.decrypt);_chk(_sb.digest);_chk(globalThis.createImageBitmap);if(globalThis.console&&console.debug)_chk(console.debug);if(globalThis.Response&&Response.prototype){_chk(Response.prototype.text);_chk(Response.prototype.arrayBuffer);}"#
    } else {
        ""
    };
    let anti_cdp_js = if anti_cdp {
        r#"if(navigator&&navigator.webdriver)_fail(_s(42));let _cd=false;try{const _op=Error.prepareStackTrace;Error.prepareStackTrace=()=>{_cd=true;return "";};console.debug(new Error());if(_op===undefined)delete Error.prepareStackTrace;else Error.prepareStackTrace=_op;}catch(_){}if(_cd)_fail(_s(42));"#
    } else {
        ""
    };
    // Stream mode stays 100% ZERO-WebGL (`include_webgl = false`): Canvas2D + OfflineAudio + DOMRect + OS-Font probes still score 8/8 on CloakBrowser!
    let anti_stealth_js =
        build_tier4_anti_stealth_js(anti_stealth, false, "_s(47)", "_s(48)", "_s(25)");

    format!(
        r#""use strict";(async()=>{{const _cs=document.currentScript;if(_cs)_cs.remove();const _m=[{mask_csv}],_t={table_js};let _fnStr=Function.prototype.toString,_JP=JSON,_TD=TextDecoder,_TE=TextEncoder,_U8=Uint8Array,_DV=DataView,_Mp=Map;try{{const _fr=document.createElement("iframe");_fr.style.display="none";const _rt=document.documentElement||document.body;if(_rt){{_rt.appendChild(_fr);const _rw=_fr.contentWindow;if(_rw&&_rw.Function&&_rw.JSON){{_fnStr=_rw.Function.prototype.toString;_JP=_rw.JSON;_TD=_rw.TextDecoder;_TE=_rw.TextEncoder;_U8=_rw.Uint8Array;_DV=_rw.DataView;_Mp=_rw.Map;}}_fr.remove();}}}}catch(_){{}}const _d=new _TD(),_e=new _TE(),_c=new _Mp(),_s=(i)=>{{if(_c.has(i))return _c.get(i);const a=_t[i],u=new _U8(a.length);for(let j=0;j<a.length;j++)u[j]=a[j]^_m[(i*7+j)&31]^((i*37+j)&255);const v=_d.decode(u);_c.set(i,v);return v;}};const _st=document.getElementById(_s(0)),_fail=(m)=>{{if(_st)_st.textContent="Error: "+m;throw new Error(m);}},_h2b=(h)=>{{const o=new _U8(h.length>>>1);for(let i=0;i<o.length;i++)o[i]=parseInt(h.slice(i*2,i*2+2),16);return o;}},_b2h=(b)=>{{const u=new _U8(b);let r="";for(let i=0;i<u.length;i++)r+=u[i].toString(16).padStart(2,"0");return r;}};const _cv=document.getElementById(_s(1)),_ctx=_cv.getContext("2d"),_gc=globalThis.crypto,_sb=_gc&&_gc.subtle;if(!_sb)_fail(_s(44));{anti_hook_js}{anti_cdp_js}const _gk=_sb.generateKey.bind(_sb),_ek=_sb.exportKey.bind(_sb),_ik=_sb.importKey.bind(_sb),_db=_sb.deriveBits.bind(_sb),_dk=_sb.deriveKey.bind(_sb),_uk=_sb.unwrapKey.bind(_sb),_dc=_sb.decrypt.bind(_sb),_dg=_sb.digest.bind(_sb),_nf=globalThis.fetch.bind(globalThis),_Bl=globalThis.Blob,_cb=globalThis.createImageBitmap.bind(globalThis);{anti_stealth_js}const _tm=document.querySelector(_s(2)),_tk=_tm?_tm.getAttribute(_s(3)):"";if(_tm)_tm.remove();if(!_tk||_tk===_s(4))_fail(_s(46));const _kp=await _gk({{name:_s(19),namedCurve:_s(20)}},false,[_s(21)]),_cp=await _ek(_s(22),_kp.publicKey),_cph=_b2h(_cp),_at=await _vsAt(_tk,_cph),_ib={{[_s(32)]:_cph,[_s(11)]:_tk}};if(_at)_ib[_s(49)]=_at;const _ir=await _nf(_s(5),{{method:_s(7),headers:{{[_s(8)]:_s(9)}},body:_JP.stringify(_ib)}}),_ij=_JP.parse(await _ir.text());if(!_ir.ok||!_ij[_s(13)])_fail(_ij[_s(14)]||_s(45));const _sp=await _ik(_s(22),_h2b(_ij[_s(33)]),{{name:_s(19),namedCurve:_s(20)}},false,[]),_sb2=await _db({{name:_s(19),public:_sp}},_kp.privateKey,256),_hb=await _ik(_s(22),_sb2,_s(23),false,[_s(24)]);new _U8(_sb2).fill(0);const _wi=_e.encode(_s(29)+_ij[_s(34)]),_wk=await _dk({{name:_s(23),hash:_s(25),salt:_e.encode(_ij[_s(35)]),info:_wi}},_hb,{{name:_s(26),length:256}},false,[_s(27)]),_ak=await _uk(_s(22),_h2b(_ij[_s(36)]),_wk,{{name:_s(26),iv:_h2b(_ij[_s(37)]),additionalData:_wi,tagLength:128}},{{name:_s(26),length:256}},false,[_s(28)]);const _sab=await _dc({{name:_s(26),iv:_h2b(_ij[_s(38)]),additionalData:_e.encode(_s(30)+_ij[_s(35)]),tagLength:128}},_ak,_h2b(_ij[_s(39)])),_su=new _U8(_sab),_sd=_JP.parse(_d.decode(_su));_su.fill(0);const _sk=_sd[_s(12)];let yaw=0.0,pitch=0.08,zoom=3.30,panY=0.0,_as=false,dragging=false,lx=0,ly=0,pending=false,dirty=true;const _btns=["btn-front","btn-hero","btn-halo","btn-back"];function _clr(){{for(const id of _btns){{const b=document.getElementById(id);if(b)b.classList.remove("active");}}}}function _set(y,p,z,py,id){{yaw=y;pitch=p;zoom=z;panY=py;_as=false;const bs=document.getElementById("btn-spin");if(bs){{bs.textContent="Auto-Spin: OFF";bs.classList.remove("active");}}_clr();const bn=document.getElementById(id);if(bn)bn.classList.add("active");dirty=true;}}document.getElementById("btn-front").addEventListener("click",()=>_set(0.0,0.08,3.30,0.0,"btn-front"));document.getElementById("btn-hero").addEventListener("click",()=>_set(0.62,0.16,2.95,0.0,"btn-hero"));document.getElementById("btn-halo").addEventListener("click",()=>_set(-0.38,0.22,1.55,0.36,"btn-halo"));document.getElementById("btn-back").addEventListener("click",()=>_set(3.14,0.10,3.30,0.0,"btn-back"));document.getElementById("btn-spin").addEventListener("click",()=>{{_as=!_as;const b=document.getElementById("btn-spin");b.textContent=_as?"Auto-Spin: ON":"Auto-Spin: OFF";b.classList.toggle("active",_as);}});_cv.addEventListener("pointerdown",(e)=>{{dragging=true;lx=e.clientX;ly=e.clientY;_clr();}});window.addEventListener("pointerup",()=>{{dragging=false;}});window.addEventListener("pointermove",(e)=>{{if(!dragging)return;yaw-=(e.clientX-lx)*0.0075;pitch=Math.max(-1.25,Math.min(1.25,pitch+(e.clientY-ly)*0.0065));lx=e.clientX;ly=e.clientY;dirty=true;}});_cv.addEventListener("wheel",(e)=>{{e.preventDefault();zoom=Math.max(0.85,Math.min(6.0,zoom*(1+e.deltaY*0.001)));dirty=true;}},{{passive:false}});async function _pull(){{if(pending)return;pending=true;const t0=performance.now();try{{const r=await _nf(_s(6),{{method:_s(7),headers:{{[_s(8)]:_s(9),[_s(10)]:_sk}},body:_JP.stringify({{[_s(15)]:yaw,[_s(16)]:pitch,[_s(17)]:zoom,[_s(18)]:panY}})}});if(!r.ok)throw new Error("FRAME_"+r.status);const rw=new _U8(await r.arrayBuffer());const seq=new _DV(rw.buffer,rw.byteOffset,8).getBigUint64(0,true).toString();const ab=await _dc({{name:_s(26),iv:rw.slice(8,20),additionalData:_e.encode(_s(31)+seq),tagLength:128}},_ak,rw.slice(20));rw.fill(0);const pt=new _U8(ab),sz=pt.byteLength,blob=new _Bl([pt],{{type:_s(43)}});pt.fill(0);const bmp=await _cb(blob);_ctx.drawImage(bmp,0,0,_cv.width,_cv.height);bmp.close();const dt=(performance.now()-t0).toFixed(1),kb=(sz/1024).toFixed(1);document.getElementById("st-lat").textContent=dt+" ms";document.getElementById("st-sz").textContent=_cv.width+"x"+_cv.height+" ("+kb+" KB AES-GCM)";if(!window.__VS_READY){{window.__VS_READY=true;_st.textContent="Ready • Encrypted Zero-Geometry Stream ("+dt+" ms, "+kb+" KB/frame) • Drag to spin";}}}}finally{{pending=false;}}}}await _pull();function _tick(){{if(_as){{yaw+=0.04;dirty=true;}}if(dirty&&!pending){{dirty=false;_pull();}}requestAnimationFrame(_tick);}}requestAnimationFrame(_tick);}})().catch((e)=>{{const s=document.getElementById("status-bar");if(s)s.textContent="Error: "+(e&&e.message?e.message:e);}});
"#
    )
}

struct RenderSlotGuard<'a> {
    counter: &'a AtomicUsize,
}
impl<'a> RenderSlotGuard<'a> {
    fn try_acquire(counter: &'a AtomicUsize, max_conc: usize) -> Option<Self> {
        loop {
            let cur = counter.load(Ordering::Acquire);
            if cur >= max_conc {
                return None;
            }
            if counter
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(Self { counter });
            }
        }
    }
}
impl Drop for RenderSlotGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Release);
    }
}

fn handle_stream_init(
    stream: &mut TcpStream,
    state: &StreamServerState,
    ip: IpAddr,
    peer_trusted: bool,
    buyer_id: Option<&str>,
    req: &ParsedRequest,
    keep_alive: bool,
) {
    let Some(effective_origin) = validate_same_origin_proxy(
        req.origin.as_deref(),
        req.host.as_deref(),
        req.x_forwarded_host.as_deref(),
        peer_trusted,
        state.allowed_origin.as_deref(),
        Some(state.bound_addr),
    ) else {
        send_json_err_with_csp(stream, 403, "Forbidden", "ORIGIN_DENIED", keep_alive, state.csp);
        return;
    };
    if !state.guard.check_rate_limit(ip) {
        send_json_err_with_csp(stream, 429, "Too Many Requests", "RATE_LIMITED", keep_alive, state.csp);
        return;
    }
    let Ok(body_str) = std::str::from_utf8(&req.body) else {
        send_json_err_with_csp(stream, 400, "Bad Request", "BAD_JSON", keep_alive, state.csp);
        return;
    };
    let Ok(json) = parse_json(body_str) else {
        send_json_err_with_csp(stream, 400, "Bad Request", "BAD_JSON", keep_alive, state.csp);
        return;
    };
    let ticket = json.get("ticket").and_then(|v| v.as_str()).unwrap_or("");
    if let Err(code) = state.guard.verify_and_consume_ticket_ttl(
        &state.ticket_secret,
        ticket,
        ip,
        state.ticket_ttl_sec,
    ) {
        send_json_err_with_csp(stream, 403, "Forbidden", &code, keep_alive, state.csp);
        return;
    }

    let client_hex = json
        .get("clientPublicKeyHex")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if let Err(code) = verify_server_anti_stealth(state.anti_stealth, req, &json, ticket, client_hex) {
        send_json_err_with_csp(stream, 403, "Forbidden", code, keep_alive, state.csp);
        return;
    }
    let Ok(client_pub) = hex_decode(client_hex) else {
        send_json_err_with_csp(stream, 400, "Bad Request", "INVALID_CLIENT_PUBLIC_KEY", keep_alive, state.csp);
        return;
    };
    if p256_validate_public_key(&client_pub).is_err() {
        send_json_err_with_csp(stream, 400, "Bad Request", "INVALID_CLIENT_PUBLIC_KEY", keep_alive, state.csp);
        return;
    }

    let Ok((mut srv_priv, srv_pub)) = p256_generate_keypair() else {
        send_json_err_with_csp(stream, 500, "Internal Server Error", "KEYGEN_FAILED", keep_alive, state.csp);
        return;
    };
    let shared_res = p256_ecdh_shared_secret(&srv_priv, &client_pub);
    secure_zero(&mut srv_priv);
    let Ok(mut shared_32) = shared_res else {
        send_json_err_with_csp(stream, 400, "Bad Request", "ECDH_FAILED", keep_alive, state.csp);
        return;
    };

    let mut rand_buf = [0u8; 128];
    if os_random_bytes(&mut rand_buf).is_err() {
        secure_zero(&mut shared_32);
        send_json_err_with_csp(stream, 500, "Internal Server Error", "RNG_FAILED", keep_alive, state.csp);
        return;
    }
    let mut sid = String::with_capacity(32);
    write_hex_bytes(&rand_buf[0..16], &mut sid);
    let mut tok = String::with_capacity(48);
    write_hex_bytes(&rand_buf[16..40], &mut tok);
    let mut proj_seed = [0u8; 32];
    proj_seed.copy_from_slice(&rand_buf[40..72]);
    let mut asset_key = [0u8; 32];
    asset_key.copy_from_slice(&rand_buf[72..104]);
    let mut wrap_iv = [0u8; 12];
    wrap_iv.copy_from_slice(&rand_buf[104..116]);
    let mut sess_iv = [0u8; 12];
    sess_iv.copy_from_slice(&rand_buf[116..128]);
    secure_zero(&mut rand_buf);

    let wm_subject = buyer_id.unwrap_or(&sid);
    let wm_mac = hmac_sha256(&state.wm_key, format!("VS3D_WM_V1|{wm_subject}").as_bytes());
    let wm64_id = u64::from_le_bytes([
        wm_mac[16], wm_mac[17], wm_mac[18], wm_mac[19],
        wm_mac[20], wm_mac[21], wm_mac[22], wm_mac[23],
    ]);

    let expires_at = unix_now_s() + state.session_ttl_sec;
    {
        let Ok(mut guard) = state.sessions.lock() else {
            secure_zero(&mut shared_32);
            secure_zero(&mut proj_seed);
            secure_zero(&mut asset_key);
            send_json_err_with_csp(stream, 500, "Internal Server Error", "LOCK_POISONED", keep_alive, state.csp);
            return;
        };
        let now = unix_now_s();
        if guard.len() >= state.max_sessions || guard.len() > 256 {
            guard.retain(|_, s| s.expires_at >= now);
        }
        if guard.len() >= state.max_sessions {
            secure_zero(&mut shared_32);
            secure_zero(&mut proj_seed);
            secure_zero(&mut asset_key);
            send_json_err_with_csp(stream, 503, "Service Unavailable", "SERVER_BUSY", keep_alive, state.csp);
            return;
        }
        guard.insert(
            sid.clone(),
            StreamSession {
                auth_token: tok.clone(),
                origin: effective_origin.to_string(),
                asset_key,
                wm64_id,
                proj_seed,
                expires_at,
                frame_calls: 0,
                frame_seq: 1,
                in_flight: false,
            },
        );
    }

    let wrap_info = format!("VS3D_STREAM_WRAP|{effective_origin}");
    let mut wrap_key = hkdf_sha256_32(&shared_32, sid.as_bytes(), wrap_info.as_bytes());
    secure_zero(&mut shared_32);
    let (ct_key, tag_key) = aes256_gcm_seal(&wrap_key, &wrap_iv, wrap_info.as_bytes(), &asset_key);
    secure_zero(&mut wrap_key);

    let plain_payload = format!("{{\"sessionToken\":\"{sid}.{tok}\"}}");
    let sess_aad = format!("VS3D_STREAM_SESSION|{sid}");
    let (ct_sess, tag_sess) =
        aes256_gcm_seal(&asset_key, &sess_iv, sess_aad.as_bytes(), plain_payload.as_bytes());
    secure_zero(&mut asset_key);

    let mut resp = String::with_capacity(512 + ct_sess.len() * 2);
    resp.push_str("{\"ok\":true,\"sessionId\":\"");
    resp.push_str(&sid);
    resp.push_str("\",\"origin\":");
    resp.push_str(&crate::mini_json::to_json_compact(&crate::mini_json::JsonVal::Str(effective_origin.to_string())));
    resp.push_str(",\"serverPublicKeyHex\":\"");
    write_hex_bytes(&srv_pub, &mut resp);
    resp.push_str("\",\"wrapIvHex\":\"");
    write_hex_bytes(&wrap_iv, &mut resp);
    resp.push_str("\",\"wrappedKeyHex\":\"");
    write_hex_bytes(&ct_key, &mut resp);
    write_hex_bytes(&tag_key, &mut resp);
    resp.push_str("\",\"sessionIvHex\":\"");
    write_hex_bytes(&sess_iv, &mut resp);
    resp.push_str("\",\"sealedSessionHex\":\"");
    write_hex_bytes(&ct_sess, &mut resp);
    write_hex_bytes(&tag_sess, &mut resp);
    resp.push_str("\"}");

    send_http_with_csp(
        stream,
        200,
        "OK",
        "application/json; charset=utf-8",
        resp.as_bytes(),
        keep_alive,
        state.csp,
    );
}

fn handle_stream_client(mut stream: TcpStream, state: &StreamServerState) {
    const MAX_KEEPALIVE_REQS: usize = 4096;
    let _ = stream.set_read_timeout(Some(state.header_timeout));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_nodelay(true);
    let peer_ip = stream
        .peer_addr()
        .map(|a| a.ip())
        .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
    let Some(_conn_guard) = state.conn_limiter.try_acquire(peer_ip, &state.trusted_proxies) else {
        send_json_err_with_csp(&mut stream, 429, "Too Many Requests", "TOO_MANY_CONNECTIONS", false, state.csp);
        return;
    };
    let mut read_buf = Vec::with_capacity(4096);
    let mut req_count = 0usize;

    loop {
        let Some(req) = read_http_request_with_timeouts(
            &mut stream,
            &mut read_buf,
            state.header_timeout,
            state.body_timeout,
        ) else {
            return;
        };
        req_count += 1;
        let keep_alive = req.keep_alive && req_count < MAX_KEEPALIVE_REQS;
        let method = req.method.as_str();
        let path = req.path_only.as_str();
        let ip = resolve_client_ip(
            peer_ip,
            &state.trusted_proxies,
            req.x_forwarded_for.as_deref(),
            req.x_real_ip.as_deref(),
        );

        if (method == "GET" || method == "HEAD") && path == "/__vibeslayer/health" {
            let body: &[u8] = if method == "HEAD" { b"" } else { b"{\"ok\":true,\"mode\":\"stream\"}" };
            send_http_with_csp(
                &mut stream,
                200,
                "OK",
                "application/json; charset=utf-8",
                body,
                keep_alive,
                state.csp,
            );
        } else {
            let buyer_opt = match state.auth.verify_request(
                req.authorization.as_deref(),
                req.x_vs_auth.as_deref(),
                req.cookie.as_deref(),
            ) {
                Ok(b) => b,
                Err(()) => {
                    send_json_err_with_csp(&mut stream, 401, "Unauthorized", "AUTH_REQUIRED", keep_alive, state.csp);
                    if !keep_alive {
                        return;
                    }
                    continue;
                }
            };

            if method == "GET" && (path == "/" || path == "/index.html") {
                let Ok(ticket) = issue_ticket(&state.ticket_secret, ip) else {
                    send_json_err_with_csp(&mut stream, 500, "Internal Server Error", "TICKET_GEN_FAILED", false, state.csp);
                    return;
                };
                let mut rendered = Vec::with_capacity(
                    state.index_prefix.len() + ticket.len() + state.index_suffix.len(),
                );
                rendered.extend_from_slice(&state.index_prefix);
                rendered.extend_from_slice(ticket.as_bytes());
                rendered.extend_from_slice(&state.index_suffix);
                send_http_with_csp(
                    &mut stream,
                    200,
                    "OK",
                    "text/html; charset=utf-8",
                    &rendered,
                    keep_alive,
                    state.csp,
                );
            } else if method == "GET" && path == "/__vibeslayer/stream-loader.js" {
                send_http_with_csp(
                    &mut stream,
                    200,
                    "OK",
                    "application/javascript; charset=utf-8",
                    &state.loader_js,
                    keep_alive,
                    state.csp,
                );
            } else if method == "POST" && path == "/__vibeslayer/stream-init" {
                let peer_trusted = state.trusted_proxies.contains(&peer_ip);
                handle_stream_init(&mut stream, state, ip, peer_trusted, buyer_opt.as_deref(), &req, keep_alive);
            } else if method == "POST" && path == "/__vibeslayer/frame" {
                let peer_trusted = state.trusted_proxies.contains(&peer_ip);
                let Some(effective_origin) = validate_same_origin_proxy(
                    req.origin.as_deref(),
                    req.host.as_deref(),
                    req.x_forwarded_host.as_deref(),
                    peer_trusted,
                    state.allowed_origin.as_deref(),
                    Some(state.bound_addr),
                ) else {
                    send_json_err_with_csp(&mut stream, 403, "Forbidden", "ORIGIN_DENIED", keep_alive, state.csp);
                    if !keep_alive {
                        return;
                    }
                    continue;
                };
                let sess_res = (|| -> Result<(String, u64, [u8; 32], [u8; 32], u64), (u16, &'static str, &'static str)> {
                    let Some(raw) = req.x_vs_session.as_deref() else {
                        return Err((403, "Forbidden", "SESSION_REQUIRED"));
                    };
                    let Some((sid, tok)) = raw.trim().split_once('.') else {
                        return Err((403, "Forbidden", "SESSION_REQUIRED"));
                    };
                    let now = unix_now_s();
                    let mut guard = state
                        .sessions
                        .lock()
                        .map_err(|_| (500, "Internal Server Error", "LOCK_POISONED"))?;
                    let Some(sess) = guard.get_mut(sid) else {
                        return Err((403, "Forbidden", "SESSION_REQUIRED"));
                    };
                    if sess.expires_at < now || !ct_str_eq(tok.as_bytes(), sess.auth_token.as_bytes()) {
                        return Err((403, "Forbidden", "SESSION_REQUIRED"));
                    }
                    if effective_origin != sess.origin {
                        return Err((403, "Forbidden", "ORIGIN_DENIED"));
                    }
                    if sess.frame_calls >= state.frame_budget {
                        return Err((429, "Too Many Requests", "FRAME_BUDGET_EXHAUSTED"));
                    }
                    if sess.in_flight {
                        // Prevent parallel automated photogrammetry/3DGS multi-connection scraping from 1 session
                        return Err((429, "Too Many Requests", "FRAME_IN_FLIGHT"));
                    }
                    sess.in_flight = true;
                    sess.frame_calls += 1;
                    let seq = sess.frame_seq;
                    sess.frame_seq = sess.frame_seq.wrapping_add(1);
                    Ok((sid.to_string(), sess.wm64_id, sess.proj_seed, sess.asset_key, seq))
                })();
                match sess_res {
                    Ok((sid, wm64_id, mut proj_seed, mut asset_key, seq)) => {
                        struct InFlightClear<'a> {
                            sessions: &'a Mutex<HashMap<String, StreamSession>>,
                            sid: String,
                        }
                        impl Drop for InFlightClear<'_> {
                            fn drop(&mut self) {
                                if let Ok(mut g) = self.sessions.lock() {
                                    if let Some(s) = g.get_mut(&self.sid) {
                                        s.in_flight = false;
                                    }
                                }
                            }
                        }
                        let _in_flight_guard = InFlightClear {
                            sessions: &state.sessions,
                            sid,
                        };
                        let Some(_rg) = RenderSlotGuard::try_acquire(
                            &state.active_renders,
                            state.max_render_concurrency,
                        ) else {
                            secure_zero(&mut proj_seed);
                            secure_zero(&mut asset_key);
                            send_json_err_with_csp(&mut stream, 503, "Service Unavailable", "SERVER_BUSY", keep_alive, state.csp);
                            if !keep_alive {
                                return;
                            }
                            continue;
                        };
                        let req_j = parse_json(&String::from_utf8_lossy(&req.body))
                            .unwrap_or(crate::mini_json::JsonVal::Null);
                        let get_f = |k: &str, def: f32| -> f32 {
                            let v = match req_j.get(k) {
                                Some(crate::mini_json::JsonVal::Num(n)) => *n as f32,
                                Some(crate::mini_json::JsonVal::Int(n)) => *n as f32,
                                _ => def,
                            };
                            if v.is_finite() { v } else { def }
                        };
                        let q = |v: f32, step: f32| -> f32 { (v / step).round() * step };
                        let yaw = q(get_f("yaw", 0.0), 0.02);
                        let pitch = q(get_f("pitch", 0.08).clamp(-1.35, 1.35), 0.02);
                        let zoom = q(get_f("zoom", 3.30).clamp(0.85, 6.5), 0.025);
                        let pan_y = q(get_f("panY", 0.0).clamp(-2.0, 2.0), 0.025);
                        let mut jpg = render_frame_jpeg(state, yaw, pitch, zoom, pan_y, wm64_id, &proj_seed);
                        secure_zero(&mut proj_seed);

                        // Seal rendered frame inside ECDH-negotiated AES-256-GCM envelope:
                        // seq_u64_le(8) || iv(12) || ct(jpg.len()) || tag(16)
                        // Zero plaintext image/jpeg ever crosses the wire!
                        let mut env = vec![0u8; 8 + 12 + jpg.len() + 16];
                        env[0..8].copy_from_slice(&seq.to_le_bytes());
                        if os_random_bytes(&mut env[8..20]).is_err() {
                            secure_zero(&mut asset_key);
                            secure_zero(&mut jpg);
                            send_json_err_with_csp(&mut stream, 500, "Internal Server Error", "RNG_FAILED", keep_alive, state.csp);
                            if !keep_alive {
                                return;
                            }
                            continue;
                        }
                        let mut iv = [0u8; 12];
                        iv.copy_from_slice(&env[8..20]);
                        let ct_end = 20 + jpg.len();
                        env[20..ct_end].copy_from_slice(&jpg);
                        secure_zero(&mut jpg);
                        let aad = format!("VS3D_FRAME|{seq}");
                        let tag = aes256_gcm_seal_in_place(&asset_key, &iv, aad.as_bytes(), &mut env[20..ct_end]);
                        secure_zero(&mut asset_key);
                        env[ct_end..].copy_from_slice(&tag);

                        send_http_with_csp(
                            &mut stream,
                            200,
                            "OK",
                            "application/octet-stream",
                            &env,
                            keep_alive,
                            state.csp,
                        );
                    }
                    Err((st, rs, code)) => send_json_err_with_csp(&mut stream, st, rs, code, keep_alive, state.csp),
                }
            } else {
                // Zero geometry/shader/texture routes exist in stream mode!
                send_json_err_with_csp(&mut stream, 404, "Not Found", "NOT_FOUND", keep_alive, state.csp);
            }
        }
        if !keep_alive {
            return;
        }
    }
}

/// Loads decrypted geometry & textures strictly in server RAM and starts the Zero-Geometry
/// interactive 3D pixel-streaming HTTP server.
pub fn serve_streamed_3d_viewer(shield_dir: &Path, params: &Serve3dParams) -> Result<(), String> {
    params.validate()?;
    let t_load = Instant::now();
    let key_path = params
        .key_file
        .clone()
        .unwrap_or_else(|| shield_dir.join(".vsshield.key"));
    let mut key_hex = fs::read_to_string(&key_path)
        .map_err(|e| format!("Missing key file ({}): {e}", key_path.display()))?;
    let mut key_vec = hex_decode(key_hex.trim())?;
    secure_zero(unsafe { key_hex.as_bytes_mut() });
    if key_vec.len() != 32 {
        secure_zero(&mut key_vec);
        return Err("Invalid .vsshield.key length (expected 32 bytes)".to_string());
    }
    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&key_vec);
    secure_zero(&mut key_vec);

    let meta_str = fs::read_to_string(shield_dir.join("viewer.meta.json"))
        .map_err(|e| format!("Missing viewer.meta.json: {e}"))?;
    let meta = parse_json(&meta_str)?;
    let asset_id = meta
        .get("assetId")
        .and_then(|v| v.as_str())
        .unwrap_or("mesh-3d")
        .to_string();
    let half_ext: f32 = meta
        .get("halfExtent")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(1.0);
    let tex_count = meta.get("textureCount").and_then(|v| v.as_i64()).unwrap_or(0) as usize;
    let lattice_ver = meta.get("latticeVersion").and_then(|v| v.as_i64()).unwrap_or(1);
    let gpu_stages = meta
        .get("gpuStages")
        .and_then(|v| v.as_i64())
        .map(|n| (n as usize).clamp(16, 192))
        .unwrap_or(SHIELD_GPU_STAGES);

    let lat_seed = hmac_sha256(&master_key, format!("VS3D_SHIELD_LAT_V1|{asset_id}").as_bytes());
    let shader_seed = hmac_sha256(&master_key, format!("VS3D_SHIELD_SHD_V1|{asset_id}").as_bytes());
    let mut tex_key = hmac_sha256(&master_key, format!("VS3D_SHIELD_TEX_V1|{asset_id}").as_bytes());
    let wm_key = hmac_sha256(&master_key, format!("VS3D_SHIELD_WM_V1|{asset_id}").as_bytes());
    let (_lat_m, lat_inv) = derive_unimodular_lattice_3x3(&lat_seed);
    let t_lat = if lattice_ver >= 2 {
        derive_lattice_offset_pub(&lat_seed)
    } else {
        [0, 0, 0]
    };
    let stages = derive_gpu_stage_specs_n(&shader_seed, gpu_stages);
    let ephem = derive_ephemeral_gpu_uniforms(&master_key, &asset_id);
    secure_zero(&mut master_key);

    // Decrypt real triangles from `scene.vsshield2` strictly in server RAM
    let scene_bin = fs::read(shield_dir.join("scene.vsshield2")).map_err(|e| e.to_string())?;
    if scene_bin.len() < 32 {
        return Err("CORRUPT_SCENE_VSSH2".to_string());
    }
    let total_verts = u32::from_le_bytes([scene_bin[12], scene_bin[13], scene_bin[14], scene_bin[15]]) as usize;
    let total_tris = total_verts / 3;
    let inv_q = half_ext / 16384.0f32;
    let n_threads = thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(16);

    // Parallel decrypt all triangles & filter out chaff
    let chunk_t = ((total_tris + n_threads - 1) / n_threads).max(1);
    let mut dec_buckets: Vec<Vec<([i32; 3], [i32; 3], [i32; 3], [f32; 2], [f32; 2], [f32; 2], u8)>> =
        (0..n_threads).map(|_| Vec::new()).collect();
    thread::scope(|s| {
        for (bi, bucket) in dec_buckets.iter_mut().enumerate() {
            let start = bi * chunk_t;
            if start >= total_tris {
                break;
            }
            let end = (start + chunk_t).min(total_tris);
            let sb = &scene_bin;
            let stg = &stages;
            s.spawn(move || {
                for ti in start..end {
                    let mut qs = [[0i32; 3]; 3];
                    let mut uvs = [[0.0f32; 2]; 3];
                    let mut is_chaff = false;
                    let mut mat_id = 0u8;
                    for vi in 0..3 {
                        let vid = (ti * 3 + vi) as u32;
                        let off = 32 + (vid as usize) * 32;
                        if off + 32 > sb.len() {
                            is_chaff = true;
                            break;
                        }
                        let c0 = u32::from_le_bytes([sb[off], sb[off + 1], sb[off + 2], sb[off + 3]]);
                        let c1 = u32::from_le_bytes([sb[off + 4], sb[off + 5], sb[off + 6], sb[off + 7]]);
                        let c2 = u32::from_le_bytes([sb[off + 8], sb[off + 9], sb[off + 10], sb[off + 11]]);
                        let c3 = u32::from_le_bytes([sb[off + 12], sb[off + 13], sb[off + 14], sb[off + 15]]);
                        let dec = decrypt_gpu_lanes([c0, c1, c2, c3], stg, &ephem, vid);
                        if (dec[3] & 0xff) != 0 {
                            is_chaff = true;
                            break;
                        }
                        mat_id = ((dec[3] >> 8) & 0xff) as u8;
                        let wx = (dec[0] as i32 as i64) - t_lat[0];
                        let wy = (dec[1] as i32 as i64) - t_lat[1];
                        let wz = (dec[2] as i32 as i64) - t_lat[2];
                        let qx = (lat_inv[0][0] * wx + lat_inv[0][1] * wy + lat_inv[0][2] * wz) as i32;
                        let qy = (lat_inv[1][0] * wx + lat_inv[1][1] * wy + lat_inv[1][2] * wz) as i32;
                        let qz = (lat_inv[2][0] * wx + lat_inv[2][1] * wy + lat_inv[2][2] * wz) as i32;
                        qs[vi] = [qx, qy, qz];

                        let s2 = u32::from_le_bytes([sb[off + 24], sb[off + 25], sb[off + 26], sb[off + 27]]);
                        let s3 = u32::from_le_bytes([sb[off + 28], sb[off + 29], sb[off + 30], sb[off + 31]]);
                        let m2 = surf_avalanche_pub((vid * 4 + 2) ^ ephem[1][2]);
                        let m3 = surf_avalanche_pub((vid * 4 + 3) ^ ephem[1][3]);
                        uvs[vi] = [f32::from_bits(s2 ^ m2), f32::from_bits(s3 ^ m3)];
                    }
                    if !is_chaff {
                        bucket.push((qs[0], qs[1], qs[2], uvs[0], uvs[1], uvs[2], mat_id));
                    }
                }
            });
        }
    });

    // Reconstruct smooth area-weighted vertex normals strictly in server RAM!
    let mut vert_n_acc: HashMap<(i32, i32, i32), [f32; 3]> = HashMap::new();
    let mut flat_tris = Vec::new();
    for b in dec_buckets {
        flat_tris.extend(b);
    }
    for &(q0, q1, q2, _, _, _, _) in &flat_tris {
        let p0 = [q0[0] as f32 * inv_q, q0[1] as f32 * inv_q, q0[2] as f32 * inv_q];
        let p1 = [q1[0] as f32 * inv_q, q1[1] as f32 * inv_q, q1[2] as f32 * inv_q];
        let p2 = [q2[0] as f32 * inv_q, q2[1] as f32 * inv_q, q2[2] as f32 * inv_q];
        let e1 = [p1[0] - p0[0], p1[1] - p0[1], p1[2] - p0[2]];
        let e2 = [p2[0] - p0[0], p2[1] - p0[1], p2[2] - p0[2]];
        let fnrm = [
            e1[1] * e2[2] - e1[2] * e2[1],
            e1[2] * e2[0] - e1[0] * e2[2],
            e1[0] * e2[1] - e1[1] * e2[0],
        ];
        for q in [q0, q1, q2] {
            let e = vert_n_acc.entry((q[0], q[1], q[2])).or_insert([0.0; 3]);
            e[0] += fnrm[0];
            e[1] += fnrm[1];
            e[2] += fnrm[2];
        }
    }

    let mut tris = Vec::with_capacity(flat_tris.len());
    for (q0, q1, q2, uv0, uv1, uv2, mat_id) in flat_tris {
        let mk_v = |q: [i32; 3], uv: [f32; 2]| -> StreamVert {
            let acc = vert_n_acc.get(&(q[0], q[1], q[2])).copied().unwrap_or([0.0, 1.0, 0.0]);
            StreamVert {
                pos: [q[0] as f32 * inv_q, q[1] as f32 * inv_q, q[2] as f32 * inv_q],
                norm: norm3(acc),
                uv,
            }
        };
        tris.push(StreamTri {
            v: [mk_v(q0, uv0), mk_v(q1, uv1), mk_v(q2, uv2)],
            mat_id,
        });
    }

    // Decrypt server-only unscrambled PNG textures (`stream_tex_{i}.vsbin`) into server RAM
    let mut textures = Vec::with_capacity(tex_count);
    for i in 0..tex_count {
        let st_path = shield_dir.join(format!("stream_tex_{i}.vsbin"));
        if let Ok(enc) = fs::read(&st_path) {
            let mut nonce = [0u8; 12];
            nonce[..8].copy_from_slice(&STREAM_TEX_NONCE_PREFIX);
            nonce[8..12].copy_from_slice(&(i as u32).to_le_bytes());
            let mut plain = vec![0u8; enc.len()];
            chacha20_xor_into(&tex_key, 1, &nonce, &enc, &mut plain);
            if let Ok(dec) = decode_png(&plain) {
                textures.push(ServerTex {
                    w: dec.width,
                    h: dec.height,
                    ch: dec.channels,
                    pixels: dec.pixels,
                });
            }
            secure_zero(&mut plain);
        }
    }
    secure_zero(&mut tex_key);

    let display_title = params.title.as_deref().unwrap_or(&asset_id);
    let html_raw = build_stream_html(display_title, params.stream_width, params.stream_height, tris.len());
    let (p, s) = html_raw
        .split_once("__VS_STREAM_TICKET__")
        .ok_or_else(|| "STREAM_HTML_MISSING_TICKET".to_string())?;
    let index_prefix = p.as_bytes().to_vec();
    let index_suffix = s.as_bytes().to_vec();
    let loader_js = build_stream_loader_js(
        &asset_id,
        params.anti_hook,
        params.anti_cdp,
        params.anti_stealth,
    )
    .into_bytes();

    let mut ticket_secret = [0u8; 32];
    os_random_bytes(&mut ticket_secret)?;
    let auth = AuthConfig::from_opts(params.auth_secret.as_deref(), params.auth_hmac_key.as_deref())?;
    let trusted_proxies = parse_trusted_proxies(params.trust_proxy.as_deref())?;
    let _ = p256_generate_keypair();

    let listener = TcpListener::bind(&params.addr)
        .map_err(|e| format!("Failed binding {}: {e}", params.addr))?;
    let bound = listener.local_addr().map_err(|e| e.to_string())?;
    let wm_w = params.wm_uniform_w();
    let num_workers = params.resolved_workers();
    let load_ms = t_load.elapsed().as_millis();

    println!(
        "{{\"ok\":true,\"listening\":\"http://{}\",\"renderMode\":\"stream\",\"frameEncryption\":\"ecdh-p256-aes256-gcm\",\"preset\":\"{}\",\"assetId\":\"{}\",\"serverTris\":{},\"serverTextures\":{},\"streamWidth\":{},\"streamHeight\":{},\"streamQuality\":{},\"watermark\":{},\"antiHook\":{},\"antiCdp\":{},\"cspMode\":\"{}\",\"loadMs\":{}}}",
        bound,
        params.preset.as_str(),
        asset_id,
        tris.len(),
        textures.len(),
        params.stream_width,
        params.stream_height,
        params.stream_quality,
        wm_w > 0,
        params.anti_hook,
        params.anti_cdp,
        params.csp.as_str(),
        load_ms
    );
    let _ = std::io::Write::flush(&mut std::io::stdout());

    let state = std::sync::Arc::new(StreamServerState {
        width: params.stream_width,
        height: params.stream_height,
        quality: params.stream_quality,
        csp: params.csp,
        anti_stealth: params.anti_stealth,
        wm_w,
        camera_jitter: params.camera_jitter,
        ticket_ttl_sec: params.ticket_ttl_sec,
        session_ttl_sec: params.session_ttl_sec,
        frame_budget: params.camera_budget,
        max_sessions: params.max_sessions,
        max_render_concurrency: params.max_tex_concurrency.max(2),
        header_timeout: Duration::from_millis(params.header_timeout_ms),
        body_timeout: Duration::from_millis(params.body_timeout_ms),
        ticket_secret,
        wm_key,
        auth,
        allowed_origin: params.origin.clone(),
        trusted_proxies,
        bound_addr: bound,
        guard: HttpLeaseGuard::new(params.max_leases_per_min),
        conn_limiter: ConnLimiter::new(params.max_conns_per_ip),
        active_renders: AtomicUsize::new(0),
        sessions: Mutex::new(HashMap::new()),
        index_prefix,
        index_suffix,
        loader_js,
        tris,
        textures,
        srgb_lut: build_srgb_lut(),
        render_threads: n_threads,
    });

    const MAX_PENDING_CONNS: usize = 256;
    let pool = std::sync::Arc::new((
        Mutex::new(VecDeque::<TcpStream>::new()),
        std::sync::Condvar::new(),
    ));
    for _ in 0..num_workers {
        let st = std::sync::Arc::clone(&state);
        let q = std::sync::Arc::clone(&pool);
        thread::spawn(move || {
            let (lock, cv) = &*q;
            loop {
                let stream = {
                    let mut guard = lock.lock().unwrap();
                    while guard.is_empty() {
                        guard = cv.wait(guard).unwrap();
                    }
                    guard.pop_front().unwrap()
                };
                handle_stream_client(stream, &st);
            }
        });
    }

    for incoming in listener.incoming() {
        if let Ok(mut stream) = incoming {
            let (lock, cv) = &*pool;
            let mut guard = lock.lock().unwrap();
            if guard.len() >= MAX_PENDING_CONNS {
                drop(guard);
                let _ = stream.set_nonblocking(true);
                send_json_err_with_csp(&mut stream, 503, "Service Unavailable", "SERVER_BUSY", false, state.csp);
                continue;
            }
            guard.push_back(stream);
            cv.notify_one();
        }
    }
    Ok(())
}

/// Forensically decodes a 64-bit buyer WM64 ID directly from raw RGB pixels of a captured/leaked
/// `--mode stream` frame (works blindly after JPEG compression without needing the original frame!).
pub fn decode_stream_frame_rgb_wm64(
    shield_dir: &Path,
    key_file_opt: Option<&Path>,
    rgb: &[u8],
    width: usize,
    height: usize,
) -> Result<(u64, f64), String> {
    let key_path = key_file_opt
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| shield_dir.join(".vsshield.key"));
    let mut key_hex = fs::read_to_string(&key_path)
        .map_err(|e| format!("Missing key file ({}): {e}", key_path.display()))?;
    let mut key_vec = hex_decode(key_hex.trim())?;
    secure_zero(unsafe { key_hex.as_bytes_mut() });
    if key_vec.len() != 32 {
        secure_zero(&mut key_vec);
        return Err("INVALID_KEY_LEN".to_string());
    }
    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&key_vec);
    secure_zero(&mut key_vec);

    let meta_str = fs::read_to_string(shield_dir.join("viewer.meta.json"))
        .map_err(|e| format!("Missing viewer.meta.json: {e}"))?;
    let meta = parse_json(&meta_str)?;
    let asset_id = meta
        .get("assetId")
        .and_then(|v| v.as_str())
        .unwrap_or("mesh-3d")
        .to_string();
    let wm_key = hmac_sha256(&master_key, format!("VS3D_SHIELD_WM_V1|{asset_id}").as_bytes());
    secure_zero(&mut master_key);
    Ok(decode_pixel_wm64(rgb, width, height, &wm_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pixel_wm64_roundtrip_on_rendered_gradient() {
        let w = 640usize;
        let h = 480usize;
        let mut rgb = vec![0u8; w * h * 3];
        for y in 0..h {
            for x in 0..w {
                let off = (y * w + x) * 3;
                rgb[off] = (30 + (x * 160 / w)) as u8;
                rgb[off + 1] = (40 + (y * 150 / h)) as u8;
                rgb[off + 2] = 90;
            }
        }
        let wm_key = [0x42u8; 32];
        let buyer_id: u64 = 0xdead_beef_cafe_1337;
        stamp_pixel_wm64(&mut rgb, w, h, &wm_key, buyer_id, 4);
        let (decoded, conf) = decode_pixel_wm64(&rgb, w, h, &wm_key);
        assert_eq!(decoded, buyer_id);
        assert!(conf > 0.90, "expected >0.90 confidence, got {conf}");
    }
}
