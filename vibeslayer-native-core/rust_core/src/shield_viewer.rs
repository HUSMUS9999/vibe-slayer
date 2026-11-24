//! Interactive Encrypted-VRAM WebGL2 3D Showcase & Live Camera-Fusion Server (`shield_viewer.rs`).
//! Secures standard glTF 2.0 `.glb` models (meshes, normals, UVs, PBR & emissive textures) with:
//! - Zero CPU/VRAM plaintext 3D vertices (`uvec4` 96-stage polymorphic GPU cipher + 3x3 unimodular lattice)
//! - 37.5% interleaved cryptographic poison/chaff triangles
//! - ChaCha20-encrypted PBR/emissive texture blobs
//! - Live server-side camera orbit fusion (`Projection * OrbitView * Scale * Lattice_Inverse`)

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::encrypted_compute::{
    derive_ephemeral_gpu_uniforms, derive_gpu_stage_specs_n, derive_unimodular_lattice_3x3,
    emit_polymorphic_webgl2_stage_functions, encrypt_gpu_lanes, GpuRoundSpec, SHIELD_GPU_STAGES,
};
use crate::mini_json::{parse_json, to_json_pretty, JsonVal};
use crate::params::{
    html_escape, AntiStealthMode, CspMode, SecurityPreset, Serve3dParams, Shield3dParams,
};
use crate::png_tile::{derive_tile_map, scramble_texture_grid};
use crate::web_runtime::{
    aes256_gcm_seal, aes256_gcm_seal_in_place, build_tier4_anti_stealth_js, ct_str_eq,
    issue_ticket, p256_ecdh_shared_secret, p256_generate_keypair, p256_validate_public_key,
    parse_trusted_proxies, read_http_request_with_timeouts, resolve_client_ip, send_http_with_csp,
    send_json_err_with_csp, validate_same_origin_proxy, verify_server_anti_stealth,
    write_hex_bytes, AuthConfig, ConnLimiter, HttpLeaseGuard,
};
use crate::{
    chacha20_xor_into, hex_decode, hex_encode, hkdf_sha256_32, hmac_sha256, os_random_bytes,
    secure_zero, sha256, Sha256Hasher,
};

const MAGIC_VSSH2: &[u8; 8] = b"VSSHLDP2";

#[derive(Clone, Copy)]
struct RichVert {
    pos: [f32; 3],
    norm: [f32; 3],
    uv: [f32; 2],
}

#[derive(Clone, Copy)]
struct RichTri {
    verts: [RichVert; 3],
    mat_id: u32,
}

#[inline(always)]
fn surf_avalanche(mut x: u32) -> u32 {
    x ^= x >> 16;
    x = x.wrapping_mul(0x7feb_352d);
    x ^= x >> 15;
    x = x.wrapping_mul(0x846c_a68b);
    x ^= x >> 16;
    x
}

#[inline(always)]
pub(crate) fn surf_avalanche_pub(x: u32) -> u32 {
    surf_avalanche(x)
}

fn read_f32_le(b: &[u8], off: usize) -> f32 {
    f32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn parse_standard_glb(
    glb_bytes: &[u8],
) -> Result<(Vec<RichTri>, [f32; 3], f32, Vec<Vec<u8>>), String> {
    if glb_bytes.len() < 28 || glb_bytes.get(0..4) != Some(b"glTF".as_slice()) {
        return Err("INVALID_GLB".to_string());
    }
    let json_len =
        u32::from_le_bytes([glb_bytes[12], glb_bytes[13], glb_bytes[14], glb_bytes[15]]) as usize;
    let bin_hdr = 20usize.checked_add(json_len).ok_or("GLB_JSON_OVERFLOW")?;
    let json_str = std::str::from_utf8(&glb_bytes[20..bin_hdr]).map_err(|e| e.to_string())?;
    let gltf = parse_json(json_str)?;

    let bin_len = u32::from_le_bytes([
        glb_bytes[bin_hdr],
        glb_bytes[bin_hdr + 1],
        glb_bytes[bin_hdr + 2],
        glb_bytes[bin_hdr + 3],
    ]) as usize;
    let bin = glb_bytes
        .get(bin_hdr + 8..bin_hdr + 8 + bin_len)
        .ok_or("TRUNCATED_GLB_BIN")?;

    let accessors = gltf.get("accessors").and_then(|v| v.as_arr()).ok_or("NO_ACCESSORS")?;
    let buffer_views = gltf.get("bufferViews").and_then(|v| v.as_arr()).ok_or("NO_BUFFERVIEWS")?;
    let meshes = gltf.get("meshes").and_then(|v| v.as_arr()).ok_or("NO_MESHES")?;

    let acc_slice = |acc_idx: usize| -> Result<(&JsonVal, &[u8], usize), String> {
        let acc = accessors.get(acc_idx).ok_or("BAD_ACC_IDX")?;
        let bv_idx = acc.get("bufferView").and_then(|v| v.as_i64()).ok_or("NO_BV")? as usize;
        let bv = buffer_views.get(bv_idx).ok_or("BAD_BV_IDX")?;
        let bv_off = bv.get("byteOffset").and_then(|v| v.as_i64()).unwrap_or(0) as usize;
        let bv_len = bv.get("byteLength").and_then(|v| v.as_i64()).unwrap_or(0) as usize;
        let acc_off = acc.get("byteOffset").and_then(|v| v.as_i64()).unwrap_or(0) as usize;
        let stride = bv.get("byteStride").and_then(|v| v.as_i64()).unwrap_or(0) as usize;
        let slice = bin.get(bv_off + acc_off..bv_off + bv_len).ok_or("BV_OOB")?;
        Ok((acc, slice, stride))
    };

    let mut tris = Vec::new();
    let mut min_b = [f32::INFINITY; 3];
    let mut max_b = [f32::NEG_INFINITY; 3];

    for mesh in meshes {
        let Some(prims) = mesh.get("primitives").and_then(|v| v.as_arr()) else {
            continue;
        };
        for prim in prims {
            let Some(attrs) = prim.get("attributes") else { continue };
            let Some(pos_idx) = attrs.get("POSITION").and_then(|v| v.as_i64()) else { continue };
            let (pos_acc, pos_buf, pos_stride_raw) = acc_slice(pos_idx as usize)?;
            if pos_acc.get("componentType").and_then(|v| v.as_i64()) != Some(5126) {
                return Err("NON_F32_POSITION".to_string());
            }
            let v_count = pos_acc.get("count").and_then(|v| v.as_i64()).unwrap_or(0) as usize;
            let pos_stride = if pos_stride_raw == 0 { 12 } else { pos_stride_raw };

            let norm_info = attrs
                .get("NORMAL")
                .and_then(|v| v.as_i64())
                .and_then(|ni| acc_slice(ni as usize).ok());
            let uv_info = attrs
                .get("TEXCOORD_0")
                .and_then(|v| v.as_i64())
                .and_then(|ui| acc_slice(ui as usize).ok());
            let mat_id = prim.get("material").and_then(|v| v.as_i64()).unwrap_or(0).max(0) as u32;

            let get_vert = |vi: usize| -> RichVert {
                let po = vi * pos_stride;
                let pos = [
                    read_f32_le(pos_buf, po),
                    read_f32_le(pos_buf, po + 4),
                    read_f32_le(pos_buf, po + 8),
                ];
                let norm = if let Some((na, nb, ns)) = &norm_info {
                    if na.get("componentType").and_then(|v| v.as_i64()) == Some(5126) {
                        let st = if *ns == 0 { 12 } else { *ns };
                        let no = vi * st;
                        [read_f32_le(nb, no), read_f32_le(nb, no + 4), read_f32_le(nb, no + 8)]
                    } else {
                        [0.0, 0.0, 1.0]
                    }
                } else {
                    [0.0, 0.0, 1.0]
                };
                let uv = if let Some((ua, ub, us)) = &uv_info {
                    if ua.get("componentType").and_then(|v| v.as_i64()) == Some(5126) {
                        let st = if *us == 0 { 8 } else { *us };
                        let uo = vi * st;
                        [read_f32_le(ub, uo), read_f32_le(ub, uo + 4)]
                    } else {
                        [0.0, 0.0]
                    }
                } else {
                    [0.0, 0.0]
                };
                RichVert { pos, norm, uv }
            };

            for vi in 0..v_count {
                let p = get_vert(vi).pos;
                for a in 0..3 {
                    if p[a] < min_b[a] {
                        min_b[a] = p[a];
                    }
                    if p[a] > max_b[a] {
                        max_b[a] = p[a];
                    }
                }
            }

            if let Some(idx_acc_i) = prim.get("indices").and_then(|v| v.as_i64()) {
                let (ia, ib, _) = acc_slice(idx_acc_i as usize)?;
                let icount = ia.get("count").and_then(|v| v.as_i64()).unwrap_or(0) as usize;
                let ctype = ia.get("componentType").and_then(|v| v.as_i64()).unwrap_or(5123);
                let read_idx = |k: usize| -> usize {
                    match ctype {
                        5121 => ib[k] as usize,
                        5123 => u16::from_le_bytes([ib[k * 2], ib[k * 2 + 1]]) as usize,
                        5125 => u32::from_le_bytes([
                            ib[k * 4],
                            ib[k * 4 + 1],
                            ib[k * 4 + 2],
                            ib[k * 4 + 3],
                        ]) as usize,
                        _ => 0,
                    }
                };
                for t in 0..(icount / 3) {
                    let i0 = read_idx(t * 3);
                    let i1 = read_idx(t * 3 + 1);
                    let i2 = read_idx(t * 3 + 2);
                    if i0 < v_count && i1 < v_count && i2 < v_count {
                        tris.push(RichTri {
                            verts: [get_vert(i0), get_vert(i1), get_vert(i2)],
                            mat_id,
                        });
                    }
                }
            } else {
                for t in 0..(v_count / 3) {
                    tris.push(RichTri {
                        verts: [get_vert(t * 3), get_vert(t * 3 + 1), get_vert(t * 3 + 2)],
                        mat_id,
                    });
                }
            }
        }
    }

    if tris.is_empty() {
        return Err("EMPTY_STANDARD_TRIS".to_string());
    }

    let center = [
        0.5 * (min_b[0] + max_b[0]),
        0.5 * (min_b[1] + max_b[1]),
        0.5 * (min_b[2] + max_b[2]),
    ];
    let half_ext = ((max_b[0] - min_b[0])
        .max(max_b[1] - min_b[1])
        .max(max_b[2] - min_b[2])
        * 0.5)
        .max(1e-4);

    let mut images_out = Vec::new();
    if let Some(imgs) = gltf.get("images").and_then(|v| v.as_arr()) {
        for img in imgs {
            if let Some(bvi) = img.get("bufferView").and_then(|v| v.as_i64()) {
                if let Some(bv) = buffer_views.get(bvi as usize) {
                    let o = bv.get("byteOffset").and_then(|v| v.as_i64()).unwrap_or(0) as usize;
                    let l = bv.get("byteLength").and_then(|v| v.as_i64()).unwrap_or(0) as usize;
                    if let Some(bytes) = bin.get(o..o + l) {
                        images_out.push(bytes.to_vec());
                    }
                }
            }
        }
    }

    Ok((tris, center, half_ext, images_out))
}

/// Derives a secret 3D lattice translation offset `t_lat` (|t_i| in [2048..6143]) so the
/// inverse lattice matrix `W_lat` has a non-trivial 4th column entangled with `L^-1 * t_lat`.
fn derive_lattice_offset(lat_seed: &[u8; 32]) -> [i64; 3] {
    let mut off = [0i64; 3];
    for i in 0..3 {
        let base = 6 + i * 4;
        let raw = u32::from_le_bytes([
            lat_seed[base],
            lat_seed[base + 1],
            lat_seed[base + 2],
            lat_seed[base + 3],
        ]);
        let mag = 2048i64 + (raw & 0x0fff) as i64;
        off[i] = if (raw & 0x1000) != 0 { -mag } else { mag };
    }
    off
}

pub(crate) fn derive_lattice_offset_pub(lat_seed: &[u8; 32]) -> [i64; 3] {
    derive_lattice_offset(lat_seed)
}

fn emit_rich_vert_shader(stages_src: &str, num_stages: usize) -> String {
    let mut s = String::with_capacity(stages_src.len() + 2400);
    s.push_str("#version 300 es\nprecision highp float;\nprecision highp int;\n");
    s.push_str("layout(location = 0) in uvec4 a_vs_cipher;\n");
    s.push_str("layout(location = 1) in uvec4 a_vs_surf;\n");
    s.push_str("uniform uvec4 u_vs_ephem[16];\n");
    s.push_str("uniform uvec4 u_vs_wm;\n");
    s.push_str("uniform mat4 u_vs_fused_mvp;\n");
    s.push_str("uniform int u_vs_thief;\n");
    s.push_str("out vec2 v_lit;\n");
    s.push_str("out vec2 v_uv;\n");
    s.push_str("flat out uint v_mat;\n");
    s.push_str("flat out uint v_chaff;\n");
    s.push_str("uint vs_aval(uint x){ x ^= x >> 16u; x *= 0x7feb352du; x ^= x >> 15u; x *= 0x846ca68bu; x ^= x >> 16u; return x; }\n");
    s.push_str(stages_src);
    s.push_str("void main(){\n  uint vid = uint(gl_VertexID);\n  uvec4 st = a_vs_cipher;\n");
    for idx in 0..num_stages {
        s.push_str(&format!("  st = vs_gpu_s{idx:03}(st, vid);\n"));
    }
    s.push_str("  uint chaff = st.w & 0xffu;\n  v_chaff = chaff;\n");
    s.push_str("  if (u_vs_thief == 0 && chaff != 0u) { gl_Position = vec4(8.0, 8.0, 8.0, 1.0); v_lit = vec2(0.0); v_uv = vec2(0.0); v_mat = 0u; return; }\n");
    s.push_str("  v_mat = (st.w >> 8u) & 0xffu;\n");
    s.push_str("  uint m0 = vs_aval(vid * 4u + 0u ^ u_vs_ephem[0].x);\n");
    s.push_str("  uint m2 = vs_aval(vid * 4u + 2u ^ u_vs_ephem[1].z);\n");
    s.push_str("  uint m3 = vs_aval(vid * 4u + 3u ^ u_vs_ephem[1].w);\n");
    s.push_str("  uint sf0 = a_vs_surf.x ^ m0;\n");
    s.push_str("  v_lit = vec2(float(sf0 & 0xffffu) / 16384.0, float(sf0 >> 16u) / 32767.0);\n");
    s.push_str("  v_uv = vec2(uintBitsToFloat(a_vs_surf.z ^ m2), uintBitsToFloat(a_vs_surf.w ^ m3));\n");
    s.push_str("  vec3 wp = vec3(float(int(st.x)), float(int(st.y)), float(int(st.z)));\n");
    s.push_str("  if (u_vs_thief != 0) { wp = clamp(wp * 0.000045, vec3(-1.35), vec3(1.35)); }\n");
    s.push_str("  vec4 clipPos = u_vs_fused_mvp * vec4(wp, 1.0);\n");
    s.push_str("  if (u_vs_thief == 0 && u_vs_wm.w != 0u) {\n");
    s.push_str("    uint wh = vs_aval(st.x ^ u_vs_wm.x) ^ vs_aval(st.y ^ u_vs_wm.y) ^ vs_aval(st.z ^ u_vs_wm.z);\n");
    s.push_str("    float sx = ((wh & 1u) != 0u) ? 1.0 : -1.0;\n");
    s.push_str("    float sy = ((wh & 2u) != 0u) ? 1.0 : -1.0;\n");
    s.push_str("    float amp = float(u_vs_wm.w) * 1.0e-5 * abs(clipPos.w);\n");
    s.push_str("    clipPos.x += sx * amp;\n");
    s.push_str("    clipPos.y += sy * amp;\n");
    s.push_str("  }\n");
    s.push_str("  gl_Position = clipPos;\n}\n");
    s
}

fn emit_rich_frag_shader() -> &'static str {
    r#"#version 300 es
precision highp float;
precision highp int;
in vec2 v_lit;
in vec2 v_uv;
flat in uint v_mat;
flat in uint v_chaff;
uniform sampler2D u_tex_base;
uniform sampler2D u_tex_mr;
uniform sampler2D u_tex_emissive;
uniform int u_has_tex;
uniform int u_vs_thief;
uniform vec3 u_cam_dir;
uniform uvec4 u_vs_ephem[16];
uniform uvec4 u_vs_tmap[64];
uniform uint u_tile_mask;
uniform uint u_tile_grid;
out vec4 fragColor;

vec3 aces_tonemap(vec3 x) {
  return clamp((x * (2.51 * x + 0.03)) / (x * (2.43 * x + 0.59) + 0.14), 0.0, 1.0);
}

vec2 vs_unscramble_uv(vec2 uv) {
  uint g = max(u_tile_grid, 1u);
  float fg = float(g);
  vec2 w = fract(uv);
  vec2 tileCoord = floor(w * fg);
  vec2 loc = clamp(fract(w * fg), vec2(0.004), vec2(0.996));
  uint ox = uint(clamp(tileCoord.x, 0.0, fg - 1.0));
  uint oy = uint(clamp(tileCoord.y, 0.0, fg - 1.0));
  uint orig = oy * g + ox;
  uint k = orig >> 2u;
  uint slot = orig & 3u;
  uvec4 v = u_vs_tmap[k] ^ u_vs_ephem[k & 15u];
  uint entry = (slot == 0u) ? v.x : ((slot == 1u) ? v.y : ((slot == 2u) ? v.z : v.w));
  uint scr = entry & 255u;
  if ((entry & 256u) != 0u) loc.x = 1.0 - loc.x;
  if ((entry & 512u) != 0u) loc.y = 1.0 - loc.y;
  float sx = float(scr % g);
  float sy = float(scr / g);
  return (vec2(sx, sy) + loc) / fg;
}

void main() {
  if (u_vs_thief != 0) {
    vec3 n = normalize(cross(dFdx(vec3(v_uv, gl_FragCoord.z)), dFdy(vec3(v_uv, gl_FragCoord.z))) + 1e-5);
    float rim = abs(n.z);
    vec3 poison = (v_chaff != 0u) ? vec3(1.0, 0.12, 0.28) : vec3(0.12, 0.85, 1.0);
    fragColor = vec4(poison * (0.28 + 0.72 * rim), 1.0);
    return;
  }

  // Zero-Normal-Oracle shading: smooth non-invertible studio irradiance (v_lit) +
  // screen-space depth-derivative rim/fresnel (strictly derived from gl_FragCoord).
  vec3 scPos = vec3(gl_FragCoord.xy * 0.0018, gl_FragCoord.z * 2.2);
  vec3 scN = normalize(cross(dFdx(scPos), dFdy(scPos)) + vec3(0.0, 0.0, 1e-5));
  float viewRim = pow(clamp(1.0 - abs(scN.z), 0.0, 1.0), 2.6);
  float orbitSheen = 0.88 + 0.12 * clamp(u_cam_dir.y * 0.5 + 0.5, 0.0, 1.0);
  float litD = max(v_lit.x, 0.16) * orbitSheen;
  float litS = clamp(v_lit.y, 0.0, 1.0);

  vec3 colorLinear;
  if (v_mat == 1u) {
    // Glowing Golden Halos (KHR_materials_emissive_strength = 3.5)
    vec3 goldBase = vec3(0.90, 0.65, 0.006);
    vec3 goldEmissive = vec3(1.0, 0.72, 0.006) * 3.5;
    colorLinear = goldBase * (0.45 + 0.55 * litD) + goldEmissive + vec3(1.2, 0.95, 0.4) * (litS * 0.9 + 0.55 * viewRim);
  } else {
    vec3 baseCol = vec3(0.78, 0.80, 0.85);
    float rough = 0.45;
    float metal = 0.35;
    vec3 emis = vec3(0.0);
    if (u_has_tex > 0) {
      vec2 rawUv = fract(v_uv);
      vec2 scrUv = (u_tile_mask != 0u) ? vs_unscramble_uv(v_uv) : rawUv;
      vec2 uv0 = ((u_tile_mask & 1u) != 0u) ? scrUv : rawUv;
      vec4 bc = texture(u_tex_base, uv0);
      baseCol = pow(bc.rgb, vec3(2.2));
      if (u_has_tex > 1) {
        vec2 uv1 = ((u_tile_mask & 2u) != 0u) ? scrUv : rawUv;
        vec4 mr = texture(u_tex_mr, uv1);
        rough = clamp(mr.g, 0.06, 1.0);
        metal = clamp(mr.b, 0.0, 1.0);
      }
      if (u_has_tex > 2) {
        vec2 uv2 = ((u_tile_mask & 4u) != 0u) ? scrUv : rawUv;
        vec3 em = pow(texture(u_tex_emissive, uv2).rgb, vec3(2.2));
        emis = em * 3.5;
      }
    }
    vec3 f0 = mix(vec3(0.04), baseCol, metal);
    vec3 diffuseAlbedo = baseCol * (1.0 - metal * 0.82);
    float specAmt = litS * (1.45 - rough * 0.85);
    vec3 ambient = vec3(0.18, 0.20, 0.26) * baseCol;
    colorLinear = ambient
      + diffuseAlbedo * litD * vec3(1.0, 0.98, 0.94)
      + f0 * specAmt * 1.45
      + vec3(0.85, 0.68, 0.25) * viewRim * 0.24
      + emis;
  }

  vec3 mapped = pow(aces_tonemap(colorLinear), vec3(1.0 / 2.2));
  fragColor = vec4(mapped, 1.0);
}
"#
}

#[derive(Clone, Copy)]
struct WmCarrier {
    vid: u32,
    qx: i16,
    qy: i16,
    qz: i16,
    tag: u32,
}

const WM_CARRIER_NONCE: [u8; 12] = *b"VS3DWMCAR001";

fn serialize_wm_carriers(carriers: &[WmCarrier]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + carriers.len() * 14);
    out.extend_from_slice(&(carriers.len() as u32).to_le_bytes());
    for c in carriers {
        out.extend_from_slice(&c.vid.to_le_bytes());
        out.extend_from_slice(&c.qx.to_le_bytes());
        out.extend_from_slice(&c.qy.to_le_bytes());
        out.extend_from_slice(&c.qz.to_le_bytes());
        out.extend_from_slice(&c.tag.to_le_bytes());
    }
    out
}

fn deserialize_wm_carriers(bytes: &[u8]) -> Result<Vec<WmCarrier>, String> {
    if bytes.len() < 4 {
        return Err("BAD_WM_CARRIERS".to_string());
    }
    let cnt = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if bytes.len() != 4 + cnt * 14 {
        return Err("BAD_WM_CARRIERS_LEN".to_string());
    }
    let mut out = Vec::with_capacity(cnt);
    for i in 0..cnt {
        let o = 4 + i * 14;
        out.push(WmCarrier {
            vid: u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]),
            qx: i16::from_le_bytes([bytes[o + 4], bytes[o + 5]]),
            qy: i16::from_le_bytes([bytes[o + 6], bytes[o + 7]]),
            qz: i16::from_le_bytes([bytes[o + 8], bytes[o + 9]]),
            tag: u32::from_le_bytes([bytes[o + 10], bytes[o + 11], bytes[o + 12], bytes[o + 13]]),
        });
    }
    Ok(out)
}

#[inline(always)]
fn carrier_chip_sign(wm_key: &[u8; 32], vid: u32) -> i64 {
    let mut msg = [0u8; 16];
    msg[..12].copy_from_slice(b"VS3D_WMCHIP|");
    msg[12..16].copy_from_slice(&vid.to_le_bytes());
    let mac = hmac_sha256(wm_key, &msg);
    if (mac[0] & 1) != 0 { 1 } else { -1 }
}

/// Computes the deterministic 64-bit forensic buyer watermark ID baked into `scene.vsshield2`.
pub fn derive_shield_v2_buyer_wm64(master_key: &[u8; 32], asset_id: &str, subject: &str) -> u64 {
    let wm_key = hmac_sha256(master_key, format!("VS3D_SHIELD_WM_V1|{asset_id}").as_bytes());
    let wm_mac = hmac_sha256(&wm_key, format!("VS3D_WM_V1|{subject}").as_bytes());
    u64::from_le_bytes([
        wm_mac[16], wm_mac[17], wm_mac[18], wm_mac[19],
        wm_mac[20], wm_mac[21], wm_mac[22], wm_mac[23],
    ])
}

/// Forensically extracts the 64-bit buyer WM64 ID directly from ripped lattice-space `wp`
/// vertices (e.g. captured via Transform Feedback after stripping `u_vs_wm`!).
pub fn decode_shield_v2_wm64_from_ripped_wp(
    shield_dir: &Path,
    key_file_opt: Option<&Path>,
    ripped_wp: &[[i32; 3]],
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

    let lat_seed = hmac_sha256(&master_key, format!("VS3D_SHIELD_LAT_V1|{asset_id}").as_bytes());
    let wm_key = hmac_sha256(&master_key, format!("VS3D_SHIELD_WM_V1|{asset_id}").as_bytes());
    let (_lat_m, lat_inv) = derive_unimodular_lattice_3x3(&lat_seed);
    let t_lat = derive_lattice_offset(&lat_seed);
    secure_zero(&mut master_key);

    let enc_carriers = fs::read(shield_dir.join("wm_carriers.vsbin"))
        .map_err(|e| format!("Missing wm_carriers.vsbin: {e}"))?;
    let mut plain_carriers = vec![0u8; enc_carriers.len()];
    chacha20_xor_into(&wm_key, 1, &WM_CARRIER_NONCE, &enc_carriers, &mut plain_carriers);
    let carriers = deserialize_wm_carriers(&plain_carriers)?;
    secure_zero(&mut plain_carriers);
    if carriers.is_empty() {
        return Err("EMPTY_WM_CARRIERS".to_string());
    }

    let mut bit_sum = [0.0f64; 64];
    let mut bit_cnt = [0usize; 64];
    for (ci, c) in carriers.iter().enumerate() {
        let Some(&wp) = ripped_wp.get(c.vid as usize) else {
            continue;
        };
        let wx = (wp[0] as i64) - t_lat[0];
        let wy = (wp[1] as i64) - t_lat[1];
        let wz = (wp[2] as i64) - t_lat[2];
        let qx = lat_inv[0][0] * wx + lat_inv[0][1] * wy + lat_inv[0][2] * wz;
        let qy = lat_inv[1][0] * wx + lat_inv[1][1] * wy + lat_inv[1][2] * wz;
        let qz = lat_inv[2][0] * wx + lat_inv[2][1] * wy + lat_inv[2][2] * wz;
        let dqx = qx - (c.qx as i64);
        let dqy = qy - (c.qy as i64);
        let dqz = qz - (c.qz as i64);
        let proj = (dqx - dqy + dqz) as f64;
        let chip = carrier_chip_sign(&wm_key, c.vid) as f64;
        let b = ci & 63;
        bit_sum[b] += proj * chip;
        bit_cnt[b] += 1;
    }

    let mut wm_id = 0u64;
    let mut active_bits = 0usize;
    let mut conf_acc = 0.0f64;
    for b in 0..64 {
        if bit_cnt[b] > 0 {
            active_bits += 1;
            if bit_sum[b] >= 0.0 {
                wm_id |= 1u64 << b;
            }
            conf_acc += (bit_sum[b].abs() / ((bit_cnt[b] as f64) * 3.0)).min(1.0);
        }
    }
    let conf = if active_bits > 0 {
        conf_acc / (active_bits as f64)
    } else {
        0.0
    };
    Ok((wm_id, conf))
}

#[inline(always)]
fn bake_non_invertible_irradiance(n: [f32; 3]) -> (u32, u32) {
    let nlen = (n[0] * n[0] + n[1] * n[1] + n[2] * n[2]).sqrt().max(1e-6);
    let nx = n[0] / nlen;
    let ny = n[1] / nlen;
    let nz = n[2] / nlen;
    // Fixed studio key + fill lights collapsed through nonlinear max(0, .) into 1 scalar
    let d1 = (nx * 0.4835 + ny * 0.6857 + nz * 0.5450).max(0.0);
    let d2 = (nx * -0.7224 + ny * 0.3718 + nz * -0.5843).max(0.0);
    let hemi = 0.5 * ny + 0.5;
    let lit_d = (0.16 + 0.22 * hemi + 1.28 * d1 + 0.42 * d2).clamp(0.0, 3.9);
    // Static studio specular highlight hint (nonlinear power-12 fold)
    let h0 = (nx * 0.2738 + ny * 0.4451 + nz * 0.8526).max(0.0);
    let lit_s = h0.powf(12.0).clamp(0.0, 1.0);
    let d_q = (lit_d * 16384.0).round().clamp(0.0, 65535.0) as u32;
    let s_q = (lit_s * 32767.0).round().clamp(0.0, 65535.0) as u32;
    (d_q, s_q)
}

/// Build an interactive WebGL2 Encrypted-VRAM Viewer Bundle inside `out_dir` if `glb_bytes` is a
/// standard uncompressed glTF 2.0 model.
pub fn build_interactive_viewer_assets(
    master_key: &[u8; 32],
    asset_id: &str,
    glb_bytes: &[u8],
    out_dir: &Path,
    key_file_opt: Option<&Path>,
) -> Result<Option<(usize, usize, usize)>, String> {
    let mut params = Shield3dParams::from_preset(SecurityPreset::Balanced);
    params.key_file = key_file_opt.map(|p| p.to_path_buf());
    build_interactive_viewer_assets_with_params(master_key, asset_id, glb_bytes, out_dir, &params)
}

pub fn build_interactive_viewer_assets_with_params(
    master_key: &[u8; 32],
    asset_id: &str,
    glb_bytes: &[u8],
    out_dir: &Path,
    params: &Shield3dParams,
) -> Result<Option<(usize, usize, usize)>, String> {
    params.validate()?;
    let Ok((real_tris, center, half_ext, images)) = parse_standard_glb(glb_bytes) else {
        return Ok(None);
    };

    let key_path = params
        .key_file
        .clone()
        .unwrap_or_else(|| out_dir.join(".vsshield.key"));
    if let Some(parent) = key_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    }
    let mut key_hex_bytes = hex_encode(master_key).into_bytes();
    fs::write(&key_path, &key_hex_bytes).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
    }
    secure_zero(&mut key_hex_bytes);
    if params.key_file.is_some() {
        let default_key = out_dir.join(".vsshield.key");
        if default_key != key_path && default_key.exists() {
            let _ = fs::remove_file(&default_key);
        }
    }

    let lat_seed = hmac_sha256(master_key, format!("VS3D_SHIELD_LAT_V1|{asset_id}").as_bytes());
    let shader_seed = hmac_sha256(master_key, format!("VS3D_SHIELD_SHD_V1|{asset_id}").as_bytes());
    let chaff_seed = hmac_sha256(master_key, format!("VS3D_SHIELD_CHF_V1|{asset_id}").as_bytes());
    let mut tex_key = hmac_sha256(master_key, format!("VS3D_SHIELD_TEX_V1|{asset_id}").as_bytes());
    let tmap_seed = hmac_sha256(master_key, format!("VS3D_SHIELD_TMAP_V2|{asset_id}").as_bytes());

    let (lat_m, _lat_inv) = derive_unimodular_lattice_3x3(&lat_seed);
    let t_lat = derive_lattice_offset(&lat_seed);
    let num_stages = params.gpu_stages;
    let stages = derive_gpu_stage_specs_n(&shader_seed, num_stages);
    let ephem = derive_ephemeral_gpu_uniforms(master_key, asset_id);
    let tile_grid = params.tile_grid;
    let tmap = derive_tile_map(&tmap_seed, tile_grid.max(1));

    let real_count = real_tris.len();
    let chaff_count = params.chaff_count_for(real_count);
    let total_tris = real_count + chaff_count;

    let mut all_tris: Vec<(RichTri, u32)> = Vec::with_capacity(total_tris);
    for t in real_tris {
        all_tris.push((t, 0u32));
    }
    for c in 0..chaff_count {
        let mut cmsg = [0u8; 36];
        cmsg[..32].copy_from_slice(&chaff_seed);
        cmsg[32..36].copy_from_slice(&(c as u32).to_le_bytes());
        let ch = sha256(&cmsg);
        let mut vs = [RichVert { pos: [0.0; 3], norm: [0.0, 1.0, 0.0], uv: [0.0; 2] }; 3];
        for v in 0..3 {
            for a in 0..3 {
                let idx = v * 6 + a * 2;
                let norm_f = (i16::from_le_bytes([ch[idx], ch[idx + 1]]) as f32) / 32768.0;
                vs[v].pos[a] = center[a] + norm_f * half_ext * 0.95;
            }
        }
        all_tris.push((RichTri { verts: vs, mat_id: 0 }, 1u32));
    }

    for i in (1..all_tris.len()).rev() {
        let mut pmsg = [0u8; 40];
        pmsg[..32].copy_from_slice(&chaff_seed);
        pmsg[32..40].copy_from_slice(&(i as u64).to_le_bytes());
        let ph = sha256(&pmsg);
        let j = (u64::from_le_bytes([ph[0], ph[1], ph[2], ph[3], ph[4], ph[5], ph[6], ph[7]]) as usize) % (i + 1);
        all_tris.swap(i, j);
    }

    let total_verts = total_tris * 3;
    let mut raw_words: Vec<[u32; 8]> = vec![[0u32; 8]; total_verts];
    let n_threads = thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(16);
    let next_tri = AtomicUsize::new(0);
    let out_mtx = Mutex::new(&mut raw_words);

    let scale_to_q = 16384.0f32 / half_ext;
    let chunks = (total_tris + 255) / 256;

    thread::scope(|s| {
        for _ in 0..n_threads {
            s.spawn(|| loop {
                let ci = next_tri.fetch_add(1, Ordering::Relaxed);
                if ci >= chunks {
                    break;
                }
                let start_t = ci * 256;
                let end_t = (start_t + 256).min(total_tris);
                let mut local = Vec::with_capacity((end_t - start_t) * 3);
                for ti in start_t..end_t {
                    let (tri, chaff_flag) = &all_tris[ti];
                    let tag = (*chaff_flag & 0xff) | ((tri.mat_id & 0xff) << 8);
                    for vi in 0..3 {
                        let vid = (ti * 3 + vi) as u32;
                        let rv = &tri.verts[vi];
                        let qx = (((rv.pos[0] - center[0]) * scale_to_q).round() as i64).clamp(-16384, 16384);
                        let qy = (((rv.pos[1] - center[1]) * scale_to_q).round() as i64).clamp(-16384, 16384);
                        let qz = (((rv.pos[2] - center[2]) * scale_to_q).round() as i64).clamp(-16384, 16384);

                        let wx = (lat_m[0][0] * qx + lat_m[0][1] * qy + lat_m[0][2] * qz + t_lat[0]) as i32;
                        let wy = (lat_m[1][0] * qx + lat_m[1][1] * qy + lat_m[1][2] * qz + t_lat[1]) as i32;
                        let wz = (lat_m[2][0] * qx + lat_m[2][1] * qy + lat_m[2][2] * qz + t_lat[2]) as i32;

                        let enc_pos = encrypt_gpu_lanes([wx as u32, wy as u32, wz as u32, tag], &stages, &ephem, vid);

                        // Zero-Normal-Oracle surface packing: store ONLY collapsed non-invertible
                        // scalar studio irradiance + random noise in s1 (ZERO 3D normal vector!)
                        let (lit_d_q, lit_s_q) = bake_non_invertible_irradiance(rv.norm);

                        let m0 = surf_avalanche((vid * 4) ^ ephem[0][0]);
                        let m1 = surf_avalanche((vid * 4 + 1) ^ ephem[0][1]);
                        let m2 = surf_avalanche((vid * 4 + 2) ^ ephem[1][2]);
                        let m3 = surf_avalanche((vid * 4 + 3) ^ ephem[1][3]);

                        let s0 = (lit_d_q | (lit_s_q << 16)) ^ m0;
                        let s1 = surf_avalanche(vid.wrapping_mul(0x9e37_79b1) ^ 0x517c_c1b7) ^ m1;
                        let s2 = rv.uv[0].to_bits() ^ m2;
                        let s3 = rv.uv[1].to_bits() ^ m3;

                        local.push([enc_pos[0], enc_pos[1], enc_pos[2], enc_pos[3], s0, s1, s2, s3]);
                    }
                }
                let mut guard = out_mtx.lock().unwrap();
                let dst_start = start_t * 3;
                guard[dst_start..dst_start + local.len()].copy_from_slice(&local);
            });
        }
    });

    // Build server-only encrypted WM64 lattice-space carrier index (up to 2,048 real vertices)
    // so serve-3d can bake per-buyer 64-bit forensic watermarks directly into `wp` in <0.3 ms!
    let mut wm_carriers: Vec<WmCarrier> = Vec::with_capacity(2048);
    let real_verts_total = real_count * 3;
    let stride = (real_verts_total / 2048).max(1);
    let mut real_seen = 0usize;
    'carrier_loop: for (ti, (tri, chaff_flag)) in all_tris.iter().enumerate() {
        if *chaff_flag != 0 {
            continue;
        }
        let tag = (*chaff_flag & 0xff) | ((tri.mat_id & 0xff) << 8);
        for vi in 0..3 {
            if real_seen % stride == 0 {
                let rv = &tri.verts[vi];
                let qx = (((rv.pos[0] - center[0]) * scale_to_q).round() as i64).clamp(-16384, 16384) as i16;
                let qy = (((rv.pos[1] - center[1]) * scale_to_q).round() as i64).clamp(-16384, 16384) as i16;
                let qz = (((rv.pos[2] - center[2]) * scale_to_q).round() as i64).clamp(-16384, 16384) as i16;
                wm_carriers.push(WmCarrier {
                    vid: (ti * 3 + vi) as u32,
                    qx,
                    qy,
                    qz,
                    tag,
                });
                if wm_carriers.len() >= 2048 {
                    break 'carrier_loop;
                }
            }
            real_seen += 1;
        }
    }
    let wm_key = hmac_sha256(master_key, format!("VS3D_SHIELD_WM_V1|{asset_id}").as_bytes());
    let mut raw_carriers = serialize_wm_carriers(&wm_carriers);
    let mut enc_carriers = vec![0u8; raw_carriers.len()];
    chacha20_xor_into(&wm_key, 1, &WM_CARRIER_NONCE, &raw_carriers, &mut enc_carriers);
    secure_zero(&mut raw_carriers);
    fs::write(out_dir.join("wm_carriers.vsbin"), &enc_carriers).map_err(|e| e.to_string())?;

    let mut bin_v2 = Vec::with_capacity(32 + total_verts * 32);
    bin_v2.extend_from_slice(MAGIC_VSSH2);
    bin_v2.extend_from_slice(&2u32.to_le_bytes());
    bin_v2.extend_from_slice(&(total_verts as u32).to_le_bytes());
    bin_v2.extend_from_slice(&(real_count as u32).to_le_bytes());
    bin_v2.extend_from_slice(&(chaff_count as u32).to_le_bytes());
    bin_v2.extend_from_slice(&(images.len() as u32).to_le_bytes());
    bin_v2.extend_from_slice(&(num_stages as u32).to_le_bytes());
    for w8 in &raw_words {
        for &w in w8 {
            bin_v2.extend_from_slice(&w.to_le_bytes());
        }
    }
    fs::write(out_dir.join("scene.vsshield2"), &bin_v2).map_err(|e| e.to_string())?;

    // Server-side cryptographic Fisher-Yates + flip texture scrambling (MCU-aligned JPEG or PNG)
    let tex_slots: Vec<Mutex<Option<Result<bool, String>>>> =
        (0..images.len()).map(|_| Mutex::new(None)).collect();
    let tex_next = AtomicUsize::new(0);
    let tex_threads = n_threads.min(images.len().max(1));
    let max_tex_dim = params.max_tex_dim;
    let png_mode = params.png_mode;
    let tex_format = params.tex_format;
    let tex_quality = params.tex_quality;
    thread::scope(|s| {
        for _ in 0..tex_threads {
            s.spawn(|| loop {
                let ti = tex_next.fetch_add(1, Ordering::Relaxed);
                if ti >= images.len() {
                    break;
                }
                let res = (|| -> Result<bool, String> {
                    let img_bytes = &images[ti];
                    let (mut payload, was_scrambled) = match scramble_texture_grid(
                        img_bytes,
                        &tmap,
                        tile_grid,
                        max_tex_dim,
                        png_mode,
                        tex_format,
                        tex_quality,
                    ) {
                        Ok((scr, flag)) => (scr, flag),
                        Err(_) => (img_bytes.clone(), false),
                    };
                    let mut nonce = [0u8; 12];
                    nonce[0..4].copy_from_slice(&(ti as u32).to_le_bytes());
                    let mut ct = vec![0u8; payload.len()];
                    chacha20_xor_into(&tex_key, 1, &nonce, &payload, &mut ct);
                    secure_zero(&mut payload);
                    fs::write(out_dir.join(format!("tex_{ti}.vsbin")), &ct)
                        .map_err(|e| e.to_string())?;

                    // Save server-only <=1024px unscrambled ChaCha20 texture for `--mode stream`
                    // (NEVER served on any HTTP route; powers zero-geometry server PBR rasterization!)
                    if let Ok(mut sm) = crate::png_tile::decode_png(img_bytes) {
                        while sm.width > 1024 || sm.height > 1024 {
                            sm = crate::png_tile::downscale_2x_box(&sm);
                        }
                        let mut st_png = crate::png_tile::encode_png_with_mode(
                            sm.width,
                            sm.height,
                            sm.color_type,
                            sm.channels,
                            &sm.pixels,
                            crate::params::PngMode::Fast,
                        );
                        let mut snonce = [0u8; 12];
                        snonce[..8].copy_from_slice(&crate::raster_stream::STREAM_TEX_NONCE_PREFIX);
                        snonce[8..12].copy_from_slice(&(ti as u32).to_le_bytes());
                        let mut sct = vec![0u8; st_png.len()];
                        chacha20_xor_into(&tex_key, 1, &snonce, &st_png, &mut sct);
                        secure_zero(&mut st_png);
                        let _ = fs::write(out_dir.join(format!("stream_tex_{ti}.vsbin")), &sct);
                    }
                    Ok(was_scrambled)
                })();
                *tex_slots[ti].lock().unwrap() = Some(res);
            });
        }
    });
    secure_zero(&mut tex_key);

    let mut scrambled_mask: u32 = 0;
    for (ti, slot) in tex_slots.iter().enumerate() {
        let was_scr = slot.lock().unwrap().take().unwrap()?;
        if was_scr && ti < 32 {
            scrambled_mask |= 1u32 << ti;
        }
    }

    let stages_glsl = emit_polymorphic_webgl2_stage_functions(&stages);
    fs::write(
        out_dir.join("shield_pbr.vert.glsl"),
        emit_rich_vert_shader(&stages_glsl, num_stages).as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        out_dir.join("shield_pbr.frag.glsl"),
        emit_rich_frag_shader().as_bytes(),
    )
    .map_err(|e| e.to_string())?;

    let meta = JsonVal::obj(vec![
        ("assetId", JsonVal::Str(asset_id.to_string())),
        ("preset", JsonVal::Str(params.preset.as_str().to_string())),
        ("latticeVersion", JsonVal::Int(2)),
        ("normalOracle", JsonVal::Bool(false)),
        ("wmCarrierCount", JsonVal::Int(wm_carriers.len() as i64)),
        ("gpuStages", JsonVal::Int(num_stages as i64)),
        ("chaffPercent", JsonVal::Num(params.chaff_pct as f64)),
        ("tileGrid", JsonVal::Int(tile_grid as i64)),
        ("maxTexDim", JsonVal::Int(max_tex_dim as i64)),
        ("pngMode", JsonVal::Str(png_mode.as_str().to_string())),
        ("texFormat", JsonVal::Str(tex_format.as_str().to_string())),
        ("texQuality", JsonVal::Int(tex_quality as i64)),
        ("tileScrambled", JsonVal::Bool(scrambled_mask != 0)),
        ("tileScrambledMask", JsonVal::Int(scrambled_mask as i64)),
        ("realTriangles", JsonVal::Int(real_count as i64)),
        ("chaffTriangles", JsonVal::Int(chaff_count as i64)),
        ("totalVertices", JsonVal::Int(total_verts as i64)),
        ("textureCount", JsonVal::Int(images.len() as i64)),
        ("halfExtent", JsonVal::Str(format!("{half_ext:.8}"))),
    ]);
    fs::write(
        out_dir.join("viewer.meta.json"),
        to_json_pretty(&meta).as_bytes(),
    )
    .map_err(|e| e.to_string())?;

    Ok(Some((real_count, chaff_count, images.len())))
}

fn mat4_mul(a: &[f32; 16], b: &[f32; 16]) -> [f32; 16] {
    let mut out = [0.0f32; 16];
    for c in 0..4 {
        for r in 0..4 {
            out[c * 4 + r] = a[r] * b[c * 4]
                + a[4 + r] * b[c * 4 + 1]
                + a[8 + r] * b[c * 4 + 2]
                + a[12 + r] * b[c * 4 + 3];
        }
    }
    out
}

fn unbiased_cam_dir(yaw_q: f32, pitch_q: f32) -> [f32; 3] {
    let p = pitch_q.clamp(-1.35, 1.35);
    let cp = p.cos();
    let sp = p.sin();
    [cp * yaw_q.sin(), sp, cp * yaw_q.cos()]
}

/// Smooth, secret, session-keyed compensated tilt-shift + angle-varying projection intrinsics
/// K(yaw, pitch) that destroy both standard 4-eq Kruppa, relaxed 2-eq Kruppa, AND constant-intrinsic
/// multi-view self-calibration (every angle adds 5 fresh unknowns), while exact lookAt eye-pan
/// compensation keeps the 3D object dead-center and visually crisp for human viewers.
fn derive_angle_varying_intrinsics(
    proj_seed: &[u8; 32],
    yaw: f32,
    pitch: f32,
    jitter: f32,
) -> (f32, f32, f32, f32, f32) {
    if jitter <= 0.0 {
        return (0.0, 0.0, 0.0, 1.0, 0.0);
    }
    let ph = |idx: usize| -> f32 {
        let b = u16::from_le_bytes([proj_seed[idx * 2], proj_seed[idx * 2 + 1]]) as f32;
        (b / 65535.0) * std::f32::consts::TAU
    };
    let sgn = |idx: usize| -> f32 {
        if (proj_seed[20 + idx] & 1) != 0 { 1.0 } else { -1.0 }
    };
    let mag = |idx: usize| -> f32 {
        (proj_seed[24 + idx] as f32) / 255.0
    };
    let s1 = (yaw * 1.3 + ph(0)).sin() * (pitch * 1.1 + ph(1)).cos();
    let s2 = (yaw * 0.9 + ph(2)).cos() * (pitch * 1.4 + ph(3)).sin();
    let s3 = (yaw * 1.7 + pitch * 0.8 + ph(4)).sin();
    let s4 = (yaw * 1.1 - pitch * 1.5 + ph(5)).cos();
    let s5 = (yaw * 0.7 + pitch * 1.9 + ph(6)).sin();
    let j = jitter.clamp(0.0, 3.0);
    // Non-zero-mean session bias + smooth angle variation -> stacking N views CANNOT average it out!
    let cx = (sgn(0) * (0.28 + 0.16 * mag(0)) * j + s1 * 0.12 * j).clamp(-0.55, 0.55);
    let cy = (sgn(1) * (0.24 + 0.16 * mag(1)) * j + s2 * 0.12 * j).clamp(-0.55, 0.55);
    let skew = (sgn(2) * (0.045 + 0.035 * mag(2)) * j + s3 * 0.03 * j).clamp(-0.12, 0.12);
    let asp_mul = (1.0 + sgn(3) * (0.045 + 0.025 * mag(3)) * j + s4 * 0.04 * j).clamp(0.84, 1.18);
    let fov_delta = (s5 * 2.5 * j).clamp(-5.0, 5.0);
    (cx, cy, skew, asp_mul, fov_delta)
}

#[allow(clippy::too_many_arguments)]
fn build_orbit_mvp(
    yaw: f32,
    pitch: f32,
    zoom: f32,
    pan_y: f32,
    roll: f32,
    aspect: f32,
    fov_deg: f32,
    near: f32,
    far: f32,
    cx: f32,
    cy: f32,
    skew: f32,
    asp_mul: f32,
) -> [f32; 16] {
    let fov = fov_deg.clamp(18.0, 72.0).to_radians();
    let fy = 1.0 / (0.5 * fov).tan();
    let fx = fy / (aspect.max(0.2) * asp_mul);
    let nf = 1.0 / (near - far);

    // Column-major OpenGL tilt-shift projection with non-zero secret principal point (cx, cy) & skew
    let proj = [
        fx,   0.0, 0.0,                0.0,
        skew, fy,  0.0,                0.0,
        cx,   cy,  (far + near) * nf, -1.0,
        0.0,  0.0, (2.0 * far * near) * nf, 0.0,
    ];

    let cp = pitch.clamp(-1.35, 1.35).cos();
    let sp = pitch.clamp(-1.35, 1.35).sin();
    let cy_a = yaw.cos();
    let sy_a = yaw.sin();
    let r = zoom.clamp(0.7, 10.0);

    let eye = [r * cp * sy_a, pan_y + r * sp, r * cp * cy_a];
    let target = [0.0f32, pan_y, 0.0f32];

    let mut z_ax = [eye[0] - target[0], eye[1] - target[1], eye[2] - target[2]];
    let z_len = (z_ax[0] * z_ax[0] + z_ax[1] * z_ax[1] + z_ax[2] * z_ax[2]).sqrt().max(1e-6);
    for v in &mut z_ax {
        *v /= z_len;
    }

    let up = [roll.sin(), roll.cos(), 0.0f32];
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

    // Exact optical-center tilt-shift compensation in camera space:
    // Shifts tx, ty so target (0, pan_y, 0) at camera depth `-r` lands at exact NDC (0, 0)
    // despite large secret off-axis principal point (cx, cy) and skew!
    let dy_comp = r * cy / fy;
    let dx_comp = (r * cx - skew * dy_comp) / fx;
    let tx = -(x_ax[0] * eye[0] + x_ax[1] * eye[1] + x_ax[2] * eye[2]) + dx_comp;
    let ty = -(y_ax[0] * eye[0] + y_ax[1] * eye[1] + y_ax[2] * eye[2]) + dy_comp;
    let tz = -(z_ax[0] * eye[0] + z_ax[1] * eye[1] + z_ax[2] * eye[2]);

    let view = [
        x_ax[0], y_ax[0], z_ax[0], 0.0,
        x_ax[1], y_ax[1], z_ax[1], 0.0,
        x_ax[2], y_ax[2], z_ax[2], 0.0,
        tx, ty, tz, 1.0,
    ];

    mat4_mul(&proj, &view)
}

fn fmt_with_commas(n: usize) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(b as char);
    }
    out
}

fn build_viewer_html(title: &str, gpu_stages: usize) -> String {
    let safe_title = html_escape(title);
    let est_toks = fmt_with_commas(gpu_stages * 1612);
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="vs-ticket" content="__VS_3D_TICKET__"/>
<title>{safe_title} — VibeSlayer 3D GPU Shield</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:radial-gradient(circle at 50% 35%,#191d2b 0%,#090b11 72%);color:#e8ecf4;font-family:system-ui,-apple-system,sans-serif;overflow:hidden;height:100vh;width:100vw;user-select:none}}
  canvas{{display:block;width:100vw;height:100vh;cursor:grab}}
  canvas:active{{cursor:grabbing}}
  .hud{{position:fixed;top:18px;left:18px;background:rgba(10,13,22,0.84);border:1px solid rgba(255,204,77,0.32);border-radius:14px;padding:16px 18px;max-width:415px;backdrop-filter:blur(10px);box-shadow:0 14px 40px rgba(0,0,0,0.55)}}
  .badge{{display:inline-block;font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;padding:4px 9px;border-radius:999px;background:rgba(255,196,46,0.16);color:#ffd15c;border:1px solid rgba(255,196,46,0.4);margin-bottom:8px}}
  .badge.danger{{background:rgba(255,56,96,0.2);color:#ff6b8b;border-color:rgba(255,56,96,0.55)}}
  h1{{font-size:17px;font-weight:700;margin-bottom:6px;color:#fff}}
  .sub{{font-size:12.5px;color:#a8b3cf;line-height:1.45;margin-bottom:12px}}
  .grid{{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px}}
  .stat{{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:9px;padding:8px 10px}}
  .stat .k{{font-size:10.5px;color:#8c98b8;text-transform:uppercase;letter-spacing:0.04em}}
  .stat .v{{font-size:13.5px;font-weight:700;color:#fff;margin-top:2px}}
  .stat .v.gold{{color:#ffd15c}}
  .stat .v.green{{color:#4ade80}}
  .controls{{display:flex;flex-wrap:wrap;gap:7px;margin-top:6px}}
  button{{background:rgba(255,255,255,0.08);color:#eef2ff;border:1px solid rgba(255,255,255,0.16);border-radius:8px;padding:7px 11px;font-size:12px;font-weight:600;cursor:pointer;transition:all .15s}}
  button:hover{{background:rgba(255,209,92,0.18);border-color:#ffd15c;color:#fff}}
  button.active{{background:#ffd15c;color:#0b0d14;border-color:#ffd15c}}
  button.thief{{background:rgba(255,56,96,0.16);border-color:rgba(255,56,96,0.5);color:#ff859e;width:100%;margin-top:8px;padding:9px 12px}}
  button.thief.active{{background:#ff2e5b;color:#fff;border-color:#ff2e5b}}
  #status-bar{{position:fixed;bottom:16px;left:18px;font-size:12px;color:#9aa6c4;background:rgba(10,13,22,0.78);padding:8px 14px;border-radius:999px;border:1px solid rgba(255,255,255,0.1)}}
</style>
</head>
<body>
<canvas id="glcanvas"></canvas>
<div class="hud">
  <div id="mode-badge" class="badge">LIVE ENCRYPTED-VRAM GPU SHIELD</div>
  <h1>{safe_title}</h1>
  <div class="sub">Drag mouse to <b>spin camera 360°</b> (scroll to zoom). Every camera move fuses <code>Camera × SecretLattice⁻¹</code> on the Rust server so 3D coordinates never exist in RAM, VRAM, or Post-Shader!</div>
  <div class="grid">
    <div class="stat"><div class="k">CPU / VRAM Plaintext</div><div class="v green" id="st-plain">0 / 0 verts</div></div>
    <div class="stat"><div class="k">Poison Chaff Clipped</div><div class="v gold" id="st-chaff">Loading...</div></div>
    <div class="stat"><div class="k">Shader Token Bomb</div><div class="v gold">~{est_toks} tok ({gpu_stages} stg)</div></div>
    <div class="stat"><div class="k">Camera-Spin Server</div><div class="v green" id="st-lat">-- ms</div></div>
  </div>
  <div class="controls">
    <button id="btn-front" class="active">Front View</button>
    <button id="btn-hero">3/4 Spin</button>
    <button id="btn-halo">Close-Up Detail</button>
    <button id="btn-back">Back View</button>
    <button id="btn-spin">Auto-Spin: OFF</button>
  </div>
  <button id="btn-thief" class="thief">Simulate Ripper / RenderDoc Steal Attempt</button>
</div>
<div id="status-bar">Initializing ECDH P-256 + Encrypted-VRAM {gpu_stages}-Stage GPU Shader...</div>
<script src="/__vibeslayer/3d-loader.js"></script>
</body>
</html>
"#
    )
}

fn build_hardened_3d_loader_js(
    asset_id: &str,
    anti_hook: bool,
    anti_cdp: bool,
    anti_stealth: AntiStealthMode,
    gpu_stages: usize,
) -> String {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"VS3D_LOADER_MASK_V3|");
    hasher.update(asset_id.as_bytes());
    let mask = hasher.finalize();

    let table: &[&str] = &[
        "status-bar",                        // 0
        "Error: ",                           // 1
        "WebGL2 unavailable",                // 2
        "WebCrypto unavailable",             // 3
        "meta[name=\"vs-ticket\"]",          // 4
        "content",                           // 5
        "__VS_3D_TICKET__",                  // 6
        "Missing session ticket",            // 7
        "ECDH",                              // 8
        "P-256",                             // 9
        "deriveBits",                        // 10
        "raw",                               // 11
        "/__vibeslayer/session",             // 12
        "POST",                              // 13
        "Content-Type",                      // 14
        "application/json",                  // 15
        "SESSION_DENIED",                    // 16
        "HKDF",                              // 17
        "deriveKey",                         // 18
        "VS3D_WRAP|",                        // 19
        "SHA-256",                           // 20
        "AES-GCM",                           // 21
        "unwrapKey",                         // 22
        "decrypt",                           // 23
        "VS3D_SESSION|",                     // 24
        "X-VS-Session",                      // 25
        "/shield_pbr.vert.glsl",             // 26
        "VS3D_ASSET|/shield_pbr.vert.glsl",  // 27
        "/shield_pbr.frag.glsl",             // 28
        "VS3D_ASSET|/shield_pbr.frag.glsl",  // 29
        "/scene.vsshield2",                  // 30
        "VS3D_ASSET|/scene.vsshield2",       // 31
        "/__vibeslayer/tex/",                // 32
        "VS3D_TEX|",                         // 33
        "/__vibeslayer/camera",              // 34
        "u_vs_ephem",                        // 35
        "u_vs_fused_mvp",                    // 36
        "u_vs_thief",                        // 37
        "u_has_tex",                         // 38
        "u_cam_dir",                         // 39
        "u_vs_tmap",                         // 40
        "u_tile_mask",                       // 41
        "u_vs_wm",                           // 42
        "u_tex_base",                        // 43
        "u_tex_mr",                          // 44
        "u_tex_emissive",                    // 45
        "glcanvas",                          // 46
        "[native code]",                     // 47
        "INTEGRITY_TAMPERED",                // 48
        "clientPublicKeyHex",                // 49
        "ticket",                            // 50
        "ok",                                // 51
        "error",                             // 52
        "serverPublicKeyHex",                // 53
        "origin",                            // 54
        "sessionId",                         // 55
        "wrappedKeyHex",                     // 56
        "wrapIvHex",                         // 57
        "sessionIvHex",                      // 58
        "sealedSessionHex",                  // 59
        "sessionToken",                      // 60
        "ephemeralUniformWords",             // 61
        "tileMap",                           // 62
        "tileMask",                          // 63
        "wmUniform",                         // 64
        "textureCount",                      // 65
        "yaw",                               // 66
        "pitch",                             // 67
        "zoom",                              // 68
        "panY",                              // 69
        "aspect",                            // 70
        "thiefMode",                         // 71
        "fusedMvp",                          // 72
        "camDir",                            // 73
        "u_tile_grid",                       // 74
        "tileGrid",                          // 75
        "AUTOMATION_DENIED",                 // 76
        "STEALTH_BROWSER_DENIED",            // 77
        "VS_ATTEST_V1|",                     // 78
        "attest",                            // 79
    ];

    let mask_csv = mask
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let mut rows = Vec::with_capacity(table.len());
    for (idx, s) in table.iter().enumerate() {
        let enc_bytes: Vec<String> = s
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(bi, &b)| {
                let pad = mask[(idx * 7 + bi) & 31]
                    ^ (idx as u8).wrapping_mul(37).wrapping_add(bi as u8);
                (b ^ pad).to_string()
            })
            .collect();
        rows.push(format!("[{}]", enc_bytes.join(",")));
    }
    let table_js = format!("[{}]", rows.join(","));
    let anti_hook_js = if anti_hook {
        r#"const _chk=(fn)=>{if(typeof fn!=="function"||!_fnStr.call(fn).includes(_s(47)))_fail(_s(48));};_chk(globalThis.fetch);_chk(_sb.generateKey);_chk(_sb.exportKey);_chk(_sb.importKey);_chk(_sb.deriveBits);_chk(_sb.deriveKey);_chk(_sb.unwrapKey);_chk(_sb.decrypt);_chk(_sb.digest);_chk(globalThis.createImageBitmap);_chk(_gl.shaderSource);_chk(_gl.bufferData);_chk(_gl.texImage2D);_chk(_gl.uniform1ui);_chk(_gl.uniform4uiv);_chk(_gl.uniformMatrix4fv);if(globalThis.console&&console.debug)_chk(console.debug);if(globalThis.Response&&Response.prototype){_chk(Response.prototype.text);_chk(Response.prototype.arrayBuffer);}"#
    } else {
        ""
    };
    let anti_cdp_js = if anti_cdp {
        r#"if(navigator&&navigator.webdriver)_fail(_s(76));let _cd=false;try{const _op=Error.prepareStackTrace;Error.prepareStackTrace=()=>{_cd=true;return "";};console.debug(new Error());if(_op===undefined)delete Error.prepareStackTrace;else Error.prepareStackTrace=_op;}catch(_){}if(_cd)_fail(_s(76));"#
    } else {
        ""
    };
    let anti_stealth_js =
        build_tier4_anti_stealth_js(anti_stealth, true, "_s(77)", "_s(78)", "_s(20)");

    format!(
        r#""use strict";(async()=>{{const _cs=document.currentScript;if(_cs)_cs.remove();const _m=[{mask_csv}],_t={table_js};let _fnStr=Function.prototype.toString,_JP=JSON,_TD=TextDecoder,_TE=TextEncoder,_U8=Uint8Array,_U32=Uint32Array,_F32=Float32Array,_Mp=Map;try{{const _fr=document.createElement("iframe");_fr.style.display="none";const _rt=document.documentElement||document.body;if(_rt){{_rt.appendChild(_fr);const _rw=_fr.contentWindow;if(_rw&&_rw.Function&&_rw.JSON){{_fnStr=_rw.Function.prototype.toString;_JP=_rw.JSON;_TD=_rw.TextDecoder;_TE=_rw.TextEncoder;_U8=_rw.Uint8Array;_U32=_rw.Uint32Array;_F32=_rw.Float32Array;_Mp=_rw.Map;}}_fr.remove();}}}}catch(_){{}}const _d=new _TD(),_e=new _TE(),_c=new _Mp(),_s=(i)=>{{if(_c.has(i))return _c.get(i);const a=_t[i],u=new _U8(a.length);for(let j=0;j<a.length;j++)u[j]=a[j]^_m[(i*7+j)&31]^((i*37+j)&255);const v=_d.decode(u);_c.set(i,v);return v;}};const _st=document.getElementById(_s(0)),_fail=(m)=>{{if(_st)_st.textContent=_s(1)+m;throw new Error(m);}},_h2b=(h)=>{{const o=new _U8(h.length>>>1);for(let i=0;i<o.length;i++)o[i]=parseInt(h.slice(i*2,i*2+2),16);return o;}},_b2h=(b)=>{{const u=new _U8(b);let r="";for(let i=0;i<u.length;i++)r+=u[i].toString(16).padStart(2,"0");return r;}};const _cv=document.getElementById(_s(46)),_gl=_cv&&_cv.getContext("webgl2",{{antialias:true,alpha:false}});if(!_gl)_fail(_s(2));const _gc=globalThis.crypto,_sb=_gc&&_gc.subtle;if(!_sb)_fail(_s(3));{anti_hook_js}{anti_cdp_js}const _gk=_sb.generateKey.bind(_sb),_ek=_sb.exportKey.bind(_sb),_ik=_sb.importKey.bind(_sb),_db=_sb.deriveBits.bind(_sb),_dk=_sb.deriveKey.bind(_sb),_uk=_sb.unwrapKey.bind(_sb),_dc=_sb.decrypt.bind(_sb),_dg=_sb.digest.bind(_sb),_nf=globalThis.fetch.bind(globalThis),_Bl=globalThis.Blob,_cb=globalThis.createImageBitmap.bind(globalThis);{anti_stealth_js}let yaw=0.0,pitch=0.08,zoom=3.30,panY=0.0,_as=false,_tf=false,ready=false,dragging=false,lastX=0,lastY=0,camPending=false,needCamUpdate=false;const _presetBtns=["btn-front","btn-hero","btn-halo","btn-back"];function _clearPresets(){{for(const id of _presetBtns){{const b=document.getElementById(id);if(b)b.classList.remove("active");}}}}function _setPreset(y,p,z,py,btnId){{yaw=y;pitch=p;zoom=z;panY=py;_as=false;const bs=document.getElementById("btn-spin");if(bs){{bs.textContent="Auto-Spin: OFF";bs.classList.remove("active");}}_clearPresets();const bn=document.getElementById(btnId);if(bn)bn.classList.add("active");needCamUpdate=true;}}document.getElementById("btn-front").addEventListener("click",()=>_setPreset(0.0,0.08,3.30,0.0,"btn-front"));document.getElementById("btn-hero").addEventListener("click",()=>_setPreset(0.62,0.16,2.95,0.0,"btn-hero"));document.getElementById("btn-halo").addEventListener("click",()=>_setPreset(-0.38,0.22,1.55,0.36,"btn-halo"));document.getElementById("btn-back").addEventListener("click",()=>_setPreset(3.14,0.10,3.30,0.0,"btn-back"));document.getElementById("btn-spin").addEventListener("click",()=>{{_as=!_as;const b=document.getElementById("btn-spin");b.textContent=_as?"Auto-Spin: ON":"Auto-Spin: OFF";b.classList.toggle("active",_as);}});document.getElementById("btn-thief").addEventListener("click",()=>{{_tf=!_tf;const b=document.getElementById("btn-thief"),bg=document.getElementById("mode-badge");b.classList.toggle("active",_tf);b.textContent=_tf?"Return to Authorized Protected View":"Simulate Ripper / RenderDoc Steal Attempt";bg.classList.toggle("danger",_tf);bg.textContent=_tf?"RIPPER / THIEF BUFFER CAPTURE (POISONED!)":"LIVE ENCRYPTED-VRAM GPU SHIELD";needCamUpdate=true;}});_cv.addEventListener("pointerdown",(e)=>{{dragging=true;lastX=e.clientX;lastY=e.clientY;_clearPresets();}});window.addEventListener("pointerup",()=>{{dragging=false;}});window.addEventListener("pointermove",(e)=>{{if(!dragging)return;yaw-=(e.clientX-lastX)*0.0075;pitch=Math.max(-1.25,Math.min(1.25,pitch+(e.clientY-lastY)*0.0065));lastX=e.clientX;lastY=e.clientY;needCamUpdate=true;}});_cv.addEventListener("wheel",(e)=>{{e.preventDefault();zoom=Math.max(0.85,Math.min(6.0,zoom*(1+e.deltaY*0.001)));needCamUpdate=true;}},{{passive:false}});const _tm=document.querySelector(_s(4)),_tk=_tm?_tm.getAttribute(_s(5)):"";if(_tm)_tm.remove();if(!_tk||_tk===_s(6))_fail(_s(7));const _kp=await _gk({{name:_s(8),namedCurve:_s(9)}},false,[_s(10)]),_cp=await _ek(_s(11),_kp.publicKey),_cph=_b2h(_cp),_at=await _vsAt(_tk,_cph),_sb0={{[_s(49)]:_cph,[_s(50)]:_tk}};if(_at)_sb0[_s(79)]=_at;const _lr=await _nf(_s(12),{{method:_s(13),headers:{{[_s(14)]:_s(15)}},body:_JP.stringify(_sb0)}}),_ls=_JP.parse(await _lr.text());if(!_lr.ok||!_ls[_s(51)])_fail(_ls[_s(52)]||_s(16));const _sp=await _ik(_s(11),_h2b(_ls[_s(53)]),{{name:_s(8),namedCurve:_s(9)}},false,[]),_sb2=await _db({{name:_s(8),public:_sp}},_kp.privateKey,256),_hb=await _ik(_s(11),_sb2,_s(17),false,[_s(18)]);new _U8(_sb2).fill(0);const _wi=_e.encode(_s(19)+_ls[_s(54)]),_wk=await _dk({{name:_s(17),hash:_s(20),salt:_e.encode(_ls[_s(55)]),info:_wi}},_hb,{{name:_s(21),length:256}},false,[_s(22)]),_ak=await _uk(_s(11),_h2b(_ls[_s(56)]),_wk,{{name:_s(21),iv:_h2b(_ls[_s(57)]),additionalData:_wi,tagLength:128}},{{name:_s(21),length:256}},false,[_s(23)]);const _sab=await _dc({{name:_s(21),iv:_h2b(_ls[_s(58)]),additionalData:_e.encode(_s(24)+_ls[_s(55)]),tagLength:128}},_ak,_h2b(_ls[_s(59)])),_su=new _U8(_sab),_sd=_JP.parse(_d.decode(_su));_su.fill(0);const _sk=_sd[_s(60)],_er=new _U32(_sd[_s(61)]),_ez=new _U32(64),_tm2=new _U32(_sd[_s(62)]),_tmv=(_sd[_s(63)]>>>0),_tg=(_sd[_s(75)]>>>0)||16,_wu=new _U32(_sd[_s(64)]);_sd[_s(61)].fill(0);_sd[_s(62)].fill(0);_sd[_s(64)].fill(0);async function _fd(url,aad){{const r=await _nf(url,{{headers:{{[_s(25)]:_sk}}}});if(!r.ok)_fail(url+":"+r.status);const rw=new _U8(await r.arrayBuffer()),ab=await _dc({{name:_s(21),iv:rw.slice(0,12),additionalData:_e.encode(aad),tagLength:128}},_ak,rw.slice(12));rw.fill(0);return ab;}}const _tCompStart=performance.now();const [_vsAb,_fsAb,_meshAb]=await Promise.all([_fd(_s(26),_s(27)),_fd(_s(28),_s(29)),_fd(_s(30),_s(31))]);const _vsSrc=_d.decode(_vsAb),_fsSrc=_d.decode(_fsAb);new _U8(_vsAb).fill(0);new _U8(_fsAb).fill(0);function _compile(tp,src){{const sh=_gl.createShader(tp);_gl.shaderSource(sh,src);_gl.compileShader(sh);if(!_gl.getShaderParameter(sh,_gl.COMPILE_STATUS))throw new Error(_gl.getShaderInfoLog(sh));return sh;}}const prog=_gl.createProgram();_gl.attachShader(prog,_compile(_gl.VERTEX_SHADER,_vsSrc));_gl.attachShader(prog,_compile(_gl.FRAGMENT_SHADER,_fsSrc));_gl.linkProgram(prog);if(!_gl.getProgramParameter(prog,_gl.LINK_STATUS))throw new Error(_gl.getProgramInfoLog(prog));const compMs=(performance.now()-_tCompStart).toFixed(0);const dv=new DataView(_meshAb,0,32),totalVerts=dv.getUint32(12,true),realTris=dv.getUint32(16,true),chaffTris=dv.getUint32(20,true),texCount=dv.getUint32(24,true);document.getElementById("st-chaff").textContent=chaffTris.toLocaleString()+" / "+realTris.toLocaleString()+" tris";const cipherWords=new _U32(_meshAb,32,totalVerts*8),vao=_gl.createVertexArray();_gl.bindVertexArray(vao);const vbo=_gl.createBuffer();_gl.bindBuffer(_gl.ARRAY_BUFFER,vbo);_gl.bufferData(_gl.ARRAY_BUFFER,cipherWords,_gl.STATIC_DRAW);_gl.enableVertexAttribArray(0);_gl.vertexAttribIPointer(0,4,_gl.UNSIGNED_INT,32,0);_gl.enableVertexAttribArray(1);_gl.vertexAttribIPointer(1,4,_gl.UNSIGNED_INT,32,16);cipherWords.fill(0);new _U8(_meshAb).fill(0);_gl.useProgram(prog);const _ue=_gl.getUniformLocation(prog,_s(35)),_up=_gl.getUniformLocation(prog,_s(36)),_uth=_gl.getUniformLocation(prog,_s(37)),_uh=_gl.getUniformLocation(prog,_s(38)),_uc=_gl.getUniformLocation(prog,_s(39)),_um=_gl.getUniformLocation(prog,_s(40)),_ut=_gl.getUniformLocation(prog,_s(41)),_ug=_gl.getUniformLocation(prog,_s(74)),_uw=_gl.getUniformLocation(prog,_s(42));_gl.uniform4uiv(_um,_tm2);_tm2.fill(0);_gl.uniform1ui(_ut,_tmv);_gl.uniform1ui(_ug,_tg);_gl.uniform4uiv(_uw,_wu);_wu.fill(0);_gl.uniform1i(_gl.getUniformLocation(prog,_s(43)),0);_gl.uniform1i(_gl.getUniformLocation(prog,_s(44)),1);_gl.uniform1i(_gl.getUniformLocation(prog,_s(45)),2);async function _loadTex(unit,idx){{const ab=await _fd(_s(32)+idx,_s(33)+idx),pt=new _U8(ab),blob=new _Bl([pt]);pt.fill(0);const bmp=await _cb(blob);const tex=_gl.createTexture();_gl.activeTexture(_gl.TEXTURE0+unit);_gl.bindTexture(_gl.TEXTURE_2D,tex);_gl.texImage2D(_gl.TEXTURE_2D,0,_gl.RGBA,_gl.RGBA,_gl.UNSIGNED_BYTE,bmp);_gl.texParameteri(_gl.TEXTURE_2D,_gl.TEXTURE_MIN_FILTER,_gl.LINEAR);_gl.texParameteri(_gl.TEXTURE_2D,_gl.TEXTURE_MAG_FILTER,_gl.LINEAR);_gl.texParameteri(_gl.TEXTURE_2D,_gl.TEXTURE_WRAP_S,_gl.CLAMP_TO_EDGE);_gl.texParameteri(_gl.TEXTURE_2D,_gl.TEXTURE_WRAP_T,_gl.CLAMP_TO_EDGE);bmp.close();return true;}}let loadedTex=0;for(let i=0;i<Math.min(texCount,3);i++){{_st.textContent="Decrypting server-scrambled PBR texture "+(i+1)+"/"+texCount+"...";if(await _loadTex(i,i))loadedTex++;}}_gl.uniform1i(_uh,loadedTex);_gl.enable(_gl.DEPTH_TEST);async function _updateCam(){{if(camPending)return;camPending=true;const aspect=_cv.width/Math.max(1,_cv.height),t0=performance.now();try{{const r=await _nf(_s(34),{{method:_s(13),headers:{{[_s(14)]:_s(15),[_s(25)]:_sk}},body:_JP.stringify({{[_s(66)]:yaw,[_s(67)]:pitch,[_s(68)]:zoom,[_s(69)]:panY,[_s(70)]:aspect,[_s(71)]:_tf}})}});if(!r.ok)_fail(_s(34)+":"+r.status);const d=_JP.parse(await r.text()),dt=(performance.now()-t0).toFixed(2);document.getElementById("st-lat").textContent=dt+" ms";_gl.useProgram(prog);_gl.uniform4uiv(_ue,_tf?_ez:_er);_gl.uniform1i(_uth,_tf?1:0);_gl.uniformMatrix4fv(_up,false,new _F32(d[_s(72)]));_gl.uniform3fv(_uc,new _F32(d[_s(73)]));}}finally{{camPending=false;}}}}const dpr0=Math.min(window.devicePixelRatio||1,2);_cv.width=Math.max(1,Math.floor(window.innerWidth*dpr0));_cv.height=Math.max(1,Math.floor(window.innerHeight*dpr0));await _updateCam();ready=true;window.__VS_READY=true;_st.textContent="Ready • {gpu_stages}-Stage GPU Shader ("+compMs+" ms) • "+realTris.toLocaleString()+" real + "+chaffTris.toLocaleString()+" chaff • Drag to spin";function _frame(){{const dpr=Math.min(window.devicePixelRatio||1,2),w=Math.max(1,Math.floor(window.innerWidth*dpr)),h=Math.max(1,Math.floor(window.innerHeight*dpr));if(_cv.width!==w||_cv.height!==h){{_cv.width=w;_cv.height=h;needCamUpdate=true;}}if(_as){{yaw+=0.014;needCamUpdate=true;}}if(needCamUpdate&&!camPending){{needCamUpdate=false;_updateCam();}}_gl.viewport(0,0,_cv.width,_cv.height);_gl.clearColor(0.045,0.055,0.085,1.0);_gl.clear(_gl.COLOR_BUFFER_BIT|_gl.DEPTH_BUFFER_BIT);if(ready){{_gl.useProgram(prog);_gl.bindVertexArray(vao);_gl.drawArrays(_gl.TRIANGLES,0,totalVerts);}}requestAnimationFrame(_frame);}}requestAnimationFrame(_frame);}})().catch((err)=>{{const s=document.getElementById("status-bar");if(s)s.textContent="Error: "+(err&&err.message?err.message:err);}});
"#
    )
}

fn unix_now_3d() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct TexSealGuard<'a> {
    counter: &'a AtomicUsize,
}

impl<'a> TexSealGuard<'a> {
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

impl Drop for TexSealGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Release);
    }
}

struct Active3dSession {
    auth_token: String,
    origin: String,
    asset_key: [u8; 32],
    proj_seed: [u8; 32],
    wm64_id: u64,
    fov_deg: f32,
    near: f32,
    far: f32,
    yaw_bias: f32,
    pitch_bias: f32,
    zoom_scale: f32,
    roll_bias: f32,
    pan_y_bias: f32,
    expires_at: u64,
    camera_calls: usize,
    asset_calls: usize,
}

impl Drop for Active3dSession {
    fn drop(&mut self) {
        secure_zero(&mut self.asset_key);
        secure_zero(&mut self.proj_seed);
    }
}

struct ShieldServerState {
    asset_id: String,
    tex_count: usize,
    tile_mask: u32,
    tile_grid: u32,
    csp: CspMode,
    anti_stealth: AntiStealthMode,
    wm_w: u32,
    camera_jitter: f32,
    ticket_ttl_sec: u64,
    session_ttl_sec: u64,
    camera_budget: usize,
    asset_budget: usize,
    max_sessions: usize,
    max_tex_concurrency: usize,
    header_timeout: Duration,
    body_timeout: Duration,
    masked_tmap_csv: String,
    ticket_secret: [u8; 32],
    wm_key: [u8; 32],
    auth: AuthConfig,
    allowed_origin: Option<String>,
    trusted_proxies: Vec<IpAddr>,
    bound_addr: SocketAddr,
    guard: HttpLeaseGuard,
    conn_limiter: ConnLimiter,
    active_tex_seals: AtomicUsize,
    sessions: Mutex<HashMap<String, Active3dSession>>,
    index_prefix: Vec<u8>,
    index_suffix: Vec<u8>,
    loader_js: Vec<u8>,
    scene_bin: Vec<u8>,
    vert_glsl: Vec<u8>,
    frag_glsl: Vec<u8>,
    enc_textures: Vec<Vec<u8>>,
    tex_key: [u8; 32],
    w_lat: [f32; 16],
    lat_m: [[i64; 3]; 3],
    t_lat: [i64; 3],
    stages: Vec<[GpuRoundSpec; 8]>,
    ephem: [[u32; 4]; 16],
    wm_carriers: Vec<WmCarrier>,
    ephem_words: [i64; 64],
}

impl Drop for ShieldServerState {
    fn drop(&mut self) {
        secure_zero(&mut self.ticket_secret);
        secure_zero(&mut self.wm_key);
        secure_zero(&mut self.tex_key);
    }
}

fn encrypt_session_blob(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(12 + plain.len() + 16);
    out.resize(12, 0u8);
    os_random_bytes(&mut out[..12])?;
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&out[..12]);
    out.extend_from_slice(plain);
    let tag = aes256_gcm_seal_in_place(key, &iv, aad, &mut out[12..12 + plain.len()]);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Bakes a buyer/session-specific 64-bit forensic BPSK watermark directly into `scene.vsshield2`
/// carrier vertices in quantized object space BEFORE Feistel encryption (< 0.3 ms for 2,048 verts),
/// so even a Transform Feedback rip that strips `u_vs_wm` permanently retains the leaker's ID!
fn bake_per_session_wm64_scene(
    state: &ShieldServerState,
    wm64_id: u64,
) -> Vec<u8> {
    let mut out = state.scene_bin.clone();
    if state.wm_w == 0 || state.wm_carriers.is_empty() || out.len() < 32 {
        return out;
    }
    let delta: i64 = (state.wm_w / 6).clamp(1, 4) as i64;
    for (ci, c) in state.wm_carriers.iter().enumerate() {
        let off = 32 + (c.vid as usize) * 32;
        if off + 16 > out.len() {
            continue;
        }
        let bit_idx = ci & 63;
        let bsign: i64 = if ((wm64_id >> bit_idx) & 1) != 0 { 1 } else { -1 };
        let chip = carrier_chip_sign(&state.wm_key, c.vid);
        let d = bsign * chip * delta;
        let qx = ((c.qx as i64) + d).clamp(-16384, 16384);
        let qy = ((c.qy as i64) - d).clamp(-16384, 16384);
        let qz = ((c.qz as i64) + d).clamp(-16384, 16384);
        let wx = (state.lat_m[0][0] * qx + state.lat_m[0][1] * qy + state.lat_m[0][2] * qz + state.t_lat[0]) as i32;
        let wy = (state.lat_m[1][0] * qx + state.lat_m[1][1] * qy + state.lat_m[1][2] * qz + state.t_lat[1]) as i32;
        let wz = (state.lat_m[2][0] * qx + state.lat_m[2][1] * qy + state.lat_m[2][2] * qz + state.t_lat[2]) as i32;
        let enc_pos = encrypt_gpu_lanes(
            [wx as u32, wy as u32, wz as u32, c.tag],
            &state.stages,
            &state.ephem,
            c.vid,
        );
        out[off..off + 4].copy_from_slice(&enc_pos[0].to_le_bytes());
        out[off + 4..off + 8].copy_from_slice(&enc_pos[1].to_le_bytes());
        out[off + 8..off + 12].copy_from_slice(&enc_pos[2].to_le_bytes());
        out[off + 12..off + 16].copy_from_slice(&enc_pos[3].to_le_bytes());
    }
    out
}

struct Verified3dSession {
    asset_key: [u8; 32],
    proj_seed: [u8; 32],
    wm64_id: u64,
    fov_deg: f32,
    near: f32,
    far: f32,
    yaw_bias: f32,
    pitch_bias: f32,
    zoom_scale: f32,
    roll_bias: f32,
    pan_y_bias: f32,
}

impl Drop for Verified3dSession {
    fn drop(&mut self) {
        secure_zero(&mut self.asset_key);
        secure_zero(&mut self.proj_seed);
    }
}

fn verify_3d_session(
    state: &ShieldServerState,
    session_hdr: Option<&str>,
    origin_hdr: Option<&str>,
    strict_origin: Option<&str>,
    count_camera: bool,
    count_asset: bool,
) -> Result<Verified3dSession, (u16, &'static str, &'static str)> {
    let Some(raw) = session_hdr else {
        return Err((403, "Forbidden", "SESSION_REQUIRED"));
    };
    let Some((sid, tok)) = raw.trim().split_once('.') else {
        return Err((403, "Forbidden", "SESSION_REQUIRED"));
    };
    let now = unix_now_3d();
    let mut guard = state
        .sessions
        .lock()
        .map_err(|_| (500, "Internal Server Error", "LOCK_POISONED"))?;
    if guard.len() > 256 {
        guard.retain(|_, s| s.expires_at >= now);
    }
    let Some(sess) = guard.get_mut(sid) else {
        return Err((403, "Forbidden", "SESSION_REQUIRED"));
    };
    if sess.expires_at < now || !ct_str_eq(tok.as_bytes(), sess.auth_token.as_bytes()) {
        return Err((403, "Forbidden", "SESSION_REQUIRED"));
    }
    if let Some(strict) = strict_origin {
        if strict != sess.origin {
            return Err((403, "Forbidden", "ORIGIN_DENIED"));
        }
    } else if let Some(org) = origin_hdr {
        if org != sess.origin {
            return Err((403, "Forbidden", "ORIGIN_DENIED"));
        }
    }
    if count_camera {
        if sess.camera_calls >= state.camera_budget {
            return Err((429, "Too Many Requests", "CAMERA_BUDGET_EXHAUSTED"));
        }
        sess.camera_calls += 1;
    }
    if count_asset {
        if sess.asset_calls >= state.asset_budget {
            return Err((429, "Too Many Requests", "ASSET_BUDGET_EXHAUSTED"));
        }
        sess.asset_calls += 1;
    }
    Ok(Verified3dSession {
        asset_key: sess.asset_key,
        proj_seed: sess.proj_seed,
        wm64_id: sess.wm64_id,
        fov_deg: sess.fov_deg,
        near: sess.near,
        far: sess.far,
        yaw_bias: sess.yaw_bias,
        pitch_bias: sess.pitch_bias,
        zoom_scale: sess.zoom_scale,
        roll_bias: sess.roll_bias,
        pan_y_bias: sess.pan_y_bias,
    })
}

fn handle_3d_session_post(
    stream: &mut TcpStream,
    state: &ShieldServerState,
    ip: IpAddr,
    peer_trusted: bool,
    buyer_id: Option<&str>,
    req: &crate::web_runtime::ParsedRequest,
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

    let mut rand_buf = [0u8; 138];
    if os_random_bytes(&mut rand_buf).is_err() {
        secure_zero(&mut shared_32);
        send_json_err_with_csp(stream, 500, "Internal Server Error", "RNG_FAILED", keep_alive, state.csp);
        return;
    }

    let mut session_id = String::with_capacity(32);
    write_hex_bytes(&rand_buf[0..16], &mut session_id);
    let mut auth_token = String::with_capacity(48);
    write_hex_bytes(&rand_buf[16..40], &mut auth_token);

    let mut asset_key = [0u8; 32];
    asset_key.copy_from_slice(&rand_buf[40..72]);
    let mut wrap_iv = [0u8; 12];
    wrap_iv.copy_from_slice(&rand_buf[72..84]);
    let mut sess_iv = [0u8; 12];
    sess_iv.copy_from_slice(&rand_buf[84..96]);
    let mut proj_seed = [0u8; 32];
    proj_seed.copy_from_slice(&rand_buf[106..138]);

    // Derive invisible per-buyer (or per-session) forensic GPU & lattice-baked WM64 ID
    let wm_subject = buyer_id.unwrap_or(&session_id);
    let wm_mac = hmac_sha256(&state.wm_key, format!("VS3D_WM_V1|{wm_subject}").as_bytes());
    let wm0 = u32::from_le_bytes([wm_mac[0], wm_mac[1], wm_mac[2], wm_mac[3]]);
    let wm1 = u32::from_le_bytes([wm_mac[4], wm_mac[5], wm_mac[6], wm_mac[7]]);
    let wm2 = u32::from_le_bytes([wm_mac[8], wm_mac[9], wm_mac[10], wm_mac[11]]);
    let wm64_id = u64::from_le_bytes([
        wm_mac[16], wm_mac[17], wm_mac[18], wm_mac[19],
        wm_mac[20], wm_mac[21], wm_mac[22], wm_mac[23],
    ]);

    let unit_f = |b: u8| -> f32 { (b as f32) / 255.0 };
    let j = state.camera_jitter;
    let fov_deg = (37.0 + (unit_f(rand_buf[98]) - 0.5) * 8.0 * j).clamp(22.0, 62.0);
    let near = (0.06 + (unit_f(rand_buf[99]) - 0.5) * 0.04 * j).clamp(0.01, 0.25);
    let far = (40.0 + (unit_f(rand_buf[100]) - 0.5) * 24.0 * j).clamp(12.0, 120.0);
    let yaw_bias = (unit_f(rand_buf[101]) - 0.5) * 0.06 * j;
    let pitch_bias = (unit_f(rand_buf[102]) - 0.5) * 0.04 * j;
    let zoom_scale = (1.0 + (unit_f(rand_buf[103]) - 0.5) * 0.10 * j).clamp(0.6, 1.5);
    let roll_bias = (unit_f(rand_buf[104]) - 0.5) * 0.05 * j;
    let pan_y_bias = (unit_f(rand_buf[105]) - 0.5) * 0.06 * j;

    // Enforce bounded active session map before completing wrap
    let expires_at = unix_now_3d() + state.session_ttl_sec;
    {
        let Ok(mut guard) = state.sessions.lock() else {
            secure_zero(&mut shared_32);
            secure_zero(&mut asset_key);
            secure_zero(&mut proj_seed);
            send_json_err_with_csp(stream, 500, "Internal Server Error", "LOCK_POISONED", keep_alive, state.csp);
            return;
        };
        let now = unix_now_3d();
        if guard.len() > 256 {
            guard.retain(|_, s| s.expires_at >= now);
        }
        if guard.len() >= state.max_sessions {
            secure_zero(&mut shared_32);
            secure_zero(&mut asset_key);
            secure_zero(&mut proj_seed);
            send_json_err_with_csp(stream, 503, "Service Unavailable", "SERVER_BUSY", keep_alive, state.csp);
            return;
        }
        guard.insert(
            session_id.clone(),
            Active3dSession {
                auth_token: auth_token.clone(),
                origin: effective_origin.to_string(),
                asset_key,
                proj_seed,
                wm64_id,
                fov_deg,
                near,
                far,
                yaw_bias,
                pitch_bias,
                zoom_scale,
                roll_bias,
                pan_y_bias,
                expires_at,
                camera_calls: 0,
                asset_calls: 0,
            },
        );
    }

    let wrap_info = format!("VS3D_WRAP|{effective_origin}");
    let mut wrap_key = hkdf_sha256_32(&shared_32, session_id.as_bytes(), wrap_info.as_bytes());
    secure_zero(&mut shared_32);

    let (ct_key, tag_key) =
        aes256_gcm_seal(&wrap_key, &wrap_iv, wrap_info.as_bytes(), &asset_key);
    secure_zero(&mut wrap_key);

    let sess_tok = format!("{session_id}.{auth_token}");
    let ephem_csv = state
        .ephem_words
        .iter()
        .map(|w| w.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let plain_payload = format!(
        "{{\"sessionToken\":\"{sess_tok}\",\"ephemeralUniformWords\":[{ephem_csv}],\"tileMap\":[{}],\"tileMask\":{},\"tileGrid\":{},\"wmUniform\":[{wm0},{wm1},{wm2},{}],\"textureCount\":{}}}",
        state.masked_tmap_csv, state.tile_mask, state.tile_grid, state.wm_w, state.tex_count
    );
    let sess_aad = format!("VS3D_SESSION|{session_id}");
    let (ct_sess, tag_sess) =
        aes256_gcm_seal(&asset_key, &sess_iv, sess_aad.as_bytes(), plain_payload.as_bytes());
    secure_zero(&mut asset_key);

    let mut resp = String::with_capacity(640 + ct_sess.len() * 2);
    resp.push_str("{\"ok\":true,\"assetId\":\"");
    resp.push_str(&state.asset_id);
    resp.push_str("\",\"sessionId\":\"");
    resp.push_str(&session_id);
    resp.push_str("\",\"origin\":\"");
    resp.push_str(effective_origin);
    resp.push_str("\",\"serverPublicKeyHex\":\"");
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

fn handle_3d_client(mut stream: TcpStream, state: &ShieldServerState) {
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
            let body: &[u8] = if method == "HEAD" { b"" } else { b"{\"ok\":true}" };
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
                    send_json_err_with_csp(
                        &mut stream,
                        500,
                        "Internal Server Error",
                        "TICKET_GEN_FAILED",
                        false,
                        state.csp,
                    );
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
            } else if method == "GET" && path == "/__vibeslayer/3d-loader.js" {
                send_http_with_csp(
                    &mut stream,
                    200,
                    "OK",
                    "application/javascript; charset=utf-8",
                    &state.loader_js,
                    keep_alive,
                    state.csp,
                );
            } else if method == "POST" && path == "/__vibeslayer/session" {
                let peer_trusted = state.trusted_proxies.contains(&peer_ip);
                handle_3d_session_post(
                    &mut stream,
                    state,
                    ip,
                    peer_trusted,
                    buyer_opt.as_deref(),
                    &req,
                    keep_alive,
                );
            } else if method == "GET"
                && matches!(
                    path,
                    "/shield_pbr.vert.glsl" | "/shield_pbr.frag.glsl" | "/scene.vsshield2"
                )
            {
                match verify_3d_session(
                    state,
                    req.x_vs_session.as_deref(),
                    req.origin.as_deref(),
                    None,
                    false,
                    true,
                ) {
                    Ok(sess) => {
                        let aad = format!("VS3D_ASSET|{path}");
                        let seal_res = match path {
                            "/shield_pbr.vert.glsl" => {
                                encrypt_session_blob(&sess.asset_key, aad.as_bytes(), &state.vert_glsl)
                            }
                            "/shield_pbr.frag.glsl" => {
                                encrypt_session_blob(&sess.asset_key, aad.as_bytes(), &state.frag_glsl)
                            }
                            _ => {
                                let wm_scene = bake_per_session_wm64_scene(state, sess.wm64_id);
                                encrypt_session_blob(&sess.asset_key, aad.as_bytes(), &wm_scene)
                            }
                        };
                        match seal_res {
                            Ok(blob) => send_http_with_csp(
                                &mut stream,
                                200,
                                "OK",
                                "application/octet-stream",
                                &blob,
                                keep_alive,
                                state.csp,
                            ),
                            Err(_) => send_json_err_with_csp(
                                &mut stream,
                                500,
                                "Internal Server Error",
                                "SEAL_FAILED",
                                keep_alive,
                                state.csp,
                            ),
                        }
                    }
                    Err((st, rs, code)) => send_json_err_with_csp(&mut stream, st, rs, code, keep_alive, state.csp),
                }
            } else if method == "GET" && path.starts_with("/__vibeslayer/tex/") {
                let idx_str = path.trim_start_matches("/__vibeslayer/tex/");
                let idx: usize = idx_str.parse().unwrap_or(999);
                match verify_3d_session(
                    state,
                    req.x_vs_session.as_deref(),
                    req.origin.as_deref(),
                    None,
                    false,
                    true,
                ) {
                    Ok(sess) => {
                        if let Some(enc) = state.enc_textures.get(idx) {
                            let Some(_tex_guard) =
                                TexSealGuard::try_acquire(&state.active_tex_seals, state.max_tex_concurrency)
                            else {
                                send_json_err_with_csp(
                                    &mut stream,
                                    503,
                                    "Service Unavailable",
                                    "SERVER_BUSY",
                                    keep_alive,
                                    state.csp,
                                );
                                if !keep_alive {
                                    return;
                                }
                                continue;
                            };
                            // Single-buffer in-place ChaCha20 + AES-256-GCM sealing (~3x less RAM!)
                            let mut blob = vec![0u8; 12 + enc.len() + 16];
                            if os_random_bytes(&mut blob[..12]).is_err() {
                                send_json_err_with_csp(
                                    &mut stream,
                                    500,
                                    "Internal Server Error",
                                    "RNG_FAILED",
                                    keep_alive,
                                    state.csp,
                                );
                                if !keep_alive {
                                    return;
                                }
                                continue;
                            }
                            let mut iv = [0u8; 12];
                            iv.copy_from_slice(&blob[..12]);
                            let mut nonce = [0u8; 12];
                            nonce[0..4].copy_from_slice(&(idx as u32).to_le_bytes());
                            chacha20_xor_into(
                                &state.tex_key,
                                1,
                                &nonce,
                                enc,
                                &mut blob[12..12 + enc.len()],
                            );
                            let aad = format!("VS3D_TEX|{idx}");
                            let tag = aes256_gcm_seal_in_place(
                                &sess.asset_key,
                                &iv,
                                aad.as_bytes(),
                                &mut blob[12..12 + enc.len()],
                            );
                            blob[12 + enc.len()..].copy_from_slice(&tag);
                            send_http_with_csp(
                                &mut stream,
                                200,
                                "OK",
                                "application/octet-stream",
                                &blob,
                                keep_alive,
                                state.csp,
                            );
                        } else {
                            send_json_err_with_csp(&mut stream, 404, "Not Found", "NOT_FOUND", keep_alive, state.csp);
                        }
                    }
                    Err((st, rs, code)) => send_json_err_with_csp(&mut stream, st, rs, code, keep_alive, state.csp),
                }
            } else if method == "POST" && path == "/__vibeslayer/camera" {
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
                match verify_3d_session(
                    state,
                    req.x_vs_session.as_deref(),
                    req.origin.as_deref(),
                    Some(effective_origin),
                    true,
                    false,
                ) {
                    Ok(sess) => {
                        let req_j =
                            parse_json(&String::from_utf8_lossy(&req.body)).unwrap_or(JsonVal::Null);
                        let get_f = |k: &str, def: f32| -> f32 {
                            let v = match req_j.get(k) {
                                Some(JsonVal::Num(n)) => *n as f32,
                                Some(JsonVal::Int(n)) => *n as f32,
                                _ => def,
                            };
                            if v.is_finite() { v } else { def }
                        };
                        let q = |v: f32, step: f32| -> f32 { (v / step).round() * step };
                        let yaw_q = q(get_f("yaw", 0.0), 0.005);
                        let pitch_q = q(get_f("pitch", 0.08).clamp(-1.35, 1.35), 0.005);
                        let zoom_q = q(get_f("zoom", 3.30).clamp(0.7, 10.0), 0.01);
                        let pan_y_q = q(get_f("panY", 0.0).clamp(-2.0, 2.0), 0.01);
                        let aspect_q = q(get_f("aspect", 1.6).clamp(0.3, 4.0), 0.005);

                        let mut rb = [0u8; 4];
                        if os_random_bytes(&mut rb).is_err() {
                            send_json_err_with_csp(
                                &mut stream,
                                500,
                                "Internal Server Error",
                                "RNG_FAILED",
                                keep_alive,
                                state.csp,
                            );
                            if !keep_alive {
                                return;
                            }
                            continue;
                        }

                        // Compute lighting camDir strictly from UNBIASED angles (zero bias oracle)
                        let cam_dir = unbiased_cam_dir(yaw_q, pitch_q);
                        let (cx, cy, skew, asp_mul, fov_delta) = derive_angle_varying_intrinsics(
                            &sess.proj_seed,
                            yaw_q,
                            pitch_q,
                            state.camera_jitter,
                        );
                        let vp = build_orbit_mvp(
                            yaw_q + sess.yaw_bias,
                            pitch_q + sess.pitch_bias,
                            zoom_q * sess.zoom_scale,
                            pan_y_q + sess.pan_y_bias,
                            sess.roll_bias,
                            aspect_q,
                            sess.fov_deg + fov_delta,
                            sess.near,
                            sess.far,
                            cx,
                            cy,
                            skew,
                            asp_mul,
                        );
                        // Never return raw un-inverted `vp` even if thiefMode is requested.
                        let mut fused = mat4_mul(&vp, &state.w_lat);
                        let u = (u32::from_le_bytes(rb) as f64) / (u32::MAX as f64);
                        let lambda = (0.65 + u * 0.90) as f32;
                        for entry in &mut fused {
                            *entry *= lambda;
                        }

                        let m_str = fused
                            .iter()
                            .map(|v| format!("{v:.7}"))
                            .collect::<Vec<_>>()
                            .join(",");
                        let c_str = cam_dir
                            .iter()
                            .map(|v| format!("{v:.5}"))
                            .collect::<Vec<_>>()
                            .join(",");
                        let out_json =
                            format!("{{\"ok\":true,\"fusedMvp\":[{m_str}],\"camDir\":[{c_str}]}}");
                        send_http_with_csp(
                            &mut stream,
                            200,
                            "OK",
                            "application/json; charset=utf-8",
                            out_json.as_bytes(),
                            keep_alive,
                            state.csp,
                        );
                    }
                    Err((st, rs, code)) => send_json_err_with_csp(&mut stream, st, rs, code, keep_alive, state.csp),
                }
            } else {
                send_json_err_with_csp(&mut stream, 404, "Not Found", "NOT_FOUND", keep_alive, state.csp);
            }
        }

        if !keep_alive {
            return;
        }
    }
}

pub fn serve_shielded_3d_viewer(
    shield_dir: &Path,
    addr: &str,
    origin_override: Option<&str>,
    auth_secret: Option<&str>,
    max_leases_per_min: usize,
    key_file_opt: Option<&Path>,
    auth_hmac_key: Option<&str>,
    trust_proxy: Option<&str>,
) -> Result<(), String> {
    let mut params = Serve3dParams::from_preset(SecurityPreset::Balanced);
    params.addr = addr.to_string();
    params.origin = origin_override.map(|o| o.to_string());
    params.auth_secret = auth_secret.map(|s| s.to_string());
    params.max_leases_per_min = max_leases_per_min;
    params.key_file = key_file_opt.map(|p| p.to_path_buf());
    params.auth_hmac_key = auth_hmac_key.map(|k| k.to_string());
    params.trust_proxy = trust_proxy.map(|t| t.to_string());
    serve_shielded_3d_viewer_with_params(shield_dir, &params)
}

pub fn serve_shielded_3d_viewer_with_params(
    shield_dir: &Path,
    params: &Serve3dParams,
) -> Result<(), String> {
    params.validate()?;
    if params.render_mode == crate::params::RenderMode3d::Stream {
        return crate::raster_stream::serve_streamed_3d_viewer(shield_dir, params);
    }
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
        .map_err(|e| format!("Missing viewer.meta.json (run shield-3d on a standard GLB first): {e}"))?;
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
    let tile_grid = meta
        .get("tileGrid")
        .and_then(|v| v.as_i64())
        .map(|n| n.max(0) as usize)
        .unwrap_or(16);
    let tile_mask = meta
        .get("tileScrambledMask")
        .and_then(|v| v.as_i64())
        .map(|m| m.max(0) as u32)
        .unwrap_or_else(|| {
            if meta.get("tileScrambled").and_then(|v| v.as_bool()).unwrap_or(false) {
                (1u32 << tex_count.min(31)).saturating_sub(1)
            } else {
                0
            }
        });

    let lat_seed = hmac_sha256(&master_key, format!("VS3D_SHIELD_LAT_V1|{asset_id}").as_bytes());
    let shader_seed = hmac_sha256(&master_key, format!("VS3D_SHIELD_SHD_V1|{asset_id}").as_bytes());
    let tex_key = hmac_sha256(&master_key, format!("VS3D_SHIELD_TEX_V1|{asset_id}").as_bytes());
    let tmap_seed = hmac_sha256(&master_key, format!("VS3D_SHIELD_TMAP_V2|{asset_id}").as_bytes());
    let wm_key = hmac_sha256(&master_key, format!("VS3D_SHIELD_WM_V1|{asset_id}").as_bytes());
    let (lat_m, lat_inv) = derive_unimodular_lattice_3x3(&lat_seed);
    let t_lat = if lattice_ver >= 2 {
        derive_lattice_offset(&lat_seed)
    } else {
        [0, 0, 0]
    };
    let stages = derive_gpu_stage_specs_n(&shader_seed, gpu_stages);
    let ephem = derive_ephemeral_gpu_uniforms(&master_key, &asset_id);
    let tmap = derive_tile_map(&tmap_seed, tile_grid.max(1));
    secure_zero(&mut master_key);

    let wm_carriers = match fs::read(shield_dir.join("wm_carriers.vsbin")) {
        Ok(enc) => {
            let mut plain = vec![0u8; enc.len()];
            chacha20_xor_into(&wm_key, 1, &WM_CARRIER_NONCE, &enc, &mut plain);
            let parsed = deserialize_wm_carriers(&plain).unwrap_or_default();
            secure_zero(&mut plain);
            parsed
        }
        Err(_) => Vec::new(),
    };

    let mut ephem_words = [0i64; 64];
    let mut ei = 0usize;
    for u4 in &ephem {
        for &w in u4 {
            ephem_words[ei] = w as i64;
            ei += 1;
        }
    }

    // Pre-mask 256-entry tile map against `u_vs_ephem` so shader unmasks via `u_vs_tmap[k] ^ u_vs_ephem[k & 15u]`
    let mut masked_tmap_parts = Vec::with_capacity(256);
    for orig in 0..256usize {
        let k = orig >> 2;
        let slot = orig & 3;
        let masked = tmap[orig] ^ ephem[k & 15][slot];
        masked_tmap_parts.push(masked.to_string());
    }
    let masked_tmap_csv = masked_tmap_parts.join(",");

    let scene_bin = fs::read(shield_dir.join("scene.vsshield2")).map_err(|e| e.to_string())?;
    let vert_glsl = fs::read(shield_dir.join("shield_pbr.vert.glsl")).map_err(|e| e.to_string())?;
    let frag_glsl = emit_rich_frag_shader().as_bytes().to_vec();

    let display_title = params.title.as_deref().unwrap_or(&asset_id);
    let html_raw = build_viewer_html(display_title, gpu_stages);
    let (p, s) = html_raw
        .split_once("__VS_3D_TICKET__")
        .ok_or_else(|| "HTML_MISSING_TICKET_PLACEHOLDER".to_string())?;
    let index_prefix = p.as_bytes().to_vec();
    let index_suffix = s.as_bytes().to_vec();
    let loader_js = build_hardened_3d_loader_js(
        &asset_id,
        params.anti_hook,
        params.anti_cdp,
        params.anti_stealth,
        gpu_stages,
    )
    .into_bytes();

    let mut enc_textures = Vec::with_capacity(tex_count);
    for i in 0..tex_count {
        enc_textures.push(fs::read(shield_dir.join(format!("tex_{i}.vsbin"))).unwrap_or_default());
    }

    let mut ticket_secret = [0u8; 32];
    os_random_bytes(&mut ticket_secret)?;

    let auth = AuthConfig::from_opts(params.auth_secret.as_deref(), params.auth_hmac_key.as_deref())?;
    let trusted_proxies = parse_trusted_proxies(params.trust_proxy.as_deref())?;

    let inv_q_scale = half_ext / 16384.0f32;
    let mut w_lat = [0.0f32; 16];
    for c in 0..3 {
        for r in 0..3 {
            w_lat[c * 4 + r] = (lat_inv[r][c] as f32) * inv_q_scale;
        }
    }
    if lattice_ver >= 2 {
        let t_lat = derive_lattice_offset(&lat_seed);
        for r in 0..3 {
            let inv_t_r =
                lat_inv[r][0] * t_lat[0] + lat_inv[r][1] * t_lat[1] + lat_inv[r][2] * t_lat[2];
            w_lat[12 + r] = -(inv_t_r as f32) * inv_q_scale;
        }
    }
    w_lat[15] = 1.0;

    let _ = p256_generate_keypair();

    let listener = TcpListener::bind(&params.addr)
        .map_err(|e| format!("Failed binding {}: {e}", params.addr))?;
    let bound = listener.local_addr().map_err(|e| e.to_string())?;
    let wm_w = params.wm_uniform_w();
    let num_workers = params.resolved_workers();
    println!(
        "{{\"ok\":true,\"listening\":\"http://{}\",\"preset\":\"{}\",\"assetId\":\"{}\",\"gpuStages\":{},\"halfExtent\":{:.6},\"latticeVersion\":{},\"tileGrid\":{},\"tileMask\":{},\"watermark\":{},\"antiHook\":{},\"antiCdp\":{},\"cspMode\":\"{}\",\"workers\":{}}}",
        bound,
        params.preset.as_str(),
        asset_id,
        gpu_stages,
        half_ext,
        lattice_ver,
        tile_grid,
        tile_mask,
        wm_w > 0,
        params.anti_hook,
        params.anti_cdp,
        params.csp.as_str(),
        num_workers
    );
    let _ = std::io::Write::flush(&mut std::io::stdout());

    let state = std::sync::Arc::new(ShieldServerState {
        asset_id,
        tex_count,
        tile_mask,
        tile_grid: tile_grid.max(1) as u32,
        csp: params.csp,
        anti_stealth: params.anti_stealth,
        wm_w,
        camera_jitter: params.camera_jitter,
        ticket_ttl_sec: params.ticket_ttl_sec,
        session_ttl_sec: params.session_ttl_sec,
        camera_budget: params.camera_budget,
        asset_budget: params.asset_budget,
        max_sessions: params.max_sessions,
        max_tex_concurrency: params.max_tex_concurrency,
        header_timeout: Duration::from_millis(params.header_timeout_ms),
        body_timeout: Duration::from_millis(params.body_timeout_ms),
        masked_tmap_csv,
        ticket_secret,
        wm_key,
        auth,
        allowed_origin: params.origin.clone(),
        trusted_proxies,
        bound_addr: bound,
        guard: HttpLeaseGuard::new(params.max_leases_per_min),
        conn_limiter: ConnLimiter::new(params.max_conns_per_ip),
        active_tex_seals: AtomicUsize::new(0),
        sessions: Mutex::new(HashMap::new()),
        index_prefix,
        index_suffix,
        loader_js,
        scene_bin,
        vert_glsl,
        frag_glsl,
        enc_textures,
        tex_key,
        w_lat,
        lat_m,
        t_lat,
        stages,
        ephem,
        wm_carriers,
        ephem_words,
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
                handle_3d_client(stream, &st);
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
                send_json_err_with_csp(
                    &mut stream,
                    503,
                    "Service Unavailable",
                    "SERVER_BUSY",
                    false,
                    state.csp,
                );
                continue;
            }
            guard.push_back(stream);
            cv.notify_one();
        }
    }
    Ok(())
}
