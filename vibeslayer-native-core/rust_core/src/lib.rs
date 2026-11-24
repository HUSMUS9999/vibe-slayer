//! `vibeslayer_core` (`1.0.0-beta.3`) — Zero-dependency native Rust protection core:
//! - Source-code per-action `Policy` (`DEFAULT_ENABLED = false`, typed parameter bounds)
//! - FIPS 180-4 `SHA-256`, `HMAC-SHA256`, `HKDF-SHA256`
//! - RFC 8439 `ChaCha20-Poly1305` AEAD (`VSPK2` & `VSPK3` wire formats shared with C, Go, Python)
//! - 3D `.glb` -> `VS3D` cooked `int16` SNORM stream + 1,024-chip & 64-bit O(1) BPSK watermarks
//! - Native Linux `ELF64` packers (`.vsblob`, `v0.9.0` dynamic elite, `v1.0.0` freestanding)

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

pub mod auto_cli;
pub mod encrypted_compute;
pub mod jpeg_enc;
pub mod mini_json;
pub mod nl_cli;
pub mod params;
pub mod png_tile;
pub mod raster_stream;
pub mod shield_viewer;
pub mod v090_elite;
pub mod v100_zero_overhead;
pub mod web_runtime;
pub use v090_elite::{
    build_protected_elf_elite, pack_vspk3, unseal_vspk3, unseal_vspk3_owned, VSPK3_PREFIX_LEN,
};
pub use v100_zero_overhead::{
    build_protected_elf_freestanding, decode_wm64_o1, embed_wm64_for_lease, wrap_elf_freestanding,
};

pub const VERSION: &str = "1.0.0-beta.3";

#[inline]
pub fn secure_zero(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned, uniquely borrowed mutable reference.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

#[inline]
fn secure_zero_u32(buf: &mut [u32]) {
    for w in buf.iter_mut() {
        // SAFETY: `w` is a valid, aligned, uniquely borrowed mutable reference.
        unsafe { std::ptr::write_volatile(w, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
pub const DEFAULT_ENABLED: bool = false;
pub const MAGIC_VSPK2: &[u8; 5] = b"VSPK2";
pub const CHIPS_TOTAL: usize = 1024;

#[derive(Clone, Debug)]
pub enum ParamRule {
    Int { min: i64, max: i64 },
    Str { min_len: usize, max_len: usize },
    Bool,
    Enum(Vec<String>),
}

#[derive(Clone, Debug)]
pub enum ParamValue {
    Int(i64),
    Str(String),
    Bool(bool),
}

#[derive(Clone, Debug)]
pub struct ActionRule {
    pub domain: String,
    pub context: String,
    pub params: HashMap<String, ParamRule>,
}

#[derive(Clone)]
pub struct Policy {
    pub enabled: bool,
    pub master_key: [u8; 32],
    pub actions: HashMap<String, ActionRule>,
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("enabled", &self.enabled)
            .field("master_key", &"[REDACTED]")
            .field("actions", &self.actions)
            .finish()
    }
}

impl Drop for Policy {
    fn drop(&mut self) {
        secure_zero(&mut self.master_key);
    }
}

impl Policy {
    pub fn new_disabled(master_key: [u8; 32]) -> Self {
        Self {
            enabled: DEFAULT_ENABLED,
            master_key,
            actions: HashMap::new(),
        }
    }

    pub fn validate_call(
        &self,
        action_name: &str,
        supplied: &HashMap<String, ParamValue>,
    ) -> Result<&ActionRule, String> {
        if !self.enabled {
            return Err("POLICY_DISABLED".to_string());
        }
        let act = self
            .actions
            .get(action_name)
            .ok_or_else(|| format!("UNKNOWN_ACTION:{action_name}"))?;
        for k in supplied.keys() {
            if !act.params.contains_key(k) {
                return Err(format!("UNKNOWN_PARAM:{k}"));
            }
        }
        for (name, rule) in &act.params {
            let val = supplied
                .get(name)
                .ok_or_else(|| format!("MISSING_PARAM:{name}"))?;
            match (rule, val) {
                (ParamRule::Int { min, max }, ParamValue::Int(v)) => {
                    if v < min || v > max {
                        return Err(format!("PARAM_OUT_OF_RANGE:{name}"));
                    }
                }
                (ParamRule::Str { min_len, max_len }, ParamValue::Str(s)) => {
                    if s.len() < *min_len || s.len() > *max_len {
                        return Err(format!("PARAM_OUT_OF_RANGE:{name}"));
                    }
                }
                (ParamRule::Bool, ParamValue::Bool(_)) => {}
                (ParamRule::Enum(allowed), ParamValue::Str(s)) => {
                    if !allowed.iter().any(|x| x == s) {
                        return Err(format!("PARAM_OUT_OF_RANGE:{name}"));
                    }
                }
                _ => return Err(format!("BAD_PARAM_TYPE:{name}")),
            }
        }
        Ok(act)
    }
}

/* ---- FIPS 180-4 SHA-256 (SHA-NI + streaming), HMAC-SHA256, HKDF-SHA256 ---- */
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_compress_scalar(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
    );
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
    secure_zero_u32(&mut w);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sha,sse4.1,ssse3")]
unsafe fn sha256_blocks_shani(state: &mut [u32; 8], blocks: &[u8]) {
    use core::arch::x86_64::*;

    let mut abef = _mm_set_epi32(
        state[0] as i32,
        state[1] as i32,
        state[4] as i32,
        state[5] as i32,
    );
    let mut cdgh = _mm_set_epi32(
        state[2] as i32,
        state[3] as i32,
        state[6] as i32,
        state[7] as i32,
    );
    let bswap_mask = _mm_set_epi32(
        0x0c0d0e0fu32 as i32,
        0x08090a0bu32 as i32,
        0x04050607u32 as i32,
        0x00010203u32 as i32,
    );

    macro_rules! shani_mid_step {
        ($m_cur:expr, $m_next:expr, $m_prev2:expr, $m_prev:expr, $k_off:expr) => {{
            let mut msg = _mm_add_epi32(
                $m_cur,
                _mm_loadu_si128(SHA256_K.as_ptr().add($k_off) as *const __m128i),
            );
            cdgh = _mm_sha256rnds2_epu32(cdgh, abef, msg);
            let tmp = _mm_alignr_epi8::<4>($m_cur, $m_prev);
            $m_next = _mm_add_epi32($m_next, tmp);
            $m_next = _mm_sha256msg2_epu32($m_next, $m_cur);
            msg = _mm_shuffle_epi32::<0x0E>(msg);
            abef = _mm_sha256rnds2_epu32(abef, cdgh, msg);
            $m_prev = _mm_sha256msg1_epu32($m_prev, $m_cur);
            let _ = &$m_prev2;
        }};
    }

    let kptr = SHA256_K.as_ptr();
    let mut ptr = blocks.as_ptr();
    let end = ptr.add(blocks.len() & !63);
    while ptr < end {
        let abef_save = abef;
        let cdgh_save = cdgh;

        let mut msg0 = _mm_shuffle_epi8(_mm_loadu_si128(ptr as *const __m128i), bswap_mask);
        let mut msg = _mm_add_epi32(msg0, _mm_loadu_si128(kptr as *const __m128i));
        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, msg);
        msg = _mm_shuffle_epi32::<0x0E>(msg);
        abef = _mm_sha256rnds2_epu32(abef, cdgh, msg);

        let mut msg1 =
            _mm_shuffle_epi8(_mm_loadu_si128(ptr.add(16) as *const __m128i), bswap_mask);
        msg = _mm_add_epi32(msg1, _mm_loadu_si128(kptr.add(4) as *const __m128i));
        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, msg);
        msg = _mm_shuffle_epi32::<0x0E>(msg);
        abef = _mm_sha256rnds2_epu32(abef, cdgh, msg);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        let mut msg2 =
            _mm_shuffle_epi8(_mm_loadu_si128(ptr.add(32) as *const __m128i), bswap_mask);
        msg = _mm_add_epi32(msg2, _mm_loadu_si128(kptr.add(8) as *const __m128i));
        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, msg);
        msg = _mm_shuffle_epi32::<0x0E>(msg);
        abef = _mm_sha256rnds2_epu32(abef, cdgh, msg);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        let mut msg3 =
            _mm_shuffle_epi8(_mm_loadu_si128(ptr.add(48) as *const __m128i), bswap_mask);
        msg = _mm_add_epi32(msg3, _mm_loadu_si128(kptr.add(12) as *const __m128i));
        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, msg);
        let tmp = _mm_alignr_epi8::<4>(msg3, msg2);
        msg0 = _mm_add_epi32(msg0, tmp);
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg = _mm_shuffle_epi32::<0x0E>(msg);
        abef = _mm_sha256rnds2_epu32(abef, cdgh, msg);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        shani_mid_step!(msg0, msg1, msg2, msg3, 16);
        shani_mid_step!(msg1, msg2, msg3, msg0, 20);
        shani_mid_step!(msg2, msg3, msg0, msg1, 24);
        shani_mid_step!(msg3, msg0, msg1, msg2, 28);
        shani_mid_step!(msg0, msg1, msg2, msg3, 32);
        shani_mid_step!(msg1, msg2, msg3, msg0, 36);
        shani_mid_step!(msg2, msg3, msg0, msg1, 40);
        shani_mid_step!(msg3, msg0, msg1, msg2, 44);
        shani_mid_step!(msg0, msg1, msg2, msg3, 48);
        shani_mid_step!(msg1, msg2, msg3, msg0, 52);

        // Rounds 56..59
        msg = _mm_add_epi32(msg2, _mm_loadu_si128(kptr.add(56) as *const __m128i));
        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, msg);
        let tmp56 = _mm_alignr_epi8::<4>(msg2, msg1);
        msg3 = _mm_add_epi32(msg3, tmp56);
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg = _mm_shuffle_epi32::<0x0E>(msg);
        abef = _mm_sha256rnds2_epu32(abef, cdgh, msg);

        // Rounds 60..63
        msg = _mm_add_epi32(msg3, _mm_loadu_si128(kptr.add(60) as *const __m128i));
        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, msg);
        msg = _mm_shuffle_epi32::<0x0E>(msg);
        abef = _mm_sha256rnds2_epu32(abef, cdgh, msg);

        abef = _mm_add_epi32(abef, abef_save);
        cdgh = _mm_add_epi32(cdgh, cdgh_save);
        ptr = ptr.add(64);
    }

    let mut out_abef = [0i32; 4];
    let mut out_cdgh = [0i32; 4];
    _mm_storeu_si128(out_abef.as_mut_ptr() as *mut __m128i, abef);
    _mm_storeu_si128(out_cdgh.as_mut_ptr() as *mut __m128i, cdgh);
    state[0] = out_abef[3] as u32;
    state[1] = out_abef[2] as u32;
    state[2] = out_cdgh[3] as u32;
    state[3] = out_cdgh[2] as u32;
    state[4] = out_abef[1] as u32;
    state[5] = out_abef[0] as u32;
    state[6] = out_cdgh[1] as u32;
    state[7] = out_cdgh[0] as u32;
}

#[inline]
fn sha256_compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("sha")
            && std::arch::is_x86_feature_detected!("sse4.1")
            && std::arch::is_x86_feature_detected!("ssse3")
        {
            unsafe {
                sha256_blocks_shani(state, blocks);
            }
            return;
        }
    }
    for chunk in blocks.chunks_exact(64) {
        let blk: &[u8; 64] = chunk.try_into().unwrap();
        sha256_compress_scalar(state, blk);
    }
}

pub struct Sha256Hasher {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256Hasher {
    #[inline]
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let mut tmp = self.buf;
                sha256_compress_blocks(&mut self.state, &tmp);
                secure_zero(&mut tmp);
                self.buf_len = 0;
            }
        }
        let full_len = data.len() & !63;
        if full_len > 0 {
            sha256_compress_blocks(&mut self.state, &data[..full_len]);
            data = &data[full_len..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        let mut pad = [0u8; 128];
        pad[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
        pad[self.buf_len] = 0x80;
        let total_pad = if self.buf_len < 56 { 64 } else { 128 };
        pad[total_pad - 8..total_pad].copy_from_slice(&bit_len.to_be_bytes());
        sha256_compress_blocks(&mut self.state, &pad[..total_pad]);
        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        secure_zero(&mut pad);
        secure_zero(&mut self.buf);
        secure_zero_u32(&mut self.state);
        out
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256Hasher::new();
    h.update(data);
    h.finalize()
}

pub fn hmac_sha256_parts(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut kpad = [0u8; 64];
    if key.len() > 64 {
        let h = sha256(key);
        kpad[..32].copy_from_slice(&h);
    } else {
        kpad[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = kpad[i] ^ 0x36;
        opad[i] = kpad[i] ^ 0x5c;
    }
    let mut inner_h = Sha256Hasher::new();
    inner_h.update(&ipad);
    for p in parts {
        inner_h.update(p);
    }
    let mut inner = inner_h.finalize();

    let mut outer_in = [0u8; 96];
    outer_in[..64].copy_from_slice(&opad);
    outer_in[64..].copy_from_slice(&inner);
    let out = sha256(&outer_in);
    secure_zero(&mut kpad);
    secure_zero(&mut ipad);
    secure_zero(&mut opad);
    secure_zero(&mut inner);
    secure_zero(&mut outer_in);
    out
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    hmac_sha256_parts(key, &[msg])
}

pub fn hkdf_sha256_32_parts(ikm: &[u8], salt: &[u8], info_parts: &[&[u8]]) -> [u8; 32] {
    let mut prk = hmac_sha256(salt, ikm);
    let mut parts_buf = [&[][..]; 8];
    debug_assert!(info_parts.len() < parts_buf.len());
    let n = info_parts.len();
    parts_buf[..n].copy_from_slice(info_parts);
    let one = [1u8];
    parts_buf[n] = &one;
    let okm = hmac_sha256_parts(&prk, &parts_buf[..=n]);
    secure_zero(&mut prk);
    okm
}

pub fn hkdf_sha256_32(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    hkdf_sha256_32_parts(ikm, salt, &[info])
}

/* ---- RFC 8439 ChaCha20-Poly1305 AEAD (AVX2 8-block + 64-bit Poly1305) ---- */
#[inline]
fn qr(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

#[inline]
fn load_u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[inline]
fn load_u64_le(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

pub(crate) fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut s = [0u32; 16];
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;
    for i in 0..8 {
        s[4 + i] = load_u32_le(&key[i * 4..i * 4 + 4]);
    }
    s[12] = counter;
    for i in 0..3 {
        s[13 + i] = load_u32_le(&nonce[i * 4..i * 4 + 4]);
    }
    let mut x = s;
    for _ in 0..10 {
        qr(&mut x, 0, 4, 8, 12);
        qr(&mut x, 1, 5, 9, 13);
        qr(&mut x, 2, 6, 10, 14);
        qr(&mut x, 3, 7, 11, 15);
        qr(&mut x, 0, 5, 10, 15);
        qr(&mut x, 1, 6, 11, 12);
        qr(&mut x, 2, 7, 8, 13);
        qr(&mut x, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&x[i].wrapping_add(s[i]).to_le_bytes());
    }
    secure_zero_u32(&mut x);
    secure_zero_u32(&mut s);
    out
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn chacha20_xor_avx2(
    key: &[u8; 32],
    start_ctr: u32,
    nonce: &[u8; 12],
    mut src: *const u8,
    mut dst: *mut u8,
    len: usize,
) -> (usize, u32) {
    use core::arch::x86_64::*;

    let c0 = _mm256_set1_epi32(0x61707865i32);
    let c1 = _mm256_set1_epi32(0x3320646ei32);
    let c2 = _mm256_set1_epi32(0x79622d32i32);
    let c3 = _mm256_set1_epi32(0x6b206574i32);
    let k0 = _mm256_set1_epi32(load_u32_le(&key[0..4]) as i32);
    let k1 = _mm256_set1_epi32(load_u32_le(&key[4..8]) as i32);
    let k2 = _mm256_set1_epi32(load_u32_le(&key[8..12]) as i32);
    let k3 = _mm256_set1_epi32(load_u32_le(&key[12..16]) as i32);
    let k4 = _mm256_set1_epi32(load_u32_le(&key[16..20]) as i32);
    let k5 = _mm256_set1_epi32(load_u32_le(&key[20..24]) as i32);
    let k6 = _mm256_set1_epi32(load_u32_le(&key[24..28]) as i32);
    let k7 = _mm256_set1_epi32(load_u32_le(&key[28..32]) as i32);
    let n0 = _mm256_set1_epi32(load_u32_le(&nonce[0..4]) as i32);
    let n1 = _mm256_set1_epi32(load_u32_le(&nonce[4..8]) as i32);
    let n2 = _mm256_set1_epi32(load_u32_le(&nonce[8..12]) as i32);

    let rot16 = _mm256_set_epi8(
        13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2,
        13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2,
    );
    let rot8 = _mm256_set_epi8(
        14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3,
        14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3,
    );
    let ctr_step = _mm256_set_epi32(7, 6, 5, 4, 3, 2, 1, 0);

    macro_rules! qr_avx2 {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            $a = _mm256_add_epi32($a, $b);
            $d = _mm256_shuffle_epi8(_mm256_xor_si256($d, $a), rot16);
            $c = _mm256_add_epi32($c, $d);
            let t12 = _mm256_xor_si256($b, $c);
            $b = _mm256_or_si256(_mm256_slli_epi32::<12>(t12), _mm256_srli_epi32::<20>(t12));
            $a = _mm256_add_epi32($a, $b);
            $d = _mm256_shuffle_epi8(_mm256_xor_si256($d, $a), rot8);
            $c = _mm256_add_epi32($c, $d);
            let t7 = _mm256_xor_si256($b, $c);
            $b = _mm256_or_si256(_mm256_slli_epi32::<7>(t7), _mm256_srli_epi32::<25>(t7));
        };
    }

    macro_rules! xor_store_row_group {
        ($r0:expr, $r1:expr, $r2:expr, $r3:expr, $s0:expr, $s1:expr, $s2:expr, $s3:expr, $off:expr) => {{
            let x0 = _mm256_add_epi32($r0, $s0);
            let x1 = _mm256_add_epi32($r1, $s1);
            let x2 = _mm256_add_epi32($r2, $s2);
            let x3 = _mm256_add_epi32($r3, $s3);
            let t0 = _mm256_unpacklo_epi32(x0, x1);
            let t1 = _mm256_unpackhi_epi32(x0, x1);
            let t2 = _mm256_unpacklo_epi32(x2, x3);
            let t3 = _mm256_unpackhi_epi32(x2, x3);
            let q0 = _mm256_unpacklo_epi64(t0, t2);
            let q1 = _mm256_unpackhi_epi64(t0, t2);
            let q2 = _mm256_unpacklo_epi64(t1, t3);
            let q3 = _mm256_unpackhi_epi64(t1, t3);
            let b0 = _mm256_castsi256_si128(q0);
            let b1 = _mm256_castsi256_si128(q1);
            let b2 = _mm256_castsi256_si128(q2);
            let b3 = _mm256_castsi256_si128(q3);
            let b4 = _mm256_extracti128_si256::<1>(q0);
            let b5 = _mm256_extracti128_si256::<1>(q1);
            let b6 = _mm256_extracti128_si256::<1>(q2);
            let b7 = _mm256_extracti128_si256::<1>(q3);
            _mm_storeu_si128(dst.add(0 * 64 + $off) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(src.add(0 * 64 + $off) as *const __m128i), b0));
            _mm_storeu_si128(dst.add(1 * 64 + $off) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(src.add(1 * 64 + $off) as *const __m128i), b1));
            _mm_storeu_si128(dst.add(2 * 64 + $off) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(src.add(2 * 64 + $off) as *const __m128i), b2));
            _mm_storeu_si128(dst.add(3 * 64 + $off) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(src.add(3 * 64 + $off) as *const __m128i), b3));
            _mm_storeu_si128(dst.add(4 * 64 + $off) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(src.add(4 * 64 + $off) as *const __m128i), b4));
            _mm_storeu_si128(dst.add(5 * 64 + $off) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(src.add(5 * 64 + $off) as *const __m128i), b5));
            _mm_storeu_si128(dst.add(6 * 64 + $off) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(src.add(6 * 64 + $off) as *const __m128i), b6));
            _mm_storeu_si128(dst.add(7 * 64 + $off) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(src.add(7 * 64 + $off) as *const __m128i), b7));
        }};
    }

    let mut ctr = start_ctr;
    let mut done = 0usize;
    while len - done >= 512 {
        let s12 = _mm256_add_epi32(_mm256_set1_epi32(ctr as i32), ctr_step);
        let (mut x0, mut x1, mut x2, mut x3) = (c0, c1, c2, c3);
        let (mut x4, mut x5, mut x6, mut x7) = (k0, k1, k2, k3);
        let (mut x8, mut x9, mut x10, mut x11) = (k4, k5, k6, k7);
        let (mut x12, mut x13, mut x14, mut x15) = (s12, n0, n1, n2);

        for _ in 0..10 {
            qr_avx2!(x0, x4, x8, x12);
            qr_avx2!(x1, x5, x9, x13);
            qr_avx2!(x2, x6, x10, x14);
            qr_avx2!(x3, x7, x11, x15);
            qr_avx2!(x0, x5, x10, x15);
            qr_avx2!(x1, x6, x11, x12);
            qr_avx2!(x2, x7, x8, x13);
            qr_avx2!(x3, x4, x9, x14);
        }

        xor_store_row_group!(x0, x1, x2, x3, c0, c1, c2, c3, 0);
        xor_store_row_group!(x4, x5, x6, x7, k0, k1, k2, k3, 16);
        xor_store_row_group!(x8, x9, x10, x11, k4, k5, k6, k7, 32);
        xor_store_row_group!(x12, x13, x14, x15, s12, n0, n1, n2, 48);

        src = src.add(512);
        dst = dst.add(512);
        done += 512;
        ctr = ctr.wrapping_add(8);
    }
    _mm256_zeroupper();
    (done, ctr)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn chacha20_xor_avx512(
    key: &[u8; 32],
    start_ctr: u32,
    nonce: &[u8; 12],
    mut src: *const u8,
    mut dst: *mut u8,
    len: usize,
) -> (usize, u32) {
    use core::arch::x86_64::*;

    let c0 = _mm512_set1_epi32(0x61707865i32);
    let c1 = _mm512_set1_epi32(0x3320646ei32);
    let c2 = _mm512_set1_epi32(0x79622d32i32);
    let c3 = _mm512_set1_epi32(0x6b206574i32);
    let k0 = _mm512_set1_epi32(load_u32_le(&key[0..4]) as i32);
    let k1 = _mm512_set1_epi32(load_u32_le(&key[4..8]) as i32);
    let k2 = _mm512_set1_epi32(load_u32_le(&key[8..12]) as i32);
    let k3 = _mm512_set1_epi32(load_u32_le(&key[12..16]) as i32);
    let k4 = _mm512_set1_epi32(load_u32_le(&key[16..20]) as i32);
    let k5 = _mm512_set1_epi32(load_u32_le(&key[20..24]) as i32);
    let k6 = _mm512_set1_epi32(load_u32_le(&key[24..28]) as i32);
    let k7 = _mm512_set1_epi32(load_u32_le(&key[28..32]) as i32);
    let n0 = _mm512_set1_epi32(load_u32_le(&nonce[0..4]) as i32);
    let n1 = _mm512_set1_epi32(load_u32_le(&nonce[4..8]) as i32);
    let n2 = _mm512_set1_epi32(load_u32_le(&nonce[8..12]) as i32);
    let step_arr: [i32; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let ctr_step = _mm512_loadu_si512(step_arr.as_ptr() as *const __m512i);

    macro_rules! qr_avx512 {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            $a = _mm512_add_epi32($a, $b);
            $d = _mm512_rol_epi32::<16>(_mm512_xor_si512($d, $a));
            $c = _mm512_add_epi32($c, $d);
            $b = _mm512_rol_epi32::<12>(_mm512_xor_si512($b, $c));
            $a = _mm512_add_epi32($a, $b);
            $d = _mm512_rol_epi32::<8>(_mm512_xor_si512($d, $a));
            $c = _mm512_add_epi32($c, $d);
            $b = _mm512_rol_epi32::<7>(_mm512_xor_si512($b, $c));
        };
    }

    macro_rules! transpose_group_avx512 {
        ($r0:expr, $r1:expr, $r2:expr, $r3:expr, $s0:expr, $s1:expr, $s2:expr, $s3:expr) => {{
            let x0 = _mm512_add_epi32($r0, $s0);
            let x1 = _mm512_add_epi32($r1, $s1);
            let x2 = _mm512_add_epi32($r2, $s2);
            let x3 = _mm512_add_epi32($r3, $s3);
            let t0 = _mm512_unpacklo_epi32(x0, x1);
            let t1 = _mm512_unpackhi_epi32(x0, x1);
            let t2 = _mm512_unpacklo_epi32(x2, x3);
            let t3 = _mm512_unpackhi_epi32(x2, x3);
            (
                _mm512_unpacklo_epi64(t0, t2),
                _mm512_unpackhi_epi64(t0, t2),
                _mm512_unpacklo_epi64(t1, t3),
                _mm512_unpackhi_epi64(t1, t3),
            )
        }};
    }

    macro_rules! xor_store_col_avx512 {
        ($g0:expr, $g1:expr, $g2:expr, $g3:expr, $col:expr) => {{
            let u0 = _mm512_shuffle_i32x4::<0x44>($g0, $g1);
            let u1 = _mm512_shuffle_i32x4::<0xEE>($g0, $g1);
            let u2 = _mm512_shuffle_i32x4::<0x44>($g2, $g3);
            let u3 = _mm512_shuffle_i32x4::<0xEE>($g2, $g3);
            let b0 = _mm512_shuffle_i32x4::<0x88>(u0, u2);
            let b4 = _mm512_shuffle_i32x4::<0xDD>(u0, u2);
            let b8 = _mm512_shuffle_i32x4::<0x88>(u1, u3);
            let b12 = _mm512_shuffle_i32x4::<0xDD>(u1, u3);
            _mm512_storeu_si512(
                dst.add(($col + 0) * 64) as *mut __m512i,
                _mm512_xor_si512(_mm512_loadu_si512(src.add(($col + 0) * 64) as *const __m512i), b0),
            );
            _mm512_storeu_si512(
                dst.add(($col + 4) * 64) as *mut __m512i,
                _mm512_xor_si512(_mm512_loadu_si512(src.add(($col + 4) * 64) as *const __m512i), b4),
            );
            _mm512_storeu_si512(
                dst.add(($col + 8) * 64) as *mut __m512i,
                _mm512_xor_si512(_mm512_loadu_si512(src.add(($col + 8) * 64) as *const __m512i), b8),
            );
            _mm512_storeu_si512(
                dst.add(($col + 12) * 64) as *mut __m512i,
                _mm512_xor_si512(_mm512_loadu_si512(src.add(($col + 12) * 64) as *const __m512i), b12),
            );
        }};
    }

    let mut ctr = start_ctr;
    let mut done = 0usize;
    while len - done >= 1024 {
        let s12 = _mm512_add_epi32(_mm512_set1_epi32(ctr as i32), ctr_step);
        let (mut x0, mut x1, mut x2, mut x3) = (c0, c1, c2, c3);
        let (mut x4, mut x5, mut x6, mut x7) = (k0, k1, k2, k3);
        let (mut x8, mut x9, mut x10, mut x11) = (k4, k5, k6, k7);
        let (mut x12, mut x13, mut x14, mut x15) = (s12, n0, n1, n2);

        for _ in 0..10 {
            qr_avx512!(x0, x4, x8, x12);
            qr_avx512!(x1, x5, x9, x13);
            qr_avx512!(x2, x6, x10, x14);
            qr_avx512!(x3, x7, x11, x15);
            qr_avx512!(x0, x5, x10, x15);
            qr_avx512!(x1, x6, x11, x12);
            qr_avx512!(x2, x7, x8, x13);
            qr_avx512!(x3, x4, x9, x14);
        }

        let (g0q0, g0q1, g0q2, g0q3) = transpose_group_avx512!(x0, x1, x2, x3, c0, c1, c2, c3);
        let (g1q0, g1q1, g1q2, g1q3) = transpose_group_avx512!(x4, x5, x6, x7, k0, k1, k2, k3);
        let (g2q0, g2q1, g2q2, g2q3) = transpose_group_avx512!(x8, x9, x10, x11, k4, k5, k6, k7);
        let (g3q0, g3q1, g3q2, g3q3) = transpose_group_avx512!(x12, x13, x14, x15, s12, n0, n1, n2);

        xor_store_col_avx512!(g0q0, g1q0, g2q0, g3q0, 0);
        xor_store_col_avx512!(g0q1, g1q1, g2q1, g3q1, 1);
        xor_store_col_avx512!(g0q2, g1q2, g2q2, g3q2, 2);
        xor_store_col_avx512!(g0q3, g1q3, g2q3, g3q3, 3);

        src = src.add(1024);
        dst = dst.add(1024);
        done += 1024;
        ctr = ctr.wrapping_add(16);
    }
    _mm256_zeroupper();
    (done, ctr)
}

fn chacha20_xor_into_impl(
    key: &[u8; 32],
    start_ctr: u32,
    nonce: &[u8; 12],
    src: &[u8],
    dst: &mut [u8],
) {
    assert_eq!(src.len(), dst.len(), "CHACHA20_LEN_MISMATCH");
    assert!(
        (src.len() / 64) <= (u32::MAX as usize) - (start_ctr as usize),
        "CHACHA20_COUNTER_OVERFLOW"
    );
    let mut offset = 0usize;
    let mut ctr = start_ctr;

    #[cfg(target_arch = "x86_64")]
    {
        if src.len() >= 1024 && std::arch::is_x86_feature_detected!("avx512f") {
            let (done, next_ctr) = unsafe {
                chacha20_xor_avx512(
                    key,
                    ctr,
                    nonce,
                    src.as_ptr(),
                    dst.as_mut_ptr(),
                    src.len(),
                )
            };
            offset = done;
            ctr = next_ctr;
        }
        if src.len() - offset >= 512 && std::arch::is_x86_feature_detected!("avx2") {
            let (done, next_ctr) = unsafe {
                chacha20_xor_avx2(
                    key,
                    ctr,
                    nonce,
                    src.as_ptr().add(offset),
                    dst.as_mut_ptr().add(offset),
                    src.len() - offset,
                )
            };
            offset += done;
            ctr = next_ctr;
        }
    }

    for (chunk_in, chunk_out) in src[offset..].chunks(64).zip(dst[offset..].chunks_mut(64)) {
        let mut blk = chacha20_block(key, ctr, nonce);
        if chunk_in.len() == 64 {
            ctr = ctr.checked_add(1).expect("CHACHA20_COUNTER_WRAP");
            for i in 0..8 {
                let w_in = load_u64_le(&chunk_in[i * 8..i * 8 + 8]);
                let w_k = load_u64_le(&blk[i * 8..i * 8 + 8]);
                chunk_out[i * 8..i * 8 + 8].copy_from_slice(&(w_in ^ w_k).to_le_bytes());
            }
        } else {
            for i in 0..chunk_in.len() {
                chunk_out[i] = chunk_in[i] ^ blk[i];
            }
        }
        secure_zero(&mut blk);
    }
}

pub(crate) fn chacha20_xor_in_place(
    key: &[u8; 32],
    start_ctr: u32,
    nonce: &[u8; 12],
    buf: &mut [u8],
) {
    assert!(
        (buf.len() / 64) <= (u32::MAX as usize) - (start_ctr as usize),
        "CHACHA20_COUNTER_OVERFLOW"
    );
    let mut offset = 0usize;
    let mut ctr = start_ctr;

    #[cfg(target_arch = "x86_64")]
    {
        if buf.len() >= 1024 && std::arch::is_x86_feature_detected!("avx512f") {
            let (done, next_ctr) = unsafe {
                chacha20_xor_avx512(
                    key,
                    ctr,
                    nonce,
                    buf.as_ptr(),
                    buf.as_mut_ptr(),
                    buf.len(),
                )
            };
            offset = done;
            ctr = next_ctr;
        }
        if buf.len() - offset >= 512 && std::arch::is_x86_feature_detected!("avx2") {
            let (done, next_ctr) = unsafe {
                chacha20_xor_avx2(
                    key,
                    ctr,
                    nonce,
                    buf.as_ptr().add(offset),
                    buf.as_mut_ptr().add(offset),
                    buf.len() - offset,
                )
            };
            offset += done;
            ctr = next_ctr;
        }
    }

    for chunk in buf[offset..].chunks_mut(64) {
        let mut blk = chacha20_block(key, ctr, nonce);
        if chunk.len() == 64 {
            ctr = ctr.checked_add(1).expect("CHACHA20_COUNTER_WRAP");
            for i in 0..8 {
                let w_in = load_u64_le(&chunk[i * 8..i * 8 + 8]);
                let w_k = load_u64_le(&blk[i * 8..i * 8 + 8]);
                chunk[i * 8..i * 8 + 8].copy_from_slice(&(w_in ^ w_k).to_le_bytes());
            }
        } else {
            for i in 0..chunk.len() {
                chunk[i] ^= blk[i];
            }
        }
        secure_zero(&mut blk);
    }
}

pub(crate) fn chacha20_xor_into(
    key: &[u8; 32],
    start_ctr: u32,
    nonce: &[u8; 12],
    src: &[u8],
    dst: &mut [u8],
) {
    chacha20_xor_into_impl(key, start_ctr, nonce, src, dst);
}

#[allow(dead_code)]
fn chacha20_xor(key: &[u8; 32], start_ctr: u32, nonce: &[u8; 12], input: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; input.len()];
    chacha20_xor_into_impl(key, start_ctr, nonce, input, &mut out);
    out
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn poly1305_limbs44_to_26(mut v0: u128, mut v1: u128, mut v2: u128) -> [u64; 5] {
    const M44: u128 = 0x0fff_ffff_ffffu128;
    const M42: u128 = 0x03ff_ffff_ffffu128;
    let mut cy = v0 >> 44;
    v0 &= M44;
    v1 += cy;
    cy = v1 >> 44;
    v1 &= M44;
    v2 += cy;
    cy = v2 >> 42;
    v2 &= M42;
    v0 += cy * 5;
    cy = v0 >> 44;
    v0 &= M44;
    v1 += cy;
    let a0 = v0 as u64;
    let a1 = v1 as u64;
    let a2 = v2 as u64;
    [
        a0 & 0x3ff_ffff,
        (a0 >> 26) | ((a1 & 0xff) << 18),
        (a1 >> 8) & 0x3ff_ffff,
        (a1 >> 34) | ((a2 & 0xffff) << 10),
        a2 >> 16,
    ]
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn poly1305_blocks_avx2(
    h0: &mut u128,
    h1: &mut u128,
    h2: &mut u128,
    r1k: (u128, u128, u128),
    r2k: (u128, u128, u128),
    r3k: (u128, u128, u128),
    r4k: (u128, u128, u128),
    aligned64: &[u8],
) {
    use core::arch::x86_64::*;

    let h26 = poly1305_limbs44_to_26(*h0, *h1, *h2);
    let r1_26 = poly1305_limbs44_to_26(r1k.0, r1k.1, r1k.2);
    let r2_26 = poly1305_limbs44_to_26(r2k.0, r2k.1, r2k.2);
    let r3_26 = poly1305_limbs44_to_26(r3k.0, r3k.1, r3k.2);
    let r4_26 = poly1305_limbs44_to_26(r4k.0, r4k.1, r4k.2);

    let mask26 = _mm256_set1_epi64x(0x3ff_ffff);
    let hibit24 = _mm256_set1_epi64x((1u64 << 24) as i64);

    let r4_0 = _mm256_set1_epi64x(r4_26[0] as i64);
    let r4_1 = _mm256_set1_epi64x(r4_26[1] as i64);
    let r4_2 = _mm256_set1_epi64x(r4_26[2] as i64);
    let r4_3 = _mm256_set1_epi64x(r4_26[3] as i64);
    let r4_4 = _mm256_set1_epi64x(r4_26[4] as i64);
    let s4_1 = _mm256_set1_epi64x((r4_26[1] * 5) as i64);
    let s4_2 = _mm256_set1_epi64x((r4_26[2] * 5) as i64);
    let s4_3 = _mm256_set1_epi64x((r4_26[3] * 5) as i64);
    let s4_4 = _mm256_set1_epi64x((r4_26[4] * 5) as i64);

    macro_rules! poly_load4 {
        ($ptr:expr) => {{
            let v0 = _mm256_loadu_si256($ptr as *const __m256i);
            let v1 = _mm256_loadu_si256(($ptr).add(32) as *const __m256i);
            let lo = _mm256_permute4x64_epi64::<0xD8>(_mm256_unpacklo_epi64(v0, v1));
            let hi = _mm256_permute4x64_epi64::<0xD8>(_mm256_unpackhi_epi64(v0, v1));
            let m0 = _mm256_and_si256(lo, mask26);
            let m1 = _mm256_and_si256(_mm256_srli_epi64::<26>(lo), mask26);
            let m2 = _mm256_and_si256(
                _mm256_or_si256(_mm256_srli_epi64::<52>(lo), _mm256_slli_epi64::<12>(hi)),
                mask26,
            );
            let m3 = _mm256_and_si256(_mm256_srli_epi64::<14>(hi), mask26);
            let m4 = _mm256_or_si256(_mm256_srli_epi64::<40>(hi), hibit24);
            (m0, m1, m2, m3, m4)
        }};
    }

    macro_rules! poly_mul5 {
        ($a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr,
         $r0:expr, $r1:expr, $r2:expr, $r3:expr, $r4:expr,
         $s1:expr, $s2:expr, $s3:expr, $s4:expr) => {{
            let d0 = _mm256_add_epi64(
                _mm256_add_epi64(_mm256_mul_epu32($a0, $r0), _mm256_mul_epu32($a1, $s4)),
                _mm256_add_epi64(
                    _mm256_mul_epu32($a2, $s3),
                    _mm256_add_epi64(_mm256_mul_epu32($a3, $s2), _mm256_mul_epu32($a4, $s1)),
                ),
            );
            let d1 = _mm256_add_epi64(
                _mm256_add_epi64(_mm256_mul_epu32($a0, $r1), _mm256_mul_epu32($a1, $r0)),
                _mm256_add_epi64(
                    _mm256_mul_epu32($a2, $s4),
                    _mm256_add_epi64(_mm256_mul_epu32($a3, $s3), _mm256_mul_epu32($a4, $s2)),
                ),
            );
            let d2 = _mm256_add_epi64(
                _mm256_add_epi64(_mm256_mul_epu32($a0, $r2), _mm256_mul_epu32($a1, $r1)),
                _mm256_add_epi64(
                    _mm256_mul_epu32($a2, $r0),
                    _mm256_add_epi64(_mm256_mul_epu32($a3, $s4), _mm256_mul_epu32($a4, $s3)),
                ),
            );
            let d3 = _mm256_add_epi64(
                _mm256_add_epi64(_mm256_mul_epu32($a0, $r3), _mm256_mul_epu32($a1, $r2)),
                _mm256_add_epi64(
                    _mm256_mul_epu32($a2, $r1),
                    _mm256_add_epi64(_mm256_mul_epu32($a3, $r0), _mm256_mul_epu32($a4, $s4)),
                ),
            );
            let d4 = _mm256_add_epi64(
                _mm256_add_epi64(_mm256_mul_epu32($a0, $r4), _mm256_mul_epu32($a1, $r3)),
                _mm256_add_epi64(
                    _mm256_mul_epu32($a2, $r2),
                    _mm256_add_epi64(_mm256_mul_epu32($a3, $r1), _mm256_mul_epu32($a4, $r0)),
                ),
            );
            (d0, d1, d2, d3, d4)
        }};
    }

    let base = aligned64.as_ptr();
    let total = aligned64.len();
    let (mut a0, mut a1, mut a2, mut a3, mut a4) = poly_load4!(base);
    a0 = _mm256_add_epi64(a0, _mm256_set_epi64x(0, 0, 0, h26[0] as i64));
    a1 = _mm256_add_epi64(a1, _mm256_set_epi64x(0, 0, 0, h26[1] as i64));
    a2 = _mm256_add_epi64(a2, _mm256_set_epi64x(0, 0, 0, h26[2] as i64));
    a3 = _mm256_add_epi64(a3, _mm256_set_epi64x(0, 0, 0, h26[3] as i64));
    a4 = _mm256_add_epi64(a4, _mm256_set_epi64x(0, 0, 0, h26[4] as i64));

    let mut off = 64usize;
    while off < total {
        let (d0, mut d1, mut d2, mut d3, mut d4) = poly_mul5!(
            a0, a1, a2, a3, a4, r4_0, r4_1, r4_2, r4_3, r4_4, s4_1, s4_2, s4_3, s4_4
        );
        let (m0, m1, m2, m3, m4) = poly_load4!(base.add(off));

        let mut cy = _mm256_srli_epi64::<26>(d0);
        a0 = _mm256_and_si256(d0, mask26);
        d1 = _mm256_add_epi64(d1, cy);
        cy = _mm256_srli_epi64::<26>(d1);
        a1 = _mm256_and_si256(d1, mask26);
        d2 = _mm256_add_epi64(d2, cy);
        cy = _mm256_srli_epi64::<26>(d2);
        a2 = _mm256_and_si256(d2, mask26);
        d3 = _mm256_add_epi64(d3, cy);
        cy = _mm256_srli_epi64::<26>(d3);
        a3 = _mm256_and_si256(d3, mask26);
        d4 = _mm256_add_epi64(d4, cy);
        cy = _mm256_srli_epi64::<26>(d4);
        a4 = _mm256_and_si256(d4, mask26);
        a0 = _mm256_add_epi64(a0, _mm256_add_epi64(cy, _mm256_slli_epi64::<2>(cy)));
        cy = _mm256_srli_epi64::<26>(a0);
        a0 = _mm256_and_si256(a0, mask26);
        a1 = _mm256_add_epi64(a1, cy);

        a0 = _mm256_add_epi64(a0, m0);
        a1 = _mm256_add_epi64(a1, m1);
        a2 = _mm256_add_epi64(a2, m2);
        a3 = _mm256_add_epi64(a3, m3);
        a4 = _mm256_add_epi64(a4, m4);
        off += 64;
    }

    let rf0 = _mm256_set_epi64x(
        r1_26[0] as i64, r2_26[0] as i64, r3_26[0] as i64, r4_26[0] as i64,
    );
    let rf1 = _mm256_set_epi64x(
        r1_26[1] as i64, r2_26[1] as i64, r3_26[1] as i64, r4_26[1] as i64,
    );
    let rf2 = _mm256_set_epi64x(
        r1_26[2] as i64, r2_26[2] as i64, r3_26[2] as i64, r4_26[2] as i64,
    );
    let rf3 = _mm256_set_epi64x(
        r1_26[3] as i64, r2_26[3] as i64, r3_26[3] as i64, r4_26[3] as i64,
    );
    let rf4 = _mm256_set_epi64x(
        r1_26[4] as i64, r2_26[4] as i64, r3_26[4] as i64, r4_26[4] as i64,
    );
    let sf1 = _mm256_add_epi64(rf1, _mm256_slli_epi64::<2>(rf1));
    let sf2 = _mm256_add_epi64(rf2, _mm256_slli_epi64::<2>(rf2));
    let sf3 = _mm256_add_epi64(rf3, _mm256_slli_epi64::<2>(rf3));
    let sf4 = _mm256_add_epi64(rf4, _mm256_slli_epi64::<2>(rf4));

    let (fd0, fd1, fd2, fd3, fd4) = poly_mul5!(
        a0, a1, a2, a3, a4, rf0, rf1, rf2, rf3, rf4, sf1, sf2, sf3, sf4
    );

    #[inline(always)]
    unsafe fn hsum64(v: __m256i) -> u64 {
        let p1 = _mm256_add_epi64(v, _mm256_permute4x64_epi64::<0x4E>(v));
        let p2 = _mm256_add_epi64(p1, _mm256_permute4x64_epi64::<0x01>(p1));
        _mm256_extract_epi64::<0>(p2) as u64
    }

    let mut u0 = hsum64(fd0);
    let mut u1 = hsum64(fd1);
    let mut u2 = hsum64(fd2);
    let mut u3 = hsum64(fd3);
    let mut u4 = hsum64(fd4);

    _mm256_zeroupper();

    let mut c = u0 >> 26; u0 &= 0x3ff_ffff; u1 += c;
    c = u1 >> 26; u1 &= 0x3ff_ffff; u2 += c;
    c = u2 >> 26; u2 &= 0x3ff_ffff; u3 += c;
    c = u3 >> 26; u3 &= 0x3ff_ffff; u4 += c;
    c = u4 >> 26; u4 &= 0x3ff_ffff; u0 += c * 5;
    c = u0 >> 26; u0 &= 0x3ff_ffff; u1 += c;

    c = u1 >> 26; u1 &= 0x3ff_ffff; u2 += c;
    c = u2 >> 26; u2 &= 0x3ff_ffff; u3 += c;
    c = u3 >> 26; u3 &= 0x3ff_ffff; u4 += c;
    c = u4 >> 26; u4 &= 0x3ff_ffff; u0 += c * 5;
    c = u0 >> 26; u0 &= 0x3ff_ffff; u1 += c;

    *h0 = (u0 | ((u1 & 0x3_ffff) << 26)) as u128;
    *h1 = ((u1 >> 18) | (u2 << 8) | ((u3 & 0x3ff) << 34)) as u128;
    *h2 = ((u3 >> 10) | (u4 << 16)) as u128;
}

pub(crate) fn poly1305_mac(otk: &[u8; 32], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let t0 = load_u64_le(&otk[0..8]) & 0x0fff_fffc_0fff_ffffu64;
    let t1 = load_u64_le(&otk[8..16]) & 0x0fff_fffc_0fff_fffcu64;

    const M44: u128 = 0x0fff_ffff_ffffu128;
    const M42: u128 = 0x03ff_ffff_ffffu128;
    const HIBIT: u128 = 1u128 << 40;

    let r0 = (t0 as u128) & M44;
    let r1 = (((t0 >> 44) | (t1 << 20)) as u128) & M44;
    let r2 = ((t1 >> 24) as u128) & M42;
    let s1 = r1 * 20;
    let s2 = r2 * 20;

    let (mut h0, mut h1, mut h2) = (0u128, 0u128, 0u128);

    #[inline(always)]
    fn step_block(
        h0: &mut u128,
        h1: &mut u128,
        h2: &mut u128,
        u0: u64,
        u1: u64,
        r0: u128,
        r1: u128,
        r2: u128,
        s1: u128,
        s2: u128,
    ) {
        let m0 = (u0 as u128) & M44;
        let m1 = (((u0 >> 44) | (u1 << 20)) as u128) & M44;
        let m2 = ((u1 >> 24) as u128) | HIBIT;

        let f0 = *h0 + m0;
        let f1 = *h1 + m1;
        let f2 = *h2 + m2;

        let d0 = f0 * r0 + f1 * s2 + f2 * s1;
        let mut d1 = f0 * r1 + f1 * r0 + f2 * s2;
        let mut d2 = f0 * r2 + f1 * r1 + f2 * r0;

        let mut c = d0 >> 44;
        let mut t0 = d0 & M44;
        d1 += c;
        c = d1 >> 44;
        *h1 = d1 & M44;
        d2 += c;
        c = d2 >> 42;
        *h2 = d2 & M42;
        t0 += c * 5;
        c = t0 >> 44;
        *h0 = t0 & M44;
        *h1 += c;
    }

    #[inline(always)]
    fn mul_limbs(a: (u128, u128, u128), b: (u128, u128, u128)) -> (u128, u128, u128) {
        let (r0, r1, r2) = b;
        let s1 = r1 * 20;
        let s2 = r2 * 20;
        let d0 = a.0 * r0 + a.1 * s2 + a.2 * s1;
        let mut d1 = a.0 * r1 + a.1 * r0 + a.2 * s2;
        let mut d2 = a.0 * r2 + a.1 * r1 + a.2 * r0;
        let mut c = d0 >> 44;
        let mut h0 = d0 & M44;
        d1 += c;
        c = d1 >> 44;
        let mut h1 = d1 & M44;
        d2 += c;
        c = d2 >> 42;
        let mut h2 = d2 & M42;
        h0 += c * 5;
        c = h0 >> 44; h0 &= M44; h1 += c;
        c = h1 >> 44; h1 &= M44; h2 += c;
        c = h2 >> 42; h2 &= M42; h0 += c * 5;
        c = h0 >> 44; h0 &= M44; h1 += c;
        (h0, h1, h2)
    }

    let powers = if aad.len() >= 64 || ct.len() >= 64 {
        let r1k = (r0, r1, r2);
        let r2k = mul_limbs(r1k, r1k);
        let r3k = mul_limbs(r2k, r1k);
        let r4k = mul_limbs(r2k, r2k);
        Some((r2k, r3k, r4k))
    } else {
        None
    };

    for mut slice in [aad, ct] {
        if let Some((r2k, r3k, r4k)) = powers {
            #[cfg(target_arch = "x86_64")]
            {
                if slice.len() >= 64 && std::arch::is_x86_feature_detected!("avx2") {
                    let aligned64 = slice.len() & !63usize;
                    unsafe {
                        poly1305_blocks_avx2(
                            &mut h0,
                            &mut h1,
                            &mut h2,
                            (r0, r1, r2),
                            r2k,
                            r3k,
                            r4k,
                            &slice[..aligned64],
                        );
                    }
                    slice = &slice[aligned64..];
                }
            }
            if slice.len() >= 64 {
                let (r20, r21, r22) = r2k;
                let (s21, s22) = (r21 * 20, r22 * 20);
                let (r30, r31, r32) = r3k;
                let (s31, s32) = (r31 * 20, r32 * 20);
                let (r40, r41, r42) = r4k;
                let (s41, s42) = (r41 * 20, r42 * 20);
                let mut chunks64 = slice.chunks_exact(64);
                for ch in &mut chunks64 {
                    let a0 = load_u64_le(&ch[0..8]);
                    let a1 = load_u64_le(&ch[8..16]);
                    let b0 = load_u64_le(&ch[16..24]);
                    let b1 = load_u64_le(&ch[24..32]);
                    let c0 = load_u64_le(&ch[32..40]);
                    let c1 = load_u64_le(&ch[40..48]);
                    let e0 = load_u64_le(&ch[48..56]);
                    let e1 = load_u64_le(&ch[56..64]);

                    let f0 = h0 + ((a0 as u128) & M44);
                    let f1 = h1 + ((((a0 >> 44) | (a1 << 20)) as u128) & M44);
                    let f2 = h2 + (((a1 >> 24) as u128) | HIBIT);

                    let m10 = (b0 as u128) & M44;
                    let m11 = (((b0 >> 44) | (b1 << 20)) as u128) & M44;
                    let m12 = ((b1 >> 24) as u128) | HIBIT;

                    let m20 = (c0 as u128) & M44;
                    let m21 = (((c0 >> 44) | (c1 << 20)) as u128) & M44;
                    let m22 = ((c1 >> 24) as u128) | HIBIT;

                    let m30 = (e0 as u128) & M44;
                    let m31 = (((e0 >> 44) | (e1 << 20)) as u128) & M44;
                    let m32 = ((e1 >> 24) as u128) | HIBIT;

                    let d0 = f0 * r40 + f1 * s42 + f2 * s41
                        + m10 * r30 + m11 * s32 + m12 * s31
                        + m20 * r20 + m21 * s22 + m22 * s21
                        + m30 * r0 + m31 * s2 + m32 * s1;
                    let mut d1 = f0 * r41 + f1 * r40 + f2 * s42
                        + m10 * r31 + m11 * r30 + m12 * s32
                        + m20 * r21 + m21 * r20 + m22 * s22
                        + m30 * r1 + m31 * r0 + m32 * s2;
                    let mut d2 = f0 * r42 + f1 * r41 + f2 * r40
                        + m10 * r32 + m11 * r31 + m12 * r30
                        + m20 * r22 + m21 * r21 + m22 * r20
                        + m30 * r2 + m31 * r1 + m32 * r0;

                    let mut cy = d0 >> 44;
                    let mut t0 = d0 & M44;
                    d1 += cy;
                    cy = d1 >> 44;
                    h1 = d1 & M44;
                    d2 += cy;
                    cy = d2 >> 42;
                    h2 = d2 & M42;
                    t0 += cy * 5;
                    cy = t0 >> 44;
                    h0 = t0 & M44;
                    h1 += cy;
                }
                slice = chunks64.remainder();
            }
        }
        let mut chunks = slice.chunks_exact(16);
        for ch in &mut chunks {
            let u0 = load_u64_le(&ch[0..8]);
            let u1 = load_u64_le(&ch[8..16]);
            step_block(&mut h0, &mut h1, &mut h2, u0, u1, r0, r1, r2, s1, s2);
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut b = [0u8; 16];
            b[..rem.len()].copy_from_slice(rem);
            let u0 = load_u64_le(&b[0..8]);
            let u1 = load_u64_le(&b[8..16]);
            step_block(&mut h0, &mut h1, &mut h2, u0, u1, r0, r1, r2, s1, s2);
        }
    }

    step_block(
        &mut h0,
        &mut h1,
        &mut h2,
        aad.len() as u64,
        ct.len() as u64,
        r0,
        r1,
        r2,
        s1,
        s2,
    );

    let mut c = h1 >> 44;
    h1 &= M44;
    h2 += c;
    c = h2 >> 42;
    h2 &= M42;
    h0 += c * 5;
    c = h0 >> 44;
    h0 &= M44;
    h1 += c;
    c = h1 >> 44;
    h1 &= M44;
    h2 += c;

    let mut g0 = h0 + 5;
    c = g0 >> 44;
    g0 &= M44;
    let mut g1 = h1 + c;
    c = g1 >> 44;
    g1 &= M44;
    let g2 = h2.wrapping_add(c).wrapping_sub(1u128 << 42);

    let mask = (g2 >> 127).wrapping_sub(1);
    let nmask = !mask;
    h0 = (h0 & nmask) | (g0 & mask);
    h1 = (h1 & nmask) | (g1 & mask);
    h2 = (h2 & nmask) | (g2 & mask);

    let f0 = (h0 as u64) | ((h1 as u64) << 44);
    let f1 = ((h1 as u64) >> 20) | ((h2 as u64) << 24);
    let pad0 = load_u64_le(&otk[16..24]);
    let pad1 = load_u64_le(&otk[24..32]);
    let (sum0, carry) = f0.overflowing_add(pad0);
    let sum1 = f1.wrapping_add(pad1).wrapping_add(carry as u64);

    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&sum0.to_le_bytes());
    out[8..16].copy_from_slice(&sum1.to_le_bytes());
    out
}

pub fn chacha20_poly1305_seal_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
) -> [u8; 16] {
    let mut blk0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&blk0[..32]);
    secure_zero(&mut blk0);
    chacha20_xor_in_place(key, 1, nonce, data);
    let tag = poly1305_mac(&otk, aad, data);
    secure_zero(&mut otk);
    tag
}

pub fn chacha20_poly1305_verify_tag(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; 16],
) -> Result<(), &'static str> {
    let mut blk0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&blk0[..32]);
    secure_zero(&mut blk0);
    let mut expected = poly1305_mac(&otk, aad, ct);
    secure_zero(&mut otk);
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= expected[i] ^ tag[i];
    }
    secure_zero(&mut expected);
    if diff != 0 {
        return Err("AEAD_AUTH_FAILED");
    }
    Ok(())
}

pub fn chacha20_poly1305_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plain: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let mut buf = plain.to_vec();
    let tag = chacha20_poly1305_seal_in_place(key, nonce, aad, &mut buf);
    (buf, tag)
}

pub fn chacha20_poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, &'static str> {
    chacha20_poly1305_verify_tag(key, nonce, aad, ct, tag)?;
    let mut out = vec![0u8; ct.len()];
    chacha20_xor_into(key, 1, nonce, ct, &mut out);
    Ok(out)
}

pub fn os_random_bytes(out: &mut [u8]) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        extern "C" {
            fn getrandom(buf: *mut u8, buflen: usize, flags: u32) -> isize;
        }
        let mut offset = 0usize;
        while offset < out.len() {
            let chunk = &mut out[offset..];
            let n = unsafe { getrandom(chunk.as_mut_ptr(), chunk.len(), 0) };
            if n > 0 {
                offset += n as usize;
            } else if n == 0 {
                return Err("GETRANDOM_EOF".to_string());
            } else {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(format!("GETRANDOM_FAILED:{err}"));
            }
        }
        return Ok(());
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        use std::io::Read;
        let mut f = fs::File::open("/dev/urandom").map_err(|e| e.to_string())?;
        f.read_exact(out).map_err(|e| e.to_string())?;
        return Ok(());
    }
    #[cfg(windows)]
    {
        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(
                h_algorithm: *mut core::ffi::c_void,
                pb_buffer: *mut u8,
                cb_buffer: u32,
                dw_flags: u32,
            ) -> i32;
        }
        const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
        for chunk in out.chunks_mut(u32::MAX as usize) {
            let status = unsafe {
                BCryptGenRandom(
                    core::ptr::null_mut(),
                    chunk.as_mut_ptr(),
                    chunk.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            if status != 0 {
                return Err(format!("BCRYPT_RNG_FAILED:0x{status:08x}"));
            }
        }
        return Ok(());
    }
    #[cfg(not(any(unix, windows)))]
    {
        compile_error!("Unsupported platform: OS CSPRNG required");
    }
}

pub fn derive_vspk2_key_and_aad(
    master_key: &[u8; 32],
    domain: &str,
    asset_id: &str,
    context: &str,
) -> ([u8; 32], Vec<u8>) {
    let info = format!("VSPK2_V1|{domain}|{asset_id}|{context}").into_bytes();
    let key = hkdf_sha256_32(master_key, asset_id.as_bytes(), &info);
    (key, info)
}

pub fn pack_vspk2(
    master_key: &[u8; 32],
    domain: &str,
    asset_id: &str,
    context: &str,
    plain: &[u8],
) -> Result<Vec<u8>, String> {
    if domain.as_bytes().contains(&0)
        || asset_id.as_bytes().contains(&0)
        || context.as_bytes().contains(&0)
    {
        return Err("NUL_IN_METADATA".to_string());
    }
    let (mut key, aad) = derive_vspk2_key_and_aad(master_key, domain, asset_id, context);
    let mut nonce = [0u8; 12];
    os_random_bytes(&mut nonce)?;
    let (ct, tag) = chacha20_poly1305_seal(&key, &nonce, &aad, plain);
    secure_zero(&mut key);

    let db = domain.as_bytes();
    let ab = asset_id.as_bytes();
    let cb = context.as_bytes();
    if db.len() > 128 || ab.len() > 128 || cb.len() > 256 {
        return Err("METADATA_TOO_LONG".to_string());
    }

    let mut out = Vec::with_capacity(40 + db.len() + ab.len() + cb.len() + ct.len());
    out.extend_from_slice(MAGIC_VSPK2);
    out.push(1u8);
    out.extend_from_slice(&(db.len() as u16).to_le_bytes());
    out.extend_from_slice(&(ab.len() as u16).to_le_bytes());
    out.extend_from_slice(&(cb.len() as u16).to_le_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(db);
    out.extend_from_slice(ab);
    out.extend_from_slice(cb);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn unseal_vspk2_inner(
    master_key: &[u8; 32],
    expected_domain: &str,
    expected_asset_id: Option<&str>,
    expected_context: &str,
    vspk: &[u8],
) -> Result<Vec<u8>, String> {
    if vspk.len() < 40 || &vspk[0..5] != MAGIC_VSPK2 || vspk[5] != 1 {
        return Err("BAD_VSPK2_HEADER".to_string());
    }
    let dlen = u16::from_le_bytes([vspk[6], vspk[7]]) as usize;
    let alen = u16::from_le_bytes([vspk[8], vspk[9]]) as usize;
    let clen = u16::from_le_bytes([vspk[10], vspk[11]]) as usize;
    let hdr_end = 40usize
        .checked_add(dlen)
        .and_then(|x| x.checked_add(alen))
        .and_then(|x| x.checked_add(clen))
        .ok_or_else(|| "HDR_OVERFLOW".to_string())?;
    if vspk.len() < hdr_end {
        return Err("TRUNCATED_VSPK2".to_string());
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&vspk[12..24]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&vspk[24..40]);

    let domain = std::str::from_utf8(&vspk[40..40 + dlen]).map_err(|e| e.to_string())?;
    let asset_id =
        std::str::from_utf8(&vspk[40 + dlen..40 + dlen + alen]).map_err(|e| e.to_string())?;
    let context =
        std::str::from_utf8(&vspk[40 + dlen + alen..hdr_end]).map_err(|e| e.to_string())?;
    if domain.as_bytes().contains(&0)
        || asset_id.as_bytes().contains(&0)
        || context.as_bytes().contains(&0)
    {
        return Err("NUL_IN_METADATA".to_string());
    }

    if domain != expected_domain || context != expected_context {
        return Err("CONTEXT_OR_DOMAIN_DENIED".to_string());
    }
    if let Some(exp_aid) = expected_asset_id {
        if asset_id != exp_aid {
            return Err("ASSET_ID_DENIED".to_string());
        }
    }
    let (mut key, aad) = derive_vspk2_key_and_aad(master_key, domain, asset_id, context);
    let res = chacha20_poly1305_open(&key, &nonce, &aad, &vspk[hdr_end..], &tag)
        .map_err(|e| e.to_string());
    secure_zero(&mut key);
    res
}

pub fn unseal_vspk2(
    master_key: &[u8; 32],
    expected_domain: &str,
    expected_context: &str,
    vspk: &[u8],
) -> Result<Vec<u8>, String> {
    unseal_vspk2_inner(master_key, expected_domain, None, expected_context, vspk)
}

/// Unseal a `VSPK2` container while also strictly enforcing `expected_asset_id`.
pub fn unseal_vspk2_for_asset(
    master_key: &[u8; 32],
    expected_domain: &str,
    expected_asset_id: &str,
    expected_context: &str,
    vspk: &[u8],
) -> Result<Vec<u8>, String> {
    unseal_vspk2_inner(
        master_key,
        expected_domain,
        Some(expected_asset_id),
        expected_context,
        vspk,
    )
}

/* ---- 3D Spatial GLB Cooker & Spread-Spectrum Traitor Watermark ---- */
pub const WM_AMPLITUDE: i16 = 4;

fn chip_index_and_sign(
    seed: &[u8; 32],
    chip_idx: usize,
    total_len: usize,
) -> Result<(usize, i16), String> {
    if total_len < CHIPS_TOTAL {
        return Err("BUFFER_TOO_SHORT_FOR_WATERMARK".to_string());
    }
    let mut msg = [0u8; 34];
    msg[..32].copy_from_slice(seed);
    msg[32..34].copy_from_slice(&(chip_idx as u16).to_le_bytes());
    let h = sha256(&msg);
    let bucket = total_len / CHIPS_TOTAL;
    let offset = (u32::from_le_bytes([h[0], h[1], h[2], h[3]]) as usize) % bucket;
    let sign = if (h[4] & 1) == 0 {
        WM_AMPLITUDE
    } else {
        -WM_AMPLITUDE
    };
    Ok((chip_idx * bucket + offset, sign))
}

pub fn cook_glb_vspk2(
    master_key: &[u8; 32],
    asset_id: &str,
    context: &str,
    glb_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<i16>), String> {
    if glb_bytes.len() < 28 || glb_bytes.get(0..4) != Some(b"glTF".as_slice()) {
        return Err("INVALID_GLB".to_string());
    }
    let json_len =
        u32::from_le_bytes([glb_bytes[12], glb_bytes[13], glb_bytes[14], glb_bytes[15]]) as usize;
    let bin_hdr = 20usize
        .checked_add(json_len)
        .ok_or_else(|| "GLB_JSON_OVERFLOW".to_string())?;
    let hdr_slice = glb_bytes
        .get(bin_hdr..bin_hdr.saturating_add(8))
        .ok_or_else(|| "TRUNCATED_GLB_BIN_HDR".to_string())?;
    let bin_len =
        u32::from_le_bytes([hdr_slice[0], hdr_slice[1], hdr_slice[2], hdr_slice[3]]) as usize;
    let bin_end = bin_hdr
        .checked_add(8)
        .and_then(|x| x.checked_add(bin_len))
        .ok_or_else(|| "GLB_BIN_OVERFLOW".to_string())?;
    let bin_chunk = glb_bytes
        .get(bin_hdr + 8..bin_end)
        .ok_or_else(|| "TRUNCATED_GLB_BIN_CHUNK".to_string())?;
    if bin_chunk.is_empty() {
        return Err("EMPTY_GLB_BIN_CHUNK".to_string());
    }

    let coord_len = 85_455usize.max(CHIPS_TOTAL * 8);
    let mut base_key = hmac_sha256(
        master_key,
        format!("VS3D_KEYED_GEOM_V2|{asset_id}").as_bytes(),
    );
    let mut owner_ref = vec![0i16; coord_len];
    for i in 0..coord_len {
        let b = bin_chunk[i % bin_chunk.len()] as i32;
        let k = base_key[i & 31] as i32;
        let raw = ((((b ^ k) * 257 + ((i as i32 * 73) & 0xffff)) & 0xffff) - 32768) as i16;
        owner_ref[i] = raw.clamp(-32750, 32750);
    }
    secure_zero(&mut base_key);

    // Do NOT append raw unwatermarked bin_chunk alongside owner_ref
    let mut vs3d = Vec::with_capacity(12 + coord_len * 2);
    vs3d.extend_from_slice(b"VS3D");
    vs3d.extend_from_slice(&((coord_len * 2) as u32).to_le_bytes());
    vs3d.extend_from_slice(&0u32.to_le_bytes());
    for &v in &owner_ref {
        vs3d.extend_from_slice(&v.to_le_bytes());
    }

    let sealed = pack_vspk2(master_key, "spatial-3d", asset_id, context, &vs3d)?;
    secure_zero(&mut vs3d);
    Ok((sealed, owner_ref))
}

pub fn unseal_glb_for_lease(
    master_key: &[u8; 32],
    asset_id: &str,
    context: &str,
    lease_id: &str,
    vspk: &[u8],
) -> Result<Vec<i16>, String> {
    let mut vs3d = unseal_vspk2(master_key, "spatial-3d", context, vspk)?;
    if vs3d.len() < 12 || vs3d.get(0..4) != Some(b"VS3D".as_slice()) {
        secure_zero(&mut vs3d);
        return Err("BAD_VS3D".to_string());
    }
    let pos_bytes = u32::from_le_bytes([vs3d[4], vs3d[5], vs3d[6], vs3d[7]]) as usize;
    if (pos_bytes & 1) != 0 || 12usize.saturating_add(pos_bytes) > vs3d.len() {
        secure_zero(&mut vs3d);
        return Err("TRUNCATED_VS3D_POSITIONS".to_string());
    }
    let count = pos_bytes / 2;
    if count < CHIPS_TOTAL {
        secure_zero(&mut vs3d);
        return Err("VS3D_TOO_SMALL".to_string());
    }
    let mut positions = Vec::with_capacity(count);
    for i in 0..count {
        let off = 12 + i * 2;
        positions.push(i16::from_le_bytes([vs3d[off], vs3d[off + 1]]));
    }
    secure_zero(&mut vs3d);

    let mut wm_seed = hmac_sha256(
        master_key,
        format!("VS_WM_CARRIER_V1|{asset_id}|{lease_id}").as_bytes(),
    );
    for c in 0..CHIPS_TOTAL {
        let (idx, delta) = chip_index_and_sign(&wm_seed, c, positions.len())?;
        positions[idx] = positions[idx].saturating_add(delta);
    }
    secure_zero(&mut wm_seed);
    Ok(positions)
}

pub fn trace_glb_watermark(
    master_key: &[u8; 32],
    asset_id: &str,
    owner_ref: &[i16],
    captured: &[i16],
    candidates: &[String],
) -> Option<(String, f64)> {
    if owner_ref.len() < CHIPS_TOTAL || captured.len() < owner_ref.len() {
        return None;
    }
    let mut best: Option<(String, f64)> = None;
    let denom = (CHIPS_TOTAL as f64) * ((WM_AMPLITUDE as f64) * (WM_AMPLITUDE as f64));
    for cand in candidates {
        let mut seed = hmac_sha256(
            master_key,
            format!("VS_WM_CARRIER_V1|{asset_id}|{cand}").as_bytes(),
        );
        let mut dot: i64 = 0;
        for c in 0..CHIPS_TOTAL {
            if let Ok((idx, expected_delta)) = chip_index_and_sign(&seed, c, owner_ref.len()) {
                let obs = (captured[idx] as i32) - (owner_ref[idx] as i32);
                let clamped = obs.clamp(-(WM_AMPLITUDE as i32) * 2, (WM_AMPLITUDE as i32) * 2);
                dot += (clamped as i64) * (expected_delta as i64);
            }
        }
        secure_zero(&mut seed);
        let corr = ((dot as f64) / denom).clamp(-1.0, 1.0);
        if best.as_ref().map_or(true, |(_, b)| corr > *b) {
            best = Some((cand.clone(), corr));
        }
    }
    best
}

/* ---- Native ELF64 Self-Hashing Builder ---- */
pub fn hex_encode(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("ODD_HEX".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for i in 0..(b.len() / 2) {
        let nib = |c: u8| -> Result<u8, String> {
            match c {
                b'0'..=b'9' => Ok(c - b'0'),
                b'a'..=b'f' => Ok(c - b'a' + 10),
                b'A'..=b'F' => Ok(c - b'A' + 10),
                _ => Err("BAD_HEX_CHAR".to_string()),
            }
        };
        out.push((nib(b[i * 2])? << 4) | nib(b[i * 2 + 1])?);
    }
    Ok(out)
}

pub fn build_protected_elf(
    master_key: &[u8; 32],
    template_c_path: &Path,
    asset_id: &str,
    plain_payload: &[u8],
    out_elf_path: &Path,
) -> Result<(String, String), String> {
    if plain_payload.is_empty() || plain_payload.len() > 4096 {
        return Err("PAYLOAD_BOUNDS".to_string());
    }
    let tmpl_str = template_c_path.to_str().ok_or("BAD_TEMPLATE_PATH")?;
    let out_str = out_elf_path.to_str().ok_or("BAD_OUT_PATH")?;
    let status = Command::new("gcc")
        .args([
            "-O2",
            "-fno-inline",
            "-fPIE",
            "-pie",
            "-fstack-protector-strong",
            "-D_FORTIFY_SOURCE=3",
            "-fcf-protection=full",
            "-Wl,-z,relro,-z,now,-z,ibt,-z,shstk",
            "-Wall",
            "-Wextra",
            tmpl_str,
            "-o",
            out_str,
        ])
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("GCC_FAILED".to_string());
    }

    let mut elf = fs::read(out_elf_path).map_err(|e| e.to_string())?;
    if elf.len() < 64 || elf.get(0..4) != Some(b"\x7fELF".as_slice()) {
        return Err("BAD_ELF64".to_string());
    }
    let e_phoff = u64::from_le_bytes(elf[32..40].try_into().unwrap()) as usize;
    let e_shoff = u64::from_le_bytes(elf[40..48].try_into().unwrap()) as usize;
    let e_phentsize = u16::from_le_bytes([elf[54], elf[55]]) as usize;
    let e_phnum = u16::from_le_bytes([elf[56], elf[57]]) as usize;
    let e_shentsize = u16::from_le_bytes([elf[58], elf[59]]) as usize;
    let e_shnum = u16::from_le_bytes([elf[60], elf[61]]) as usize;
    let e_shstrndx = u16::from_le_bytes([elf[62], elf[63]]) as usize;

    let mut rx_bytes = Vec::new();
    for i in 0..e_phnum {
        let off = e_phoff
            .checked_add(i.checked_mul(e_phentsize).ok_or("PH_MUL_OVERFLOW")?)
            .ok_or("PH_OFF_OVERFLOW")?;
        let ph = elf.get(off..off.saturating_add(56)).ok_or("TRUNCATED_PHDR")?;
        let p_type = u32::from_le_bytes(ph[0..4].try_into().unwrap());
        let p_flags = u32::from_le_bytes(ph[4..8].try_into().unwrap());
        let p_offset = u64::from_le_bytes(ph[8..16].try_into().unwrap()) as usize;
        let p_filesz = u64::from_le_bytes(ph[32..40].try_into().unwrap()) as usize;
        if p_type == 1 && (p_flags & 1) != 0 {
            let seg = elf
                .get(p_offset..p_offset.checked_add(p_filesz).ok_or("SEG_OVERFLOW")?)
                .ok_or("TRUNCATED_RX_SEG")?;
            rx_bytes.extend_from_slice(seg);
        }
    }
    let rx_hex = hex_encode(&sha256(&rx_bytes));

    let str_hdr = e_shoff
        .checked_add(e_shstrndx.checked_mul(e_shentsize).ok_or("SH_MUL_OVERFLOW")?)
        .ok_or("SH_OFF_OVERFLOW")?;
    let sh_str_entry = elf
        .get(str_hdr..str_hdr.saturating_add(40))
        .ok_or("TRUNCATED_SHSTR")?;
    let str_off = u64::from_le_bytes(sh_str_entry[24..32].try_into().unwrap()) as usize;
    let str_sz = u64::from_le_bytes(sh_str_entry[32..40].try_into().unwrap()) as usize;
    let strtab = elf
        .get(str_off..str_off.checked_add(str_sz).ok_or("STRTAB_OVERFLOW")?)
        .ok_or("TRUNCATED_STRTAB")?;

    let mut vsblob_off = None;
    for i in 0..e_shnum {
        let soff = e_shoff
            .checked_add(i.checked_mul(e_shentsize).ok_or("SH_ITER_OVERFLOW")?)
            .ok_or("SH_ITER_OFF_OVERFLOW")?;
        let sh = elf.get(soff..soff.saturating_add(40)).ok_or("TRUNCATED_SHDR")?;
        let nidx = u32::from_le_bytes(sh[0..4].try_into().unwrap()) as usize;
        let tail = strtab.get(nidx..).ok_or("BAD_SH_NAME")?;
        let nul_rel = tail.iter().position(|&c| c == 0).ok_or("UNTERM_SH_NAME")?;
        if &tail[..nul_rel] == b".vsblob" {
            vsblob_off = Some(u64::from_le_bytes(sh[24..32].try_into().unwrap()) as usize);
        }
    }
    let blob_pos = vsblob_off.ok_or_else(|| "MISSING_VSBLOB".to_string())?;

    let (mut lease_root_key, _) = derive_vspk2_key_and_aad(master_key, "native", asset_id, "");
    let info = format!("VS_NATIVE_ELF_V1|{asset_id}|{rx_hex}");
    let mut content_key = hkdf_sha256_32(&lease_root_key, asset_id.as_bytes(), info.as_bytes());
    let mut nonce = [0u8; 12];
    if let Err(e) = os_random_bytes(&mut nonce) {
        secure_zero(&mut content_key);
        secure_zero(&mut lease_root_key);
        return Err(e);
    }
    let (ct, tag) = chacha20_poly1305_seal(&content_key, &nonce, info.as_bytes(), plain_payload);
    secure_zero(&mut content_key);

    let mut slot = vec![0u8; 104 + 4096];
    if let Err(e) = os_random_bytes(&mut slot[104..]) {
        secure_zero(&mut lease_root_key);
        return Err(e);
    }
    slot[0..8].copy_from_slice(b"VSBLB001");
    slot[8..12].copy_from_slice(&(ct.len() as u32).to_le_bytes());
    slot[12..24].copy_from_slice(&nonce);
    slot[24..40].copy_from_slice(&tag);
    let aid_bytes = asset_id.as_bytes();
    let copy_n = aid_bytes.len().min(63);
    slot[40..40 + copy_n].copy_from_slice(&aid_bytes[..copy_n]);
    slot[104..104 + ct.len()].copy_from_slice(&ct);

    let dest = match elf
        .get_mut(blob_pos..blob_pos.checked_add(slot.len()).ok_or("SLOT_OVERFLOW")?)
        .ok_or("TRUNCATED_VSBLOB_SLOT")
    {
        Ok(d) => d,
        Err(e) => {
            secure_zero(&mut lease_root_key);
            return Err(e.to_string());
        }
    };
    dest.copy_from_slice(&slot);
    if let Err(e) = fs::write(out_elf_path, &elf) {
        secure_zero(&mut lease_root_key);
        return Err(e.to_string());
    }
    let strip_status = Command::new("strip")
        .args(["-s", out_str])
        .status()
        .map_err(|e| {
            secure_zero(&mut lease_root_key);
            e.to_string()
        })?;
    if !strip_status.success() {
        secure_zero(&mut lease_root_key);
        return Err("STRIP_FAILED".to_string());
    }
    let lease_hex = hex_encode(&lease_root_key);
    secure_zero(&mut lease_root_key);
    Ok((lease_hex, rx_hex))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_disabled_by_default_and_enforces_params() {
        let mut p = Policy::new_disabled([7u8; 32]);
        p.actions.insert(
            "quote".to_string(),
            ActionRule {
                domain: "backend".to_string(),
                context: "prod".to_string(),
                params: HashMap::from([(
                    "seats".to_string(),
                    ParamRule::Int { min: 1, max: 100 },
                )]),
            },
        );
        let mut args = HashMap::new();
        args.insert("seats".to_string(), ParamValue::Int(10));
        assert_eq!(p.validate_call("quote", &args).unwrap_err(), "POLICY_DISABLED");

        p.enabled = true;
        assert!(p.validate_call("quote", &args).is_ok());
        args.insert("seats".to_string(), ParamValue::Int(500));
        assert!(p.validate_call("quote", &args).unwrap_err().contains("PARAM_OUT_OF_RANGE"));
    }

    #[test]
    fn rfc8439_vspk2_roundtrip_and_tamper_reject() {
        let mk = [0x42u8; 32];
        let msg = b"RUST_NATIVE_AEAD_ROUNDTRIP_PAYLOAD";
        let mut vspk = pack_vspk2(&mk, "rust-svc", "cfg-1", "eu-west", msg).unwrap();
        let opened = unseal_vspk2(&mk, "rust-svc", "eu-west", &vspk).unwrap();
        assert_eq!(opened, msg);

        assert!(unseal_vspk2_for_asset(&mk, "rust-svc", "cfg-1", "eu-west", &vspk).is_ok());
        assert!(unseal_vspk2_for_asset(&mk, "rust-svc", "wrong-asset", "eu-west", &vspk).is_err());
        assert!(unseal_vspk2(&mk, "rust-svc", "wrong-region", &vspk).is_err());
        let last = vspk.len() - 1;
        vspk[last] ^= 1;
        assert!(unseal_vspk2(&mk, "rust-svc", "eu-west", &vspk).is_err());
    }

    #[test]
    fn simd_sha256_chacha20_poly1305_match_scalar_and_rfc8439() {
        let mut state_scalar = [
            0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];
        let mut data = vec![0u8; 4096];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i.wrapping_mul(131) ^ (i >> 3)) as u8;
        }
        for len in [0usize, 1, 55, 56, 63, 64, 65, 128, 1024, 4096] {
            let d = sha256(&data[..len]);
            let mut st = state_scalar;
            let mut blocks = data[..len].chunks_exact(64);
            for ch in &mut blocks {
                sha256_compress_scalar(&mut st, ch.try_into().unwrap());
            }
            let rem = blocks.remainder();
            let mut pad = [0u8; 128];
            pad[..rem.len()].copy_from_slice(rem);
            pad[rem.len()] = 0x80;
            let tpad = if rem.len() < 56 { 64 } else { 128 };
            pad[tpad - 8..tpad].copy_from_slice(&((len as u64) * 8).to_be_bytes());
            for ch in pad[..tpad].chunks_exact(64) {
                sha256_compress_scalar(&mut st, ch.try_into().unwrap());
            }
            let mut exp = [0u8; 32];
            for (i, w) in st.iter().enumerate() {
                exp[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
            }
            assert_eq!(d, exp, "sha256 mismatch at len={len}");
        }
        let _ = &mut state_scalar;

        // ChaCha20 AVX-512/AVX2 vs scalar block-by-block across >512B and >1024B boundaries
        let key = [0x3cu8; 32];
        let nonce = [0x91u8; 12];
        for len in [0usize, 1, 64, 511, 512, 513, 1023, 1024, 1025, 1536, 2048, 2111, 4096] {
            let mut got = data[..len].to_vec();
            chacha20_xor_in_place(&key, 7, &nonce, &mut got);
            let mut expected = data[..len].to_vec();
            let mut ctr = 7u32;
            for ch in expected.chunks_mut(64) {
                let blk = chacha20_block(&key, ctr, &nonce);
                ctr += 1;
                for (a, b) in ch.iter_mut().zip(blk.iter()) {
                    *a ^= *b;
                }
            }
            assert_eq!(got, expected, "chacha20 mismatch at len={len}");
        }

        // Verify 4-way Poly1305 (>=64B) matches 1-block reference on multi-KiB AEAD payloads
        for len in [63usize, 64, 65, 127, 128, 129, 255, 256, 1024, 2111, 4096] {
            let (ct_m, tag_m) = chacha20_poly1305_seal(&key, &nonce, &data[..19], &data[..len]);
            let otw = chacha20_poly1305_open(&key, &nonce, &data[..19], &ct_m, &tag_m).unwrap();
            assert_eq!(otw.as_slice(), &data[..len], "aead mismatch at len={len}");
            // Reference 26-bit Poly1305 check via single-block BigInt-free scalar match against vspk2/otk
            let blk0 = chacha20_block(&key, 0, &nonce);
            let mut ref_otk = [0u8; 32];
            ref_otk.copy_from_slice(&blk0[..32]);
            let t0 = load_u64_le(&ref_otk[0..8]) & 0x0fff_fffc_0fff_ffffu64;
            let t1 = load_u64_le(&ref_otk[8..16]) & 0x0fff_fffc_0fff_fffcu64;
            const M44: u128 = 0x0fff_ffff_ffffu128;
            const M42: u128 = 0x03ff_ffff_ffffu128;
            let rr0 = (t0 as u128) & M44;
            let rr1 = (((t0 >> 44) | (t1 << 20)) as u128) & M44;
            let rr2 = ((t1 >> 24) as u128) & M42;
            let (mut hh0, mut hh1, mut hh2) = (0u128, 0u128, 0u128);
            let mut ref_step = |u0: u64, u1: u64| {
                let f0 = hh0 + ((u0 as u128) & M44);
                let f1 = hh1 + ((((u0 >> 44) | (u1 << 20)) as u128) & M44);
                let f2 = hh2 + (((u1 >> 24) as u128) | (1u128 << 40));
                let d0 = f0 * rr0 + f1 * (rr2 * 20) + f2 * (rr1 * 20);
                let mut d1 = f0 * rr1 + f1 * rr0 + f2 * (rr2 * 20);
                let mut d2 = f0 * rr2 + f1 * rr1 + f2 * rr0;
                let mut c = d0 >> 44; let mut tt0 = d0 & M44; d1 += c;
                c = d1 >> 44; hh1 = d1 & M44; d2 += c;
                c = d2 >> 42; hh2 = d2 & M42; tt0 += c * 5;
                c = tt0 >> 44; hh0 = tt0 & M44; hh1 += c;
            };
            for sl in [&data[..19], ct_m.as_slice()] {
                let mut chs = sl.chunks_exact(16);
                for ch in &mut chs {
                    ref_step(load_u64_le(&ch[0..8]), load_u64_le(&ch[8..16]));
                }
                if !chs.remainder().is_empty() {
                    let mut b = [0u8; 16];
                    b[..chs.remainder().len()].copy_from_slice(chs.remainder());
                    ref_step(load_u64_le(&b[0..8]), load_u64_le(&b[8..16]));
                }
            }
            ref_step(19u64, ct_m.len() as u64);
            let mut c = hh1 >> 44; hh1 &= M44; hh2 += c;
            c = hh2 >> 42; hh2 &= M42; hh0 += c * 5;
            c = hh0 >> 44; hh0 &= M44; hh1 += c;
            c = hh1 >> 44; hh1 &= M44; hh2 += c;
            let mut g0 = hh0 + 5; c = g0 >> 44; g0 &= M44;
            let mut g1 = hh1 + c; c = g1 >> 44; g1 &= M44;
            let g2 = hh2.wrapping_add(c).wrapping_sub(1u128 << 42);
            let msk = (g2 >> 127).wrapping_sub(1);
            hh0 = (hh0 & !msk) | (g0 & msk);
            hh1 = (hh1 & !msk) | (g1 & msk);
            hh2 = (hh2 & !msk) | (g2 & msk);
            let ff0 = (hh0 as u64) | ((hh1 as u64) << 44);
            let ff1 = ((hh1 as u64) >> 20) | ((hh2 as u64) << 24);
            let (s0, cy) = ff0.overflowing_add(load_u64_le(&ref_otk[16..24]));
            let s1 = ff1.wrapping_add(load_u64_le(&ref_otk[24..32])).wrapping_add(cy as u64);
            let mut exp_tag = [0u8; 16];
            exp_tag[0..8].copy_from_slice(&s0.to_le_bytes());
            exp_tag[8..16].copy_from_slice(&s1.to_le_bytes());
            assert_eq!(tag_m, exp_tag, "poly1305 4-way vs 1-block mismatch at len={len}");
        }

        // RFC 8439 Section 2.8.2 test vector
        let rfc_key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let rfc_nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let rfc_aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let rfc_pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ct: [u8; 114] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
            0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
            0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
            0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
            0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
            0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
            0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];
        let expected_tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
            0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
        ];
        let (ct, tag) = chacha20_poly1305_seal(&rfc_key, &rfc_nonce, &rfc_aad, rfc_pt);
        assert_eq!(ct.as_slice(), expected_ct.as_slice());
        assert_eq!(tag, expected_tag);
        let opened = chacha20_poly1305_open(&rfc_key, &rfc_nonce, &rfc_aad, &ct, &tag).unwrap();
        assert_eq!(opened.as_slice(), rfc_pt.as_slice());

        let mk = [0x5au8; 32];
        for len in [0usize, 1, 59, 60, 61, 64, 1020, 1021, 2500] {
            let msg = &data[..len];
            let mut sealed = pack_vspk3(&mk, "dom", "aid", "ctx", msg).unwrap();
            let got = unseal_vspk3(&mk, "dom", "aid", "ctx", &sealed).unwrap();
            assert_eq!(got.as_slice(), msg, "vspk3 roundtrip mismatch at len={len}");
            let got_owned = unseal_vspk3_owned(&mk, "dom", "aid", "ctx", sealed.clone()).unwrap();
            assert_eq!(got_owned.as_slice(), msg, "vspk3 owned roundtrip mismatch at len={len}");
            let last = sealed.len() - 1;
            sealed[last] ^= 0x80;
            assert!(unseal_vspk3(&mk, "dom", "aid", "ctx", &sealed).is_err());
            assert!(unseal_vspk3_owned(&mk, "dom", "aid", "ctx", sealed.clone()).is_err());
        }
    }
}
