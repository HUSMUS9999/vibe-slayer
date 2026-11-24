//! Pure-Rust zero-dependency Website Bundler & Live Runtime Protection Server (`1.0.0-beta.3`).
//! Implements:
//! - FIPS 197 AES-256 + NIST SP 800-38D AES-256-GCM (W3C WebCrypto compatible)
//! - FIPS 186-4 / SEC1 ECDH P-256 (secp256r1, 65-byte uncompressed raw public keys)
//! - `./vibe-slayer website <site-dir>` (encrypts all web assets + emits non-extractable WebCrypto loader)
//! - `./vibe-slayer serve <protected-site-dir>` (origin-pinned, single-use ticket, rate-limited HTTP/1.1 server)

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{IoSlice, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::auto_cli::{
    load_or_create_vault, parse_key_hex_32, record_artifact, resolve_default_keys_path,
    resolve_known_metadata, sha256_hex, walk_repo_files,
};
use crate::mini_json::{parse_json, to_json_pretty, JsonVal};
use crate::{hex_decode, hkdf_sha256_32, hmac_sha256, os_random_bytes, secure_zero};

/* ============================== FIPS 197 AES-256 ============================== */

#[rustfmt::skip]
const AES_SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

fn sub_word(w: u32) -> u32 {
    let b = w.to_be_bytes();
    u32::from_be_bytes([
        AES_SBOX[b[0] as usize],
        AES_SBOX[b[1] as usize],
        AES_SBOX[b[2] as usize],
        AES_SBOX[b[3] as usize],
    ])
}

fn aes256_expand_key(key: &[u8; 32]) -> [u32; 60] {
    const RCON: [u32; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];
    let mut w = [0u32; 60];
    for i in 0..8 {
        w[i] = u32::from_be_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    for i in 8..60 {
        let mut tmp = w[i - 1];
        if i % 8 == 0 {
            tmp = sub_word(tmp.rotate_left(8)) ^ (RCON[i / 8 - 1] << 24);
        } else if i % 8 == 4 {
            tmp = sub_word(tmp);
        }
        w[i] = w[i - 8] ^ tmp;
    }
    w
}

#[inline]
fn xtime(x: u8) -> u8 {
    (x << 1) ^ (((x >> 7) & 1) * 0x1b)
}

#[inline]
fn mul3(x: u8) -> u8 {
    xtime(x) ^ x
}

fn aes256_encrypt_block(rk: &[u32; 60], block: &[u8; 16]) -> [u8; 16] {
    let mut st = *block;
    let add_rk = |s: &mut [u8; 16], round: usize| {
        for c in 0..4 {
            let kb = rk[round * 4 + c].to_be_bytes();
            s[c * 4] ^= kb[0];
            s[c * 4 + 1] ^= kb[1];
            s[c * 4 + 2] ^= kb[2];
            s[c * 4 + 3] ^= kb[3];
        }
    };

    add_rk(&mut st, 0);
    for round in 1..=14 {
        for b in &mut st {
            *b = AES_SBOX[*b as usize];
        }
        // ShiftRows (column-major layout: index = col*4 + row)
        let t1 = st[1];
        st[1] = st[5];
        st[5] = st[9];
        st[9] = st[13];
        st[13] = t1;

        st.swap(2, 10);
        st.swap(6, 14);

        let t3 = st[15];
        st[15] = st[11];
        st[11] = st[7];
        st[7] = st[3];
        st[3] = t3;

        if round < 14 {
            for c in 0..4 {
                let off = c * 4;
                let a0 = st[off];
                let a1 = st[off + 1];
                let a2 = st[off + 2];
                let a3 = st[off + 3];
                st[off] = xtime(a0) ^ mul3(a1) ^ a2 ^ a3;
                st[off + 1] = a0 ^ xtime(a1) ^ mul3(a2) ^ a3;
                st[off + 2] = a0 ^ a1 ^ xtime(a2) ^ mul3(a3);
                st[off + 3] = mul3(a0) ^ a1 ^ a2 ^ xtime(a3);
            }
        }
        add_rk(&mut st, round);
    }
    st
}

/* ========================== NIST SP 800-38D AES-256-GCM ========================== */

fn gf128_mul_scalar(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = y;
    const R: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;
    for i in 0..128 {
        if ((x >> (127 - i)) & 1) != 0 {
            z ^= v;
        }
        let lsb = v & 1;
        v >>= 1;
        if lsb != 0 {
            v ^= R;
        }
    }
    z
}

fn ghash_scalar(h: u128, aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut y = 0u128;
    for slice in [aad, ct] {
        for ch in slice.chunks(16) {
            let mut blk = [0u8; 16];
            blk[..ch.len()].copy_from_slice(ch);
            y = gf128_mul_scalar(y ^ u128::from_be_bytes(blk), h);
        }
    }
    let mut lens = [0u8; 16];
    lens[0..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    lens[8..16].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
    y = gf128_mul_scalar(y ^ u128::from_be_bytes(lens), h);
    y.to_be_bytes()
}

fn inc32(ctr: &mut [u8; 16]) {
    let mut v = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]);
    v = v.wrapping_add(1);
    ctr[12..16].copy_from_slice(&v.to_be_bytes());
}

fn aes256_gctr_scalar(rk: &[u32; 60], icb: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let mut ctr = *icb;
    for (in_ch, out_ch) in data.chunks(16).zip(out.chunks_mut(16)) {
        let ks = aes256_encrypt_block(rk, &ctr);
        for i in 0..in_ch.len() {
            out_ch[i] = in_ch[i] ^ ks[i];
        }
        inc32(&mut ctr);
    }
    out
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,pclmulqdq,sse4.1,ssse3")]
unsafe fn ghash_mul_pclmul(a: core::arch::x86_64::__m128i, b: core::arch::x86_64::__m128i) -> core::arch::x86_64::__m128i {
    use core::arch::x86_64::*;

    let tmp2 = _mm_clmulepi64_si128::<0x00>(a, b);
    let tmp3 = _mm_clmulepi64_si128::<0x11>(a, b);
    let a_mix = _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(a), a);
    let b_mix = _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(b), b);
    let mid = _mm_xor_si128(
        _mm_clmulepi64_si128::<0x00>(a_mix, b_mix),
        _mm_xor_si128(tmp2, tmp3),
    );
    let mut lo = _mm_xor_si128(tmp2, _mm_slli_si128::<8>(mid));
    let mut hi = _mm_xor_si128(tmp3, _mm_srli_si128::<8>(mid));

    // Shift 256-bit [hi : lo] left by 1 bit to align reflected GCM degrees
    let c_lo = _mm_srli_epi64::<63>(lo);
    let c_hi = _mm_srli_epi64::<63>(hi);
    lo = _mm_or_si128(_mm_slli_epi64::<1>(lo), _mm_slli_si128::<8>(c_lo));
    hi = _mm_or_si128(
        _mm_slli_epi64::<1>(hi),
        _mm_or_si128(_mm_slli_si128::<8>(c_hi), _mm_srli_si128::<8>(c_lo)),
    );

    // 2-step Carryless-Multiply reduction modulo x^128 + x^127 + x^126 + x^121 + 1
    let poly = _mm_set_epi64x(0, 0xc200_0000_0000_0000u64 as i64);
    let t1 = _mm_clmulepi64_si128::<0x00>(lo, poly);
    let lo1 = _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(lo), t1);
    let t2 = _mm_clmulepi64_si128::<0x00>(lo1, poly);
    _mm_xor_si128(hi, _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(lo1), t2))
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,pclmulqdq,sse4.1,ssse3")]
unsafe fn ghash_pclmul(
    h_be_xmm: core::arch::x86_64::__m128i,
    bswap_mask: core::arch::x86_64::__m128i,
    aad: &[u8],
    ct: &[u8],
) -> core::arch::x86_64::__m128i {
    use core::arch::x86_64::*;

    let h1 = h_be_xmm;
    let h2 = ghash_mul_pclmul(h1, h1);
    let h3 = ghash_mul_pclmul(h2, h1);
    let h4 = ghash_mul_pclmul(h2, h2);
    let poly = _mm_set_epi64x(0, 0xc200_0000_0000_0000u64 as i64);

    let mut y = _mm_setzero_si128();

    let feed_slice = |y: &mut __m128i, s: &[u8]| {
        let mut p = s.as_ptr();
        let mut rem = s.len();
        while rem >= 64 {
            let b0 = _mm_xor_si128(
                *y,
                _mm_shuffle_epi8(_mm_loadu_si128(p as *const __m128i), bswap_mask),
            );
            let b1 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(16) as *const __m128i), bswap_mask);
            let b2 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(32) as *const __m128i), bswap_mask);
            let b3 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(48) as *const __m128i), bswap_mask);

            // Schoolbook sums across 4 blocks (reduce only once!)
            let lo0 = _mm_clmulepi64_si128::<0x00>(b0, h4);
            let hi0 = _mm_clmulepi64_si128::<0x11>(b0, h4);
            let m0 = _mm_clmulepi64_si128::<0x00>(
                _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(b0), b0),
                _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(h4), h4),
            );

            let lo1 = _mm_clmulepi64_si128::<0x00>(b1, h3);
            let hi1 = _mm_clmulepi64_si128::<0x11>(b1, h3);
            let m1 = _mm_clmulepi64_si128::<0x00>(
                _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(b1), b1),
                _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(h3), h3),
            );

            let lo2 = _mm_clmulepi64_si128::<0x00>(b2, h2);
            let hi2 = _mm_clmulepi64_si128::<0x11>(b2, h2);
            let m2 = _mm_clmulepi64_si128::<0x00>(
                _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(b2), b2),
                _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(h2), h2),
            );

            let lo3 = _mm_clmulepi64_si128::<0x00>(b3, h1);
            let hi3 = _mm_clmulepi64_si128::<0x11>(b3, h1);
            let m3 = _mm_clmulepi64_si128::<0x00>(
                _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(b3), b3),
                _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(h1), h1),
            );

            let sum_lo = _mm_xor_si128(_mm_xor_si128(lo0, lo1), _mm_xor_si128(lo2, lo3));
            let sum_hi = _mm_xor_si128(_mm_xor_si128(hi0, hi1), _mm_xor_si128(hi2, hi3));
            let sum_m = _mm_xor_si128(_mm_xor_si128(m0, m1), _mm_xor_si128(m2, m3));
            let mid = _mm_xor_si128(sum_m, _mm_xor_si128(sum_lo, sum_hi));

            let mut lo = _mm_xor_si128(sum_lo, _mm_slli_si128::<8>(mid));
            let mut hi = _mm_xor_si128(sum_hi, _mm_srli_si128::<8>(mid));

            let c_lo = _mm_srli_epi64::<63>(lo);
            let c_hi = _mm_srli_epi64::<63>(hi);
            lo = _mm_or_si128(_mm_slli_epi64::<1>(lo), _mm_slli_si128::<8>(c_lo));
            hi = _mm_or_si128(
                _mm_slli_epi64::<1>(hi),
                _mm_or_si128(_mm_slli_si128::<8>(c_hi), _mm_srli_si128::<8>(c_lo)),
            );

            let t1 = _mm_clmulepi64_si128::<0x00>(lo, poly);
            let rlo = _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(lo), t1);
            let t2 = _mm_clmulepi64_si128::<0x00>(rlo, poly);
            *y = _mm_xor_si128(hi, _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(rlo), t2));

            p = p.add(64);
            rem -= 64;
        }
        while rem >= 16 {
            let blk = _mm_shuffle_epi8(_mm_loadu_si128(p as *const __m128i), bswap_mask);
            *y = ghash_mul_pclmul(_mm_xor_si128(*y, blk), h1);
            p = p.add(16);
            rem -= 16;
        }
        if rem > 0 {
            let mut tail = [0u8; 16];
            core::ptr::copy_nonoverlapping(p, tail.as_mut_ptr(), rem);
            let blk = _mm_shuffle_epi8(
                _mm_loadu_si128(tail.as_ptr() as *const __m128i),
                bswap_mask,
            );
            *y = ghash_mul_pclmul(_mm_xor_si128(*y, blk), h1);
        }
    };

    feed_slice(&mut y, aad);
    feed_slice(&mut y, ct);

    let mut lens = [0u8; 16];
    lens[0..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    lens[8..16].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
    let lblk = _mm_shuffle_epi8(
        _mm_loadu_si128(lens.as_ptr() as *const __m128i),
        bswap_mask,
    );
    y = ghash_mul_pclmul(_mm_xor_si128(y, lblk), h1);
    _mm_shuffle_epi8(y, bswap_mask)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,pclmulqdq,sse4.1,ssse3")]
unsafe fn load_aes256_rks(rk: &[u32; 60]) -> [core::arch::x86_64::__m128i; 15] {
    use core::arch::x86_64::_mm_set_epi32;
    let mut rks = [core::arch::x86_64::_mm_setzero_si128(); 15];
    for r in 0..15 {
        rks[r] = _mm_set_epi32(
            rk[r * 4 + 3].swap_bytes() as i32,
            rk[r * 4 + 2].swap_bytes() as i32,
            rk[r * 4 + 1].swap_bytes() as i32,
            rk[r * 4 + 0].swap_bytes() as i32,
        );
    }
    rks
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,pclmulqdq,sse4.1,ssse3")]
unsafe fn aes_enc_one(
    rks: &[core::arch::x86_64::__m128i; 15],
    mut b: core::arch::x86_64::__m128i,
) -> core::arch::x86_64::__m128i {
    use core::arch::x86_64::*;
    b = _mm_xor_si128(b, rks[0]);
    for r in 1..14 {
        b = _mm_aesenc_si128(b, rks[r]);
    }
    _mm_aesenclast_si128(b, rks[14])
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,pclmulqdq,sse4.1,ssse3")]
unsafe fn aes256_gctr_aesni(
    rks: &[core::arch::x86_64::__m128i; 15],
    icb: &[u8; 16],
    input: &[u8],
    out: &mut [u8],
) {
    use core::arch::x86_64::*;

    let bswap_ctr32 = _mm_set_epi8(12, 13, 14, 15, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    let one_lane3 = _mm_set_epi32(1, 0, 0, 0);
    let mut ctr_le = _mm_shuffle_epi8(
        _mm_loadu_si128(icb.as_ptr() as *const __m128i),
        bswap_ctr32,
    );

    let mut off = 0usize;
    let in_ptr = input.as_ptr();
    let out_ptr = out.as_mut_ptr();
    while input.len() - off >= 128 {
        let mut b0 = _mm_shuffle_epi8(ctr_le, bswap_ctr32);
        ctr_le = _mm_add_epi32(ctr_le, one_lane3);
        let mut b1 = _mm_shuffle_epi8(ctr_le, bswap_ctr32);
        ctr_le = _mm_add_epi32(ctr_le, one_lane3);
        let mut b2 = _mm_shuffle_epi8(ctr_le, bswap_ctr32);
        ctr_le = _mm_add_epi32(ctr_le, one_lane3);
        let mut b3 = _mm_shuffle_epi8(ctr_le, bswap_ctr32);
        ctr_le = _mm_add_epi32(ctr_le, one_lane3);
        let mut b4 = _mm_shuffle_epi8(ctr_le, bswap_ctr32);
        ctr_le = _mm_add_epi32(ctr_le, one_lane3);
        let mut b5 = _mm_shuffle_epi8(ctr_le, bswap_ctr32);
        ctr_le = _mm_add_epi32(ctr_le, one_lane3);
        let mut b6 = _mm_shuffle_epi8(ctr_le, bswap_ctr32);
        ctr_le = _mm_add_epi32(ctr_le, one_lane3);
        let mut b7 = _mm_shuffle_epi8(ctr_le, bswap_ctr32);
        ctr_le = _mm_add_epi32(ctr_le, one_lane3);

        let k0 = rks[0];
        b0 = _mm_xor_si128(b0, k0);
        b1 = _mm_xor_si128(b1, k0);
        b2 = _mm_xor_si128(b2, k0);
        b3 = _mm_xor_si128(b3, k0);
        b4 = _mm_xor_si128(b4, k0);
        b5 = _mm_xor_si128(b5, k0);
        b6 = _mm_xor_si128(b6, k0);
        b7 = _mm_xor_si128(b7, k0);

        for r in 1..14 {
            let kr = rks[r];
            b0 = _mm_aesenc_si128(b0, kr);
            b1 = _mm_aesenc_si128(b1, kr);
            b2 = _mm_aesenc_si128(b2, kr);
            b3 = _mm_aesenc_si128(b3, kr);
            b4 = _mm_aesenc_si128(b4, kr);
            b5 = _mm_aesenc_si128(b5, kr);
            b6 = _mm_aesenc_si128(b6, kr);
            b7 = _mm_aesenc_si128(b7, kr);
        }

        let k14 = rks[14];
        b0 = _mm_aesenclast_si128(b0, k14);
        b1 = _mm_aesenclast_si128(b1, k14);
        b2 = _mm_aesenclast_si128(b2, k14);
        b3 = _mm_aesenclast_si128(b3, k14);
        b4 = _mm_aesenclast_si128(b4, k14);
        b5 = _mm_aesenclast_si128(b5, k14);
        b6 = _mm_aesenclast_si128(b6, k14);
        b7 = _mm_aesenclast_si128(b7, k14);

        let p = in_ptr.add(off);
        let q = out_ptr.add(off);
        _mm_storeu_si128(q as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p as *const __m128i), b0));
        _mm_storeu_si128(q.add(16) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(16) as *const __m128i), b1));
        _mm_storeu_si128(q.add(32) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(32) as *const __m128i), b2));
        _mm_storeu_si128(q.add(48) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(48) as *const __m128i), b3));
        _mm_storeu_si128(q.add(64) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(64) as *const __m128i), b4));
        _mm_storeu_si128(q.add(80) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(80) as *const __m128i), b5));
        _mm_storeu_si128(q.add(96) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(96) as *const __m128i), b6));
        _mm_storeu_si128(q.add(112) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(112) as *const __m128i), b7));

        off += 128;
    }

    while off < input.len() {
        let ctr_blk = _mm_shuffle_epi8(ctr_le, bswap_ctr32);
        ctr_le = _mm_add_epi32(ctr_le, one_lane3);
        let ks = aes_enc_one(rks, ctr_blk);
        let rem = input.len() - off;
        if rem >= 16 {
            let v = _mm_xor_si128(_mm_loadu_si128(in_ptr.add(off) as *const __m128i), ks);
            _mm_storeu_si128(out_ptr.add(off) as *mut __m128i, v);
            off += 16;
        } else {
            let mut ks_bytes = [0u8; 16];
            _mm_storeu_si128(ks_bytes.as_mut_ptr() as *mut __m128i, ks);
            for i in 0..rem {
                *out_ptr.add(off + i) = *in_ptr.add(off + i) ^ ks_bytes[i];
            }
            off += rem;
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,pclmulqdq,sse4.1,ssse3")]
unsafe fn aes256_gcm_seal_aesni(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    plain: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    use core::arch::x86_64::*;

    let mut rk = aes256_expand_key(key);
    let mut rks = load_aes256_rks(&rk);
    for w in &mut rk {
        unsafe { std::ptr::write_volatile(w, 0) };
    }
    let bswap_mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    let h_raw = aes_enc_one(&rks, _mm_setzero_si128());
    let h_be = _mm_shuffle_epi8(h_raw, bswap_mask);

    let mut j0 = [0u8; 16];
    j0[0..12].copy_from_slice(iv);
    j0[15] = 1;
    let mut ctr1 = j0;
    inc32(&mut ctr1);

    let mut ct = vec![0u8; plain.len()];
    aes256_gctr_aesni(&rks, &ctr1, plain, &mut ct);
    let s = ghash_pclmul(h_be, bswap_mask, aad, &ct);
    let ej0 = aes_enc_one(&rks, _mm_loadu_si128(j0.as_ptr() as *const __m128i));
    let mut tag = [0u8; 16];
    _mm_storeu_si128(tag.as_mut_ptr() as *mut __m128i, _mm_xor_si128(s, ej0));
    for k in &mut rks {
        unsafe { std::ptr::write_volatile(k, _mm_setzero_si128()) };
    }
    (ct, tag)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,pclmulqdq,sse4.1,ssse3")]
unsafe fn aes256_gcm_open_aesni(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, String> {
    use core::arch::x86_64::*;

    let mut rk = aes256_expand_key(key);
    let mut rks = load_aes256_rks(&rk);
    for w in &mut rk {
        unsafe { std::ptr::write_volatile(w, 0) };
    }
    let bswap_mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    let h_raw = aes_enc_one(&rks, _mm_setzero_si128());
    let h_be = _mm_shuffle_epi8(h_raw, bswap_mask);

    let mut j0 = [0u8; 16];
    j0[0..12].copy_from_slice(iv);
    j0[15] = 1;

    let s = ghash_pclmul(h_be, bswap_mask, aad, ct);
    let ej0 = aes_enc_one(&rks, _mm_loadu_si128(j0.as_ptr() as *const __m128i));
    let mut expected_tag = [0u8; 16];
    _mm_storeu_si128(
        expected_tag.as_mut_ptr() as *mut __m128i,
        _mm_xor_si128(s, ej0),
    );
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= expected_tag[i] ^ tag[i];
    }
    if diff != 0 {
        for k in &mut rks {
            unsafe { std::ptr::write_volatile(k, _mm_setzero_si128()) };
        }
        return Err("AES_GCM_AUTH_TAG_FAILED".to_string());
    }

    let mut ctr1 = j0;
    inc32(&mut ctr1);
    let mut plain = vec![0u8; ct.len()];
    aes256_gctr_aesni(&rks, &ctr1, ct, &mut plain);
    for k in &mut rks {
        unsafe { std::ptr::write_volatile(k, _mm_setzero_si128()) };
    }
    Ok(plain)
}

#[inline]
fn has_aesni_pclmul() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        return std::arch::is_x86_feature_detected!("aes")
            && std::arch::is_x86_feature_detected!("pclmulqdq")
            && std::arch::is_x86_feature_detected!("sse4.1")
            && std::arch::is_x86_feature_detected!("ssse3");
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

fn aes256_gcm_seal_scalar(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    plain: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let mut rk = aes256_expand_key(key);
    let h = u128::from_be_bytes(aes256_encrypt_block(&rk, &[0u8; 16]));
    let mut j0 = [0u8; 16];
    j0[0..12].copy_from_slice(iv);
    j0[15] = 1;

    let mut ctr1 = j0;
    inc32(&mut ctr1);
    let ct = aes256_gctr_scalar(&rk, &ctr1, plain);
    let s = ghash_scalar(h, aad, &ct);
    let ej0 = aes256_encrypt_block(&rk, &j0);
    for w in &mut rk {
        unsafe { std::ptr::write_volatile(w, 0) };
    }

    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = s[i] ^ ej0[i];
    }
    (ct, tag)
}

fn aes256_gcm_open_scalar(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, String> {
    let mut rk = aes256_expand_key(key);
    let h = u128::from_be_bytes(aes256_encrypt_block(&rk, &[0u8; 16]));
    let mut j0 = [0u8; 16];
    j0[0..12].copy_from_slice(iv);
    j0[15] = 1;

    let s = ghash_scalar(h, aad, ct);
    let ej0 = aes256_encrypt_block(&rk, &j0);
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= (s[i] ^ ej0[i]) ^ tag[i];
    }
    if diff != 0 {
        for w in &mut rk {
            unsafe { std::ptr::write_volatile(w, 0) };
        }
        return Err("AES_GCM_AUTH_TAG_FAILED".to_string());
    }

    let mut ctr1 = j0;
    inc32(&mut ctr1);
    let plain = aes256_gctr_scalar(&rk, &ctr1, ct);
    for w in &mut rk {
        unsafe { std::ptr::write_volatile(w, 0) };
    }
    Ok(plain)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,pclmulqdq,sse4.1,ssse3")]
#[inline]
unsafe fn ghash_reduce_256(lo: core::arch::x86_64::__m128i, hi: core::arch::x86_64::__m128i) -> core::arch::x86_64::__m128i {
    use core::arch::x86_64::*;

    let c_lo = _mm_srli_epi64::<63>(lo);
    let c_hi = _mm_srli_epi64::<63>(hi);
    let lo_s = _mm_or_si128(_mm_slli_epi64::<1>(lo), _mm_slli_si128::<8>(c_lo));
    let hi_s = _mm_or_si128(
        _mm_slli_epi64::<1>(hi),
        _mm_or_si128(_mm_slli_si128::<8>(c_hi), _mm_srli_si128::<8>(c_lo)),
    );
    let poly = _mm_set_epi64x(0, 0xc200_0000_0000_0000u64 as i64);
    let t1 = _mm_clmulepi64_si128::<0x00>(lo_s, poly);
    let lo1 = _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(lo_s), t1);
    let t2 = _mm_clmulepi64_si128::<0x00>(lo1, poly);
    _mm_xor_si128(hi_s, _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(lo1), t2))
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,pclmulqdq,sse4.1,ssse3")]
unsafe fn ghash_update_chunk_pclmul(
    h1: core::arch::x86_64::__m128i,
    h2: core::arch::x86_64::__m128i,
    h3: core::arch::x86_64::__m128i,
    h4: core::arch::x86_64::__m128i,
    bswap_mask: core::arch::x86_64::__m128i,
    y: &mut core::arch::x86_64::__m128i,
    data: &[u8],
) {
    use core::arch::x86_64::*;

    let mut off = 0usize;
    let ptr = data.as_ptr();
    while off + 64 <= data.len() {
        let p = ptr.add(off);
        let b0 = _mm_xor_si128(_mm_shuffle_epi8(_mm_loadu_si128(p as *const __m128i), bswap_mask), *y);
        let b1 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(16) as *const __m128i), bswap_mask);
        let b2 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(32) as *const __m128i), bswap_mask);
        let b3 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(48) as *const __m128i), bswap_mask);

        let lo0 = _mm_clmulepi64_si128::<0x00>(b0, h4);
        let hi0 = _mm_clmulepi64_si128::<0x11>(b0, h4);
        let m0 = _mm_clmulepi64_si128::<0x00>(
            _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(b0), b0),
            _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(h4), h4),
        );

        let lo1 = _mm_clmulepi64_si128::<0x00>(b1, h3);
        let hi1 = _mm_clmulepi64_si128::<0x11>(b1, h3);
        let m1 = _mm_clmulepi64_si128::<0x00>(
            _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(b1), b1),
            _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(h3), h3),
        );

        let lo2 = _mm_clmulepi64_si128::<0x00>(b2, h2);
        let hi2 = _mm_clmulepi64_si128::<0x11>(b2, h2);
        let m2 = _mm_clmulepi64_si128::<0x00>(
            _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(b2), b2),
            _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(h2), h2),
        );

        let lo3 = _mm_clmulepi64_si128::<0x00>(b3, h1);
        let hi3 = _mm_clmulepi64_si128::<0x11>(b3, h1);
        let m3 = _mm_clmulepi64_si128::<0x00>(
            _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(b3), b3),
            _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(h1), h1),
        );

        let lo_sum = _mm_xor_si128(_mm_xor_si128(lo0, lo1), _mm_xor_si128(lo2, lo3));
        let hi_sum = _mm_xor_si128(_mm_xor_si128(hi0, hi1), _mm_xor_si128(hi2, hi3));
        let mid_sum = _mm_xor_si128(_mm_xor_si128(m0, m1), _mm_xor_si128(m2, m3));
        let mid = _mm_xor_si128(mid_sum, _mm_xor_si128(lo_sum, hi_sum));
        let lo = _mm_xor_si128(lo_sum, _mm_slli_si128::<8>(mid));
        let hi = _mm_xor_si128(hi_sum, _mm_srli_si128::<8>(mid));
        *y = ghash_reduce_256(lo, hi);
        off += 64;
    }
    while off + 16 <= data.len() {
        let blk = _mm_shuffle_epi8(_mm_loadu_si128(ptr.add(off) as *const __m128i), bswap_mask);
        *y = ghash_mul_pclmul(_mm_xor_si128(*y, blk), h1);
        off += 16;
    }
    if off < data.len() {
        let mut last = [0u8; 16];
        let rem = data.len() - off;
        last[..rem].copy_from_slice(&data[off..]);
        let blk = _mm_shuffle_epi8(_mm_loadu_si128(last.as_ptr() as *const __m128i), bswap_mask);
        *y = ghash_mul_pclmul(_mm_xor_si128(*y, blk), h1);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,pclmulqdq,sse4.1,ssse3")]
unsafe fn seal_web_asset_in_place_aesni(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
) -> (String, [u8; 16]) {
    use core::arch::x86_64::*;

    let mut rk = aes256_expand_key(key);
    let mut rks = load_aes256_rks(&rk);
    for w in &mut rk {
        unsafe { std::ptr::write_volatile(w, 0) };
    }

    let bswap_mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    let bswap_ctr32 = _mm_set_epi8(12, 13, 14, 15, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    let one_lane3 = _mm_set_epi32(1, 0, 0, 0);
    let k0 = rks[0];

    let h1 = _mm_shuffle_epi8(aes_enc_one(&rks, _mm_setzero_si128()), bswap_mask);
    let h2 = ghash_mul_pclmul(h1, h1);
    let h3 = ghash_mul_pclmul(h2, h1);
    let h4 = ghash_mul_pclmul(h2, h2);

    let mut y = _mm_setzero_si128();
    ghash_update_chunk_pclmul(h1, h2, h3, h4, bswap_mask, &mut y, aad);

    let mut j0 = [0u8; 16];
    j0[0..12].copy_from_slice(iv);
    j0[15] = 1;
    let ej0 = aes_enc_one(&rks, _mm_loadu_si128(j0.as_ptr() as *const __m128i));

    let mut ctr_bytes = [0u8; 16];
    ctr_bytes[0..12].copy_from_slice(iv);
    ctr_bytes[12..16].copy_from_slice(&2u32.to_le_bytes());
    let mut ctr_le = _mm_loadu_si128(ctr_bytes.as_ptr() as *const __m128i);

    let total_pt_len = data.len();
    let mut sha = crate::Sha256Hasher::new();

    for chunk in data.chunks_mut(32_768) {
        sha.update(chunk);

        let ptr = chunk.as_mut_ptr();
        let clen = chunk.len();
        let mut off = 0usize;
        while off + 128 <= clen {
            let mut b0 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr32), k0);
            ctr_le = _mm_add_epi32(ctr_le, one_lane3);
            let mut b1 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr32), k0);
            ctr_le = _mm_add_epi32(ctr_le, one_lane3);
            let mut b2 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr32), k0);
            ctr_le = _mm_add_epi32(ctr_le, one_lane3);
            let mut b3 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr32), k0);
            ctr_le = _mm_add_epi32(ctr_le, one_lane3);
            let mut b4 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr32), k0);
            ctr_le = _mm_add_epi32(ctr_le, one_lane3);
            let mut b5 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr32), k0);
            ctr_le = _mm_add_epi32(ctr_le, one_lane3);
            let mut b6 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr32), k0);
            ctr_le = _mm_add_epi32(ctr_le, one_lane3);
            let mut b7 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr32), k0);
            ctr_le = _mm_add_epi32(ctr_le, one_lane3);

            for r in 1..14 {
                let kr = rks[r];
                b0 = _mm_aesenc_si128(b0, kr);
                b1 = _mm_aesenc_si128(b1, kr);
                b2 = _mm_aesenc_si128(b2, kr);
                b3 = _mm_aesenc_si128(b3, kr);
                b4 = _mm_aesenc_si128(b4, kr);
                b5 = _mm_aesenc_si128(b5, kr);
                b6 = _mm_aesenc_si128(b6, kr);
                b7 = _mm_aesenc_si128(b7, kr);
            }
            let k14 = rks[14];
            b0 = _mm_aesenclast_si128(b0, k14);
            b1 = _mm_aesenclast_si128(b1, k14);
            b2 = _mm_aesenclast_si128(b2, k14);
            b3 = _mm_aesenclast_si128(b3, k14);
            b4 = _mm_aesenclast_si128(b4, k14);
            b5 = _mm_aesenclast_si128(b5, k14);
            b6 = _mm_aesenclast_si128(b6, k14);
            b7 = _mm_aesenclast_si128(b7, k14);

            let p = ptr.add(off);
            _mm_storeu_si128(p as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p as *const __m128i), b0));
            _mm_storeu_si128(p.add(16) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(16) as *const __m128i), b1));
            _mm_storeu_si128(p.add(32) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(32) as *const __m128i), b2));
            _mm_storeu_si128(p.add(48) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(48) as *const __m128i), b3));
            _mm_storeu_si128(p.add(64) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(64) as *const __m128i), b4));
            _mm_storeu_si128(p.add(80) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(80) as *const __m128i), b5));
            _mm_storeu_si128(p.add(96) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(96) as *const __m128i), b6));
            _mm_storeu_si128(p.add(112) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(112) as *const __m128i), b7));
            off += 128;
        }
        while off < clen {
            let ctr_blk = _mm_shuffle_epi8(ctr_le, bswap_ctr32);
            ctr_le = _mm_add_epi32(ctr_le, one_lane3);
            let ks = aes_enc_one(&rks, ctr_blk);
            let rem = clen - off;
            if rem >= 16 {
                let p = ptr.add(off);
                let v = _mm_xor_si128(_mm_loadu_si128(p as *const __m128i), ks);
                _mm_storeu_si128(p as *mut __m128i, v);
                off += 16;
            } else {
                let mut ks_bytes = [0u8; 16];
                _mm_storeu_si128(ks_bytes.as_mut_ptr() as *mut __m128i, ks);
                for i in 0..rem {
                    *ptr.add(off + i) ^= ks_bytes[i];
                }
                off += rem;
            }
        }

        ghash_update_chunk_pclmul(h1, h2, h3, h4, bswap_mask, &mut y, chunk);
    }

    let plain_sha = crate::hex_encode(&sha.finalize());

    let mut lblk = [0u8; 16];
    lblk[0..8].copy_from_slice(&((aad.len() as u64).wrapping_mul(8)).to_be_bytes());
    lblk[8..16].copy_from_slice(&((total_pt_len as u64).wrapping_mul(8)).to_be_bytes());
    let lref = _mm_shuffle_epi8(_mm_loadu_si128(lblk.as_ptr() as *const __m128i), bswap_mask);
    y = ghash_mul_pclmul(_mm_xor_si128(y, lref), h1);
    let s = _mm_shuffle_epi8(y, bswap_mask);

    let mut tag = [0u8; 16];
    _mm_storeu_si128(tag.as_mut_ptr() as *mut __m128i, _mm_xor_si128(s, ej0));
    for k in &mut rks {
        unsafe { std::ptr::write_volatile(k, _mm_setzero_si128()) };
    }
    (plain_sha, tag)
}

/// Fused L1-cache-resident SHA-256(plaintext) + in-place AES-256-GCM encryption + GHASH tag.
pub fn seal_web_asset_in_place(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
) -> (String, [u8; 16]) {
    #[cfg(target_arch = "x86_64")]
    {
        if has_aesni_pclmul() {
            return unsafe { seal_web_asset_in_place_aesni(key, iv, aad, data) };
        }
    }
    let plain_sha = sha256_hex(data);
    let (mut ct, tag) = aes256_gcm_seal_scalar(key, iv, aad, data);
    data.copy_from_slice(&ct);
    secure_zero(&mut ct);
    (plain_sha, tag)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,pclmulqdq,sse4.1,ssse3")]
unsafe fn aes256_gcm_seal_in_place_aesni(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
) -> [u8; 16] {
    use core::arch::x86_64::*;

    let mut rk = aes256_expand_key(key);
    let mut rks = load_aes256_rks(&rk);
    for w in &mut rk {
        unsafe { std::ptr::write_volatile(w, 0) };
    }

    let bswap_mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    let bswap_ctr32 = _mm_set_epi8(12, 13, 14, 15, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    let one_lane3 = _mm_set_epi32(1, 0, 0, 0);
    let k0 = rks[0];

    let h1 = _mm_shuffle_epi8(aes_enc_one(&rks, _mm_setzero_si128()), bswap_mask);
    let h2 = ghash_mul_pclmul(h1, h1);
    let h3 = ghash_mul_pclmul(h2, h1);
    let h4 = ghash_mul_pclmul(h2, h2);

    let mut y = _mm_setzero_si128();
    ghash_update_chunk_pclmul(h1, h2, h3, h4, bswap_mask, &mut y, aad);

    let mut j0 = [0u8; 16];
    j0[0..12].copy_from_slice(iv);
    j0[15] = 1;
    let ej0 = aes_enc_one(&rks, _mm_loadu_si128(j0.as_ptr() as *const __m128i));

    let mut ctr_bytes = [0u8; 16];
    ctr_bytes[0..12].copy_from_slice(iv);
    ctr_bytes[12..16].copy_from_slice(&2u32.to_le_bytes());
    let mut ctr_le = _mm_loadu_si128(ctr_bytes.as_ptr() as *const __m128i);

    let total_pt_len = data.len();

    for chunk in data.chunks_mut(32_768) {
        let ptr = chunk.as_mut_ptr();
        let clen = chunk.len();
        let mut off = 0usize;
        while off + 128 <= clen {
            let mut b0 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr32), k0);
            ctr_le = _mm_add_epi32(ctr_le, one_lane3);
            let mut b1 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr32), k0);
            ctr_le = _mm_add_epi32(ctr_le, one_lane3);
            let mut b2 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr32), k0);
            ctr_le = _mm_add_epi32(ctr_le, one_lane3);
            let mut b3 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr32), k0);
            ctr_le = _mm_add_epi32(ctr_le, one_lane3);
            let mut b4 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr32), k0);
            ctr_le = _mm_add_epi32(ctr_le, one_lane3);
            let mut b5 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr32), k0);
            ctr_le = _mm_add_epi32(ctr_le, one_lane3);
            let mut b6 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr32), k0);
            ctr_le = _mm_add_epi32(ctr_le, one_lane3);
            let mut b7 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr32), k0);
            ctr_le = _mm_add_epi32(ctr_le, one_lane3);

            for r in 1..14 {
                let kr = rks[r];
                b0 = _mm_aesenc_si128(b0, kr);
                b1 = _mm_aesenc_si128(b1, kr);
                b2 = _mm_aesenc_si128(b2, kr);
                b3 = _mm_aesenc_si128(b3, kr);
                b4 = _mm_aesenc_si128(b4, kr);
                b5 = _mm_aesenc_si128(b5, kr);
                b6 = _mm_aesenc_si128(b6, kr);
                b7 = _mm_aesenc_si128(b7, kr);
            }
            let k14 = rks[14];
            b0 = _mm_aesenclast_si128(b0, k14);
            b1 = _mm_aesenclast_si128(b1, k14);
            b2 = _mm_aesenclast_si128(b2, k14);
            b3 = _mm_aesenclast_si128(b3, k14);
            b4 = _mm_aesenclast_si128(b4, k14);
            b5 = _mm_aesenclast_si128(b5, k14);
            b6 = _mm_aesenclast_si128(b6, k14);
            b7 = _mm_aesenclast_si128(b7, k14);

            let p = ptr.add(off);
            _mm_storeu_si128(p as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p as *const __m128i), b0));
            _mm_storeu_si128(p.add(16) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(16) as *const __m128i), b1));
            _mm_storeu_si128(p.add(32) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(32) as *const __m128i), b2));
            _mm_storeu_si128(p.add(48) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(48) as *const __m128i), b3));
            _mm_storeu_si128(p.add(64) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(64) as *const __m128i), b4));
            _mm_storeu_si128(p.add(80) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(80) as *const __m128i), b5));
            _mm_storeu_si128(p.add(96) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(96) as *const __m128i), b6));
            _mm_storeu_si128(p.add(112) as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(p.add(112) as *const __m128i), b7));
            off += 128;
        }
        while off < clen {
            let ctr_blk = _mm_shuffle_epi8(ctr_le, bswap_ctr32);
            ctr_le = _mm_add_epi32(ctr_le, one_lane3);
            let ks = aes_enc_one(&rks, ctr_blk);
            let rem = clen - off;
            if rem >= 16 {
                let p = ptr.add(off);
                let v = _mm_xor_si128(_mm_loadu_si128(p as *const __m128i), ks);
                _mm_storeu_si128(p as *mut __m128i, v);
                off += 16;
            } else {
                let mut ks_bytes = [0u8; 16];
                _mm_storeu_si128(ks_bytes.as_mut_ptr() as *mut __m128i, ks);
                for i in 0..rem {
                    *ptr.add(off + i) ^= ks_bytes[i];
                }
                off += rem;
            }
        }

        ghash_update_chunk_pclmul(h1, h2, h3, h4, bswap_mask, &mut y, chunk);
    }

    let mut lblk = [0u8; 16];
    lblk[0..8].copy_from_slice(&((aad.len() as u64).wrapping_mul(8)).to_be_bytes());
    lblk[8..16].copy_from_slice(&((total_pt_len as u64).wrapping_mul(8)).to_be_bytes());
    let lref = _mm_shuffle_epi8(_mm_loadu_si128(lblk.as_ptr() as *const __m128i), bswap_mask);
    y = ghash_mul_pclmul(_mm_xor_si128(y, lref), h1);
    let s = _mm_shuffle_epi8(y, bswap_mask);

    let mut tag = [0u8; 16];
    _mm_storeu_si128(tag.as_mut_ptr() as *mut __m128i, _mm_xor_si128(s, ej0));
    for k in &mut rks {
        unsafe { std::ptr::write_volatile(k, _mm_setzero_si128()) };
    }
    tag
}

/// L1-cache-fused in-place AES-256-GCM encryption + GHASH tag without plaintext SHA-256 pass.
pub fn aes256_gcm_seal_in_place(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
) -> [u8; 16] {
    #[cfg(target_arch = "x86_64")]
    {
        if has_aesni_pclmul() {
            return unsafe { aes256_gcm_seal_in_place_aesni(key, iv, aad, data) };
        }
    }
    let (mut ct, tag) = aes256_gcm_seal_scalar(key, iv, aad, data);
    data.copy_from_slice(&ct);
    secure_zero(&mut ct);
    tag
}

pub fn aes256_gcm_seal(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    plain: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    #[cfg(target_arch = "x86_64")]
    {
        if has_aesni_pclmul() {
            return unsafe { aes256_gcm_seal_aesni(key, iv, aad, plain) };
        }
    }
    aes256_gcm_seal_scalar(key, iv, aad, plain)
}

pub fn aes256_gcm_open(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, String> {
    #[cfg(target_arch = "x86_64")]
    {
        if has_aesni_pclmul() {
            return unsafe { aes256_gcm_open_aesni(key, iv, aad, ct, tag) };
        }
    }
    aes256_gcm_open_scalar(key, iv, aad, ct, tag)
}

/* ======================== FIPS 186-4 ECDH P-256 (secp256r1) ======================== */

type Fe = [u64; 4]; // Little-endian 256-bit limbs

const P256_P: Fe = [
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
];

const P256_N: Fe = [
    0xf3b9_cac2_fc63_2551,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
];

const P256_B: Fe = [
    0x3bce_3c3e_27d2_604b,
    0x651d_06b0_cc53_b0f6,
    0xb3eb_bd55_7698_86bc,
    0x5ac6_35d8_aa3a_93e7,
];

const P256_GX: Fe = [
    0xf4a1_3945_d898_c296,
    0x7703_7d81_2deb_33a0,
    0xf8bc_e6e5_63a4_40f2,
    0x6b17_d1f2_e12c_4247,
];

const P256_GY: Fe = [
    0xcbb6_4068_37bf_51f5,
    0x2bce_3357_6b31_5ece,
    0x8ee7_eb4a_7c0f_9e16,
    0x4fe3_42e2_fe1a_7f9b,
];

fn u256_ge(a: &Fe, b: &Fe) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true
}

fn u256_is_zero(a: &Fe) -> bool {
    (a[0] | a[1] | a[2] | a[3]) == 0
}

fn u256_add_raw(a: &Fe, b: &Fe) -> (Fe, u64) {
    let mut r = [0u64; 4];
    let mut c = 0u128;
    for i in 0..4 {
        let sum = (a[i] as u128) + (b[i] as u128) + c;
        r[i] = sum as u64;
        c = sum >> 64;
    }
    (r, c as u64)
}

fn u256_sub_raw(a: &Fe, b: &Fe) -> (Fe, u64) {
    let mut r = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let diff = (a[i] as i128) - (b[i] as i128) - borrow;
        if diff < 0 {
            r[i] = (diff + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            r[i] = diff as u64;
            borrow = 0;
        }
    }
    (r, borrow as u64)
}

fn fp_add(a: &Fe, b: &Fe) -> Fe {
    let (s, c) = u256_add_raw(a, b);
    if c != 0 || u256_ge(&s, &P256_P) {
        u256_sub_raw(&s, &P256_P).0
    } else {
        s
    }
}

fn fp_sub(a: &Fe, b: &Fe) -> Fe {
    let (d, borrow) = u256_sub_raw(a, b);
    if borrow != 0 {
        u256_add_raw(&d, &P256_P).0
    } else {
        d
    }
}

#[inline]
fn fp_mul(a: &Fe, b: &Fe) -> Fe {
    let mut prod = [0u64; 8];
    for i in 0..4 {
        let mut c = 0u128;
        for j in 0..4 {
            let v = (a[i] as u128) * (b[j] as u128) + (prod[i + j] as u128) + c;
            prod[i + j] = v as u64;
            c = v >> 64;
        }
        prod[i + 4] = c as u64;
    }

    // FIPS 186-4 Section D.2.3 Solinas reduction for P-256 = 2^256 - 2^224 + 2^192 + 2^96 - 1
    let mut c = [0i64; 16];
    for i in 0..8 {
        c[i * 2] = (prod[i] & 0xffff_ffff) as i64;
        c[i * 2 + 1] = (prod[i] >> 32) as i64;
    }

    let mut t = [0i64; 8];
    t[0] = c[0] + c[8] + c[9] - c[11] - c[12] - c[13] - c[14];
    t[1] = c[1] + c[9] + c[10] - c[12] - c[13] - c[14] - c[15];
    t[2] = c[2] + c[10] + c[11] - c[13] - c[14] - c[15];
    t[3] = c[3] + 2 * (c[11] + c[12]) + c[13] - c[8] - c[9] - c[15];
    t[4] = c[4] + 2 * (c[12] + c[13]) + c[14] - c[9] - c[10];
    t[5] = c[5] + 2 * (c[13] + c[14]) + c[15] - c[10] - c[11];
    t[6] = c[6] + 3 * c[14] + 2 * c[15] + c[13] - c[8] - c[9];
    t[7] = c[7] + 3 * c[15] + c[8] - c[10] - c[11] - c[12] - c[13];

    let mut carry = 0i64;
    for limb in &mut t {
        let v = *limb + carry;
        *limb = v & 0xffff_ffff;
        carry = v >> 32;
    }
    while carry != 0 {
        let cv = carry;
        carry = 0;
        t[0] += cv;
        t[3] -= cv;
        t[6] -= cv;
        t[7] += cv;
        for limb in &mut t {
            let v = *limb + carry;
            *limb = v & 0xffff_ffff;
            carry = v >> 32;
        }
    }

    let mut r = [
        (t[0] as u64) | ((t[1] as u64) << 32),
        (t[2] as u64) | ((t[3] as u64) << 32),
        (t[4] as u64) | ((t[5] as u64) << 32),
        (t[6] as u64) | ((t[7] as u64) << 32),
    ];
    if u256_ge(&r, &P256_P) {
        r = u256_sub_raw(&r, &P256_P).0;
    }
    r
}

#[inline]
fn fp_sqr(a: &Fe) -> Fe {
    fp_mul(a, a)
}

fn fp_inv(a: &Fe) -> Fe {
    // a^(p - 2) mod p via square-and-multiply from p-2
    let p_minus_2 = u256_sub_raw(&P256_P, &[2, 0, 0, 0]).0;
    let mut res = [1u64, 0, 0, 0];
    for bit in (0..256).rev() {
        res = fp_sqr(&res);
        if ((p_minus_2[bit / 64] >> (bit % 64)) & 1) != 0 {
            res = fp_mul(&res, a);
        }
    }
    res
}

fn fe_from_be32(b: &[u8]) -> Fe {
    let mut f = [0u64; 4];
    for i in 0..4 {
        let off = (3 - i) * 8;
        f[i] = u64::from_be_bytes(b[off..off + 8].try_into().unwrap());
    }
    f
}

fn fe_to_be32(f: &Fe) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        let off = (3 - i) * 8;
        out[off..off + 8].copy_from_slice(&f[i].to_be_bytes());
    }
    out
}

#[derive(Clone, Copy)]
struct JacPoint {
    x: Fe,
    y: Fe,
    z: Fe, // z == 0 encodes point at infinity
}

impl JacPoint {
    const INFINITY: Self = Self {
        x: [0; 4],
        y: [1, 0, 0, 0],
        z: [0; 4],
    };

    fn from_affine(x: Fe, y: Fe) -> Self {
        Self {
            x,
            y,
            z: [1, 0, 0, 0],
        }
    }
}

fn p256_double(p: &JacPoint) -> JacPoint {
    if u256_is_zero(&p.z) || u256_is_zero(&p.y) {
        return JacPoint::INFINITY;
    }
    // P-256 has a = -3: M = 3*(X - Z^2)*(X + Z^2)
    let z2 = fp_sqr(&p.z);
    let x_minus_z2 = fp_sub(&p.x, &z2);
    let x_plus_z2 = fp_add(&p.x, &z2);
    let m1 = fp_mul(&x_minus_z2, &x_plus_z2);
    let m = fp_add(&m1, &fp_add(&m1, &m1));

    let y2 = fp_sqr(&p.y);
    let xy2 = fp_mul(&p.x, &y2);
    let s1 = fp_add(&xy2, &xy2);
    let s = fp_add(&s1, &s1); // 4*X*Y^2

    let y4 = fp_sqr(&y2);
    let y4_2 = fp_add(&y4, &y4);
    let y4_4 = fp_add(&y4_2, &y4_2);
    let u = fp_add(&y4_4, &y4_4); // 8*Y^4

    let m2 = fp_sqr(&m);
    let x3 = fp_sub(&fp_sub(&m2, &s), &s);
    let y3 = fp_sub(&fp_mul(&m, &fp_sub(&s, &x3)), &u);
    let yz = fp_mul(&p.y, &p.z);
    let z3 = fp_add(&yz, &yz);
    JacPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

fn p256_add(p: &JacPoint, q: &JacPoint) -> JacPoint {
    if u256_is_zero(&p.z) {
        return *q;
    }
    if u256_is_zero(&q.z) {
        return *p;
    }
    let z1z1 = fp_sqr(&p.z);
    let z2z2 = fp_sqr(&q.z);
    let u1 = fp_mul(&p.x, &z2z2);
    let u2 = fp_mul(&q.x, &z1z1);
    let s1 = fp_mul(&p.y, &fp_mul(&q.z, &z2z2));
    let s2 = fp_mul(&q.y, &fp_mul(&p.z, &z1z1));

    if u1 == u2 {
        if s1 == s2 {
            return p256_double(p);
        }
        return JacPoint::INFINITY;
    }

    let h = fp_sub(&u2, &u1);
    let r = fp_sub(&s2, &s1);
    let h2 = fp_sqr(&h);
    let h3 = fp_mul(&h, &h2);
    let u1h2 = fp_mul(&u1, &h2);

    let r2 = fp_sqr(&r);
    let x3 = fp_sub(&fp_sub(&r2, &h3), &fp_add(&u1h2, &u1h2));
    let y3 = fp_sub(&fp_mul(&r, &fp_sub(&u1h2, &x3)), &fp_mul(&s1, &h3));
    let z3 = fp_mul(&h, &fp_mul(&p.z, &q.z));
    JacPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

fn p256_add_mixed(p: &JacPoint, qx: &Fe, qy: &Fe) -> JacPoint {
    if u256_is_zero(&p.z) {
        return JacPoint::from_affine(*qx, *qy);
    }
    let z1z1 = fp_sqr(&p.z);
    let u2 = fp_mul(qx, &z1z1);
    let s2 = fp_mul(qy, &fp_mul(&p.z, &z1z1));

    if p.x == u2 {
        if p.y == s2 {
            return p256_double(p);
        }
        return JacPoint::INFINITY;
    }

    let h = fp_sub(&u2, &p.x);
    let r = fp_sub(&s2, &p.y);
    let h2 = fp_sqr(&h);
    let h3 = fp_mul(&h, &h2);
    let u1h2 = fp_mul(&p.x, &h2);

    let r2 = fp_sqr(&r);
    let x3 = fp_sub(&fp_sub(&r2, &h3), &fp_add(&u1h2, &u1h2));
    let y3 = fp_sub(&fp_mul(&r, &fp_sub(&u1h2, &x3)), &fp_mul(&p.y, &h3));
    let z3 = fp_mul(&p.z, &h);
    JacPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

fn p256_batch_to_affine<const N: usize>(pts: &[JacPoint; N]) -> [(Fe, Fe); N] {
    // Montgomery batch inversion: 1 fp_inv across all N non-infinity points.
    let mut prefix = [[1u64, 0, 0, 0]; N];
    let mut acc = [1u64, 0, 0, 0];
    for i in 0..N {
        if !u256_is_zero(&pts[i].z) {
            prefix[i] = acc;
            acc = fp_mul(&acc, &pts[i].z);
        }
    }
    let mut inv_acc = fp_inv(&acc);
    let mut out = [([0u64; 4], [0u64; 4]); N];
    for i in (0..N).rev() {
        if !u256_is_zero(&pts[i].z) {
            let zinv = fp_mul(&inv_acc, &prefix[i]);
            inv_acc = fp_mul(&inv_acc, &pts[i].z);
            let zinv2 = fp_sqr(&zinv);
            let zinv3 = fp_mul(&zinv2, &zinv);
            out[i] = (fp_mul(&pts[i].x, &zinv2), fp_mul(&pts[i].y, &zinv3));
        }
    }
    out
}

fn p256_g_table() -> &'static Vec<[(Fe, Fe); 15]> {
    static G_TABLE: OnceLock<Vec<[(Fe, Fe); 15]>> = OnceLock::new();
    G_TABLE.get_or_init(|| {
        let mut table = Vec::with_capacity(64);
        let mut base = JacPoint::from_affine(P256_GX, P256_GY);
        for _win in 0..64 {
            let mut jac_row = [JacPoint::INFINITY; 15];
            jac_row[0] = base;
            for d in 1..15 {
                jac_row[d] = p256_add(&jac_row[d - 1], &base);
            }
            table.push(p256_batch_to_affine(&jac_row));
            for _ in 0..4 {
                base = p256_double(&base);
            }
        }
        table
    })
}

fn p256_scalar_mul_g(scalar: &Fe) -> JacPoint {
    let table = p256_g_table();
    let mut r = JacPoint::INFINITY;
    for win in 0..64 {
        let limb = win >> 4;
        let shift = (win & 15) * 4;
        let nib = ((scalar[limb] >> shift) & 0xf) as usize;
        if nib != 0 {
            let (qx, qy) = &table[win][nib - 1];
            r = p256_add_mixed(&r, qx, qy);
        }
    }
    r
}

fn p256_scalar_mul(scalar: &Fe, px: &Fe, py: &Fe) -> JacPoint {
    let base = JacPoint::from_affine(*px, *py);
    let mut jac_row = [JacPoint::INFINITY; 15];
    jac_row[0] = base;
    for d in 1..15 {
        jac_row[d] = p256_add_mixed(&jac_row[d - 1], px, py);
    }
    let aff_row = p256_batch_to_affine(&jac_row);

    let mut r = JacPoint::INFINITY;
    for win in (0..64).rev() {
        if !u256_is_zero(&r.z) {
            r = p256_double(&r);
            r = p256_double(&r);
            r = p256_double(&r);
            r = p256_double(&r);
        }
        let limb = win >> 4;
        let shift = (win & 15) * 4;
        let nib = ((scalar[limb] >> shift) & 0xf) as usize;
        if nib != 0 {
            let (qx, qy) = &aff_row[nib - 1];
            r = p256_add_mixed(&r, qx, qy);
        }
    }
    r
}

fn p256_to_affine(p: &JacPoint) -> Result<(Fe, Fe), String> {
    if u256_is_zero(&p.z) {
        return Err("P256_POINT_AT_INFINITY".to_string());
    }
    let zinv = fp_inv(&p.z);
    let zinv2 = fp_sqr(&zinv);
    let zinv3 = fp_mul(&zinv2, &zinv);
    Ok((fp_mul(&p.x, &zinv2), fp_mul(&p.y, &zinv3)))
}

fn parse_valid_scalar(priv_be: &[u8; 32]) -> Result<Fe, String> {
    let k = fe_from_be32(priv_be);
    if u256_is_zero(&k) || u256_ge(&k, &P256_N) {
        return Err("P256_SCALAR_OUT_OF_RANGE".to_string());
    }
    Ok(k)
}

pub fn p256_generate_keypair() -> Result<([u8; 32], [u8; 65]), String> {
    let mut scalar = [0u8; 32];
    loop {
        os_random_bytes(&mut scalar)?;
        if let Ok(pub_bytes) = p256_public_key(&scalar) {
            return Ok((scalar, pub_bytes));
        }
    }
}

pub fn p256_public_key(priv_scalar: &[u8; 32]) -> Result<[u8; 65], String> {
    let k = parse_valid_scalar(priv_scalar)?;
    let q = p256_scalar_mul_g(&k);
    let (ax, ay) = p256_to_affine(&q)?;
    let mut out = [0u8; 65];
    out[0] = 0x04;
    out[1..33].copy_from_slice(&fe_to_be32(&ax));
    out[33..65].copy_from_slice(&fe_to_be32(&ay));
    Ok(out)
}

pub fn p256_validate_public_key(pub_bytes: &[u8]) -> Result<(Fe, Fe), String> {
    if pub_bytes.len() != 65 || pub_bytes[0] != 0x04 {
        return Err("INVALID_CLIENT_PUBLIC_KEY".to_string());
    }
    let x = fe_from_be32(&pub_bytes[1..33]);
    let y = fe_from_be32(&pub_bytes[33..65]);
    if u256_ge(&x, &P256_P) || u256_ge(&y, &P256_P) {
        return Err("INVALID_CLIENT_PUBLIC_KEY".to_string());
    }
    // Check y^2 == x^3 - 3*x + b (mod p)
    let y2 = fp_sqr(&y);
    let x2 = fp_sqr(&x);
    let x3 = fp_mul(&x2, &x);
    let three_x = fp_add(&x, &fp_add(&x, &x));
    let rhs = fp_add(&fp_sub(&x3, &three_x), &P256_B);
    if y2 != rhs {
        return Err("INVALID_CLIENT_PUBLIC_KEY".to_string());
    }
    Ok((x, y))
}

pub fn p256_ecdh_shared_secret(
    priv_scalar: &[u8; 32],
    peer_pub_65: &[u8],
) -> Result<[u8; 32], String> {
    let k = parse_valid_scalar(priv_scalar)?;
    let (px, py) = p256_validate_public_key(peer_pub_65)?;
    let shared = p256_scalar_mul(&k, &px, &py);
    let (sx, _) = p256_to_affine(&shared)?;
    Ok(fe_to_be32(&sx))
}

/* =========================== Website Bundler & Loader =========================== */

fn mime_for_rel(rel: &str) -> &'static str {
    let lower = rel.to_ascii_lowercase();
    if lower.ends_with(".html") || lower.ends_with(".htm") {
        "text/html; charset=utf-8"
    } else if lower.ends_with(".js") || lower.ends_with(".mjs") {
        "application/javascript; charset=utf-8"
    } else if lower.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if lower.ends_with(".json") {
        "application/json; charset=utf-8"
    } else if lower.ends_with(".wasm") {
        "application/wasm"
    } else if lower.ends_with(".glb") {
        "model/gltf-binary"
    } else if lower.ends_with(".svg") {
        "image/svg+xml"
    } else if lower.ends_with(".png") {
        "image/png"
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg"
    } else if lower.ends_with(".webp") {
        "image/webp"
    } else if lower.ends_with(".woff2") {
        "font/woff2"
    } else {
        "application/octet-stream"
    }
}

fn build_bootstrap_html(title: &str) -> String {
    let safe_title = crate::params::html_escape(title);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="vs-ticket" content="__VS_RUNTIME_TICKET__">
<title>{safe_title}</title>
</head>
<body>
<noscript>JavaScript and WebCrypto are required to unlock this site.</noscript>
<div id="vs-boot-status" style="font-family:system-ui,sans-serif;padding:24px;color:#444">Verifying session...</div>
<script src="/__vibeslayer/loader.js"></script>
</body>
</html>
"#
    )
}

fn decode_js_string_literal(inner: &str) -> Option<String> {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(esc) = chars.next() else {
            return None;
        };
        match esc {
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'b' => out.push('\x08'),
            'f' => out.push('\x0c'),
            'v' => out.push('\x0b'),
            '\\' => out.push('\\'),
            '\'' => out.push('\''),
            '"' => out.push('"'),
            '\n' => {}
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
            }
            '0' => {
                if matches!(chars.peek(), Some('0'..='9')) {
                    return None;
                }
                out.push('\0');
            }
            '1'..='7' => return None,
            'x' => {
                let a = chars.next()?;
                let b = chars.next()?;
                let s: String = [a, b].into_iter().collect();
                let v = u8::from_str_radix(&s, 16).ok()?;
                out.push(char::from(v));
            }
            'u' => {
                if chars.peek() == Some(&'{') {
                    chars.next();
                    let mut hex = String::new();
                    loop {
                        let d = chars.next()?;
                        if d == '}' {
                            break;
                        }
                        if hex.len() >= 6 {
                            return None;
                        }
                        hex.push(d);
                    }
                    if hex.is_empty() {
                        return None;
                    }
                    let cp = u32::from_str_radix(&hex, 16).ok()?;
                    if (0xD800..=0xDFFF).contains(&cp) {
                        return None;
                    }
                    out.push(char::from_u32(cp)?);
                } else {
                    let mut hex = String::with_capacity(4);
                    for _ in 0..4 {
                        hex.push(chars.next()?);
                    }
                    let cp = u32::from_str_radix(&hex, 16).ok()?;
                    if (0xD800..=0xDFFF).contains(&cp) {
                        return None;
                    }
                    out.push(char::from_u32(cp)?);
                }
            }
            other => out.push(other),
        }
    }
    Some(out)
}

#[inline]
fn is_js_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b'$' || b >= 0x80
}

#[inline]
fn is_js_ident_part(b: u8) -> bool {
    is_js_ident_start(b) || b.is_ascii_digit()
}

fn next_significant_js_byte(bytes: &[u8], mut i: usize) -> Option<u8> {
    let n = bytes.len();
    while i < n {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b == b'/' && i + 1 < n {
            if bytes[i + 1] == b'/' {
                i += 2;
                while i < n && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            if bytes[i + 1] == b'*' {
                i += 2;
                while i + 1 < n && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(n);
                continue;
            }
        }
        return Some(b);
    }
    None
}

fn regex_allowed_after(prev_tok: &str) -> bool {
    if prev_tok.is_empty() || prev_tok == "ctrl:)" {
        return true;
    }
    if let Some(kw) = prev_tok.strip_prefix("id:") {
        return matches!(
            kw,
            "return"
                | "throw"
                | "case"
                | "delete"
                | "void"
                | "typeof"
                | "yield"
                | "await"
                | "in"
                | "instanceof"
                | "new"
                | "else"
                | "do"
                | "of"
        );
    }
    if let Some(p) = prev_tok.strip_prefix("punct:") {
        return p != ")" && p != "]";
    }
    false
}

/// Masks JavaScript/ES-module single/double-quoted string literals (`len >= min_str_len`)
/// into a deterministic XOR-obfuscated lookup table while stripping comments and
/// preserving directives, import/export specifiers, object keys, regexes, and template literals.
pub fn harden_js_string_literals(src: &str, seed: &[u8; 32]) -> String {
    harden_js_string_literals_min(src, seed, 4)
}

pub(crate) fn harden_js_string_literals_min(
    src: &str,
    seed: &[u8; 32],
    min_str_len: usize,
) -> String {
    harden_js_advanced(
        src,
        seed,
        min_str_len,
        None,
        0,
        crate::params::AntiStealthMode::Off,
    )
}

/// Compact synchronous anti-stealth / anti-CloakBrowser self-defense guard injected into
/// individual hardened Web Component modules (`.js`/`.mjs`) when `--anti-stealth` is enabled.
/// Safe in non-DOM runtimes (guarded by `typeof document !== "undefined"`).
fn build_component_anti_stealth_guard_js(
    mode: crate::params::AntiStealthMode,
    tag: &str,
) -> String {
    if mode == crate::params::AntiStealthMode::Off {
        return String::new();
    }
    let thresh = mode.score_threshold();
    format!(
        r##"(()=>{{if(typeof document==="undefined")return;if(typeof navigator!=="undefined"&&navigator.webdriver)throw new Error("STEALTH_BROWSER_DENIED");let _s_{tag}=0;try{{const c=document.createElement("canvas");c.width=24;c.height=24;const x=c.getContext("2d");if(x){{x.fillStyle="#808080";x.fillRect(0,0,24,24);const d=x.getImageData(0,0,24,24).data,r0=d[0],g0=d[1],b0=d[2];for(let i=4;i<d.length;i+=4){{if(d[i]!==r0||d[i+1]!==g0||d[i+2]!==b0){{_s_{tag}+=2;break;}}}}}}}}catch(_){{}}try{{const c=document.createElement("canvas");c.width=24;c.height=24;const g=c.getContext("webgl2")||c.getContext("webgl");if(g){{g.clearColor(0.5,0.5,0.5,1);g.clear(g.COLOR_BUFFER_BIT);const p=new Uint8Array(24*24*4);g.readPixels(0,0,24,24,g.RGBA,g.UNSIGNED_BYTE,p);const r0=p[0],g0=p[1],b0=p[2];for(let i=4;i<p.length;i+=4){{if(p[i]!==r0||p[i+1]!==g0||p[i+2]!==b0){{_s_{tag}+=2;break;}}}}const ls=g.getExtension("WEBGL_lose_context");if(ls)ls.loseContext();}}}}catch(_){{}}const _rt=document.body||document.documentElement;try{{const dpr=(typeof window!=="undefined"&&window.devicePixelRatio)||1;if(Math.abs(dpr-Math.round(dpr))<1e-6&&_rt){{const dv=document.createElement("div");dv.style.cssText="position:fixed;left:10px;top:20px;width:100px;height:50px;margin:0;padding:0;border:0;visibility:hidden";_rt.appendChild(dv);const r=dv.getBoundingClientRect();dv.remove();if(Math.abs(r.left-10)>1e-3||Math.abs(r.top-20)>1e-3||Math.abs(r.width-100)>1e-3||Math.abs(r.height-50)>1e-3)_s_{tag}+=2;}}}}catch(_){{}}try{{const pl=String((typeof navigator!=="undefined"&&navigator.platform)||""),up=String((typeof navigator!=="undefined"&&navigator.userAgentData&&navigator.userAgentData.platform)||"");if(_rt&&(pl.startsWith("Win")||up==="Windows"||pl==="MacIntel"||up==="macOS")){{const sp=document.createElement("span");sp.textContent="mmmmmmmmmmlliWWWW1234567890";sp.style.cssText="position:fixed;left:-9999px;top:0;font-size:72px;white-space:nowrap;visibility:hidden";_rt.appendChild(sp);const mw=(f)=>{{sp.style.fontFamily=f;return sp.offsetWidth;}};const base=mw("monospace");const ls=(pl.startsWith("Win")||up==="Windows")?['"Segoe UI",monospace','"Tahoma",monospace','"Consolas",monospace','"Calibri",monospace']:['"Helvetica Neue",monospace','"Geneva",monospace','"Menlo",monospace'];let df=0;for(const f of ls){{if(mw(f)!==base)df++;}}sp.remove();if(df===0)_s_{tag}+=2;}}}}catch(_){{}}if(_s_{tag}>={thresh})throw new Error("STEALTH_BROWSER_DENIED");}})();"##
    ) + "\n"
}

/// Generates a deterministic, syntactically valid, unreachable-at-runtime polymorphic JS
/// decoy state-machine block (`bloat_kb * 1024` bytes) to overwhelm static LLM/AI decompilers
/// (~500 tokens/KB -> 96 KB ≈ ~48,000+ LLM tokens per file) while adding ~0 ms execution cost
/// (V8 lazily skips compiling uncalled function bodies!).
fn build_polymorphic_js_decoy_vm(seed: &[u8; 32], tag: &str, bloat_kb: usize) -> String {
    if bloat_kb == 0 {
        return String::new();
    }
    let target_bytes = bloat_kb.min(512) * 1024;
    let mut s0 = u64::from_le_bytes(seed[0..8].try_into().unwrap()) | 1;
    let mut s1 = u64::from_le_bytes(seed[8..16].try_into().unwrap()) | 1;
    let mut next_u32 = || -> u32 {
        s0 ^= s0 << 13;
        s0 ^= s0 >> 7;
        s0 ^= s0 << 17;
        s1 = s1.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((s0 ^ s1) >> 16) as u32
    };

    let mut out = String::with_capacity(target_bytes + 1024);
    use std::fmt::Write as _;
    let _ = writeln!(
        &mut out,
        "\nfunction _vs_vm_{tag}(_k,_s){{let a=(_k[0]^0x{:08x})>>>0,b=(_k[1]^0x{:08x})>>>0,c=(_k[2]^0x{:08x})>>>0,d=(_k[3]^0x{:08x})>>>0,pc=(_s&255);const _r=new Uint32Array(16);while(pc>=0){{switch(pc){{",
        next_u32(),
        next_u32(),
        next_u32(),
        next_u32(),
    );
    let mut st = 0u32;
    while out.len() + 260 < target_bytes {
        let k0 = next_u32();
        let k1 = next_u32();
        let k2 = next_u32();
        let k3 = next_u32();
        let sh0 = (k0 & 15) + 1;
        let sh1 = ((k1 >> 8) & 15) + 1;
        let slot = k2 & 15;
        let nxt = (st.wrapping_add(1 + (k3 & 3))) & 0x7fff;
        let _ = writeln!(
            &mut out,
            "case {st}:a=((a+Math.imul(b^0x{k0:08x},0x{:08x}))>>>0);b=(((b<<{sh0})|(b>>>{}))^(c+0x{k1:08x}))>>>0;c=((c^Math.imul(d|1,0x{k2:08x}))+((a>>>{sh1})^(a<<{})))>>>0;d=(d+a+b^0x{k3:08x})>>>0;_r[{slot}]=(a^b^c^d)>>>0;pc=((_r[{slot}]&1)?{nxt}:-1);break;",
            next_u32() | 1,
            32 - sh0,
            32 - sh1,
        );
        st += 1;
    }
    let _ = writeln!(&mut out, "default:pc=-1;break;}}}}return (a^b^c^d^_r[0])>>>0;}}");
    out
}

pub(crate) fn harden_js_advanced(
    src: &str,
    seed: &[u8; 32],
    min_str_len: usize,
    rt_key_opt: Option<(&[u8; 32], &str)>,
    bloat_kb: usize,
    anti_stealth: crate::params::AntiStealthMode,
) -> String {
    let mut hasher = crate::Sha256Hasher::new();
    hasher.update(b"VSWEB1_JSHARD|");
    hasher.update(seed);
    let mask = hasher.finalize();
    let mut tag = String::with_capacity(6);
    write_hex_bytes(&mask[..3], &mut tag);

    let fn_name = format!("_vsd_{tag}");
    let bytes = src.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(n + 256);
    let mut table: Vec<String> = Vec::new();
    let mut tmpl_stack: Vec<usize> = Vec::new();
    let mut paren_stack: Vec<bool> = Vec::new();
    let mut brace_depth: usize = 0;
    let mut in_template = false;
    let mut prev_tok = String::new();
    let mut i = 0usize;

    while i < n {
        if in_template {
            let b = bytes[i];
            if b == b'\\' {
                let start = i;
                i += 1;
                if i < n {
                    let ch_len = src[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
                    i += ch_len;
                }
                out.push_str(&src[start..i]);
                continue;
            }
            if b == b'`' {
                out.push('`');
                i += 1;
                in_template = false;
                prev_tok = "tmpl".to_string();
                continue;
            }
            if b == b'$' && i + 1 < n && bytes[i + 1] == b'{' {
                out.push_str("${");
                i += 2;
                brace_depth += 1;
                tmpl_stack.push(brace_depth);
                in_template = false;
                prev_tok = "punct:{".to_string();
                continue;
            }
            let ch = src[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }

        let b = bytes[i];

        if b.is_ascii_whitespace() {
            out.push(b as char);
            i += 1;
            continue;
        }

        // Line comments //
        if b == b'/' && i + 1 < n && bytes[i + 1] == b'/' {
            i += 2;
            while i < n && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        // Block comments /* ... */
        if b == b'/' && i + 1 < n && bytes[i + 1] == b'*' {
            i += 2;
            let mut has_nl = false;
            while i + 1 < n && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] == b'\n' {
                    has_nl = true;
                }
                i += 1;
            }
            i = (i + 2).min(n);
            out.push(if has_nl { '\n' } else { ' ' });
            continue;
        }

        // Regex literal /pattern/flags
        if b == b'/' && regex_allowed_after(&prev_tok) {
            let start = i;
            i += 1;
            let mut in_class = false;
            let mut closed = false;
            while i < n {
                let c = bytes[i];
                if c == b'\n' || c == b'\r' {
                    break;
                }
                if c == b'\\' {
                    i += 1;
                    if i < n {
                        let cl = src[i..].chars().next().map(|ch| ch.len_utf8()).unwrap_or(1);
                        i += cl;
                    }
                    continue;
                }
                if c == b'[' {
                    in_class = true;
                    i += 1;
                    continue;
                }
                if c == b']' {
                    in_class = false;
                    i += 1;
                    continue;
                }
                if c == b'/' && !in_class {
                    i += 1;
                    while i < n && bytes[i].is_ascii_alphabetic() {
                        i += 1;
                    }
                    closed = true;
                    break;
                }
                let cl = src[i..].chars().next().map(|ch| ch.len_utf8()).unwrap_or(1);
                i += cl;
            }
            if closed {
                out.push_str(&src[start..i]);
                prev_tok = "regex".to_string();
                continue;
            }
            i = start;
        }

        // Template literal start
        if b == b'`' {
            out.push('`');
            i += 1;
            in_template = true;
            continue;
        }

        // String literal '...' or "..."
        if b == b'\'' || b == b'"' {
            let quote = b;
            let start = i;
            i += 1;
            let mut end_quote = None;
            while i < n {
                let c = bytes[i];
                if c == b'\\' {
                    i += 1;
                    if i < n {
                        if bytes[i] == b'\r' && i + 1 < n && bytes[i + 1] == b'\n' {
                            i += 2;
                        } else {
                            let cl = src[i..].chars().next().map(|ch| ch.len_utf8()).unwrap_or(1);
                            i += cl;
                        }
                    }
                    continue;
                }
                if c == quote {
                    end_quote = Some(i);
                    i += 1;
                    break;
                }
                if c == b'\n' || c == b'\r' {
                    break;
                }
                let cl = src[i..].chars().next().map(|ch| ch.len_utf8()).unwrap_or(1);
                i += cl;
            }

            let Some(eq_idx) = end_quote else {
                out.push_str(&src[start..i]);
                prev_tok = "str".to_string();
                continue;
            };
            let inner = &src[start + 1..eq_idx];
            let next_sig = next_significant_js_byte(bytes, i);
            let is_module_spec = matches!(
                prev_tok.as_str(),
                "id:from" | "id:import" | "id:export" | "id:as"
            );
            let is_obj_key = next_sig == Some(b':')
                && matches!(prev_tok.as_str(), "punct:{" | "punct:,");
            let is_method_or_field = matches!(next_sig, Some(b'(' | b'='))
                && matches!(
                    prev_tok.as_str(),
                    "punct:{"
                        | "punct:,"
                        | "punct:;"
                        | "punct:}"
                        | "punct:*"
                        | "id:get"
                        | "id:set"
                        | "id:static"
                        | "id:async"
                );

            let should_keep_raw = is_module_spec || is_obj_key || is_method_or_field;
            if !should_keep_raw {
                if let Some(decoded) = decode_js_string_literal(inner) {
                    if decoded.len() >= min_str_len.max(2) && decoded != "use strict" && decoded != "use asm" {
                        let idx = table.len();
                        table.push(decoded);
                        if out
                            .as_bytes()
                            .last()
                            .map_or(false, |&lb| is_js_ident_part(lb))
                        {
                            out.push(' ');
                        }
                        use std::fmt::Write as _;
                        let _ = write!(&mut out, "{fn_name}({idx})");
                        prev_tok = "str".to_string();
                        continue;
                    }
                }
            }
            out.push_str(&src[start..i]);
            prev_tok = "str".to_string();
            continue;
        }

        // Braces track template ${...} exit
        if b == b'{' {
            brace_depth += 1;
            out.push('{');
            i += 1;
            prev_tok = "punct:{".to_string();
            continue;
        }
        if b == b'}' {
            out.push('}');
            i += 1;
            if tmpl_stack.last().copied() == Some(brace_depth) {
                tmpl_stack.pop();
                brace_depth = brace_depth.saturating_sub(1);
                in_template = true;
                prev_tok.clear();
            } else {
                brace_depth = brace_depth.saturating_sub(1);
                prev_tok = "punct:}".to_string();
            }
            continue;
        }

        // Identifiers / keywords
        if is_js_ident_start(b) {
            let start = i;
            let cl = src[i..].chars().next().map(|ch| ch.len_utf8()).unwrap_or(1);
            i += cl;
            while i < n && is_js_ident_part(bytes[i]) {
                let cl2 = src[i..].chars().next().map(|ch| ch.len_utf8()).unwrap_or(1);
                i += cl2;
            }
            let word = &src[start..i];
            out.push_str(word);
            prev_tok = format!("id:{word}");
            continue;
        }

        // Numbers
        if b.is_ascii_digit() {
            let start = i;
            i += 1;
            while i < n
                && (bytes[i].is_ascii_alphanumeric()
                    || bytes[i] == b'_'
                    || bytes[i] == b'.'
                    || ((bytes[i] == b'+' || bytes[i] == b'-')
                        && i > 0
                        && (bytes[i - 1] == b'e' || bytes[i - 1] == b'E')))
            {
                i += 1;
            }
            out.push_str(&src[start..i]);
            prev_tok = "num".to_string();
            continue;
        }

        // Parentheses track control-statement headers (if/while/for/with) so regex after ')' works
        if b == b'(' {
            let is_ctrl = matches!(
                prev_tok.as_str(),
                "id:if" | "id:while" | "id:for" | "id:with"
            );
            paren_stack.push(is_ctrl);
            out.push('(');
            prev_tok = "punct:(".to_string();
            i += 1;
            continue;
        }
        if b == b')' {
            let is_ctrl = paren_stack.pop().unwrap_or(false);
            out.push(')');
            prev_tok = if is_ctrl {
                "ctrl:)".to_string()
            } else {
                "punct:)".to_string()
            };
            i += 1;
            continue;
        }

        // Increment/decrement operators affect regex heuristic
        if i + 1 < n && ((b == b'+' && bytes[i + 1] == b'+') || (b == b'-' && bytes[i + 1] == b'-')) {
            out.push(b as char);
            out.push(bytes[i + 1] as char);
            prev_tok = format!("op:{}{}", b as char, bytes[i + 1] as char);
            i += 2;
            continue;
        }

        out.push(b as char);
        prev_tok = format!("punct:{}", b as char);
        i += 1;
    }

    let decoy_tail = build_polymorphic_js_decoy_vm(seed, &tag, bloat_kb);
    let comp_guard = build_component_anti_stealth_guard_js(anti_stealth, &tag);
    if table.is_empty() {
        if comp_guard.is_empty() && decoy_tail.is_empty() {
            return out;
        }
        let trimmed = out.trim_start();
        let lead_ws = out.len() - trimmed.len();
        for dir in ["\"use strict\";", "'use strict';", "\"use strict\"", "'use strict'"] {
            if let Some(after) = trimmed.strip_prefix(dir) {
                let split_at = lead_ws + dir.len();
                let mut combined =
                    String::with_capacity(out.len() + comp_guard.len() + decoy_tail.len() + 2);
                combined.push_str(&out[..split_at]);
                if !dir.ends_with(';') {
                    combined.push(';');
                }
                combined.push('\n');
                combined.push_str(&comp_guard);
                combined.push_str(after);
                combined.push_str(&decoy_tail);
                return combined;
            }
        }
        let mut combined = String::with_capacity(comp_guard.len() + out.len() + decoy_tail.len());
        combined.push_str(&comp_guard);
        combined.push_str(&out);
        combined.push_str(&decoy_tail);
        return combined;
    }

    let eff_mask: [u8; 32] = match rt_key_opt {
        Some((rk, _)) => {
            let mut m = [0u8; 32];
            for idx_m in 0..32 {
                m[idx_m] = mask[idx_m] ^ rk[idx_m];
            }
            m
        }
        None => mask,
    };
    let mask_csv = eff_mask
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let mut rows = Vec::with_capacity(table.len());
    for (idx, s) in table.iter().enumerate() {
        let enc: Vec<String> = s
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(bi, &b)| {
                let pad = mask[(idx * 7 + bi) & 31]
                    ^ (idx as u8).wrapping_mul(37).wrapping_add(bi as u8);
                (b ^ pad).to_string()
            })
            .collect();
        rows.push(format!("[{}]", enc.join(",")));
    }
    let header = match rt_key_opt {
        Some((_, site_id)) => format!(
            "{comp_guard}const _vsm_{tag}=[{mask_csv}],_vst_{tag}=[{}],_vsc_{tag}=new Map(),_vstd_{tag}=new TextDecoder(),{fn_name}=(i)=>{{if(_vsc_{tag}.has(i))return _vsc_{tag}.get(i);const _rk=globalThis[Symbol.for(\"vs_rt_{site_id}\")];if(!_rk||_rk.length!==32)throw new Error(\"VS_RUNTIME_KEY_REQUIRED\");const a=_vst_{tag}[i],u=new Uint8Array(a.length);for(let j=0;j<a.length;j++){{const k=(i*7+j)&31;u[j]=a[j]^(_vsm_{tag}[k]^_rk[k])^((i*37+j)&255);}}const v=_vstd_{tag}.decode(u);_vsc_{tag}.set(i,v);return v;}};\n",
            rows.join(",")
        ),
        None => format!(
            "{comp_guard}const _vsm_{tag}=[{mask_csv}],_vst_{tag}=[{}],_vsc_{tag}=new Map(),_vstd_{tag}=new TextDecoder(),{fn_name}=(i)=>{{if(_vsc_{tag}.has(i))return _vsc_{tag}.get(i);const a=_vst_{tag}[i],u=new Uint8Array(a.length);for(let j=0;j<a.length;j++)u[j]=a[j]^_vsm_{tag}[(i*7+j)&31]^((i*37+j)&255);const v=_vstd_{tag}.decode(u);_vsc_{tag}.set(i,v);return v;}};\n",
            rows.join(",")
        ),
    };

    let trimmed = out.trim_start();
    let lead_ws = out.len() - trimmed.len();
    for dir in ["\"use strict\";", "'use strict';", "\"use strict\"", "'use strict'"] {
        if let Some(after) = trimmed.strip_prefix(dir) {
            let split_at = lead_ws + dir.len();
            let mut combined =
                String::with_capacity(out.len() + header.len() + decoy_tail.len() + 2);
            combined.push_str(&out[..split_at]);
            if !dir.ends_with(';') {
                combined.push(';');
            }
            combined.push('\n');
            combined.push_str(&header);
            combined.push_str(after);
            combined.push_str(&decoy_tail);
            return combined;
        }
    }
    let mut combined = String::with_capacity(header.len() + out.len() + decoy_tail.len());
    combined.push_str(&header);
    combined.push_str(&out);
    combined.push_str(&decoy_tail);
    combined
}

/// Generates a compact, zero-false-positive Tier-4 stealth/anti-detect browser integrity probe
/// + cryptographic SHA-256 attestation helper (`_vsAt(tk, pkh)`).
/// Catches C++-patched anti-detect browsers (e.g. CloakBrowser / fingerprint-noise Chromium forks)
/// via hardware/physics invariants that real browsers never violate:
///   1) 2D Canvas flat solid `#808080` fillRect synthetic pixel noise (+2)
///   2) WebGL `gl.clear(0.5)` flat-fill `readPixels` synthetic noise (+2, optional when `include_webgl`)
///   3) Silent `OfflineAudioContext` (256 zero samples) non-zero synthetic noise (+2)
///   4) Integer-DPR `getBoundingClientRect()` sub-pixel poisoning (+2)
///   5) OS platform vs mandatory system fonts contradiction (Windows/macOS lie) (+2)
///   6) Spoofed D3D11 NVIDIA/RTX renderer lacking `KHR_parallel_shader_compile` (+1)
pub(crate) fn build_tier4_anti_stealth_js(
    mode: crate::params::AntiStealthMode,
    include_webgl: bool,
    fail_msg_expr: &str,
    pfx_expr: &str,
    sha_expr: &str,
) -> String {
    if mode == crate::params::AntiStealthMode::Off {
        return "const _vsAt=async()=>null;".to_string();
    }
    let thresh = mode.score_threshold();
    let gl_probe = if include_webgl {
        r#"try{const c=document.createElement("canvas");c.width=32;c.height=32;const g=c.getContext("webgl2")||c.getContext("webgl");if(g){g.clearColor(0.5,0.5,0.5,1);g.clear(g.COLOR_BUFFER_BIT);const p=new _U8(32*32*4);g.readPixels(0,0,32,32,g.RGBA,g.UNSIGNED_BYTE,p);const r0=p[0],g0=p[1],b0=p[2];for(let i=4;i<p.length;i+=4){if(p[i]!==r0||p[i+1]!==g0||p[i+2]!==b0){sc+=2;fl|=2;break;}}const ex=g.getExtension("WEBGL_debug_renderer_info"),ur=ex?String(g.getParameter(ex.UNMASKED_RENDERER_WEBGL)||""):"";const exs=g.getSupportedExtensions()||[];if((ur.includes("Direct3D11")||ur.includes("D3D11"))&&(ur.includes("NVIDIA")||ur.includes("RTX"))&&!exs.includes("KHR_parallel_shader_compile")&&exs.length<30){sc+=1;fl|=32;}const ls=g.getExtension("WEBGL_lose_context");if(ls)ls.loseContext();}}catch(_){}"#
    } else {
        ""
    };
    format!(
        r##"const _vsAt=async(tk,pkh)=>{{let sc=0,fl=0;try{{const c=document.createElement("canvas");c.width=32;c.height=32;const x=c.getContext("2d");if(x){{x.fillStyle="#808080";x.fillRect(0,0,32,32);const d=x.getImageData(0,0,32,32).data,r0=d[0],g0=d[1],b0=d[2];for(let i=4;i<d.length;i+=4){{if(d[i]!==r0||d[i+1]!==g0||d[i+2]!==b0){{sc+=2;fl|=1;break;}}}}}}}}catch(_){{}}{gl_probe}try{{const OA=globalThis.OfflineAudioContext||globalThis.webkitOfflineAudioContext;if(OA){{const ac=new OA(1,256,44100),ab=ac.createBuffer(1,256,44100),sr=ac.createBufferSource();sr.buffer=ab;sr.connect(ac.destination);sr.start(0);const ch=(await ac.startRendering()).getChannelData(0);for(let i=0;i<ch.length;i++){{if(ch[i]!==0){{sc+=2;fl|=4;break;}}}}}}}}catch(_){{}}try{{const dpr=window.devicePixelRatio||1;if(Math.abs(dpr-Math.round(dpr))<1e-6&&document.body){{const dv=document.createElement("div");dv.style.cssText="position:fixed;left:10px;top:20px;width:100px;height:50px;margin:0;padding:0;border:0;visibility:hidden";document.body.appendChild(dv);const r=dv.getBoundingClientRect();dv.remove();if(Math.abs(r.left-10)>1e-3||Math.abs(r.top-20)>1e-3||Math.abs(r.width-100)>1e-3||Math.abs(r.height-50)>1e-3){{sc+=2;fl|=8;}}}}}}catch(_){{}}try{{const pl=String(navigator.platform||""),up=String((navigator.userAgentData&&navigator.userAgentData.platform)||"");if(document.body&&(pl.startsWith("Win")||up==="Windows"||pl==="MacIntel"||up==="macOS")){{const sp=document.createElement("span");sp.textContent="mmmmmmmmmmlliWWWW1234567890";sp.style.cssText="position:fixed;left:-9999px;top:0;font-size:72px;white-space:nowrap;visibility:hidden";document.body.appendChild(sp);const mw=(f)=>{{sp.style.fontFamily=f;return sp.offsetWidth;}};const base=mw("monospace");const list=(pl.startsWith("Win")||up==="Windows")?['"Segoe UI",monospace','"Tahoma",monospace','"Consolas",monospace','"Calibri",monospace']:['"Helvetica Neue",monospace','"Geneva",monospace','"Menlo",monospace'];let diff=0;for(const f of list){{if(mw(f)!==base)diff++;}}sp.remove();if(diff===0){{sc+=2;fl|=16;}}}}}}catch(_){{}}if(sc>={thresh})_fail({fail_msg_expr});const pl=String(navigator.platform||"");const dg=await _dg({sha_expr},_e.encode({pfx_expr}+tk+"|"+pkh+"|"+sc+"|"+fl+"|"+pl));return{{s:sc,f:fl,p:pl,d:_b2h(dg)}};}};"##
    )
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || h.len() < n.len() {
        return false;
    }
    h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

fn os_family_from_ua(ua: &str) -> Option<&'static str> {
    if contains_ci(ua, "Windows") {
        Some("win")
    } else if contains_ci(ua, "Mac OS X") || contains_ci(ua, "Macintosh") {
        Some("mac")
    } else if contains_ci(ua, "Android") {
        Some("android")
    } else if contains_ci(ua, "Linux") || contains_ci(ua, "X11") {
        Some("linux")
    } else {
        None
    }
}

fn os_family_from_ch_platform(ch_plat: &str) -> Option<&'static str> {
    let clean = ch_plat.trim().trim_matches('"');
    if clean.eq_ignore_ascii_case("Windows") {
        Some("win")
    } else if clean.eq_ignore_ascii_case("macOS") {
        Some("mac")
    } else if clean.eq_ignore_ascii_case("Android") {
        Some("android")
    } else if clean.eq_ignore_ascii_case("Linux") {
        Some("linux")
    } else {
        None
    }
}

fn os_family_from_nav_platform(plat: &str) -> Option<&'static str> {
    if plat.starts_with("Win") {
        Some("win")
    } else if plat.starts_with("Mac") {
        Some("mac")
    } else if plat.starts_with("Linux") || plat.starts_with("X11") {
        Some("linux")
    } else {
        None
    }
}

/// Server-side Tier-4 anti-stealth / anti-automation verifier shared across `serve`,
/// `serve-3d --mode gpu`, and `serve-3d --mode stream`.
pub(crate) fn verify_server_anti_stealth(
    mode: crate::params::AntiStealthMode,
    req: &ParsedRequest,
    json: &JsonVal,
    ticket: &str,
    client_pub_hex: &str,
) -> Result<(), &'static str> {
    if mode == crate::params::AntiStealthMode::Off {
        return Ok(());
    }

    // 1. Cross-check HTTP User-Agent vs Sec-CH-UA-Platform consistency
    if let (Some(ua), Some(chp)) = (req.user_agent.as_deref(), req.sec_ch_ua_platform.as_deref()) {
        if let (Some(f_ua), Some(f_ch)) = (os_family_from_ua(ua), os_family_from_ch_platform(chp)) {
            if f_ua != f_ch {
                return Err("STEALTH_BROWSER_DENIED");
            }
        }
    }

    // 2. Strict mode blocks headless/automation User-Agent & Sec-CH-UA headers outright
    if mode == crate::params::AntiStealthMode::Strict {
        for hdr in [req.user_agent.as_deref(), req.sec_ch_ua.as_deref()]
            .into_iter()
            .flatten()
        {
            for marker in [
                "HeadlessChrome",
                "Playwright",
                "Puppeteer",
                "PhantomJS",
                "Selenium",
                "WebDriver",
            ] {
                if contains_ci(hdr, marker) {
                    return Err("AUTOMATION_DENIED");
                }
            }
        }
    }

    // 3. Verify cryptographic Tier-4 attestation payload (`attest`)
    let Some(att) = json.get("attest") else {
        return if mode == crate::params::AntiStealthMode::Strict {
            Err("STEALTH_ATTEST_REQUIRED")
        } else {
            Ok(())
        };
    };

    let s = match att.get("s") {
        Some(JsonVal::Int(n)) if *n >= 0 => *n as u32,
        Some(JsonVal::Num(n)) if *n >= 0.0 && n.is_finite() => *n as u32,
        _ => return Err("STEALTH_ATTEST_INVALID"),
    };
    let f = match att.get("f") {
        Some(JsonVal::Int(n)) if *n >= 0 => *n as u32,
        Some(JsonVal::Num(n)) if *n >= 0.0 && n.is_finite() => *n as u32,
        _ => return Err("STEALTH_ATTEST_INVALID"),
    };
    let plat = att.get("p").and_then(|v| v.as_str()).unwrap_or("");
    let digest = att.get("d").and_then(|v| v.as_str()).unwrap_or("");
    if digest.len() != 64 {
        return Err("STEALTH_ATTEST_INVALID");
    }

    if s >= mode.score_threshold() {
        return Err("STEALTH_BROWSER_DENIED");
    }

    let expected_msg = format!("VS_ATTEST_V1|{ticket}|{client_pub_hex}|{s}|{f}|{plat}");
    let expected_hex = crate::hex_encode(&crate::sha256(expected_msg.as_bytes()));
    if !ct_str_eq(digest.as_bytes(), expected_hex.as_bytes()) {
        return Err("STEALTH_ATTEST_INVALID");
    }

    // Cross-check attested JS `navigator.platform` against HTTP headers
    if let Some(f_js) = os_family_from_nav_platform(plat) {
        if let Some(ua) = req.user_agent.as_deref() {
            if let Some(f_ua) = os_family_from_ua(ua) {
                if f_ua != "android" && f_js != f_ua {
                    return Err("STEALTH_BROWSER_DENIED");
                }
            }
        }
        if let Some(chp) = req.sec_ch_ua_platform.as_deref() {
            if let Some(f_ch) = os_family_from_ch_platform(chp) {
                if f_ch != "android" && f_js != f_ch {
                    return Err("STEALTH_BROWSER_DENIED");
                }
            }
        }
    }

    Ok(())
}

fn build_hardened_browser_loader_js(
    site_id: &str,
    anti_hook: bool,
    anti_cdp: bool,
    anti_stealth: crate::params::AntiStealthMode,
) -> String {
    let mut hasher = crate::Sha256Hasher::new();
    hasher.update(b"VS_LOADER_MASK_V2|");
    hasher.update(site_id.as_bytes());
    let mask = hasher.finalize();

    let table: &[&str] = &[
        "vs-boot-status",                    // 0
        "Access denied: ",                   // 1
        "WebCrypto unavailable",             // 2
        "meta[name=\"vs-ticket\"]",          // 3
        "content",                           // 4
        "__VS_RUNTIME_TICKET__",             // 5
        "Missing session ticket",            // 6
        "ECDH",                              // 7
        "P-256",                             // 8
        "deriveBits",                        // 9
        "raw",                               // 10
        "/__vibeslayer/lease",               // 11
        "POST",                              // 12
        "Content-Type",                      // 13
        "application/json",                  // 14
        "LEASE_DENIED",                      // 15
        "HKDF",                              // 16
        "deriveKey",                         // 17
        "VSWEB1_WRAP|",                      // 18
        "SHA-256",                           // 19
        "AES-GCM",                           // 20
        "unwrapKey",                         // 21
        "decrypt",                           // 22
        "VSWEB1|__manifest__",               // 23
        "Missing site manifest",             // 24
        "VSWEB1|",                           // 25
        "application/octet-stream",          // 26
        "index.html",                        // 27
        "text/html",                         // 28
        "link[href], img[src], script[src]", // 29
        "iframe",                            // 30
        "[native code]",                     // 31
        "INTEGRITY_TAMPERED",                // 32
        "clientPublicKeyHex",                // 33
        "ticket",                            // 34
        "serverPublicKeyHex",                // 35
        "origin",                            // 36
        "leaseId",                           // 37
        "wrappedKeyHex",                     // 38
        "wrapIvHex",                         // 39
        "manifestIvHex",                     // 40
        "sealedManifestHex",                 // 41
        "files",                             // 42
        "vsweb",                             // 43
        "mime",                              // 44
        "entry",                             // 45
        "ok",                                // 46
        "error",                             // 47
        "text/javascript",                   // 48
        "application/javascript",            // 49
        "module",                            // 50
        "AUTOMATION_DENIED",                 // 51
        "rtKeyHex",                          // 52
        "vs_rt_",                            // 53
        "siteId",                            // 54
        "STEALTH_BROWSER_DENIED",            // 55
        "VS_ATTEST_V1|",                     // 56
        "attest",                            // 57
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
    let chk_block = if anti_hook {
        r#"_chk(globalThis.fetch);_chk(_sb.generateKey);_chk(_sb.exportKey);_chk(_sb.importKey);_chk(_sb.deriveBits);_chk(_sb.deriveKey);_chk(_sb.unwrapKey);_chk(_sb.decrypt);_chk(_sb.digest);if(globalThis.console&&console.debug)_chk(console.debug);if(globalThis.Response&&Response.prototype){_chk(Response.prototype.text);_chk(Response.prototype.arrayBuffer);}"#
    } else {
        ""
    };
    let anti_cdp_block = if anti_cdp {
        r#"if(navigator&&navigator.webdriver)_fail(_s(51));let _cd=false;try{const _op=Error.prepareStackTrace;Error.prepareStackTrace=()=>{_cd=true;return "";};console.debug(new Error());if(_op===undefined)delete Error.prepareStackTrace;else Error.prepareStackTrace=_op;}catch(_){}if(_cd)_fail(_s(51));"#
    } else {
        ""
    };
    let anti_stealth_block =
        build_tier4_anti_stealth_js(anti_stealth, true, "_s(55)", "_s(56)", "_s(19)");

    format!(
        r#""use strict";(async()=>{{const _cs=document.currentScript;if(_cs)_cs.remove();const _m=[{mask_csv}],_t={table_js};let _fnStr=Function.prototype.toString,_JP=JSON,_TD=TextDecoder,_TE=TextEncoder,_U8=Uint8Array,_Mp=Map;try{{const _fr=document.createElement("iframe");_fr.style.display="none";const _rt=document.documentElement||document.body;if(_rt){{_rt.appendChild(_fr);const _rw=_fr.contentWindow;if(_rw&&_rw.Function&&_rw.JSON){{_fnStr=_rw.Function.prototype.toString;_JP=_rw.JSON;_TD=_rw.TextDecoder;_TE=_rw.TextEncoder;_U8=_rw.Uint8Array;_Mp=_rw.Map;}}_fr.remove();}}}}catch(_){{}}const _d=new _TD(),_e=new _TE(),_c=new _Mp(),_s=(i)=>{{if(_c.has(i))return _c.get(i);const a=_t[i],u=new _U8(a.length);for(let j=0;j<a.length;j++)u[j]=a[j]^_m[(i*7+j)&31]^((i*37+j)&255);const v=_d.decode(u);_c.set(i,v);return v;}};const _st=document.getElementById(_s(0)),_fail=(m)=>{{if(_st)_st.textContent=_s(1)+m;throw new Error(m);}},_chk=(fn)=>{{if(typeof fn!=="function"||!_fnStr.call(fn).includes(_s(31)))_fail(_s(32));}},_h2b=(h)=>{{const o=new _U8(h.length>>>1);for(let i=0;i<o.length;i++)o[i]=parseInt(h.slice(i*2,i*2+2),16);return o;}},_b2h=(b)=>{{const u=new _U8(b);let r="";for(let i=0;i<u.length;i++)r+=u[i].toString(16).padStart(2,"0");return r;}};const _gc=globalThis.crypto,_sb=_gc&&_gc.subtle;if(!_sb)_fail(_s(2));{chk_block}{anti_cdp_block}const _gk=_sb.generateKey.bind(_sb),_ek=_sb.exportKey.bind(_sb),_ik=_sb.importKey.bind(_sb),_db=_sb.deriveBits.bind(_sb),_dk=_sb.deriveKey.bind(_sb),_uk=_sb.unwrapKey.bind(_sb),_dc=_sb.decrypt.bind(_sb),_dg=_sb.digest.bind(_sb),_nf=globalThis.fetch.bind(globalThis),_Bl=globalThis.Blob,_cu=URL.createObjectURL.bind(URL),_ru=URL.revokeObjectURL.bind(URL),_DP=DOMParser;{anti_stealth_block}const _tm=document.querySelector(_s(3)),_tk=_tm?_tm.getAttribute(_s(4)):"";if(_tm)_tm.remove();if(!_tk||_tk===_s(5))_fail(_s(6));const _kp=await _gk({{name:_s(7),namedCurve:_s(8)}},false,[_s(9)]),_cp=await _ek(_s(10),_kp.publicKey),_cph=_b2h(_cp),_at=await _vsAt(_tk,_cph),_lb={{[_s(33)]:_cph,[_s(34)]:_tk}};if(_at)_lb[_s(57)]=_at;const _lr=await _nf(_s(11),{{method:_s(12),headers:{{[_s(13)]:_s(14)}},body:_JP.stringify(_lb)}}),_ls=_JP.parse(await _lr.text());if(!_lr.ok||!_ls[_s(46)])_fail(_ls[_s(47)]||_s(15));const _sp=await _ik(_s(10),_h2b(_ls[_s(35)]),{{name:_s(7),namedCurve:_s(8)}},false,[]),_sb2=await _db({{name:_s(7),public:_sp}},_kp.privateKey,256),_hb=await _ik(_s(10),_sb2,_s(16),false,[_s(17)]);new _U8(_sb2).fill(0);const _wi=_e.encode(_s(18)+_ls[_s(36)]),_wk=await _dk({{name:_s(16),hash:_s(19),salt:_e.encode(_ls[_s(37)]),info:_wi}},_hb,{{name:_s(20),length:256}},false,[_s(21)]),_ck=await _uk(_s(10),_h2b(_ls[_s(38)]),_wk,{{name:_s(20),iv:_h2b(_ls[_s(39)]),additionalData:_wi,tagLength:128}},{{name:_s(20),length:256}},false,[_s(22)]);if(!_ls[_s(40)]||!_ls[_s(41)])_fail(_s(24));const _mab=await _dc({{name:_s(20),iv:_h2b(_ls[_s(40)]),additionalData:_e.encode(_s(23)),tagLength:128}},_ck,_h2b(_ls[_s(41)])),_mu=new _U8(_mab),_mf=_JP.parse(_d.decode(_mu)),_fl=_mf[_s(42)]||{{}};_mu.fill(0);if(_mf[_s(52)]){{const _rkb=_h2b(_mf[_s(52)]),_rsy=Symbol.for(_s(53)+(_ls[_s(54)]||""));Object.defineProperty(globalThis,_rsy,{{value:_rkb,configurable:true,enumerable:false,writable:false}});window.addEventListener("pagehide",()=>{{try{{_rkb.fill(0);delete globalThis[_rsy];}}catch(_){{}}}},{{once:true}});}}async function _da(rp){{const cl=rp.replace(/^\/+/,""),mt=_fl[cl];if(!mt)return null;const r=await _nf("/"+mt[_s(43)]);if(!r.ok)_fail(cl);const rw=new _U8(await r.arrayBuffer()),ab=await _dc({{name:_s(20),iv:rw.slice(0,12),additionalData:_e.encode(_s(25)+cl),tagLength:128}},_ck,rw.slice(12));rw.fill(0);return{{bytes:new _U8(ab),mime:mt[_s(44)]||_s(26)}};}}window.fetch=async function(inp,ini){{const us=typeof inp==="string"?inp:inp&&inp.url?inp.url:"";try{{const u=new URL(us,window.location.origin);if(u.origin===window.location.origin){{const k=u.pathname.replace(/^\/+/,"");if(_fl[k]){{const a=await _da(k);return new Response(a.bytes,{{status:200,headers:{{[_s(13)]:a.mime}}}});}}}}}}catch(_){{}}return _nf(inp,ini);}};const _eh=await _da(_mf[_s(45)]||_s(27));if(!_eh)_fail(_s(27));const _ehStr=_d.decode(_eh.bytes);_eh.bytes.fill(0);const _ps=new _DP().parseFromString(_ehStr,_s(28)),_bu=new Set();for(const el of _ps.querySelectorAll(_s(29))){{const at=el.hasAttribute("src")?"src":"href",vl=el.getAttribute(at);if(!vl||/^(https?:|data:|blob:|\/__vibeslayer\/)/i.test(vl))continue;const rl=vl.replace(/^\.\//,"").replace(/^\/+/,"");if(!_fl[rl])continue;const a=await _da(rl),u=_cu(new _Bl([a.bytes],{{type:a.mime}}));a.bytes.fill(0);_bu.add(u);el.setAttribute(at,u);if(el.tagName!=="SCRIPT"){{el.addEventListener("load",()=>_ru(u),{{once:true}});el.addEventListener("error",()=>_ru(u),{{once:true}});}}}}document.title=_ps.title||document.title;const _sr=[];for(const sc of _ps.querySelectorAll("script")){{_sr.push({{src:sc.getAttribute("src"),type:sc.getAttribute("type"),text:sc.textContent}});sc.remove();}}document.head.replaceChildren(...Array.from(_ps.head.children).map((n)=>document.importNode(n,true)));document.body.replaceChildren(...Array.from(_ps.body.children).map((n)=>document.importNode(n,true)));for(const sc of _sr){{const nd=document.createElement("script");if(sc.type)nd.type=sc.type;if(sc.src){{nd.src=sc.src;if(_bu.has(sc.src)){{const u=sc.src;nd.addEventListener("load",()=>{{_ru(u);nd.remove();}},{{once:true}});nd.addEventListener("error",()=>{{_ru(u);nd.remove();}},{{once:true}});}}else{{nd.addEventListener("load",()=>nd.remove(),{{once:true}});nd.addEventListener("error",()=>nd.remove(),{{once:true}});}}}}else if(!sc.type||sc.type===_s(48)||sc.type===_s(49)||sc.type===_s(50)){{const u=_cu(new _Bl([sc.text],{{type:_s(49)}}));nd.src=u;nd.addEventListener("load",()=>{{_ru(u);nd.remove();}},{{once:true}});nd.addEventListener("error",()=>{{_ru(u);nd.remove();}},{{once:true}});}}else{{nd.textContent=sc.text;}}document.body.appendChild(nd);}}}})();
"#
    )
}

pub fn protect_website(
    site_dir: &Path,
    out_dir_opt: Option<&Path>,
    allowed_origin: Option<&str>,
    keys_opt: Option<&Path>,
    reg_opt: Option<&Path>,
    no_gitignore: bool,
) -> Result<JsonVal, String> {
    let params = crate::params::WebsiteBuildParams::from_preset(crate::params::SecurityPreset::Balanced);
    protect_website_with_params(
        site_dir,
        out_dir_opt,
        allowed_origin,
        keys_opt,
        reg_opt,
        no_gitignore,
        &params,
    )
}

pub fn protect_website_with_options(
    site_dir: &Path,
    out_dir_opt: Option<&Path>,
    allowed_origin: Option<&str>,
    keys_opt: Option<&Path>,
    reg_opt: Option<&Path>,
    no_gitignore: bool,
    harden_js: bool,
) -> Result<JsonVal, String> {
    let mut params =
        crate::params::WebsiteBuildParams::from_preset(crate::params::SecurityPreset::Balanced);
    params.harden_js = harden_js;
    protect_website_with_params(
        site_dir,
        out_dir_opt,
        allowed_origin,
        keys_opt,
        reg_opt,
        no_gitignore,
        &params,
    )
}

pub fn protect_website_with_params(
    site_dir: &Path,
    out_dir_opt: Option<&Path>,
    allowed_origin: Option<&str>,
    keys_opt: Option<&Path>,
    reg_opt: Option<&Path>,
    no_gitignore: bool,
    params: &crate::params::WebsiteBuildParams,
) -> Result<JsonVal, String> {
    params.validate()?;
    let harden_js = params.harden_js;
    let min_str_len = params.min_str_len;
    let abs_in = fs::canonicalize(site_dir)
        .map_err(|e| format!("Website directory not accessible ({}): {e}", site_dir.display()))?;
    if !abs_in.is_dir() {
        return Err(format!("Expected a directory for website mode: {}", abs_in.display()));
    }
    if !abs_in.join("index.html").is_file() {
        return Err(format!(
            "Website folder must contain an index.html file: {}",
            abs_in.display()
        ));
    }

    let out_dir = match out_dir_opt {
        Some(p) => {
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                std::env::current_dir().map_err(|e| e.to_string())?.join(p)
            }
        }
        None => PathBuf::from(format!("{}-web-protected", abs_in.display())),
    };
    if out_dir == abs_in {
        return Err("Output directory must differ from website input directory.".to_string());
    }
    let assets_dir = out_dir.join("assets");
    fs::create_dir_all(&assets_dir).map_err(|e| e.to_string())?;
    let abs_out = fs::canonicalize(&out_dir).map_err(|e| e.to_string())?;

    let walked = walk_repo_files(&abs_in, &[abs_out.clone()])?;

    let keys_path = resolve_default_keys_path(&abs_in, keys_opt);
    let mut vault = load_or_create_vault(&keys_path, Some(&abs_in), true, no_gitignore)?;
    let master_hex = vault
        .get("masterKeyHex")
        .and_then(|v| v.as_str())
        .ok_or("VAULT_MISSING_MASTER_KEY")?
        .to_string();
    let mut master_key = parse_key_hex_32(&master_hex)?;

    let site_id = sha256_hex(abs_in.to_string_lossy().as_bytes())[..16].to_string();
    let mut site_key = hkdf_sha256_32(&master_key, site_id.as_bytes(), b"VSWEB1_SITE_KEY");
    let mut rt_key = hkdf_sha256_32(&site_key, site_id.as_bytes(), b"VSWEB1_RTKEY_V1");
    let js_bloat_kb = params.js_bloat_kb;
    let anti_stealth = params.anti_stealth;
    secure_zero(&mut master_key);

    let items: Vec<(PathBuf, String)> = walked
        .into_iter()
        .filter(|(_, rel, _)| {
            rel != "vibeslayer.web.json" && rel != "vibe-slayer-loader.js" && rel != ".gitignore"
        })
        .map(|(full, rel, _)| (full, rel))
        .collect();

    let total_items = items.len();
    let num_threads = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(16)
        .min(total_items.max(1));
    let next_idx = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<Result<(String, JsonVal), String>>>> =
        (0..total_items).map(|_| Mutex::new(None)).collect();

    thread::scope(|s| {
        for _ in 0..num_threads {
            s.spawn(|| {
                loop {
                    let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                    if idx >= total_items {
                        break;
                    }
                    let (full_path, rel_path) = &items[idx];
                    let res = (|| -> Result<(String, JsonVal), String> {
                        let meta_len = fs::metadata(full_path)
                            .map(|m| m.len() as usize)
                            .unwrap_or(0);
                        let mut iv = [0u8; 12];
                        os_random_bytes(&mut iv)?;
                        let is_js = harden_js && {
                            let low = rel_path.to_ascii_lowercase();
                            low.ends_with(".js") || low.ends_with(".mjs")
                        };
                        let mut blob;
                        if is_js {
                            let raw_bytes = fs::read(full_path).map_err(|e| e.to_string())?;
                            let hardened_opt = std::str::from_utf8(&raw_bytes).ok().map(|s| {
                                let seed = hkdf_sha256_32(
                                    &site_key,
                                    rel_path.as_bytes(),
                                    b"VSWEB1_JSHARDEN",
                                );
                                harden_js_advanced(
                                    s,
                                    &seed,
                                    min_str_len,
                                    Some((&rt_key, site_id.as_str())),
                                    js_bloat_kb,
                                    anti_stealth,
                                )
                            });
                            let plain_slice: &[u8] = match hardened_opt {
                                Some(ref h) => h.as_bytes(),
                                None => &raw_bytes,
                            };
                            blob = Vec::with_capacity(
                                12usize.saturating_add(plain_slice.len()).saturating_add(16),
                            );
                            blob.extend_from_slice(&iv);
                            blob.extend_from_slice(plain_slice);
                        } else {
                            blob = Vec::with_capacity(
                                12usize.saturating_add(meta_len).saturating_add(16 + 1),
                            );
                            blob.extend_from_slice(&iv);
                            let mut file = fs::File::open(full_path).map_err(|e| e.to_string())?;
                            file.read_to_end(&mut blob).map_err(|e| e.to_string())?;
                        }
                        let plain_len = blob.len() - 12;
                        let aad = format!("VSWEB1|{rel_path}");
                        let tag = aes256_gcm_seal_in_place(
                            &site_key,
                            &iv,
                            aad.as_bytes(),
                            &mut blob[12..12 + plain_len],
                        );
                        blob.extend_from_slice(&tag);

                        let blob_name =
                            format!("{}.vsweb", &sha256_hex(rel_path.as_bytes())[..16]);
                        fs::write(assets_dir.join(&blob_name), &blob)
                            .map_err(|e| e.to_string())?;

                        Ok((
                            rel_path.clone(),
                            JsonVal::obj(vec![
                                ("vsweb", JsonVal::Str(format!("assets/{blob_name}"))),
                                ("mime", JsonVal::Str(mime_for_rel(rel_path).to_string())),
                                ("plainBytes", JsonVal::Int(plain_len as i64)),
                            ]),
                        ))
                    })();
                    *slots[idx].lock().unwrap() = Some(res);
                }
            });
        }
    });
    secure_zero(&mut site_key);
    secure_zero(&mut rt_key);

    let mut file_map = Vec::with_capacity(total_items);
    for slot in &slots {
        let entry = slot.lock().unwrap().take().unwrap()?;
        file_map.push(entry);
    }
    let sealed_count: usize = file_map.len();

    let manifest = JsonVal::obj(vec![
        ("version", JsonVal::Str("1.0.0-beta.3".to_string())),
        ("mode", JsonVal::Str("website-runtime".to_string())),
        ("siteId", JsonVal::Str(site_id.clone())),
        ("entry", JsonVal::Str("index.html".to_string())),
        (
            "allowedOrigin",
            match allowed_origin {
                Some(o) => JsonVal::Str(o.to_string()),
                None => JsonVal::Null,
            },
        ),
        ("files", JsonVal::Obj(file_map)),
    ]);
    let manifest_path = abs_out.join("vibeslayer.web.json");
    let manifest_json = to_json_pretty(&manifest);
    fs::write(&manifest_path, manifest_json.as_bytes()).map_err(|e| e.to_string())?;
    let manifest_sha = sha256_hex(manifest_json.as_bytes());

    fs::write(abs_out.join("index.html"), build_bootstrap_html(&params.title).as_bytes())
        .map_err(|e| e.to_string())?;
    fs::write(
        abs_out.join("vibe-slayer-loader.js"),
        build_hardened_browser_loader_js(&site_id, params.anti_hook, params.anti_cdp, params.anti_stealth).as_bytes(),
    )
    .map_err(|e| e.to_string())?;

    let (reg_path, mut reg_data) = {
        let rp = crate::auto_cli::resolve_registry_path(reg_opt);
        let rd = crate::auto_cli::load_workspace_registry(&rp);
        (rp, rd)
    };
    let art_meta = JsonVal::obj(vec![
        ("engine", JsonVal::Str("website-runtime".to_string())),
        ("domain", JsonVal::Str("web".to_string())),
        ("assetId", JsonVal::Str(site_id.clone())),
        ("absOutPath", JsonVal::Str(abs_out.to_string_lossy().to_string())),
        ("outputSha256", JsonVal::Str(manifest_sha)),
        ("originalName", JsonVal::Str(abs_in.file_name().unwrap_or_default().to_string_lossy().to_string())),
        ("originalSha256", JsonVal::Str(String::new())),
        ("standalone", JsonVal::Bool(false)),
    ]);
    record_artifact(&mut vault, &keys_path, &reg_path, &mut reg_data, art_meta)?;

    Ok(JsonVal::obj(vec![
        ("ok", JsonVal::Bool(true)),
        ("mode", JsonVal::Str("website".to_string())),
        ("inputDir", JsonVal::Str(abs_in.to_string_lossy().to_string())),
        ("outputDir", JsonVal::Str(abs_out.to_string_lossy().to_string())),
        ("siteId", JsonVal::Str(site_id)),
        ("sealedFiles", JsonVal::Int(sealed_count as i64)),
        ("manifestPath", JsonVal::Str(manifest_path.to_string_lossy().to_string())),
        ("keysFile", JsonVal::Str(keys_path.to_string_lossy().to_string())),
        (
            "allowedOrigin",
            match allowed_origin {
                Some(o) => JsonVal::Str(o.to_string()),
                None => JsonVal::Null,
            },
        ),
        ("params", params.to_json()),
    ]))
}

/* ======================== Live Zero-Node HTTP/1.1 Runtime Server ======================== */

const GUARD_SHARDS: usize = 16;

struct LeaseGuardShard {
    used_tickets: HashMap<String, u64>,
    ip_hits: HashMap<IpAddr, VecDeque<u64>>,
    ops: usize,
}

impl LeaseGuardShard {
    fn new() -> Self {
        Self {
            used_tickets: HashMap::new(),
            ip_hits: HashMap::new(),
            ops: 0,
        }
    }
}

pub(crate) struct HttpLeaseGuard {
    shards: [Mutex<LeaseGuardShard>; GUARD_SHARDS],
    max_per_min: usize,
}

impl HttpLeaseGuard {
    pub(crate) fn new(max_per_min: usize) -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(LeaseGuardShard::new())),
            max_per_min: max_per_min.max(1),
        }
    }

    pub(crate) fn verify_and_consume_ticket_ttl(
        &self,
        ticket_secret: &[u8; 32],
        ticket: &str,
        ip: IpAddr,
        ttl_secs: u64,
    ) -> Result<(), String> {
        use std::fmt::Write;
        let (nonce_hex, rest) = ticket
            .split_once('.')
            .ok_or_else(|| "TICKET_REPLAYED_OR_INVALID".to_string())?;
        let (ts_str, mac_hex) = rest
            .split_once('.')
            .ok_or_else(|| "TICKET_REPLAYED_OR_INVALID".to_string())?;
        if mac_hex.contains('.') {
            return Err("TICKET_REPLAYED_OR_INVALID".to_string());
        }
        let ts: u64 = ts_str.parse().map_err(|_| "TICKET_REPLAYED_OR_INVALID")?;
        let now = unix_now_secs();
        if now.saturating_sub(ts) > ttl_secs || ts > now.saturating_add(5) {
            return Err("TICKET_EXPIRED".to_string());
        }
        let mut mac_msg = String::with_capacity(nonce_hex.len() + ts_str.len() + 36);
        let _ = write!(&mut mac_msg, "{nonce_hex}.{ts}|{ip}");
        let mac = hmac_sha256(ticket_secret, mac_msg.as_bytes());
        let mut expected_hex = String::with_capacity(64);
        write_hex_bytes(&mac, &mut expected_hex);
        if !ct_str_eq(mac_hex.as_bytes(), expected_hex.as_bytes()) {
            return Err("TICKET_REPLAYED_OR_INVALID".to_string());
        }

        let shard_idx = shard_index_str(nonce_hex);
        let mut guard = self.shards[shard_idx]
            .lock()
            .map_err(|_| "LOCK_POISONED".to_string())?;
        guard.ops += 1;
        if (guard.ops & 255) == 0 {
            guard.used_tickets.retain(|_, exp| *exp >= now);
        }
        if let Some(&exp) = guard.used_tickets.get(nonce_hex) {
            if exp >= now {
                return Err("TICKET_REPLAYED_OR_INVALID".to_string());
            }
        }
        guard
            .used_tickets
            .insert(nonce_hex.to_string(), now + ttl_secs.saturating_add(30));
        Ok(())
    }

    pub(crate) fn check_rate_limit(&self, ip: IpAddr) -> bool {
        const MAX_IPS_PER_SHARD: usize = 4096; // 4096 * 16 shards = 65,536 tracked IPs max
        let now = unix_now_secs();
        let shard_idx = shard_index_ip(ip);
        let Ok(mut guard) = self.shards[shard_idx].lock() else {
            return false;
        };
        guard.ops = guard.ops.wrapping_add(1);
        if (guard.ops & 255) == 0 {
            guard.ip_hits.retain(|_, v| {
                while v.front().map_or(false, |&t| now.saturating_sub(t) >= 60) {
                    v.pop_front();
                }
                !v.is_empty()
            });
        }
        if !guard.ip_hits.contains_key(&ip) && guard.ip_hits.len() >= MAX_IPS_PER_SHARD {
            guard.ip_hits.retain(|_, v| {
                while v.front().map_or(false, |&t| now.saturating_sub(t) >= 60) {
                    v.pop_front();
                }
                !v.is_empty()
            });
            if guard.ip_hits.len() >= MAX_IPS_PER_SHARD {
                return false;
            }
        }
        let q = guard.ip_hits.entry(ip).or_default();
        while q.front().map_or(false, |&t| now.saturating_sub(t) >= 60) {
            q.pop_front();
        }
        if q.len() >= self.max_per_min {
            return false;
        }
        q.push_back(now);
        true
    }
}

pub(crate) struct ConnLimiter {
    active: Mutex<HashMap<IpAddr, usize>>,
    max_per_ip: usize,
}

pub(crate) struct ConnGuard<'a> {
    limiter: &'a ConnLimiter,
    ip: IpAddr,
}

impl ConnLimiter {
    pub(crate) fn new(max_per_ip: usize) -> Self {
        Self {
            active: Mutex::new(HashMap::new()),
            max_per_ip: max_per_ip.max(1),
        }
    }

    pub(crate) fn try_acquire(&self, ip: IpAddr, trusted_proxies: &[IpAddr]) -> Option<ConnGuard<'_>> {
        // Trusted reverse proxies legitimately multiplex many clients over one peer IP
        let limit = if trusted_proxies.contains(&ip) {
            usize::MAX
        } else {
            self.max_per_ip
        };
        let mut guard = self.active.lock().ok()?;
        let cnt = guard.entry(ip).or_insert(0);
        if *cnt >= limit {
            if *cnt == 0 {
                guard.remove(&ip);
            }
            return None;
        }
        *cnt += 1;
        Some(ConnGuard { limiter: self, ip })
    }
}

impl Drop for ConnGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.limiter.active.lock() {
            if let Some(cnt) = guard.get_mut(&self.ip) {
                if *cnt <= 1 {
                    guard.remove(&self.ip);
                } else {
                    *cnt -= 1;
                }
            }
        }
    }
}

pub(crate) struct AuthConfig {
    static_secret: Option<Vec<u8>>,
    hmac_key: Option<[u8; 32]>,
}

impl Drop for AuthConfig {
    fn drop(&mut self) {
        if let Some(ref mut s) = self.static_secret {
            secure_zero(s);
        }
        if let Some(ref mut k) = self.hmac_key {
            secure_zero(k);
        }
    }
}

fn is_valid_buyer_id(buyer_id: &str) -> bool {
    !buyer_id.is_empty()
        && buyer_id.len() <= 128
        && buyer_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'@' | b':'))
}

/// Mints a short-lived HMAC-SHA256 signed buyer access token: `vs1.<buyer_id>.<exp>.<mac_hex>`.
pub fn mint_signed_auth_token(
    hmac_key: &[u8; 32],
    buyer_id: &str,
    ttl_secs: u64,
) -> Result<String, String> {
    if !is_valid_buyer_id(buyer_id) {
        return Err(
            "Invalid buyer_id (use 1..=128 ASCII alphanumeric or [-_@:] characters)".to_string(),
        );
    }
    let exp = unix_now_secs().saturating_add(ttl_secs.max(1));
    let payload = format!("vs1.{buyer_id}.{exp}");
    let mac = hmac_sha256(hmac_key, payload.as_bytes());
    let mut out = String::with_capacity(payload.len() + 65);
    out.push_str(&payload);
    out.push('.');
    write_hex_bytes(&mac, &mut out);
    Ok(out)
}

/// Verifies a signed buyer token (`vs1.<buyer_id>.<exp>.<mac_hex>`), returning `Some(buyer_id)`
/// if the signature is valid and unexpired.
pub fn verify_signed_auth_token(hmac_key: &[u8; 32], token: &str) -> Option<String> {
    let (ver, rest1) = token.split_once('.')?;
    if ver != "vs1" {
        return None;
    }
    let (buyer_id, rest2) = rest1.split_once('.')?;
    if !is_valid_buyer_id(buyer_id) {
        return None;
    }
    let (exp_str, mac_hex) = rest2.split_once('.')?;
    if mac_hex.contains('.') || mac_hex.len() != 64 {
        return None;
    }
    let exp: u64 = exp_str.parse().ok()?;
    if exp < unix_now_secs() {
        return None;
    }
    let payload = format!("vs1.{buyer_id}.{exp_str}");
    let expected = hmac_sha256(hmac_key, payload.as_bytes());
    let mut expected_hex = String::with_capacity(64);
    write_hex_bytes(&expected, &mut expected_hex);
    if ct_secret_eq(mac_hex.as_bytes(), expected_hex.as_bytes()) {
        Some(buyer_id.to_string())
    } else {
        None
    }
}

impl AuthConfig {
    pub(crate) fn from_opts(
        static_secret: Option<&str>,
        hmac_key_hex: Option<&str>,
    ) -> Result<Self, String> {
        let static_bytes = static_secret.and_then(|s| {
            if s.is_empty() {
                None
            } else {
                Some(s.as_bytes().to_vec())
            }
        });
        let hmac_key = match hmac_key_hex {
            Some(h) if !h.trim().is_empty() => {
                let mut raw = hex_decode(h.trim())
                    .map_err(|e| format!("Invalid --auth-hmac-key hex: {e}"))?;
                if raw.len() != 32 {
                    secure_zero(&mut raw);
                    return Err("--auth-hmac-key must be 32 bytes (64 hex chars)".to_string());
                }
                let mut k = [0u8; 32];
                k.copy_from_slice(&raw);
                secure_zero(&mut raw);
                Some(k)
            }
            _ => None,
        };
        Ok(Self {
            static_secret: static_bytes,
            hmac_key,
        })
    }

    /// Returns `Ok(Some(buyer_id))` for signed tokens, `Ok(None)` for static secret or open mode,
    /// and `Err(())` when authentication is configured and none of the supplied credentials matched.
    pub(crate) fn verify_request(
        &self,
        auth_hdr: Option<&str>,
        x_auth: Option<&str>,
        cookie_hdr: Option<&str>,
    ) -> Result<Option<String>, ()> {
        if self.static_secret.is_none() && self.hmac_key.is_none() {
            return Ok(None);
        }
        let check_cand = |cand: &str| -> Option<Option<String>> {
            if let Some(ref key) = self.hmac_key {
                if let Some(buyer) = verify_signed_auth_token(key, cand) {
                    return Some(Some(buyer));
                }
            }
            if let Some(ref secret) = self.static_secret {
                if ct_secret_eq(cand.as_bytes(), secret) {
                    return Some(None);
                }
            }
            None
        };

        if let Some(hdr) = auth_hdr {
            let bytes = hdr.as_bytes();
            if bytes.len() >= 7 && bytes[..7].eq_ignore_ascii_case(b"bearer ") {
                if let Some(res) = check_cand(hdr[7..].trim()) {
                    return Ok(res);
                }
            }
        }
        if let Some(x) = x_auth {
            if let Some(res) = check_cand(x.trim()) {
                return Ok(res);
            }
        }
        if let Some(ck) = cookie_hdr {
            for part in ck.split(';') {
                if let Some((k, v)) = part.trim().split_once('=') {
                    let k = k.trim();
                    if k == "vs_auth" || k == "vibeslayer_auth" {
                        if let Some(res) = check_cand(v.trim()) {
                            return Ok(res);
                        }
                    }
                }
            }
        }
        Err(())
    }
}

pub(crate) fn parse_trusted_proxies(spec: Option<&str>) -> Result<Vec<IpAddr>, String> {
    let Some(raw) = spec else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for part in raw.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let ip: IpAddr = trimmed
            .parse()
            .map_err(|_| format!("Invalid IP address in --trust-proxy: '{trimmed}'"))?;
        out.push(ip);
    }
    Ok(out)
}

/// Resolves real client IP. Only trusts `X-Forwarded-For` / `X-Real-Ip` when `peer_ip` is in
/// `trusted_proxies`, walking `X-Forwarded-For` right-to-left past trusted proxy hops so
/// client-injected left-hand headers cannot spoof the rate-limit / ticket-binding identity.
pub(crate) fn resolve_client_ip(
    peer_ip: IpAddr,
    trusted_proxies: &[IpAddr],
    x_forwarded_for: Option<&str>,
    x_real_ip: Option<&str>,
) -> IpAddr {
    if trusted_proxies.is_empty() || !trusted_proxies.contains(&peer_ip) {
        return peer_ip;
    }
    if let Some(xff) = x_forwarded_for {
        for token in xff.rsplit(',') {
            if let Ok(ip) = token.trim().parse::<IpAddr>() {
                if !trusted_proxies.contains(&ip) {
                    return ip;
                }
            }
        }
    }
    if let Some(xri) = x_real_ip {
        if let Ok(ip) = xri.trim().parse::<IpAddr>() {
            return ip;
        }
    }
    peer_ip
}

enum CachedIndexHtml {
    Split(Vec<u8>, Vec<u8>),
    Raw(String),
}

struct ServerState {
    site_id: String,
    site_key: [u8; 32],
    ticket_secret: [u8; 32],
    auth: AuthConfig,
    allowed_origin: Option<String>,
    trusted_proxies: Vec<IpAddr>,
    bound_addr: SocketAddr,
    csp: crate::params::CspMode,
    anti_stealth: crate::params::AntiStealthMode,
    ticket_ttl_sec: u64,
    header_timeout: Duration,
    body_timeout: Duration,
    guard: HttpLeaseGuard,
    conn_limiter: ConnLimiter,
    index_html: CachedIndexHtml,
    loader_js: Vec<u8>,
    manifest_json: Vec<u8>,
    assets: HashMap<String, Vec<u8>>,
}

impl Drop for ServerState {
    fn drop(&mut self) {
        secure_zero(&mut self.site_key);
        secure_zero(&mut self.ticket_secret);
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[inline]
pub(crate) fn ct_str_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Length-hiding constant-time secret comparison via fixed-key HMAC-SHA256.
#[inline]
pub(crate) fn ct_secret_eq(a: &[u8], b: &[u8]) -> bool {
    const DOMAIN_KEY: &[u8; 32] = b"VS_CT_SECRET_EQ_DOMAIN_KEY_V1___";
    let ha = hmac_sha256(DOMAIN_KEY, a);
    let hb = hmac_sha256(DOMAIN_KEY, b);
    ct_str_eq(&ha, &hb)
}

#[cfg(test)]
#[inline]
pub(crate) fn check_bearer_or_cookie_auth(
    auth_hdr: Option<&str>,
    x_auth: Option<&str>,
    cookie_hdr: Option<&str>,
    expected: Option<&str>,
) -> bool {
    let Some(secret_str) = expected else {
        return true;
    };
    if secret_str.is_empty() {
        return true;
    }
    let secret = secret_str.as_bytes();
    if let Some(hdr) = auth_hdr {
        let bytes = hdr.as_bytes();
        if bytes.len() >= 7 && bytes[..7].eq_ignore_ascii_case(b"bearer ") {
            if ct_secret_eq(hdr[7..].trim().as_bytes(), secret) {
                return true;
            }
        }
    }
    if let Some(x) = x_auth {
        if ct_secret_eq(x.trim().as_bytes(), secret) {
            return true;
        }
    }
    if let Some(ck) = cookie_hdr {
        for part in ck.split(';') {
            if let Some((k, v)) = part.trim().split_once('=') {
                let k = k.trim();
                if k == "vs_auth" || k == "vibeslayer_auth" {
                    if ct_secret_eq(v.trim().as_bytes(), secret) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn is_loopback_host(host_only: &str) -> bool {
    host_only.eq_ignore_ascii_case("localhost")
        || host_only == "127.0.0.1"
        || host_only == "[::1]"
        || host_only == "::1"
}

fn host_matches_bound(host_hdr: &str, bound: SocketAddr) -> bool {
    let (h_name, h_port_opt) = if let Some(rest) = host_hdr.strip_prefix('[') {
        if let Some((ip6, tail)) = rest.split_once(']') {
            let port = if tail.is_empty() {
                None
            } else if let Some(p) = tail.strip_prefix(':') {
                match p.parse::<u16>() {
                    Ok(v) => Some(v),
                    Err(_) => return false,
                }
            } else {
                return false;
            };
            (format!("[{ip6}]"), port)
        } else {
            return false;
        }
    } else if let Some((h, p)) = host_hdr.rsplit_once(':') {
        match p.parse::<u16>() {
            Ok(port) => (h.to_string(), Some(port)),
            Err(_) => return false,
        }
    } else {
        (host_hdr.to_string(), None)
    };

    if h_name.is_empty()
        || h_name.contains('/')
        || h_name.contains('@')
        || h_name.bytes().any(|b| b.is_ascii_whitespace())
    {
        return false;
    }

    let bound_port = bound.port();
    match h_port_opt {
        Some(p) if p != bound_port => return false,
        None if bound_port != 80 && bound_port != 443 => return false,
        _ => {}
    }

    if bound.ip().is_unspecified() {
        return true;
    }
    if bound.ip().is_loopback() {
        return is_loopback_host(&h_name);
    }
    let expected_ip = match bound.ip() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    h_name.eq_ignore_ascii_case(&expected_ip)
}

#[inline]
pub(crate) fn validate_same_origin_proxy<'a>(
    origin: Option<&'a str>,
    host: Option<&str>,
    x_forwarded_host: Option<&str>,
    peer_trusted: bool,
    allowed_origin: Option<&'a str>,
    bound_addr: Option<SocketAddr>,
) -> Option<&'a str> {
    if allowed_origin.is_some() {
        return validate_same_origin(origin, host, allowed_origin, bound_addr);
    }
    if peer_trusted {
        if let (Some(origin_hdr), Some(xfh_raw)) = (origin, x_forwarded_host) {
            let xfh = xfh_raw.split(',').next().unwrap_or("").trim();
            if !xfh.is_empty()
                && !xfh.contains('/')
                && !xfh.contains('@')
                && !xfh.bytes().any(|b| b.is_ascii_whitespace())
            {
                let xfh_no80 = xfh.strip_suffix(":80").unwrap_or(xfh);
                let xfh_no443 = xfh.strip_suffix(":443").unwrap_or(xfh);
                if let Some(rest) = origin_hdr.strip_prefix("http://") {
                    if rest == xfh || rest == xfh_no80 {
                        return Some(origin_hdr);
                    }
                }
                if let Some(rest) = origin_hdr.strip_prefix("https://") {
                    if rest == xfh || rest == xfh_no443 {
                        return Some(origin_hdr);
                    }
                }
            }
        }
    }
    validate_same_origin(origin, host, allowed_origin, bound_addr)
}

#[inline]
pub(crate) fn validate_same_origin<'a>(
    origin: Option<&'a str>,
    host: Option<&str>,
    allowed_origin: Option<&'a str>,
    bound_addr: Option<SocketAddr>,
) -> Option<&'a str> {
    let origin_hdr = match origin {
        Some(o) if !o.is_empty() => o,
        _ => return None,
    };
    if let Some(pinned) = allowed_origin {
        if origin_hdr == pinned {
            return Some(pinned);
        }
        return None;
    }
    if let Some(expected_host) = host {
        if let Some(bound) = bound_addr {
            if !host_matches_bound(expected_host, bound) {
                return None;
            }
        }
        let valid_http = origin_hdr
            .strip_prefix("http://")
            .map_or(false, |s| s == expected_host);
        let valid_https = origin_hdr
            .strip_prefix("https://")
            .map_or(false, |s| s == expected_host);
        if valid_http || valid_https {
            return Some(origin_hdr);
        }
    }
    None
}

#[inline]
pub(crate) fn write_hex_bytes(bytes: &[u8], out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
}

#[inline]
fn shard_index_str(s: &str) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in s.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    (h as usize) & (GUARD_SHARDS - 1)
}

#[inline]
fn shard_index_ip(ip: IpAddr) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    match ip {
        IpAddr::V4(v4) => {
            for b in v4.octets() {
                h ^= b as u64;
                h = h.wrapping_mul(0x100_0000_01b3);
            }
        }
        IpAddr::V6(v6) => {
            for b in v6.octets() {
                h ^= b as u64;
                h = h.wrapping_mul(0x100_0000_01b3);
            }
        }
    }
    (h as usize) & (GUARD_SHARDS - 1)
}

pub(crate) fn issue_ticket(secret: &[u8; 32], ip: IpAddr) -> Result<String, String> {
    use std::fmt::Write;
    let mut nonce = [0u8; 16];
    os_random_bytes(&mut nonce)?;
    let ts = unix_now_secs();
    let mut msg = String::with_capacity(80);
    write_hex_bytes(&nonce, &mut msg);
    let _ = write!(&mut msg, ".{ts}");
    let payload_len = msg.len();
    let _ = write!(&mut msg, "|{ip}");
    let mac = hmac_sha256(secret, msg.as_bytes());
    msg.truncate(payload_len);
    msg.push('.');
    write_hex_bytes(&mac, &mut msg);
    Ok(msg)
}

fn write_all_vectored(stream: &mut TcpStream, a: &[u8], b: &[u8]) {
    let mut a_off = 0usize;
    let mut b_off = 0usize;
    while a_off < a.len() {
        let slices = if b_off < b.len() {
            [IoSlice::new(&a[a_off..]), IoSlice::new(&b[b_off..])]
        } else {
            [IoSlice::new(&a[a_off..]), IoSlice::new(&[])]
        };
        let n_slices = if b_off < b.len() { 2 } else { 1 };
        match stream.write_vectored(&slices[..n_slices]) {
            Ok(0) | Err(_) => return,
            Ok(mut n) => {
                let rem_a = a.len() - a_off;
                if n < rem_a {
                    a_off += n;
                } else {
                    a_off = a.len();
                    n -= rem_a;
                    b_off = (b_off + n).min(b.len());
                }
            }
        }
    }
    while b_off < b.len() {
        match stream.write(&b[b_off..]) {
            Ok(0) | Err(_) => return,
            Ok(n) => b_off += n,
        }
    }
}

pub(crate) fn send_http_with_csp(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
    keep_alive: bool,
    csp: crate::params::CspMode,
) {
    use std::io::Write as _;
    let conn_hdr = if keep_alive { "keep-alive" } else { "close" };
    let csp_line = csp.header_line();
    let mut hdr_buf = [0u8; 1024];
    let hdr_len = {
        let mut cursor = std::io::Cursor::new(&mut hdr_buf[..]);
        let _ = write!(
            cursor,
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nCross-Origin-Resource-Policy: same-origin\r\n{csp_line}Connection: {conn_hdr}\r\n\r\n",
            body.len()
        );
        cursor.position() as usize
    };
    write_all_vectored(stream, &hdr_buf[..hdr_len], body);
}

pub(crate) fn send_json_err_with_csp(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    code: &str,
    keep_alive: bool,
    csp: crate::params::CspMode,
) {
    use std::fmt::Write as _;
    let mut payload = String::with_capacity(32 + code.len());
    let _ = write!(&mut payload, "{{\"ok\":false,\"error\":\"{code}\"}}");
    send_http_with_csp(
        stream,
        status,
        reason,
        "application/json; charset=utf-8",
        payload.as_bytes(),
        keep_alive,
        csp,
    );
}

pub(crate) struct ParsedRequest {
    pub(crate) method: String,
    pub(crate) path_only: String,
    pub(crate) origin: Option<String>,
    pub(crate) host: Option<String>,
    pub(crate) x_forwarded_host: Option<String>,
    pub(crate) user_agent: Option<String>,
    pub(crate) sec_ch_ua: Option<String>,
    pub(crate) sec_ch_ua_platform: Option<String>,
    pub(crate) authorization: Option<String>,
    pub(crate) x_vs_auth: Option<String>,
    pub(crate) x_vs_session: Option<String>,
    pub(crate) cookie: Option<String>,
    pub(crate) x_forwarded_for: Option<String>,
    pub(crate) x_real_ip: Option<String>,
    pub(crate) keep_alive: bool,
    pub(crate) body: Vec<u8>,
}

fn send_proto_err_close(stream: &mut TcpStream, status: u16, reason: &str, code: &str) {
    send_json_err_with_csp(stream, status, reason, code, false, crate::params::CspMode::Off);
}

/// Normalizes RFC 9112 §3.2 request-target forms (origin-form `/a?b` AND proxy absolute-form
/// `http://host:port/a?b` / `https://host/a?b`) into `(path_only, optional_authority)`.
fn normalize_request_target(target: &str) -> (String, Option<String>) {
    let stripped = if target.len() >= 7 && target[..7].eq_ignore_ascii_case("http://") {
        Some(&target[7..])
    } else if target.len() >= 8 && target[..8].eq_ignore_ascii_case("https://") {
        Some(&target[8..])
    } else {
        None
    };
    if let Some(after_scheme) = stripped {
        if let Some(slash_idx) = after_scheme.find('/') {
            let auth = after_scheme[..slash_idx].to_string();
            let rest = &after_scheme[slash_idx..];
            let path = rest.split('?').next().unwrap_or("/").to_string();
            return (path, if auth.is_empty() { None } else { Some(auth) });
        }
        let auth = after_scheme.split('?').next().unwrap_or("").to_string();
        return ("/".to_string(), if auth.is_empty() { None } else { Some(auth) });
    }
    (target.split('?').next().unwrap_or("/").to_string(), None)
}

/// Decodes an RFC 9112 §7.1 `Transfer-Encoding: chunked` body directly from `buf`/`stream`,
/// enforcing `max_body` and `body_timeout` and draining exact bytes so keep-alive stays in sync.
fn read_chunked_body(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    body_start: usize,
    body_deadline_start: Instant,
    body_timeout: Duration,
    max_body: usize,
) -> Result<Vec<u8>, (u16, &'static str, &'static str)> {
    buf.drain(..body_start);
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];

    let ensure_line = |stream: &mut TcpStream, buf: &mut Vec<u8>, chunk: &mut [u8; 4096]| -> Result<usize, (u16, &'static str, &'static str)> {
        loop {
            if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
                return Ok(pos);
            }
            if buf.len() > 8192 {
                return Err((400, "Bad Request", "BAD_CHUNK_LINE"));
            }
            if body_deadline_start.elapsed() > body_timeout {
                return Err((408, "Request Timeout", "BODY_TIMEOUT"));
            }
            match stream.read(chunk) {
                Ok(0) | Err(_) => return Err((400, "Bad Request", "INCOMPLETE_CHUNKED_BODY")),
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    };

    loop {
        let crlf = ensure_line(stream, buf, &mut chunk)?;
        let size_line = std::str::from_utf8(&buf[..crlf])
            .map_err(|_| (400, "Bad Request", "BAD_CHUNK_SIZE"))?;
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        if hex_part.is_empty() || hex_part.len() > 8 {
            return Err((400, "Bad Request", "BAD_CHUNK_SIZE"));
        }
        let chunk_sz = usize::from_str_radix(hex_part, 16)
            .map_err(|_| (400, "Bad Request", "BAD_CHUNK_SIZE"))?;
        buf.drain(..crlf + 2);

        if chunk_sz == 0 {
            // Drain optional trailers up to final empty CRLF line
            loop {
                let t_crlf = ensure_line(stream, buf, &mut chunk)?;
                buf.drain(..t_crlf + 2);
                if t_crlf == 0 {
                    break;
                }
            }
            return Ok(out);
        }

        if out.len().saturating_add(chunk_sz) > max_body {
            return Err((413, "Payload Too Large", "PAYLOAD_TOO_LARGE"));
        }
        let need = chunk_sz + 2;
        while buf.len() < need {
            if body_deadline_start.elapsed() > body_timeout {
                return Err((408, "Request Timeout", "BODY_TIMEOUT"));
            }
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return Err((400, "Bad Request", "INCOMPLETE_CHUNKED_BODY")),
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        if &buf[chunk_sz..chunk_sz + 2] != b"\r\n" {
            return Err((400, "Bad Request", "BAD_CHUNK_TERMINATOR"));
        }
        out.extend_from_slice(&buf[..chunk_sz]);
        buf.drain(..need);
    }
}

pub(crate) fn read_http_request_with_timeouts(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    header_timeout: Duration,
    body_timeout: Duration,
) -> Option<ParsedRequest> {
    const MAX_HEADER_BYTES: usize = 32 * 1024;
    const MAX_BODY_BYTES: usize = 64 * 1024;

    let mut chunk = [0u8; 4096];
    let mut scan_from = 0usize;
    let mut first_byte_at: Option<Instant> = if buf.is_empty() {
        None
    } else {
        Some(Instant::now())
    };
    let hdr_end = loop {
        if buf.len() >= 4 {
            let start = scan_from.saturating_sub(3);
            if let Some(rel) = buf[start..].windows(4).position(|w| w == b"\r\n\r\n") {
                break start + rel;
            }
        }
        scan_from = buf.len();
        if buf.len() > MAX_HEADER_BYTES {
            send_proto_err_close(stream, 431, "Request Header Fields Too Large", "HEADERS_TOO_LARGE");
            return None;
        }
        if let Some(t0) = first_byte_at {
            if t0.elapsed() > header_timeout {
                return None;
            }
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => {
                if first_byte_at.is_none() {
                    first_byte_at = Some(Instant::now());
                }
                buf.extend_from_slice(&chunk[..n]);
            }
        }
    };

    let parsed_hdrs = (|| -> Result<_, (u16, &'static str, &'static str)> {
        let hdr_str = std::str::from_utf8(&buf[..hdr_end])
            .map_err(|_| (400, "Bad Request", "BAD_HTTP_UTF8"))?;
        let mut lines = hdr_str.split("\r\n");
        let req_line = lines.next().ok_or((400, "Bad Request", "BAD_REQUEST_LINE"))?;
        let mut parts = req_line.split_whitespace();
        let method = parts
            .next()
            .ok_or((400, "Bad Request", "BAD_REQUEST_LINE"))?
            .to_string();
        let target = parts.next().ok_or((400, "Bad Request", "BAD_REQUEST_LINE"))?;
        let version = parts.next().unwrap_or("HTTP/1.1");
        let (path_only, target_auth) = normalize_request_target(target);

        let mut origin: Option<String> = None;
        let mut host: Option<String> = None;
        let mut x_forwarded_host: Option<String> = None;
        let mut user_agent: Option<String> = None;
        let mut sec_ch_ua: Option<String> = None;
        let mut sec_ch_ua_platform: Option<String> = None;
        let mut authorization: Option<String> = None;
        let mut x_vs_auth: Option<String> = None;
        let mut x_vs_session: Option<String> = None;
        let mut cookie: Option<String> = None;
        let mut x_forwarded_for: Option<String> = None;
        let mut x_real_ip: Option<String> = None;
        let mut conn_val: Option<&str> = None;
        let mut content_len: Option<usize> = None;
        let mut has_te = false;
        let mut is_chunked = false;
        let mut expect_100 = false;

        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                let k = k.trim();
                let v = v.trim();
                if k.eq_ignore_ascii_case("content-length") {
                    let parsed_cl = v
                        .parse::<usize>()
                        .map_err(|_| (400, "Bad Request", "BAD_CONTENT_LENGTH"))?;
                    if let Some(prev) = content_len {
                        if prev != parsed_cl {
                            return Err((400, "Bad Request", "CONFLICTING_CONTENT_LENGTH"));
                        }
                    }
                    content_len = Some(parsed_cl);
                } else if k.eq_ignore_ascii_case("transfer-encoding") {
                    has_te = true;
                    if v.split(',').any(|t| t.trim().eq_ignore_ascii_case("chunked")) {
                        is_chunked = true;
                    }
                } else if k.eq_ignore_ascii_case("expect") {
                    if v.eq_ignore_ascii_case("100-continue") {
                        expect_100 = true;
                    }
                } else if k.eq_ignore_ascii_case("origin") {
                    origin = Some(v.to_string());
                } else if k.eq_ignore_ascii_case("host") {
                    host = Some(v.to_string());
                } else if k.eq_ignore_ascii_case("x-forwarded-host") {
                    x_forwarded_host = Some(v.to_string());
                } else if k.eq_ignore_ascii_case("user-agent") {
                    user_agent = Some(v.to_string());
                } else if k.eq_ignore_ascii_case("sec-ch-ua") {
                    sec_ch_ua = Some(v.to_string());
                } else if k.eq_ignore_ascii_case("sec-ch-ua-platform") {
                    sec_ch_ua_platform = Some(v.to_string());
                } else if k.eq_ignore_ascii_case("authorization") {
                    authorization = Some(v.to_string());
                } else if k.eq_ignore_ascii_case("x-vs-auth") {
                    x_vs_auth = Some(v.to_string());
                } else if k.eq_ignore_ascii_case("x-vs-session") {
                    x_vs_session = Some(v.to_string());
                } else if k.eq_ignore_ascii_case("cookie") {
                    match cookie {
                        Some(ref mut existing) => {
                            existing.push_str("; ");
                            existing.push_str(v);
                        }
                        None => cookie = Some(v.to_string()),
                    }
                } else if k.eq_ignore_ascii_case("x-forwarded-for") {
                    match x_forwarded_for {
                        Some(ref mut existing) => {
                            existing.push_str(", ");
                            existing.push_str(v);
                        }
                        None => x_forwarded_for = Some(v.to_string()),
                    }
                } else if k.eq_ignore_ascii_case("x-real-ip") {
                    x_real_ip = Some(v.to_string());
                } else if k.eq_ignore_ascii_case("connection") {
                    conn_val = Some(v);
                }
            }
        }

        // RFC 9112 §6.3: Reject CL+TE conflict to prevent HTTP request smuggling
        if has_te && content_len.is_some() {
            return Err((400, "Bad Request", "CL_TE_SMUGGLING_REJECTED"));
        }
        if has_te && !is_chunked {
            return Err((400, "Bad Request", "UNSUPPORTED_TRANSFER_ENCODING"));
        }
        if host.is_none() {
            host = target_auth;
        }
        let keep_alive = if version.eq_ignore_ascii_case("HTTP/1.0") {
            conn_val.map_or(false, |v| v.eq_ignore_ascii_case("keep-alive"))
        } else {
            !conn_val.map_or(false, |v| {
                v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close"))
            })
        };
        Ok((
            method,
            path_only,
            origin,
            host,
            x_forwarded_host,
            user_agent,
            sec_ch_ua,
            sec_ch_ua_platform,
            authorization,
            x_vs_auth,
            x_vs_session,
            cookie,
            x_forwarded_for,
            x_real_ip,
            keep_alive,
            content_len.unwrap_or(0),
            is_chunked,
            expect_100,
        ))
    })();

    let (
        method,
        path_only,
        origin,
        host,
        x_forwarded_host,
        user_agent,
        sec_ch_ua,
        sec_ch_ua_platform,
        authorization,
        x_vs_auth,
        x_vs_session,
        cookie,
        x_forwarded_for,
        x_real_ip,
        keep_alive,
        content_len,
        is_chunked,
        expect_100,
    ) = match parsed_hdrs {
        Ok(v) => v,
        Err((st, rs, code)) => {
            send_proto_err_close(stream, st, rs, code);
            return None;
        }
    };

    if !is_chunked && content_len > MAX_BODY_BYTES {
        send_proto_err_close(stream, 413, "Payload Too Large", "PAYLOAD_TOO_LARGE");
        return None;
    }

    if expect_100 {
        let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
    }

    let body_deadline_start = first_byte_at.unwrap_or_else(Instant::now);
    let body_start = hdr_end + 4;
    let body = if is_chunked {
        match read_chunked_body(
            stream,
            buf,
            body_start,
            body_deadline_start,
            body_timeout,
            MAX_BODY_BYTES,
        ) {
            Ok(b) => b,
            Err((st, rs, code)) => {
                send_proto_err_close(stream, st, rs, code);
                return None;
            }
        }
    } else {
        let total_needed = body_start + content_len;
        while buf.len() < total_needed {
            if body_deadline_start.elapsed() > body_timeout {
                return None;
            }
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return None,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let b = buf[body_start..total_needed].to_vec();
        buf.drain(..total_needed);
        b
    };

    Some(ParsedRequest {
        method,
        path_only,
        origin,
        host,
        x_forwarded_host,
        user_agent,
        sec_ch_ua,
        sec_ch_ua_platform,
        authorization,
        x_vs_auth,
        x_vs_session,
        cookie,
        x_forwarded_for,
        x_real_ip,
        keep_alive,
        body,
    })
}

fn handle_client(mut stream: TcpStream, state: &ServerState) {
    const MAX_KEEPALIVE_REQS: usize = 4096;
    let _ = stream.set_read_timeout(Some(state.header_timeout));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_nodelay(true);
    let csp = state.csp;
    let peer_ip = stream
        .peer_addr()
        .map(|a| a.ip())
        .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
    let Some(_conn_guard) = state.conn_limiter.try_acquire(peer_ip, &state.trusted_proxies) else {
        send_json_err_with_csp(
            &mut stream,
            429,
            "Too Many Requests",
            "TOO_MANY_CONNECTIONS",
            false,
            csp,
        );
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
        let path_only = req.path_only.as_str();
        let ip = resolve_client_ip(
            peer_ip,
            &state.trusted_proxies,
            req.x_forwarded_for.as_deref(),
            req.x_real_ip.as_deref(),
        );

        if (method == "GET" || method == "HEAD") && path_only == "/__vibeslayer/health" {
            let body: &[u8] = if method == "HEAD" { b"" } else { b"{\"ok\":true}" };
            send_http_with_csp(
                &mut stream,
                200,
                "OK",
                "application/json; charset=utf-8",
                body,
                keep_alive,
                csp,
            );
        } else if method == "GET" && path_only == "/__vibeslayer/vibeslayer.web.json" {
            send_json_err_with_csp(
                &mut stream,
                403,
                "Forbidden",
                "MANIFEST_SEALED_IN_LEASE",
                keep_alive,
                csp,
            );
        } else if state
            .auth
            .verify_request(
                req.authorization.as_deref(),
                req.x_vs_auth.as_deref(),
                req.cookie.as_deref(),
            )
            .is_err()
        {
            send_json_err_with_csp(&mut stream, 401, "Unauthorized", "AUTH_REQUIRED", keep_alive, csp);
        } else if method == "GET" && (path_only == "/" || path_only == "/index.html") {
            let Ok(ticket) = issue_ticket(&state.ticket_secret, ip) else {
                send_json_err_with_csp(
                    &mut stream,
                    500,
                    "Internal Server Error",
                    "TICKET_GEN_FAILED",
                    false,
                    csp,
                );
                return;
            };
            match &state.index_html {
                CachedIndexHtml::Split(prefix, suffix) => {
                    let mut rendered =
                        Vec::with_capacity(prefix.len() + ticket.len() + suffix.len());
                    rendered.extend_from_slice(prefix);
                    rendered.extend_from_slice(ticket.as_bytes());
                    rendered.extend_from_slice(suffix);
                    send_http_with_csp(
                        &mut stream,
                        200,
                        "OK",
                        "text/html; charset=utf-8",
                        &rendered,
                        keep_alive,
                        csp,
                    );
                }
                CachedIndexHtml::Raw(html) => {
                    let rendered = html.replace("__VS_RUNTIME_TICKET__", &ticket);
                    send_http_with_csp(
                        &mut stream,
                        200,
                        "OK",
                        "text/html; charset=utf-8",
                        rendered.as_bytes(),
                        keep_alive,
                        csp,
                    );
                }
            }
        } else if method == "GET" && path_only == "/__vibeslayer/loader.js" {
            send_http_with_csp(
                &mut stream,
                200,
                "OK",
                "application/javascript; charset=utf-8",
                &state.loader_js,
                keep_alive,
                csp,
            );
        } else if method == "GET" && path_only.starts_with("/assets/") {
            let name = path_only.trim_start_matches("/assets/");
            if !name.is_empty()
                && !name.contains('/')
                && !name.contains('\\')
                && !name.contains("..")
                && name.ends_with(".vsweb")
            {
                if let Some(bytes) = state.assets.get(name) {
                    send_http_with_csp(
                        &mut stream,
                        200,
                        "OK",
                        "application/octet-stream",
                        bytes,
                        keep_alive,
                        csp,
                    );
                } else {
                    send_json_err_with_csp(&mut stream, 404, "Not Found", "ASSET_NOT_FOUND", keep_alive, csp);
                }
            } else {
                send_json_err_with_csp(&mut stream, 404, "Not Found", "ASSET_NOT_FOUND", keep_alive, csp);
            }
        } else if method == "POST" && path_only == "/__vibeslayer/lease" {
            let peer_trusted = state.trusted_proxies.contains(&peer_ip);
            handle_lease_request(&mut stream, state, ip, peer_trusted, &req, keep_alive);
        } else {
            send_json_err_with_csp(&mut stream, 404, "Not Found", "NOT_FOUND", keep_alive, csp);
        }

        if !keep_alive {
            return;
        }
    }
}

fn handle_lease_request(
    stream: &mut TcpStream,
    state: &ServerState,
    ip: IpAddr,
    peer_trusted: bool,
    req: &ParsedRequest,
    keep_alive: bool,
) {
    let csp = state.csp;
    let Some(effective_origin) = validate_same_origin_proxy(
        req.origin.as_deref(),
        req.host.as_deref(),
        req.x_forwarded_host.as_deref(),
        peer_trusted,
        state.allowed_origin.as_deref(),
        Some(state.bound_addr),
    ) else {
        send_json_err_with_csp(stream, 403, "Forbidden", "ORIGIN_DENIED", keep_alive, csp);
        return;
    };

    if !state.guard.check_rate_limit(ip) {
        send_json_err_with_csp(stream, 429, "Too Many Requests", "RATE_LIMITED", keep_alive, csp);
        return;
    }

    let Ok(body_str) = std::str::from_utf8(&req.body) else {
        send_json_err_with_csp(stream, 400, "Bad Request", "BAD_JSON", keep_alive, csp);
        return;
    };
    let Ok(json) = parse_json(body_str) else {
        send_json_err_with_csp(stream, 400, "Bad Request", "BAD_JSON", keep_alive, csp);
        return;
    };
    let ticket = json.get("ticket").and_then(|v| v.as_str()).unwrap_or("");
    if let Err(code) = state.guard.verify_and_consume_ticket_ttl(
        &state.ticket_secret,
        ticket,
        ip,
        state.ticket_ttl_sec,
    ) {
        send_json_err_with_csp(stream, 403, "Forbidden", &code, keep_alive, csp);
        return;
    }

    let client_hex = json
        .get("clientPublicKeyHex")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if let Err(code) = verify_server_anti_stealth(state.anti_stealth, req, &json, ticket, client_hex) {
        send_json_err_with_csp(stream, 403, "Forbidden", code, keep_alive, csp);
        return;
    }
    let Ok(client_pub) = hex_decode(client_hex) else {
        send_json_err_with_csp(stream, 400, "Bad Request", "INVALID_CLIENT_PUBLIC_KEY", keep_alive, csp);
        return;
    };
    if p256_validate_public_key(&client_pub).is_err() {
        send_json_err_with_csp(stream, 400, "Bad Request", "INVALID_CLIENT_PUBLIC_KEY", keep_alive, csp);
        return;
    }

    let Ok((mut srv_priv, srv_pub)) = p256_generate_keypair() else {
        send_json_err_with_csp(stream, 500, "Internal Server Error", "KEYGEN_FAILED", keep_alive, csp);
        return;
    };
    let shared_res = p256_ecdh_shared_secret(&srv_priv, &client_pub);
    secure_zero(&mut srv_priv);
    let Ok(mut shared_32) = shared_res else {
        send_json_err_with_csp(stream, 400, "Bad Request", "ECDH_FAILED", keep_alive, csp);
        return;
    };

    let mut rand_buf = [0u8; 40];
    if os_random_bytes(&mut rand_buf).is_err() {
        secure_zero(&mut shared_32);
        send_json_err_with_csp(stream, 500, "Internal Server Error", "RNG_FAILED", keep_alive, csp);
        return;
    }
    let mut lease_id = String::with_capacity(32);
    write_hex_bytes(&rand_buf[..16], &mut lease_id);
    let mut wrap_iv = [0u8; 12];
    wrap_iv.copy_from_slice(&rand_buf[16..28]);
    let mut manifest_iv = [0u8; 12];
    manifest_iv.copy_from_slice(&rand_buf[28..40]);

    let wrap_info = format!("VSWEB1_WRAP|{effective_origin}");
    let mut wrap_key = hkdf_sha256_32(&shared_32, lease_id.as_bytes(), wrap_info.as_bytes());
    secure_zero(&mut shared_32);

    let (ct_key, tag_key) =
        aes256_gcm_seal(&wrap_key, &wrap_iv, wrap_info.as_bytes(), &state.site_key);
    secure_zero(&mut wrap_key);

    let (m_ct, m_tag) = aes256_gcm_seal(
        &state.site_key,
        &manifest_iv,
        b"VSWEB1|__manifest__",
        &state.manifest_json,
    );

    let mut resp = String::with_capacity(512 + (m_ct.len() + m_tag.len()) * 2);
    resp.push_str("{\"ok\":true,\"siteId\":\"");
    resp.push_str(&state.site_id);
    resp.push_str("\",\"leaseId\":\"");
    resp.push_str(&lease_id);
    resp.push_str("\",\"origin\":\"");
    resp.push_str(effective_origin);
    resp.push_str("\",\"serverPublicKeyHex\":\"");
    write_hex_bytes(&srv_pub, &mut resp);
    resp.push_str("\",\"wrapIvHex\":\"");
    write_hex_bytes(&wrap_iv, &mut resp);
    resp.push_str("\",\"wrappedKeyHex\":\"");
    write_hex_bytes(&ct_key, &mut resp);
    write_hex_bytes(&tag_key, &mut resp);
    resp.push_str("\",\"manifestIvHex\":\"");
    write_hex_bytes(&manifest_iv, &mut resp);
    resp.push_str("\",\"sealedManifestHex\":\"");
    write_hex_bytes(&m_ct, &mut resp);
    write_hex_bytes(&m_tag, &mut resp);
    resp.push_str("\"}");

    send_http_with_csp(
        stream,
        200,
        "OK",
        "application/json; charset=utf-8",
        resp.as_bytes(),
        keep_alive,
        csp,
    );
}

pub fn serve_website(
    protected_site_dir: &Path,
    addr: &str,
    origin_override: Option<&str>,
    keys_opt: Option<&Path>,
    reg_opt: Option<&Path>,
    max_leases_per_min: usize,
    auth_secret: Option<&str>,
    auth_hmac_key: Option<&str>,
    trust_proxy: Option<&str>,
) -> Result<(), String> {
    let mut params =
        crate::params::ServeWebParams::from_preset(crate::params::SecurityPreset::Balanced);
    params.addr = addr.to_string();
    params.origin = origin_override.map(|s| s.to_string());
    params.max_leases_per_min = max_leases_per_min;
    params.auth_secret = auth_secret.map(|s| s.to_string());
    params.auth_hmac_key = auth_hmac_key.map(|s| s.to_string());
    params.trust_proxy = trust_proxy.map(|s| s.to_string());
    serve_website_with_params(protected_site_dir, keys_opt, reg_opt, &params)
}

pub fn serve_website_with_params(
    protected_site_dir: &Path,
    keys_opt: Option<&Path>,
    reg_opt: Option<&Path>,
    params: &crate::params::ServeWebParams,
) -> Result<(), String> {
    params.validate()?;
    let abs_dir = fs::canonicalize(protected_site_dir)
        .map_err(|e| format!("Protected website dir missing ({}): {e}", protected_site_dir.display()))?;
    let manifest_raw = fs::read_to_string(abs_dir.join("vibeslayer.web.json"))
        .map_err(|e| format!("Missing vibeslayer.web.json in {}: {e}", abs_dir.display()))?;
    let manifest = parse_json(&manifest_raw)?;
    let site_id = manifest
        .get("siteId")
        .and_then(|v| v.as_str())
        .ok_or("MANIFEST_MISSING_SITE_ID")?
        .to_string();
    let allowed_origin = params
        .origin
        .clone()
        .or_else(|| manifest.get("allowedOrigin").and_then(|v| v.as_str()).map(|s| s.to_string()));

    let ctx = resolve_known_metadata(&abs_dir.join("vibeslayer.web.json"), keys_opt, reg_opt);
    let vault = ctx.vault.ok_or_else(|| {
        format!(
            "No keys.json found for {}. Pass --keys <path/to/.vibeslayer/keys.json>.",
            abs_dir.display()
        )
    })?;
    let master_hex = vault
        .get("masterKeyHex")
        .and_then(|v| v.as_str())
        .ok_or("VAULT_MISSING_MASTER_KEY")?;
    let mut master_key = parse_key_hex_32(master_hex)?;
    let site_key = hkdf_sha256_32(&master_key, site_id.as_bytes(), b"VSWEB1_SITE_KEY");
    let mut rt_key = hkdf_sha256_32(&site_key, site_id.as_bytes(), b"VSWEB1_RTKEY_V1");
    secure_zero(&mut master_key);
    // Inject per-site runtime decryption key ONLY into the in-memory manifest delivered
    // over ECDH P-256 + AES-256-GCM lease (never written to vibeslayer.web.json on disk!).
    let mut live_manifest = manifest;
    live_manifest.insert("rtKeyHex", JsonVal::Str(crate::hex_encode(&rt_key)));
    secure_zero(&mut rt_key);
    let live_manifest_bytes = to_json_pretty(&live_manifest).into_bytes();

    let mut ticket_secret = [0u8; 32];
    os_random_bytes(&mut ticket_secret)?;

    let auth = AuthConfig::from_opts(params.auth_secret.as_deref(), params.auth_hmac_key.as_deref())?;
    let trusted_proxies = parse_trusted_proxies(params.trust_proxy.as_deref())?;

    let index_raw = fs::read_to_string(abs_dir.join("index.html"))
        .map_err(|e| format!("Missing index.html in {}: {e}", abs_dir.display()))?;
    let index_html = if index_raw.matches("__VS_RUNTIME_TICKET__").count() == 1 {
        let (p, s) = index_raw.split_once("__VS_RUNTIME_TICKET__").unwrap();
        CachedIndexHtml::Split(p.as_bytes().to_vec(), s.as_bytes().to_vec())
    } else {
        CachedIndexHtml::Raw(index_raw)
    };
    let loader_js = fs::read(abs_dir.join("vibe-slayer-loader.js")).unwrap_or_default();

    let mut assets = HashMap::new();
    if let Ok(entries) = fs::read_dir(abs_dir.join("assets")) {
        for ent in entries.flatten() {
            let p = ent.path();
            if p.is_file() {
                if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                    if name.ends_with(".vsweb") {
                        if let Ok(bytes) = fs::read(&p) {
                            assets.insert(name.to_string(), bytes);
                        }
                    }
                }
            }
        }
    }

    // Pre-warm fixed-base P-256 generator table before accepting leases.
    let _ = p256_g_table();

    let listener = TcpListener::bind(&params.addr)
        .map_err(|e| format!("Failed binding {}: {e}", params.addr))?;
    let bound = listener.local_addr().map_err(|e| e.to_string())?;
    let num_workers = params.resolved_workers();
    println!(
        "[vibe-slayer] Live Website Runtime Protection active at http://{bound} (preset={}, csp={}, workers={num_workers})",
        params.preset.as_str(),
        params.csp.as_str()
    );
    println!(
        "[vibe-slayer] Serving encrypted bundle: {} (origin={}, maxLeases/min={}, ticketTtl={}s)",
        abs_dir.display(),
        allowed_origin.as_deref().unwrap_or("same-host"),
        params.max_leases_per_min,
        params.ticket_ttl_sec
    );
    let _ = std::io::stdout().flush();

    let state = Arc::new(ServerState {
        site_id,
        site_key,
        ticket_secret,
        auth,
        allowed_origin,
        trusted_proxies,
        bound_addr: bound,
        csp: params.csp,
        anti_stealth: params.anti_stealth,
        ticket_ttl_sec: params.ticket_ttl_sec,
        header_timeout: Duration::from_millis(params.header_timeout_ms),
        body_timeout: Duration::from_millis(params.body_timeout_ms),
        guard: HttpLeaseGuard::new(params.max_leases_per_min),
        conn_limiter: ConnLimiter::new(params.max_conns_per_ip),
        index_html,
        loader_js,
        manifest_json: live_manifest_bytes,
        assets,
    });

    const MAX_PENDING_CONNS: usize = 256;
    let pool = Arc::new((Mutex::new(VecDeque::<TcpStream>::new()), Condvar::new()));
    for _ in 0..num_workers {
        let st = Arc::clone(&state);
        let q = Arc::clone(&pool);
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
                handle_client(stream, &st);
            }
        });
    }

    for conn in listener.incoming() {
        if let Ok(mut stream) = conn {
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
                    params.csp,
                );
                continue;
            }
            guard.push_back(stream);
            cv.notify_one();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex_encode;

    #[test]
    fn nist_sp800_38d_aes256_gcm_test_vector() {
        // NIST SP 800-38D Test Case 16 (256-bit key, 96-bit IV, 20-byte AAD, 60-byte PT)
        let key_hex = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
        let iv_hex = "cafebabefacedbaddecaf888";
        let aad_hex = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        let pt_hex = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
        let exp_ct_hex = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";
        let exp_tag_hex = "76fc6ece0f4e1768cddf8853bb2d551b";

        let key: [u8; 32] = hex_decode(key_hex).unwrap().try_into().unwrap();
        let iv: [u8; 12] = hex_decode(iv_hex).unwrap().try_into().unwrap();
        let aad = hex_decode(aad_hex).unwrap();
        let pt = hex_decode(pt_hex).unwrap();

        let (mut ct, tag) = aes256_gcm_seal(&key, &iv, &aad, &pt);
        assert_eq!(hex_encode(&ct), exp_ct_hex);
        assert_eq!(hex_encode(&tag), exp_tag_hex);

        let dec = aes256_gcm_open(&key, &iv, &aad, &ct, &tag).unwrap();
        assert_eq!(dec, pt);

        ct[0] ^= 0x01;
        assert!(aes256_gcm_open(&key, &iv, &aad, &ct, &tag).is_err());
    }

    #[test]
    fn rfc5903_p256_ecdh_test_vector() {
        // RFC 5903 Section 8.1 Test Vector (256-bit Random ECP Group / P-256)
        let di: [u8; 32] = hex_decode("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433")
            .unwrap()
            .try_into()
            .unwrap();
        let dr: [u8; 32] = hex_decode("C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53")
            .unwrap()
            .try_into()
            .unwrap();

        let mut expected_pub_i = vec![0x04u8];
        expected_pub_i.extend(
            hex_decode("DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180").unwrap(),
        );
        expected_pub_i.extend(
            hex_decode("5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3").unwrap(),
        );

        let mut expected_pub_r = vec![0x04u8];
        expected_pub_r.extend(
            hex_decode("D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63").unwrap(),
        );
        expected_pub_r.extend(
            hex_decode("56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB").unwrap(),
        );

        let pub_i = p256_public_key(&di).unwrap();
        let pub_r = p256_public_key(&dr).unwrap();
        assert_eq!(pub_i.as_slice(), expected_pub_i.as_slice());
        assert_eq!(pub_r.as_slice(), expected_pub_r.as_slice());

        let z_ir = p256_ecdh_shared_secret(&di, &pub_r).unwrap();
        let z_ri = p256_ecdh_shared_secret(&dr, &pub_i).unwrap();
        assert_eq!(z_ir, z_ri);
        assert_eq!(
            hex_encode(&z_ir),
            "d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de"
        );

        // Tampering 1 byte of Y puts point off curve and must be rejected!
        let mut bad_pub = pub_r;
        bad_pub[64] ^= 0x01;
        assert!(p256_validate_public_key(&bad_pub).is_err());
        assert!(p256_ecdh_shared_secret(&di, &bad_pub).is_err());
    }

    #[test]
    fn aesni_gcm_and_solinas_p256_multi_vector_parity() {
        let key = [0x4bu8; 32];
        let iv = [0x92u8; 12];
        let aad = b"VSWEB1|assets/chunk-check.js";
        let mut pt = vec![0u8; 4097];
        for (i, b) in pt.iter_mut().enumerate() {
            *b = (i.wrapping_mul(73) ^ (i >> 2)) as u8;
        }
        for len in [0usize, 1, 15, 16, 17, 63, 64, 65, 127, 128, 255, 1024, 4097] {
            let (ct, tag) = aes256_gcm_seal(&key, &iv, aad, &pt[..len]);
            let (ct_s, tag_s) = aes256_gcm_seal_scalar(&key, &iv, aad, &pt[..len]);
            assert_eq!(ct, ct_s, "gcm ct mismatch at len={len}");
            assert_eq!(tag, tag_s, "gcm tag mismatch at len={len}");
            let dec = aes256_gcm_open(&key, &iv, aad, &ct, &tag).unwrap();
            assert_eq!(dec.as_slice(), &pt[..len]);
            let dec_s = aes256_gcm_open_scalar(&key, &iv, aad, &ct, &tag).unwrap();
            assert_eq!(dec_s.as_slice(), &pt[..len]);
        }

        // Multi-pair randomized P-256 keygen + ECDH agreement
        for _ in 0..8 {
            let (da, pa) = p256_generate_keypair().unwrap();
            let (db, pb) = p256_generate_keypair().unwrap();
            let sab = p256_ecdh_shared_secret(&da, &pb).unwrap();
            let sba = p256_ecdh_shared_secret(&db, &pa).unwrap();
            assert_eq!(sab, sba);
        }

        // L1-fused seal_web_asset_in_place parity across 32 KiB chunk boundaries & tail remainders
        let mut big = vec![0u8; 100_003];
        for (i, b) in big.iter_mut().enumerate() {
            *b = (i.wrapping_mul(37) ^ (i >> 5)) as u8;
        }
        for len in [0usize, 1, 15, 16, 65, 32_767, 32_768, 32_769, 65_536, 100_003] {
            let mut buf = big[..len].to_vec();
            let (sha_in, tag_in) = seal_web_asset_in_place(&key, &iv, aad, &mut buf);
            let exp_sha = sha256_hex(&big[..len]);
            let (exp_ct, exp_tag) = aes256_gcm_seal(&key, &iv, aad, &big[..len]);
            assert_eq!(sha_in, exp_sha, "fused sha mismatch at len={len}");
            assert_eq!(buf, exp_ct, "fused ct mismatch at len={len}");
            assert_eq!(tag_in, exp_tag, "fused tag mismatch at len={len}");
        }
    }

    #[test]
    fn harden_js_preserves_syntax_and_masks_canaries() {
        let sample = r#""use strict";
// Sensitive build note: VS_COMMENT_CANARY_9999
import { Lit } from "./lit.js";
const cfg = { "public-key": "ok", route: "/api/secret-vault" };
const re = /https?:\/\/example\.com\/[a-z]+/i;
class Card {
  async mount() {
    const s = "VS_WC3D_SHADER_FORMULA_ALPHA_7721";
    const u = 'https://internal.example/assets/halo-mesh.json';
    const d = cond ? "alpha_branch" : "beta_branch";
    const m = `<div>${s} ${"INNER_CANARY_44"}</div>`;
    return m + d + u + String(re.test(s)) + cfg["public-key"];
  }
}
export { Lit, Card };
"#;
        let seed = [0x5au8; 32];
        let out = harden_js_string_literals(sample, &seed);
        assert!(!out.contains("VS_COMMENT_CANARY_9999"), "comment should be stripped");
        assert!(!out.contains("VS_WC3D_SHADER_FORMULA_ALPHA_7721"), "double-quoted secret masked");
        assert!(!out.contains("halo-mesh.json"), "single-quoted asset URL masked");
        assert!(!out.contains("/api/secret-vault"), "object property value string masked");
        assert!(!out.contains("alpha_branch"), "ternary branch string masked");
        assert!(!out.contains("INNER_CANARY_44"), "template interpolation expression string masked");
        assert!(out.contains("\"use strict\";"), "directive preserved");
        assert!(out.contains("from \"./lit.js\""), "ES module specifier preserved");
        assert!(out.contains("\"public-key\":"), "quoted object key preserved");
        assert!(out.contains("/https?:\\/\\/example\\.com\\/[a-z]+/i"), "regex preserved");
        assert!(out.contains("_vsm"), "XOR mask table emitted");
        assert!(out.contains("_vst"), "encoded string table emitted");
        assert!(out.contains("_vsd"), "decoder helper emitted");

        assert!(check_bearer_or_cookie_auth(Some("Bearer top-secret"), None, None, Some("top-secret")));
        assert!(check_bearer_or_cookie_auth(None, Some("top-secret"), None, Some("top-secret")));
        assert!(check_bearer_or_cookie_auth(None, None, Some("foo=1; vs_auth=top-secret; bar=2"), Some("top-secret")));
        assert!(!check_bearer_or_cookie_auth(None, None, Some("vs_auth=wrong"), Some("top-secret")));
        assert!(check_bearer_or_cookie_auth(None, None, None, None));
    }

    #[test]
    fn js_lexer_ctrl_paren_regex_signed_tokens_proxy_and_bound_host() {
        // Regex after control-flow ')' vs division after expression ')'
        let js_src = r#"if (cond && (x > 1)) /foo"bar/.test(s); const y = (a + b) / 2; const z = "SECRET_VAL_42";"#;
        let out = harden_js_string_literals(js_src, &[0x22u8; 32]);
        assert!(out.contains(r#"/foo"bar/.test(s)"#), "regex after if (...) must stay intact: {out}");
        assert!(out.contains("(a + b) / 2"), "division after (...) must stay intact: {out}");
        assert!(!out.contains("SECRET_VAL_42"), "string literal after regex must still be masked: {out}");

        // Length-hiding secret equality
        assert!(ct_secret_eq(b"alpha-secret-token", b"alpha-secret-token"));
        assert!(!ct_secret_eq(b"alpha", b"alpha-secret-token"));

        // Signed buyer tokens
        let key = [0x77u8; 32];
        let tok = mint_signed_auth_token(&key, "buyer_4281", 300).unwrap();
        assert_eq!(verify_signed_auth_token(&key, &tok).as_deref(), Some("buyer_4281"));
        let mut tampered = tok.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'a' { 'b' } else { 'a' });
        assert!(verify_signed_auth_token(&key, &tampered).is_none());
        // Expired token
        let exp_payload = "vs1.buyer_4281.1000";
        let exp_mac = hmac_sha256(&key, exp_payload.as_bytes());
        let exp_tok = format!("{exp_payload}.{}", hex_encode(&exp_mac));
        assert!(verify_signed_auth_token(&key, &exp_tok).is_none());

        // Right-to-left trusted proxy IP resolution (anti-spoof)
        let trusted = parse_trusted_proxies(Some("127.0.0.1,10.0.0.1")).unwrap();
        let proxy_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let direct_ip: IpAddr = "198.51.100.7".parse().unwrap();
        // Direct untrusted peer cannot spoof XFF
        assert_eq!(
            resolve_client_ip(direct_ip, &trusted, Some("203.0.113.9"), None),
            direct_ip
        );
        // Through trusted proxy, spoofed left IP is ignored; real right-most untrusted IP wins
        assert_eq!(
            resolve_client_ip(proxy_ip, &trusted, Some("1.2.3.4, 203.0.113.55, 10.0.0.1"), None),
            "203.0.113.55".parse::<IpAddr>().unwrap()
        );

        // Bound-host validation when --origin is unpinned
        let bound: SocketAddr = "127.0.0.1:8791".parse().unwrap();
        assert!(validate_same_origin(Some("http://127.0.0.1:8791"), Some("127.0.0.1:8791"), None, Some(bound)).is_some());
        assert!(validate_same_origin(Some("http://localhost:8791"), Some("localhost:8791"), None, Some(bound)).is_some());
        assert!(validate_same_origin(Some("http://evil.com"), Some("evil.com"), None, Some(bound)).is_none());
        assert!(validate_same_origin(Some("http://evil.com:8791"), Some("evil.com:8791"), None, Some(bound)).is_none());
        assert!(validate_same_origin(Some("http://127.0.0.1:9999"), Some("127.0.0.1:9999"), None, Some(bound)).is_none());
    }
}
