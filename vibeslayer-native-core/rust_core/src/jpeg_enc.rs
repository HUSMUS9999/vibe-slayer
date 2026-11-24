//! Pure-Rust zero-dependency Baseline JPEG encoder (4:4:4 sampling, 8x8 MCUs).
//!
//! Because every MCU is 8x8 pixels and our scrambled texture tiles (4x4, 8x8, 16x16 on
//! >=128px textures) are exact multiples of 8 pixels, 4:4:4 JPEG encoding produces ZERO
//! cross-tile ringing/bleeding while shrinking opaque 2K/4K PBR textures by ~80-90%.
//! Also powers low-latency 2D frames for server-rendered `--mode stream` 3D viewing.

const ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10,
    17, 24, 32, 25, 18, 11, 4, 5,
    12, 19, 26, 33, 40, 48, 41, 34,
    27, 20, 13, 6, 7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36,
    29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46,
    53, 60, 61, 54, 47, 55, 62, 63,
];

const STD_LUMA_Q: [u8; 64] = [
    16, 11, 10, 16, 24, 40, 51, 61,
    12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77,
    24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101,
    72, 92, 95, 98, 112, 100, 103, 99,
];

const STD_CHROMA_Q: [u8; 64] = [
    17, 18, 24, 47, 99, 99, 99, 99,
    18, 21, 26, 66, 99, 99, 99, 99,
    24, 26, 56, 99, 99, 99, 99, 99,
    47, 66, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
];

// ITU-T T.81 Annex K standard Huffman tables
const DC_LUMA_BITS: [u8; 16] = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0];
const DC_LUMA_VALS: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

const DC_CHROMA_BITS: [u8; 16] = [0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0];
const DC_CHROMA_VALS: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

const AC_LUMA_BITS: [u8; 16] = [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 125];
const AC_LUMA_VALS: [u8; 162] = [
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12,
    0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
    0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08,
    0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0,
    0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0a, 0x16,
    0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
    0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
    0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
    0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
    0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
    0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6,
    0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5,
    0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4,
    0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
    0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea,
    0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa,
];

const AC_CHROMA_BITS: [u8; 16] = [0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 119];
const AC_CHROMA_VALS: [u8; 162] = [
    0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21,
    0x31, 0x06, 0x12, 0x41, 0x51, 0x07, 0x61, 0x71,
    0x13, 0x22, 0x32, 0x81, 0x08, 0x14, 0x42, 0x91,
    0xa1, 0xb1, 0xc1, 0x09, 0x23, 0x33, 0x52, 0xf0,
    0x15, 0x62, 0x72, 0xd1, 0x0a, 0x16, 0x24, 0x34,
    0xe1, 0x25, 0xf1, 0x17, 0x18, 0x19, 0x1a, 0x26,
    0x27, 0x28, 0x29, 0x2a, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
    0x79, 0x7a, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x92, 0x93, 0x94, 0x95, 0x96,
    0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5,
    0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4,
    0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3,
    0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2,
    0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
    0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
    0xea, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa,
];

fn build_huff_lut(bits: &[u8; 16], vals: &[u8]) -> [(u16, u8); 256] {
    let mut lut = [(0u16, 0u8); 256];
    let mut code: u16 = 0;
    let mut idx = 0usize;
    for len in 1..=16u8 {
        let count = bits[(len - 1) as usize] as usize;
        for _ in 0..count {
            let sym = vals[idx] as usize;
            lut[sym] = (code, len);
            code = code.wrapping_add(1);
            idx += 1;
        }
        code <<= 1;
    }
    lut
}

fn scale_qtable(base: &[u8; 64], quality: u8) -> [u8; 64] {
    let q = quality.clamp(1, 100) as i32;
    let scale = if q < 50 { 5000 / q } else { 200 - q * 2 };
    let mut out = [1u8; 64];
    for i in 0..64 {
        let v = ((base[i] as i32) * scale + 50) / 100;
        out[i] = v.clamp(1, 255) as u8;
    }
    out
}

struct JpegBitWriter<'a> {
    out: &'a mut Vec<u8>,
    bit_buf: u32,
    bit_cnt: u32,
}

impl<'a> JpegBitWriter<'a> {
    #[inline(always)]
    fn write_bits(&mut self, val: u32, n: u32) {
        self.bit_buf = (self.bit_buf << n) | (val & ((1u32 << n) - 1));
        self.bit_cnt += n;
        while self.bit_cnt >= 8 {
            self.bit_cnt -= 8;
            let b = ((self.bit_buf >> self.bit_cnt) & 0xff) as u8;
            self.out.push(b);
            if b == 0xff {
                self.out.push(0x00);
            }
        }
    }

    fn flush(&mut self) {
        if self.bit_cnt > 0 {
            let pad = 8 - self.bit_cnt;
            self.write_bits((1u32 << pad) - 1, pad);
        }
    }
}

/// Fast AAN 1D + 2D Forward DCT scaled by `1 / (8 * a_u * a_v * Q[u,v])`!
const AAN_SCALE: [f32; 8] = [
    1.0,
    1.387_039_9,
    1.306_563_0,
    1.175_875_6,
    1.0,
    0.785_694_96,
    0.541_196_1,
    0.275_899_38,
];

fn build_fdct_inv_q(qtable: &[u8; 64]) -> [f32; 64] {
    let mut inv = [0.0f32; 64];
    for r in 0..8 {
        for c in 0..8 {
            let idx = r * 8 + c;
            inv[idx] = 1.0 / (8.0 * AAN_SCALE[r] * AAN_SCALE[c] * (qtable[idx] as f32));
        }
    }
    inv
}

#[inline(always)]
fn aan_fdct_8x8(d: &mut [f32; 64]) {
    // Pass 1: rows
    for r in 0..8 {
        let i = r * 8;
        let tmp0 = d[i] + d[i + 7];
        let tmp7 = d[i] - d[i + 7];
        let tmp1 = d[i + 1] + d[i + 6];
        let tmp6 = d[i + 1] - d[i + 6];
        let tmp2 = d[i + 2] + d[i + 5];
        let tmp5 = d[i + 2] - d[i + 5];
        let tmp3 = d[i + 3] + d[i + 4];
        let tmp4 = d[i + 3] - d[i + 4];

        let tmp10 = tmp0 + tmp3;
        let tmp13 = tmp0 - tmp3;
        let tmp11 = tmp1 + tmp2;
        let tmp12 = tmp1 - tmp2;

        d[i] = tmp10 + tmp11;
        d[i + 4] = tmp10 - tmp11;
        let z1 = (tmp12 + tmp13) * 0.707_106_78;
        d[i + 2] = tmp13 + z1;
        d[i + 6] = tmp13 - z1;

        let tmp10 = tmp4 + tmp5;
        let tmp11 = tmp5 + tmp6;
        let tmp12 = tmp6 + tmp7;
        let z5 = (tmp10 - tmp12) * 0.382_683_43;
        let z2 = 0.541_196_1 * tmp10 + z5;
        let z4 = 1.306_563_0 * tmp12 + z5;
        let z3 = tmp11 * 0.707_106_78;
        let z11 = tmp7 + z3;
        let z13 = tmp7 - z3;

        d[i + 5] = z13 + z2;
        d[i + 3] = z13 - z2;
        d[i + 1] = z11 + z4;
        d[i + 7] = z11 - z4;
    }
    // Pass 2: columns
    for c in 0..8 {
        let tmp0 = d[c] + d[56 + c];
        let tmp7 = d[c] - d[56 + c];
        let tmp1 = d[8 + c] + d[48 + c];
        let tmp6 = d[8 + c] - d[48 + c];
        let tmp2 = d[16 + c] + d[40 + c];
        let tmp5 = d[16 + c] - d[40 + c];
        let tmp3 = d[24 + c] + d[32 + c];
        let tmp4 = d[24 + c] - d[32 + c];

        let tmp10 = tmp0 + tmp3;
        let tmp13 = tmp0 - tmp3;
        let tmp11 = tmp1 + tmp2;
        let tmp12 = tmp1 - tmp2;

        d[c] = tmp10 + tmp11;
        d[32 + c] = tmp10 - tmp11;
        let z1 = (tmp12 + tmp13) * 0.707_106_78;
        d[16 + c] = tmp13 + z1;
        d[48 + c] = tmp13 - z1;

        let tmp10 = tmp4 + tmp5;
        let tmp11 = tmp5 + tmp6;
        let tmp12 = tmp6 + tmp7;
        let z5 = (tmp10 - tmp12) * 0.382_683_43;
        let z2 = 0.541_196_1 * tmp10 + z5;
        let z4 = 1.306_563_0 * tmp12 + z5;
        let z3 = tmp11 * 0.707_106_78;
        let z11 = tmp7 + z3;
        let z13 = tmp7 - z3;

        d[40 + c] = z13 + z2;
        d[24 + c] = z13 - z2;
        d[8 + c] = z11 + z4;
        d[56 + c] = z11 - z4;
    }
}

#[inline(always)]
fn bit_size_and_code(v: i32) -> (u32, u32) {
    let abs_v = v.unsigned_abs();
    if abs_v == 0 {
        return (0, 0);
    }
    let n = 32 - abs_v.leading_zeros();
    let bits = if v > 0 {
        abs_v
    } else {
        ((1u32 << n) - 1) - abs_v
    };
    (n, bits)
}

#[inline(always)]
fn encode_du(
    bw: &mut JpegBitWriter,
    block: &mut [f32; 64],
    inv_q: &[f32; 64],
    dc_lut: &[(u16, u8); 256],
    ac_lut: &[(u16, u8); 256],
    prev_dc: &mut i32,
) {
    aan_fdct_8x8(block);
    let mut zz = [0i32; 64];
    for i in 0..64 {
        let k = ZIGZAG[i];
        let v = block[k] * inv_q[k];
        zz[i] = if v >= 0.0 { (v + 0.5) as i32 } else { (v - 0.5) as i32 };
    }

    // DC coefficient
    let diff = zz[0] - *prev_dc;
    *prev_dc = zz[0];
    let (dc_n, dc_bits) = bit_size_and_code(diff);
    let (hc, hl) = dc_lut[dc_n.min(11) as usize];
    bw.write_bits(hc as u32, hl as u32);
    if dc_n > 0 {
        bw.write_bits(dc_bits, dc_n);
    }

    // AC coefficients
    let mut last_nz = 63usize;
    while last_nz > 0 && zz[last_nz] == 0 {
        last_nz -= 1;
    }
    if last_nz == 0 {
        let (eob_c, eob_l) = ac_lut[0x00];
        bw.write_bits(eob_c as u32, eob_l as u32);
        return;
    }

    let mut i = 1usize;
    while i <= last_nz {
        let mut run = 0usize;
        while i <= last_nz && zz[i] == 0 {
            run += 1;
            i += 1;
        }
        while run >= 16 {
            let (zrl_c, zrl_l) = ac_lut[0xf0];
            bw.write_bits(zrl_c as u32, zrl_l as u32);
            run -= 16;
        }
        let val = zz[i];
        let (ac_n, ac_bits) = bit_size_and_code(val);
        let sym = ((run as usize) << 4) | (ac_n.min(10) as usize);
        let (hc, hl) = ac_lut[sym];
        bw.write_bits(hc as u32, hl as u32);
        bw.write_bits(ac_bits, ac_n.min(10));
        i += 1;
    }
    if last_nz < 63 {
        let (eob_c, eob_l) = ac_lut[0x00];
        bw.write_bits(eob_c as u32, eob_l as u32);
    }
}

fn write_dqt(out: &mut Vec<u8>, id: u8, qtable: &[u8; 64]) {
    out.extend_from_slice(&[0xff, 0xdb, 0x00, 67, id]);
    for &z in &ZIGZAG {
        out.push(qtable[z]);
    }
}

fn write_dht(out: &mut Vec<u8>, tc_th: u8, bits: &[u8; 16], vals: &[u8]) {
    let len = (2 + 1 + 16 + vals.len()) as u16;
    out.extend_from_slice(&[0xff, 0xc4]);
    out.extend_from_slice(&len.to_be_bytes());
    out.push(tc_th);
    out.extend_from_slice(bits);
    out.extend_from_slice(vals);
}

/// Encodes an RGB or RGBA pixel buffer (`channels == 3` or `4`, ignoring alpha) into
/// a valid JFIF Baseline 4:4:4 JPEG (`quality` in `1..=100`).
pub fn encode_jpeg(width: usize, height: usize, channels: usize, pixels: &[u8], quality: u8) -> Vec<u8> {
    assert!(channels == 3 || channels == 4);
    assert!(width > 0 && height > 0 && width <= 65535 && height <= 65535);
    assert!(pixels.len() >= width * height * channels);

    let q_luma = scale_qtable(&STD_LUMA_Q, quality);
    let q_chroma = scale_qtable(&STD_CHROMA_Q, quality);
    let inv_q_luma = build_fdct_inv_q(&q_luma);
    let inv_q_chroma = build_fdct_inv_q(&q_chroma);

    let dc_luma_lut = build_huff_lut(&DC_LUMA_BITS, &DC_LUMA_VALS);
    let dc_chroma_lut = build_huff_lut(&DC_CHROMA_BITS, &DC_CHROMA_VALS);
    let ac_luma_lut = build_huff_lut(&AC_LUMA_BITS, &AC_LUMA_VALS);
    let ac_chroma_lut = build_huff_lut(&AC_CHROMA_BITS, &AC_CHROMA_VALS);

    let mut out = Vec::with_capacity((width * height / 6).max(4096));

    // SOI + APP0 (JFIF 1.01)
    out.extend_from_slice(&[
        0xff, 0xd8,
        0xff, 0xe0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    ]);

    // DQT (0 = luma, 1 = chroma)
    write_dqt(&mut out, 0, &q_luma);
    write_dqt(&mut out, 1, &q_chroma);

    // SOF0 (Baseline DCT, 8-bit, 3 components, 4:4:4 sampling 0x11)
    out.extend_from_slice(&[0xff, 0xc0, 0x00, 17, 8]);
    out.extend_from_slice(&(height as u16).to_be_bytes());
    out.extend_from_slice(&(width as u16).to_be_bytes());
    out.extend_from_slice(&[
        3,
        1, 0x11, 0, // Y
        2, 0x11, 1, // Cb
        3, 0x11, 1, // Cr
    ]);

    // DHT (DC0, AC0, DC1, AC1)
    write_dht(&mut out, 0x00, &DC_LUMA_BITS, &DC_LUMA_VALS);
    write_dht(&mut out, 0x10, &AC_LUMA_BITS, &AC_LUMA_VALS);
    write_dht(&mut out, 0x01, &DC_CHROMA_BITS, &DC_CHROMA_VALS);
    write_dht(&mut out, 0x11, &AC_CHROMA_BITS, &AC_CHROMA_VALS);

    // SOS
    out.extend_from_slice(&[
        0xff, 0xda, 0x00, 12,
        3,
        1, 0x00,
        2, 0x11,
        3, 0x11,
        0x00, 0x3f, 0x00,
    ]);

    let mut bw = JpegBitWriter {
        out: &mut out,
        bit_buf: 0,
        bit_cnt: 0,
    };
    let mut prev_y = 0i32;
    let mut prev_cb = 0i32;
    let mut prev_cr = 0i32;
    let mut by = [0.0f32; 64];
    let mut bcb = [0.0f32; 64];
    let mut bcr = [0.0f32; 64];

    let stride = width * channels;
    let mcu_y_cnt = (height + 7) / 8;
    let mcu_x_cnt = (width + 7) / 8;

    for my in 0..mcu_y_cnt {
        let base_y = my * 8;
        for mx in 0..mcu_x_cnt {
            let base_x = mx * 8;
            for ly in 0..8 {
                let sy = (base_y + ly).min(height - 1) * stride;
                let row = ly * 8;
                for lx in 0..8 {
                    let sx = (base_x + lx).min(width - 1) * channels;
                    let off = sy + sx;
                    let r = pixels[off] as f32;
                    let g = pixels[off + 1] as f32;
                    let b = pixels[off + 2] as f32;
                    by[row + lx] = 0.299 * r + 0.587 * g + 0.114 * b - 128.0;
                    bcb[row + lx] = -0.168_736 * r - 0.331_264 * g + 0.5 * b;
                    bcr[row + lx] = 0.5 * r - 0.418_688 * g - 0.081_312 * b;
                }
            }
            encode_du(&mut bw, &mut by, &inv_q_luma, &dc_luma_lut, &ac_luma_lut, &mut prev_y);
            encode_du(&mut bw, &mut bcb, &inv_q_chroma, &dc_chroma_lut, &ac_chroma_lut, &mut prev_cb);
            encode_du(&mut bw, &mut bcr, &inv_q_chroma, &dc_chroma_lut, &ac_chroma_lut, &mut prev_cr);
        }
    }

    bw.flush();
    // EOI
    out.extend_from_slice(&[0xff, 0xd9]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_444_jpeg_encodes_valid_jfif_and_compresses() {
        let w = 128usize;
        let h = 128usize;
        let mut rgb = vec![0u8; w * h * 3];
        for y in 0..h {
            for x in 0..w {
                let off = (y * w + x) * 3;
                rgb[off] = ((x * 2) & 0xff) as u8;
                rgb[off + 1] = ((y * 2) & 0xff) as u8;
                rgb[off + 2] = ((x + y) & 0xff) as u8;
            }
        }
        let jpg = encode_jpeg(w, h, 3, &rgb, 88);
        assert!(jpg.starts_with(&[0xff, 0xd8, 0xff, 0xe0]));
        assert!(jpg.ends_with(&[0xff, 0xd9]));
        assert!(jpg.len() < rgb.len() / 5, "expected >5x compression, got {} vs {}", jpg.len(), rgb.len());
    }
}
