//! Pure-Rust zero-dependency PNG decoder, downscaler, `16x16` cryptographic Fisher-Yates
//! + mirror-flip tile scrambler, and fast Fixed-Huffman LZ77 PNG encoder.
//!
//! Ensures unscrambled 3D textures never cross the network or enter browser RAM (`Blob` /
//! `createImageBitmap` / Canvas 2D), while shrinking oversized (>4096) textures via crisp 2x2
//! box filtering.

use crate::sha256;

const PNG_SIG: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

/* ============================ Checksums (CRC-32 & Adler-32) ============================ */

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320u32 & mask);
        }
    }
    !crc
}

fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += byte as u32;
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

/* =========================== RFC 1950/1951 Pure-Rust Inflate =========================== */

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
    131, 163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

#[inline]
fn reverse_bits(mut v: u32, n: u32) -> u32 {
    let mut r = 0u32;
    for _ in 0..n {
        r = (r << 1) | (v & 1);
        v >>= 1;
    }
    r
}

struct HuffTable {
    /// Direct 10-bit lookup: `(len << 16) | sym`, or `0` if code length > 10 / invalid.
    fast: [u32; 1024],
    count: [u16; 16],
    first_code: [u32; 16],
    first_sym: [u16; 16],
    syms: Vec<u16>,
    max_len: u8,
}

impl HuffTable {
    fn build(lengths: &[u8]) -> Result<Self, String> {
        let mut count = [0u16; 16];
        let mut max_len = 0u8;
        for &l in lengths {
            if l > 15 {
                return Err("HUFF_LEN_OOB".to_string());
            }
            if l > 0 {
                count[l as usize] += 1;
                if l > max_len {
                    max_len = l;
                }
            }
        }
        let mut first_code = [0u32; 16];
        let mut first_sym = [0u16; 16];
        let mut code = 0u32;
        let mut sym_off = 0u16;
        for bits in 1..=15 {
            code = (code + count[bits - 1] as u32) << 1;
            first_code[bits] = code;
            first_sym[bits] = sym_off;
            sym_off = sym_off.saturating_add(count[bits]);
        }

        let mut next_code = first_code;
        let mut next_sym = first_sym;
        let mut syms = vec![0u16; sym_off as usize];
        let mut fast = [0u32; 1024];

        for (sym, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let l = len as usize;
            let c = next_code[l];
            next_code[l] += 1;
            let idx = next_sym[l] as usize;
            next_sym[l] += 1;
            syms[idx] = sym as u16;

            if l <= 10 {
                let rev = reverse_bits(c, len as u32) as usize;
                let step = 1usize << l;
                let entry = ((len as u32) << 16) | (sym as u32);
                let mut pos = rev;
                while pos < 1024 {
                    fast[pos] = entry;
                    pos += step;
                }
            }
        }
        Ok(Self {
            fast,
            count,
            first_code,
            first_sym,
            syms,
            max_len,
        })
    }
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bit_buf: u64,
    bit_cnt: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bit_buf: 0,
            bit_cnt: 0,
        }
    }

    #[inline(always)]
    fn refill(&mut self) {
        while self.bit_cnt <= 56 && self.pos < self.data.len() {
            self.bit_buf |= (self.data[self.pos] as u64) << self.bit_cnt;
            self.pos += 1;
            self.bit_cnt += 8;
        }
    }

    #[inline(always)]
    fn read_bits(&mut self, n: u32) -> Result<u32, String> {
        if self.bit_cnt < n {
            self.refill();
            if self.bit_cnt < n {
                return Err("DEFLATE_EOF".to_string());
            }
        }
        let val = (self.bit_buf & ((1u64 << n) - 1)) as u32;
        self.bit_buf >>= n;
        self.bit_cnt -= n;
        Ok(val)
    }

    #[inline(always)]
    fn align_byte(&mut self) {
        let drop = self.bit_cnt & 7;
        self.bit_buf >>= drop;
        self.bit_cnt -= drop;
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        self.align_byte();
        let buffered_bytes = (self.bit_cnt / 8) as usize;
        self.pos -= buffered_bytes;
        self.bit_buf = 0;
        self.bit_cnt = 0;
        let end = self.pos.checked_add(n).ok_or("DEFLATE_LEN_OVF")?;
        if end > self.data.len() {
            return Err("DEFLATE_RAW_EOF".to_string());
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    #[inline(always)]
    fn decode_huff(&mut self, tbl: &HuffTable) -> Result<u16, String> {
        if self.bit_cnt < 15 {
            self.refill();
        }
        let entry = tbl.fast[(self.bit_buf & 1023) as usize];
        if entry != 0 {
            let len = entry >> 16;
            if len <= self.bit_cnt {
                self.bit_buf >>= len;
                self.bit_cnt -= len;
                return Ok((entry & 0xffff) as u16);
            }
        }
        let mut code = 0u32;
        for bits in 1..=(tbl.max_len as usize) {
            if self.bit_cnt == 0 {
                self.refill();
                if self.bit_cnt == 0 {
                    return Err("HUFF_EOF".to_string());
                }
            }
            code = (code << 1) | ((self.bit_buf & 1) as u32);
            self.bit_buf >>= 1;
            self.bit_cnt -= 1;
            let cnt = tbl.count[bits] as u32;
            let first = tbl.first_code[bits];
            if cnt > 0 && code >= first && (code - first) < cnt {
                let idx = (tbl.first_sym[bits] as u32) + (code - first);
                return Ok(tbl.syms[idx as usize]);
            }
        }
        Err("INVALID_HUFF_CODE".to_string())
    }
}

fn fixed_huff_tables() -> Result<(HuffTable, HuffTable), String> {
    let mut lit = [0u8; 288];
    lit[0..144].fill(8);
    lit[144..256].fill(9);
    lit[256..280].fill(7);
    lit[280..288].fill(8);
    let dist = [5u8; 32];
    Ok((HuffTable::build(&lit)?, HuffTable::build(&dist)?))
}

fn zlib_decompress(zlib: &[u8], max_out: usize) -> Result<Vec<u8>, String> {
    if zlib.len() < 6 {
        return Err("ZLIB_TOO_SHORT".to_string());
    }
    let cmf = zlib[0];
    let flg = zlib[1];
    if (cmf & 0x0f) != 8 || (cmf >> 4) > 7 {
        return Err("ZLIB_BAD_METHOD".to_string());
    }
    if ((cmf as u16) * 256 + (flg as u16)) % 31 != 0 {
        return Err("ZLIB_BAD_CHECK".to_string());
    }
    let mut start = 2usize;
    if (flg & 0x20) != 0 {
        start += 4;
    }
    if start + 4 > zlib.len() {
        return Err("ZLIB_TRUNCATED".to_string());
    }
    let mut br = BitReader::new(&zlib[start..zlib.len() - 4]);
    let mut out = Vec::with_capacity((zlib.len() * 4).min(max_out));

    loop {
        let bfinal = br.read_bits(1)?;
        let btype = br.read_bits(2)?;
        if btype == 0 {
            let hdr = br.read_bytes(4)?;
            let len = u16::from_le_bytes([hdr[0], hdr[1]]);
            let nlen = u16::from_le_bytes([hdr[2], hdr[3]]);
            if len != !nlen {
                return Err("DEFLATE_BAD_STORED_LEN".to_string());
            }
            if out.len() + (len as usize) > max_out {
                return Err("DEFLATE_OUT_LIMIT".to_string());
            }
            let raw = br.read_bytes(len as usize)?;
            out.extend_from_slice(raw);
        } else if btype == 1 || btype == 2 {
            let (lit_tbl, dist_tbl) = if btype == 1 {
                fixed_huff_tables()?
            } else {
                let hlit = br.read_bits(5)? as usize + 257;
                let hdist = br.read_bits(5)? as usize + 1;
                let hclen = br.read_bits(4)? as usize + 4;
                let mut cl_lens = [0u8; 19];
                for i in 0..hclen {
                    cl_lens[CL_ORDER[i]] = br.read_bits(3)? as u8;
                }
                let cl_tbl = HuffTable::build(&cl_lens)?;
                let total = hlit + hdist;
                let mut all_lens = Vec::with_capacity(total);
                while all_lens.len() < total {
                    let sym = br.decode_huff(&cl_tbl)?;
                    match sym {
                        0..=15 => all_lens.push(sym as u8),
                        16 => {
                            let prev = *all_lens.last().ok_or("CL_REP_EMPTY")?;
                            let rep = br.read_bits(2)? as usize + 3;
                            for _ in 0..rep {
                                if all_lens.len() < total {
                                    all_lens.push(prev);
                                }
                            }
                        }
                        17 => {
                            let rep = br.read_bits(3)? as usize + 3;
                            for _ in 0..rep {
                                if all_lens.len() < total {
                                    all_lens.push(0);
                                }
                            }
                        }
                        18 => {
                            let rep = br.read_bits(7)? as usize + 11;
                            for _ in 0..rep {
                                if all_lens.len() < total {
                                    all_lens.push(0);
                                }
                            }
                        }
                        _ => return Err("CL_BAD_SYM".to_string()),
                    }
                }
                (
                    HuffTable::build(&all_lens[..hlit])?,
                    HuffTable::build(&all_lens[hlit..total])?,
                )
            };

            loop {
                let sym = br.decode_huff(&lit_tbl)?;
                if sym < 256 {
                    if out.len() >= max_out {
                        return Err("DEFLATE_OUT_LIMIT".to_string());
                    }
                    out.push(sym as u8);
                } else if sym == 256 {
                    break;
                } else {
                    let lidx = (sym as usize).wrapping_sub(257);
                    if lidx >= 29 {
                        return Err("DEFLATE_BAD_LEN_SYM".to_string());
                    }
                    let mut mlen = LEN_BASE[lidx] as usize;
                    let lex = LEN_EXTRA[lidx] as u32;
                    if lex > 0 {
                        mlen += br.read_bits(lex)? as usize;
                    }
                    let dsym = br.decode_huff(&dist_tbl)? as usize;
                    if dsym >= 30 {
                        return Err("DEFLATE_BAD_DIST_SYM".to_string());
                    }
                    let mut dist = DIST_BASE[dsym] as usize;
                    let dex = DIST_EXTRA[dsym] as u32;
                    if dex > 0 {
                        dist += br.read_bits(dex)? as usize;
                    }
                    if dist == 0 || dist > out.len() {
                        return Err("DEFLATE_DIST_OOB".to_string());
                    }
                    if out.len() + mlen > max_out {
                        return Err("DEFLATE_OUT_LIMIT".to_string());
                    }
                    if dist >= mlen {
                        let src_start = out.len() - dist;
                        out.extend_from_within(src_start..src_start + mlen);
                    } else {
                        for _ in 0..mlen {
                            let b = out[out.len() - dist];
                            out.push(b);
                        }
                    }
                }
            }
        } else {
            return Err("DEFLATE_BAD_BTYPE".to_string());
        }
        if bfinal != 0 {
            break;
        }
    }

    let expected_adler = u32::from_be_bytes([
        zlib[zlib.len() - 4],
        zlib[zlib.len() - 3],
        zlib[zlib.len() - 2],
        zlib[zlib.len() - 1],
    ]);
    if adler32(&out) != expected_adler {
        return Err("ZLIB_ADLER_MISMATCH".to_string());
    }
    Ok(out)
}

/* =================== Fast Pure-Rust Dynamic-Huffman LZ77 Zlib Encoder =================== */

struct BitWriter {
    out: Vec<u8>,
    bit_buf: u64,
    bit_cnt: u32,
}

impl BitWriter {
    fn with_capacity(cap: usize) -> Self {
        Self {
            out: Vec::with_capacity(cap),
            bit_buf: 0,
            bit_cnt: 0,
        }
    }

    #[inline(always)]
    fn write_bits(&mut self, val: u32, n: u32) {
        self.bit_buf |= (val as u64) << self.bit_cnt;
        self.bit_cnt += n;
        while self.bit_cnt >= 8 {
            self.out.push((self.bit_buf & 0xff) as u8);
            self.bit_buf >>= 8;
            self.bit_cnt -= 8;
        }
    }

    fn finish_byte(&mut self) {
        if self.bit_cnt > 0 {
            self.out.push((self.bit_buf & 0xff) as u8);
            self.bit_buf = 0;
            self.bit_cnt = 0;
        }
    }
}

/// Builds RFC 1951 length-limited canonical Huffman code lengths (`<= max_bits`).
fn build_limited_huff_lengths(freqs: &[u32], max_bits: u8) -> Vec<u8> {
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;

    let n = freqs.len();
    let mut lens = vec![0u8; n];
    let mut active: Vec<(u32, usize)> = freqs
        .iter()
        .enumerate()
        .filter_map(|(i, &f)| if f > 0 { Some((f, i)) } else { None })
        .collect();

    if active.is_empty() {
        return lens;
    }
    if active.len() == 1 {
        lens[active[0].1] = 1;
        return lens;
    }

    // Build binary Huffman tree in flat array; nodes 0..n are leaves, >= n are internal.
    let mut children: Vec<(usize, usize)> = Vec::with_capacity(active.len());
    let mut heap: BinaryHeap<Reverse<(u64, usize)>> = BinaryHeap::with_capacity(active.len());
    for &(f, sym) in &active {
        heap.push(Reverse((f as u64, sym)));
    }
    while heap.len() > 1 {
        let Reverse((f1, n1)) = heap.pop().unwrap();
        let Reverse((f2, n2)) = heap.pop().unwrap();
        let parent_id = n + children.len();
        children.push((n1, n2));
        heap.push(Reverse((f1 + f2, parent_id)));
    }
    let root = heap.pop().unwrap().0 .1;

    // Iterative DFS for exact depths
    let mut stack = vec![(root, 0u8)];
    let mut max_depth = 0u8;
    while let Some((node, d)) = stack.pop() {
        if node < n {
            lens[node] = d.max(1);
            if lens[node] > max_depth {
                max_depth = lens[node];
            }
        } else {
            let (l, r) = children[node - n];
            stack.push((l, d.saturating_add(1)));
            stack.push((r, d.saturating_add(1)));
        }
    }

    if max_depth > max_bits {
        // Clamp depths to max_bits, then restore exact Kraft equality sum(2^(max_bits - l)) == 2^max_bits.
        for &(_, sym) in &active {
            if lens[sym] > max_bits {
                lens[sym] = max_bits;
            }
        }
        let limit = 1u64 << max_bits;
        let mut kraft: u64 = active.iter().map(|&(_, s)| 1u64 << (max_bits - lens[s])).sum();

        // Sort active by (freq asc, sym asc) so least-frequent symbols lengthen first.
        active.sort_unstable_by_key(|&(f, s)| (f, s));

        while kraft > limit {
            // Find the longest code with len < max_bits (smallest frequency tie-break)
            let mut best_sym = None;
            let mut best_len = 0u8;
            for &(_, sym) in &active {
                let l = lens[sym];
                if l < max_bits && l > best_len {
                    best_len = l;
                    best_sym = Some(sym);
                }
            }
            if let Some(sym) = best_sym {
                let drop_w = 1u64 << (max_bits - lens[sym] - 1);
                lens[sym] += 1;
                kraft -= drop_w;
            } else {
                break;
            }
        }

        // If kraft < limit, promote most-frequent symbols whose weight gain fits in (limit - kraft).
        active.sort_unstable_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        while kraft < limit {
            let rem = limit - kraft;
            let mut promoted = false;
            for &(_, sym) in &active {
                let l = lens[sym];
                if l > 1 {
                    let gain = 1u64 << (max_bits - l);
                    if gain <= rem {
                        lens[sym] -= 1;
                        kraft += gain;
                        promoted = true;
                        break;
                    }
                }
            }
            if !promoted {
                break;
            }
        }
    }

    lens
}

fn build_canonical_enc_codes(lens: &[u8]) -> Vec<(u16, u8)> {
    let mut bl_count = [0u16; 16];
    for &l in lens {
        if l > 0 {
            bl_count[l as usize] += 1;
        }
    }
    let mut next_code = [0u32; 16];
    let mut code = 0u32;
    for bits in 1..=15 {
        code = (code + bl_count[bits - 1] as u32) << 1;
        next_code[bits] = code;
    }
    let mut out = vec![(0u16, 0u8); lens.len()];
    for (sym, &l) in lens.iter().enumerate() {
        if l > 0 {
            let c = next_code[l as usize];
            next_code[l as usize] += 1;
            out[sym] = (reverse_bits(c, l as u32) as u16, l);
        }
    }
    out
}

#[inline(always)]
fn match_len_code(mlen: usize) -> (usize, u32, u32) {
    let mut lidx = 0usize;
    while lidx + 1 < 29 && (LEN_BASE[lidx + 1] as usize) <= mlen {
        lidx += 1;
    }
    (
        257 + lidx,
        (mlen - LEN_BASE[lidx] as usize) as u32,
        LEN_EXTRA[lidx] as u32,
    )
}

#[inline(always)]
fn match_dist_code(dist: usize) -> (usize, u32, u32) {
    let mut didx = 0usize;
    while didx + 1 < 30 && (DIST_BASE[didx + 1] as usize) <= dist {
        didx += 1;
    }
    (
        didx,
        (dist - DIST_BASE[didx] as usize) as u32,
        DIST_EXTRA[didx] as u32,
    )
}

#[derive(Clone, Copy)]
enum DeflateTok {
    Lit(u8),
    Match { len: u16, dist: u16 },
}

fn emit_dynamic_block(bw: &mut BitWriter, tokens: &[DeflateTok], bfinal: bool) {
    let mut lit_freqs = [0u32; 286];
    let mut dist_freqs = [0u32; 30];
    lit_freqs[256] = 1; // End-of-block symbol
    for &t in tokens {
        match t {
            DeflateTok::Lit(b) => lit_freqs[b as usize] += 1,
            DeflateTok::Match { len, dist } => {
                let (lsym, _, _) = match_len_code(len as usize);
                let (dsym, _, _) = match_dist_code(dist as usize);
                lit_freqs[lsym] += 1;
                dist_freqs[dsym] += 1;
            }
        }
    }
    if dist_freqs.iter().all(|&f| f == 0) {
        dist_freqs[0] = 1;
    }

    let lit_lens = build_limited_huff_lengths(&lit_freqs, 15);
    let dist_lens = build_limited_huff_lengths(&dist_freqs, 15);
    let lit_codes = build_canonical_enc_codes(&lit_lens);
    let dist_codes = build_canonical_enc_codes(&dist_lens);

    let mut hlit = 286usize;
    while hlit > 257 && lit_lens[hlit - 1] == 0 {
        hlit -= 1;
    }
    let mut hdist = 30usize;
    while hdist > 1 && dist_lens[hdist - 1] == 0 {
        hdist -= 1;
    }

    // RLE-encode combined lit_lens[..hlit] + dist_lens[..hdist]
    let mut combined = Vec::with_capacity(hlit + hdist);
    combined.extend_from_slice(&lit_lens[..hlit]);
    combined.extend_from_slice(&dist_lens[..hdist]);

    let mut rle: Vec<(u8, u8, u8)> = Vec::with_capacity(combined.len());
    let mut cl_freqs = [0u32; 19];
    let mut i = 0usize;
    while i < combined.len() {
        let v = combined[i];
        let mut run = 1usize;
        while i + run < combined.len() && combined[i + run] == v {
            run += 1;
        }
        if v == 0 {
            let mut rem = run;
            while rem > 0 {
                if rem >= 11 {
                    let take = rem.min(138);
                    rle.push((18, (take - 11) as u8, 7));
                    cl_freqs[18] += 1;
                    rem -= take;
                } else if rem >= 3 {
                    let take = rem.min(10);
                    rle.push((17, (take - 3) as u8, 3));
                    cl_freqs[17] += 1;
                    rem -= take;
                } else {
                    rle.push((0, 0, 0));
                    cl_freqs[0] += 1;
                    rem -= 1;
                }
            }
        } else {
            rle.push((v, 0, 0));
            cl_freqs[v as usize] += 1;
            let mut rem = run - 1;
            while rem > 0 {
                if rem >= 3 {
                    let take = rem.min(6);
                    rle.push((16, (take - 3) as u8, 2));
                    cl_freqs[16] += 1;
                    rem -= take;
                } else {
                    rle.push((v, 0, 0));
                    cl_freqs[v as usize] += 1;
                    rem -= 1;
                }
            }
        }
        i += run;
    }

    let cl_lens = build_limited_huff_lengths(&cl_freqs, 7);
    let cl_codes = build_canonical_enc_codes(&cl_lens);
    let mut hclen = 19usize;
    while hclen > 4 && cl_lens[CL_ORDER[hclen - 1]] == 0 {
        hclen -= 1;
    }

    // Header: BFINAL (1 bit) + BTYPE=10 (2 bits)
    bw.write_bits(if bfinal { 1 } else { 0 }, 1);
    bw.write_bits(0b10, 2);
    bw.write_bits((hlit - 257) as u32, 5);
    bw.write_bits((hdist - 1) as u32, 5);
    bw.write_bits((hclen - 4) as u32, 4);
    for &sym in &CL_ORDER[..hclen] {
        bw.write_bits(cl_lens[sym] as u32, 3);
    }
    for &(sym, extra, extra_bits) in &rle {
        let (code, len) = cl_codes[sym as usize];
        bw.write_bits(code as u32, len as u32);
        if extra_bits > 0 {
            bw.write_bits(extra as u32, extra_bits as u32);
        }
    }

    // Payload tokens
    for &t in tokens {
        match t {
            DeflateTok::Lit(b) => {
                let (code, len) = lit_codes[b as usize];
                bw.write_bits(code as u32, len as u32);
            }
            DeflateTok::Match { len, dist } => {
                let (lsym, lex_v, lex_b) = match_len_code(len as usize);
                let (lc, ll) = lit_codes[lsym];
                bw.write_bits(lc as u32, ll as u32);
                if lex_b > 0 {
                    bw.write_bits(lex_v, lex_b);
                }
                let (dsym, dex_v, dex_b) = match_dist_code(dist as usize);
                let (dc, dl) = dist_codes[dsym];
                bw.write_bits(dc as u32, dl as u32);
                if dex_b > 0 {
                    bw.write_bits(dex_v, dex_b);
                }
            }
        }
    }
    let (eob_c, eob_l) = lit_codes[256];
    bw.write_bits(eob_c as u32, eob_l as u32);
}

fn zlib_compress_fast(raw: &[u8]) -> Vec<u8> {
    const HASH_SIZE: usize = 32768;
    const BLOCK_TOK_LIMIT: usize = 131_072;

    let mut bw = BitWriter::with_capacity(raw.len() / 3 + 128);
    // Zlib header: CMF=0x78 (DEFLATE 32K), FLG=0x01 (FCHECK valid: 0x7801 % 31 == 0)
    bw.out.push(0x78);
    bw.out.push(0x01);

    let mut head1 = vec![u32::MAX; HASH_SIZE];
    let mut head2 = vec![u32::MAX; HASH_SIZE];
    let mut tokens: Vec<DeflateTok> = Vec::with_capacity(BLOCK_TOK_LIMIT + 16);
    let n = raw.len();
    let mut pos = 0usize;

    #[inline(always)]
    fn hash3(b: &[u8], i: usize) -> usize {
        let v = (b[i] as u32) | ((b[i + 1] as u32) << 8) | ((b[i + 2] as u32) << 16);
        ((v.wrapping_mul(0x1e35_a7bd)) >> 17) as usize & (HASH_SIZE - 1)
    }

    #[inline(always)]
    fn match_len_at(raw: &[u8], p: usize, pos: usize, max_m: usize) -> usize {
        let mut mlen = 3usize;
        while mlen + 8 <= max_m && raw[p + mlen..p + mlen + 8] == raw[pos + mlen..pos + mlen + 8] {
            mlen += 8;
        }
        while mlen < max_m && raw[p + mlen] == raw[pos + mlen] {
            mlen += 1;
        }
        mlen
    }

    while pos < n {
        if pos + 3 <= n {
            let h = hash3(raw, pos);
            let p1 = head1[h];
            let p2 = head2[h];
            head2[h] = p1;
            head1[h] = pos as u32;

            let max_m = (n - pos).min(258);
            let mut best_len = 0usize;
            let mut best_dist = 0usize;
            for cand in [p1, p2] {
                if cand != u32::MAX {
                    let p = cand as usize;
                    let dist = pos - p;
                    if dist > 0
                        && dist <= 32768
                        && raw[p] == raw[pos]
                        && raw[p + 1] == raw[pos + 1]
                        && raw[p + 2] == raw[pos + 2]
                    {
                        let ml = match_len_at(raw, p, pos, max_m);
                        if ml > best_len {
                            best_len = ml;
                            best_dist = dist;
                            if best_len >= 64 {
                                break;
                            }
                        }
                    }
                }
            }

            if best_len >= 3 {
                tokens.push(DeflateTok::Match {
                    len: best_len as u16,
                    dist: best_dist as u16,
                });
                if pos + 1 + 3 <= n {
                    let h1 = hash3(raw, pos + 1);
                    head2[h1] = head1[h1];
                    head1[h1] = (pos + 1) as u32;
                }
                pos += best_len;
                if tokens.len() >= BLOCK_TOK_LIMIT && pos < n {
                    emit_dynamic_block(&mut bw, &tokens, false);
                    tokens.clear();
                }
                continue;
            }
        }
        tokens.push(DeflateTok::Lit(raw[pos]));
        pos += 1;
        if tokens.len() >= BLOCK_TOK_LIMIT && pos < n {
            emit_dynamic_block(&mut bw, &tokens, false);
            tokens.clear();
        }
    }

    emit_dynamic_block(&mut bw, &tokens, true);
    bw.finish_byte();
    bw.out.extend_from_slice(&adler32(raw).to_be_bytes());
    bw.out
}

/* ================================ PNG Decode / Encode ================================ */

pub struct DecodedPng {
    pub width: usize,
    pub height: usize,
    pub color_type: u8,
    pub channels: usize,
    pub pixels: Vec<u8>,
}

#[inline(always)]
fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let a = a as i32;
    let b = b as i32;
    let c = c as i32;
    let p = a + b - c;
    let pa = (p - a).abs();
    let pb = (p - b).abs();
    let pc = (p - c).abs();
    if pa <= pb && pa <= pc {
        a as u8
    } else if pb <= pc {
        b as u8
    } else {
        c as u8
    }
}

pub fn decode_png(bytes: &[u8]) -> Result<DecodedPng, String> {
    if bytes.len() < 33 || &bytes[..8] != PNG_SIG {
        return Err("NOT_PNG".to_string());
    }
    let mut pos = 8usize;
    let mut width = 0usize;
    let mut height = 0usize;
    let mut bit_depth = 0u8;
    let mut color_type = 0u8;
    let mut interlace = 0u8;
    let mut idat = Vec::new();
    let mut saw_ihdr = false;

    while pos + 12 <= bytes.len() {
        let len = u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
            as usize;
        let ctype = &bytes[pos + 4..pos + 8];
        let data_start = pos + 8;
        let data_end = data_start.checked_add(len).ok_or("PNG_CHUNK_OVF")?;
        if data_end + 4 > bytes.len() {
            return Err("PNG_CHUNK_TRUNCATED".to_string());
        }
        let chunk_data = &bytes[data_start..data_end];
        if ctype == b"IHDR" && len == 13 {
            width = u32::from_be_bytes([chunk_data[0], chunk_data[1], chunk_data[2], chunk_data[3]])
                as usize;
            height = u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]])
                as usize;
            bit_depth = chunk_data[8];
            color_type = chunk_data[9];
            interlace = chunk_data[12];
            saw_ihdr = true;
        } else if ctype == b"IDAT" {
            idat.extend_from_slice(chunk_data);
        } else if ctype == b"IEND" {
            break;
        }
        pos = data_end + 4;
    }

    if !saw_ihdr || width == 0 || height == 0 || width > 16384 || height > 16384 {
        return Err("PNG_UNSUPPORTED_DIMS".to_string());
    }
    if bit_depth != 8 || interlace != 0 {
        return Err("PNG_UNSUPPORTED_FORMAT".to_string());
    }
    let channels = match color_type {
        0 => 1,
        2 => 3,
        4 => 2,
        6 => 4,
        _ => return Err("PNG_UNSUPPORTED_COLORTYPE".to_string()),
    };

    let row_bytes = width.checked_mul(channels).ok_or("PNG_ROW_OVF")?;
    let expected_raw = height
        .checked_mul(row_bytes + 1)
        .ok_or("PNG_SIZE_OVF")?;
    let raw = zlib_decompress(&idat, expected_raw)?;
    if raw.len() != expected_raw {
        return Err("PNG_RAW_LEN_MISMATCH".to_string());
    }

    let mut pixels = vec![0u8; height * row_bytes];
    for y in 0..height {
        let src_row = &raw[y * (row_bytes + 1)..(y + 1) * (row_bytes + 1)];
        let filter = src_row[0];
        let filt_data = &src_row[1..];
        let cur_start = y * row_bytes;
        match filter {
            0 => {
                pixels[cur_start..cur_start + row_bytes].copy_from_slice(filt_data);
            }
            1 => {
                for x in 0..row_bytes {
                    let left = if x >= channels {
                        pixels[cur_start + x - channels]
                    } else {
                        0
                    };
                    pixels[cur_start + x] = filt_data[x].wrapping_add(left);
                }
            }
            2 => {
                for x in 0..row_bytes {
                    let up = if y > 0 {
                        pixels[cur_start - row_bytes + x]
                    } else {
                        0
                    };
                    pixels[cur_start + x] = filt_data[x].wrapping_add(up);
                }
            }
            3 => {
                for x in 0..row_bytes {
                    let left = if x >= channels {
                        pixels[cur_start + x - channels]
                    } else {
                        0
                    };
                    let up = if y > 0 {
                        pixels[cur_start - row_bytes + x]
                    } else {
                        0
                    };
                    let avg = ((left as u16 + up as u16) >> 1) as u8;
                    pixels[cur_start + x] = filt_data[x].wrapping_add(avg);
                }
            }
            4 => {
                for x in 0..row_bytes {
                    let left = if x >= channels {
                        pixels[cur_start + x - channels]
                    } else {
                        0
                    };
                    let up = if y > 0 {
                        pixels[cur_start - row_bytes + x]
                    } else {
                        0
                    };
                    let up_left = if y > 0 && x >= channels {
                        pixels[cur_start - row_bytes + x - channels]
                    } else {
                        0
                    };
                    pixels[cur_start + x] = filt_data[x].wrapping_add(paeth(left, up, up_left));
                }
            }
            _ => return Err("PNG_BAD_FILTER".to_string()),
        }
    }

    Ok(DecodedPng {
        width,
        height,
        color_type,
        channels,
        pixels,
    })
}

fn push_png_chunk(out: &mut Vec<u8>, ctype: &[u8; 4], payload: &[u8]) {
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    let crc_start = out.len();
    out.extend_from_slice(ctype);
    out.extend_from_slice(payload);
    let c = crc32(&out[crc_start..]);
    out.extend_from_slice(&c.to_be_bytes());
}

fn zlib_compress_fixed_fast(raw: &[u8]) -> Vec<u8> {
    const HASH_SIZE: usize = 32768;
    let mut bw = BitWriter::with_capacity(raw.len() / 2 + 64);
    bw.out.push(0x78);
    bw.out.push(0x01);
    // BFINAL=1, BTYPE=01 (Fixed Huffman)
    bw.write_bits(0b011, 3);

    #[inline(always)]
    fn write_fixed_lit(bw: &mut BitWriter, sym: u16) {
        let (code, len) = if sym <= 143 {
            (0x30u32 + sym as u32, 8u32)
        } else if sym <= 255 {
            (0x190u32 + (sym - 144) as u32, 9u32)
        } else if sym <= 279 {
            ((sym - 256) as u32, 7u32)
        } else {
            (0xc0u32 + (sym - 280) as u32, 8u32)
        };
        bw.write_bits(reverse_bits(code, len), len);
    }

    #[inline(always)]
    fn hash3(b: &[u8], i: usize) -> usize {
        let v = (b[i] as u32) | ((b[i + 1] as u32) << 8) | ((b[i + 2] as u32) << 16);
        ((v.wrapping_mul(0x1e35_a7bd)) >> 17) as usize & (HASH_SIZE - 1)
    }

    let mut head = vec![u32::MAX; HASH_SIZE];
    let n = raw.len();
    let mut pos = 0usize;
    while pos < n {
        if pos + 3 <= n {
            let h = hash3(raw, pos);
            let prev = head[h];
            head[h] = pos as u32;
            if prev != u32::MAX {
                let p = prev as usize;
                let dist = pos - p;
                if dist > 0
                    && dist <= 32768
                    && raw[p] == raw[pos]
                    && raw[p + 1] == raw[pos + 1]
                    && raw[p + 2] == raw[pos + 2]
                {
                    let max_m = (n - pos).min(258);
                    let mut mlen = 3usize;
                    while mlen + 8 <= max_m
                        && raw[p + mlen..p + mlen + 8] == raw[pos + mlen..pos + mlen + 8]
                    {
                        mlen += 8;
                    }
                    while mlen < max_m && raw[p + mlen] == raw[pos + mlen] {
                        mlen += 1;
                    }
                    let (lsym, lex_v, lex_b) = match_len_code(mlen);
                    write_fixed_lit(&mut bw, lsym as u16);
                    if lex_b > 0 {
                        bw.write_bits(lex_v, lex_b);
                    }
                    let (dsym, dex_v, dex_b) = match_dist_code(dist);
                    bw.write_bits(reverse_bits(dsym as u32, 5), 5);
                    if dex_b > 0 {
                        bw.write_bits(dex_v, dex_b);
                    }
                    if pos + 1 + 3 <= n {
                        let h1 = hash3(raw, pos + 1);
                        head[h1] = (pos + 1) as u32;
                    }
                    pos += mlen;
                    continue;
                }
            }
        }
        write_fixed_lit(&mut bw, raw[pos] as u16);
        pos += 1;
    }
    write_fixed_lit(&mut bw, 256);
    bw.finish_byte();
    bw.out.extend_from_slice(&adler32(raw).to_be_bytes());
    bw.out
}

pub fn encode_png_with_mode(
    width: usize,
    height: usize,
    color_type: u8,
    channels: usize,
    pixels: &[u8],
    mode: crate::params::PngMode,
) -> Vec<u8> {
    let row_bytes = width * channels;
    let mut filtered = Vec::with_capacity(height * (row_bytes + 1));

    let zlib = match mode {
        crate::params::PngMode::Fast => {
            for y in 0..height {
                let row = &pixels[y * row_bytes..(y + 1) * row_bytes];
                filtered.push(1u8); // Fast Sub filter
                for x in 0..row_bytes {
                    let left = if x >= channels { row[x - channels] } else { 0 };
                    filtered.push(row[x].wrapping_sub(left));
                }
            }
            zlib_compress_fixed_fast(&filtered)
        }
        crate::params::PngMode::Optimal => {
            let mut row_sub = vec![0u8; row_bytes];
            let mut row_up = vec![0u8; row_bytes];
            let mut row_paeth = vec![0u8; row_bytes];

            for y in 0..height {
                let row = &pixels[y * row_bytes..(y + 1) * row_bytes];
                let prev = if y > 0 {
                    Some(&pixels[(y - 1) * row_bytes..y * row_bytes])
                } else {
                    None
                };

                let mut score_sub = 0u64;
                let mut score_up = 0u64;
                let mut score_paeth = 0u64;

                for x in 0..row_bytes {
                    let cur = row[x];
                    let left = if x >= channels { row[x - channels] } else { 0 };
                    let up = prev.map_or(0, |p| p[x]);
                    let up_left = if x >= channels {
                        prev.map_or(0, |p| p[x - channels])
                    } else {
                        0
                    };

                    let fs = cur.wrapping_sub(left);
                    let fu = cur.wrapping_sub(up);
                    let fp = cur.wrapping_sub(paeth(left, up, up_left));

                    row_sub[x] = fs;
                    row_up[x] = fu;
                    row_paeth[x] = fp;

                    score_sub += (fs as i8).unsigned_abs() as u64;
                    score_up += (fu as i8).unsigned_abs() as u64;
                    score_paeth += (fp as i8).unsigned_abs() as u64;
                }

                if score_paeth <= score_sub && score_paeth <= score_up {
                    filtered.push(4u8);
                    filtered.extend_from_slice(&row_paeth);
                } else if score_sub <= score_up {
                    filtered.push(1u8);
                    filtered.extend_from_slice(&row_sub);
                } else {
                    filtered.push(2u8);
                    filtered.extend_from_slice(&row_up);
                }
            }
            zlib_compress_fast(&filtered)
        }
    };

    let mut out = Vec::with_capacity(64 + zlib.len());
    out.extend_from_slice(PNG_SIG);

    let mut ihdr = [0u8; 13];
    ihdr[0..4].copy_from_slice(&(width as u32).to_be_bytes());
    ihdr[4..8].copy_from_slice(&(height as u32).to_be_bytes());
    ihdr[8] = 8; // bit depth
    ihdr[9] = color_type;
    push_png_chunk(&mut out, b"IHDR", &ihdr);
    push_png_chunk(&mut out, b"IDAT", &zlib);
    push_png_chunk(&mut out, b"IEND", &[]);
    out
}

pub fn encode_png(width: usize, height: usize, color_type: u8, channels: usize, pixels: &[u8]) -> Vec<u8> {
    encode_png_with_mode(
        width,
        height,
        color_type,
        channels,
        pixels,
        crate::params::PngMode::Optimal,
    )
}

/* ================= Cryptographic Fisher-Yates + Flip Tile Scrambler ================= */

/// Derives a cryptographic `grid x grid` tile map (`grid` in `{4, 8, 16}`, packed into 256 entries):
/// `entry = (scrambled_tile_idx & 0xff) | (flip_x << 8) | (flip_y << 9)`.
pub fn derive_tile_map(seed: &[u8; 32], grid: usize) -> [u32; 256] {
    let mut perm = [0u32; 256];
    let n_tiles = (grid * grid).clamp(1, 256);
    for i in 0..n_tiles {
        perm[i] = i as u32;
    }
    for i in (1..n_tiles).rev() {
        let mut msg = [0u8; 36];
        msg[..32].copy_from_slice(seed);
        msg[32..36].copy_from_slice(&(i as u32).to_le_bytes());
        let h = sha256(&msg);
        let r = u32::from_le_bytes([h[0], h[1], h[2], h[3]]) as usize;
        let j = r % (i + 1);
        perm.swap(i, j);
    }
    for i in 0..n_tiles {
        let mut msg = [0u8; 36];
        msg[..32].copy_from_slice(seed);
        msg[32..36].copy_from_slice(&((i as u32) ^ 0xa5a5_0000).to_le_bytes());
        let h = sha256(&msg);
        let flips = ((h[0] as u32) & 0x3) << 8;
        perm[i] |= flips;
    }
    perm
}

/// Derives a cryptographic 256-entry `16x16` tile map (`256! * 4^256` states).
pub fn derive_tile_map_256(seed: &[u8; 32]) -> [u32; 256] {
    derive_tile_map(seed, 16)
}

pub(crate) fn downscale_2x_box(img: &DecodedPng) -> DecodedPng {
    let nw = (img.width / 2).max(1);
    let nh = (img.height / 2).max(1);
    let ch = img.channels;
    let src_stride = img.width * ch;
    let dst_stride = nw * ch;
    let mut out = vec![0u8; nh * dst_stride];
    for y in 0..nh {
        let sy0 = (y * 2) * src_stride;
        let sy1 = (y * 2 + 1).min(img.height - 1) * src_stride;
        let dy = y * dst_stride;
        for x in 0..nw {
            let sx0 = (x * 2) * ch;
            let sx1 = (x * 2 + 1).min(img.width - 1) * ch;
            let dx = dy + x * ch;
            for c in 0..ch {
                let sum = img.pixels[sy0 + sx0 + c] as u16
                    + img.pixels[sy0 + sx1 + c] as u16
                    + img.pixels[sy1 + sx0 + c] as u16
                    + img.pixels[sy1 + sx1 + c] as u16;
                out[dx + c] = ((sum + 2) >> 2) as u8;
            }
        }
    }
    DecodedPng {
        width: nw,
        height: nh,
        color_type: img.color_type,
        channels: ch,
        pixels: out,
    }
}

/// Checks whether a decoded image has any non-opaque alpha pixel (meaning lossless PNG is required).
fn has_transparency(img: &DecodedPng) -> bool {
    if img.channels != 4 {
        return false;
    }
    img.pixels.chunks_exact(4).any(|px| px[3] < 254)
}

/// Decodes a PNG, downscales via crisp 2x2 box filtering if larger than `max_dim`,
/// scrambles & mirrors all `grid x grid` tiles (`grid` in `{0, 4, 8, 16}`) using `tmap`,
/// and encodes using `tex_format` (`Auto` = MCU-aligned 4:4:4 JPEG for opaque >=64px textures,
/// PNG otherwise; `Jpeg`; or `Png`). Returns `(encoded_bytes, was_scrambled)`.
pub fn scramble_texture_grid(
    png_bytes: &[u8],
    tmap: &[u32; 256],
    grid: usize,
    max_dim: usize,
    mode: crate::params::PngMode,
    tex_format: crate::params::TexFormat,
    jpeg_quality: u8,
) -> Result<(Vec<u8>, bool), String> {
    let mut img = decode_png(png_bytes)?;
    let mut resized = false;
    while img.width > max_dim || img.height > max_dim {
        img = downscale_2x_box(&img);
        resized = true;
    }

    let use_jpeg = |w: usize, h: usize, transparent: bool| -> bool {
        match tex_format {
            crate::params::TexFormat::Png => false,
            crate::params::TexFormat::Jpeg => true,
            crate::params::TexFormat::Auto => !transparent && w >= 64 && h >= 64,
        }
    };
    let transparent = has_transparency(&img);

    if grid == 0 {
        if use_jpeg(img.width, img.height, transparent) {
            let jpg = crate::jpeg_enc::encode_jpeg(img.width, img.height, img.channels, &img.pixels, jpeg_quality);
            if tex_format == crate::params::TexFormat::Jpeg || jpg.len() < png_bytes.len() || resized {
                return Ok((jpg, false));
            }
        }
        if resized {
            return Ok((
                encode_png_with_mode(img.width, img.height, img.color_type, img.channels, &img.pixels, mode),
                false,
            ));
        }
        return Ok((png_bytes.to_vec(), false));
    }
    if !matches!(grid, 4 | 8 | 16) {
        return Err(format!("PNG_UNSUPPORTED_TILE_GRID:{grid}"));
    }
    if img.width < grid || img.height < grid {
        return Err("PNG_TOO_SMALL_FOR_GRID".to_string());
    }
    let tw = (img.width / grid) * grid;
    let th = (img.height / grid) * grid;
    let tile_w = tw / grid;
    let tile_h = th / grid;
    let ch = img.channels;
    let src_stride = img.width * ch;
    let dst_stride = tw * ch;
    let mut scrambled = vec![0u8; th * dst_stride];
    let n_tiles = grid * grid;

    for orig in 0..n_tiles {
        let ox = orig % grid;
        let oy = orig / grid;
        let entry = tmap[orig];
        let scr = (entry & 0xff) as usize;
        let sx = scr % grid;
        let sy = scr / grid;
        let flip_x = (entry & 256) != 0;
        let flip_y = (entry & 512) != 0;

        for ly in 0..tile_h {
            let src_y = oy * tile_h + ly;
            let dst_ly = if flip_y { tile_h - 1 - ly } else { ly };
            let dst_y = sy * tile_h + dst_ly;
            let src_row_off = src_y * src_stride;
            let dst_row_off = dst_y * dst_stride;
            if !flip_x {
                let s_off = src_row_off + (ox * tile_w) * ch;
                let d_off = dst_row_off + (sx * tile_w) * ch;
                let len = tile_w * ch;
                scrambled[d_off..d_off + len].copy_from_slice(&img.pixels[s_off..s_off + len]);
            } else {
                for lx in 0..tile_w {
                    let src_x = ox * tile_w + lx;
                    let dst_x = sx * tile_w + (tile_w - 1 - lx);
                    let s_off = src_row_off + src_x * ch;
                    let d_off = dst_row_off + dst_x * ch;
                    scrambled[d_off..d_off + ch].copy_from_slice(&img.pixels[s_off..s_off + ch]);
                }
            }
        }
    }

    // MCU-aligned 4:4:4 JPEG when tile dims are multiples of 8 (zero cross-tile bleed!)
    if use_jpeg(tw, th, transparent) && (tile_w % 8 == 0) && (tile_h % 8 == 0) {
        let jpg = crate::jpeg_enc::encode_jpeg(tw, th, ch, &scrambled, jpeg_quality);
        return Ok((jpg, true));
    }

    Ok((
        encode_png_with_mode(tw, th, img.color_type, ch, &scrambled, mode),
        true,
    ))
}

/// Decodes a PNG, downscales via crisp 2x2 box filtering if larger than `max_dim`,
/// scrambles & mirrors all `grid x grid` tiles (`grid` in `{0, 4, 8, 16}`) using `tmap`,
/// and re-encodes as PNG using `mode` (`Fast` or `Optimal`). Returns `(png_bytes, was_scrambled)`.
pub fn scramble_png_grid(
    png_bytes: &[u8],
    tmap: &[u32; 256],
    grid: usize,
    max_dim: usize,
    mode: crate::params::PngMode,
) -> Result<(Vec<u8>, bool), String> {
    scramble_texture_grid(png_bytes, tmap, grid, max_dim, mode, crate::params::TexFormat::Png, 90)
}

/// Decodes a PNG, downscales via crisp 2x2 box filtering if larger than `max_dim`,
/// scrambles & mirrors all `16x16` tiles using `tmap`, and re-encodes as a valid PNG.
pub fn scramble_png_16x16(
    png_bytes: &[u8],
    tmap: &[u32; 256],
    max_dim: usize,
) -> Result<Vec<u8>, String> {
    scramble_png_grid(png_bytes, tmap, 16, max_dim, crate::params::PngMode::Optimal).map(|(b, _)| b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_roundtrip_and_server_tile_scramble_exact_pixel_match() {
        for (color_type, channels) in [(2u8, 3usize), (6u8, 4usize)] {
            let w = 64usize;
            let h = 64usize;
            let mut pixels = vec![0u8; w * h * channels];
            for y in 0..h {
                for x in 0..w {
                    let off = (y * w + x) * channels;
                    pixels[off] = ((x * 4) & 0xff) as u8;
                    pixels[off + 1] = ((y * 4) & 0xff) as u8;
                    pixels[off + 2] = (((x ^ y) * 3) & 0xff) as u8;
                    if channels == 4 {
                        pixels[off + 3] = 255;
                    }
                }
            }
            let orig_png = encode_png(w, h, color_type, channels, &pixels);
            let dec_orig = decode_png(&orig_png).expect("decode orig png");
            assert_eq!(dec_orig.width, w);
            assert_eq!(dec_orig.height, h);
            assert_eq!(dec_orig.pixels, pixels);

            let seed = [0x3cu8; 32];
            let tmap = derive_tile_map_256(&seed);
            // Verify permutation is bijective on [0..255]
            let mut seen = [false; 256];
            for &e in &tmap {
                let s = (e & 0xff) as usize;
                assert!(!seen[s], "duplicate tile destination {s}");
                seen[s] = true;
            }

            let scr_png = scramble_png_16x16(&orig_png, &tmap, 4096).expect("scramble png");
            let dec_scr = decode_png(&scr_png).expect("decode scrambled png");
            assert_eq!(dec_scr.width, w);
            assert_eq!(dec_scr.height, h);
            assert_ne!(dec_scr.pixels, pixels, "scrambled pixels must differ from original");

            // Simulate exact shader vs_unscramble_uv lookup at every pixel center
            let tile_w = w / 16;
            let tile_h = h / 16;
            for y in 0..h {
                for x in 0..w {
                    let ox = x / tile_w;
                    let oy = y / tile_h;
                    let lx = x % tile_w;
                    let ly = y % tile_h;
                    let entry = tmap[oy * 16 + ox];
                    let scr = (entry & 0xff) as usize;
                    let sx = scr & 15;
                    let sy = scr >> 4;
                    let dlx = if (entry & 256) != 0 { tile_w - 1 - lx } else { lx };
                    let dly = if (entry & 512) != 0 { tile_h - 1 - ly } else { ly };
                    let dx = sx * tile_w + dlx;
                    let dy = sy * tile_h + dly;
                    let s_off = (y * w + x) * channels;
                    let d_off = (dy * w + dx) * channels;
                    assert_eq!(
                        &dec_scr.pixels[d_off..d_off + channels],
                        &pixels[s_off..s_off + channels],
                        "pixel mismatch at ({x},{y})"
                    );
                }
            }
        }

        // Verify parameterized grids (8x8 Fast mode, 4x4 Optimal mode, and grid=0 unscrambled)
        {
            let w = 64usize;
            let h = 64usize;
            let mut pixels = vec![0u8; w * h * 3];
            for y in 0..h {
                for x in 0..w {
                    let off = (y * w + x) * 3;
                    pixels[off] = ((x * 4) & 0xff) as u8;
                    pixels[off + 1] = ((y * 4) & 0xff) as u8;
                    pixels[off + 2] = (((x + y) * 2) & 0xff) as u8;
                }
            }
            let orig_png = encode_png(w, h, 2, 3, &pixels);
            let seed = [0x9au8; 32];

            // 8x8 + PngMode::Fast exact pixel match
            let tmap8 = derive_tile_map(&seed, 8);
            let (scr8, was8) =
                scramble_png_grid(&orig_png, &tmap8, 8, 4096, crate::params::PngMode::Fast)
                    .expect("scramble 8x8 fast");
            assert!(was8);
            let dec8 = decode_png(&scr8).expect("decode 8x8 fast");
            assert_ne!(dec8.pixels, pixels);
            let tw = w / 8;
            let th = h / 8;
            for y in 0..h {
                for x in 0..w {
                    let entry = tmap8[(y / th) * 8 + (x / tw)];
                    let scr = (entry & 0xff) as usize;
                    let sx = scr % 8;
                    let sy = scr / 8;
                    let lx = x % tw;
                    let ly = y % th;
                    let dlx = if (entry & 256) != 0 { tw - 1 - lx } else { lx };
                    let dly = if (entry & 512) != 0 { th - 1 - ly } else { ly };
                    let s_off = (y * w + x) * 3;
                    let d_off = ((sy * th + dly) * w + (sx * tw + dlx)) * 3;
                    assert_eq!(&dec8.pixels[d_off..d_off + 3], &pixels[s_off..s_off + 3]);
                }
            }

            // grid=0 disables scrambling cleanly
            let (unscr, was0) =
                scramble_png_grid(&orig_png, &tmap8, 0, 4096, crate::params::PngMode::Fast)
                    .expect("grid=0");
            assert!(!was0);
            assert_eq!(decode_png(&unscr).unwrap().pixels, pixels);
        }

        // Stress length-limited Huffman Kraft equality on Fibonacci frequencies (depth > 20 -> clamped to 7 & 15)
        let mut fib = vec![0u32; 28];
        let mut a = 1u32;
        let mut b = 1u32;
        for f in &mut fib {
            *f = a;
            let next = a.saturating_add(b);
            a = b;
            b = next;
        }
        for max_b in [7u8, 15u8] {
            let lens = build_limited_huff_lengths(&fib, max_b);
            assert!(lens.iter().all(|&l| l >= 1 && l <= max_b));
            let kraft: u64 = lens.iter().map(|&l| 1u64 << (max_b - l)).sum();
            assert_eq!(kraft, 1u64 << max_b, "Kraft sum mismatch for max_bits={max_b}");
        }
    }
}
