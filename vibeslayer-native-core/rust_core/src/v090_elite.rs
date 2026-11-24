//! `v090_elite` (`1.0.0-beta.3`) — Key-committing headerless `VSPK3` container
//! and hardened multi-stage native `ELF64` builder (`build_protected_elf_elite`).

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::{
    chacha20_block, chacha20_poly1305_seal, chacha20_poly1305_seal_in_place,
    chacha20_poly1305_verify_tag, chacha20_xor_in_place, chacha20_xor_into, hex_encode,
    hkdf_sha256_32,
    hkdf_sha256_32_parts, hmac_sha256, hmac_sha256_parts, os_random_bytes, secure_zero, sha256,
};

pub const VSPK3_PREFIX_LEN: usize = 32 + 12 + 32 + 16; // 92 bytes
pub const VSPK3_PAD_QUANTUM: usize = 1024;

fn encode_canonical_vspk3_info(domain: &str, asset_id: &str, context: &str) -> Vec<u8> {
    let db = domain.as_bytes();
    let ab = asset_id.as_bytes();
    let cb = context.as_bytes();
    let mut info = Vec::with_capacity(10 + 12 + db.len() + ab.len() + cb.len());
    info.extend_from_slice(b"VSPK3_CMT4");
    info.extend_from_slice(&(db.len() as u32).to_le_bytes());
    info.extend_from_slice(db);
    info.extend_from_slice(&(ab.len() as u32).to_le_bytes());
    info.extend_from_slice(ab);
    info.extend_from_slice(&(cb.len() as u32).to_le_bytes());
    info.extend_from_slice(cb);
    info
}

fn derive_vspk3_subkeys(
    master_key: &[u8; 32],
    salt: &[u8; 32],
    canonical_info: &[u8],
) -> ([u8; 32], [u8; 32]) {
    let enc_key = hkdf_sha256_32_parts(master_key, salt, &[canonical_info, b"|ENC"]);
    let cmt_key = hkdf_sha256_32_parts(master_key, salt, &[canonical_info, b"|CMT"]);
    (enc_key, cmt_key)
}

fn compute_vspk3_cmt4(cmt_key: &[u8; 32], nonce: &[u8; 12], canonical_info: &[u8]) -> [u8; 32] {
    hmac_sha256_parts(cmt_key, &[nonce, canonical_info])
}

fn build_vspk3_aad(
    salt: &[u8; 32],
    nonce: &[u8; 12],
    cmt4: &[u8; 32],
    canonical_info: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(76 + canonical_info.len());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad.extend_from_slice(cmt4);
    aad.extend_from_slice(canonical_info);
    aad
}

pub fn pack_vspk3(
    master_key: &[u8; 32],
    domain: &str,
    asset_id: &str,
    context: &str,
    plain: &[u8],
) -> Result<Vec<u8>, String> {
    if plain.len() > (u32::MAX as usize) - 4 {
        return Err("PLAIN_EXCEEDS_U32_MAX".to_string());
    }
    let raw_needed = 4usize
        .checked_add(plain.len())
        .ok_or_else(|| "PLAIN_OVERFLOW".to_string())?;
    let padded_len = raw_needed
        .checked_next_multiple_of(VSPK3_PAD_QUANTUM)
        .ok_or_else(|| "PAD_OVERFLOW".to_string())?;

    let mut out = vec![0u8; VSPK3_PREFIX_LEN + padded_len];
    os_random_bytes(&mut out[0..44])?;
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&out[0..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&out[32..44]);

    out[VSPK3_PREFIX_LEN..VSPK3_PREFIX_LEN + 4]
        .copy_from_slice(&(plain.len() as u32).to_le_bytes());
    out[VSPK3_PREFIX_LEN + 4..VSPK3_PREFIX_LEN + 4 + plain.len()].copy_from_slice(plain);
    if padded_len > 4 + plain.len() {
        os_random_bytes(&mut out[VSPK3_PREFIX_LEN + 4 + plain.len()..])?;
    }

    let info = encode_canonical_vspk3_info(domain, asset_id, context);
    let (mut enc_key, mut cmt_key) = derive_vspk3_subkeys(master_key, &salt, &info);
    let cmt4 = compute_vspk3_cmt4(&cmt_key, &nonce, &info);
    secure_zero(&mut cmt_key);
    out[44..76].copy_from_slice(&cmt4);

    let aad = build_vspk3_aad(&salt, &nonce, &cmt4, &info);
    let tag = chacha20_poly1305_seal_in_place(&enc_key, &nonce, &aad, &mut out[VSPK3_PREFIX_LEN..]);
    secure_zero(&mut enc_key);
    out[76..92].copy_from_slice(&tag);
    Ok(out)
}

pub fn unseal_vspk3(
    master_key: &[u8; 32],
    domain: &str,
    asset_id: &str,
    context: &str,
    blob: &[u8],
) -> Result<Vec<u8>, String> {
    if blob.len() < VSPK3_PREFIX_LEN + VSPK3_PAD_QUANTUM {
        return Err("TRUNCATED_VSPK3".to_string());
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&blob[0..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[32..44]);
    let mut cmt4 = [0u8; 32];
    cmt4.copy_from_slice(&blob[44..76]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&blob[76..92]);
    let ct = &blob[92..];
    if ct.len() % VSPK3_PAD_QUANTUM != 0 {
        return Err("UNALIGNED_VSPK3_CIPHERTEXT".to_string());
    }

    let info = encode_canonical_vspk3_info(domain, asset_id, context);
    let (mut enc_key, mut cmt_key) = derive_vspk3_subkeys(master_key, &salt, &info);
    let mut expected_cmt4 = compute_vspk3_cmt4(&cmt_key, &nonce, &info);
    secure_zero(&mut cmt_key);

    let mut diff = 0u8;
    for i in 0..32 {
        diff |= expected_cmt4[i] ^ cmt4[i];
    }
    secure_zero(&mut expected_cmt4);
    if diff != 0 {
        secure_zero(&mut enc_key);
        return Err("CMT4_COMMITMENT_FAILED".to_string());
    }

    let aad = build_vspk3_aad(&salt, &nonce, &cmt4, &info);
    if let Err(e) = chacha20_poly1305_verify_tag(&enc_key, &nonce, &aad, ct, &tag) {
        secure_zero(&mut enc_key);
        return Err(e.to_string());
    }

    // Authenticated: decrypt block 1 on stack to read exact plain_len without allocating ct.len().
    let mut blk1 = chacha20_block(&enc_key, 1, &nonce);
    let len_bytes = [
        ct[0] ^ blk1[0],
        ct[1] ^ blk1[1],
        ct[2] ^ blk1[2],
        ct[3] ^ blk1[3],
    ];
    let plain_len = u32::from_le_bytes(len_bytes) as usize;
    if 4usize.saturating_add(plain_len) > ct.len() {
        secure_zero(&mut blk1);
        secure_zero(&mut enc_key);
        return Err("CORRUPT_VSPK3_LENGTH".to_string());
    }

    let mut out = vec![0u8; plain_len];
    let first_avail = (ct.len().min(64)).saturating_sub(4);
    let first_n = plain_len.min(first_avail);
    for i in 0..first_n {
        out[i] = ct[4 + i] ^ blk1[4 + i];
    }
    secure_zero(&mut blk1);
    if plain_len > first_n {
        let rest = plain_len - first_n;
        chacha20_xor_into(&enc_key, 2, &nonce, &ct[64..64 + rest], &mut out[first_n..]);
    }
    secure_zero(&mut enc_key);
    Ok(out)
}

/// Zero-extra-allocation VSPK3 unsealing: verifies prefix/MAC, decrypts block 1 header on stack,
/// decrypts ciphertext payload in-place at `&mut blob[96..]`, shifts left by 96B, and truncates.
pub fn unseal_vspk3_owned(
    master_key: &[u8; 32],
    domain: &str,
    asset_id: &str,
    context: &str,
    mut blob: Vec<u8>,
) -> Result<Vec<u8>, String> {
    if blob.len() < VSPK3_PREFIX_LEN + VSPK3_PAD_QUANTUM {
        return Err("TRUNCATED_VSPK3".to_string());
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&blob[0..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[32..44]);
    let mut cmt4 = [0u8; 32];
    cmt4.copy_from_slice(&blob[44..76]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&blob[76..92]);

    let ct_len = blob.len() - VSPK3_PREFIX_LEN;
    if ct_len % VSPK3_PAD_QUANTUM != 0 {
        return Err("UNALIGNED_VSPK3_CIPHERTEXT".to_string());
    }

    let info = encode_canonical_vspk3_info(domain, asset_id, context);
    let (mut enc_key, mut cmt_key) = derive_vspk3_subkeys(master_key, &salt, &info);
    let mut expected_cmt4 = compute_vspk3_cmt4(&cmt_key, &nonce, &info);
    secure_zero(&mut cmt_key);

    let mut diff = 0u8;
    for i in 0..32 {
        diff |= cmt4[i] ^ expected_cmt4[i];
    }
    secure_zero(&mut expected_cmt4);
    if std::hint::black_box(diff) != 0 {
        secure_zero(&mut enc_key);
        return Err("CMT4_COMMITMENT_FAILED".to_string());
    }

    let aad = build_vspk3_aad(&salt, &nonce, &cmt4, &info);
    if let Err(e) = chacha20_poly1305_verify_tag(
        &enc_key,
        &nonce,
        &aad,
        &blob[VSPK3_PREFIX_LEN..],
        &tag,
    ) {
        secure_zero(&mut enc_key);
        return Err(e.to_string());
    }

    let mut blk1 = chacha20_block(&enc_key, 1, &nonce);
    let len_bytes = [
        blob[VSPK3_PREFIX_LEN] ^ blk1[0],
        blob[VSPK3_PREFIX_LEN + 1] ^ blk1[1],
        blob[VSPK3_PREFIX_LEN + 2] ^ blk1[2],
        blob[VSPK3_PREFIX_LEN + 3] ^ blk1[3],
    ];
    let plain_len = u32::from_le_bytes(len_bytes) as usize;
    if 4usize.saturating_add(plain_len) > ct_len {
        secure_zero(&mut blk1);
        secure_zero(&mut enc_key);
        return Err("CORRUPT_VSPK3_LENGTH".to_string());
    }

    let dst_start = VSPK3_PREFIX_LEN + 4;
    let first_avail = (ct_len.min(64)).saturating_sub(4);
    let first_n = plain_len.min(first_avail);
    for i in 0..first_n {
        blob[dst_start + i] ^= blk1[4 + i];
    }
    secure_zero(&mut blk1);
    if plain_len > first_n {
        let rest = plain_len - first_n;
        let tail_start = VSPK3_PREFIX_LEN + 64;
        chacha20_xor_in_place(&enc_key, 2, &nonce, &mut blob[tail_start..tail_start + rest]);
    }
    secure_zero(&mut enc_key);

    blob.copy_within(dst_start..dst_start + plain_len, 0);
    let zero_end = plain_len.saturating_add(dst_start).min(blob.len());
    secure_zero(&mut blob[plain_len..zero_end]);
    blob.truncate(plain_len);
    Ok(blob)
}

const ELITE_STAGES: usize = 96;
const LATTICE_WORDS: usize = 256;
const ENC_FRAME_LEN: usize = 4100; // Fixed 4B len + up to 4096B payload (zero length leakage!)
const VAULT_BYTES: usize = 4608;   // 92B header + 4100B frame + 416B pad; gcd(73, 4608) == 1

fn derive_stage_constants(build_seed: &[u8; 32], stage: usize) -> [u64; 16] {
    let mut out = [0u64; 16];
    for blk in 0..4 {
        let mut msg = [0u8; 40];
        msg[0..32].copy_from_slice(build_seed);
        msg[32..36].copy_from_slice(&(stage as u32).to_le_bytes());
        msg[36..40].copy_from_slice(&(blk as u32).to_le_bytes());
        let d = sha256(&msg);
        for w in 0..4 {
            let off = w * 8;
            out[blk * 4 + w] = u64::from_le_bytes(d[off..off + 8].try_into().unwrap()) | 1;
        }
    }
    out
}

fn eval_stage_rust(mut s: u64, lattice: &[u64; LATTICE_WORDS], c: &[u64; 16], stage: usize) -> u64 {
    for r in 0..16 {
        let idx = ((s.wrapping_shr(11) ^ (r as u64).wrapping_mul(17) ^ (stage as u64)) as usize)
            & (LATTICE_WORDS - 1);
        let lv = lattice[idx];
        let rot = (((r * 5 + stage * 3) % 53) + 5) as u32;
        s = s.wrapping_add(lv ^ c[r]);
        s = s.rotate_left(rot) ^ lv.wrapping_mul(c[(r + 3) & 15]);
        s = s.wrapping_mul(c[(r + 7) & 15]).wrapping_add(0x9e3779b97f4a7c15);
    }
    s
}

fn extract_vs_ring_offsets_pre_strip(elf: &[u8]) -> Result<Vec<u64>, String> {
    if elf.len() < 64 || elf.get(0..4) != Some(b"\x7fELF".as_slice()) {
        return Err("INVALID_ELF64".to_string());
    }
    let e_shoff = u64::from_le_bytes(elf[40..48].try_into().unwrap()) as usize;
    let e_shentsize = u16::from_le_bytes([elf[58], elf[59]]) as usize;
    let e_shnum = u16::from_le_bytes([elf[60], elf[61]]) as usize;
    let e_shstrndx = u16::from_le_bytes([elf[62], elf[63]]) as usize;
    if e_shentsize < 64 || e_shstrndx >= e_shnum {
        return Err("INVALID_SECTION_HEADER_TABLE".to_string());
    }

    let shstr_hdr_off = e_shoff + e_shstrndx * e_shentsize;
    let shstr_hdr = elf
        .get(shstr_hdr_off..shstr_hdr_off + 64)
        .ok_or("TRUNCATED_SHSTRTAB_HDR")?;
    let shstr_off = u64::from_le_bytes(shstr_hdr[24..32].try_into().unwrap()) as usize;
    let shstr_sz = u64::from_le_bytes(shstr_hdr[32..40].try_into().unwrap()) as usize;
    let shstr = elf
        .get(shstr_off..shstr_off.checked_add(shstr_sz).ok_or("SHSTR_OVERFLOW")?)
        .ok_or("TRUNCATED_SHSTRTAB")?;

    let mut symtab_info: Option<(usize, usize, usize, usize)> = None;
    let mut rela_info: Option<(usize, usize, usize)> = None;
    let mut sections: Vec<(usize, usize)> = Vec::with_capacity(e_shnum);

    for i in 0..e_shnum {
        let off = e_shoff
            .checked_add(i.checked_mul(e_shentsize).ok_or("SH_MUL_OVERFLOW")?)
            .ok_or("SH_OFF_OVERFLOW")?;
        let sh = elf.get(off..off + 64).ok_or("TRUNCATED_SHDR")?;
        let sh_name = u32::from_le_bytes(sh[0..4].try_into().unwrap()) as usize;
        let sh_type = u32::from_le_bytes(sh[4..8].try_into().unwrap());
        let sh_offset = u64::from_le_bytes(sh[24..32].try_into().unwrap()) as usize;
        let sh_size = u64::from_le_bytes(sh[32..40].try_into().unwrap()) as usize;
        let sh_link = u32::from_le_bytes(sh[40..44].try_into().unwrap()) as usize;
        let sh_entsize = u64::from_le_bytes(sh[56..64].try_into().unwrap()) as usize;
        sections.push((sh_offset, sh_size));

        let name_tail = shstr.get(sh_name..).ok_or("BAD_SH_NAME")?;
        let name_nul = name_tail.iter().position(|&b| b == 0).ok_or("UNTERM_SH_NAME")?;
        let name = &name_tail[..name_nul];

        if sh_type == 2 {
            symtab_info = Some((sh_offset, sh_size, sh_link, sh_entsize.max(24)));
        } else if sh_type == 4 && name == b".rela.dyn" {
            rela_info = Some((sh_offset, sh_size, sh_entsize.max(24)));
        }
    }

    let (sym_off, sym_sz, sym_link, sym_es) =
        symtab_info.ok_or_else(|| "MISSING_SYMTAB".to_string())?;
    let (str_off, str_sz) = *sections.get(sym_link).ok_or("MISSING_STRTAB")?;
    let strtab = elf
        .get(str_off..str_off.checked_add(str_sz).ok_or("STRTAB_OVERFLOW")?)
        .ok_or("TRUNCATED_STRTAB")?;
    let symtab = elf
        .get(sym_off..sym_off.checked_add(sym_sz).ok_or("SYMTAB_OVERFLOW")?)
        .ok_or("TRUNCATED_SYMTAB")?;

    let mut ring_vaddr: Option<u64> = None;
    let mut pos = 0usize;
    while pos + 24 <= symtab.len() {
        let ent = &symtab[pos..pos + 24];
        let st_name = u32::from_le_bytes(ent[0..4].try_into().unwrap()) as usize;
        let st_value = u64::from_le_bytes(ent[8..16].try_into().unwrap());
        let st_size = u64::from_le_bytes(ent[16..24].try_into().unwrap());
        if let Some(tail) = strtab.get(st_name..) {
            if let Some(nul) = tail.iter().position(|&b| b == 0) {
                if &tail[..nul] == b"VS_RING" && st_size == (ELITE_STAGES * 8) as u64 {
                    ring_vaddr = Some(st_value);
                    break;
                }
            }
        }
        pos += sym_es;
    }
    let ring_base = ring_vaddr.ok_or_else(|| "MISSING_VS_RING_SYMBOL".to_string())?;

    let (rela_off, rela_sz, rela_es) =
        rela_info.ok_or_else(|| "MISSING_RELA_DYN".to_string())?;
    let rela = elf
        .get(rela_off..rela_off.checked_add(rela_sz).ok_or("RELA_OVERFLOW")?)
        .ok_or("TRUNCATED_RELA_DYN")?;

    let mut relocs = HashMap::new();
    let mut rpos = 0usize;
    while rpos + 24 <= rela.len() {
        let ent = &rela[rpos..rpos + 24];
        let r_offset = u64::from_le_bytes(ent[0..8].try_into().unwrap());
        let r_info = u64::from_le_bytes(ent[8..16].try_into().unwrap());
        let r_addend = i64::from_le_bytes(ent[16..24].try_into().unwrap()) as u64;
        if (r_info & 0xffff_ffff) == 8 {
            relocs.insert(r_offset, r_addend);
        }
        rpos += rela_es;
    }

    let mut offsets = Vec::with_capacity(ELITE_STAGES);
    for i in 0..ELITE_STAGES {
        let slot_va = ring_base + (i as u64) * 8;
        let target_off = relocs
            .get(&slot_va)
            .copied()
            .ok_or_else(|| "MISSING_VS_RING_RELOC_SLOT".to_string())?;
        offsets.push(target_off);
    }
    Ok(offsets)
}

fn compute_integrity_digest_rust(
    elf: &[u8],
    vault_start: usize,
    vault_end: usize,
    lattice: &[u64; LATTICE_WORDS],
    mask_seed: &[u8; 32],
    ring_offsets: &[u64],
) -> Result<[u8; 32], String> {
    if elf.len() < 64 || elf.get(0..4) != Some(b"\x7fELF".as_slice()) {
        return Err("INVALID_ELF64".to_string());
    }
    if vault_start >= vault_end || vault_end > elf.len() {
        return Err("BAD_VAULT_RANGE".to_string());
    }
    let e_phoff = u64::from_le_bytes(elf[32..40].try_into().unwrap()) as usize;
    let e_phentsize = u16::from_le_bytes([elf[54], elf[55]]) as usize;
    let e_phnum = u16::from_le_bytes([elf[56], elf[57]]) as usize;

    let mut msg = Vec::new();
    let mut found_rx = false;
    let mut vault_covered = false;
    for i in 0..e_phnum {
        let off = e_phoff
            .checked_add(i.checked_mul(e_phentsize).ok_or("PH_MUL_OVERFLOW")?)
            .ok_or("PH_OFF_OVERFLOW")?;
        let ph = elf.get(off..off.saturating_add(56)).ok_or("TRUNCATED_PHDR")?;
        let p_type = u32::from_le_bytes(ph[0..4].try_into().unwrap());
        let p_flags = u32::from_le_bytes(ph[4..8].try_into().unwrap());
        let p_offset = u64::from_le_bytes(ph[8..16].try_into().unwrap()) as usize;
        let p_filesz = u64::from_le_bytes(ph[32..40].try_into().unwrap()) as usize;
        if p_type == 1 && (p_flags & 2) == 0 {
            let seg_end = p_offset.checked_add(p_filesz).ok_or("SEG_OVERFLOW")?;
            let seg = elf.get(p_offset..seg_end).ok_or("TRUNCATED_RO_SEGMENT")?;
            if (p_flags & 1) != 0 {
                found_rx = true;
            }
            if vault_end <= p_offset || vault_start >= seg_end {
                msg.extend_from_slice(seg);
            } else {
                vault_covered = true;
                let excl_lo = vault_start.max(p_offset);
                let excl_hi = vault_end.min(seg_end);
                if excl_lo > p_offset {
                    msg.extend_from_slice(&elf[p_offset..excl_lo]);
                }
                if excl_hi < seg_end {
                    msg.extend_from_slice(&elf[excl_hi..seg_end]);
                }
            }
        }
    }
    if !found_rx {
        return Err("NO_PF_X_SEGMENT".to_string());
    }
    if !vault_covered {
        return Err("RO_VAULT_NOT_IN_IMMUTABLE_SEGMENT".to_string());
    }
    for &w in lattice {
        msg.extend_from_slice(&w.to_le_bytes());
    }
    msg.extend_from_slice(mask_seed);
    for &ro in ring_offsets {
        msg.extend_from_slice(&ro.to_le_bytes());
    }
    let out = sha256(&msg);
    secure_zero(&mut msg);
    Ok(out)
}

fn format_xor_c_arrays(name: &str, plain: &[u8], mask_seed: &[u8; 32], salt: u8) -> String {
    use std::fmt::Write;
    let d = sha256(&[&mask_seed[..], &[salt]].concat());
    let mut enc = String::new();
    let mut msk = String::new();
    for (i, &b) in plain.iter().enumerate() {
        let m = d[i & 31] ^ ((i.wrapping_mul(41).wrapping_add(salt as usize) & 0xff) as u8);
        let e = b ^ m;
        let _ = write!(enc, "0x{:02x},", e);
        let _ = write!(msk, "0x{:02x},", m);
    }
    format!(
        "static const uint8_t {name}_ENC[{len}] = {{{enc}}};\nstatic const uint8_t {name}_MSK[{len}] = {{{msk}}};\n",
        len = plain.len()
    )
}

fn emit_elite_c_source(
    crypto_hdr_path: &Path,
    lattice: &[u64; LATTICE_WORDS],
    stage_consts: &[[u64; 16]],
    perm: &[usize; ELITE_STAGES],
    locator: &[u8; 32],
    mask_seed: &[u8; 32],
    initial_acc: u64,
) -> String {
    use std::fmt::Write;
    let mut src = String::with_capacity(245_760);
    writeln!(src, "#define _GNU_SOURCE").unwrap();
    writeln!(src, "#include <elf.h>").unwrap();
    writeln!(src, "#include <stdint.h>").unwrap();
    writeln!(src, "#include <stdio.h>").unwrap();
    writeln!(src, "#include <stdlib.h>").unwrap();
    writeln!(src, "#include <string.h>").unwrap();
    writeln!(src, "#include <sys/mman.h>").unwrap();
    writeln!(src, "#include <sys/prctl.h>").unwrap();
    writeln!(src, "#include {:?}", crypto_hdr_path.to_str().unwrap()).unwrap();
    writeln!(src, "extern const Elf64_Ehdr __ehdr_start;").unwrap();
    src.push_str(&format_xor_c_arrays("VS_LIT_ENVFD", b"VS_LEASE_FD=", mask_seed, 1));
    src.push_str(&format_xor_c_arrays("VS_LIT_ENVNAME", b"VS_LEASE_FD", mask_seed, 2));
    src.push_str(&format_xor_c_arrays("VS_LIT_STATUS", b"/proc/self/status", mask_seed, 3));
    src.push_str(&format_xor_c_arrays("VS_LIT_PID", b"Pid:", mask_seed, 4));
    src.push_str(&format_xor_c_arrays("VS_LIT_PPID", b"PPid:", mask_seed, 5));
    src.push_str(&format_xor_c_arrays("VS_LIT_TRACER", b"TracerPid:", mask_seed, 6));

    writeln!(
        src,
        "__attribute__((used, aligned(64))) static const uint64_t RO_LATTICE[{}] = {{",
        LATTICE_WORDS
    )
    .unwrap();
    for (i, w) in lattice.iter().enumerate() {
        if i % 4 == 0 {
            write!(src, "    ").unwrap();
        }
        write!(src, "0x{:016x}ULL,", w).unwrap();
        if i % 4 == 3 {
            writeln!(src).unwrap();
        }
    }
    writeln!(src, "}};").unwrap();

    writeln!(
        src,
        "__attribute__((used, aligned(64))) static const volatile uint8_t RO_VAULT[{}] = {{",
        VAULT_BYTES
    )
    .unwrap();
    for i in 0..VAULT_BYTES {
        let b = if i < 32 {
            locator[i]
        } else {
            mask_seed[i & 31].wrapping_mul((i as u8) | 1)
        };
        if i % 16 == 0 {
            write!(src, "    ").unwrap();
        }
        write!(src, "0x{:02x},", b).unwrap();
        if i % 16 == 15 {
            writeln!(src).unwrap();
        }
    }
    writeln!(src, "}};").unwrap();

    write!(src, "static const uint8_t RO_MASK_SEED[32] = {{").unwrap();
    for b in mask_seed {
        write!(src, "0x{:02x},", b).unwrap();
    }
    writeln!(src, "}};").unwrap();

    for stg in 0..ELITE_STAGES {
        let c = &stage_consts[stg];
        writeln!(
            src,
            "__attribute__((noinline, used)) static uint64_t vs_stg_{:03}(uint64_t s, const uint64_t *lat) {{",
            stg
        )
        .unwrap();
        for r in 0..16 {
            let rot = ((r * 5 + stg * 3) % 53) + 5;
            writeln!(
                src,
                "    {{ size_t idx = (size_t)(((s >> 11) ^ {}ULL ^ {}ULL) & {}); uint64_t lv = lat[idx]; s += (lv ^ 0x{:016x}ULL); s = ((s << {}) | (s >> {})) ^ (lv * 0x{:016x}ULL); s = (s * 0x{:016x}ULL) + 0x9e3779b97f4a7c15ULL; }}",
                (r as u64) * 17,
                stg,
                LATTICE_WORDS - 1,
                c[r],
                rot,
                64 - rot,
                c[(r + 3) & 15],
                c[(r + 7) & 15]
            )
            .unwrap();
        }
        writeln!(src, "    return s;\n}}").unwrap();
    }

    writeln!(src, "typedef uint64_t (*vs_stg_fn)(uint64_t, const uint64_t *);").unwrap();
    writeln!(
        src,
        "__attribute__((used, visibility(\"hidden\"))) const vs_stg_fn VS_RING[{}] = {{",
        ELITE_STAGES
    )
    .unwrap();
    for &idx in perm {
        writeln!(src, "    vs_stg_{:03},", idx).unwrap();
    }
    writeln!(src, "}};").unwrap();

    src.push_str(&format!(
        r#"
/* Direct Linux x86_64 syscalls so LD_PRELOAD libc wrappers cannot spoof prctl/openat/read */
static inline long vs_sys_prctl(int option, unsigned long a2) {{
    long ret;
    register long r10 __asm__("r10") = 0;
    register long r8  __asm__("r8")  = 0;
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "a"(157L), "D"((long)option), "S"(a2), "d"(0L), "r"(r10), "r"(r8)
        : "rcx", "r11", "memory"
    );
    return ret;
}}

static inline long vs_sys_openat(int dfd, const char *path, int flags) {{
    long ret;
    register long r10 __asm__("r10") = 0;
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "a"(257L), "D"((long)dfd), "S"(path), "d"((long)flags), "r"(r10)
        : "rcx", "r11", "memory"
    );
    return ret;
}}

static inline long vs_sys_read(int fd, void *buf, size_t count) {{
    long ret;
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "a"(0L), "D"((long)fd), "S"(buf), "d"(count)
        : "rcx", "r11", "memory"
    );
    return ret;
}}

static inline long vs_sys_close(int fd) {{
    long ret;
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "a"(3L), "D"((long)fd)
        : "rcx", "r11", "memory"
    );
    return ret;
}}

static inline void *vs_sys_mmap_anon(size_t length) {{
    long ret;
    register long r10 __asm__("r10") = 0x22L; /* MAP_PRIVATE | MAP_ANONYMOUS */
    register long r8  __asm__("r8")  = -1L;
    register long r9  __asm__("r9")  = 0L;
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "a"(9L), "D"(0L), "S"(length), "d"(0x3L /* PROT_READ|PROT_WRITE */), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    if (ret < 0 && ret >= -4095L) return MAP_FAILED;
    return (void *)ret;
}}

static inline long vs_sys_munmap(void *addr, size_t length) {{
    long ret;
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "a"(11L), "D"(addr), "S"(length)
        : "rcx", "r11", "memory"
    );
    return ret;
}}

static inline long vs_sys_mlock(const void *addr, size_t length) {{
    long ret;
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "a"(149L), "D"(addr), "S"(length)
        : "rcx", "r11", "memory"
    );
    return ret;
}}

static inline long vs_sys_munlock(const void *addr, size_t length) {{
    long ret;
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "a"(150L), "D"(addr), "S"(length)
        : "rcx", "r11", "memory"
    );
    return ret;
}}

static inline long vs_sys_madvise(void *addr, size_t length, int advice) {{
    long ret;
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "a"(28L), "D"(addr), "S"(length), "d"((long)advice)
        : "rcx", "r11", "memory"
    );
    return ret;
}}

__attribute__((constructor(101)))
static void vs_early_process_lock(void) {{
    (void)vs_sys_prctl(4 /* PR_SET_DUMPABLE */, 0UL);
    (void)vs_sys_prctl(38 /* PR_SET_NO_NEW_PRIVS */, 1UL);
    (void)vs_sys_prctl(0x59616d61 /* PR_SET_PTRACER */, 0UL);
}}

static void vs_unmask_str(char *dst, const uint8_t *enc, const uint8_t *msk, size_t n) {{
    for (size_t i = 0; i < n; i++) {{
        dst[i] = (char)(enc[i] ^ msk[i]);
    }}
    dst[n] = '\0';
}}

static long vs_read_all_fd(int fd, uint8_t *buf, size_t max_len) {{
    size_t total = 0U;
    while (total < max_len) {{
        long r = vs_sys_read(fd, buf + total, max_len - total);
        if (r == -4L) continue; /* -EINTR */
        if (r < 0L) return -1L;
        if (r == 0L) break;
        total += (size_t)r;
    }}
    return (long)total;
}}

static int compute_integrity_digest(
    uint8_t out_hash[32],
    uintptr_t *rx_lo_out,
    uintptr_t *rx_hi_out,
    uintptr_t *load_bias_out
) {{
    const Elf64_Ehdr *eh = &__ehdr_start;
    const Elf64_Phdr *ph = (const Elf64_Phdr *)((const uint8_t *)eh + eh->e_phoff);
    uintptr_t first_vaddr = 0;
    int have_first = 0;
    for (uint16_t i = 0; i < eh->e_phnum; i++) {{
        if (ph[i].p_type == PT_LOAD) {{
            first_vaddr = (uintptr_t)ph[i].p_vaddr;
            have_first = 1;
            break;
        }}
    }}
    if (!have_first) return -1;
    uintptr_t load_bias = (uintptr_t)eh - first_vaddr;
    uintptr_t v_lo = (uintptr_t)(const volatile void *)RO_VAULT;
    uintptr_t v_hi = v_lo + sizeof(RO_VAULT);

    vs_sha256_ctx ctx;
    vs_sha256_init(&ctx);
    int found_rx = 0;
    int vault_covered = 0;
    uintptr_t rx_lo = UINTPTR_MAX, rx_hi = 0;
    for (uint16_t i = 0; i < eh->e_phnum; i++) {{
        if (ph[i].p_type == PT_LOAD && (ph[i].p_flags & PF_W) == 0U) {{
            uintptr_t seg_lo = load_bias + (uintptr_t)ph[i].p_vaddr;
            uintptr_t seg_hi = seg_lo + (uintptr_t)ph[i].p_filesz;
            if ((ph[i].p_flags & PF_X) != 0U) {{
                if (seg_lo < rx_lo) rx_lo = seg_lo;
                if (seg_hi > rx_hi) rx_hi = seg_hi;
                found_rx = 1;
            }}
            if (v_hi <= seg_lo || v_lo >= seg_hi) {{
                vs_sha256_update(&ctx, (const uint8_t *)seg_lo, (size_t)ph[i].p_filesz);
            }} else {{
                vault_covered = 1;
                uintptr_t excl_lo = (v_lo > seg_lo) ? v_lo : seg_lo;
                uintptr_t excl_hi = (v_hi < seg_hi) ? v_hi : seg_hi;
                if (excl_lo > seg_lo) {{
                    vs_sha256_update(&ctx, (const uint8_t *)seg_lo, (size_t)(excl_lo - seg_lo));
                }}
                if (excl_hi < seg_hi) {{
                    vs_sha256_update(&ctx, (const uint8_t *)excl_hi, (size_t)(seg_hi - excl_hi));
                }}
            }}
        }}
    }}
    if (!found_rx || !vault_covered) {{
        vs_secure_zero(&ctx, sizeof(ctx));
        return -1;
    }}
    vs_sha256_update(&ctx, (const uint8_t *)RO_LATTICE, sizeof(RO_LATTICE));
    vs_sha256_update(&ctx, RO_MASK_SEED, sizeof(RO_MASK_SEED));
    for (size_t i = 0; i < {stages}; i++) {{
        uint64_t rel_off = (uint64_t)((uintptr_t)VS_RING[i] - load_bias);
        uint8_t le[8];
        vs_store32_le(le + 0, (uint32_t)(rel_off & 0xffffffffULL));
        vs_store32_le(le + 4, (uint32_t)(rel_off >> 32));
        vs_sha256_update(&ctx, le, 8U);
    }}
    vs_sha256_final(&ctx, out_hash);
    vs_secure_zero(&ctx, sizeof(ctx));
    *rx_lo_out = rx_lo;
    *rx_hi_out = rx_hi;
    *load_bias_out = load_bias;
    return 0;
}}

/* Fail-closed runtime status & dumpable check via direct kernel syscalls */
static uint32_t read_runtime_tracer_field(long *dumpable_out) {{
    long dmp = vs_sys_prctl(3 /* PR_GET_DUMPABLE */, 0UL);
    *dumpable_out = dmp;
    if (dmp != 0L) return 0xfffffffeU;

    char path[18];
    vs_unmask_str(path, VS_LIT_STATUS_ENC, VS_LIT_STATUS_MSK, sizeof(VS_LIT_STATUS_ENC));
    long fd = vs_sys_openat(-100, path, 0);
    vs_secure_zero(path, sizeof(path));
    if (fd < 0L) return 0xffffffffU;

    char buf[8192];
    long n = vs_read_all_fd((int)fd, (uint8_t *)buf, sizeof(buf) - 1U);
    int overflow_file = 0;
    if (n == (long)(sizeof(buf) - 1U)) {{
        uint8_t extra = 0U;
        long r_extra;
        do {{
            r_extra = vs_sys_read((int)fd, &extra, 1U);
        }} while (r_extra == -4L);
        if (r_extra != 0L) overflow_file = 1;
    }}
    (void)vs_sys_close((int)fd);
    if (n <= 0L || overflow_file) {{
        vs_secure_zero(buf, sizeof(buf));
        return 0xffffffffU;
    }}
    buf[n] = '\0';

    char pid_tag[5], ppid_tag[6], tr_tag[11];
    vs_unmask_str(pid_tag, VS_LIT_PID_ENC, VS_LIT_PID_MSK, sizeof(VS_LIT_PID_ENC));
    vs_unmask_str(ppid_tag, VS_LIT_PPID_ENC, VS_LIT_PPID_MSK, sizeof(VS_LIT_PPID_ENC));
    vs_unmask_str(tr_tag, VS_LIT_TRACER_ENC, VS_LIT_TRACER_MSK, sizeof(VS_LIT_TRACER_ENC));

    int saw_pid = 0;
    int saw_ppid = 0;
    int tracer_count = 0;
    int invalid = 0;
    uint32_t val = 0xffffffffU;

    size_t pos = 0U;
    size_t total = (size_t)n;
    while (pos < total) {{
        size_t lend = pos;
        while (lend < total && buf[lend] != '\n') lend++;
        const char *line = buf + pos;
        size_t llen = lend - pos;

        if (llen >= 5U && memcmp(line, pid_tag, 4U) == 0 && (line[4] == '\t' || line[4] == ' ')) {{
            saw_pid = 1;
        }} else if (llen >= 6U && memcmp(line, ppid_tag, 5U) == 0 && (line[5] == '\t' || line[5] == ' ')) {{
            if (saw_pid) saw_ppid = 1;
        }} else if (llen >= 10U && memcmp(line, tr_tag, 10U) == 0 &&
                   (llen == 10U || line[10] == '\t' || line[10] == ' ' || (line[10] >= '0' && line[10] <= '9'))) {{
            if (!saw_pid || !saw_ppid) {{
                invalid = 1;
                break;
            }}
            tracer_count++;
            if (tracer_count > 1) {{
                invalid = 1;
                break;
            }}
            size_t k = 10U;
            while (k < llen && (line[k] == ' ' || line[k] == '\t')) k++;
            if (k >= llen || line[k] < '0' || line[k] > '9') {{
                invalid = 1;
                break;
            }}
            uint32_t parsed = 0U;
            while (k < llen && line[k] >= '0' && line[k] <= '9') {{
                uint32_t d = (uint32_t)(line[k] - '0');
                if (parsed > (0x0fffffffU - d) / 10U) {{
                    invalid = 1;
                    parsed = 0xffffffffU;
                    break;
                }}
                parsed = parsed * 10U + d;
                k++;
            }}
            if (invalid) break;
            while (k < llen && (line[k] == ' ' || line[k] == '\t' || line[k] == '\r')) k++;
            if (k != llen) {{
                invalid = 1;
                break;
            }}
            val = parsed;
        }}
        pos = (lend < total) ? (lend + 1U) : lend;
    }}

    vs_secure_zero(pid_tag, sizeof(pid_tag));
    vs_secure_zero(ppid_tag, sizeof(ppid_tag));
    vs_secure_zero(tr_tag, sizeof(tr_tag));
    vs_secure_zero(buf, sizeof(buf));
    if (invalid || !saw_pid || !saw_ppid || tracer_count != 1) {{
        return 0xffffffffU;
    }}
    return val;
}}

static int ingest_lease_key(int argc, char **argv, char **envp, uint8_t lease_key[32]) {{
    char env_pfx[13], env_name[12];
    vs_unmask_str(env_pfx, VS_LIT_ENVFD_ENC, VS_LIT_ENVFD_MSK, sizeof(VS_LIT_ENVFD_ENC));
    vs_unmask_str(env_name, VS_LIT_ENVNAME_ENC, VS_LIT_ENVNAME_MSK, sizeof(VS_LIT_ENVNAME_ENC));

    int lfd = -1;
    int bad_env = 0;
    if (envp != NULL) {{
        for (size_t i = 0; envp[i] != NULL; i++) {{
            if (memcmp(envp[i], env_pfx, 12U) == 0) {{
                char *val = envp[i] + 12;
                size_t digits = 0U;
                int acc = 0;
                while (val[digits] >= '0' && val[digits] <= '9') {{
                    if (digits >= 6U) {{
                        bad_env = 1;
                        break;
                    }}
                    acc = acc * 10 + (int)(val[digits] - '0');
                    digits++;
                }}
                if (bad_env || digits == 0U || val[digits] != '\0' || acc < 3) {{
                    vs_secure_zero(val, strlen(val));
                    bad_env = 1;
                }} else {{
                    vs_secure_zero(val, digits);
                    lfd = acc;
                }}
                break;
            }}
        }}
    }}
    unsetenv(env_name);
    vs_secure_zero(env_pfx, sizeof(env_pfx));
    vs_secure_zero(env_name, sizeof(env_name));
    if (bad_env) return -1;

    if (lfd >= 3) {{
        char hex_buf[65];
        long got = vs_read_all_fd(lfd, (uint8_t *)hex_buf, 64U);
        (void)vs_sys_close(lfd);
        if (got != 64L) {{
            vs_secure_zero(hex_buf, sizeof(hex_buf));
            return -1;
        }}
        hex_buf[64] = '\0';
        int rc = vs_hex_decode(hex_buf, lease_key, 32U);
        vs_secure_zero(hex_buf, sizeof(hex_buf));
        return rc == 32 ? 0 : -1;
    }}
    if (argc < 2 || !argv[1]) return -1;
    size_t alen = strlen(argv[1]);
    int rc = vs_hex_decode(argv[1], lease_key, 32U);
    /* Immediately scrub argv[1] in process stack memory */
    vs_secure_zero(argv[1], alen);
    return rc == 32 ? 0 : -1;
}}

int main(int argc, char **argv, char **envp) {{
    (void)vs_sys_prctl(4 /* PR_SET_DUMPABLE */, 0UL);
    (void)vs_sys_prctl(38 /* PR_SET_NO_NEW_PRIVS */, 1UL);
    (void)vs_sys_prctl(0x59616d61 /* PR_SET_PTRACER */, 0UL);

    uint8_t lease_key[32];
    if (ingest_lease_key(argc, argv, envp, lease_key) != 0) {{
        vs_secure_zero(lease_key, sizeof(lease_key));
        return 2;
    }}

    long dmp_pre = 1L;
    uint32_t tr_pre = read_runtime_tracer_field(&dmp_pre);

    uint8_t rx_hash[32];
    uintptr_t rx_lo = 0, rx_hi = 0, load_bias = 0;
    if (compute_integrity_digest(rx_hash, &rx_lo, &rx_hi, &load_bias) != 0) {{
        vs_secure_zero(rx_hash, sizeof(rx_hash));
        vs_secure_zero(lease_key, sizeof(lease_key));
        return 3;
    }}
    (void)load_bias;

    uint64_t acc = 0x{:016x}ULL;
    for (size_t i = 0; i < {stages}; i++) {{
        uintptr_t fn_ptr = (uintptr_t)VS_RING[i];
        if (fn_ptr < rx_lo || fn_ptr >= rx_hi) {{
            vs_secure_zero(rx_hash, sizeof(rx_hash));
            vs_secure_zero(lease_key, sizeof(lease_key));
            return 3;
        }}
        acc = VS_RING[i](acc, RO_LATTICE);
    }}
    long dumpable = 1L;
    uint32_t tr_post = read_runtime_tracer_field(&dumpable);
    uint32_t tr_state = tr_pre | tr_post | ((dmp_pre == 0L && dumpable == 0L) ? 0U : 0xfffffffeU);

    uint8_t raw[{vault_bytes}];
    for (size_t i = 0; i < {vault_bytes}; i++) {{
        size_t phys = (i * 73U) % {vault_bytes}U;
        uint8_t m = RO_MASK_SEED[i & 31U] ^ (uint8_t)((i * 29U) & 0xffU);
        raw[i] = RO_VAULT[phys] ^ m;
    }}

    uint8_t salt[32], nonce[12], cmt4[32], tag[16];
    memcpy(salt,  raw + 0,  32);
    memcpy(nonce, raw + 32, 12);
    memcpy(cmt4,  raw + 44, 32);
    memcpy(tag,   raw + 76, 16);

    uint8_t transcript[48];
    memcpy(transcript + 0, rx_hash, 32);
    vs_store32_le(transcript + 32, (uint32_t)(acc & 0xffffffffULL));
    vs_store32_le(transcript + 36, (uint32_t)(acc >> 32));
    vs_store32_le(transcript + 40, tr_state);
    memcpy(transcript + 44, "ENC2", 4);

    uint8_t enc_key[32], cmt_key[32];
    vs_hkdf_sha256_32(lease_key, 32, salt, 32, transcript, 48, enc_key);
    memcpy(transcript + 44, "CMT2", 4);
    vs_hkdf_sha256_32(lease_key, 32, salt, 32, transcript, 48, cmt_key);
    vs_secure_zero(lease_key, sizeof(lease_key));

    uint8_t cmt_msg[56];
    memcpy(cmt_msg, nonce, 12);
    memcpy(cmt_msg + 12, transcript, 44);
    uint8_t expected_cmt[32];
    vs_hmac_sha256(cmt_key, 32, cmt_msg, 56, expected_cmt);
    vs_secure_zero(cmt_key, sizeof(cmt_key));
    vs_secure_zero(cmt_msg, sizeof(cmt_msg));

    uint8_t diff = 0;
    for (size_t i = 0; i < 32; i++) diff |= (uint8_t)(expected_cmt[i] ^ cmt4[i]);
    vs_secure_zero(expected_cmt, sizeof(expected_cmt));
    if (diff != 0) {{
        vs_secure_zero(enc_key, sizeof(enc_key));
        vs_secure_zero(raw, sizeof(raw));
        vs_secure_zero(salt, sizeof(salt));
        vs_secure_zero(nonce, sizeof(nonce));
        vs_secure_zero(cmt4, sizeof(cmt4));
        vs_secure_zero(tag, sizeof(tag));
        vs_secure_zero(transcript, sizeof(transcript));
        vs_secure_zero(rx_hash, sizeof(rx_hash));
        return 3;
    }}

    uint8_t aad[120];
    memcpy(aad + 0,  salt, 32);
    memcpy(aad + 32, nonce, 12);
    memcpy(aad + 44, cmt4, 32);
    memcpy(aad + 76, transcript, 44);

    const size_t map_sz = 8192U;
    uint8_t *page = (uint8_t *)vs_sys_mmap_anon(map_sz);
    if (page == MAP_FAILED) {{
        vs_secure_zero(enc_key, sizeof(enc_key));
        vs_secure_zero(raw, sizeof(raw));
        vs_secure_zero(aad, sizeof(aad));
        vs_secure_zero(salt, sizeof(salt));
        vs_secure_zero(nonce, sizeof(nonce));
        vs_secure_zero(cmt4, sizeof(cmt4));
        vs_secure_zero(tag, sizeof(tag));
        vs_secure_zero(transcript, sizeof(transcript));
        vs_secure_zero(rx_hash, sizeof(rx_hash));
        return 4;
    }}
    (void)vs_sys_mlock(page, map_sz);
#ifdef MADV_DONTDUMP
    (void)vs_sys_madvise(page, map_sz, MADV_DONTDUMP);
#endif

    int rc = vs_chacha20_poly1305_open(enc_key, nonce, aad, 120, raw + 92, {enc_frame_len}U, tag, page);
    vs_secure_zero(enc_key, sizeof(enc_key));
    vs_secure_zero(raw, sizeof(raw));
    vs_secure_zero(aad, sizeof(aad));
    vs_secure_zero(salt, sizeof(salt));
    vs_secure_zero(nonce, sizeof(nonce));
    vs_secure_zero(cmt4, sizeof(cmt4));
    vs_secure_zero(tag, sizeof(tag));
    vs_secure_zero(transcript, sizeof(transcript));
    vs_secure_zero(rx_hash, sizeof(rx_hash));
    if (rc != 0) {{
        vs_secure_zero(page, map_sz);
        (void)vs_sys_munlock(page, map_sz);
        (void)vs_sys_munmap(page, map_sz);
        return 3;
    }}

    uint32_t plain_len = vs_load32_le(page);
    if (plain_len == 0U || plain_len > 4096U) {{
        vs_secure_zero(page, map_sz);
        (void)vs_sys_munlock(page, map_sz);
        (void)vs_sys_munmap(page, map_sz);
        return 3;
    }}

    uint8_t payload_sha[32];
    vs_sha256(page + 4, plain_len, payload_sha);
    vs_secure_zero(page, map_sz);
    (void)vs_sys_munlock(page, map_sz);
    (void)vs_sys_munmap(page, map_sz);

    char payload_sha_hex[65];
    vs_hex_encode(payload_sha, 32, payload_sha_hex);
    printf("{{\"ok\":true,\"dumpable\":%ld,\"payloadSha256\":\"%s\"}}\n", dumpable, payload_sha_hex);
    vs_secure_zero(payload_sha, sizeof(payload_sha));
    vs_secure_zero(payload_sha_hex, sizeof(payload_sha_hex));
    return 0;
}}
"#,
        initial_acc,
        stages = ELITE_STAGES,
        vault_bytes = VAULT_BYTES,
        enc_frame_len = ENC_FRAME_LEN,
    ));

    src
}

pub fn build_protected_elf_elite(
    master_key: &[u8; 32],
    crypto_hdr_path: &Path,
    asset_id: &str,
    plain_payload: &[u8],
    out_elf_path: &Path,
) -> Result<(String, String), String> {
    if plain_payload.is_empty() || plain_payload.len() > 4096 {
        return Err("PAYLOAD_BOUNDS".to_string());
    }

    let mut build_nonce = [0u8; 32];
    os_random_bytes(&mut build_nonce)?;
    let mut build_seed = hmac_sha256(&build_nonce, asset_id.as_bytes());
    secure_zero(&mut build_nonce);

    let mut locator = [0u8; 32];
    os_random_bytes(&mut locator)?;
    let mut mask_seed = [0u8; 32];
    os_random_bytes(&mut mask_seed)?;

    let mut lattice = [0u64; LATTICE_WORDS];
    for i in 0..LATTICE_WORDS {
        let mut m = [0u8; 36];
        m[0..32].copy_from_slice(&build_seed);
        m[32..36].copy_from_slice(&(i as u32).to_le_bytes());
        let d = sha256(&m);
        lattice[i] = u64::from_le_bytes(d[0..8].try_into().unwrap());
    }

    let mut stage_consts = [[0u64; 16]; ELITE_STAGES];
    for stg in 0..ELITE_STAGES {
        stage_consts[stg] = derive_stage_constants(&build_seed, stg);
    }

    let mut perm = [0usize; ELITE_STAGES];
    for (i, p) in perm.iter_mut().enumerate() {
        *p = i;
    }
    for i in (1..ELITE_STAGES).rev() {
        let d = sha256(&[&build_seed[..], &(i as u32).to_le_bytes()].concat());
        let j = (u32::from_le_bytes(d[0..4].try_into().unwrap()) as usize) % (i + 1);
        perm.swap(i, j);
    }

    let init_digest = sha256(&[&build_seed[..], b"INIT_ACC"].concat());
    let initial_acc = u64::from_le_bytes(init_digest[0..8].try_into().unwrap());
    secure_zero(&mut build_seed);

    let mut acc = initial_acc;
    for &stg_idx in &perm {
        acc = eval_stage_rust(acc, &lattice, &stage_consts[stg_idx], stg_idx);
    }

    let mut c_src = emit_elite_c_source(
        crypto_hdr_path,
        &lattice,
        &stage_consts,
        &perm,
        &locator,
        &mask_seed,
        initial_acc,
    );

    let tmp_c = out_elf_path.with_extension("elite_gen.c");
    fs::write(&tmp_c, &c_src).map_err(|e| e.to_string())?;
    unsafe {
        secure_zero(c_src.as_bytes_mut());
    }

    let tmp_str = tmp_c.to_str().ok_or("BAD_TMP_C_PATH")?;
    let out_str = out_elf_path.to_str().ok_or("BAD_OUT_ELF_PATH")?;
    let status = Command::new("gcc")
        .args([
            "-O1",
            "-fno-tree-loop-distribute-patterns",
            "-fPIE",
            "-pie",
            "-fstack-protector-strong",
            "-D_FORTIFY_SOURCE=3",
            "-fcf-protection=full",
            "-Wl,-z,relro,-z,now,-z,separate-code,-z,ibt,-z,shstk",
            "-Wall",
            "-Wextra",
            tmp_str,
            "-o",
            out_str,
        ])
        .status();
    let _ = fs::remove_file(&tmp_c);
    let status = status.map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("GCC_ELITE_FAILED".to_string());
    }

    let elf_pre = fs::read(out_elf_path).map_err(|e| e.to_string())?;
    let ring_offsets = extract_vs_ring_offsets_pre_strip(&elf_pre)?;

    let strip_status = Command::new("strip")
        .args(["-s", out_str])
        .status()
        .map_err(|e| e.to_string())?;
    if !strip_status.success() {
        return Err("STRIP_ELITE_FAILED".to_string());
    }

    let mut elf = fs::read(out_elf_path).map_err(|e| e.to_string())?;
    let vault_pos = elf
        .windows(32)
        .position(|w| w == locator)
        .ok_or_else(|| "MISSING_RO_VAULT_LOCATOR".to_string())?;
    let vault_end = vault_pos.checked_add(VAULT_BYTES).ok_or("VAULT_OVERFLOW")?;

    let rx_hash = compute_integrity_digest_rust(
        &elf,
        vault_pos,
        vault_end,
        &lattice,
        &mask_seed,
        &ring_offsets,
    )?;
    let rx_hex = hex_encode(&rx_hash);

    let lease_info = encode_canonical_vspk3_info("native-elite", asset_id, "");
    let mut lease_root_key = hkdf_sha256_32(master_key, asset_id.as_bytes(), &lease_info);

    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    os_random_bytes(&mut salt)?;
    os_random_bytes(&mut nonce)?;

    let mut transcript = [0u8; 48];
    transcript[0..32].copy_from_slice(&rx_hash);
    transcript[32..40].copy_from_slice(&acc.to_le_bytes());
    transcript[40..44].copy_from_slice(&0u32.to_le_bytes());
    transcript[44..48].copy_from_slice(b"ENC2");
    let mut enc_key = hkdf_sha256_32(&lease_root_key, &salt, &transcript);
    transcript[44..48].copy_from_slice(b"CMT2");
    let mut cmt_key = hkdf_sha256_32(&lease_root_key, &salt, &transcript);

    let mut cmt_msg = [0u8; 56];
    cmt_msg[0..12].copy_from_slice(&nonce);
    cmt_msg[12..56].copy_from_slice(&transcript[0..44]);
    let cmt4 = hmac_sha256(&cmt_key, &cmt_msg);
    secure_zero(&mut cmt_key);

    let mut aad = [0u8; 120];
    aad[0..32].copy_from_slice(&salt);
    aad[32..44].copy_from_slice(&nonce);
    aad[44..76].copy_from_slice(&cmt4);
    aad[76..120].copy_from_slice(&transcript[0..44]);

    // Fixed 4100-byte Pad-Then-Encrypt frame (hides exact plain_payload length!)
    let mut plain_frame = vec![0u8; ENC_FRAME_LEN];
    plain_frame[0..4].copy_from_slice(&(plain_payload.len() as u32).to_le_bytes());
    plain_frame[4..4 + plain_payload.len()].copy_from_slice(plain_payload);
    if ENC_FRAME_LEN > 4 + plain_payload.len() {
        os_random_bytes(&mut plain_frame[4 + plain_payload.len()..])?;
    }

    let (ct, tag) = chacha20_poly1305_seal(&enc_key, &nonce, &aad, &plain_frame);
    secure_zero(&mut enc_key);
    secure_zero(&mut plain_frame);

    let mut raw_vault = vec![0u8; VAULT_BYTES];
    os_random_bytes(&mut raw_vault)?;
    raw_vault[0..32].copy_from_slice(&salt);
    raw_vault[32..44].copy_from_slice(&nonce);
    raw_vault[44..76].copy_from_slice(&cmt4);
    raw_vault[76..92].copy_from_slice(&tag);
    raw_vault[92..92 + ENC_FRAME_LEN].copy_from_slice(&ct);

    let mut phys_vault = vec![0u8; VAULT_BYTES];
    for i in 0..VAULT_BYTES {
        let phys = (i * 73) % VAULT_BYTES;
        let m = mask_seed[i & 31] ^ (((i * 29) & 0xff) as u8);
        phys_vault[phys] = raw_vault[i] ^ m;
    }
    secure_zero(&mut raw_vault);
    let dest = elf
        .get_mut(vault_pos..vault_end)
        .ok_or("TRUNCATED_VAULT_REGION")?;
    dest.copy_from_slice(&phys_vault);

    let post_rx = compute_integrity_digest_rust(
        &elf,
        vault_pos,
        vault_end,
        &lattice,
        &mask_seed,
        &ring_offsets,
    )?;
    secure_zero(&mut mask_seed);
    if post_rx != rx_hash {
        secure_zero(&mut lease_root_key);
        return Err("RX_OR_RO_INTEGRITY_MUTATED".to_string());
    }
    if let Err(e) = fs::write(out_elf_path, &elf) {
        secure_zero(&mut lease_root_key);
        return Err(e.to_string());
    }

    let lease_hex = hex_encode(&lease_root_key);
    secure_zero(&mut lease_root_key);
    Ok((lease_hex, rx_hex))
}
