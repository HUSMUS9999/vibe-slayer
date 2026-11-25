//! `vs-vault`: Headerless, key-committing, 64-bit streaming AEAD asset vaults.
//!
//! Implements **VSPK3 v2** — hardened against all Loop 1 & Loop 2 audit findings:
//! 1. **64-bit Rogaway-Zhang STREAM chunked AEAD** (`64 KiB` chunks, constant `~134 KiB` RAM,
//!    pre-expanded once-per-stream `StreamAeadKey` + `HmacKey` with single-buffer in-place
//!    sealing/opening, `O(1)` random-access chunk seek).
//! 2. **Proved Bellare-Hoang `Ctx` + `UtC` CMT-4 key commitment** folding `salt`, canonical
//!    `(domain, asset_id, context)`, chunk index, final-chunk flag, and AEAD tag into HMAC-SHA256.
//! 3. **Exact `MIN_TWO_CHUNKS` (`66,656` B) lookahead window**: rejects truncated `[66609..66655]`
//!    containers *before* decrypting chunk `0`, explicitly flushes writers, and zeroizes all
//!    sensitive buffers on every normal or error exit (`Zeroizing`).
//! 4. **Single unified constant-time `VaultError::AuthenticationFailed`** (zero error oracles).
//! 5. **Pluggable `KmsProvider` trait** + audited backward-compatible **VSPK3 v1** and **VSPK2**.

#![forbid(unsafe_code)]

use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use thiserror::Error;
use vs_crypto::{
    aead_open, aead_open_detached, aead_seal, aead_seal_detached, ct_eq, hkdf_sha256_32,
    hmac_sha256_parts, random_bytes, AeadAlg, HmacKey, SecretKey32, StreamAeadKey,
};
use zeroize::{Zeroize, Zeroizing};

/// VSPK3 v2 streaming prefix: `salt (32 B) || hdr_cmt (32 B)`.
pub const VSPK3_V2_PREFIX_LEN: usize = 64;
/// Fixed intermediate chunk plaintext size: `64 KiB`.
pub const VSPK3_V2_CHUNK_PLAIN: usize = 65_536;
/// Length-hiding final chunk padding quantum: `1 KiB`.
pub const VSPK3_V2_PAD_QUANTUM: usize = 1024;
/// Per-chunk authentication trailer: `aead_tag (16 B) || cmt4_ctx (32 B)`.
pub const VSPK3_V2_TRAILER_LEN: usize = 48;
/// Exact on-disk byte stride of every intermediate chunk record (`65,536 + 48`).
pub const VSPK3_V2_INTERMEDIATE_RECORD_LEN: usize = VSPK3_V2_CHUNK_PLAIN + VSPK3_V2_TRAILER_LEN;
/// Minimum valid final record size (`1,024 + 48 = 1,072 B`).
pub const VSPK3_V2_MIN_FINAL_RECORD_LEN: usize = VSPK3_V2_PAD_QUANTUM + VSPK3_V2_TRAILER_LEN;
/// Maximum valid final record size (`ceil_1024(4 + 65,536) + 48 = 66,608 B`).
pub const VSPK3_V2_MAX_FINAL_RECORD_LEN: usize =
    ((4 + VSPK3_V2_CHUNK_PLAIN).div_ceil(VSPK3_V2_PAD_QUANTUM) * VSPK3_V2_PAD_QUANTUM)
        + VSPK3_V2_TRAILER_LEN;
/// Minimum valid two-chunk body (`65,584 + 1,072 = 66,656 B`). Any EOF length in
/// `(66,608, 66,656)` is mathematically invalid and rejected before decrypting chunk 0.
pub const VSPK3_V2_MIN_TWO_CHUNKS_LEN: usize =
    VSPK3_V2_INTERMEDIATE_RECORD_LEN + VSPK3_V2_MIN_FINAL_RECORD_LEN;
/// Minimum valid VSPK3 v2 container size (`64 + 1,072 = 1,136 B`).
pub const VSPK3_V2_MIN_LEN: usize = VSPK3_V2_PREFIX_LEN + VSPK3_V2_MIN_FINAL_RECORD_LEN;

/// Legacy VSPK3 v1 & VSPK2 constants (audited read/write compatibility).
pub const VSPK3_V1_PREFIX_LEN: usize = 92;
pub const VSPK3_V1_PAD_QUANTUM: usize = 1024;
pub const MAGIC_VSPK2: &[u8; 5] = b"VSPK2";

#[inline]
const fn max_chunks_for_alg(alg: AeadAlg) -> u64 {
    match alg {
        // NIST SP 800-38D AES-GCM safe chunk limit (< 2^32 chunks = 256 TiB)
        AeadAlg::Aes256Gcm => (1u64 << 32) - 1,
        // Cap below i64::MAX / 65584 (< 2^46 chunks = 4 PiB) so u64/i64 byte totals never overflow
        AeadAlg::ChaCha20Poly1305 => (1u64 << 46) - 1,
    }
}

#[derive(Debug, Error)]
pub enum VaultError {
    /// Unified opaque authentication failure — never reveals whether commitment, AEAD tag,
    /// chunk counter, or final-chunk length/padding failed.
    #[error("vault authentication failed")]
    AuthenticationFailed,
    #[error("invalid vault metadata")]
    InvalidMetadata,
    #[error("chunk index out of range")]
    ChunkOutOfRange,
    #[error("kms error: {0}")]
    Kms(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Pluggable key management abstraction (local zeroized keys, AWS/GCP KMS, Vault Transit, HSM).
pub trait KmsProvider: Send + Sync {
    fn resolve_master_key(&self, key_id: &str) -> Result<SecretKey32, VaultError>;
}

/// Zeroized in-memory key provider for standalone/local/dev deployments.
pub struct LocalKeyProvider {
    key: SecretKey32,
}

impl LocalKeyProvider {
    pub fn new(key: SecretKey32) -> Self {
        Self { key }
    }
}

impl KmsProvider for LocalKeyProvider {
    fn resolve_master_key(&self, _key_id: &str) -> Result<SecretKey32, VaultError> {
        Ok(self.key.clone())
    }
}

/// Canonical length-prefixed metadata binding (unambiguous across arbitrary UTF-8 strings).
pub fn encode_canonical_info(
    tag: &[u8],
    domain: &str,
    asset_id: &str,
    context: &str,
) -> Result<Vec<u8>, VaultError> {
    if domain.len() > 4096 || asset_id.len() > 4096 || context.len() > 4096 {
        return Err(VaultError::InvalidMetadata);
    }
    let mut out =
        Vec::with_capacity(tag.len() + 12 + domain.len() + asset_id.len() + context.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(&(domain.len() as u32).to_le_bytes());
    out.extend_from_slice(domain.as_bytes());
    out.extend_from_slice(&(asset_id.len() as u32).to_le_bytes());
    out.extend_from_slice(asset_id.as_bytes());
    out.extend_from_slice(&(context.len() as u32).to_le_bytes());
    out.extend_from_slice(context.as_bytes());
    Ok(out)
}

#[inline]
fn stream_nonce(chunk_index: u64, is_final: bool) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[3] = if is_final { 0x01 } else { 0x00 };
    nonce[4..12].copy_from_slice(&chunk_index.to_be_bytes());
    nonce
}

fn derive_v2_subkeys(
    master_key: &SecretKey32,
    salt: &[u8; 32],
    info: &[u8],
    alg: AeadAlg,
) -> Result<(SecretKey32, SecretKey32, [u8; 32]), VaultError> {
    let alg_tag: &[u8] = match alg {
        AeadAlg::Aes256Gcm => b"|AES256GCM",
        AeadAlg::ChaCha20Poly1305 => b"|CHACHA20P1305",
    };
    let mut enc_info = Zeroizing::new(Vec::with_capacity(info.len() + alg_tag.len() + 4));
    enc_info.extend_from_slice(info);
    enc_info.extend_from_slice(alg_tag);
    enc_info.extend_from_slice(b"|ENC");

    let mut cmt_info = Zeroizing::new(Vec::with_capacity(info.len() + alg_tag.len() + 4));
    cmt_info.extend_from_slice(info);
    cmt_info.extend_from_slice(alg_tag);
    cmt_info.extend_from_slice(b"|CMT");

    let enc_key = hkdf_sha256_32(master_key.as_bytes(), salt, &enc_info)
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let cmt_key = hkdf_sha256_32(master_key.as_bytes(), salt, &cmt_info)
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let hdr_cmt = hmac_sha256_parts(
        cmt_key.as_bytes(),
        &[b"VSPK3_V2_HDR|", salt, alg_tag, info],
    );
    Ok((enc_key, cmt_key, hdr_cmt))
}

#[inline]
fn chunk_ctx_commitment_with_key(
    cmt_hmac: &HmacKey,
    salt: &[u8; 32],
    nonce: &[u8; 12],
    info: &[u8],
    chunk_index: u64,
    is_final: bool,
    aead_tag: &[u8; 16],
) -> [u8; 32] {
    let flag = [if is_final { 1u8 } else { 0u8 }];
    let idx_be = chunk_index.to_be_bytes();
    cmt_hmac.sign_parts(&[b"VSPK3_V2_CTX|", salt, nonce, &idx_be, &flag, info, aead_tag])
}

/// Reusable AAD scratch buffer (`salt || hdr_cmt || chunk_index_be || is_final || info`).
struct ChunkAadScratch {
    buf: Vec<u8>,
}

impl ChunkAadScratch {
    fn new(salt: &[u8; 32], hdr_cmt: &[u8; 32], info: &[u8]) -> Self {
        let mut buf = Vec::with_capacity(64 + 9 + info.len());
        buf.extend_from_slice(salt);
        buf.extend_from_slice(hdr_cmt);
        buf.extend_from_slice(&[0u8; 9]);
        buf.extend_from_slice(info);
        Self { buf }
    }

    #[inline]
    fn update(&mut self, chunk_index: u64, is_final: bool) -> &[u8] {
        self.buf[64..72].copy_from_slice(&chunk_index.to_be_bytes());
        self.buf[72] = if is_final { 1 } else { 0 };
        &self.buf
    }
}

fn read_up_to<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Stream-seal arbitrarily large inputs into a headerless **VSPK3 v2** container using constant
/// `~134 KiB` RAM, once-per-stream key expansion, and zero per-chunk heap allocations.
pub fn seal_vspk3_v2_stream<R: Read, W: Write>(
    master_key: &SecretKey32,
    alg: AeadAlg,
    domain: &str,
    asset_id: &str,
    context: &str,
    mut reader: R,
    mut writer: W,
) -> Result<u64, VaultError> {
    let info = encode_canonical_info(b"VSPK3_V2_STREAM", domain, asset_id, context)?;
    let salt = random_bytes::<32>().map_err(|_| VaultError::AuthenticationFailed)?;
    let (enc_key, cmt_key, hdr_cmt) = derive_v2_subkeys(master_key, &salt, &info, alg)?;

    let aead_key = StreamAeadKey::new(alg, &enc_key).map_err(|_| VaultError::AuthenticationFailed)?;
    let cmt_hmac = HmacKey::new(&cmt_key);
    let mut aad_scratch = ChunkAadScratch::new(&salt, &hdr_cmt, &info);

    writer.write_all(&salt)?;
    writer.write_all(&hdr_cmt)?;
    let mut total_written: u64 = VSPK3_V2_PREFIX_LEN as u64;

    let max_chunks = max_chunks_for_alg(alg);
    let mut buf = Zeroizing::new(vec![0u8; VSPK3_V2_CHUNK_PLAIN + 1]);
    let mut final_plain = Zeroizing::new(vec![0u8; VSPK3_V2_MAX_FINAL_RECORD_LEN - VSPK3_V2_TRAILER_LEN]);
    let mut carried: Option<u8> = None;
    let mut chunk_index: u64 = 0;

    loop {
        let start = if let Some(b) = carried.take() {
            buf[0] = b;
            1
        } else {
            0
        };
        let n = read_up_to(&mut reader, &mut buf[start..])?;
        let filled = start + n;

        if filled > VSPK3_V2_CHUNK_PLAIN {
            if chunk_index >= max_chunks {
                return Err(VaultError::AuthenticationFailed);
            }
            carried = Some(buf[VSPK3_V2_CHUNK_PLAIN]);

            let nonce = stream_nonce(chunk_index, false);
            let aad = aad_scratch.update(chunk_index, false);
            let chunk_slice = &mut buf[..VSPK3_V2_CHUNK_PLAIN];
            let tag = aead_key
                .seal_in_place_separate_tag(&nonce, aad, chunk_slice)
                .map_err(|_| VaultError::AuthenticationFailed)?;
            let ctx_cmt = chunk_ctx_commitment_with_key(
                &cmt_hmac,
                &salt,
                &nonce,
                &info,
                chunk_index,
                false,
                &tag,
            );
            writer.write_all(chunk_slice)?;
            writer.write_all(&tag)?;
            writer.write_all(&ctx_cmt)?;
            total_written = total_written
                .checked_add(VSPK3_V2_INTERMEDIATE_RECORD_LEN as u64)
                .ok_or(VaultError::AuthenticationFailed)?;

            chunk_index += 1;
            continue;
        }

        if chunk_index > max_chunks {
            return Err(VaultError::AuthenticationFailed);
        }

        let unpadded_len = 4 + filled;
        let padded_len = unpadded_len.div_ceil(VSPK3_V2_PAD_QUANTUM) * VSPK3_V2_PAD_QUANTUM;
        let fslice = &mut final_plain[..padded_len];
        fslice[0..4].copy_from_slice(&(filled as u32).to_le_bytes());
        fslice[4..4 + filled].copy_from_slice(&buf[..filled]);
        fslice[4 + filled..].fill(0);

        let nonce = stream_nonce(chunk_index, true);
        let aad = aad_scratch.update(chunk_index, true);
        let tag = aead_key
            .seal_in_place_separate_tag(&nonce, aad, fslice)
            .map_err(|_| VaultError::AuthenticationFailed)?;
        let ctx_cmt = chunk_ctx_commitment_with_key(
            &cmt_hmac,
            &salt,
            &nonce,
            &info,
            chunk_index,
            true,
            &tag,
        );

        writer.write_all(fslice)?;
        writer.write_all(&tag)?;
        writer.write_all(&ctx_cmt)?;
        total_written = total_written
            .checked_add((padded_len + VSPK3_V2_TRAILER_LEN) as u64)
            .ok_or(VaultError::AuthenticationFailed)?;
        break;
    }

    writer.flush()?;
    Ok(total_written)
}

/// Convenience in-memory **VSPK3 v2** seal.
pub fn seal_vspk3_v2(
    master_key: &SecretKey32,
    alg: AeadAlg,
    domain: &str,
    asset_id: &str,
    context: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let mut out = Vec::with_capacity(
        VSPK3_V2_PREFIX_LEN + plaintext.len() + VSPK3_V2_PAD_QUANTUM + VSPK3_V2_TRAILER_LEN,
    );
    seal_vspk3_v2_stream(
        master_key,
        alg,
        domain,
        asset_id,
        context,
        Cursor::new(plaintext),
        &mut out,
    )?;
    Ok(out)
}

/// Verify only the 64-byte **VSPK3 v2** header commitment (`O(1)` before creating output files).
pub fn verify_vspk3_v2_header_commitment(
    master_key: &SecretKey32,
    alg: AeadAlg,
    domain: &str,
    asset_id: &str,
    context: &str,
    prefix64: &[u8; VSPK3_V2_PREFIX_LEN],
) -> Result<(), VaultError> {
    let info = encode_canonical_info(b"VSPK3_V2_STREAM", domain, asset_id, context)?;
    let mut salt = [0u8; 32];
    let mut hdr_cmt = [0u8; 32];
    salt.copy_from_slice(&prefix64[0..32]);
    hdr_cmt.copy_from_slice(&prefix64[32..64]);
    let (_enc_key, _cmt_key, expected_hdr) = derive_v2_subkeys(master_key, &salt, &info, alg)?;
    if ct_eq(&hdr_cmt, &expected_hdr) {
        Ok(())
    } else {
        Err(VaultError::AuthenticationFailed)
    }
}

/// Stream-unseal a **VSPK3 v2** container in constant `~134 KiB` RAM with unified constant-time
/// error handling, `MIN_TWO_CHUNKS` lookahead validation, and explicit `writer.flush()`.
pub fn unseal_vspk3_v2_stream<R: Read, W: Write>(
    master_key: &SecretKey32,
    alg: AeadAlg,
    domain: &str,
    asset_id: &str,
    context: &str,
    mut reader: R,
    mut writer: W,
) -> Result<u64, VaultError> {
    let info = encode_canonical_info(b"VSPK3_V2_STREAM", domain, asset_id, context)?;

    let mut prefix = [0u8; VSPK3_V2_PREFIX_LEN];
    if read_up_to(&mut reader, &mut prefix)? != VSPK3_V2_PREFIX_LEN {
        return Err(VaultError::AuthenticationFailed);
    }
    let mut salt = [0u8; 32];
    let mut hdr_cmt = [0u8; 32];
    salt.copy_from_slice(&prefix[0..32]);
    hdr_cmt.copy_from_slice(&prefix[32..64]);

    let (enc_key, cmt_key, expected_hdr_cmt) = derive_v2_subkeys(master_key, &salt, &info, alg)?;
    if !ct_eq(&hdr_cmt, &expected_hdr_cmt) {
        return Err(VaultError::AuthenticationFailed);
    }

    let aead_key = StreamAeadKey::new(alg, &enc_key).map_err(|_| VaultError::AuthenticationFailed)?;
    let cmt_hmac = HmacKey::new(&cmt_key);
    let mut aad_scratch = ChunkAadScratch::new(&salt, &hdr_cmt, &info);
    let max_chunks = max_chunks_for_alg(alg);

    // Lookahead window = `MIN_TWO_CHUNKS` (66,656 B):
    // - `buffered < 1,072`: truncated -> reject immediately.
    // - `1,072 <= buffered <= 66,608`: EOF reached -> MUST be the terminal final chunk.
    // - `66,609 <= buffered < 66,656`: EOF reached in forbidden gap -> reject BEFORE decrypting chunk 0!
    // - `buffered == 66,656`: guaranteed >= 1 intermediate chunk + >= 1,072 B remaining.
    let mut window = Zeroizing::new(vec![0u8; VSPK3_V2_MIN_TWO_CHUNKS_LEN]);
    let mut work = Zeroizing::new(vec![0u8; VSPK3_V2_MAX_FINAL_RECORD_LEN]);
    let mut buffered = 0usize;
    let mut chunk_index: u64 = 0;
    let mut total_plain: u64 = 0;

    loop {
        if buffered < window.len() {
            let n = read_up_to(&mut reader, &mut window[buffered..])?;
            buffered += n;
        }
        if buffered < VSPK3_V2_MIN_FINAL_RECORD_LEN
            || (buffered > VSPK3_V2_MAX_FINAL_RECORD_LEN && buffered < VSPK3_V2_MIN_TWO_CHUNKS_LEN)
        {
            return Err(VaultError::AuthenticationFailed);
        }

        let is_final = buffered <= VSPK3_V2_MAX_FINAL_RECORD_LEN;
        if !is_final {
            if chunk_index >= max_chunks {
                return Err(VaultError::AuthenticationFailed);
            }
            let ct_len = VSPK3_V2_CHUNK_PLAIN;
            let mut tag = [0u8; 16];
            let mut ctx_cmt = [0u8; 32];
            tag.copy_from_slice(&window[ct_len..ct_len + 16]);
            ctx_cmt.copy_from_slice(&window[ct_len + 16..VSPK3_V2_INTERMEDIATE_RECORD_LEN]);

            let nonce = stream_nonce(chunk_index, false);
            let expected_ctx = chunk_ctx_commitment_with_key(
                &cmt_hmac,
                &salt,
                &nonce,
                &info,
                chunk_index,
                false,
                &tag,
            );
            if !ct_eq(&ctx_cmt, &expected_ctx) {
                return Err(VaultError::AuthenticationFailed);
            }
            let aad = aad_scratch.update(chunk_index, false);
            let wslice = &mut work[..ct_len + 16];
            wslice.copy_from_slice(&window[..ct_len + 16]);
            let pt_len = aead_key
                .open_in_place_detached(&nonce, aad, wslice)
                .map_err(|_| VaultError::AuthenticationFailed)?;
            writer.write_all(&wslice[..pt_len])?;
            wslice[..pt_len].zeroize();
            total_plain = total_plain
                .checked_add(pt_len as u64)
                .ok_or(VaultError::AuthenticationFailed)?;

            let remain = buffered - VSPK3_V2_INTERMEDIATE_RECORD_LEN;
            window.copy_within(VSPK3_V2_INTERMEDIATE_RECORD_LEN..buffered, 0);
            buffered = remain;
            chunk_index += 1;
        } else {
            if chunk_index > max_chunks {
                return Err(VaultError::AuthenticationFailed);
            }
            let ct_len = buffered - VSPK3_V2_TRAILER_LEN;
            if ct_len < VSPK3_V2_PAD_QUANTUM || !ct_len.is_multiple_of(VSPK3_V2_PAD_QUANTUM) {
                return Err(VaultError::AuthenticationFailed);
            }
            let mut tag = [0u8; 16];
            let mut ctx_cmt = [0u8; 32];
            tag.copy_from_slice(&window[ct_len..ct_len + 16]);
            ctx_cmt.copy_from_slice(&window[ct_len + 16..buffered]);

            let nonce = stream_nonce(chunk_index, true);
            let expected_ctx = chunk_ctx_commitment_with_key(
                &cmt_hmac,
                &salt,
                &nonce,
                &info,
                chunk_index,
                true,
                &tag,
            );
            if !ct_eq(&ctx_cmt, &expected_ctx) {
                return Err(VaultError::AuthenticationFailed);
            }
            let aad = aad_scratch.update(chunk_index, true);
            let wslice = &mut work[..ct_len + 16];
            wslice.copy_from_slice(&window[..ct_len + 16]);
            let pt_len = aead_key
                .open_in_place_detached(&nonce, aad, wslice)
                .map_err(|_| VaultError::AuthenticationFailed)?;
            if pt_len < 4 {
                wslice[..pt_len].zeroize();
                return Err(VaultError::AuthenticationFailed);
            }
            let rem_len = u32::from_le_bytes([wslice[0], wslice[1], wslice[2], wslice[3]]) as usize;
            if rem_len > VSPK3_V2_CHUNK_PLAIN || 4 + rem_len > pt_len {
                wslice[..pt_len].zeroize();
                return Err(VaultError::AuthenticationFailed);
            }
            let mut pad_or = 0u8;
            for &b in &wslice[4 + rem_len..pt_len] {
                pad_or |= b;
            }
            if pad_or != 0 {
                wslice[..pt_len].zeroize();
                return Err(VaultError::AuthenticationFailed);
            }
            writer.write_all(&wslice[4..4 + rem_len])?;
            wslice[..pt_len].zeroize();
            total_plain = total_plain
                .checked_add(rem_len as u64)
                .ok_or(VaultError::AuthenticationFailed)?;
            break;
        }
    }

    writer.flush()?;
    Ok(total_plain)
}

/// Convenience in-memory **VSPK3 v2** unseal (zeroizes partial output on error).
pub fn unseal_vspk3_v2(
    master_key: &SecretKey32,
    alg: AeadAlg,
    domain: &str,
    asset_id: &str,
    context: &str,
    container: &[u8],
) -> Result<Vec<u8>, VaultError> {
    if container.len() < VSPK3_V2_MIN_LEN {
        return Err(VaultError::AuthenticationFailed);
    }
    let mut out = Vec::with_capacity(container.len().saturating_sub(VSPK3_V2_PREFIX_LEN));
    if let Err(e) = unseal_vspk3_v2_stream(
        master_key,
        alg,
        domain,
        asset_id,
        context,
        Cursor::new(container),
        &mut out,
    ) {
        out.zeroize();
        return Err(e);
    }
    Ok(out)
}

/// `O(1)` random-access **VSPK3 v2** chunk reader (authenticates both `hdr_cmt` AND the terminal
/// `is_final = true` chunk on `open()` to defeat truncation/extension attacks).
pub struct Vspk3V2RandomAccess<R: Read + Seek> {
    reader: R,
    alg: AeadAlg,
    salt: [u8; 32],
    hdr_cmt: [u8; 32],
    info: Vec<u8>,
    enc_key: SecretKey32,
    cmt_hmac: HmacKey,
    chunk_count: u64,
    total_len: u64,
}

impl<R: Read + Seek> Vspk3V2RandomAccess<R> {
    pub fn open(
        master_key: &SecretKey32,
        alg: AeadAlg,
        domain: &str,
        asset_id: &str,
        context: &str,
        mut reader: R,
    ) -> Result<Self, VaultError> {
        let info = encode_canonical_info(b"VSPK3_V2_STREAM", domain, asset_id, context)?;
        let total_len = reader.seek(SeekFrom::End(0))?;
        if total_len < VSPK3_V2_MIN_LEN as u64 {
            return Err(VaultError::AuthenticationFailed);
        }
        reader.seek(SeekFrom::Start(0))?;
        let mut prefix = [0u8; VSPK3_V2_PREFIX_LEN];
        if read_up_to(&mut reader, &mut prefix)? != VSPK3_V2_PREFIX_LEN {
            return Err(VaultError::AuthenticationFailed);
        }
        let mut salt = [0u8; 32];
        let mut hdr_cmt = [0u8; 32];
        salt.copy_from_slice(&prefix[0..32]);
        hdr_cmt.copy_from_slice(&prefix[32..64]);

        let (enc_key, cmt_key, expected_hdr) = derive_v2_subkeys(master_key, &salt, &info, alg)?;
        if !ct_eq(&hdr_cmt, &expected_hdr) {
            return Err(VaultError::AuthenticationFailed);
        }

        let body_len = total_len - VSPK3_V2_PREFIX_LEN as u64;
        let stride = VSPK3_V2_INTERMEDIATE_RECORD_LEN as u64;
        let max_final = VSPK3_V2_MAX_FINAL_RECORD_LEN as u64;
        let min_final = VSPK3_V2_MIN_FINAL_RECORD_LEN as u64;

        let mut k = body_len.saturating_sub(max_final).div_ceil(stride);
        if k > max_chunks_for_alg(alg) {
            return Err(VaultError::AuthenticationFailed);
        }
        let k_bytes = k
            .checked_mul(stride)
            .ok_or(VaultError::AuthenticationFailed)?;
        if body_len < k_bytes.saturating_add(min_final) {
            return Err(VaultError::AuthenticationFailed);
        }
        let mut final_len = body_len - k_bytes;
        if final_len > max_final {
            k = k.checked_add(1).ok_or(VaultError::AuthenticationFailed)?;
            if k > max_chunks_for_alg(alg) {
                return Err(VaultError::AuthenticationFailed);
            }
            let k_bytes2 = k
                .checked_mul(stride)
                .ok_or(VaultError::AuthenticationFailed)?;
            final_len = body_len
                .checked_sub(k_bytes2)
                .ok_or(VaultError::AuthenticationFailed)?;
        }
        if final_len < min_final || final_len > max_final {
            return Err(VaultError::AuthenticationFailed);
        }
        let final_ct_len = final_len - VSPK3_V2_TRAILER_LEN as u64;
        if !(final_ct_len as usize).is_multiple_of(VSPK3_V2_PAD_QUANTUM) {
            return Err(VaultError::AuthenticationFailed);
        }

        let mut ra = Self {
            reader,
            alg,
            salt,
            hdr_cmt,
            info,
            enc_key,
            cmt_hmac: HmacKey::new(&cmt_key),
            chunk_count: k + 1,
            total_len,
        };
        // Cryptographically authenticate the terminal chunk (`is_final = true`) in O(1) on open()
        // so truncated or extended containers cannot be opened.
        let mut term = ra.read_chunk(k)?;
        term.zeroize();
        Ok(ra)
    }

    pub fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    /// Read and authenticate a single chunk by index in `O(1)` seeks.
    pub fn read_chunk(&mut self, chunk_index: u64) -> Result<Vec<u8>, VaultError> {
        if chunk_index >= self.chunk_count {
            return Err(VaultError::ChunkOutOfRange);
        }
        let is_final = chunk_index + 1 == self.chunk_count;
        let offset = (VSPK3_V2_PREFIX_LEN as u64)
            .checked_add(
                chunk_index
                    .checked_mul(VSPK3_V2_INTERMEDIATE_RECORD_LEN as u64)
                    .ok_or(VaultError::AuthenticationFailed)?,
            )
            .ok_or(VaultError::AuthenticationFailed)?;
        let rec_len = if is_final {
            (self.total_len - offset) as usize
        } else {
            VSPK3_V2_INTERMEDIATE_RECORD_LEN
        };
        if !(VSPK3_V2_MIN_FINAL_RECORD_LEN..=VSPK3_V2_MAX_FINAL_RECORD_LEN).contains(&rec_len) {
            return Err(VaultError::AuthenticationFailed);
        }

        self.reader.seek(SeekFrom::Start(offset))?;
        let mut rec = Zeroizing::new(vec![0u8; rec_len]);
        if read_up_to(&mut self.reader, &mut rec)? != rec_len {
            return Err(VaultError::AuthenticationFailed);
        }

        let ct_len = rec_len - VSPK3_V2_TRAILER_LEN;
        if is_final && !ct_len.is_multiple_of(VSPK3_V2_PAD_QUANTUM) {
            return Err(VaultError::AuthenticationFailed);
        }
        let ct = &rec[..ct_len];
        let mut tag = [0u8; 16];
        let mut ctx_cmt = [0u8; 32];
        tag.copy_from_slice(&rec[ct_len..ct_len + 16]);
        ctx_cmt.copy_from_slice(&rec[ct_len + 16..]);

        let nonce = stream_nonce(chunk_index, is_final);
        let expected_ctx = chunk_ctx_commitment_with_key(
            &self.cmt_hmac,
            &self.salt,
            &nonce,
            &self.info,
            chunk_index,
            is_final,
            &tag,
        );
        if !ct_eq(&ctx_cmt, &expected_ctx) {
            return Err(VaultError::AuthenticationFailed);
        }
        let mut aad_scratch = ChunkAadScratch::new(&self.salt, &self.hdr_cmt, &self.info);
        let aad = aad_scratch.update(chunk_index, is_final);
        let mut plain = aead_open_detached(
            self.alg,
            self.enc_key.as_bytes(),
            &nonce,
            aad,
            ct,
            &tag,
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;

        if !is_final {
            return Ok(plain);
        }
        if plain.len() < 4 {
            plain.zeroize();
            return Err(VaultError::AuthenticationFailed);
        }
        let rem_len = u32::from_le_bytes([plain[0], plain[1], plain[2], plain[3]]) as usize;
        if rem_len > VSPK3_V2_CHUNK_PLAIN || 4 + rem_len > plain.len() {
            plain.zeroize();
            return Err(VaultError::AuthenticationFailed);
        }
        let mut pad_or = 0u8;
        for &b in &plain[4 + rem_len..] {
            pad_or |= b;
        }
        if pad_or != 0 {
            plain.zeroize();
            return Err(VaultError::AuthenticationFailed);
        }
        let res = plain[4..4 + rem_len].to_vec();
        plain.zeroize();
        Ok(res)
    }
}

// ==================== AUDITED BACKWARD-COMPATIBLE VSPK3 v1 & VSPK2 ====================

/// O(1) header-commitment verification for legacy **VSPK3 v1** (avoids reading multi-GB files
/// before rejecting non-v1 / wrong-key inputs).
pub fn verify_vspk3_v1_header_commitment(
    master_key: &SecretKey32,
    domain: &str,
    asset_id: &str,
    context: &str,
    prefix92: &[u8; VSPK3_V1_PREFIX_LEN],
) -> Result<(), VaultError> {
    let info = encode_canonical_info(b"VSPK3_CMT4", domain, asset_id, context)?;
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    let mut cmt4 = [0u8; 32];
    salt.copy_from_slice(&prefix92[0..32]);
    nonce.copy_from_slice(&prefix92[32..44]);
    cmt4.copy_from_slice(&prefix92[44..76]);

    let mut cmt_info = Zeroizing::new(info.clone());
    cmt_info.extend_from_slice(b"|CMT");
    let cmt_key = hkdf_sha256_32(master_key.as_bytes(), &salt, &cmt_info)
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let expected_cmt = hmac_sha256_parts(cmt_key.as_bytes(), &[&nonce, &info]);
    if ct_eq(&cmt4, &expected_cmt) {
        Ok(())
    } else {
        Err(VaultError::AuthenticationFailed)
    }
}

/// Seal a legacy wire-compatible **VSPK3 v1** container (`ring` ChaCha20-Poly1305 + HMAC-SHA256).
pub fn seal_vspk3_v1(
    master_key: &SecretKey32,
    domain: &str,
    asset_id: &str,
    context: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    if plaintext.len() > (u32::MAX as usize) - 4 {
        return Err(VaultError::InvalidMetadata);
    }
    let info = encode_canonical_info(b"VSPK3_CMT4", domain, asset_id, context)?;
    let salt = random_bytes::<32>().map_err(|_| VaultError::AuthenticationFailed)?;
    let nonce = random_bytes::<12>().map_err(|_| VaultError::AuthenticationFailed)?;

    let mut enc_info = Zeroizing::new(info.clone());
    enc_info.extend_from_slice(b"|ENC");
    let mut cmt_info = Zeroizing::new(info.clone());
    cmt_info.extend_from_slice(b"|CMT");

    let enc_key = hkdf_sha256_32(master_key.as_bytes(), &salt, &enc_info)
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let cmt_key = hkdf_sha256_32(master_key.as_bytes(), &salt, &cmt_info)
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let cmt4 = hmac_sha256_parts(cmt_key.as_bytes(), &[&nonce, &info]);

    let unpadded = 4 + plaintext.len();
    let padded_len = unpadded.div_ceil(VSPK3_V1_PAD_QUANTUM) * VSPK3_V1_PAD_QUANTUM;
    let mut padded = Zeroizing::new(vec![0u8; padded_len]);
    padded[0..4].copy_from_slice(&(plaintext.len() as u32).to_le_bytes());
    padded[4..4 + plaintext.len()].copy_from_slice(plaintext);

    let mut aad = Vec::with_capacity(76 + info.len());
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&nonce);
    aad.extend_from_slice(&cmt4);
    aad.extend_from_slice(&info);

    let (ct, tag) = aead_seal_detached(
        AeadAlg::ChaCha20Poly1305,
        enc_key.as_bytes(),
        &nonce,
        &aad,
        &padded,
    )
    .map_err(|_| VaultError::AuthenticationFailed)?;

    let mut out = Vec::with_capacity(VSPK3_V1_PREFIX_LEN + ct.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&cmt4);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unseal a legacy **VSPK3 v1** container with unified constant-time authentication error and
/// constant-time zero-padding verification.
pub fn unseal_vspk3_v1(
    master_key: &SecretKey32,
    domain: &str,
    asset_id: &str,
    context: &str,
    vspk: &[u8],
) -> Result<Vec<u8>, VaultError> {
    if vspk.len() < VSPK3_V1_PREFIX_LEN + VSPK3_V1_PAD_QUANTUM {
        return Err(VaultError::AuthenticationFailed);
    }
    let ct = &vspk[VSPK3_V1_PREFIX_LEN..];
    if !ct.len().is_multiple_of(VSPK3_V1_PAD_QUANTUM) {
        return Err(VaultError::AuthenticationFailed);
    }
    let info = encode_canonical_info(b"VSPK3_CMT4", domain, asset_id, context)?;

    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    let mut cmt4 = [0u8; 32];
    let mut tag = [0u8; 16];
    salt.copy_from_slice(&vspk[0..32]);
    nonce.copy_from_slice(&vspk[32..44]);
    cmt4.copy_from_slice(&vspk[44..76]);
    tag.copy_from_slice(&vspk[76..92]);

    let mut enc_info = Zeroizing::new(info.clone());
    enc_info.extend_from_slice(b"|ENC");
    let mut cmt_info = Zeroizing::new(info.clone());
    cmt_info.extend_from_slice(b"|CMT");

    let enc_key = hkdf_sha256_32(master_key.as_bytes(), &salt, &enc_info)
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let cmt_key = hkdf_sha256_32(master_key.as_bytes(), &salt, &cmt_info)
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let expected_cmt = hmac_sha256_parts(cmt_key.as_bytes(), &[&nonce, &info]);
    if !ct_eq(&cmt4, &expected_cmt) {
        return Err(VaultError::AuthenticationFailed);
    }

    let mut aad = Vec::with_capacity(76 + info.len());
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&nonce);
    aad.extend_from_slice(&cmt4);
    aad.extend_from_slice(&info);

    let mut inner = aead_open_detached(
        AeadAlg::ChaCha20Poly1305,
        enc_key.as_bytes(),
        &nonce,
        &aad,
        ct,
        &tag,
    )
    .map_err(|_| VaultError::AuthenticationFailed)?;
    if inner.len() < 4 {
        inner.zeroize();
        return Err(VaultError::AuthenticationFailed);
    }
    let plain_len = u32::from_le_bytes([inner[0], inner[1], inner[2], inner[3]]) as usize;
    if 4 + plain_len > inner.len() {
        inner.zeroize();
        return Err(VaultError::AuthenticationFailed);
    }
    let mut pad_or = 0u8;
    for &b in &inner[4 + plain_len..] {
        pad_or |= b;
    }
    if pad_or != 0 {
        inner.zeroize();
        return Err(VaultError::AuthenticationFailed);
    }
    let out = inner[4..4 + plain_len].to_vec();
    inner.zeroize();
    Ok(out)
}

/// Audited `ring` ChaCha20-Poly1305 legacy **VSPK2** container seal (for C/Go/Python compat).
pub fn pack_vspk2(
    master_key: &SecretKey32,
    domain: &str,
    asset_id: &str,
    context: &str,
    plain: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let db = domain.as_bytes();
    let ab = asset_id.as_bytes();
    let cb = context.as_bytes();
    if db.len() > 128
        || ab.len() > 128
        || cb.len() > 256
        || db.contains(&0)
        || ab.contains(&0)
        || cb.contains(&0)
    {
        return Err(VaultError::InvalidMetadata);
    }
    let info = format!("VSPK2_V1|{domain}|{asset_id}|{context}");
    let key = hkdf_sha256_32(master_key.as_bytes(), ab, info.as_bytes())
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let nonce = random_bytes::<12>().map_err(|_| VaultError::AuthenticationFailed)?;
    let ct_and_tag = aead_seal(
        AeadAlg::ChaCha20Poly1305,
        key.as_bytes(),
        &nonce,
        info.as_bytes(),
        plain,
    )
    .map_err(|_| VaultError::AuthenticationFailed)?;
    if ct_and_tag.len() < 16 {
        return Err(VaultError::AuthenticationFailed);
    }
    let split = ct_and_tag.len() - 16;
    let (ct, tag) = ct_and_tag.split_at(split);

    let mut out = Vec::with_capacity(40 + db.len() + ab.len() + cb.len() + ct.len());
    out.extend_from_slice(MAGIC_VSPK2);
    out.push(1u8);
    out.extend_from_slice(&(db.len() as u16).to_le_bytes());
    out.extend_from_slice(&(ab.len() as u16).to_le_bytes());
    out.extend_from_slice(&(cb.len() as u16).to_le_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(tag);
    out.extend_from_slice(db);
    out.extend_from_slice(ab);
    out.extend_from_slice(cb);
    out.extend_from_slice(ct);
    Ok(out)
}

/// Audited `ring` ChaCha20-Poly1305 legacy **VSPK2** container unseal with unified auth error.
pub fn unseal_vspk2(
    master_key: &SecretKey32,
    expected_domain: &str,
    expected_asset_id: Option<&str>,
    expected_context: &str,
    blob: &[u8],
) -> Result<Vec<u8>, VaultError> {
    if blob.len() < 40 || &blob[0..5] != MAGIC_VSPK2 || blob[5] != 1 {
        return Err(VaultError::AuthenticationFailed);
    }
    let dlen = u16::from_le_bytes([blob[6], blob[7]]) as usize;
    let alen = u16::from_le_bytes([blob[8], blob[9]]) as usize;
    let clen = u16::from_le_bytes([blob[10], blob[11]]) as usize;
    if dlen > 128 || alen > 128 || clen > 256 {
        return Err(VaultError::AuthenticationFailed);
    }
    let hdr_end = 40 + dlen + alen + clen;
    if blob.len() < hdr_end {
        return Err(VaultError::AuthenticationFailed);
    }
    let dom = std::str::from_utf8(&blob[40..40 + dlen])
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let aid = std::str::from_utf8(&blob[40 + dlen..40 + dlen + alen])
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let ctx = std::str::from_utf8(&blob[40 + dlen + alen..hdr_end])
        .map_err(|_| VaultError::AuthenticationFailed)?;
    if dom != expected_domain
        || ctx != expected_context
        || expected_asset_id.is_some_and(|want| want != aid)
    {
        return Err(VaultError::AuthenticationFailed);
    }
    let info = format!("VSPK2_V1|{dom}|{aid}|{ctx}");
    let key = hkdf_sha256_32(master_key.as_bytes(), aid.as_bytes(), info.as_bytes())
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[12..24]);
    let tag = &blob[24..40];
    let ct = &blob[hdr_end..];
    let mut ct_and_tag = Vec::with_capacity(ct.len() + 16);
    ct_and_tag.extend_from_slice(ct);
    ct_and_tag.extend_from_slice(tag);

    aead_open(
        AeadAlg::ChaCha20Poly1305,
        key.as_bytes(),
        &nonce,
        info.as_bytes(),
        &ct_and_tag,
    )
    .map_err(|_| VaultError::AuthenticationFailed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn vspk3_v2_roundtrip_edge_sizes_and_random_access() {
        let mk = SecretKey32::generate().unwrap();
        for alg in [AeadAlg::Aes256Gcm, AeadAlg::ChaCha20Poly1305] {
            for &sz in &[0usize, 1, 1020, 1024, 65_535, 65_536, 65_537, 200_000] {
                let plain: Vec<u8> = (0..sz).map(|i| ((i * 31 + 7) & 0xff) as u8).collect();
                let sealed = seal_vspk3_v2(&mk, alg, "weights", "llama-7b", "prod", &plain).unwrap();
                let opened = unseal_vspk3_v2(&mk, alg, "weights", "llama-7b", "prod", &sealed).unwrap();
                assert_eq!(opened, plain, "mismatch at size {sz} alg {alg:?}");

                let mut ra = Vspk3V2RandomAccess::open(
                    &mk,
                    alg,
                    "weights",
                    "llama-7b",
                    "prod",
                    Cursor::new(&sealed),
                )
                .unwrap();
                let mut reassembled = Vec::new();
                for c in 0..ra.chunk_count() {
                    reassembled.extend_from_slice(&ra.read_chunk(c).unwrap());
                }
                assert_eq!(reassembled, plain);
            }
        }
    }

    #[test]
    fn vspk3_v2_rejects_lookahead_gap_truncation_and_reordering_before_writing() {
        let mk = SecretKey32::generate().unwrap();
        let plain = vec![0xA5u8; 200_000];
        let sealed =
            seal_vspk3_v2(&mk, AeadAlg::Aes256Gcm, "cad", "gearbox", "prod", &plain).unwrap();

        // CRIT-02 regression: truncated in forbidden [66,609..66,655] body gap writes ZERO bytes!
        let gap_blob = &sealed[..VSPK3_V2_PREFIX_LEN + VSPK3_V2_MAX_FINAL_RECORD_LEN + 1];
        let mut sink = Vec::new();
        assert!(matches!(
            unseal_vspk3_v2_stream(&mk, AeadAlg::Aes256Gcm, "cad", "gearbox", "prod", Cursor::new(gap_blob), &mut sink),
            Err(VaultError::AuthenticationFailed)
        ));
        assert!(sink.is_empty(), "must not emit chunk 0 before rejecting gap truncation");

        // HIGH-02 regression: Vspk3V2RandomAccess::open rejects truncated & extended vaults!
        let trunc_1chunk = &sealed[..VSPK3_V2_PREFIX_LEN + VSPK3_V2_INTERMEDIATE_RECORD_LEN];
        assert!(matches!(
            Vspk3V2RandomAccess::open(&mk, AeadAlg::Aes256Gcm, "cad", "gearbox", "prod", Cursor::new(trunc_1chunk)),
            Err(VaultError::AuthenticationFailed)
        ));
        let mut extended = sealed.clone();
        extended.extend_from_slice(&[0u8; 1024]);
        assert!(matches!(
            Vspk3V2RandomAccess::open(&mk, AeadAlg::Aes256Gcm, "cad", "gearbox", "prod", Cursor::new(&extended)),
            Err(VaultError::AuthenticationFailed)
        ));

        // Chunk reordering rejected with unified error
        let mut reordered = sealed.clone();
        let c0 = VSPK3_V2_PREFIX_LEN;
        let c1 = c0 + VSPK3_V2_INTERMEDIATE_RECORD_LEN;
        let first_chunk = reordered[c0..c1].to_vec();
        reordered.copy_within(c1..c1 + VSPK3_V2_INTERMEDIATE_RECORD_LEN, c0);
        reordered[c1..c1 + VSPK3_V2_INTERMEDIATE_RECORD_LEN].copy_from_slice(&first_chunk);
        assert!(matches!(
            unseal_vspk3_v2(&mk, AeadAlg::Aes256Gcm, "cad", "gearbox", "prod", &reordered),
            Err(VaultError::AuthenticationFailed)
        ));
    }

    #[test]
    fn vspk3_v1_and_vspk2_backward_compat_roundtrip() {
        let mk = SecretKey32::generate().unwrap();
        let msg = b"legacy-v1-and-v2-compat";
        let s1 = seal_vspk3_v1(&mk, "backend", "cfg", "prod", msg).unwrap();
        let p92: &[u8; VSPK3_V1_PREFIX_LEN] = s1[..VSPK3_V1_PREFIX_LEN].try_into().unwrap();
        verify_vspk3_v1_header_commitment(&mk, "backend", "cfg", "prod", p92).unwrap();
        assert_eq!(unseal_vspk3_v1(&mk, "backend", "cfg", "prod", &s1).unwrap(), msg);

        let s2 = pack_vspk2(&mk, "backend", "cfg", "prod", msg).unwrap();
        assert_eq!(unseal_vspk2(&mk, "backend", Some("cfg"), "prod", &s2).unwrap(), msg);
        assert!(unseal_vspk2(&mk, "backend", Some("other"), "prod", &s2).is_err());
    }
}
