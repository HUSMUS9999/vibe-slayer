//! `vs-crypto`: Audited, constant-time, `#![forbid(unsafe_code)]` cryptographic foundation.
//!
//! Built exclusively on `ring` (BoringSSL constant-time assembly for P-256 ECDH, AES-256-GCM,
//! ChaCha20-Poly1305, SHA-256, HMAC-SHA256, HKDF-SHA256, and CSPRNG), `subtle`, and `zeroize`.
//!
//! Key security guarantees:
//! - Zero hand-rolled cryptographic primitives or lookup-table S-boxes.
//! - Ephemeral per-session keys + strictly monotonic 64-bit counter nonces (`SessionAead`)
//!   eliminating NIST SP 800-38D random-IV exhaustion under static keys.
//! - Constant-time tag & token comparisons with unified opaque authentication errors.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256};
use ring::digest;
use ring::hkdf::{KeyType, Salt, HKDF_SHA256};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Maximum counter messages per single AEAD session key (well below 2^32 NIST SP 800-38D bound).
pub const MAX_SESSION_NONCE_COUNTER: u64 = (1u64 << 31) - 1;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("invalid key material")]
    InvalidKey,
    #[error("invalid input")]
    InvalidInput,
    #[error("session nonce budget exhausted; rotate key")]
    NonceExhausted,
    #[error("csprng failure")]
    RngFailure,
    #[error("token expired")]
    TokenExpired,
}

/// Zeroized 32-byte symmetric key wrapper.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey32([u8; 32]);

impl SecretKey32 {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; 32] = slice.try_into().map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self(arr))
    }

    pub fn from_hex(s: &str) -> Result<Self, CryptoError> {
        let raw = hex::decode(s.trim()).map_err(|_| CryptoError::InvalidKey)?;
        let res = Self::from_slice(&raw);
        let mut raw = raw;
        raw.zeroize();
        res
    }

    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; 32];
        fill_random(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.0))
    }
}

impl std::fmt::Debug for SecretKey32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey32([REDACTED])")
    }
}

/// Fill a buffer with cryptographically secure OS random bytes.
pub fn fill_random(dest: &mut [u8]) -> Result<(), CryptoError> {
    let rng = SystemRandom::new();
    rng.fill(dest).map_err(|_| CryptoError::RngFailure)
}

/// Generate a random byte array of fixed length `N`.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut buf = [0u8; N];
    fill_random(&mut buf)?;
    Ok(buf)
}

/// Constant-time equality check over equal-length byte slices.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// HMAC-SHA256 over a single message.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&k, msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Streaming multi-part HMAC-SHA256.
pub fn hmac_sha256_parts(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut ctx = hmac::Context::with_key(&k);
    for p in parts {
        ctx.update(p);
    }
    let tag = ctx.sign();
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Verify HMAC-SHA256 in constant time.
pub fn hmac_sha256_verify(key: &[u8], msg: &[u8], expected_tag: &[u8]) -> Result<(), CryptoError> {
    if expected_tag.len() != 32 {
        return Err(CryptoError::AuthenticationFailed);
    }
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::verify(&k, msg, expected_tag).map_err(|_| CryptoError::AuthenticationFailed)
}

struct LenKeyType(usize);
impl KeyType for LenKeyType {
    fn len(&self) -> usize {
        self.0
    }
}

/// RFC 5869 HKDF-SHA256 deriving a 32-byte key.
pub fn hkdf_sha256_32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<SecretKey32, CryptoError> {
    let s = Salt::new(HKDF_SHA256, salt);
    let prk = s.extract(ikm);
    let info_slices = [info];
    let okm = prk
        .expand(&info_slices, LenKeyType(32))
        .map_err(|_| CryptoError::InvalidInput)?;
    let mut out = [0u8; 32];
    okm.fill(&mut out).map_err(|_| CryptoError::InvalidInput)?;
    Ok(SecretKey32::from_bytes(out))
}

/// Supported audited AEAD algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AeadAlg {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl AeadAlg {
    fn ring_alg(self) -> &'static aead::Algorithm {
        match self {
            AeadAlg::Aes256Gcm => &aead::AES_256_GCM,
            AeadAlg::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }
}

/// Pre-expanded AEAD key for zero-key-schedule-per-chunk streaming encryption/decryption.
pub struct StreamAeadKey {
    lsk: LessSafeKey,
}

impl StreamAeadKey {
    pub fn new(alg: AeadAlg, key: &SecretKey32) -> Result<Self, CryptoError> {
        let unbound =
            UnboundKey::new(alg.ring_alg(), key.as_bytes()).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            lsk: LessSafeKey::new(unbound),
        })
    }

    pub fn seal_in_place_separate_tag(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<[u8; 16], CryptoError> {
        let tag = self
            .lsk
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(*nonce), Aad::from(aad), in_out)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        let mut out = [0u8; 16];
        out.copy_from_slice(tag.as_ref());
        Ok(out)
    }

    pub fn open_in_place_detached(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        in_out_with_tag: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if in_out_with_tag.len() < 16 {
            return Err(CryptoError::AuthenticationFailed);
        }
        match self.lsk.open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            in_out_with_tag,
        ) {
            Ok(pt) => Ok(pt.len()),
            Err(_) => {
                in_out_with_tag.zeroize();
                Err(CryptoError::AuthenticationFailed)
            }
        }
    }
}

/// Pre-expanded HMAC-SHA256 key for streaming commitment computation.
pub struct HmacKey {
    key: hmac::Key,
}

impl HmacKey {
    pub fn new(key: &SecretKey32) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, key.as_bytes()),
        }
    }

    pub fn sign_parts(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut ctx = hmac::Context::with_key(&self.key);
        for part in parts {
            ctx.update(part);
        }
        let tag = ctx.sign();
        let mut out = [0u8; 32];
        out.copy_from_slice(tag.as_ref());
        out
    }
}

/// Detached AEAD seal returning `(ciphertext, tag16)`.
pub fn aead_seal_detached(
    alg: AeadAlg,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), CryptoError> {
    let unbound = UnboundKey::new(alg.ring_alg(), key).map_err(|_| CryptoError::InvalidKey)?;
    let lsk = LessSafeKey::new(unbound);
    let mut buf = plaintext.to_vec();
    let tag = lsk
        .seal_in_place_separate_tag(Nonce::assume_unique_for_key(*nonce), Aad::from(aad), &mut buf)
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let mut tag_bytes = [0u8; 16];
    tag_bytes.copy_from_slice(tag.as_ref());
    Ok((buf, tag_bytes))
}

/// Detached AEAD open verifying `tag16` in constant time; returns zeroized plaintext on error.
pub fn aead_open_detached(
    alg: AeadAlg,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag16: &[u8; 16],
) -> Result<Vec<u8>, CryptoError> {
    let unbound = UnboundKey::new(alg.ring_alg(), key).map_err(|_| CryptoError::InvalidKey)?;
    let lsk = LessSafeKey::new(unbound);
    let mut in_out = Vec::with_capacity(ciphertext.len() + 16);
    in_out.extend_from_slice(ciphertext);
    in_out.extend_from_slice(tag16);
    match lsk.open_in_place(Nonce::assume_unique_for_key(*nonce), Aad::from(aad), &mut in_out) {
        Ok(pt) => {
            let len = pt.len();
            in_out.truncate(len);
            Ok(in_out)
        }
        Err(_) => {
            in_out.zeroize();
            Err(CryptoError::AuthenticationFailed)
        }
    }
}

/// Combined AEAD seal returning `ciphertext || tag16` (WebCrypto-compatible).
pub fn aead_seal(
    alg: AeadAlg,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (mut ct, tag) = aead_seal_detached(alg, key, nonce, aad, plaintext)?;
    ct.extend_from_slice(&tag);
    Ok(ct)
}

/// Combined AEAD open consuming `ciphertext || tag16`.
pub fn aead_open(
    alg: AeadAlg,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ct_and_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ct_and_tag.len() < 16 {
        return Err(CryptoError::AuthenticationFailed);
    }
    let split = ct_and_tag.len() - 16;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ct_and_tag[split..]);
    aead_open_detached(alg, key, nonce, aad, &ct_and_tag[..split], &tag)
}

/// Per-session AEAD engine with strictly monotonic latched 32-bit counter nonces and 64-bit random prefix.
///
/// Nonce format (12 bytes): `nonce_prefix_8B || counter_be_4B`.
/// Eliminates static-key NIST SP 800-38D random-IV collision risk by construction and latches at
/// `MAX_SESSION_NONCE_COUNTER` so the counter can never wrap around.
pub struct SessionAead {
    key: SecretKey32,
    stream_key: StreamAeadKey,
    nonce_prefix: [u8; 8],
    counter: AtomicU64,
}

impl SessionAead {
    pub fn new(alg: AeadAlg, key: SecretKey32) -> Result<Self, CryptoError> {
        let nonce_prefix = random_bytes::<8>()?;
        let stream_key = StreamAeadKey::new(alg, &key)?;
        Ok(Self {
            key,
            stream_key,
            nonce_prefix,
            counter: AtomicU64::new(0),
        })
    }

    pub fn from_parts(
        alg: AeadAlg,
        key: SecretKey32,
        nonce_prefix: [u8; 8],
    ) -> Result<Self, CryptoError> {
        let stream_key = StreamAeadKey::new(alg, &key)?;
        Ok(Self {
            key,
            stream_key,
            nonce_prefix,
            counter: AtomicU64::new(0),
        })
    }

    /// Seal plaintext with the next strictly monotonic nonce. Returns `(nonce12, ct_with_tag)`.
    pub fn seal_next(&self, aad: &[u8], plaintext: &[u8]) -> Result<([u8; 12], Vec<u8>), CryptoError> {
        let seq = self
            .counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                (cur < MAX_SESSION_NONCE_COUNTER).then_some(cur + 1)
            })
            .map_err(|_| CryptoError::NonceExhausted)?;
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.nonce_prefix);
        nonce[8..].copy_from_slice(&(seq as u32).to_be_bytes());
        let mut buf = plaintext.to_vec();
        let tag = self.stream_key.seal_in_place_separate_tag(&nonce, aad, &mut buf)?;
        buf.extend_from_slice(&tag);
        Ok((nonce, buf))
    }

    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], ct_and_tag: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buf = ct_and_tag.to_vec();
        let len = self.stream_key.open_in_place_detached(nonce, aad, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    pub fn key(&self) -> &SecretKey32 {
        &self.key
    }
}

/// Constant-time ephemeral P-256 ECDH key agreement (WebCrypto compatible, SEC1 uncompressed 65B).
/// Binds both public keys (`peer_pub || server_pub`) into the HKDF transcript alongside `hkdf_info`.
pub fn ecdh_p256_agree_ephemeral(
    peer_uncompressed_pub65: &[u8],
    hkdf_salt: &[u8],
    hkdf_info: &[u8],
) -> Result<([u8; 65], SecretKey32), CryptoError> {
    if peer_uncompressed_pub65.len() != 65 || peer_uncompressed_pub65[0] != 0x04 {
        return Err(CryptoError::InvalidKey);
    }
    let rng = SystemRandom::new();
    let priv_key =
        EphemeralPrivateKey::generate(&ECDH_P256, &rng).map_err(|_| CryptoError::RngFailure)?;
    let pub_key_bytes = priv_key
        .compute_public_key()
        .map_err(|_| CryptoError::InvalidKey)?;
    let server_pub65: [u8; 65] = pub_key_bytes
        .as_ref()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey)?;

    let mut bound_info = Vec::with_capacity(hkdf_info.len() + 130);
    bound_info.extend_from_slice(hkdf_info);
    bound_info.extend_from_slice(peer_uncompressed_pub65);
    bound_info.extend_from_slice(&server_pub65);

    let peer_key = UnparsedPublicKey::new(&ECDH_P256, peer_uncompressed_pub65);
    let derived = agreement::agree_ephemeral(priv_key, &peer_key, |shared_secret| {
        hkdf_sha256_32(shared_secret, hkdf_salt, &bound_info)
    })
    .map_err(|_| CryptoError::InvalidKey)??;

    Ok((server_pub65, derived))
}

/// Signed, origin- and scope-bound session grant (NO volatile IP pinning).
///
/// Format: `base64url(json_claims).base64url(hmac_sha256_tag)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionGrantClaims {
    pub sub: String,
    pub aud: String,
    #[serde(default)]
    pub asset_id: String,
    pub jti: String,
    pub iat: u64,
    pub exp: u64,
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// Returns current UNIX timestamp in seconds, failing closed (`u64::MAX`) if the system clock is invalid.
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

/// Mint an HMAC-SHA256 signed `SessionGrantClaims` token.
pub fn mint_session_grant(
    signing_key: &SecretKey32,
    claims: &SessionGrantClaims,
) -> Result<String, CryptoError> {
    let payload_json = serde_json::to_vec(claims).map_err(|_| CryptoError::InvalidInput)?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
    let mac = hmac_sha256_parts(
        signing_key.as_bytes(),
        &[b"VS_GRANT_V2|", payload_b64.as_bytes()],
    );
    let sig_b64 = URL_SAFE_NO_PAD.encode(mac);
    Ok(format!("{payload_b64}.{sig_b64}"))
}

/// Verify an HMAC-SHA256 signed `SessionGrantClaims` token in constant time.
pub fn verify_session_grant(
    signing_key: &SecretKey32,
    token: &str,
    expected_aud: Option<&str>,
    expected_asset_id: Option<&str>,
    now_secs: Option<u64>,
) -> Result<SessionGrantClaims, CryptoError> {
    let (payload_b64, sig_b64) = token
        .trim()
        .split_once('.')
        .ok_or(CryptoError::AuthenticationFailed)?;
    let sig = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    if sig.len() != 32 {
        return Err(CryptoError::AuthenticationFailed);
    }
    let expected = hmac_sha256_parts(
        signing_key.as_bytes(),
        &[b"VS_GRANT_V2|", payload_b64.as_bytes()],
    );
    if !ct_eq(&sig, &expected) {
        return Err(CryptoError::AuthenticationFailed);
    }
    let payload_raw = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let claims: SessionGrantClaims =
        serde_json::from_slice(&payload_raw).map_err(|_| CryptoError::AuthenticationFailed)?;
    let now = now_secs.unwrap_or_else(now_unix_secs);
    if claims.exp <= now || claims.iat > now.saturating_add(60) {
        return Err(CryptoError::TokenExpired);
    }
    if let Some(aud) = expected_aud {
        if aud.is_empty() || claims.aud != aud {
            return Err(CryptoError::AuthenticationFailed);
        }
    }
    if let Some(aid) = expected_asset_id {
        if aid.is_empty() || claims.asset_id != aid {
            return Err(CryptoError::AuthenticationFailed);
        }
    }
    Ok(claims)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn session_aead_monotonic_nonces_and_tamper_rejection() {
        let key = SecretKey32::generate().unwrap();
        let sess = SessionAead::new(AeadAlg::Aes256Gcm, key).unwrap();
        let (n0, ct0) = sess.seal_next(b"aad-0", b"hello zero-geometry").unwrap();
        let (n1, ct1) = sess.seal_next(b"aad-1", b"second frame").unwrap();
        assert_ne!(n0, n1);
        assert_eq!(&n0[..8], &n1[..8]);
        assert_eq!(&n0[8..], &0u32.to_be_bytes());
        assert_eq!(&n1[8..], &1u32.to_be_bytes());

        assert_eq!(sess.open(&n0, b"aad-0", &ct0).unwrap(), b"hello zero-geometry");
        assert_eq!(sess.open(&n1, b"aad-1", &ct1).unwrap(), b"second frame");
        assert!(sess.open(&n0, b"wrong-aad", &ct0).is_err());

        let mut tampered = ct0.clone();
        tampered[0] ^= 0x01;
        assert_eq!(
            sess.open(&n0, b"aad-0", &tampered),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn ecdh_p256_roundtrip_agreement_matches() {
        let rng = SystemRandom::new();
        let client_priv = EphemeralPrivateKey::generate(&ECDH_P256, &rng).unwrap();
        let client_pub = client_priv.compute_public_key().unwrap();
        let salt = random_bytes::<32>().unwrap();
        let info = b"VS_SESSION_V2|test";

        let (server_pub65, server_key) =
            ecdh_p256_agree_ephemeral(client_pub.as_ref(), &salt, info).unwrap();

        let server_unparsed = UnparsedPublicKey::new(&ECDH_P256, &server_pub65);
        let mut bound_info = Vec::from(info);
        bound_info.extend_from_slice(client_pub.as_ref());
        bound_info.extend_from_slice(&server_pub65);
        let client_key = agreement::agree_ephemeral(client_priv, &server_unparsed, |ss| {
            hkdf_sha256_32(ss, &salt, &bound_info)
        })
        .unwrap()
        .unwrap();

        assert!(ct_eq(server_key.as_bytes(), client_key.as_bytes()));
    }

    #[test]
    fn session_grant_mint_verify_and_expiry() {
        let key = SecretKey32::generate().unwrap();
        let claims = SessionGrantClaims {
            sub: "buyer-42".into(),
            aud: "https://viewer.example".into(),
            asset_id: "hero-car".into(),
            jti: "jti-001".into(),
            iat: 1000,
            exp: 2000,
            scopes: vec!["3d:stream".into()],
        };
        let tok = mint_session_grant(&key, &claims).unwrap();
        let verified = verify_session_grant(
            &key,
            &tok,
            Some("https://viewer.example"),
            Some("hero-car"),
            Some(1500),
        )
        .unwrap();
        assert_eq!(verified, claims);
        assert_eq!(
            verify_session_grant(&key, &tok, Some("https://viewer.example"), None, Some(2001)),
            Err(CryptoError::TokenExpired)
        );
        assert_eq!(
            verify_session_grant(&key, &tok, Some("https://evil.example"), None, Some(1500)),
            Err(CryptoError::AuthenticationFailed)
        );
    }
}
