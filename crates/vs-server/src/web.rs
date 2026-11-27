//! Hardened async web asset delivery (`vs-server::web`):
//!
//! Security and concurrency design:
//! - **Fail-closed `/__vibeslayer/lease` authentication:** requires `auth_signing_key`
//!   with `expected_aud = site_id`, `"web:lease"` scope, optional `asset_id` filtering, and `jti`
//!   replay rejection unless explicit `allow_anonymous_public_site: true` opt-in is set.
//! - **Closure-scoped key handling:** `loader.js` keeps non-extractable
//!   `CryptoKey` handles closure-scoped inside an IIFE with full ECDH `clientPub || serverPub`
//!   HKDF transcript binding (never exposes key material on `window`).
//! - **Authenticated `.vsweb` v2 bundle:** HMAC-SHA256 over serialized manifest verified
//!   in constant time in `WebBundle::from_bytes`, plus length-prefixed AAD binding `site_id`,
//!   `path`, and `content_type` (defeats MIME spoofing & `|` delimiter injection).
//! - **O(1) `HashSet` lease filtering, `16 KiB` body cap, `TimeoutLayer`, and ref-counted `Bytes`
//!   asset storage.**

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tower_http::timeout::TimeoutLayer;
use vs_crypto::{
    aead_seal, ct_eq, ecdh_p256_agree_ephemeral, hkdf_sha256_32, hmac_sha256_parts, now_unix_secs,
    random_bytes, sha256, verify_session_grant, AeadAlg, SecretKey32, SessionAead,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardMode {
    Off,
    Observe,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SealedAssetDisk {
    path: String,
    content_type: String,
    etag: String,
    blob: Vec<u8>,
    asset_salt: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct SealedAsset {
    pub path: String,
    pub content_type: String,
    pub etag: String,
    /// `nonce12 || ciphertext || tag16` encrypted under per-asset key.
    pub blob: Bytes,
    pub asset_salt: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct WebBundleDisk {
    version: u32,
    site_id: String,
    assets: Vec<SealedAssetDisk>,
}

#[derive(Debug, Clone)]
pub struct WebBundle {
    pub site_id: String,
    pub master_key: SecretKey32,
    pub assets: HashMap<String, SealedAsset>,
}

const VSWEB_V2_MAGIC: &[u8; 8] = b"VSWEBV02";

/// Unambiguous length-prefixed AAD/HKDF info binding `site_id`, `path`, and `content_type`.
fn encode_asset_info(site_id: &str, path: &str, content_type: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(14 + 12 + site_id.len() + path.len() + content_type.len());
    out.extend_from_slice(b"VSWEB_V2_ASSET");
    out.extend_from_slice(&(site_id.len() as u32).to_le_bytes());
    out.extend_from_slice(site_id.as_bytes());
    out.extend_from_slice(&(path.len() as u32).to_le_bytes());
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(&(content_type.len() as u32).to_le_bytes());
    out.extend_from_slice(content_type.as_bytes());
    out
}

fn bundle_mac(master_key: &SecretKey32, json_bytes: &[u8]) -> Result<[u8; 32], String> {
    let mac_key = hkdf_sha256_32(
        master_key.as_bytes(),
        b"VSWEB_V2_BUNDLE_MAC_SALT",
        b"VSWEB_V2_BUNDLE_MAC_V2",
    )
    .map_err(|_| "bundle mac key derivation failed".to_string())?;
    Ok(hmac_sha256_parts(
        mac_key.as_bytes(),
        &[b"VSWEB_V2_MAC|", json_bytes],
    ))
}

impl WebBundle {
    /// Serialize the sealed `.vsweb` v2 bundle with a 32-byte keyed HMAC-SHA256 authenticator:
    /// `VSWEBV02 (8B) || mac32 (32B) || json_bytes`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut assets: Vec<SealedAssetDisk> = self
            .assets
            .values()
            .map(|a| SealedAssetDisk {
                path: a.path.clone(),
                content_type: a.content_type.clone(),
                etag: a.etag.clone(),
                blob: a.blob.to_vec(),
                asset_salt: a.asset_salt,
            })
            .collect();
        assets.sort_by(|a, b| a.path.cmp(&b.path));
        let disk = WebBundleDisk {
            version: 2,
            site_id: self.site_id.clone(),
            assets,
        };
        let json_bytes = serde_json::to_vec(&disk).map_err(|e| format!("serialize failed: {e}"))?;
        let mac = bundle_mac(&self.master_key, &json_bytes)?;
        let mut out = Vec::with_capacity(8 + 32 + json_bytes.len());
        out.extend_from_slice(VSWEB_V2_MAGIC);
        out.extend_from_slice(&mac);
        out.extend_from_slice(&json_bytes);
        Ok(out)
    }

    /// Authenticate and load a `.vsweb` v2 bundle from disk using the site's `master_key`.
    pub fn from_bytes(master_key: SecretKey32, raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 40 || &raw[..8] != VSWEB_V2_MAGIC {
            return Err("invalid .vsweb v2 bundle".into());
        }
        let provided_mac = &raw[8..40];
        let json_bytes = &raw[40..];
        let expected_mac = bundle_mac(&master_key, json_bytes)?;
        if !ct_eq(provided_mac, &expected_mac) {
            return Err("bundle authentication failed".into());
        }
        let disk: WebBundleDisk =
            serde_json::from_slice(json_bytes).map_err(|e| format!("invalid .vsweb v2 json: {e}"))?;
        if disk.version != 2 {
            return Err(format!("unsupported .vsweb version {}", disk.version));
        }
        let mut assets = HashMap::with_capacity(disk.assets.len());
        for a in disk.assets {
            assets.insert(
                a.path.clone(),
                SealedAsset {
                    path: a.path,
                    content_type: a.content_type,
                    etag: a.etag,
                    blob: Bytes::from(a.blob),
                    asset_salt: a.asset_salt,
                },
            );
        }
        Ok(Self {
            site_id: disk.site_id,
            master_key,
            assets,
        })
    }

    /// Seal `(relative_path, content_type, plaintext)` entries into content-hashed `.vsweb` v2 blobs.
    pub fn seal_files(
        site_id: impl Into<String>,
        master_key: SecretKey32,
        files: Vec<(String, String, Vec<u8>)>,
    ) -> Result<Self, vs_crypto::CryptoError> {
        let site_id = site_id.into();
        let mut assets = HashMap::with_capacity(files.len());
        for (rel, ct_type, plain) in files {
            let norm = rel.trim_start_matches('/').to_string();
            let asset_salt = random_bytes::<32>()?;
            let info = encode_asset_info(&site_id, &norm, &ct_type);
            let asset_key = hkdf_sha256_32(master_key.as_bytes(), &asset_salt, &info)?;
            let nonce = random_bytes::<12>()?;
            let ct = aead_seal(AeadAlg::Aes256Gcm, asset_key.as_bytes(), &nonce, &info, &plain)?;
            let mut blob = Vec::with_capacity(12 + ct.len());
            blob.extend_from_slice(&nonce);
            blob.extend_from_slice(&ct);
            let digest = sha256(&blob);
            let etag = format!("\"{}\"", hex::encode(&digest[..12]));
            assets.insert(
                norm.clone(),
                SealedAsset {
                    path: norm,
                    content_type: ct_type,
                    etag,
                    blob: Bytes::from(blob),
                    asset_salt,
                },
            );
        }
        Ok(Self {
            site_id,
            master_key,
            assets,
        })
    }
}

const MAX_WEB_USED_JTIS: usize = 50_000;

struct WebJtiCache {
    entries: HashMap<String, u64>,
    last_prune: Instant,
}

#[derive(Clone)]
pub struct WebServerState {
    pub bundle: Arc<WebBundle>,
    pub auth_signing_key: Option<SecretKey32>,
    /// Must be explicitly `true` to serve `/__vibeslayer/lease` without a signed bearer grant.
    pub allow_anonymous_public_site: bool,
    pub spa_fallback: bool,
    pub guard_mode: GuardMode,
    used_jtis: Arc<Mutex<WebJtiCache>>,
}

impl WebServerState {
    pub fn new(
        bundle: Arc<WebBundle>,
        auth_signing_key: Option<SecretKey32>,
        allow_anonymous_public_site: bool,
        spa_fallback: bool,
        guard_mode: GuardMode,
    ) -> Self {
        Self {
            bundle,
            auth_signing_key,
            allow_anonymous_public_site,
            spa_fallback,
            guard_mode,
            used_jtis: Arc::new(Mutex::new(WebJtiCache {
                entries: HashMap::new(),
                last_prune: Instant::now(),
            })),
        }
    }
}

#[derive(Deserialize)]
struct LeaseRequest {
    client_pub_b64: String,
    #[serde(default)]
    asset_paths: Vec<String>,
}

#[derive(Serialize)]
struct LeaseAssetEntry {
    path: String,
    content_type: String,
    etag: String,
    asset_key_b64: String,
    aad_b64: String,
}

impl Drop for LeaseAssetEntry {
    fn drop(&mut self) {
        self.asset_key_b64.zeroize();
    }
}

#[derive(Serialize)]
struct LeaseResponse {
    server_pub_b64: String,
    hkdf_salt_b64: String,
    hkdf_info: String,
    manifest_nonce_b64: String,
    manifest_ct_b64: String,
    guard_mode: GuardMode,
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

async fn handle_shell(State(st): State<WebServerState>) -> impl IntoResponse {
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{}</title></head><body><div id=\"app\"></div>\
         <script type=\"module\" src=\"/__vibeslayer/loader.js\"></script></body></html>",
        escape_html(&st.bundle.site_id)
    );
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    (StatusCode::OK, headers, Html(html))
}

async fn handle_asset(
    State(st): State<WebServerState>,
    Path(asset_path): Path<String>,
) -> Result<Response, StatusCode> {
    let key = asset_path.trim_start_matches('/');
    let asset = st.bundle.assets.get(key).ok_or(StatusCode::NOT_FOUND)?;
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    if let Ok(ev) = HeaderValue::from_str(&asset.etag) {
        headers.insert(axum::http::header::ETAG, ev);
    }
    Ok((StatusCode::OK, headers, asset.blob.clone()).into_response())
}

async fn handle_lease(
    State(st): State<WebServerState>,
    headers: HeaderMap,
    Json(req): Json<LeaseRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    if req.asset_paths.len() > 256 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // CRIT-01 fix: fail closed unless auth succeeds OR explicit `allow_anonymous_public_site` opt-in.
    let mut allowed_asset_filter: Option<String> = None;
    if let Some(ref signing_key) = st.auth_signing_key {
        let auth = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let now = now_unix_secs();
        let claims = verify_session_grant(
            signing_key,
            auth,
            Some(&st.bundle.site_id),
            None,
            Some(now),
        )
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
        if !claims.scopes.iter().any(|s| s == "web:lease") {
            return Err(StatusCode::FORBIDDEN);
        }
        // Reject empty jti so single-use replay tracking cannot be bypassed (Loop 3 LOW-1)
        if claims.jti.is_empty() {
            return Err(StatusCode::UNAUTHORIZED);
        }
        {
            let mut cache = st
                .used_jtis
                .lock()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let now_inst = Instant::now();
            if now_inst.duration_since(cache.last_prune) >= Duration::from_secs(30) {
                cache.last_prune = now_inst;
                cache.entries.retain(|_, exp| *exp > now);
            }
            if let Some(&exp) = cache.entries.get(&claims.jti) {
                if exp > now {
                    return Err(StatusCode::CONFLICT);
                }
            }
            if !cache.entries.contains_key(&claims.jti) && cache.entries.len() >= MAX_WEB_USED_JTIS {
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            cache.entries.insert(claims.jti, claims.exp);
        }
        if !claims.asset_id.is_empty() {
            allowed_asset_filter = Some(claims.asset_id);
        }
    } else if !st.allow_anonymous_public_site {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let client_pub = B64
        .decode(req.client_pub_b64.trim())
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let salt = random_bytes::<32>().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let lease_id = hex::encode(random_bytes::<12>().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);
    let hkdf_info = format!("VSWEB_V2_LEASE|{}|{lease_id}", st.bundle.site_id);

    let (server_pub, wrap_key) =
        ecdh_p256_agree_ephemeral(&client_pub, &salt, hkdf_info.as_bytes())
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    let sess_aead = SessionAead::new(AeadAlg::Aes256Gcm, wrap_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // O(1) HashSet lookup eliminates quadratic O(|A|*|R|) CPU DoS (HIGH-06)
    let requested_set: HashSet<&str> = req
        .asset_paths
        .iter()
        .map(|p| p.trim_start_matches('/'))
        .collect();

    let mut entries = Vec::new();
    for asset in st.bundle.assets.values() {
        if let Some(ref only_asset) = allowed_asset_filter {
            if asset.path != *only_asset {
                continue;
            }
        }
        if !requested_set.is_empty() && !requested_set.contains(asset.path.as_str()) {
            continue;
        }
        let info = encode_asset_info(&st.bundle.site_id, &asset.path, &asset.content_type);
        let asset_key = hkdf_sha256_32(st.bundle.master_key.as_bytes(), &asset.asset_salt, &info)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        entries.push(LeaseAssetEntry {
            path: asset.path.clone(),
            content_type: asset.content_type.clone(),
            etag: asset.etag.clone(),
            asset_key_b64: B64.encode(asset_key.as_bytes()),
            aad_b64: B64.encode(&info),
        });
    }

    let manifest_bytes = Zeroizing::new(
        serde_json::to_vec(&entries).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    let (nonce, ct) = sess_aead
        .seal_next(hkdf_info.as_bytes(), &manifest_bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok((
        StatusCode::OK,
        resp_headers,
        Json(LeaseResponse {
            server_pub_b64: B64.encode(server_pub),
            hkdf_salt_b64: B64.encode(salt),
            hkdf_info,
            manifest_nonce_b64: B64.encode(nonce),
            manifest_ct_b64: B64.encode(ct),
            guard_mode: st.guard_mode,
        }),
    ))
}

async fn handle_loader_js() -> impl IntoResponse {
    // Closure-scoped non-extractable WebCrypto keys — ZERO global `window.__VS_MANIFEST__` leak (CRIT-01)
    // Per-token cache clears rejected promises so transient errors never poison future calls (Loop 3 HIGH-2)
    const LOADER_JS: &str = r#"(() => {
  const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const toB64 = (u) => btoa(String.fromCharCode(...u));
  const leasesByToken = new Map();

  async function initLease(token) {
    const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    const pubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch('/__vibeslayer/lease', {
      method: 'POST', headers,
      body: JSON.stringify({ client_pub_b64: toB64(pubRaw) })
    });
    if (!res.ok) throw new Error(`lease failed: ${res.status}`);
    const lease = await res.json();
    const srvRaw = b64(lease.server_pub_b64);
    const srvPub = await crypto.subtle.importKey('raw', srvRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: srvPub }, kp.privateKey, 256);
    const hkdfKey = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    const infoPrefix = new TextEncoder().encode(lease.hkdf_info);
    const boundInfo = new Uint8Array(infoPrefix.length + pubRaw.length + srvRaw.length);
    boundInfo.set(infoPrefix, 0);
    boundInfo.set(pubRaw, infoPrefix.length);
    boundInfo.set(srvRaw, infoPrefix.length + pubRaw.length);
    const wrapKey = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: b64(lease.hkdf_salt_b64), info: boundInfo },
      hkdfKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64(lease.manifest_nonce_b64), additionalData: infoPrefix },
      wrapKey, b64(lease.manifest_ct_b64)
    );
    const entries = JSON.parse(new TextDecoder().decode(pt));
    const keys = new Map();
    for (const e of entries) {
      const ck = await crypto.subtle.importKey('raw', b64(e.asset_key_b64), { name: 'AES-GCM' }, false, ['decrypt']);
      keys.set(e.path, { key: ck, aad: b64(e.aad_b64), contentType: e.content_type });
    }
    return keys;
  }

  function getKeysForToken(token) {
    const cacheKey = token ? `tok:${token}` : 'anon';
    let p = leasesByToken.get(cacheKey);
    if (!p) {
      if (leasesByToken.size >= 64) {
        const oldest = leasesByToken.keys().next().value;
        leasesByToken.delete(oldest);
      }
      p = initLease(token).catch((err) => {
        if (leasesByToken.get(cacheKey) === p) leasesByToken.delete(cacheKey);
        throw err;
      });
      leasesByToken.set(cacheKey, p);
    }
    return p;
  }

  Object.defineProperty(window, 'vibeSlayerDecryptAsset', {
    value: async (assetPath, token) => {
      const keys = await getKeysForToken(token);
      const clean = String(assetPath || '').replace(/^\/+/, '');
      const meta = keys.get(clean);
      if (!meta) throw new Error(`asset not leased: ${clean}`);
      const res = await fetch(`/assets/${clean}`);
      if (!res.ok) throw new Error(`fetch failed: ${res.status}`);
      const blob = new Uint8Array(await res.arrayBuffer());
      const iv = blob.subarray(0, 12);
      const ct = blob.subarray(12);
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: meta.aad }, meta.key, ct);
      return { bytes: new Uint8Array(plain), contentType: meta.contentType };
    },
    writable: false, configurable: false
  });
})();
"#;
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/javascript; charset=utf-8"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("public, max-age=3600"));
    (StatusCode::OK, headers, LOADER_JS)
}

async fn handle_spa_fallback(State(st): State<WebServerState>) -> Response {
    if st.spa_fallback {
        handle_shell(State(st)).await.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

pub fn build_web_router(state: WebServerState) -> Router {
    Router::new()
        .route("/", get(handle_shell))
        .route("/__vibeslayer/loader.js", get(handle_loader_js))
        .route(
            "/__vibeslayer/lease",
            post(handle_lease).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route("/assets/{*asset_path}", get(handle_asset))
        .fallback(get(handle_spa_fallback))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(20),
        ))
        .with_state(state)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use vs_crypto::{mint_session_grant, SessionGrantClaims};

    #[tokio::test]
    async fn web_router_enforces_fail_closed_auth_bundle_mac_spa_fallback_and_immutable_assets() {
        let mk = SecretKey32::generate().unwrap();
        let auth_key = SecretKey32::generate().unwrap();
        let bundle = WebBundle::seal_files(
            "demo-site",
            mk.clone(),
            vec![(
                "app.abc123.js".into(),
                "application/javascript".into(),
                b"console.log('sealed');".to_vec(),
            )],
        )
        .unwrap();

        // MED-02: bundle serialization authenticates manifest & rejects tampering
        let raw = bundle.to_bytes().unwrap();
        assert!(WebBundle::from_bytes(mk.clone(), &raw).is_ok());
        let mut tampered = raw.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(WebBundle::from_bytes(mk, &tampered).is_err());

        let state = WebServerState::new(
            Arc::new(bundle),
            Some(auth_key.clone()),
            false,
            true,
            GuardMode::Observe,
        );
        let app = build_web_router(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        // 1. SPA deep-link fallback returns 200 HTML shell
        let resp_spa = raw_http(addr, "GET /products/watch-42 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await;
        assert!(resp_spa.contains("200 OK"));
        assert!(resp_spa.contains("/__vibeslayer/loader.js"));

        // 2. Content-hashed asset gets immutable cache header
        let resp_asset = raw_http(addr, "GET /assets/app.abc123.js HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await;
        assert!(resp_asset.contains("200 OK"));
        assert!(resp_asset.to_ascii_lowercase().contains("max-age=31536000, immutable"));

        // 3. CRIT-01: unauthenticated lease request MUST fail closed with 401!
        let rng = ring::rand::SystemRandom::new();
        let kp = ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::ECDH_P256, &rng).unwrap();
        let pub_b64 = B64.encode(kp.compute_public_key().unwrap().as_ref());
        let lease_body = format!("{{\"client_pub_b64\":\"{pub_b64}\"}}");
        let resp_unauth = raw_http(
            addr,
            &format!("POST /__vibeslayer/lease HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{lease_body}", lease_body.len()),
        ).await;
        assert!(resp_unauth.contains("401"));

        // 4. Scoped bearer token succeeds ONCE and rejects jti replay (409)!
        let now = now_unix_secs();
        let tok = mint_session_grant(
            &auth_key,
            &SessionGrantClaims {
                sub: "user-1".into(),
                aud: "demo-site".into(),
                asset_id: "app.abc123.js".into(),
                jti: "lease-jti-1".into(),
                iat: now,
                exp: now + 120,
                scopes: vec!["web:lease".into()],
            },
        )
        .unwrap();
        let auth_req = format!(
            "POST /__vibeslayer/lease HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {tok}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{lease_body}",
            lease_body.len()
        );
        let resp_ok = raw_http(addr, &auth_req).await;
        assert!(resp_ok.contains("200 OK"), "expected 200, got: {resp_ok}");
        let resp_replay = raw_http(addr, &auth_req).await;
        assert!(resp_replay.contains("409"), "expected 409 on jti replay, got: {resp_replay}");

        srv.abort();
    }

    async fn raw_http(addr: std::net::SocketAddr, req: &str) -> String {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }
}
