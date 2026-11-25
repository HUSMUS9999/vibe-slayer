//! `vs-server`: Hardened async Tokio/Axum multi-SKU zero-geometry 3D streaming & `.vsweb` v2 server.
//!
//! Loop 2 security & scalability guarantees (`#![forbid(unsafe_code)]`):
//! - Async HTTP/1.1+HTTP/2 with `TimeoutLayer`, strict `DefaultBodyLimit` (`16 KiB` JSON / `4 MiB`
//!   forensics), bounded `render_sem` + `forensics_sem` with `503` backpressure timeouts, and
//!   non-blocking `spawn_blocking` for all glTF I/O, rendering, and FFT decoding.
//! - Scoped bearer auth (`stream:3d`, `forensics:trace`), `jti` replay cache, authenticated-only
//!   watermark attribution (`claims.sub`), and fail-closed CORS (`allow_any_origin` opt-in).
//! - Image decompression-bomb limits (`2048×2048`, `32 MiB`) before decoding on `/v1/forensics/trace`.
//! - Bounded `sessions` map, per-subject active session caps, secondary subject-level spherical
//!   `ViewCoverageBudget` (defeating multi-session 3DGS sweeps), cached `Bytes` turntables,
//!   DOM-safe `<vs-3d-viewer>` (zero `innerHTML` XSS), and validated CSP `frame-ancestors`.

#![forbid(unsafe_code)]

#[cfg(feature = "web")]
pub mod web;

#[cfg(feature = "3d")]
mod server_3d {
    use std::collections::{HashMap, VecDeque};
    use std::io::Cursor;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use axum::body::Bytes;
    use axum::extract::{ConnectInfo, DefaultBodyLimit, Extension, Path, State};
    use axum::http::header::{
        AUTHORIZATION, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, ORIGIN, VARY,
    };
    use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use image::{ImageReader, Limits};
    use ipnet::IpNet;
    use serde::{Deserialize, Serialize};
    use tokio::sync::Semaphore;
    use tower_http::cors::{AllowOrigin, CorsLayer};
    use tower_http::timeout::TimeoutLayer;
    use vs_3d::anti_3dgs::ViewCoverageBudget;
    use vs_3d::{render_watermarked_jpeg_with_engine, AssetCatalog, OrbitCamera};
    use vs_crypto::{
        ecdh_p256_agree_ephemeral, hmac_sha256_parts, now_unix_secs, random_bytes,
        verify_session_grant, AeadAlg, SecretKey32, SessionAead, SessionGrantClaims,
    };
    use vs_watermark::WatermarkEngine;

    const DEFAULT_CSP_PREFIX: &str =
        "default-src 'self'; img-src 'self' data: blob:; style-src 'self'; script-src 'self'; frame-ancestors ";

    /// Configuration for the multi-SKU zero-geometry 3D streaming server.
    #[derive(Debug, Clone)]
    pub struct Server3dConfig {
        pub wm_key: SecretKey32,
        /// Optional HMAC-SHA256 signing key (MUST be separate from `wm_key` in production).
        pub auth_signing_key: Option<SecretKey32>,
        /// Allow unauthenticated `/v1/forensics/trace` calls (ONLY for local tests; default `false`).
        pub allow_unauthenticated_trace: bool,
        /// Allowed CORS origins. Empty fails closed (same-origin) unless `allow_any_origin` is true.
        pub allowed_origins: Vec<String>,
        /// Explicit dev opt-in for wildcard CORS (`false` by default).
        pub allow_any_origin: bool,
        /// Allowed CSP `frame-ancestors` tokens (validated against `;`/CRLF injection).
        pub frame_ancestors: String,
        /// Maximum fraction of the 192-bin sphere a session or subject may sweep before degrading.
        pub max_sphere_coverage: f32,
        /// Enable UX-safe smooth harmonic anti-3DGS camera-intrinsics perturbation.
        pub anti_3dgs: bool,
        pub max_concurrent_renders: usize,
        pub max_concurrent_traces: usize,
        pub max_sessions: usize,
        pub max_sessions_per_subject: usize,
        pub max_width: usize,
        pub max_height: usize,
        pub jpeg_quality: u8,
        pub session_ttl: Duration,
        pub trusted_proxies: Vec<IpNet>,
    }

    impl Server3dConfig {
        pub fn new(wm_key: SecretKey32) -> Self {
            Self {
                wm_key,
                auth_signing_key: None,
                allow_unauthenticated_trace: false,
                allowed_origins: Vec::new(),
                allow_any_origin: false,
                frame_ancestors: "'self'".to_string(),
                max_sphere_coverage: 0.45,
                anti_3dgs: true,
                max_concurrent_renders: std::thread::available_parallelism()
                    .map(|n| n.get().clamp(2, 16))
                    .unwrap_or(4),
                max_concurrent_traces: 2,
                max_sessions: 10_000,
                max_sessions_per_subject: 8,
                max_width: 1280,
                max_height: 820,
                jpeg_quality: 84,
                session_ttl: Duration::from_secs(900),
                trusted_proxies: Vec::new(),
            }
        }
    }

    struct ActiveStreamSession {
        asset_id: String,
        subject_key: String,
        buyer_id: u64,
        proj_seed: [u8; 32],
        aead: Arc<SessionAead>,
        budget: ViewCoverageBudget,
        expires_at: Instant,
    }

    struct SubjectBudgetEntry {
        budget: ViewCoverageBudget,
        expires_at: Instant,
    }

    struct TurntableCache {
        entries: HashMap<(String, u32), Bytes>,
        order: VecDeque<(String, u32)>,
        max_entries: usize,
    }

    impl TurntableCache {
        fn new(max_entries: usize) -> Self {
            Self {
                entries: HashMap::new(),
                order: VecDeque::new(),
                max_entries: max_entries.max(1),
            }
        }

        fn get(&self, key: &(String, u32)) -> Option<Bytes> {
            self.entries.get(key).cloned()
        }

        fn insert(&mut self, key: (String, u32), val: Bytes) {
            if let Some(slot) = self.entries.get_mut(&key) {
                *slot = val;
                return;
            }
            if self.entries.len() >= self.max_entries {
                if let Some(old) = self.order.pop_front() {
                    self.entries.remove(&old);
                }
            }
            self.order.push_back(key.clone());
            self.entries.insert(key, val);
        }
    }

    const MAX_USED_JTIS: usize = 50_000;
    const MAX_RATE_BUCKETS: usize = 20_000;

    struct RateBucket {
        tokens: f64,
        last_refill: Instant,
    }

    struct SharedStateInner {
        sessions: HashMap<String, ActiveStreamSession>,
        subject_budgets: HashMap<(String, String), SubjectBudgetEntry>,
        used_jtis: HashMap<String, u64>,
        rate_buckets: HashMap<String, RateBucket>,
        last_prune: Instant,
        last_rate_prune: Instant,
    }

    impl SharedStateInner {
        fn new() -> Self {
            let now = Instant::now();
            Self {
                sessions: HashMap::new(),
                subject_budgets: HashMap::new(),
                used_jtis: HashMap::new(),
                rate_buckets: HashMap::new(),
                last_prune: now,
                last_rate_prune: now,
            }
        }

        fn maybe_prune(&mut self, now: Instant, now_unix: u64) {
            // Strictly time-gated pruning prevents O(N) global-Mutex thrashing at high load (Loop 3 MED-6)
            if now.duration_since(self.last_prune) < Duration::from_secs(30) {
                return;
            }
            self.last_prune = now;
            self.sessions.retain(|_, s| s.expires_at > now);
            self.subject_budgets.retain(|_, b| b.expires_at > now);
            self.used_jtis.retain(|_, exp| *exp > now_unix);
            self.rate_buckets
                .retain(|_, b| now.duration_since(b.last_refill) < Duration::from_secs(120));
        }

        fn allow_rate(&mut self, key: &str, capacity: f64, refill_per_sec: f64, now: Instant) -> bool {
            if self.rate_buckets.len() >= MAX_RATE_BUCKETS && !self.rate_buckets.contains_key(key) {
                if now.duration_since(self.last_rate_prune) >= Duration::from_secs(10) {
                    self.last_rate_prune = now;
                    self.rate_buckets
                        .retain(|_, b| now.duration_since(b.last_refill) < Duration::from_secs(60));
                }
                if self.rate_buckets.len() >= MAX_RATE_BUCKETS {
                    return false;
                }
            }
            let b = self.rate_buckets.entry(key.to_string()).or_insert(RateBucket {
                tokens: capacity,
                last_refill: now,
            });
            let elapsed = now.duration_since(b.last_refill).as_secs_f64();
            b.tokens = (b.tokens + elapsed * refill_per_sec).min(capacity);
            b.last_refill = now;
            if b.tokens >= 1.0 {
                b.tokens -= 1.0;
                true
            } else {
                false
            }
        }
    }

    #[derive(Clone)]
    pub struct App3dState {
        pub catalog: AssetCatalog,
        pub cfg: Arc<Server3dConfig>,
        wm_engine: Arc<WatermarkEngine>,
        inner: Arc<Mutex<SharedStateInner>>,
        turntables: Arc<Mutex<TurntableCache>>,
        render_sem: Arc<Semaphore>,
        forensics_sem: Arc<Semaphore>,
    }

    impl App3dState {
        pub fn new(catalog: AssetCatalog, cfg: Server3dConfig) -> Self {
            let wm_engine = Arc::new(WatermarkEngine::new(cfg.wm_key.clone()));
            let render_sem = Arc::new(Semaphore::new(cfg.max_concurrent_renders.max(1)));
            let forensics_sem = Arc::new(Semaphore::new(cfg.max_concurrent_traces.max(1)));
            Self {
                catalog,
                cfg: Arc::new(cfg),
                wm_engine,
                inner: Arc::new(Mutex::new(SharedStateInner::new())),
                turntables: Arc::new(Mutex::new(TurntableCache::new(256))),
                render_sem,
                forensics_sem,
            }
        }
    }

    /// Resolve true client IP by walking `X-Forwarded-For` right-to-left skipping trusted proxy CIDRs.
    pub fn resolve_client_ip(
        peer: IpAddr,
        xff_header: Option<&str>,
        trusted_proxies: &[IpNet],
    ) -> IpAddr {
        let is_trusted = |ip: IpAddr| trusted_proxies.iter().any(|net| net.contains(&ip));
        if !is_trusted(peer) {
            return peer;
        }
        if let Some(xff) = xff_header {
            for part in xff.rsplit(',') {
                match part.trim().parse::<IpAddr>() {
                    Ok(ip) => {
                        if !is_trusted(ip) {
                            return ip;
                        }
                    }
                    // Fail closed to peer on malformed/unparseable XFF hop (Loop 4 HIGH-3)
                    Err(_) => return peer,
                }
            }
        }
        peer
    }

    fn sanitize_frame_ancestors(raw: &str) -> String {
        if raw.contains(';') || raw.contains(',') || raw.chars().any(|c| c.is_control()) {
            return "'self'".to_string();
        }
        let mut tokens = Vec::new();
        for tok in raw.split_whitespace() {
            let valid = matches!(tok, "'self'" | "'none'" | "https:" | "http:")
                || ((tok.starts_with("https://") || tok.starts_with("http://"))
                    && tok.len() > 8
                    && tok
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b":/.-_*".contains(&b)));
            if valid {
                tokens.push(tok);
            }
        }
        if tokens.is_empty() {
            "'self'".to_string()
        } else {
            tokens.join(" ")
        }
    }

    fn csp_header_value(frame_ancestors: &str) -> HeaderValue {
        let fa = sanitize_frame_ancestors(frame_ancestors);
        let policy = format!("{DEFAULT_CSP_PREFIX}{fa}");
        HeaderValue::from_str(&policy).unwrap_or_else(|_| {
            HeaderValue::from_static(
                "default-src 'self'; img-src 'self' data: blob:; style-src 'self'; script-src 'self'; frame-ancestors 'self'",
            )
        })
    }

    fn extract_client_key(
        cfg: &Server3dConfig,
        connect: Option<Extension<ConnectInfo<SocketAddr>>>,
        headers: &HeaderMap,
    ) -> String {
        match connect {
            Some(Extension(ConnectInfo(addr))) => {
                // Join ALL X-Forwarded-For header instances lossily so obs-text (>=0x80) never drops a hop (Loop 4 HIGH-3)
                let joined: Vec<String> = headers
                    .get_all("x-forwarded-for")
                    .iter()
                    .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
                    .collect();
                let xff_owned = if joined.is_empty() {
                    None
                } else {
                    Some(joined.join(", "))
                };
                resolve_client_ip(addr.ip(), xff_owned.as_deref(), &cfg.trusted_proxies).to_string()
            }
            None => "local".to_string(),
        }
    }

    fn check_bearer_auth(
        cfg: &Server3dConfig,
        headers: &HeaderMap,
        expected_asset_id: Option<&str>,
        required_scope: &str,
        fail_closed_if_no_key: bool,
    ) -> Result<Option<SessionGrantClaims>, StatusCode> {
        let Some(ref key) = cfg.auth_signing_key else {
            return if fail_closed_if_no_key {
                Err(StatusCode::UNAUTHORIZED)
            } else {
                Ok(None)
            };
        };
        let auth = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let token = auth
            .strip_prefix("Bearer ")
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let req_origin = headers.get(ORIGIN).and_then(|v| v.to_str().ok());
        // If browser Origin header is present, enforce allowlist and bind expected_aud = Origin.
        // If absent (server-to-server forensics or same-origin GET), still verify claims.aud against allowlist (Loop 3 MED-5).
        let expected_aud = if !cfg.allowed_origins.is_empty() {
            if let Some(org) = req_origin {
                if !cfg.allowed_origins.iter().any(|o| o == org) {
                    return Err(StatusCode::FORBIDDEN);
                }
                Some(org)
            } else {
                None
            }
        } else {
            None
        };
        let claims = verify_session_grant(
            key,
            token,
            expected_aud,
            expected_asset_id,
            Some(now_unix_secs()),
        )
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
        if claims.jti.is_empty() {
            return Err(StatusCode::UNAUTHORIZED);
        }
        if !cfg.allowed_origins.is_empty()
            && expected_aud.is_none()
            && !cfg.allowed_origins.iter().any(|o| o == &claims.aud)
        {
            return Err(StatusCode::FORBIDDEN);
        }
        if !claims.scopes.iter().any(|s| s == required_scope) {
            return Err(StatusCode::FORBIDDEN);
        }
        Ok(Some(claims))
    }

    #[derive(Deserialize)]
    struct SessionInitRequest {
        client_pub_b64: String,
        #[serde(default)]
        buyer_label: String,
    }

    #[derive(Serialize)]
    struct SessionInitResponse {
        session_id: String,
        asset_id: String,
        server_pub_b64: String,
        hkdf_salt_b64: String,
        hkdf_info: String,
        buyer_id_hex: String,
        max_width: usize,
        max_height: usize,
        ttl_secs: u64,
    }

    #[derive(Deserialize)]
    struct FrameRequest {
        session_id: String,
        yaw: f32,
        pitch: f32,
        #[serde(default = "default_zoom")]
        zoom: f32,
        #[serde(default)]
        pan_y: f32,
        #[serde(default = "default_w")]
        width: usize,
        #[serde(default = "default_h")]
        height: usize,
    }

    fn default_zoom() -> f32 {
        2.8
    }
    fn default_w() -> usize {
        640
    }
    fn default_h() -> usize {
        400
    }

    #[derive(Serialize)]
    struct FrameResponse {
        nonce_b64: String,
        aad: String,
        ct_b64: String,
        degraded_turntable: bool,
    }

    #[derive(Serialize)]
    struct TraceResponse {
        detected: bool,
        buyer_id_hex: Option<String>,
        verified_mac: bool,
        sync_z_score: f32,
        bit_confidence: f32,
        detected_scale: f32,
        detected_offset: (usize, usize),
    }

    async fn handle_health() -> impl IntoResponse {
        Json(serde_json::json!({ "ok": true, "service": "vs-server", "version": env!("CARGO_PKG_VERSION") }))
    }

    async fn handle_list_models(State(st): State<App3dState>) -> impl IntoResponse {
        Json(serde_json::json!({ "models": st.catalog.list_ids() }))
    }

    async fn handle_poster(
        State(st): State<App3dState>,
        Path(asset_id): Path<String>,
    ) -> Result<Response, StatusCode> {
        let permit = tokio::time::timeout(
            Duration::from_secs(5),
            st.render_sem.clone().acquire_owned(),
        )
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

        let catalog = st.catalog.clone();
        let jpg = tokio::task::spawn_blocking(move || {
            let _p = permit;
            catalog.get_poster_jpeg(&asset_id)
        })
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::NOT_FOUND)?;

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/jpeg"));
        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=86400, stale-while-revalidate=604800"),
        );
        headers.insert(
            CONTENT_SECURITY_POLICY,
            csp_header_value(&st.cfg.frame_ancestors),
        );
        Ok((StatusCode::OK, headers, Bytes::copy_from_slice(&jpg)).into_response())
    }

    async fn handle_turntable(
        State(st): State<App3dState>,
        connect: Option<Extension<ConnectInfo<SocketAddr>>>,
        Path((asset_id, angle_idx)): Path<(String, u32)>,
        headers: HeaderMap,
    ) -> Result<Response, StatusCode> {
        let _claims = check_bearer_auth(&st.cfg, &headers, Some(&asset_id), "stream:3d", false)?;
        let client_ip = extract_client_key(&st.cfg, connect, &headers);
        {
            let mut inner = st
                .inner
                .lock()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            if !inner.allow_rate(&format!("tt:{client_ip}"), 30.0, 6.0, Instant::now()) {
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
        }

        let cache_ctl = if st.cfg.auth_signing_key.is_some() {
            HeaderValue::from_static("private, no-store")
        } else {
            HeaderValue::from_static("public, max-age=3600")
        };

        let idx = angle_idx % 36;
        let cache_key = (asset_id.clone(), idx);
        if let Some(hit) = st
            .turntables
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .get(&cache_key)
        {
            let mut resp_headers = HeaderMap::new();
            resp_headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/jpeg"));
            resp_headers.insert(CACHE_CONTROL, cache_ctl);
            if st.cfg.auth_signing_key.is_some() {
                resp_headers.insert(VARY, HeaderValue::from_static("Authorization"));
            }
            resp_headers.insert(
                CONTENT_SECURITY_POLICY,
                csp_header_value(&st.cfg.frame_ancestors),
            );
            return Ok((StatusCode::OK, resp_headers, hit).into_response());
        }

        let permit = tokio::time::timeout(
            Duration::from_secs(5),
            st.render_sem.clone().acquire_owned(),
        )
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

        let catalog = st.catalog.clone();
        let wm_engine = Arc::clone(&st.wm_engine);
        let asset_for_render = asset_id.clone();
        let jpg = tokio::task::spawn_blocking(move || {
            let _p = permit;
            let scene = catalog.get_scene(&asset_for_render)?;
            let yaw = (idx as f32) * (2.0 * std::f32::consts::PI / 36.0);
            let cam = OrbitCamera {
                yaw,
                pitch: 0.28,
                zoom: 2.8,
                pan_y: 0.0,
            };
            render_watermarked_jpeg_with_engine(
                &scene,
                cam,
                512,
                320,
                &wm_engine,
                0x5455_524E_0000_0000 | (idx as u64),
                &[0u8; 32],
                false,
                82,
            )
        })
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::NOT_FOUND)?;

        let bytes = Bytes::from(jpg);
        st.turntables
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .insert(cache_key, bytes.clone());

        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/jpeg"));
        resp_headers.insert(CACHE_CONTROL, cache_ctl);
        if st.cfg.auth_signing_key.is_some() {
            resp_headers.insert(VARY, HeaderValue::from_static("Authorization"));
        }
        resp_headers.insert(
            CONTENT_SECURITY_POLICY,
            csp_header_value(&st.cfg.frame_ancestors),
        );
        Ok((StatusCode::OK, resp_headers, bytes).into_response())
    }

    async fn handle_session_init(
        State(st): State<App3dState>,
        connect: Option<Extension<ConnectInfo<SocketAddr>>>,
        Path(asset_id): Path<String>,
        headers: HeaderMap,
        Json(req): Json<SessionInitRequest>,
    ) -> Result<impl IntoResponse, StatusCode> {
        let claims = check_bearer_auth(&st.cfg, &headers, Some(&asset_id), "stream:3d", false)?;
        let client_ip = extract_client_key(&st.cfg, connect, &headers);
        if !st.catalog.contains(&asset_id) {
            return Err(StatusCode::NOT_FOUND);
        }

        // MED-06 fix: when authenticated, ALWAYS derive buyer_id strictly from verified claims.sub.
        let (subject_key, attribution_identity) = match &claims {
            Some(c) => (format!("sub:{}", c.sub), c.sub.clone()),
            None => {
                let lbl = if req.buyer_label.is_empty() {
                    format!("anon:{client_ip}")
                } else {
                    req.buyer_label.chars().take(64).collect()
                };
                (format!("ip:{client_ip}"), lbl)
            }
        };

        // Pre-check rate limit, jti replay, and session capacity BEFORE expensive P-256 ECDH (Loop 3 MED-7)
        let pre_now = Instant::now();
        let pre_now_unix = now_unix_secs();
        {
            let mut inner = st
                .inner
                .lock()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            inner.maybe_prune(pre_now, pre_now_unix);
            if !inner.allow_rate(&format!("sess:{client_ip}"), 15.0, 2.0, pre_now) {
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
            if let Some(c) = &claims {
                if let Some(&exp) = inner.used_jtis.get(&c.jti) {
                    if exp > pre_now_unix {
                        return Err(StatusCode::CONFLICT);
                    }
                }
                if !inner.used_jtis.contains_key(&c.jti) && inner.used_jtis.len() >= MAX_USED_JTIS {
                    return Err(StatusCode::SERVICE_UNAVAILABLE);
                }
            }
            if inner.sessions.len() >= st.cfg.max_sessions {
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            let subj_active = inner
                .sessions
                .values()
                .filter(|s| s.subject_key == subject_key && s.expires_at > pre_now)
                .count();
            if subj_active >= st.cfg.max_sessions_per_subject {
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
        }

        let client_pub = B64
            .decode(req.client_pub_b64.trim())
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let salt = random_bytes::<32>().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let sid_bytes = random_bytes::<16>().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let session_id = hex::encode(sid_bytes);
        let hkdf_info = format!("VS3D_V2_SESSION|{asset_id}|{session_id}");

        let (server_pub, session_key) =
            ecdh_p256_agree_ephemeral(&client_pub, &salt, hkdf_info.as_bytes())
                .map_err(|_| StatusCode::BAD_REQUEST)?;
        let aead = Arc::new(
            SessionAead::new(AeadAlg::Aes256Gcm, session_key)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        );

        let bid_mac = hmac_sha256_parts(
            st.cfg.wm_key.as_bytes(),
            &[
                b"VS3D_BUYER_ID|",
                asset_id.as_bytes(),
                b"|",
                attribution_identity.as_bytes(),
                b"|",
                session_id.as_bytes(),
            ],
        );
        let buyer_id = u64::from_le_bytes([
            bid_mac[0], bid_mac[1], bid_mac[2], bid_mac[3], bid_mac[4], bid_mac[5], bid_mac[6],
            bid_mac[7],
        ]);
        let proj_seed = hmac_sha256_parts(
            st.cfg.wm_key.as_bytes(),
            &[b"VS3D_PROJ_SEED|", session_id.as_bytes()],
        );

        let now = Instant::now();
        let now_unix = now_unix_secs();
        {
            let mut inner = st
                .inner
                .lock()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            // Re-verify capacity BEFORE burning single-use jti (Loop 3 MED-7)
            if inner.sessions.len() >= st.cfg.max_sessions {
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            let subj_active = inner
                .sessions
                .values()
                .filter(|s| s.subject_key == subject_key && s.expires_at > now)
                .count();
            if subj_active >= st.cfg.max_sessions_per_subject {
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
            if let Some(c) = &claims {
                if let Some(&exp) = inner.used_jtis.get(&c.jti) {
                    if exp > now_unix {
                        return Err(StatusCode::CONFLICT);
                    }
                }
                if !inner.used_jtis.contains_key(&c.jti) && inner.used_jtis.len() >= MAX_USED_JTIS {
                    return Err(StatusCode::SERVICE_UNAVAILABLE);
                }
                inner.used_jtis.insert(c.jti.clone(), c.exp);
            }
            inner.sessions.insert(
                session_id.clone(),
                ActiveStreamSession {
                    asset_id: asset_id.clone(),
                    subject_key,
                    buyer_id,
                    proj_seed,
                    aead,
                    budget: ViewCoverageBudget::new(st.cfg.max_sphere_coverage),
                    expires_at: now + st.cfg.session_ttl,
                },
            );
        }

        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        Ok((
            StatusCode::OK,
            resp_headers,
            Json(SessionInitResponse {
                session_id,
                asset_id,
                server_pub_b64: B64.encode(server_pub),
                hkdf_salt_b64: B64.encode(salt),
                hkdf_info,
                buyer_id_hex: format!("{buyer_id:016x}"),
                max_width: st.cfg.max_width.max(128),
                max_height: st.cfg.max_height.max(128),
                ttl_secs: st.cfg.session_ttl.as_secs(),
            }),
        ))
    }

    async fn handle_frame(
        State(st): State<App3dState>,
        connect: Option<Extension<ConnectInfo<SocketAddr>>>,
        Path(asset_id): Path<String>,
        headers: HeaderMap,
        Json(req): Json<FrameRequest>,
    ) -> Result<Response, StatusCode> {
        let raw_cam = OrbitCamera {
            yaw: req.yaw,
            pitch: req.pitch,
            zoom: req.zoom,
            pan_y: req.pan_y,
        };
        if !raw_cam.is_finite() {
            return Err(StatusCode::BAD_REQUEST);
        }
        let cam = raw_cam.clamped();
        let client_ip = extract_client_key(&st.cfg, connect, &headers);
        let now = Instant::now();

        let (buyer_id, proj_seed, aead, degraded_turntable) = {
            let mut inner = st
                .inner
                .lock()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            if !inner.allow_rate(&format!("frm:{client_ip}"), 60.0, 20.0, now) {
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
            let expired = inner
                .sessions
                .get(&req.session_id)
                .map(|s| s.expires_at <= now)
                .unwrap_or(false);
            if expired {
                inner.sessions.remove(&req.session_id);
                return Err(StatusCode::UNAUTHORIZED);
            }
            let (subject_key, buyer_id, proj_seed, aead, sess_degraded) = {
                let sess = inner
                    .sessions
                    .get_mut(&req.session_id)
                    .ok_or(StatusCode::UNAUTHORIZED)?;
                if sess.asset_id != asset_id {
                    return Err(StatusCode::UNAUTHORIZED);
                }
                let degraded = sess.budget.record(cam).is_err();
                (
                    sess.subject_key.clone(),
                    sess.buyer_id,
                    sess.proj_seed,
                    Arc::clone(&sess.aead),
                    degraded,
                )
            };
            // Secondary subject+asset spherical budget defeats multi-session 3DGS sweeps (HIGH-04)
            let subj_key = (subject_key, asset_id.clone());
            let subj_degraded = {
                let entry = inner
                    .subject_budgets
                    .entry(subj_key)
                    .or_insert_with(|| SubjectBudgetEntry {
                        budget: ViewCoverageBudget::new(st.cfg.max_sphere_coverage),
                        expires_at: now + st.cfg.session_ttl * 2,
                    });
                if entry.expires_at <= now {
                    entry.budget = ViewCoverageBudget::new(st.cfg.max_sphere_coverage);
                    entry.expires_at = now + st.cfg.session_ttl * 2;
                }
                entry.budget.record(cam).is_err()
            };
            (buyer_id, proj_seed, aead, sess_degraded || subj_degraded)
        };

        let eff_cam = if degraded_turntable {
            let step = (cam.yaw / (2.0 * std::f32::consts::PI) * 16.0).round();
            OrbitCamera {
                yaw: step * (2.0 * std::f32::consts::PI / 16.0),
                pitch: 0.28,
                zoom: 2.8,
                pan_y: 0.0,
            }
        } else {
            cam
        };

        let w = req.width.clamp(128, st.cfg.max_width.max(128));
        let h = req.height.clamp(128, st.cfg.max_height.max(128));

        let permit = tokio::time::timeout(
            Duration::from_secs(5),
            st.render_sem.clone().acquire_owned(),
        )
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

        let catalog = st.catalog.clone();
        let wm_engine = Arc::clone(&st.wm_engine);
        let anti_3dgs = st.cfg.anti_3dgs;
        let q = st.cfg.jpeg_quality;
        let asset_for_render = asset_id.clone();

        let jpg = tokio::task::spawn_blocking(move || {
            let _p = permit;
            let scene = catalog.get_scene(&asset_for_render)?;
            render_watermarked_jpeg_with_engine(
                &scene,
                eff_cam,
                w,
                h,
                &wm_engine,
                buyer_id,
                &proj_seed,
                anti_3dgs && !degraded_turntable,
                q,
            )
        })
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::NOT_FOUND)?;

        let aad = format!("VS3D_FRAME|{asset_id}|{}", req.session_id);
        let (nonce, ct) = aead
            .seal_next(aad.as_bytes(), &jpg)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        resp_headers.insert(
            CONTENT_SECURITY_POLICY,
            csp_header_value(&st.cfg.frame_ancestors),
        );
        Ok((
            StatusCode::OK,
            resp_headers,
            Json(FrameResponse {
                nonce_b64: B64.encode(nonce),
                aad,
                ct_b64: B64.encode(ct),
                degraded_turntable,
            }),
        )
            .into_response())
    }

    async fn handle_forensics_trace(
        State(st): State<App3dState>,
        connect: Option<Extension<ConnectInfo<SocketAddr>>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<impl IntoResponse, StatusCode> {
        // CRIT-03 fix: fail closed unless authenticated with explicit `forensics:trace` scope!
        let _claims = check_bearer_auth(
            &st.cfg,
            &headers,
            None,
            "forensics:trace",
            !st.cfg.allow_unauthenticated_trace,
        )?;
        let client_ip = extract_client_key(&st.cfg, connect, &headers);
        {
            let mut inner = st
                .inner
                .lock()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            if !inner.allow_rate(&format!("trc:{client_ip}"), 6.0, 0.5, Instant::now()) {
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
        }
        if body.is_empty() || body.len() > 4 * 1024 * 1024 {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }

        let permit = tokio::time::timeout(
            Duration::from_secs(5),
            st.forensics_sem.clone().acquire_owned(),
        )
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

        let wm_engine = Arc::clone(&st.wm_engine);
        let res = tokio::task::spawn_blocking(move || {
            let _p = permit;
            let mut reader = ImageReader::new(Cursor::new(&body))
                .with_guessed_format()
                .map_err(|_| StatusCode::BAD_REQUEST)?;
            // Strict decompression-bomb guard (prevents 50 KB PNG -> 7.4 GB RAM OOM!)
            let mut limits = Limits::default();
            limits.max_image_width = Some(2048);
            limits.max_image_height = Some(2048);
            limits.max_alloc = Some(32 * 1024 * 1024);
            reader.limits(limits);

            let img = reader
                .decode()
                .map_err(|_| StatusCode::BAD_REQUEST)?
                .to_rgb8();
            let w = img.width() as usize;
            let h = img.height() as usize;
            Ok::<_, StatusCode>(wm_engine.decode_frame_rgb_blind(img.as_raw(), w, h))
        })
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;

        match res {
            Ok(wm) => Ok(Json(TraceResponse {
                detected: true,
                buyer_id_hex: Some(format!("{:016x}", wm.buyer_id)),
                verified_mac: wm.verified_mac,
                sync_z_score: wm.sync_z_score,
                bit_confidence: wm.bit_confidence,
                detected_scale: wm.detected_scale,
                detected_offset: wm.detected_offset,
            })),
            Err(_) => Ok(Json(TraceResponse {
                detected: false,
                buyer_id_hex: None,
                verified_mac: false,
                sync_z_score: 0.0,
                bit_confidence: 0.0,
                detected_scale: 1.0,
                detected_offset: (0, 0),
            })),
        }
    }

    /// DOM-safe, LCP-safe (`0 CLS`), WCAG 2.2 keyboard-accessible `<vs-3d-viewer>` Web Component.
    /// Uses `document.createElement` (zero `innerHTML` XSS!), validates `api-base`, binds ECDH
    /// pubkeys into WebCrypto HKDF, and coalesces rapid drag/wheel poses.
    async fn handle_embed_js(State(st): State<App3dState>) -> impl IntoResponse {
        const VIEWER_JS: &str = r#"(() => {
  if (customElements.get('vs-3d-viewer')) return;
  const b64ToBytes = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const bytesToB64 = (b) => btoa(String.fromCharCode(...b));
  const sanitizeBase = (raw) => {
    const s = String(raw || '').trim().replace(/\/+$/, '');
    if (!s || /[\x00-\x20\\]/.test(s)) return '';
    if (s.startsWith('/') && !s.startsWith('//')) return s;
    try {
      const u = new URL(s);
      if (u.protocol === 'https:' || u.protocol === 'http:') return u.origin + u.pathname.replace(/\/+$/, '');
    } catch (_) {}
    return '';
  };

  class Vs3dViewer extends HTMLElement {
    constructor() {
      super();
      this.attachShadow({ mode: 'open' });
      this._yaw = 0.45; this._pitch = 0.28; this._zoom = 2.8;
      this._session = null; this._aesKey = null; this._inFlight = false; this._dirty = false;
    }
    connectedCallback() {
      const asset = String(this.getAttribute('asset-id') || 'model');
      const assetEnc = encodeURIComponent(asset);
      const base = sanitizeBase(this.getAttribute('api-base'));
      const style = document.createElement('style');
      style.textContent = `:host{display:block;position:relative;aspect-ratio:16/10;background:#0a0d12;overflow:hidden;border-radius:10px;user-select:none}
        img,canvas{position:absolute;inset:0;width:100%;height:100%;object-fit:contain;display:block}
        canvas{cursor:grab;outline:none}canvas:active{cursor:grabbing}`;
      const poster = document.createElement('img');
      poster.src = `${base}/v1/models/${assetEnc}/poster`;
      poster.alt = `3D Preview: ${asset}`;
      poster.loading = 'eager';
      poster.decoding = 'async';

      const canvas = document.createElement('canvas');
      canvas.width = 640;
      canvas.height = 400;
      canvas.tabIndex = 0;
      canvas.setAttribute('role', 'img');
      canvas.setAttribute('aria-label', `Interactive 3D view of ${asset}. Drag or use arrow keys to rotate; +/- or wheel to zoom.`);
      this.shadowRoot.replaceChildren(style, poster, canvas);

      this._poster = poster;
      this._canvas = canvas;
      this._ctx = canvas.getContext('2d');
      this._base = base;
      this._assetEnc = assetEnc;

      const io = new IntersectionObserver((entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          io.disconnect();
          this._bindControls();
        }
      });
      io.observe(this);
    }
    async _ensureSession() {
      if (this._session) return;
      const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
      const pubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
      const headers = { 'Content-Type': 'application/json' };
      const token = this.getAttribute('token');
      if (token) headers['Authorization'] = `Bearer ${token}`;
      const res = await fetch(`${this._base}/v1/models/${this._assetEnc}/session`, {
        method: 'POST', headers,
        body: JSON.stringify({ client_pub_b64: bytesToB64(pubRaw) })
      });
      if (!res.ok) throw new Error(`session init failed: ${res.status}`);
      const data = await res.json();
      const srvRaw = b64ToBytes(data.server_pub_b64);
      const srvPub = await crypto.subtle.importKey('raw', srvRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
      const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: srvPub }, kp.privateKey, 256);
      const hkdfKey = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
      const infoPrefix = new TextEncoder().encode(data.hkdf_info);
      const boundInfo = new Uint8Array(infoPrefix.length + pubRaw.length + srvRaw.length);
      boundInfo.set(infoPrefix, 0);
      boundInfo.set(pubRaw, infoPrefix.length);
      boundInfo.set(srvRaw, infoPrefix.length + pubRaw.length);
      this._aesKey = await crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: b64ToBytes(data.hkdf_salt_b64), info: boundInfo },
        hkdfKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
      );
      this._session = data.session_id;
    }
    _requestRender() {
      this._dirty = true;
      if (!this._inFlight) this._drainRender().catch(() => {});
    }
    async _drainRender() {
      this._inFlight = true;
      try {
        while (this._dirty) {
          this._dirty = false;
          let res;
          for (let attempt = 0; attempt < 2; attempt++) {
            await this._ensureSession();
            res = await fetch(`${this._base}/v1/models/${this._assetEnc}/frame`, {
              method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                session_id: this._session, yaw: this._yaw, pitch: this._pitch, zoom: this._zoom,
                width: this._canvas.width, height: this._canvas.height
              })
            });
            if (res.status === 401 && attempt === 0) {
              this._session = null;
              this._aesKey = null;
              continue;
            }
            break;
          }
          if (!res || !res.ok) return;
          const f = await res.json();
          const pt = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: b64ToBytes(f.nonce_b64), additionalData: new TextEncoder().encode(f.aad) },
            this._aesKey, b64ToBytes(f.ct_b64)
          );
          const bmp = await createImageBitmap(new Blob([pt], { type: 'image/jpeg' }));
          this._ctx.drawImage(bmp, 0, 0, this._canvas.width, this._canvas.height);
          bmp.close();
          if (this._poster) this._poster.style.display = 'none';
        }
      } finally { this._inFlight = false; }
    }
    _bindControls() {
      let dragging = false, lx = 0, ly = 0;
      this._canvas.addEventListener('pointerdown', (e) => {
        dragging = true; lx = e.clientX; ly = e.clientY;
        this._canvas.setPointerCapture(e.pointerId);
        this._requestRender();
      });
      this._canvas.addEventListener('pointermove', (e) => {
        if (!dragging) return;
        this._yaw += (e.clientX - lx) * 0.012;
        this._pitch = Math.max(-1.3, Math.min(1.3, this._pitch + (e.clientY - ly) * 0.012));
        lx = e.clientX; ly = e.clientY;
        this._requestRender();
      });
      this._canvas.addEventListener('pointerup', () => { dragging = false; });
      this._canvas.addEventListener('wheel', (e) => {
        e.preventDefault();
        this._zoom = Math.max(1.3, Math.min(6.0, this._zoom + e.deltaY * 0.002));
        this._requestRender();
      }, { passive: false });
      this._canvas.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowLeft') this._yaw -= 0.15;
        else if (e.key === 'ArrowRight') this._yaw += 0.15;
        else if (e.key === 'ArrowUp') this._pitch = Math.min(1.3, this._pitch + 0.12);
        else if (e.key === 'ArrowDown') this._pitch = Math.max(-1.3, this._pitch - 0.12);
        else if (e.key === '+' || e.key === '=') this._zoom = Math.max(1.3, this._zoom - 0.25);
        else if (e.key === '-') this._zoom = Math.min(6.0, this._zoom + 0.25);
        else return;
        e.preventDefault();
        this._requestRender();
      });
    }
  }
  customElements.define('vs-3d-viewer', Vs3dViewer);
})();
"#;
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/javascript; charset=utf-8"),
        );
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("public, max-age=3600"));
        headers.insert(
            CONTENT_SECURITY_POLICY,
            csp_header_value(&st.cfg.frame_ancestors),
        );
        (StatusCode::OK, headers, VIEWER_JS)
    }

    /// Build the hardened async Tokio/Axum router for multi-SKU 3D pixel streaming.
    pub fn build_3d_router(state: App3dState) -> Router {
        let mut router = Router::new()
            .route("/healthz", get(handle_health))
            .route("/v1/models", get(handle_list_models))
            .route("/v1/models/{asset_id}/poster", get(handle_poster))
            .route(
                "/v1/models/{asset_id}/turntable/{angle_idx}",
                get(handle_turntable),
            )
            .route(
                "/v1/models/{asset_id}/session",
                post(handle_session_init).layer(DefaultBodyLimit::max(16 * 1024)),
            )
            .route(
                "/v1/models/{asset_id}/frame",
                post(handle_frame).layer(DefaultBodyLimit::max(16 * 1024)),
            )
            .route(
                "/v1/forensics/trace",
                post(handle_forensics_trace).layer(DefaultBodyLimit::max(4 * 1024 * 1024)),
            )
            .route("/v1/embed/vs-3d-viewer.js", get(handle_embed_js))
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                Duration::from_secs(20),
            ));

        if !state.cfg.allowed_origins.is_empty() {
            let vals: Vec<HeaderValue> = state
                .cfg
                .allowed_origins
                .iter()
                .filter_map(|o| HeaderValue::from_str(o).ok())
                .collect();
            let cors = CorsLayer::new()
                .allow_origin(AllowOrigin::list(vals))
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([AUTHORIZATION, CONTENT_TYPE]);
            router = router.layer(cors);
        } else if state.cfg.allow_any_origin {
            let cors = CorsLayer::new()
                .allow_origin(AllowOrigin::any())
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([AUTHORIZATION, CONTENT_TYPE]);
            router = router.layer(cors);
        }

        router.with_state(state)
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    mod tests {
        use super::*;
        use std::net::Ipv4Addr;
        use std::path::Path as StdPath;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use vs_crypto::{aead_open, hkdf_sha256_32, mint_session_grant};

        #[test]
        fn trusted_proxy_cidr_resolution_prevents_xff_spoofing() {
            let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap(), "172.16.0.0/12".parse().unwrap()];
            let peer = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
            let resolved = resolve_client_ip(
                peer,
                Some("1.2.3.4, 203.0.113.42, 172.18.0.5"),
                &trusted,
            );
            assert_eq!(resolved, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)));

            let untrusted_peer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
            let resolved2 = resolve_client_ip(untrusted_peer, Some("1.2.3.4"), &trusted);
            assert_eq!(resolved2, untrusted_peer);

            // Loop 4 HIGH-3 regression: malformed XFF hop fails closed to peer instead of skipping to attacker IP
            let resolved_bad = resolve_client_ip(peer, Some("198.51.100.42, unknown"), &trusted);
            assert_eq!(resolved_bad, peer);
        }

        #[test]
        fn csp_sanitization_blocks_semicolon_injection() {
            let v = csp_header_value("'self'; report-uri https://evil.test");
            let s = v.to_str().unwrap();
            assert!(!s.contains("report-uri"));
            assert!(s.contains("default-src 'self'"));
            assert!(s.contains("frame-ancestors "));
        }

        #[tokio::test]
        async fn survives_200_idle_keepalive_sockets_without_starvation() {
            let cfg = Server3dConfig::new(SecretKey32::generate().unwrap());
            let app = build_3d_router(App3dState::new(AssetCatalog::new(), cfg));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let srv = tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });

            let mut idle = Vec::with_capacity(200);
            for _ in 0..200 {
                idle.push(tokio::net::TcpStream::connect(addr).await.unwrap());
            }

            let mut probe = tokio::net::TcpStream::connect(addr).await.unwrap();
            probe
                .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut resp = String::new();
            probe.read_to_string(&mut resp).await.unwrap();
            assert!(resp.contains("200 OK"), "unexpected response: {resp}");
            assert!(resp.contains("\"ok\":true"));

            drop(idle);
            srv.abort();
        }

        #[tokio::test]
        async fn end_to_end_multi_sku_auth_session_frame_decrypt_and_scoped_trace() {
            let fixture = StdPath::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../vibeslayer-native-core/tests/fixtures/sample_mesh.glb");
            if !fixture.exists() {
                return;
            }
            let catalog = AssetCatalog::new();
            catalog.register_file("hero-sku", &fixture);

            let wm_key = SecretKey32::generate().unwrap();
            let auth_key = SecretKey32::generate().unwrap();
            let mut cfg = Server3dConfig::new(wm_key);
            cfg.auth_signing_key = Some(auth_key.clone());
            let state = App3dState::new(catalog, cfg);
            let app = build_3d_router(state);

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let srv = tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });

            let rng = ring::rand::SystemRandom::new();
            let c_priv =
                ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::ECDH_P256, &rng)
                    .unwrap();
            let c_pub = c_priv.compute_public_key().unwrap();

            let now = now_unix_secs();
            let stream_tok = mint_session_grant(
                &auth_key,
                &SessionGrantClaims {
                    sub: "buyer-verified".into(),
                    aud: "https://shop.example".into(),
                    asset_id: "hero-sku".into(),
                    jti: "jti-1".into(),
                    iat: now,
                    exp: now + 300,
                    scopes: vec!["stream:3d".into()],
                },
            )
            .unwrap();

            let init_body = serde_json::to_vec(&serde_json::json!({
                "client_pub_b64": B64.encode(c_pub.as_ref()),
                "buyer_label": "attacker-trying-to-spoof"
            }))
            .unwrap();
            let init_raw = http_post_json(
                addr,
                "/v1/models/hero-sku/session",
                &init_body,
                Some(&stream_tok),
            )
            .await;
            let init_json: serde_json::Value = serde_json::from_slice(&init_raw).unwrap();
            let sid = init_json["session_id"].as_str().unwrap().to_string();
            let srv_pub_bytes = B64.decode(init_json["server_pub_b64"].as_str().unwrap()).unwrap();
            let salt = B64.decode(init_json["hkdf_salt_b64"].as_str().unwrap()).unwrap();
            let info = init_json["hkdf_info"].as_str().unwrap().as_bytes();
            let expected_bid = init_json["buyer_id_hex"].as_str().unwrap().to_string();

            // Client binds `info || client_pub || server_pub` matching LOW-05!
            let mut bound_info = Vec::from(info);
            bound_info.extend_from_slice(c_pub.as_ref());
            bound_info.extend_from_slice(&srv_pub_bytes);
            let srv_unparsed = ring::agreement::UnparsedPublicKey::new(
                &ring::agreement::ECDH_P256,
                &srv_pub_bytes,
            );
            let sess_key = ring::agreement::agree_ephemeral(c_priv, &srv_unparsed, |ss| {
                hkdf_sha256_32(ss, &salt, &bound_info)
            })
            .unwrap()
            .unwrap();

            // Request encrypted frame
            let f_body = serde_json::to_vec(&serde_json::json!({
                "session_id": sid, "yaw": 0.6, "pitch": 0.25, "zoom": 2.7, "width": 512, "height": 384
            }))
            .unwrap();
            let f_raw = http_post_json(addr, "/v1/models/hero-sku/frame", &f_body, None).await;
            let f_json: serde_json::Value = serde_json::from_slice(&f_raw).unwrap();
            let nonce: [u8; 12] = B64
                .decode(f_json["nonce_b64"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let ct = B64.decode(f_json["ct_b64"].as_str().unwrap()).unwrap();
            let aad = f_json["aad"].as_str().unwrap().as_bytes();
            let jpg = aead_open(AeadAlg::Aes256Gcm, sess_key.as_bytes(), &nonce, aad, &ct).unwrap();

            // Crop 20% off-grid, re-encode PNG
            let img = image::load_from_memory(&jpg).unwrap().to_rgb8();
            let cropped = image::imageops::crop_imm(&img, 41, 33, 420, 310).to_image();
            let mut png_bytes = Vec::new();
            cropped
                .write_to(&mut Cursor::new(&mut png_bytes), image::ImageFormat::Png)
                .unwrap();

            // Viewer token (`stream:3d` only) MUST be rejected with 403 on `/v1/forensics/trace` (CRIT-03)!
            let (status_viewer, _) =
                http_post_raw(addr, "/v1/forensics/trace", &png_bytes, Some(&stream_tok)).await;
            assert_eq!(status_viewer, 403);

            // Admin token (`forensics:trace`) succeeds and extracts exact buyer_id!
            let trace_tok = mint_session_grant(
                &auth_key,
                &SessionGrantClaims {
                    sub: "forensics-admin".into(),
                    aud: "https://admin.example".into(),
                    asset_id: String::new(),
                    jti: "jti-trace-1".into(),
                    iat: now,
                    exp: now + 300,
                    scopes: vec!["forensics:trace".into()],
                },
            )
            .unwrap();
            let (status_admin, trace_raw) =
                http_post_raw(addr, "/v1/forensics/trace", &png_bytes, Some(&trace_tok)).await;
            assert_eq!(status_admin, 200);
            let trace_json: serde_json::Value = serde_json::from_slice(&trace_raw).unwrap();
            assert_eq!(trace_json["detected"].as_bool(), Some(true));
            assert_eq!(
                trace_json["buyer_id_hex"].as_str(),
                Some(expected_bid.as_str())
            );

            srv.abort();
        }

        async fn http_post_json(
            addr: std::net::SocketAddr,
            path: &str,
            body: &[u8],
            bearer: Option<&str>,
        ) -> Vec<u8> {
            let (status, resp_body) = http_post_raw(addr, path, body, bearer).await;
            assert_eq!(status, 200, "POST {path} returned {status}");
            resp_body
        }

        async fn http_post_raw(
            addr: std::net::SocketAddr,
            path: &str,
            body: &[u8],
            bearer: Option<&str>,
        ) -> (u16, Vec<u8>) {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            let auth_line = match bearer {
                Some(t) => format!("Authorization: Bearer {t}\r\n"),
                None => String::new(),
            };
            let req = format!(
                "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n{auth_line}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            s.write_all(req.as_bytes()).await.unwrap();
            s.write_all(body).await.unwrap();
            let mut resp = Vec::new();
            s.read_to_end(&mut resp).await.unwrap();
            let hdr_end = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
            let hdr_str = String::from_utf8_lossy(&resp[..hdr_end]);
            let status: u16 = hdr_str
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
                .parse()
                .unwrap();
            (status, resp[hdr_end + 4..].to_vec())
        }
    }
}

#[cfg(feature = "3d")]
pub use server_3d::{build_3d_router, resolve_client_ip, App3dState, Server3dConfig};
