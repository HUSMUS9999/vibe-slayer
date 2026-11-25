#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Args, Parser, Subcommand, ValueEnum};
use image::{ImageReader, Limits};
use ipnet::IpNet;
use vibeslayer_core::{pack_vspk2, scan, unseal_vspk2, VERSION};
use vs_3d::AssetCatalog;
use vs_crypto::{
    mint_session_grant, now_unix_secs, random_bytes, sha256, verify_session_grant, AeadAlg,
    SecretKey32, SessionGrantClaims,
};
use vs_nl::{translate as translate_nl, NaturalPlan};
use vs_server::web::{build_web_router, GuardMode, WebBundle, WebServerState};
use vs_server::{build_3d_router, App3dState, Server3dConfig};
use vs_vault::{
    seal_vspk3_v1, seal_vspk3_v2_stream, unseal_vspk3_v1, unseal_vspk3_v2_stream,
    verify_vspk3_v1_header_commitment, verify_vspk3_v2_header_commitment, Vspk3V2RandomAccess,
    VSPK3_V1_PAD_QUANTUM, VSPK3_V1_PREFIX_LEN, VSPK3_V2_CHUNK_PLAIN, VSPK3_V2_PREFIX_LEN,
};
use vs_watermark::decode_frame_rgb_blind;
use zeroize::Zeroizing;

/// Max container size permitted for legacy in-memory VSPK3 v1 fallback (prevents OOM on huge v2 files).
const MAX_V1_FALLBACK_BYTES: u64 = 256 * 1024 * 1024;
const MAX_WEB_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_WEB_BUNDLE_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "vibe-slayer",
    version = VERSION,
    about = "Modular audited 3D pixel-streaming shield, VSPK3 v2 STREAM vault, blind forensic watermarker, and hardened web bundler"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Secure reusable key input flags (`--key-file`, `--key-stdin`, `VIBESLAYER_KEY` env fallback, or `--key`).
#[derive(Args, Debug, Clone)]
struct KeyArgs {
    /// 64-hex-char 32-byte key (prefer --key-file, --key-stdin, or VIBESLAYER_KEY env to avoid argv exposure)
    #[arg(long, conflicts_with_all = ["key_file", "key_stdin"])]
    key: Option<String>,
    /// Read 64-hex-char 32-byte key from a 0600 file
    #[arg(long, conflicts_with_all = ["key", "key_stdin"])]
    key_file: Option<PathBuf>,
    /// Read 64-hex-char 32-byte key from standard input
    #[arg(long, default_value_t = false, conflicts_with_all = ["key", "key_file"])]
    key_stdin: bool,
    /// Allow reading --key-file even if group/other permissions are set on Unix
    #[arg(long, default_value_t = false)]
    allow_insecure_key_file: bool,
}

impl KeyArgs {
    fn resolve_required(&self) -> Result<SecretKey32, String> {
        self.resolve_optional()?
            .ok_or_else(|| "missing key: pass --key-file <PATH>, --key-stdin, or set VIBESLAYER_KEY".into())
    }

    fn resolve_optional(&self) -> Result<Option<SecretKey32>, String> {
        if let Some(ref path) = self.key_file {
            return read_key_file(path, self.allow_insecure_key_file).map(Some);
        }
        if self.key_stdin {
            let mut line = Zeroizing::new(String::new());
            io::stdin()
                .take(256)
                .read_to_string(&mut line)
                .map_err(|e| format!("read key from stdin failed: {e}"))?;
            return SecretKey32::from_hex(line.trim())
                .map(Some)
                .map_err(|_| "invalid stdin key: expected 64 hex chars (32 bytes)".into());
        }
        if let Some(ref raw) = self.key {
            let zeroed = Zeroizing::new(raw.clone());
            return SecretKey32::from_hex(zeroed.trim())
                .map(Some)
                .map_err(|_| "invalid key: expected 64 hex chars (32 bytes)".into());
        }
        // Fallback to VIBESLAYER_KEY env ONLY when no explicit CLI key flag was passed (Loop 3 LOW-8)
        if let Ok(env_val) = std::env::var("VIBESLAYER_KEY") {
            let zeroed = Zeroizing::new(env_val);
            if !zeroed.trim().is_empty() {
                return SecretKey32::from_hex(zeroed.trim())
                    .map(Some)
                    .map_err(|_| "invalid VIBESLAYER_KEY env: expected 64 hex chars (32 bytes)".into());
            }
        }
        Ok(None)
    }
}

fn read_key_file(path: &Path, allow_insecure: bool) -> Result<SecretKey32, String> {
    // Open once and validate permissions on the open fd + bounded 256-byte read (zero TOCTOU/OOM — Loop 3 LOW-9)
    let file = File::open(path).map_err(|e| format!("open key file failed: {e}"))?;
    #[cfg(unix)]
    if !allow_insecure {
        let meta = file
            .metadata()
            .map_err(|e| format!("fstat key file failed: {e}"))?;
        let mode = meta.permissions().mode() & 0o777;
        if (mode & 0o077) != 0 {
            return Err(format!(
                "refusing insecure key file {} (mode {:04o}; run `chmod 600` or pass --allow-insecure-key-file)",
                path.display(),
                mode
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = allow_insecure;

    let mut raw = Zeroizing::new(String::new());
    file.take(256)
        .read_to_string(&mut raw)
        .map_err(|e| format!("read key file failed: {e}"))?;
    SecretKey32::from_hex(raw.trim())
        .map_err(|_| "invalid key file contents: expected 64 hex chars (32 bytes)".into())
}

fn write_key_file_0600(path: &Path, key: &SecretKey32) -> Result<(), String> {
    let hex_str = Zeroizing::new(format!("{}\n", hex::encode(key.as_bytes())));
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts
        .open(path)
        .map_err(|e| format!("create key file {} failed: {e}", path.display()))?;
    f.write_all(hex_str.as_bytes())
        .map_err(|e| format!("write key file failed: {e}"))?;
    f.sync_all()
        .map_err(|e| format!("sync key file failed: {e}"))?;
    Ok(())
}

#[derive(Copy, Clone, ValueEnum)]
enum CipherArg {
    AesGcm,
    Chacha20,
}

impl From<CipherArg> for AeadAlg {
    fn from(c: CipherArg) -> Self {
        match c {
            CipherArg::AesGcm => AeadAlg::Aes256Gcm,
            CipherArg::Chacha20 => AeadAlg::ChaCha20Poly1305,
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum GuardModeArg {
    Off,
    Observe,
}

#[derive(Subcommand)]
enum Commands {
    /// Print version metadata as JSON
    Version,

    /// Run built-in cryptographic & watermark self-verification demo
    Demo,

    /// Serve a single .glb model or a directory of .glb models via zero-geometry pixel streaming
    #[command(name = "serve-3d", alias = "serve3d")]
    Serve3d {
        /// Path to a .glb file or directory containing .glb models
        path: PathBuf,
        /// Listen address (e.g. 127.0.0.1:8090)
        #[arg(long, alias = "addr", default_value = "127.0.0.1:8090")]
        bind: SocketAddr,
        /// Watermark master key (generated ephemerally if omitted)
        #[command(flatten)]
        key_args: KeyArgs,
        /// Write newly generated watermark key to a 0600 file
        #[arg(long)]
        key_out: Option<PathBuf>,
        /// Separate HMAC signing key file to require scoped bearer grants (`stream:3d` / `forensics:trace`)
        #[arg(long)]
        auth_key_file: Option<PathBuf>,
        /// Allow unauthenticated `/v1/forensics/trace` calls (local dev/testing ONLY)
        #[arg(long, default_value_t = false)]
        allow_unauthenticated_trace: bool,
        /// Allowed CORS origins (repeatable, e.g. --allow-origin https://shop.example.com)
        #[arg(long)]
        allow_origin: Vec<String>,
        /// Explicit dev opt-in for wildcard CORS
        #[arg(long, default_value_t = false)]
        allow_any_origin: bool,
        /// CSP frame-ancestors policy (e.g. "'self' https://shop.example.com")
        #[arg(long, default_value = "'self'")]
        frame_ancestors: String,
        /// Maximum fraction of 192 spherical view bins per session/subject (anti-3DGS/VGGT)
        #[arg(long, default_value_t = 0.35)]
        max_sphere_coverage: f32,
        /// Disable smooth harmonic anti-3DGS intrinsics perturbation
        #[arg(long, default_value_t = false)]
        disable_perturbation: bool,
        /// Trusted reverse-proxy CIDR ranges (repeatable, e.g. --trust-proxy 10.0.0.0/8)
        #[arg(long)]
        trust_proxy: Vec<IpNet>,
        /// JPEG frame quality (60..95)
        #[arg(long, default_value_t = 84)]
        jpeg_quality: u8,
    },

    /// Blindly extract and verify the 64-bit forensic buyer_id from a leaked screenshot (survives crop, scale, JPEG)
    #[command(name = "trace-3d", alias = "trace3d")]
    Trace3d {
        /// Path to leaked PNG/JPEG/WebP screenshot
        #[arg(long = "image", short = 'i', value_name = "IMAGE", conflicts_with = "image_pos")]
        image_flag: Option<PathBuf>,
        /// Positional image path (if --image not passed)
        image_pos: Option<PathBuf>,
        #[command(flatten)]
        key_args: KeyArgs,
    },

    /// Streaming VSPK3 v2 / legacy v1 authenticated encryption vault
    Vault {
        #[command(subcommand)]
        action: VaultCommands,
    },

    /// Bundle a static web / SPA directory into an authenticated `.vsweb` v2 archive
    Website {
        /// Input directory containing HTML/JS/CSS assets
        dir: PathBuf,
        /// Output `.vsweb` bundle path
        #[arg(short, long)]
        out: PathBuf,
        #[command(flatten)]
        key_args: KeyArgs,
        /// Write newly generated bundle master key to a 0600 file
        #[arg(long)]
        key_out: Option<PathBuf>,
        /// Site display identifier (also bound as token audience `aud`)
        #[arg(long, default_value = "vibe-slayer-app")]
        site_id: String,
    },

    /// Serve an authenticated `.vsweb` v2 bundle over async HTTP/1.1+HTTP/2 with ephemeral lease handshakes
    Serve {
        /// Path to `.vsweb` v2 bundle
        bundle: PathBuf,
        /// Listen address
        #[arg(long, alias = "addr", default_value = "127.0.0.1:8080")]
        bind: SocketAddr,
        #[command(flatten)]
        key_args: KeyArgs,
        /// Signing key file required for `web:lease` bearer grants on `/__vibeslayer/lease`
        #[arg(long)]
        auth_key_file: Option<PathBuf>,
        /// Explicit opt-in to serve `/__vibeslayer/lease` anonymously for public sites
        #[arg(long, default_value_t = false)]
        allow_anonymous_public_site: bool,
        /// Disable SPA deep-link fallback to bootstrap shell (return 404 on unknown routes)
        #[arg(long, default_value_t = false)]
        no_spa_fallback: bool,
        /// Non-blocking guard mode (off | observe)
        #[arg(long, value_enum, default_value_t = GuardModeArg::Observe)]
        mode: GuardModeArg,
    },

    /// Mint or verify IP-agnostic HMAC-SHA256 session grant tokens
    Token {
        #[command(subcommand)]
        action: TokenCommands,
    },

    /// Scan a file or directory for accidental hardcoded secrets and private keys
    Scan {
        /// File or directory to audit
        path: PathBuf,
    },

    /// Preview the exact CLI command for a plain-English request without executing it
    Explain {
        #[arg(required = true)]
        sentence: Vec<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Translate plain English into a Vibe-Slayer command (pass --dry-run to preview only)
    Ask {
        #[arg(required = true)]
        sentence: Vec<String>,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// [Compat] Seal a file into legacy VSPK2 container (audited ring ChaCha20-Poly1305)
    Pack {
        #[command(flatten)]
        key_args: KeyArgs,
        #[arg(long, default_value = "default")]
        domain: String,
        #[arg(long)]
        asset_id: String,
        #[arg(long, default_value = "")]
        context: String,
        #[arg(long = "in")]
        in_path: PathBuf,
        #[arg(long = "out")]
        out_path: PathBuf,
    },

    /// [Compat] Unseal a legacy VSPK2 container
    Unseal {
        #[command(flatten)]
        key_args: KeyArgs,
        #[arg(long, default_value = "default")]
        domain: String,
        #[arg(long)]
        asset_id: Option<String>,
        #[arg(long, default_value = "")]
        context: String,
        #[arg(long = "in")]
        in_path: PathBuf,
        #[arg(long = "out")]
        out_path: PathBuf,
    },

    /// [Compat] Seal a file into VSPK3 (defaults to v1 for C/Go/Py interop; pass --v2 for 64-bit STREAM)
    PackV3 {
        #[command(flatten)]
        key_args: KeyArgs,
        #[arg(long, default_value = "default")]
        domain: String,
        #[arg(long)]
        asset_id: String,
        #[arg(long, default_value = "")]
        context: String,
        #[arg(long = "in")]
        in_path: PathBuf,
        #[arg(long = "out")]
        out_path: PathBuf,
        #[arg(long, default_value_t = false)]
        v2: bool,
    },

    /// [Compat] Unseal VSPK3 v1 or VSPK3 v2 STREAM (auto-detected)
    UnsealV3 {
        #[command(flatten)]
        key_args: KeyArgs,
        #[arg(long, default_value = "default")]
        domain: String,
        #[arg(long)]
        asset_id: String,
        #[arg(long, default_value = "")]
        context: String,
        #[arg(long = "in")]
        in_path: PathBuf,
        #[arg(long = "out")]
        out_path: PathBuf,
    },
}

#[derive(Subcommand)]
enum VaultCommands {
    /// Seal any file (multi-GB safe, constant ~134 KiB RAM) into VSPK3 v2 STREAM (or legacy --v1)
    Seal {
        #[arg(conflicts_with = "in_path")]
        in_pos: Option<PathBuf>,
        #[arg(long = "in", conflicts_with = "in_pos")]
        in_path: Option<PathBuf>,
        #[arg(short = 'o', long = "out")]
        out_path: PathBuf,
        #[command(flatten)]
        key_args: KeyArgs,
        #[arg(long, default_value = "default")]
        domain: String,
        #[arg(long, default_value = "asset")]
        asset_id: String,
        #[arg(long, default_value = "prod")]
        context: String,
        #[arg(long, value_enum, default_value_t = CipherArg::AesGcm)]
        cipher: CipherArg,
        #[arg(long, default_value_t = false)]
        v1: bool,
    },
    /// Unseal a VSPK3 v2 STREAM or legacy VSPK3 v1 file (auto-detected, atomic 0600 temp staging)
    Unseal {
        #[arg(conflicts_with = "in_path")]
        in_pos: Option<PathBuf>,
        #[arg(long = "in", conflicts_with = "in_pos")]
        in_path: Option<PathBuf>,
        #[arg(short = 'o', long = "out")]
        out_path: PathBuf,
        #[command(flatten)]
        key_args: KeyArgs,
        #[arg(long, default_value = "default")]
        domain: String,
        #[arg(long, default_value = "asset")]
        asset_id: String,
        #[arg(long, default_value = "prod")]
        context: String,
        #[arg(long, value_enum)]
        cipher: Option<CipherArg>,
    },
    /// Verify header & terminal chunk commitment and inspect layout of a VSPK3 v2 STREAM vault
    Inspect {
        #[arg(conflicts_with = "in_path")]
        in_pos: Option<PathBuf>,
        #[arg(long = "in", conflicts_with = "in_pos")]
        in_path: Option<PathBuf>,
        #[command(flatten)]
        key_args: KeyArgs,
        #[arg(long, default_value = "default")]
        domain: String,
        #[arg(long, default_value = "asset")]
        asset_id: String,
        #[arg(long, default_value = "prod")]
        context: String,
        #[arg(long, value_enum)]
        cipher: Option<CipherArg>,
    },
}

#[derive(Subcommand)]
enum TokenCommands {
    /// Mint a signed origin/asset/scope-bound session grant
    Mint {
        #[command(flatten)]
        key_args: KeyArgs,
        #[arg(long)]
        subject: String,
        #[arg(long, default_value = "vibe-slayer-app")]
        origin: String,
        #[arg(long, default_value = "")]
        asset_id: String,
        /// Repeatable scopes (defaults to stream:3d; pass e.g. --scope forensics:trace or --scope web:lease)
        #[arg(long = "scope")]
        scopes: Vec<String>,
        #[arg(long, default_value_t = 900)]
        ttl: u64,
    },
    /// Verify a signed session grant
    Verify {
        #[command(flatten)]
        key_args: KeyArgs,
        #[arg(long)]
        token: String,
        #[arg(long)]
        origin: Option<String>,
        #[arg(long)]
        asset_id: Option<String>,
    },
}

fn guess_content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

fn collect_web_files(root: &Path) -> Result<Vec<(String, String, Vec<u8>)>, String> {
    let root_meta = fs::symlink_metadata(root).map_err(|e| format!("stat dir failed: {e}"))?;
    if !root_meta.is_dir() {
        return Err(format!("not a directory: {}", root.display()));
    }
    let mut out = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = fs::read_dir(&dir).map_err(|e| format!("read_dir failed: {e}"))?;
        for entry in rd.flatten() {
            // MED-15 fix: never follow symlinks (prevents cycles & root-escape reads like /etc/passwd)
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            let p = entry.path();
            if ft.is_dir() {
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    if !name.starts_with('.') && name != "node_modules" {
                        stack.push(p);
                    }
                }
            } else if ft.is_file() {
                if out.len() >= 4096 {
                    return Err("web bundle exceeds 4096 file-count cap".into());
                }
                let file =
                    File::open(&p).map_err(|e| format!("open {} failed: {e}", p.display()))?;
                let meta = file
                    .metadata()
                    .map_err(|e| format!("fstat {} failed: {e}", p.display()))?;
                if !meta.is_file() {
                    continue;
                }
                if meta.len() > MAX_WEB_FILE_BYTES {
                    return Err(format!(
                        "file {} exceeds 16 MiB web bundle per-file cap",
                        p.display()
                    ));
                }
                let mut bytes = Vec::with_capacity((meta.len() as usize).min(1024 * 1024));
                file.take(MAX_WEB_FILE_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|e| format!("read {} failed: {e}", p.display()))?;
                if (bytes.len() as u64) > MAX_WEB_FILE_BYTES {
                    return Err(format!(
                        "file {} exceeds 16 MiB web bundle per-file cap",
                        p.display()
                    ));
                }
                total_bytes = total_bytes.saturating_add(bytes.len() as u64);
                if total_bytes > MAX_WEB_BUNDLE_BYTES {
                    return Err("total web bundle exceeds 128 MiB cap".into());
                }
                let rel = p
                    .strip_prefix(root)
                    .map_err(|e| format!("strip_prefix failed: {e}"))?
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, guess_content_type(&p).to_string(), bytes));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// RAII guard that guarantees sibling temporary files are deleted on ANY error path (Loop 3 MED-12).
struct TempFileGuard {
    path: Option<PathBuf>,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn persist(mut self, target: &Path) -> Result<(), String> {
        if let Some(ref p) = self.path {
            fs::rename(p, target).map_err(|e| format!("atomic rename failed: {e}"))?;
            self.path = None;
        }
        Ok(())
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(ref p) = self.path {
            let _ = fs::remove_file(p);
        }
    }
}

fn create_unique_sibling_temp(out_path: &Path) -> Result<(TempFileGuard, File), String> {
    let parent = out_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let stem = out_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("out");
    let pid = std::process::id();
    for _ in 0..8 {
        let rand8 = random_bytes::<8>().map_err(|e| format!("rng failed: {e}"))?;
        let candidate = parent.join(format!(".{stem}.{pid}.{}.vstmp", hex::encode(rand8)));
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        match opts.open(&candidate) {
            Ok(f) => return Ok((TempFileGuard::new(candidate), f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("create temp file failed: {e}")),
        }
    }
    Err("unable to allocate unique temp file".into())
}

#[allow(clippy::too_many_arguments)]
fn vault_seal_cmd(
    in_path: &Path,
    out_path: &Path,
    key: &SecretKey32,
    domain: &str,
    asset_id: &str,
    context: &str,
    alg: AeadAlg,
    legacy_v1: bool,
) -> Result<serde_json::Value, String> {
    if legacy_v1 {
        let plain = fs::read(in_path).map_err(|e| format!("read input failed: {e}"))?;
        let sealed =
            seal_vspk3_v1(key, domain, asset_id, context, &plain).map_err(|e| e.to_string())?;
        fs::write(out_path, &sealed).map_err(|e| format!("write output failed: {e}"))?;
        return Ok(serde_json::json!({
            "ok": true,
            "format": "vspk3-v1",
            "inputBytes": plain.len(),
            "outputBytes": sealed.len(),
            "sha256": hex::encode(sha256(&sealed)),
        }));
    }
    let input = File::open(in_path).map_err(|e| format!("open input failed: {e}"))?;
    let (tmp_guard, output) = create_unique_sibling_temp(out_path)?;
    let mut writer = BufWriter::new(output);
    let written = seal_vspk3_v2_stream(
        key,
        alg,
        domain,
        asset_id,
        context,
        BufReader::new(input),
        &mut writer,
    )
    .map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| format!("flush failed: {e}"))?;
    let inner = writer
        .into_inner()
        .map_err(|e| format!("flush inner failed: {e}"))?;
    inner.sync_all().map_err(|e| format!("sync failed: {e}"))?;
    drop(inner);
    tmp_guard.persist(out_path)?;
    Ok(serde_json::json!({
        "ok": true,
        "format": "vspk3-v2-stream",
        "cipher": format!("{alg:?}"),
        "chunkSize": VSPK3_V2_CHUNK_PLAIN,
        "outputBytes": written,
    }))
}

fn try_unseal_v2_to_temp(
    in_path: &Path,
    out_path: &Path,
    key: &SecretKey32,
    alg: AeadAlg,
    domain: &str,
    asset_id: &str,
    context: &str,
) -> Result<u64, String> {
    // CRIT-11 fix: verify 64-byte header commitment BEFORE creating any temp file!
    let mut prefix = [0u8; VSPK3_V2_PREFIX_LEN];
    {
        let mut f = File::open(in_path).map_err(|e| format!("open input failed: {e}"))?;
        f.read_exact(&mut prefix)
            .map_err(|_| "vault authentication failed".to_string())?;
    }
    verify_vspk3_v2_header_commitment(key, alg, domain, asset_id, context, &prefix)
        .map_err(|e| e.to_string())?;

    let input = File::open(in_path).map_err(|e| format!("open input failed: {e}"))?;
    let (tmp_guard, output) = create_unique_sibling_temp(out_path)?;
    let mut writer = BufWriter::new(output);
    let plain_bytes = unseal_vspk3_v2_stream(
        key,
        alg,
        domain,
        asset_id,
        context,
        BufReader::new(input),
        &mut writer,
    )
    .map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| format!("flush failed: {e}"))?;
    let inner = writer
        .into_inner()
        .map_err(|e| format!("flush inner failed: {e}"))?;
    inner.sync_all().map_err(|e| format!("sync failed: {e}"))?;
    drop(inner);
    tmp_guard.persist(out_path)?;
    Ok(plain_bytes)
}

fn vault_unseal_cmd(
    in_path: &Path,
    out_path: &Path,
    key: &SecretKey32,
    domain: &str,
    asset_id: &str,
    context: &str,
    cipher_hint: Option<AeadAlg>,
) -> Result<serde_json::Value, String> {
    let candidates: Vec<AeadAlg> = match cipher_hint {
        Some(a) => vec![a],
        None => vec![AeadAlg::Aes256Gcm, AeadAlg::ChaCha20Poly1305],
    };

    for alg in candidates {
        if let Ok(plain_bytes) =
            try_unseal_v2_to_temp(in_path, out_path, key, alg, domain, asset_id, context)
        {
            return Ok(serde_json::json!({
                "ok": true,
                "format": "vspk3-v2-stream",
                "cipher": format!("{alg:?}"),
                "plainBytes": plain_bytes,
            }));
        }
    }

    // CRIT-10 fix: guard legacy v1 fallback with size bounds + O(1) prefix92 CMT-4 check before fs::read!
    if cipher_hint.is_none() {
        let len = fs::metadata(in_path)
            .map_err(|e| format!("stat input failed: {e}"))?
            .len();
        let min_v1 = (VSPK3_V1_PREFIX_LEN + VSPK3_V1_PAD_QUANTUM) as u64;
        if len >= min_v1
            && len <= MAX_V1_FALLBACK_BYTES
            && (len - VSPK3_V1_PREFIX_LEN as u64).is_multiple_of(VSPK3_V1_PAD_QUANTUM as u64)
        {
            let mut prefix92 = [0u8; VSPK3_V1_PREFIX_LEN];
            let mut f = File::open(in_path).map_err(|e| format!("open input failed: {e}"))?;
            if f.read_exact(&mut prefix92).is_ok()
                && verify_vspk3_v1_header_commitment(key, domain, asset_id, context, &prefix92)
                    .is_ok()
            {
                let blob = fs::read(in_path).map_err(|e| format!("read input failed: {e}"))?;
                if let Ok(plain) = unseal_vspk3_v1(key, domain, asset_id, context, &blob) {
                    let (tmp_guard, mut out_f) = create_unique_sibling_temp(out_path)?;
                    out_f
                        .write_all(&plain)
                        .map_err(|e| format!("write output failed: {e}"))?;
                    out_f
                        .sync_all()
                        .map_err(|e| format!("sync output failed: {e}"))?;
                    drop(out_f);
                    tmp_guard.persist(out_path)?;
                    return Ok(serde_json::json!({
                        "ok": true,
                        "format": "vspk3-v1",
                        "plainBytes": plain.len(),
                    }));
                }
            }
        }
    }

    Err("vault authentication failed".into())
}

fn format_plan_human(plan: &NaturalPlan, dry_run: bool) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "Intent : {} ({})\n",
        plan.intent,
        if dry_run { "preview only" } else { "executing" }
    ));
    s.push_str(&format!("Goal   : {}\n", plan.goal));
    s.push_str(&format!("Command: {}\n", plan.display_command()));
    for r in &plan.reasons {
        s.push_str(&format!("  - {r}\n"));
    }
    if let Some(next) = &plan.next_command {
        s.push_str(&format!("Next   : {next}\n"));
    }
    s
}

async fn run_async(cli: Cli) -> Result<(), (u8, String)> {
    match cli.command {
        Commands::Version => {
            println!(
                "{}",
                serde_json::json!({
                    "version": VERSION,
                    "crates": ["vs-crypto", "vs-vault", "vs-watermark", "vs-3d", "vs-server", "vs-nl"],
                    "unsafe_code": "forbid"
                })
            );
            Ok(())
        }
        Commands::Demo => {
            let key = SecretKey32::generate().map_err(|e| (1, e.to_string()))?;
            let payload = b"vibe-slayer v2 audited STREAM + blind watermark self-check";
            let sealed = vs_vault::seal_vspk3_v2(
                &key,
                AeadAlg::Aes256Gcm,
                "demo",
                "self-check",
                "local",
                payload,
            )
            .map_err(|e| (1, e.to_string()))?;
            let opened = vs_vault::unseal_vspk3_v2(
                &key,
                AeadAlg::Aes256Gcm,
                "demo",
                "self-check",
                "local",
                &sealed,
            )
            .map_err(|e| (1, e.to_string()))?;
            let vault_ok = opened == payload;
            let mut rgb = vec![120u8; 256 * 256 * 3];
            let buyer = 0x0123_4567_89AB_CDEFu64;
            let psnr = vs_watermark::embed_frame_rgb(
                &mut rgb,
                256,
                256,
                &key,
                buyer,
                vs_watermark::EmbedConfig::default(),
            )
            .map_err(|e| (1, e.to_string()))?;
            let wm = decode_frame_rgb_blind(&rgb, 256, 256, &key).map_err(|e| (1, e.to_string()))?;
            println!(
                "{}",
                serde_json::json!({
                    "ok": vault_ok && wm.verified_mac && wm.buyer_id == buyer,
                    "vaultStreamRoundtrip": vault_ok,
                    "watermarkPsnrDb": (psnr * 100.0).round() / 100.0,
                    "watermarkBuyerHex": format!("{:016x}", wm.buyer_id),
                    "watermarkVerifiedMac": wm.verified_mac,
                })
            );
            Ok(())
        }
        Commands::Serve3d {
            path,
            bind,
            key_args,
            key_out,
            auth_key_file,
            allow_unauthenticated_trace,
            allow_origin,
            allow_any_origin,
            frame_ancestors,
            max_sphere_coverage,
            disable_perturbation,
            trust_proxy,
            jpeg_quality,
        } => {
            let master = match key_args.resolve_optional().map_err(|e| (1, e))? {
                Some(k) => k,
                None => {
                    let gen = SecretKey32::generate().map_err(|e| (1, e.to_string()))?;
                    if let Some(ref ko) = key_out {
                        write_key_file_0600(ko, &gen).map_err(|e| (1, e))?;
                        eprintln!("[vibe-slayer] wrote 0600 watermark key to {}", ko.display());
                    } else {
                        eprintln!(
                            "[vibe-slayer] ephemeral watermark key (pass --key-out <FILE> to save securely)"
                        );
                    }
                    gen
                }
            };
            let auth_key = match auth_key_file {
                Some(ref p) => Some(
                    read_key_file(p, key_args.allow_insecure_key_file).map_err(|e| (1, e))?,
                ),
                None => None,
            };

            let catalog = AssetCatalog::new();
            let count = if path.is_dir() {
                catalog.register_dir(&path).map_err(|e| (1, e.to_string()))?
            } else {
                let id = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("model")
                    .to_string();
                catalog.register_file(id, path);
                1
            };
            let mut cfg = Server3dConfig::new(master);
            cfg.auth_signing_key = auth_key;
            cfg.allow_unauthenticated_trace = allow_unauthenticated_trace;
            cfg.allowed_origins = allow_origin;
            cfg.allow_any_origin = allow_any_origin;
            cfg.frame_ancestors = frame_ancestors;
            cfg.max_sphere_coverage = max_sphere_coverage.clamp(0.05, 1.0);
            cfg.anti_3dgs = !disable_perturbation;
            cfg.trusted_proxies = trust_proxy;
            cfg.jpeg_quality = jpeg_quality.clamp(60, 95);

            let state = App3dState::new(catalog, cfg);
            let app = build_3d_router(state);
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .map_err(|e| (1, format!("bind {bind} failed: {e}")))?;
            eprintln!(
                "[vibe-slayer] serving {count} 3D model(s) on http://{bind} (GET /v1/models, embed /v1/embed/vs-3d-viewer.js)"
            );
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .map_err(|e| (1, format!("server error: {e}")))?;
            Ok(())
        }
        Commands::Trace3d {
            image_flag,
            image_pos,
            key_args,
        } => {
            let image = image_flag
                .or(image_pos)
                .ok_or_else(|| (1, "specify image path (positional or --image)".to_string()))?;
            let wm_key = key_args.resolve_required().map_err(|e| (1, e))?;
            let mut reader = ImageReader::open(&image)
                .map_err(|e| (1, format!("open image failed: {e}")))?
                .with_guessed_format()
                .map_err(|e| (1, format!("detect format failed: {e}")))?;
            let mut limits = Limits::default();
            limits.max_image_width = Some(4096);
            limits.max_image_height = Some(4096);
            limits.max_alloc = Some(64 * 1024 * 1024);
            reader.limits(limits);
            let img = reader
                .decode()
                .map_err(|e| (1, format!("decode image failed: {e}")))?
                .to_rgb8();
            let w = img.width() as usize;
            let h = img.height() as usize;
            match decode_frame_rgb_blind(img.as_raw(), w, h, &wm_key) {
                Ok(wm) => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "ok": true,
                            "detected": true,
                            "buyer_id_hex": format!("{:016x}", wm.buyer_id),
                            "verified_mac": wm.verified_mac,
                            "sync_z_score": wm.sync_z_score,
                            "bit_confidence": wm.bit_confidence,
                            "detected_scale": wm.detected_scale,
                            "detected_offset": wm.detected_offset,
                        })
                    );
                    Ok(())
                }
                Err(e) => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "ok": false,
                            "detected": false,
                            "error": e.to_string()
                        })
                    );
                    Err((2, e.to_string()))
                }
            }
        }
        Commands::Vault { action } => match action {
            VaultCommands::Seal {
                in_pos,
                in_path,
                out_path,
                key_args,
                domain,
                asset_id,
                context,
                cipher,
                v1,
            } => {
                let src = in_path
                    .or(in_pos)
                    .ok_or_else(|| (1, "specify input file (positional or --in)".to_string()))?;
                let k = key_args.resolve_required().map_err(|e| (1, e))?;
                let res = vault_seal_cmd(
                    &src,
                    &out_path,
                    &k,
                    &domain,
                    &asset_id,
                    &context,
                    cipher.into(),
                    v1,
                )
                .map_err(|e| (1, e))?;
                println!("{res}");
                Ok(())
            }
            VaultCommands::Unseal {
                in_pos,
                in_path,
                out_path,
                key_args,
                domain,
                asset_id,
                context,
                cipher,
            } => {
                let src = in_path
                    .or(in_pos)
                    .ok_or_else(|| (1, "specify input vault file (positional or --in)".to_string()))?;
                let k = key_args.resolve_required().map_err(|e| (1, e))?;
                let res = vault_unseal_cmd(
                    &src,
                    &out_path,
                    &k,
                    &domain,
                    &asset_id,
                    &context,
                    cipher.map(Into::into),
                )
                .map_err(|e| (3, e))?;
                println!("{res}");
                Ok(())
            }
            VaultCommands::Inspect {
                in_pos,
                in_path,
                key_args,
                domain,
                asset_id,
                context,
                cipher,
            } => {
                let src = in_path
                    .or(in_pos)
                    .ok_or_else(|| (1, "specify input vault file (positional or --in)".to_string()))?;
                let k = key_args.resolve_required().map_err(|e| (1, e))?;
                let candidates: Vec<AeadAlg> = match cipher {
                    Some(c) => vec![c.into()],
                    None => vec![AeadAlg::Aes256Gcm, AeadAlg::ChaCha20Poly1305],
                };
                for alg in candidates {
                    let f = File::open(&src).map_err(|e| (1, format!("open failed: {e}")))?;
                    if let Ok(ra) = Vspk3V2RandomAccess::open(&k, alg, &domain, &asset_id, &context, f)
                    {
                        println!(
                            "{}",
                            serde_json::json!({
                                "ok": true,
                                "format": "vspk3-v2-stream",
                                "cipher": format!("{alg:?}"),
                                "chunkSize": VSPK3_V2_CHUNK_PLAIN,
                                "chunkCount": ra.chunk_count(),
                            })
                        );
                        return Ok(());
                    }
                }
                Err((3, "vault authentication failed".into()))
            }
        },
        Commands::Website {
            dir,
            out,
            key_args,
            key_out,
            site_id,
        } => {
            let master = match key_args.resolve_optional().map_err(|e| (1, e))? {
                Some(k) => k,
                None => {
                    let gen = SecretKey32::generate().map_err(|e| (1, e.to_string()))?;
                    if let Some(ref ko) = key_out {
                        write_key_file_0600(ko, &gen).map_err(|e| (1, e))?;
                        eprintln!("[vibe-slayer] wrote 0600 website master key to {}", ko.display());
                    } else {
                        return Err((
                            1,
                            "pass --key-file / VIBESLAYER_KEY or --key-out <FILE> to store generated key securely".into(),
                        ));
                    }
                    gen
                }
            };
            let files = collect_web_files(&dir).map_err(|e| (1, e))?;
            let count = files.len();
            let bundle = WebBundle::seal_files(&site_id, master, files)
                .map_err(|e| (1, format!("seal web bundle failed: {e}")))?;
            let bytes = bundle
                .to_bytes()
                .map_err(|e| (1, format!("serialize bundle failed: {e}")))?;
            fs::write(&out, &bytes).map_err(|e| (1, format!("write bundle failed: {e}")))?;
            println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "format": "vsweb-v2",
                    "siteId": site_id,
                    "files": count,
                    "outputBytes": bytes.len(),
                    "out": out.display().to_string(),
                })
            );
            Ok(())
        }
        Commands::Serve {
            bundle,
            bind,
            key_args,
            auth_key_file,
            allow_anonymous_public_site,
            no_spa_fallback,
            mode,
        } => {
            let master = key_args.resolve_required().map_err(|e| (1, e))?;
            let auth_key = match auth_key_file {
                Some(ref p) => Some(
                    read_key_file(p, key_args.allow_insecure_key_file).map_err(|e| (1, e))?,
                ),
                None => None,
            };
            if auth_key.is_none() && !allow_anonymous_public_site {
                return Err((
                    1,
                    "pass --auth-key-file <PATH> (recommended) or explicit --allow-anonymous-public-site".into(),
                ));
            }
            let raw = fs::read(&bundle).map_err(|e| (1, format!("read bundle failed: {e}")))?;
            let wb = WebBundle::from_bytes(master, &raw).map_err(|e| (3, e))?;
            let state = WebServerState::new(
                Arc::new(wb),
                auth_key,
                allow_anonymous_public_site,
                !no_spa_fallback,
                match mode {
                    GuardModeArg::Off => GuardMode::Off,
                    GuardModeArg::Observe => GuardMode::Observe,
                },
            );
            let app = build_web_router(state);
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .map_err(|e| (1, format!("bind {bind} failed: {e}")))?;
            eprintln!("[vibe-slayer] serving authenticated .vsweb v2 bundle on http://{bind}");
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .map_err(|e| (1, format!("server error: {e}")))?;
            Ok(())
        }
        Commands::Token { action } => match action {
            TokenCommands::Mint {
                key_args,
                subject,
                origin,
                asset_id,
                scopes,
                ttl,
            } => {
                let k = key_args.resolve_required().map_err(|e| (1, e))?;
                let now = now_unix_secs();
                let jti = hex::encode(random_bytes::<12>().map_err(|e| (1, e.to_string()))?);
                let eff_scopes = if scopes.is_empty() {
                    vec!["stream:3d".into()]
                } else {
                    scopes
                };
                let claims = SessionGrantClaims {
                    sub: subject,
                    aud: origin,
                    asset_id,
                    jti,
                    iat: now,
                    exp: now.saturating_add(ttl),
                    scopes: eff_scopes,
                };
                let tok = mint_session_grant(&k, &claims).map_err(|e| (1, e.to_string()))?;
                println!("{}", serde_json::json!({ "ok": true, "token": tok, "ttlSecs": ttl }));
                Ok(())
            }
            TokenCommands::Verify {
                key_args,
                token,
                origin,
                asset_id,
            } => {
                let k = key_args.resolve_required().map_err(|e| (1, e))?;
                let claims = verify_session_grant(
                    &k,
                    &token,
                    origin.as_deref(),
                    asset_id.as_deref(),
                    Some(now_unix_secs()),
                )
                .map_err(|e| (3, e.to_string()))?;
                println!("{}", serde_json::json!({ "ok": true, "claims": claims }));
                Ok(())
            }
        },
        Commands::Scan { path } => {
            let report = scan::scan_path(&path);
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| (1, e.to_string()))?
            );
            if report.findings.is_empty() {
                Ok(())
            } else {
                Err((2, format!("{} finding(s) detected", report.findings.len())))
            }
        }
        Commands::Explain { sentence, json } => {
            let joined = sentence.join(" ");
            let plan = translate_nl(&joined).map_err(|e| (1, e))?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&plan).map_err(|e| (1, e.to_string()))?
                );
            } else {
                print!("{}", format_plan_human(&plan, true));
            }
            Ok(())
        }
        Commands::Ask {
            sentence,
            dry_run,
            json,
        } => {
            let joined = sentence.join(" ");
            let plan = translate_nl(&joined).map_err(|e| (1, e))?;
            if dry_run {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&plan).map_err(|e| (1, e.to_string()))?
                    );
                } else {
                    print!("{}", format_plan_human(&plan, true));
                }
                return Ok(());
            }
            if !json {
                eprint!("{}", format_plan_human(&plan, false));
            }
            let mut argv = vec!["vibe-slayer".to_string()];
            argv.extend(plan.argv.iter().cloned());
            let parsed = Cli::try_parse_from(argv).map_err(|e| (1, e.to_string()))?;
            Box::pin(run_async(parsed)).await
        }
        Commands::Pack {
            key_args,
            domain,
            asset_id,
            context,
            in_path,
            out_path,
        } => {
            let k = key_args.resolve_required().map_err(|e| (1, e))?;
            let plain = fs::read(&in_path).map_err(|e| (1, format!("read failed: {e}")))?;
            let vspk = pack_vspk2(&k, &domain, &asset_id, &context, &plain)
                .map_err(|e| (1, e.to_string()))?;
            fs::write(&out_path, &vspk).map_err(|e| (1, format!("write failed: {e}")))?;
            println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "inputBytes": plain.len(),
                    "outputBytes": vspk.len(),
                    "sha256": hex::encode(sha256(&vspk)),
                })
            );
            Ok(())
        }
        Commands::Unseal {
            key_args,
            domain,
            asset_id,
            context,
            in_path,
            out_path,
        } => {
            let k = key_args.resolve_required().map_err(|e| (1, e))?;
            let blob = fs::read(&in_path).map_err(|e| (1, format!("read failed: {e}")))?;
            let plain = unseal_vspk2(&k, &domain, asset_id.as_deref(), &context, &blob)
                .map_err(|e| (3, e.to_string()))?;
            fs::write(&out_path, &plain).map_err(|e| (1, format!("write failed: {e}")))?;
            println!("{}", serde_json::json!({ "ok": true, "plainBytes": plain.len() }));
            Ok(())
        }
        Commands::PackV3 {
            key_args,
            domain,
            asset_id,
            context,
            in_path,
            out_path,
            v2,
        } => {
            let k = key_args.resolve_required().map_err(|e| (1, e))?;
            let res = vault_seal_cmd(
                &in_path,
                &out_path,
                &k,
                &domain,
                &asset_id,
                &context,
                AeadAlg::Aes256Gcm,
                !v2,
            )
            .map_err(|e| (1, e))?;
            println!("{res}");
            Ok(())
        }
        Commands::UnsealV3 {
            key_args,
            domain,
            asset_id,
            context,
            in_path,
            out_path,
        } => {
            let k = key_args.resolve_required().map_err(|e| (1, e))?;
            let res = vault_unseal_cmd(&in_path, &out_path, &k, &domain, &asset_id, &context, None)
                .map_err(|e| (3, e))?;
            println!("{res}");
            Ok(())
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match run_async(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, msg)) => {
            eprintln!("error: {msg}");
            ExitCode::from(code)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn every_vs_nl_plan_parses_cleanly_in_clap_cli() {
        let samples = [
            "run demo",
            "stream ./hero.glb on port 8790",
            "trace watermark in ./leaked.png",
            "seal ./weights.safetensors",
            "unseal ./weights.safetensors.vsp3",
            "inspect ./weights.safetensors.vsp3",
            "scan ./my-repo",
            "bundle website ./dist",
            "serve ./site.vsweb on port 8081",
            "mint token",
        ];
        for s in samples {
            let plan = translate_nl(s).unwrap();
            let mut argv = vec!["vibe-slayer".to_string()];
            argv.extend(plan.argv.iter().cloned());
            assert!(
                Cli::try_parse_from(&argv).is_ok(),
                "NL plan for '{s}' failed clap parse: {argv:?}"
            );
        }
    }
}
