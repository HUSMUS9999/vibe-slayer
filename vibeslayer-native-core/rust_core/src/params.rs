//! Unified, user-friendly parametrization layer (`params.rs`) for VibeSlayer:
//! - One-flag presets: `--preset fast | balanced | paranoid`
//! - Human-editable JSON config file: `vibe-slayer init-config` + `--config <file.json>`
//! - Environment variable fallbacks (`VIBESLAYER_AUTH_SECRET`, `VIBESLAYER_AUTH_HMAC_KEY`,
//!   `VIBESLAYER_KEY_FILE`, `VIBESLAYER_ORIGIN`, `VIBESLAYER_TRUST_PROXY`, `VIBESLAYER_PRESET`)
//! - Strict range/enum validation with actionable error messages

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::mini_json::{parse_json, to_json_pretty, JsonVal};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityPreset {
    Fast,
    Balanced,
    Paranoid,
}

impl SecurityPreset {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "fast" | "dev" | "light" => Ok(Self::Fast),
            "balanced" | "default" | "standard" => Ok(Self::Balanced),
            "paranoid" | "max" | "strict" | "hardened" => Ok(Self::Paranoid),
            other => Err(format!(
                "Invalid --preset '{other}': expected 'fast', 'balanced', or 'paranoid'"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Balanced => "balanced",
            Self::Paranoid => "paranoid",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PngMode {
    Fast,
    Optimal,
}

impl PngMode {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "fast" | "fixed" => Ok(Self::Fast),
            "optimal" | "dynamic" | "best" => Ok(Self::Optimal),
            other => Err(format!(
                "Invalid --png-mode '{other}': expected 'fast' or 'optimal'"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Optimal => "optimal",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TexFormat {
    Auto,
    Jpeg,
    Png,
}

impl TexFormat {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" | "smart" => Ok(Self::Auto),
            "jpeg" | "jpg" => Ok(Self::Jpeg),
            "png" | "lossless" => Ok(Self::Png),
            other => Err(format!(
                "Invalid --tex-format '{other}': expected 'auto', 'jpeg', or 'png'"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Jpeg => "jpeg",
            Self::Png => "png",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenderMode3d {
    Gpu,
    Stream,
}

impl RenderMode3d {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "gpu" | "webgl" | "webgl2" => Ok(Self::Gpu),
            "stream" | "server" | "pixel" => Ok(Self::Stream),
            other => Err(format!(
                "Invalid --mode '{other}': expected 'gpu' or 'stream'"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gpu => "gpu",
            Self::Stream => "stream",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AntiStealthMode {
    Off,
    Balanced,
    Strict,
}

impl AntiStealthMode {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "disabled" | "0" | "false" => Ok(Self::Off),
            "balanced" | "default" | "standard" => Ok(Self::Balanced),
            "strict" | "paranoid" | "max" | "on" | "1" | "true" => Ok(Self::Strict),
            other => Err(format!(
                "Invalid --anti-stealth '{other}': expected 'off', 'balanced', or 'strict'"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Balanced => "balanced",
            Self::Strict => "strict",
        }
    }

    pub fn score_threshold(self) -> u32 {
        match self {
            Self::Off => u32::MAX,
            Self::Balanced => 4,
            Self::Strict => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CspMode {
    Strict,
    Relaxed,
    Off,
}

impl CspMode {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "strict" | "on" | "default" => Ok(Self::Strict),
            "relaxed" | "compat" => Ok(Self::Relaxed),
            "off" | "none" | "disabled" => Ok(Self::Off),
            other => Err(format!(
                "Invalid --csp '{other}': expected 'strict', 'relaxed', or 'off'"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Relaxed => "relaxed",
            Self::Off => "off",
        }
    }

    pub fn header_line(self) -> &'static str {
        match self {
            Self::Strict => "Content-Security-Policy: default-src 'self'; script-src 'self' blob:; style-src 'self' 'unsafe-inline' blob:; img-src 'self' data: blob:; connect-src 'self'; frame-src 'self' about:; object-src 'none'; frame-ancestors 'none'\r\n",
            Self::Relaxed => "Content-Security-Policy: default-src 'self' https:; script-src 'self' blob:; style-src 'self' 'unsafe-inline' https: blob:; img-src 'self' data: blob: https:; connect-src 'self' https:; frame-src 'self' about:; object-src 'none'; frame-ancestors 'none'\r\n",
            Self::Off => "",
        }
    }
}

pub fn parse_bool_flag(s: &str, flag: &str) -> Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" | "enable" | "enabled" => Ok(true),
        "0" | "false" | "off" | "no" | "disable" | "disabled" => Ok(false),
        other => Err(format!(
            "Invalid {flag} '{other}': expected 'on' or 'off' (or true/false)"
        )),
    }
}

pub fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if !c.is_control() => out.push(c),
            _ => {}
        }
    }
    out
}

fn json_get_section<'a>(root: &'a JsonVal, section: &str, key: &str) -> Option<&'a JsonVal> {
    root.get(section)
        .and_then(|sec| sec.get(key))
        .or_else(|| root.get(key))
}

fn json_as_usize(v: &JsonVal) -> Option<usize> {
    match v {
        JsonVal::Int(n) if *n >= 0 => Some(*n as usize),
        JsonVal::Num(n) if *n >= 0.0 && n.is_finite() => Some(*n as usize),
        _ => None,
    }
}

fn json_as_u64(v: &JsonVal) -> Option<u64> {
    match v {
        JsonVal::Int(n) if *n >= 0 => Some(*n as u64),
        JsonVal::Num(n) if *n >= 0.0 && n.is_finite() => Some(*n as u64),
        _ => None,
    }
}

fn json_as_f32(v: &JsonVal) -> Option<f32> {
    match v {
        JsonVal::Num(n) if n.is_finite() => Some(*n as f32),
        JsonVal::Int(n) => Some(*n as f32),
        _ => None,
    }
}

pub fn load_config_json(path: &Path) -> Result<JsonVal, String> {
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("Failed reading --config '{}': {e}", path.display()))?;
    parse_json(&raw).map_err(|e| format!("Invalid JSON in --config '{}': {e}", path.display()))
}

pub fn detect_preset_from_sources(
    cli_preset: Option<&str>,
    cfg_json: Option<&JsonVal>,
    section: &str,
) -> Result<SecurityPreset, String> {
    if let Some(p) = cli_preset {
        return SecurityPreset::parse(p);
    }
    if let Some(cfg) = cfg_json {
        if let Some(p) = json_get_section(cfg, section, "preset").and_then(|v| v.as_str()) {
            return SecurityPreset::parse(p);
        }
    }
    if let Ok(env_p) = env::var("VIBESLAYER_PRESET") {
        if !env_p.trim().is_empty() {
            return SecurityPreset::parse(&env_p);
        }
    }
    Ok(SecurityPreset::Balanced)
}

/* =============================== Shield-3D Build Params =============================== */

#[derive(Clone, Debug)]
pub struct Shield3dParams {
    pub preset: SecurityPreset,
    pub gpu_stages: usize,
    pub chaff_pct: f32,
    pub max_tex_dim: usize,
    pub tile_grid: usize,
    pub png_mode: PngMode,
    pub tex_format: TexFormat,
    pub tex_quality: u8,
    pub key_file: Option<PathBuf>,
}

impl Shield3dParams {
    pub fn from_preset(preset: SecurityPreset) -> Self {
        match preset {
            SecurityPreset::Fast => Self {
                preset,
                gpu_stages: 32,
                chaff_pct: 20.0,
                max_tex_dim: 2048,
                tile_grid: 8,
                png_mode: PngMode::Fast,
                tex_format: TexFormat::Auto,
                tex_quality: 85,
                key_file: env_opt_path("VIBESLAYER_KEY_FILE"),
            },
            SecurityPreset::Balanced => Self {
                preset,
                gpu_stages: 96,
                chaff_pct: 37.5,
                max_tex_dim: 4096,
                tile_grid: 16,
                png_mode: PngMode::Optimal,
                tex_format: TexFormat::Auto,
                tex_quality: 90,
                key_file: env_opt_path("VIBESLAYER_KEY_FILE"),
            },
            SecurityPreset::Paranoid => Self {
                preset,
                gpu_stages: 128,
                chaff_pct: 50.0,
                max_tex_dim: 4096,
                tile_grid: 16,
                png_mode: PngMode::Optimal,
                tex_format: TexFormat::Auto,
                tex_quality: 92,
                key_file: env_opt_path("VIBESLAYER_KEY_FILE"),
            },
        }
    }

    pub fn apply_json(&mut self, root: &JsonVal) -> Result<(), String> {
        if let Some(v) = json_get_section(root, "shield3d", "gpuStages") {
            self.gpu_stages = json_as_usize(v).ok_or("config shield3d.gpuStages must be integer")?;
        }
        if let Some(v) = json_get_section(root, "shield3d", "chaffPercent") {
            self.chaff_pct = json_as_f32(v).ok_or("config shield3d.chaffPercent must be number")?;
        }
        if let Some(v) = json_get_section(root, "shield3d", "maxTexDim") {
            self.max_tex_dim = json_as_usize(v).ok_or("config shield3d.maxTexDim must be integer")?;
        }
        if let Some(v) = json_get_section(root, "shield3d", "tileGrid") {
            self.tile_grid = json_as_usize(v).ok_or("config shield3d.tileGrid must be integer")?;
        }
        if let Some(s) = json_get_section(root, "shield3d", "pngMode").and_then(|v| v.as_str()) {
            self.png_mode = PngMode::parse(s)?;
        }
        if let Some(s) = json_get_section(root, "shield3d", "texFormat").and_then(|v| v.as_str()) {
            self.tex_format = TexFormat::parse(s)?;
        }
        if let Some(v) = json_get_section(root, "shield3d", "texQuality") {
            let q = json_as_usize(v).ok_or("config shield3d.texQuality must be integer")?;
            self.tex_quality = q.min(255) as u8;
        }
        if let Some(s) = json_get_section(root, "shield3d", "keyFile").and_then(|v| v.as_str()) {
            if !s.trim().is_empty() {
                self.key_file = Some(PathBuf::from(s));
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        if !(16..=192).contains(&self.gpu_stages) {
            return Err(format!(
                "Invalid --gpu-stages '{}': expected integer in 16..=192",
                self.gpu_stages
            ));
        }
        if !self.chaff_pct.is_finite() || !(0.0..=75.0).contains(&self.chaff_pct) {
            return Err(format!(
                "Invalid --chaff-pct '{}': expected number in 0..=75",
                self.chaff_pct
            ));
        }
        if !(256..=8192).contains(&self.max_tex_dim) {
            return Err(format!(
                "Invalid --max-tex-dim '{}': expected integer in 256..=8192",
                self.max_tex_dim
            ));
        }
        if !matches!(self.tile_grid, 0 | 4 | 8 | 16) {
            return Err(format!(
                "Invalid --tile-grid '{}': expected 0 (off), 4, 8, or 16",
                self.tile_grid
            ));
        }
        if !(50..=98).contains(&self.tex_quality) {
            return Err(format!(
                "Invalid --tex-quality '{}': expected integer in 50..=98",
                self.tex_quality
            ));
        }
        Ok(())
    }

    pub fn chaff_count_for(&self, real_count: usize) -> usize {
        ((real_count as f64) * (self.chaff_pct as f64) / 100.0).floor() as usize
    }

    pub fn to_json(&self) -> JsonVal {
        JsonVal::obj(vec![
            ("preset", JsonVal::Str(self.preset.as_str().to_string())),
            ("gpuStages", JsonVal::Int(self.gpu_stages as i64)),
            ("chaffPercent", JsonVal::Num(self.chaff_pct as f64)),
            ("maxTexDim", JsonVal::Int(self.max_tex_dim as i64)),
            ("tileGrid", JsonVal::Int(self.tile_grid as i64)),
            ("pngMode", JsonVal::Str(self.png_mode.as_str().to_string())),
            ("texFormat", JsonVal::Str(self.tex_format.as_str().to_string())),
            ("texQuality", JsonVal::Int(self.tex_quality as i64)),
            (
                "keyFile",
                match &self.key_file {
                    Some(p) => JsonVal::Str(p.to_string_lossy().to_string()),
                    None => JsonVal::Null,
                },
            ),
        ])
    }
}

/* =============================== Serve-3D Runtime Params ============================== */

#[derive(Clone, Debug)]
pub struct Serve3dParams {
    pub preset: SecurityPreset,
    pub render_mode: RenderMode3d,
    pub stream_width: usize,
    pub stream_height: usize,
    pub stream_quality: u8,
    pub addr: String,
    pub origin: Option<String>,
    pub key_file: Option<PathBuf>,
    pub auth_secret: Option<String>,
    pub auth_hmac_key: Option<String>,
    pub trust_proxy: Option<String>,
    pub title: Option<String>,
    pub watermark: bool,
    pub wm_strength: f32,
    pub anti_hook: bool,
    pub anti_cdp: bool,
    pub anti_stealth: AntiStealthMode,
    pub csp: CspMode,
    pub camera_jitter: f32,
    pub ticket_ttl_sec: u64,
    pub session_ttl_sec: u64,
    pub camera_budget: usize,
    pub asset_budget: usize,
    pub max_leases_per_min: usize,
    pub max_sessions: usize,
    pub max_conns_per_ip: usize,
    pub max_tex_concurrency: usize,
    pub header_timeout_ms: u64,
    pub body_timeout_ms: u64,
    pub workers: usize,
}

impl Serve3dParams {
    pub fn from_preset(preset: SecurityPreset) -> Self {
        let base_env = (
            env_opt_str("VIBESLAYER_ORIGIN"),
            env_opt_path("VIBESLAYER_KEY_FILE"),
            env_opt_str("VIBESLAYER_AUTH_SECRET"),
            env_opt_str("VIBESLAYER_AUTH_HMAC_KEY"),
            env_opt_str("VIBESLAYER_TRUST_PROXY"),
        );
        match preset {
            SecurityPreset::Fast => Self {
                preset,
                render_mode: RenderMode3d::Gpu,
                stream_width: 800,
                stream_height: 540,
                stream_quality: 80,
                addr: "127.0.0.1:8790".to_string(),
                origin: base_env.0,
                key_file: base_env.1,
                auth_secret: base_env.2,
                auth_hmac_key: base_env.3,
                trust_proxy: base_env.4,
                title: None,
                watermark: true,
                wm_strength: 1.0,
                anti_hook: false,
                anti_cdp: false,
                anti_stealth: AntiStealthMode::Off,
                csp: CspMode::Relaxed,
                camera_jitter: 0.5,
                ticket_ttl_sec: 60,
                session_ttl_sec: 1800,
                camera_budget: 30_000,
                asset_budget: 48,
                max_leases_per_min: 180,
                max_sessions: 8192,
                max_conns_per_ip: 64,
                max_tex_concurrency: 8,
                header_timeout_ms: 5000,
                body_timeout_ms: 8000,
                workers: 0,
            },
            SecurityPreset::Balanced => Self {
                preset,
                render_mode: RenderMode3d::Gpu,
                stream_width: 960,
                stream_height: 640,
                stream_quality: 84,
                addr: "127.0.0.1:8790".to_string(),
                origin: base_env.0,
                key_file: base_env.1,
                auth_secret: base_env.2,
                auth_hmac_key: base_env.3,
                trust_proxy: base_env.4,
                title: None,
                watermark: true,
                wm_strength: 1.2,
                anti_hook: true,
                anti_cdp: true,
                anti_stealth: AntiStealthMode::Balanced,
                csp: CspMode::Strict,
                camera_jitter: 1.0,
                ticket_ttl_sec: 30,
                session_ttl_sec: 600,
                camera_budget: 12_000,
                asset_budget: 24,
                max_leases_per_min: 60,
                max_sessions: 4096,
                max_conns_per_ip: 32,
                max_tex_concurrency: 4,
                header_timeout_ms: 3000,
                body_timeout_ms: 5000,
                workers: 0,
            },
            SecurityPreset::Paranoid => Self {
                preset,
                render_mode: RenderMode3d::Stream,
                stream_width: 960,
                stream_height: 640,
                stream_quality: 86,
                addr: "127.0.0.1:8790".to_string(),
                origin: base_env.0,
                key_file: base_env.1,
                auth_secret: base_env.2,
                auth_hmac_key: base_env.3,
                trust_proxy: base_env.4,
                title: None,
                watermark: true,
                wm_strength: 1.8,
                anti_hook: true,
                anti_cdp: true,
                anti_stealth: AntiStealthMode::Strict,
                csp: CspMode::Strict,
                camera_jitter: 1.5,
                ticket_ttl_sec: 20,
                session_ttl_sec: 180,
                camera_budget: 4_000,
                asset_budget: 12,
                max_leases_per_min: 30,
                max_sessions: 2048,
                max_conns_per_ip: 16,
                max_tex_concurrency: 2,
                header_timeout_ms: 2000,
                body_timeout_ms: 4000,
                workers: 0,
            },
        }
    }

    pub fn apply_json(&mut self, root: &JsonVal) -> Result<(), String> {
        if let Some(s) = json_get_section(root, "serve3d", "renderMode").and_then(|v| v.as_str()) {
            self.render_mode = RenderMode3d::parse(s)?;
        }
        if let Some(v) = json_get_section(root, "serve3d", "streamWidth") {
            self.stream_width =
                json_as_usize(v).ok_or("config serve3d.streamWidth must be integer")?;
        }
        if let Some(v) = json_get_section(root, "serve3d", "streamHeight") {
            self.stream_height =
                json_as_usize(v).ok_or("config serve3d.streamHeight must be integer")?;
        }
        if let Some(v) = json_get_section(root, "serve3d", "streamQuality") {
            let q = json_as_usize(v).ok_or("config serve3d.streamQuality must be integer")?;
            self.stream_quality = q.min(255) as u8;
        }
        if let Some(s) = json_get_section(root, "serve3d", "addr").and_then(|v| v.as_str()) {
            if !s.trim().is_empty() {
                self.addr = s.to_string();
            }
        }
        if let Some(s) = json_get_section(root, "serve3d", "origin").and_then(|v| v.as_str()) {
            if !s.trim().is_empty() {
                self.origin = Some(s.to_string());
            }
        }
        if let Some(s) = json_get_section(root, "serve3d", "keyFile")
            .or_else(|| json_get_section(root, "shield3d", "keyFile"))
            .and_then(|v| v.as_str())
        {
            if !s.trim().is_empty() {
                self.key_file = Some(PathBuf::from(s));
            }
        }
        if let Some(s) = json_get_section(root, "serve3d", "authSecret").and_then(|v| v.as_str()) {
            if !s.is_empty() {
                self.auth_secret = Some(s.to_string());
            }
        }
        if let Some(s) = json_get_section(root, "serve3d", "authHmacKey").and_then(|v| v.as_str()) {
            if !s.is_empty() {
                self.auth_hmac_key = Some(s.to_string());
            }
        }
        if let Some(s) = json_get_section(root, "serve3d", "trustProxy").and_then(|v| v.as_str()) {
            if !s.is_empty() {
                self.trust_proxy = Some(s.to_string());
            }
        }
        if let Some(s) = json_get_section(root, "serve3d", "title").and_then(|v| v.as_str()) {
            if !s.trim().is_empty() {
                self.title = Some(s.to_string());
            }
        }
        if let Some(b) = json_get_section(root, "serve3d", "watermark").and_then(|v| v.as_bool()) {
            self.watermark = b;
        }
        if let Some(v) = json_get_section(root, "serve3d", "watermarkStrength") {
            self.wm_strength =
                json_as_f32(v).ok_or("config serve3d.watermarkStrength must be number")?;
        }
        if let Some(b) = json_get_section(root, "serve3d", "antiHook").and_then(|v| v.as_bool()) {
            self.anti_hook = b;
        }
        if let Some(b) = json_get_section(root, "serve3d", "antiCdp").and_then(|v| v.as_bool()) {
            self.anti_cdp = b;
        }
        if let Some(s) = json_get_section(root, "serve3d", "antiStealth").and_then(|v| v.as_str()) {
            self.anti_stealth = AntiStealthMode::parse(s)?;
        }
        if let Some(s) = json_get_section(root, "serve3d", "cspMode").and_then(|v| v.as_str()) {
            self.csp = CspMode::parse(s)?;
        }
        if let Some(v) = json_get_section(root, "serve3d", "cameraJitter") {
            self.camera_jitter =
                json_as_f32(v).ok_or("config serve3d.cameraJitter must be number")?;
        }
        if let Some(v) = json_get_section(root, "serve3d", "ticketTtlSec") {
            self.ticket_ttl_sec =
                json_as_u64(v).ok_or("config serve3d.ticketTtlSec must be integer")?;
        }
        if let Some(v) = json_get_section(root, "serve3d", "sessionTtlSec") {
            self.session_ttl_sec =
                json_as_u64(v).ok_or("config serve3d.sessionTtlSec must be integer")?;
        }
        if let Some(v) = json_get_section(root, "serve3d", "cameraBudget") {
            self.camera_budget =
                json_as_usize(v).ok_or("config serve3d.cameraBudget must be integer")?;
        }
        if let Some(v) = json_get_section(root, "serve3d", "assetBudget") {
            self.asset_budget =
                json_as_usize(v).ok_or("config serve3d.assetBudget must be integer")?;
        }
        if let Some(v) = json_get_section(root, "serve3d", "maxLeasesPerMin") {
            self.max_leases_per_min =
                json_as_usize(v).ok_or("config serve3d.maxLeasesPerMin must be integer")?;
        }
        if let Some(v) = json_get_section(root, "serve3d", "maxSessions") {
            self.max_sessions =
                json_as_usize(v).ok_or("config serve3d.maxSessions must be integer")?;
        }
        if let Some(v) = json_get_section(root, "serve3d", "maxConnsPerIp") {
            self.max_conns_per_ip =
                json_as_usize(v).ok_or("config serve3d.maxConnsPerIp must be integer")?;
        }
        if let Some(v) = json_get_section(root, "serve3d", "maxTexConcurrency") {
            self.max_tex_concurrency =
                json_as_usize(v).ok_or("config serve3d.maxTexConcurrency must be integer")?;
        }
        if let Some(v) = json_get_section(root, "serve3d", "headerTimeoutMs") {
            self.header_timeout_ms =
                json_as_u64(v).ok_or("config serve3d.headerTimeoutMs must be integer")?;
        }
        if let Some(v) = json_get_section(root, "serve3d", "bodyTimeoutMs") {
            self.body_timeout_ms =
                json_as_u64(v).ok_or("config serve3d.bodyTimeoutMs must be integer")?;
        }
        if let Some(v) = json_get_section(root, "serve3d", "workers") {
            self.workers = json_as_usize(v).ok_or("config serve3d.workers must be integer")?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        if !(320..=1920).contains(&self.stream_width) {
            return Err(format!(
                "Invalid --stream-width '{}': expected integer in 320..=1920",
                self.stream_width
            ));
        }
        if !(240..=1080).contains(&self.stream_height) {
            return Err(format!(
                "Invalid --stream-height '{}': expected integer in 240..=1080",
                self.stream_height
            ));
        }
        if !(50..=96).contains(&self.stream_quality) {
            return Err(format!(
                "Invalid --stream-quality '{}': expected integer in 50..=96",
                self.stream_quality
            ));
        }
        if !self.wm_strength.is_finite() || !(0.0..=5.0).contains(&self.wm_strength) {
            return Err(format!(
                "Invalid --wm-strength '{}': expected number in 0.0..=5.0",
                self.wm_strength
            ));
        }
        if !self.camera_jitter.is_finite() || !(0.0..=3.0).contains(&self.camera_jitter) {
            return Err(format!(
                "Invalid --camera-jitter '{}': expected number in 0.0..=3.0",
                self.camera_jitter
            ));
        }
        if !(5..=300).contains(&self.ticket_ttl_sec) {
            return Err(format!(
                "Invalid --ticket-ttl '{}': expected integer in 5..=300 seconds",
                self.ticket_ttl_sec
            ));
        }
        if !(30..=86400).contains(&self.session_ttl_sec) {
            return Err(format!(
                "Invalid --session-ttl '{}': expected integer in 30..=86400 seconds",
                self.session_ttl_sec
            ));
        }
        if !(100..=1_000_000).contains(&self.camera_budget) {
            return Err(format!(
                "Invalid --camera-budget '{}': expected integer in 100..=1000000",
                self.camera_budget
            ));
        }
        if !(6..=1000).contains(&self.asset_budget) {
            return Err(format!(
                "Invalid --asset-budget '{}': expected integer in 6..=1000",
                self.asset_budget
            ));
        }
        if !(1..=100_000_000).contains(&self.max_leases_per_min) {
            return Err(format!(
                "Invalid --max-leases-per-min '{}': expected integer in 1..=100000000",
                self.max_leases_per_min
            ));
        }
        if !(16..=65536).contains(&self.max_sessions) {
            return Err(format!(
                "Invalid --max-sessions '{}': expected integer in 16..=65536",
                self.max_sessions
            ));
        }
        if !(2..=1024).contains(&self.max_conns_per_ip) {
            return Err(format!(
                "Invalid --max-conns-per-ip '{}': expected integer in 2..=1024",
                self.max_conns_per_ip
            ));
        }
        if !(1..=32).contains(&self.max_tex_concurrency) {
            return Err(format!(
                "Invalid --max-tex-concurrency '{}': expected integer in 1..=32",
                self.max_tex_concurrency
            ));
        }
        if !(500..=30_000).contains(&self.header_timeout_ms) {
            return Err(format!(
                "Invalid --header-timeout-ms '{}': expected integer in 500..=30000",
                self.header_timeout_ms
            ));
        }
        if !(500..=60_000).contains(&self.body_timeout_ms) {
            return Err(format!(
                "Invalid --body-timeout-ms '{}': expected integer in 500..=60000",
                self.body_timeout_ms
            ));
        }
        if self.workers != 0 && !(4..=128).contains(&self.workers) {
            return Err(format!(
                "Invalid --workers '{}': expected 0 (auto) or integer in 4..=128",
                self.workers
            ));
        }
        Ok(())
    }

    pub fn resolved_workers(&self) -> usize {
        if self.workers != 0 {
            self.workers
        } else {
            std::thread::available_parallelism()
                .map(|n| n.get() * 4)
                .unwrap_or(32)
                .clamp(32, 64)
        }
    }

    pub fn wm_uniform_w(&self) -> u32 {
        if !self.watermark || self.wm_strength <= 0.0 {
            0
        } else {
            (self.wm_strength * 10.0).round().clamp(1.0, 50.0) as u32
        }
    }

    pub fn to_json(&self) -> JsonVal {
        JsonVal::obj(vec![
            ("preset", JsonVal::Str(self.preset.as_str().to_string())),
            ("renderMode", JsonVal::Str(self.render_mode.as_str().to_string())),
            ("streamWidth", JsonVal::Int(self.stream_width as i64)),
            ("streamHeight", JsonVal::Int(self.stream_height as i64)),
            ("streamQuality", JsonVal::Int(self.stream_quality as i64)),
            ("addr", JsonVal::Str(self.addr.clone())),
            (
                "origin",
                match &self.origin {
                    Some(o) => JsonVal::Str(o.clone()),
                    None => JsonVal::Null,
                },
            ),
            (
                "title",
                match &self.title {
                    Some(t) => JsonVal::Str(t.clone()),
                    None => JsonVal::Null,
                },
            ),
            ("watermark", JsonVal::Bool(self.watermark)),
            ("watermarkStrength", JsonVal::Num(self.wm_strength as f64)),
            ("antiHook", JsonVal::Bool(self.anti_hook)),
            ("antiCdp", JsonVal::Bool(self.anti_cdp)),
            ("antiStealth", JsonVal::Str(self.anti_stealth.as_str().to_string())),
            ("cspMode", JsonVal::Str(self.csp.as_str().to_string())),
            ("cameraJitter", JsonVal::Num(self.camera_jitter as f64)),
            ("ticketTtlSec", JsonVal::Int(self.ticket_ttl_sec as i64)),
            ("sessionTtlSec", JsonVal::Int(self.session_ttl_sec as i64)),
            ("cameraBudget", JsonVal::Int(self.camera_budget as i64)),
            ("assetBudget", JsonVal::Int(self.asset_budget as i64)),
            ("maxLeasesPerMin", JsonVal::Int(self.max_leases_per_min as i64)),
            ("maxSessions", JsonVal::Int(self.max_sessions as i64)),
            ("maxConnsPerIp", JsonVal::Int(self.max_conns_per_ip as i64)),
            ("maxTexConcurrency", JsonVal::Int(self.max_tex_concurrency as i64)),
            ("headerTimeoutMs", JsonVal::Int(self.header_timeout_ms as i64)),
            ("bodyTimeoutMs", JsonVal::Int(self.body_timeout_ms as i64)),
            ("workers", JsonVal::Int(self.resolved_workers() as i64)),
        ])
    }
}

/* =============================== Website Build Params ================================= */

#[derive(Clone, Debug)]
pub struct WebsiteBuildParams {
    pub preset: SecurityPreset,
    pub harden_js: bool,
    pub min_str_len: usize,
    pub js_bloat_kb: usize,
    pub anti_hook: bool,
    pub anti_cdp: bool,
    pub anti_stealth: AntiStealthMode,
    pub title: String,
}

impl WebsiteBuildParams {
    pub fn from_preset(preset: SecurityPreset) -> Self {
        match preset {
            SecurityPreset::Fast => Self {
                preset,
                harden_js: false,
                min_str_len: 6,
                js_bloat_kb: 0,
                anti_hook: false,
                anti_cdp: false,
                anti_stealth: AntiStealthMode::Off,
                title: "Protected by Vibe-Slayer".to_string(),
            },
            SecurityPreset::Balanced => Self {
                preset,
                harden_js: false,
                min_str_len: 4,
                js_bloat_kb: 0,
                anti_hook: true,
                anti_cdp: true,
                anti_stealth: AntiStealthMode::Balanced,
                title: "Protected by Vibe-Slayer".to_string(),
            },
            SecurityPreset::Paranoid => Self {
                preset,
                harden_js: true,
                min_str_len: 3,
                js_bloat_kb: 96,
                anti_hook: true,
                anti_cdp: true,
                anti_stealth: AntiStealthMode::Strict,
                title: "Protected by Vibe-Slayer".to_string(),
            },
        }
    }

    pub fn apply_json(&mut self, root: &JsonVal) -> Result<(), String> {
        if let Some(b) = json_get_section(root, "website", "hardenJs").and_then(|v| v.as_bool()) {
            self.harden_js = b;
        }
        if let Some(v) = json_get_section(root, "website", "minStrLen") {
            self.min_str_len =
                json_as_usize(v).ok_or("config website.minStrLen must be integer")?;
        }
        if let Some(v) = json_get_section(root, "website", "jsBloatKb") {
            self.js_bloat_kb =
                json_as_usize(v).ok_or("config website.jsBloatKb must be integer")?;
        }
        if let Some(b) = json_get_section(root, "website", "antiHook").and_then(|v| v.as_bool()) {
            self.anti_hook = b;
        }
        if let Some(b) = json_get_section(root, "website", "antiCdp").and_then(|v| v.as_bool()) {
            self.anti_cdp = b;
        }
        if let Some(s) = json_get_section(root, "website", "antiStealth").and_then(|v| v.as_str()) {
            self.anti_stealth = AntiStealthMode::parse(s)?;
        }
        if let Some(s) = json_get_section(root, "website", "title").and_then(|v| v.as_str()) {
            if !s.trim().is_empty() {
                self.title = s.to_string();
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        if !(2..=64).contains(&self.min_str_len) {
            return Err(format!(
                "Invalid --min-str-len '{}': expected integer in 2..=64",
                self.min_str_len
            ));
        }
        if self.js_bloat_kb > 512 {
            return Err(format!(
                "Invalid --js-bloat-kb '{}': expected integer in 0..=512",
                self.js_bloat_kb
            ));
        }
        Ok(())
    }

    pub fn to_json(&self) -> JsonVal {
        JsonVal::obj(vec![
            ("preset", JsonVal::Str(self.preset.as_str().to_string())),
            ("hardenJs", JsonVal::Bool(self.harden_js)),
            ("minStrLen", JsonVal::Int(self.min_str_len as i64)),
            ("jsBloatKb", JsonVal::Int(self.js_bloat_kb as i64)),
            ("antiHook", JsonVal::Bool(self.anti_hook)),
            ("antiCdp", JsonVal::Bool(self.anti_cdp)),
            ("antiStealth", JsonVal::Str(self.anti_stealth.as_str().to_string())),
            ("title", JsonVal::Str(self.title.clone())),
        ])
    }
}

/* =============================== Serve Web Runtime Params ============================= */

#[derive(Clone, Debug)]
pub struct ServeWebParams {
    pub preset: SecurityPreset,
    pub addr: String,
    pub origin: Option<String>,
    pub auth_secret: Option<String>,
    pub auth_hmac_key: Option<String>,
    pub trust_proxy: Option<String>,
    pub csp: CspMode,
    pub anti_stealth: AntiStealthMode,
    pub ticket_ttl_sec: u64,
    pub max_leases_per_min: usize,
    pub max_conns_per_ip: usize,
    pub header_timeout_ms: u64,
    pub body_timeout_ms: u64,
    pub workers: usize,
}

impl ServeWebParams {
    pub fn from_preset(preset: SecurityPreset) -> Self {
        let base_env = (
            env_opt_str("VIBESLAYER_ORIGIN"),
            env_opt_str("VIBESLAYER_AUTH_SECRET"),
            env_opt_str("VIBESLAYER_AUTH_HMAC_KEY"),
            env_opt_str("VIBESLAYER_TRUST_PROXY"),
        );
        match preset {
            SecurityPreset::Fast => Self {
                preset,
                addr: "127.0.0.1:8080".to_string(),
                origin: base_env.0,
                auth_secret: base_env.1,
                auth_hmac_key: base_env.2,
                trust_proxy: base_env.3,
                csp: CspMode::Relaxed,
                anti_stealth: AntiStealthMode::Off,
                ticket_ttl_sec: 60,
                max_leases_per_min: 180,
                max_conns_per_ip: 64,
                header_timeout_ms: 5000,
                body_timeout_ms: 8000,
                workers: 0,
            },
            SecurityPreset::Balanced => Self {
                preset,
                addr: "127.0.0.1:8080".to_string(),
                origin: base_env.0,
                auth_secret: base_env.1,
                auth_hmac_key: base_env.2,
                trust_proxy: base_env.3,
                csp: CspMode::Strict,
                anti_stealth: AntiStealthMode::Balanced,
                ticket_ttl_sec: 30,
                max_leases_per_min: 60,
                max_conns_per_ip: 32,
                header_timeout_ms: 3000,
                body_timeout_ms: 5000,
                workers: 0,
            },
            SecurityPreset::Paranoid => Self {
                preset,
                addr: "127.0.0.1:8080".to_string(),
                origin: base_env.0,
                auth_secret: base_env.1,
                auth_hmac_key: base_env.2,
                trust_proxy: base_env.3,
                csp: CspMode::Strict,
                anti_stealth: AntiStealthMode::Strict,
                ticket_ttl_sec: 20,
                max_leases_per_min: 30,
                max_conns_per_ip: 16,
                header_timeout_ms: 2000,
                body_timeout_ms: 4000,
                workers: 0,
            },
        }
    }

    pub fn apply_json(&mut self, root: &JsonVal) -> Result<(), String> {
        if let Some(s) = json_get_section(root, "serve", "addr").and_then(|v| v.as_str()) {
            if !s.trim().is_empty() {
                self.addr = s.to_string();
            }
        }
        if let Some(s) = json_get_section(root, "serve", "origin").and_then(|v| v.as_str()) {
            if !s.trim().is_empty() {
                self.origin = Some(s.to_string());
            }
        }
        if let Some(s) = json_get_section(root, "serve", "authSecret").and_then(|v| v.as_str()) {
            if !s.is_empty() {
                self.auth_secret = Some(s.to_string());
            }
        }
        if let Some(s) = json_get_section(root, "serve", "authHmacKey").and_then(|v| v.as_str()) {
            if !s.is_empty() {
                self.auth_hmac_key = Some(s.to_string());
            }
        }
        if let Some(s) = json_get_section(root, "serve", "trustProxy").and_then(|v| v.as_str()) {
            if !s.is_empty() {
                self.trust_proxy = Some(s.to_string());
            }
        }
        if let Some(s) = json_get_section(root, "serve", "cspMode").and_then(|v| v.as_str()) {
            self.csp = CspMode::parse(s)?;
        }
        if let Some(s) = json_get_section(root, "serve", "antiStealth").and_then(|v| v.as_str()) {
            self.anti_stealth = AntiStealthMode::parse(s)?;
        }
        if let Some(v) = json_get_section(root, "serve", "ticketTtlSec") {
            self.ticket_ttl_sec =
                json_as_u64(v).ok_or("config serve.ticketTtlSec must be integer")?;
        }
        if let Some(v) = json_get_section(root, "serve", "maxLeasesPerMin") {
            self.max_leases_per_min =
                json_as_usize(v).ok_or("config serve.maxLeasesPerMin must be integer")?;
        }
        if let Some(v) = json_get_section(root, "serve", "maxConnsPerIp") {
            self.max_conns_per_ip =
                json_as_usize(v).ok_or("config serve.maxConnsPerIp must be integer")?;
        }
        if let Some(v) = json_get_section(root, "serve", "headerTimeoutMs") {
            self.header_timeout_ms =
                json_as_u64(v).ok_or("config serve.headerTimeoutMs must be integer")?;
        }
        if let Some(v) = json_get_section(root, "serve", "bodyTimeoutMs") {
            self.body_timeout_ms =
                json_as_u64(v).ok_or("config serve.bodyTimeoutMs must be integer")?;
        }
        if let Some(v) = json_get_section(root, "serve", "workers") {
            self.workers = json_as_usize(v).ok_or("config serve.workers must be integer")?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        if !(5..=300).contains(&self.ticket_ttl_sec) {
            return Err(format!(
                "Invalid --ticket-ttl '{}': expected integer in 5..=300 seconds",
                self.ticket_ttl_sec
            ));
        }
        if !(1..=100_000_000).contains(&self.max_leases_per_min) {
            return Err(format!(
                "Invalid --max-leases-per-min '{}': expected integer in 1..=100000000",
                self.max_leases_per_min
            ));
        }
        if !(2..=1024).contains(&self.max_conns_per_ip) {
            return Err(format!(
                "Invalid --max-conns-per-ip '{}': expected integer in 2..=1024",
                self.max_conns_per_ip
            ));
        }
        if !(500..=30_000).contains(&self.header_timeout_ms) {
            return Err(format!(
                "Invalid --header-timeout-ms '{}': expected integer in 500..=30000",
                self.header_timeout_ms
            ));
        }
        if !(500..=60_000).contains(&self.body_timeout_ms) {
            return Err(format!(
                "Invalid --body-timeout-ms '{}': expected integer in 500..=60000",
                self.body_timeout_ms
            ));
        }
        if self.workers != 0 && !(4..=128).contains(&self.workers) {
            return Err(format!(
                "Invalid --workers '{}': expected 0 (auto) or integer in 4..=128",
                self.workers
            ));
        }
        Ok(())
    }

    pub fn resolved_workers(&self) -> usize {
        if self.workers != 0 {
            self.workers
        } else {
            std::thread::available_parallelism()
                .map(|n| n.get() * 4)
                .unwrap_or(32)
                .clamp(32, 64)
        }
    }

    pub fn to_json(&self) -> JsonVal {
        JsonVal::obj(vec![
            ("preset", JsonVal::Str(self.preset.as_str().to_string())),
            ("addr", JsonVal::Str(self.addr.clone())),
            (
                "origin",
                match &self.origin {
                    Some(o) => JsonVal::Str(o.clone()),
                    None => JsonVal::Null,
                },
            ),
            ("cspMode", JsonVal::Str(self.csp.as_str().to_string())),
            ("antiStealth", JsonVal::Str(self.anti_stealth.as_str().to_string())),
            ("ticketTtlSec", JsonVal::Int(self.ticket_ttl_sec as i64)),
            ("maxLeasesPerMin", JsonVal::Int(self.max_leases_per_min as i64)),
            ("maxConnsPerIp", JsonVal::Int(self.max_conns_per_ip as i64)),
            ("headerTimeoutMs", JsonVal::Int(self.header_timeout_ms as i64)),
            ("bodyTimeoutMs", JsonVal::Int(self.body_timeout_ms as i64)),
            ("workers", JsonVal::Int(self.resolved_workers() as i64)),
        ])
    }
}

/// Renders a clean, ready-to-edit `vibeslayer.config.json` template for any preset.
pub fn build_default_config_template(preset: SecurityPreset) -> String {
    let s3d = Shield3dParams::from_preset(preset);
    let sv3d = Serve3dParams::from_preset(preset);
    let wb = WebsiteBuildParams::from_preset(preset);
    let sw = ServeWebParams::from_preset(preset);

    let root = JsonVal::obj(vec![
        ("preset", JsonVal::Str(preset.as_str().to_string())),
        (
            "shield3d",
            JsonVal::obj(vec![
                ("gpuStages", JsonVal::Int(s3d.gpu_stages as i64)),
                ("chaffPercent", JsonVal::Num(s3d.chaff_pct as f64)),
                ("maxTexDim", JsonVal::Int(s3d.max_tex_dim as i64)),
                ("tileGrid", JsonVal::Int(s3d.tile_grid as i64)),
                ("pngMode", JsonVal::Str(s3d.png_mode.as_str().to_string())),
                ("texFormat", JsonVal::Str(s3d.tex_format.as_str().to_string())),
                ("texQuality", JsonVal::Int(s3d.tex_quality as i64)),
                ("keyFile", JsonVal::Null),
            ]),
        ),
        (
            "serve3d",
            JsonVal::obj(vec![
                ("renderMode", JsonVal::Str(sv3d.render_mode.as_str().to_string())),
                ("streamWidth", JsonVal::Int(sv3d.stream_width as i64)),
                ("streamHeight", JsonVal::Int(sv3d.stream_height as i64)),
                ("streamQuality", JsonVal::Int(sv3d.stream_quality as i64)),
                ("addr", JsonVal::Str(sv3d.addr)),
                ("origin", JsonVal::Null),
                ("title", JsonVal::Null),
                ("watermark", JsonVal::Bool(sv3d.watermark)),
                ("watermarkStrength", JsonVal::Num(sv3d.wm_strength as f64)),
                ("antiHook", JsonVal::Bool(sv3d.anti_hook)),
                ("antiCdp", JsonVal::Bool(sv3d.anti_cdp)),
                ("antiStealth", JsonVal::Str(sv3d.anti_stealth.as_str().to_string())),
                ("cspMode", JsonVal::Str(sv3d.csp.as_str().to_string())),
                ("cameraJitter", JsonVal::Num(sv3d.camera_jitter as f64)),
                ("ticketTtlSec", JsonVal::Int(sv3d.ticket_ttl_sec as i64)),
                ("sessionTtlSec", JsonVal::Int(sv3d.session_ttl_sec as i64)),
                ("cameraBudget", JsonVal::Int(sv3d.camera_budget as i64)),
                ("assetBudget", JsonVal::Int(sv3d.asset_budget as i64)),
                ("maxLeasesPerMin", JsonVal::Int(sv3d.max_leases_per_min as i64)),
                ("maxSessions", JsonVal::Int(sv3d.max_sessions as i64)),
                ("maxConnsPerIp", JsonVal::Int(sv3d.max_conns_per_ip as i64)),
                ("maxTexConcurrency", JsonVal::Int(sv3d.max_tex_concurrency as i64)),
                ("headerTimeoutMs", JsonVal::Int(sv3d.header_timeout_ms as i64)),
                ("bodyTimeoutMs", JsonVal::Int(sv3d.body_timeout_ms as i64)),
                ("workers", JsonVal::Int(0)),
                ("trustProxy", JsonVal::Null),
            ]),
        ),
        (
            "website",
            JsonVal::obj(vec![
                ("hardenJs", JsonVal::Bool(wb.harden_js)),
                ("minStrLen", JsonVal::Int(wb.min_str_len as i64)),
                ("jsBloatKb", JsonVal::Int(wb.js_bloat_kb as i64)),
                ("antiHook", JsonVal::Bool(wb.anti_hook)),
                ("antiCdp", JsonVal::Bool(wb.anti_cdp)),
                ("antiStealth", JsonVal::Str(wb.anti_stealth.as_str().to_string())),
                ("title", JsonVal::Str(wb.title)),
            ]),
        ),
        (
            "serve",
            JsonVal::obj(vec![
                ("addr", JsonVal::Str(sw.addr)),
                ("origin", JsonVal::Null),
                ("cspMode", JsonVal::Str(sw.csp.as_str().to_string())),
                ("antiStealth", JsonVal::Str(sw.anti_stealth.as_str().to_string())),
                ("ticketTtlSec", JsonVal::Int(sw.ticket_ttl_sec as i64)),
                ("maxLeasesPerMin", JsonVal::Int(sw.max_leases_per_min as i64)),
                ("maxConnsPerIp", JsonVal::Int(sw.max_conns_per_ip as i64)),
                ("headerTimeoutMs", JsonVal::Int(sw.header_timeout_ms as i64)),
                ("bodyTimeoutMs", JsonVal::Int(sw.body_timeout_ms as i64)),
                ("workers", JsonVal::Int(0)),
                ("trustProxy", JsonVal::Null),
            ]),
        ),
    ]);
    format!("{}\n", to_json_pretty(&root))
}

fn env_opt_str(key: &str) -> Option<String> {
    env::var(key).ok().and_then(|s| {
        if s.trim().is_empty() {
            None
        } else {
            Some(s)
        }
    })
}

fn env_opt_path(key: &str) -> Option<PathBuf> {
    env_opt_str(key).map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_config_overlay_and_validation_work() {
        for p in [
            SecurityPreset::Fast,
            SecurityPreset::Balanced,
            SecurityPreset::Paranoid,
        ] {
            let tpl = build_default_config_template(p);
            let parsed = parse_json(&tpl).expect("valid config template json");

            let mut s3d = Shield3dParams::from_preset(p);
            s3d.apply_json(&parsed).unwrap();
            s3d.validate().unwrap();

            let mut sv3d = Serve3dParams::from_preset(p);
            sv3d.apply_json(&parsed).unwrap();
            sv3d.validate().unwrap();

            let mut wb = WebsiteBuildParams::from_preset(p);
            wb.apply_json(&parsed).unwrap();
            wb.validate().unwrap();

            let mut sw = ServeWebParams::from_preset(p);
            sw.apply_json(&parsed).unwrap();
            sw.validate().unwrap();
        }

        // Custom overlay overrides preset defaults cleanly
        let custom = parse_json(
            r#"{"preset":"fast","shield3d":{"gpuStages":64,"tileGrid":8,"chaffPercent":25},"serve3d":{"watermark":false,"cspMode":"off","assetBudget":10}}"#,
        )
        .unwrap();
        let mut s3d = Shield3dParams::from_preset(SecurityPreset::Fast);
        s3d.apply_json(&custom).unwrap();
        s3d.validate().unwrap();
        assert_eq!(s3d.gpu_stages, 64);
        assert_eq!(s3d.tile_grid, 8);
        assert_eq!(s3d.chaff_count_for(100), 25);

        let mut sv3d = Serve3dParams::from_preset(SecurityPreset::Fast);
        sv3d.apply_json(&custom).unwrap();
        sv3d.validate().unwrap();
        assert!(!sv3d.watermark);
        assert_eq!(sv3d.wm_uniform_w(), 0);
        assert_eq!(sv3d.csp, CspMode::Off);
        assert_eq!(sv3d.asset_budget, 10);

        // Invalid values rejected with descriptive errors
        let mut bad = Shield3dParams::from_preset(SecurityPreset::Balanced);
        bad.tile_grid = 12;
        assert!(bad.validate().is_err());
        bad.tile_grid = 16;
        bad.gpu_stages = 999;
        assert!(bad.validate().is_err());

        // HTML escape strips XSS payloads
        assert_eq!(
            html_escape("<script>\"x\" & 'y'</script>"),
            "&lt;script&gt;&quot;x&quot; &amp; &#39;y&#39;&lt;/script&gt;"
        );
    }
}
