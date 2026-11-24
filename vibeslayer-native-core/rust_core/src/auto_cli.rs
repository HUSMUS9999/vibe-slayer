//! Zero-Node Pure-Rust Auto-Protection Engine (`1.0.0-beta.3`).
//! Powers `./vibe-slayer <target>`, `scan`, `test`, `run`, `unseal`, `watermark`, `trace`, and `demo`.

use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, RwLock};
use std::thread;
use std::time::Duration;

use crate::mini_json::{parse_json, to_json_pretty, JsonVal};
use crate::{
    build_protected_elf_freestanding, cook_glb_vspk2, decode_wm64_o1, embed_wm64_for_lease,
    hex_decode, hex_encode, hmac_sha256, os_random_bytes, pack_vspk3, secure_zero, sha256,
    unseal_vspk3, wrap_elf_freestanding,
};

#[derive(Clone, Debug)]
pub struct SecretWarning {
    pub rel_path: String,
    pub line: usize,
    pub kind: String,
    pub preview: String,
}

impl SecretWarning {
    pub fn to_json(&self) -> JsonVal {
        JsonVal::obj(vec![
            ("relPath", JsonVal::Str(self.rel_path.clone())),
            ("line", JsonVal::Int(self.line as i64)),
            ("kind", JsonVal::Str(self.kind.clone())),
            ("preview", JsonVal::Str(self.preview.clone())),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct CliOpts {
    pub out_path: Option<PathBuf>,
    pub keys_file: Option<PathBuf>,
    pub registry_path: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub preset: Option<String>,
    pub context: Option<String>,
    pub origin: Option<String>,
    pub addr: Option<String>,
    pub buyer: Option<String>,
    pub wm_id_hex: Option<String>,
    pub model_path: Option<PathBuf>,
    pub dir_path: Option<PathBuf>,
    pub auth_secret: Option<String>,
    pub auth_hmac_key: Option<String>,
    pub trust_proxy: Option<String>,
    pub title: Option<String>,
    pub csp: Option<String>,
    pub anti_hook: Option<String>,
    pub anti_cdp: Option<String>,
    pub anti_stealth: Option<String>,
    pub min_str_len: Option<usize>,
    pub js_bloat_kb: Option<usize>,
    pub ticket_ttl: Option<u64>,
    pub max_conns_per_ip: Option<usize>,
    pub header_timeout_ms: Option<u64>,
    pub body_timeout_ms: Option<u64>,
    pub workers: Option<usize>,
    pub max_leases_override: Option<usize>,
    pub harden_js_override: Option<bool>,
    pub max_leases_per_min: usize,
    pub standalone: bool,
    pub seal_all: bool,
    pub harden_js: bool,
    pub force_vault: bool,
    pub no_gitignore: bool,
    pub json: bool,
}

impl Default for CliOpts {
    fn default() -> Self {
        Self {
            out_path: None,
            keys_file: None,
            registry_path: None,
            config_path: None,
            preset: None,
            context: None,
            origin: None,
            addr: None,
            buyer: None,
            wm_id_hex: None,
            model_path: None,
            dir_path: None,
            auth_secret: None,
            auth_hmac_key: None,
            trust_proxy: None,
            title: None,
            csp: None,
            anti_hook: None,
            anti_cdp: None,
            anti_stealth: None,
            min_str_len: None,
            js_bloat_kb: None,
            ticket_ttl: None,
            max_conns_per_ip: None,
            header_timeout_ms: None,
            body_timeout_ms: None,
            workers: None,
            max_leases_override: None,
            harden_js_override: None,
            max_leases_per_min: 60,
            standalone: false,
            seal_all: false,
            harden_js: false,
            force_vault: false,
            no_gitignore: false,
            json: false,
        }
    }
}

pub struct KnownMeta {
    pub abs_target: PathBuf,
    pub target_sha: Option<String>,
    pub vault: Option<JsonVal>,
    pub keys_path: Option<PathBuf>,
    pub entry: Option<JsonVal>,
    pub reg_path: PathBuf,
    pub registry: JsonVal,
}

pub fn sha256_hex(buf: &[u8]) -> String {
    hex_encode(&sha256(buf))
}

pub fn sha256_file_hex(path: &Path) -> Result<String, String> {
    let b = fs::read(path).map_err(|e| e.to_string())?;
    Ok(sha256_hex(&b))
}

pub fn shannon_entropy(buf: &[u8]) -> f64 {
    if buf.is_empty() {
        return 0.0;
    }
    let mut c0 = [0u32; 256];
    let mut c1 = [0u32; 256];
    let mut c2 = [0u32; 256];
    let mut c3 = [0u32; 256];
    let mut chunks = buf.chunks_exact(4);
    for ch in &mut chunks {
        c0[ch[0] as usize] += 1;
        c1[ch[1] as usize] += 1;
        c2[ch[2] as usize] += 1;
        c3[ch[3] as usize] += 1;
    }
    for &b in chunks.remainder() {
        c0[b as usize] += 1;
    }
    let inv_n = 1.0 / (buf.len() as f64);
    let mut h = 0.0;
    for i in 0..256 {
        let c = c0[i] + c1[i] + c2[i] + c3[i];
        if c == 0 {
            continue;
        }
        let p = (c as f64) * inv_n;
        h -= p * p.log2();
    }
    (h * 100_000.0).round() / 100_000.0
}

pub fn parse_key_hex_32(hex: &str) -> Result<[u8; 32], String> {
    let mut b = hex_decode(hex.trim())?;
    if b.len() != 32 {
        secure_zero(&mut b);
        return Err("KEY_MUST_BE_32_BYTES_HEX".to_string());
    }
    let arr: [u8; 32] = b.as_slice().try_into().unwrap();
    secure_zero(&mut b);
    Ok(arr)
}

pub fn detect_workspace_root() -> Option<PathBuf> {
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            if dir.join("vibeslayer-native-core").is_dir() {
                return Some(dir.to_path_buf());
            }
            if let Some(p1) = dir.parent() {
                if let Some(p2) = p1.parent() {
                    if p2.join("vibeslayer-native-core").is_dir() {
                        return Some(p2.to_path_buf());
                    }
                }
            }
        }
    }
    if let Ok(cwd) = env::current_dir() {
        let mut cur = cwd.as_path();
        for _ in 0..5 {
            if cur.join("vibeslayer-native-core").is_dir() {
                return Some(cur.to_path_buf());
            }
            match cur.parent() {
                Some(p) => cur = p,
                None => break,
            }
        }
    }
    None
}

pub fn abs_path_clean(p: &Path) -> Result<PathBuf, String> {
    if p.is_absolute() {
        Ok(p.to_path_buf())
    } else {
        Ok(env::current_dir().map_err(|e| e.to_string())?.join(p))
    }
}

pub fn resolve_registry_path(custom_reg: Option<&Path>) -> PathBuf {
    if let Some(p) = custom_reg {
        return abs_path_clean(p).unwrap_or_else(|_| p.to_path_buf());
    }
    if let Ok(env_p) = env::var("VIBESLAYER_REGISTRY") {
        if !env_p.trim().is_empty() {
            let p = PathBuf::from(env_p);
            return abs_path_clean(&p).unwrap_or(p);
        }
    }
    if let Some(ws) = detect_workspace_root() {
        return ws.join(".vibeslayer-registry.json");
    }
    env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".vibeslayer-registry.json")
}

pub fn write_private_json(file_path: &Path, val: &JsonVal) -> Result<(), String> {
    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    let body = to_json_pretty(val);
    fs::write(file_path, body.as_bytes()).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(file_path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn make_executable(file_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(file_path, fs::Permissions::from_mode(0o755));
    }
    #[cfg(not(unix))]
    {
        let _ = file_path;
    }
}

pub fn ensure_gitignore_lines(
    dir_path: &Path,
    required: &[&str],
    create_if_missing: bool,
) -> bool {
    let gitignore_path = dir_path.join(".gitignore");
    let has_git = dir_path.join(".git").exists();
    let exists = gitignore_path.exists();
    if !exists && !create_if_missing && !has_git {
        return false;
    }
    let existing = fs::read_to_string(&gitignore_path).unwrap_or_default();
    let existing_lines: HashSet<String> = existing.lines().map(|l| l.trim().to_string()).collect();
    let to_add: Vec<&str> = required
        .iter()
        .copied()
        .filter(|line| !existing_lines.contains(*line))
        .collect();
    if to_add.is_empty() {
        return false;
    }
    let prefix = if !existing.is_empty() && !existing.ends_with('\n') {
        "\n"
    } else {
        ""
    };
    let header = if existing.contains("# Vibe-Slayer automatic key & registry protection") {
        ""
    } else {
        "# Vibe-Slayer automatic key & registry protection\n"
    };
    let next = format!("{existing}{prefix}{header}{}\n", to_add.join("\n"));
    fs::write(gitignore_path, next).is_ok()
}

fn load_json_if_exists(path: &Path) -> Option<JsonVal> {
    if !path.is_file() {
        return None;
    }
    let raw = fs::read_to_string(path).ok()?;
    parse_json(&raw).ok()
}

fn create_empty_vault() -> Result<JsonVal, String> {
    let mut mk = [0u8; 32];
    os_random_bytes(&mut mk)?;
    let mk_hex = hex_encode(&mk);
    secure_zero(&mut mk);
    Ok(JsonVal::obj(vec![
        ("version", JsonVal::Str("1.0.0-beta.3".to_string())),
        ("masterKeyHex", JsonVal::Str(mk_hex)),
        ("buyers", JsonVal::empty_obj()),
        ("artifacts", JsonVal::empty_obj()),
        ("byPath", JsonVal::empty_obj()),
        ("watermarks", JsonVal::empty_obj()),
    ]))
}

pub fn resolve_default_keys_path(input_path: &Path, custom_keys: Option<&Path>) -> PathBuf {
    if let Some(k) = custom_keys {
        return abs_path_clean(k).unwrap_or_else(|_| k.to_path_buf());
    }
    let abs_in = abs_path_clean(input_path).unwrap_or_else(|_| input_path.to_path_buf());
    let base_dir = if abs_in.is_dir() {
        abs_in
    } else {
        abs_in
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
    };
    base_dir.join(".vibeslayer").join("keys.json")
}

pub fn load_or_create_vault(
    keys_path: &Path,
    project_root: Option<&Path>,
    create_gitignore: bool,
    no_gitignore: bool,
) -> Result<JsonVal, String> {
    let existing = load_json_if_exists(keys_path);
    let vault = match existing {
        Some(mut v)
            if v.get("masterKeyHex")
                .and_then(|x| x.as_str())
                .map(|s| parse_key_hex_32(s).is_ok())
                .unwrap_or(false) =>
        {
            v.ensure_obj("buyers");
            v.ensure_obj("artifacts");
            v.ensure_obj("byPath");
            v.ensure_obj("watermarks");
            v
        }
        _ => create_empty_vault()?,
    };
    write_private_json(keys_path, &vault)?;
    if !no_gitignore {
        if let Some(root) = project_root {
            ensure_gitignore_lines(
                root,
                &[".vibeslayer/", "*.vibeslayer.keys.json", ".env"],
                create_gitignore,
            );
        }
    }
    let _ = vault.get("version");
    Ok(vault)
}

pub fn load_workspace_registry(reg_path: &Path) -> JsonVal {
    if let Some(mut v) = load_json_if_exists(reg_path) {
        if matches!(v, JsonVal::Obj(_)) {
            v.ensure_obj("artifacts");
            v.ensure_obj("byPath");
            v.ensure_obj("watermarks");
            return v;
        }
    }
    JsonVal::obj(vec![
        ("artifacts", JsonVal::empty_obj()),
        ("byPath", JsonVal::empty_obj()),
        ("watermarks", JsonVal::empty_obj()),
    ])
}

pub fn save_workspace_registry(reg_path: &Path, data: &JsonVal) -> Result<(), String> {
    write_private_json(reg_path, data)?;
    if let Some(ws) = detect_workspace_root() {
        if reg_path == ws.join(".vibeslayer-registry.json") {
            ensure_gitignore_lines(&ws, &[".vibeslayer-registry.json", ".vibeslayer/"], true);
        }
    }
    Ok(())
}

pub(crate) fn record_artifact_mem(
    vault: &mut JsonVal,
    keys_abs: &Path,
    reg: &mut JsonVal,
    mut meta: JsonVal,
) -> Result<(), String> {
    let abs_out = meta
        .get("absOutPath")
        .and_then(|v| v.as_str())
        .ok_or("ARTIFACT_MISSING_ABS_OUT")?
        .to_string();
    let out_sha = meta
        .get("outputSha256")
        .and_then(|v| v.as_str())
        .ok_or("ARTIFACT_MISSING_SHA")?
        .to_string();
    meta.insert("absOutPath", JsonVal::Str(abs_out.clone()));

    vault
        .ensure_obj("artifacts")
        .insert(out_sha.clone(), meta.clone());
    vault
        .ensure_obj("byPath")
        .insert(abs_out.clone(), JsonVal::Str(out_sha.clone()));

    let reg_entry = JsonVal::obj(vec![
        ("keysFile", JsonVal::Str(keys_abs.to_string_lossy().to_string())),
        ("outputSha256", JsonVal::Str(out_sha.clone())),
        (
            "engine",
            meta.get("engine").cloned().unwrap_or(JsonVal::Null),
        ),
        (
            "domain",
            meta.get("domain").cloned().unwrap_or(JsonVal::Null),
        ),
        (
            "assetId",
            meta.get("assetId").cloned().unwrap_or(JsonVal::Null),
        ),
        (
            "context",
            meta.get("context")
                .cloned()
                .unwrap_or_else(|| JsonVal::Str(String::new())),
        ),
        (
            "standalone",
            JsonVal::Bool(meta.get("standalone").and_then(|v| v.as_bool()).unwrap_or(false)),
        ),
        (
            "relPath",
            meta.get("relPath")
                .cloned()
                .unwrap_or_else(|| JsonVal::Str(abs_out.clone())),
        ),
        (
            "originalName",
            meta.get("originalName").cloned().unwrap_or(JsonVal::Null),
        ),
        (
            "originalSha256",
            meta.get("originalSha256").cloned().unwrap_or(JsonVal::Null),
        ),
        (
            "ownerRefPath",
            meta.get("ownerRefPath").cloned().unwrap_or(JsonVal::Null),
        ),
        ("coords", meta.get("coords").cloned().unwrap_or(JsonVal::Null)),
    ]);
    reg.ensure_obj("artifacts").insert(out_sha.clone(), reg_entry);
    reg.ensure_obj("byPath").insert(abs_out, JsonVal::Str(out_sha));
    Ok(())
}

pub fn record_artifact(
    vault: &mut JsonVal,
    keys_path: &Path,
    reg_path: &Path,
    reg: &mut JsonVal,
    meta: JsonVal,
) -> Result<(), String> {
    let keys_abs = abs_path_clean(keys_path)?;
    record_artifact_mem(vault, &keys_abs, reg, meta)?;
    write_private_json(keys_path, vault)?;
    save_workspace_registry(reg_path, reg)?;
    Ok(())
}

pub fn resolve_known_metadata(
    target_path: &Path,
    custom_keys: Option<&Path>,
    custom_reg: Option<&Path>,
) -> KnownMeta {
    let abs_target = abs_path_clean(target_path).unwrap_or_else(|_| target_path.to_path_buf());
    let target_sha = if abs_target.is_file() {
        sha256_file_hex(&abs_target).ok()
    } else {
        None
    };

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(k) = custom_keys {
        if let Ok(ak) = abs_path_clean(k) {
            candidates.push(ak);
        }
    }

    let start_dir = if abs_target.is_dir() {
        abs_target.clone()
    } else {
        abs_target
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
    };

    let mut cur = start_dir;
    for _ in 0..6 {
        candidates.push(cur.join(".vibeslayer").join("keys.json"));
        let cur_s = cur.to_string_lossy();
        if let Some(stripped) = cur_s.strip_suffix("-protected") {
            candidates.push(PathBuf::from(stripped).join(".vibeslayer").join("keys.json"));
        }
        if let Some(stripped) = cur_s.strip_suffix("-web-protected") {
            candidates.push(PathBuf::from(stripped).join(".vibeslayer").join("keys.json"));
        }
        match cur.parent() {
            Some(p) if p != cur => cur = p.to_path_buf(),
            _ => break,
        }
    }

    let abs_str = abs_target.to_string_lossy().to_string();
    let mut found_vault: Option<JsonVal> = None;
    let mut found_keys_path: Option<PathBuf> = None;
    let mut found_entry: Option<JsonVal> = None;

    for vp in candidates {
        let Some(v) = load_json_if_exists(&vp) else {
            continue;
        };
        if v.get("masterKeyHex").and_then(|x| x.as_str()).is_none() {
            continue;
        }
        if found_vault.is_none() {
            found_vault = Some(v.clone());
            found_keys_path = Some(vp.clone());
        }
        let sha_key = target_sha
            .as_ref()
            .filter(|s| v.get("artifacts").and_then(|a| a.get(s)).is_some())
            .cloned()
            .or_else(|| {
                v.get("byPath")
                    .and_then(|bp| bp.get(&abs_str))
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
            });
        if let Some(sk) = sha_key {
            if let Some(ent) = v.get("artifacts").and_then(|a| a.get(&sk)) {
                found_entry = Some(ent.clone());
                found_vault = Some(v);
                found_keys_path = Some(vp);
                break;
            }
        }
    }

    let reg_path = resolve_registry_path(custom_reg);
    let reg = load_workspace_registry(&reg_path);
    let reg_sha = target_sha
        .as_ref()
        .filter(|s| reg.get("artifacts").and_then(|a| a.get(s)).is_some())
        .cloned()
        .or_else(|| {
            reg.get("byPath")
                .and_then(|bp| bp.get(&abs_str))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        });
    if found_entry.is_none() {
        if let Some(rk) = reg_sha {
            if let Some(reg_ent) = reg.get("artifacts").and_then(|a| a.get(&rk)) {
                found_entry = Some(reg_ent.clone());
                if let Some(kf) = reg_ent.get("keysFile").and_then(|v| v.as_str()) {
                    let kfp = PathBuf::from(kf);
                    if let Some(rv) = load_json_if_exists(&kfp) {
                        if rv.get("masterKeyHex").and_then(|v| v.as_str()).is_some() {
                            if let Some(tsha) = target_sha.as_ref() {
                                if let Some(full_ent) =
                                    rv.get("artifacts").and_then(|a| a.get(tsha))
                                {
                                    found_entry = Some(full_ent.clone());
                                }
                            } else if let Some(sha_by_path) = rv
                                .get("byPath")
                                .and_then(|bp| bp.get(&abs_str))
                                .and_then(|v| v.as_str())
                            {
                                if let Some(full_ent) =
                                    rv.get("artifacts").and_then(|a| a.get(sha_by_path))
                                {
                                    found_entry = Some(full_ent.clone());
                                }
                            }
                            found_vault = Some(rv);
                            found_keys_path = Some(kfp);
                        }
                    }
                }
            }
        }
    }

    KnownMeta {
        abs_target,
        target_sha,
        vault: found_vault,
        keys_path: found_keys_path,
        entry: found_entry,
        reg_path,
        registry: reg,
    }
}

/* ================================ Secret Scanner ================================ */

fn is_token_char(b: u8, allow_hyphen: bool) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || (allow_hyphen && b == b'-')
}

fn find_prefixed_token(line: &str, prefix: &str, min_tail: usize, allow_hyphen: bool) -> Option<String> {
    let bytes = line.as_bytes();
    let pbytes = prefix.as_bytes();
    let mut i = 0usize;
    while i + pbytes.len() <= bytes.len() {
        if &bytes[i..i + pbytes.len()] == pbytes {
            let prev_ok = i == 0 || !is_token_char(bytes[i - 1], false);
            if prev_ok {
                let mut end = i + pbytes.len();
                while end < bytes.len() && is_token_char(bytes[end], allow_hyphen) {
                    end += 1;
                }
                let tail_len = end - (i + pbytes.len());
                if tail_len >= min_tail {
                    return Some(line[i..end].to_string());
                }
            }
        }
        i += 1;
    }
    None
}

pub fn scan_secrets_in_bytes(buf: &[u8], rel_path: &str) -> Vec<SecretWarning> {
    if buf.is_empty() {
        return Vec::new();
    }
    let sample = &buf[..buf.len().min(1024)];
    if sample.contains(&0) {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(buf);
    let mut findings = Vec::new();

    let secret_keywords = [
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "PRIVATE_KEY",
        "API_KEY",
        "AUTH_KEY",
        "MASTER_KEY",
    ];
    let placeholders = [
        "example",
        "changeme",
        "placeholder",
        "xxx",
        "dummy",
        "test_only",
        "\"\"",
        "''",
    ];

    for (idx, line) in text.lines().enumerate() {
        let line_no = idx + 1;

        if let Some(tok) = find_prefixed_token(line, "sk-proj-", 20, true)
            .or_else(|| find_prefixed_token(line, "sk-", 20, true))
        {
            findings.push(SecretWarning {
                rel_path: rel_path.to_string(),
                line: line_no,
                kind: "OpenAI API Key".to_string(),
                preview: format!("{}... (redacted)", &tok[..tok.len().min(6)]),
            });
        }

        for pfx in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
            if let Some(tok) = find_prefixed_token(line, pfx, 20, false) {
                findings.push(SecretWarning {
                    rel_path: rel_path.to_string(),
                    line: line_no,
                    kind: "GitHub Token".to_string(),
                    preview: format!("{}... (redacted)", &tok[..tok.len().min(6)]),
                });
            }
        }

        if let Some(tok) = find_prefixed_token(line, "AKIA", 16, false) {
            if tok.len() == 20 && tok[4..].bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'Z').contains(&b)) {
                findings.push(SecretWarning {
                    rel_path: rel_path.to_string(),
                    line: line_no,
                    kind: "AWS Access Key".to_string(),
                    preview: format!("{}... (redacted)", &tok[..6]),
                });
            }
        }

        if let Some(tok) = find_prefixed_token(line, "AIza", 35, true) {
            findings.push(SecretWarning {
                rel_path: rel_path.to_string(),
                line: line_no,
                kind: "Google API Key".to_string(),
                preview: format!("{}... (redacted)", &tok[..6]),
            });
        }

        if line.contains("-----BEGIN ") && line.contains("PRIVATE KEY-----") {
            findings.push(SecretWarning {
                rel_path: rel_path.to_string(),
                line: line_no,
                kind: "Private Key Block".to_string(),
                preview: "-----B... (redacted)".to_string(),
            });
        }

        let trimmed = line.trim_start();
        let after_export = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim_start();
        if let Some((lhs, rhs)) = after_export.split_once('=') {
            let key = lhs.trim();
            if !key.is_empty()
                && (key.as_bytes()[0].is_ascii_alphabetic() || key.as_bytes()[0] == b'_')
                && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                let up = key.to_ascii_uppercase();
                if secret_keywords.iter().any(|kw| up.contains(kw)) {
                    let val = rhs.trim().trim_matches('"').trim_matches('\'').trim();
                    let low = val.to_ascii_lowercase();
                    let is_ph = placeholders.iter().any(|p| low == *p)
                        || low.starts_with("your_")
                        || low.starts_with("your-")
                        || (val.starts_with('<') && val.ends_with('>'))
                        || val.starts_with("${");
                    if val.len() >= 6 && !is_ph {
                        findings.push(SecretWarning {
                            rel_path: rel_path.to_string(),
                            line: line_no,
                            kind: "Hardcoded Env Secret".to_string(),
                            preview: format!("{key}=*** (redacted)"),
                        });
                    }
                }
            }
        }
    }
    findings
}

/* =============================== File Classifier =============================== */

fn is_runnable_elf64_x86_64(buf: &[u8], file_name_lower: &str) -> bool {
    if buf.len() < 64 || &buf[0..4] != b"\x7fELF" {
        return false;
    }
    if buf[4] != 2 || buf[5] != 1 {
        return false;
    }
    let e_type = u16::from_le_bytes([buf[16], buf[17]]);
    let e_machine = u16::from_le_bytes([buf[18], buf[19]]);
    if (e_type != 2 && e_type != 3) || e_machine != 62 {
        return false;
    }
    if file_name_lower.ends_with(".node")
        || file_name_lower.ends_with(".o")
        || file_name_lower.ends_with(".a")
        || file_name_lower.ends_with(".so")
        || file_name_lower.contains(".so.")
    {
        return false;
    }
    true
}

fn is_valid_glb_header(buf: &[u8]) -> bool {
    buf.len() >= 28 && &buf[0..4] == b"glTF"
}

fn is_wasm_module(buf: &[u8], ext: &str) -> bool {
    (buf.len() >= 8 && &buf[0..4] == b"\x00asm") || ext == ".wasm"
}

fn file_ext_lower(lower_base: &str) -> &str {
    match lower_base.rfind('.') {
        Some(idx) if idx > 0 => &lower_base[idx..],
        _ => "",
    }
}

struct Classification {
    engine: &'static str,
    domain: &'static str,
    secrets: Vec<SecretWarning>,
}

fn classify_file(
    file_path: &Path,
    rel_path: &str,
    buf: &[u8],
    is_directory_mode: bool,
    seal_all: bool,
    force_vault: bool,
) -> Classification {
    let base = file_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let lower_base = base.to_ascii_lowercase();
    let ext = file_ext_lower(&lower_base);
    let secrets = scan_secrets_in_bytes(buf, rel_path);

    let is_vault_ext = matches!(ext, ".vault" | ".secret");
    if force_vault || is_vault_ext {
        if !buf.is_empty() && buf.len() <= 4096 {
            return Classification {
                engine: "freestanding-vault",
                domain: "vault",
                secrets,
            };
        }
        return Classification {
            engine: "vspk3",
            domain: "secrets",
            secrets,
        };
    }

    if is_runnable_elf64_x86_64(buf, &lower_base) {
        return Classification {
            engine: "wrap-elf",
            domain: "native",
            secrets,
        };
    }

    if is_valid_glb_header(buf) {
        return Classification {
            engine: "glb-dual",
            domain: "spatial-3d",
            secrets,
        };
    }

    if is_wasm_module(buf, ext) {
        return Classification {
            engine: "vspk3",
            domain: "wasm",
            secrets,
        };
    }

    let is_ai_ext = matches!(
        ext,
        ".safetensors" | ".onnx" | ".pt" | ".pth" | ".gguf" | ".ckpt" | ".weights" | ".f32" | ".npy" | ".npz"
    );
    let rel_norm = format!("/{}", rel_path.replace('\\', "/").to_ascii_lowercase());
    let is_model_bin = ext == ".bin"
        && (rel_norm.contains("/models/")
            || rel_norm.contains("/model/")
            || rel_norm.contains("/weights/")
            || rel_norm.contains("/weight/")
            || rel_norm.contains("/checkpoints/")
            || rel_norm.contains("/checkpoint/"));
    if is_ai_ext || is_model_bin {
        return Classification {
            engine: "vspk3",
            domain: "data-ai",
            secrets,
        };
    }

    let is_public_base = matches!(
        lower_base.as_str(),
        "license"
            | "license.md"
            | "license.txt"
            | "copying"
            | ".gitignore"
            | ".gitattributes"
            | ".editorconfig"
            | ".env.example"
            | ".env.sample"
            | ".env.template"
            | "index.html"
            | "package.json"
            | "package-lock.json"
            | "tsconfig.json"
    );
    let is_secret_ext = matches!(ext, ".pem" | ".key" | ".p12" | ".pfx");
    if (lower_base.starts_with(".env") && !is_public_base) || is_secret_ext {
        return Classification {
            engine: "vspk3",
            domain: "secrets",
            secrets,
        };
    }

    let is_public_ext = matches!(
        ext,
        ".css" | ".png" | ".jpg" | ".jpeg" | ".gif" | ".svg" | ".ico" | ".webp" | ".woff2" | ".woff" | ".ttf"
    );
    if is_directory_mode
        && !seal_all
        && secrets.is_empty()
        && (is_public_base || lower_base.starts_with("readme") || is_public_ext)
    {
        return Classification {
            engine: "copy-public",
            domain: "public",
            secrets,
        };
    }

    if !secrets.is_empty() {
        return Classification {
            engine: "vspk3",
            domain: "secrets",
            secrets,
        };
    }

    let is_code_ext = matches!(
        ext,
        ".js"
            | ".mjs"
            | ".cjs"
            | ".ts"
            | ".tsx"
            | ".jsx"
            | ".py"
            | ".go"
            | ".rs"
            | ".c"
            | ".cc"
            | ".cpp"
            | ".h"
            | ".hpp"
            | ".java"
            | ".cs"
            | ".sh"
            | ".rb"
            | ".php"
            | ".sql"
            | ".yaml"
            | ".yml"
            | ".toml"
            | ".json"
    );
    if is_code_ext {
        return Classification {
            engine: "vspk3",
            domain: "code",
            secrets,
        };
    }

    Classification {
        engine: "vspk3",
        domain: "asset",
        secrets,
    }
}

pub fn walk_repo_files(
    root_dir: &Path,
    excluded_real: &[PathBuf],
) -> Result<Vec<(PathBuf, String, u64)>, String> {
    const SKIP_DIRS: &[&str] = &[
        ".git",
        ".vibeslayer",
        "node_modules",
        "target",
        "dist_protected",
        "__pycache__",
        ".venv",
        "venv",
        ".next",
        ".cache",
    ];
    const SKIP_EXTS: &[&str] = &[
        ".vspk",
        ".vspk2",
        ".vspk3",
        ".vs3d",
        ".vsra",
        ".vsweb",
        ".protected",
        ".free_gen.c",
    ];

    fn visit(
        cur_dir: &Path,
        rel_prefix: &str,
        excluded_real: &[PathBuf],
        skip_dirs: &[&str],
        skip_exts: &[&str],
        out: &mut Vec<(PathBuf, String, u64)>,
    ) -> Result<(), String> {
        let mut entries: Vec<_> = fs::read_dir(cur_dir)
            .map_err(|e| e.to_string())?
            .filter_map(|r| r.ok())
            .collect();
        entries.sort_by(|a, b| a.file_name().cmp(&b.file_name()));

        for ent in entries {
            let name = ent.file_name().to_string_lossy().to_string();
            let full = ent.path();
            let meta = match fs::symlink_metadata(&full) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            let rel = if rel_prefix.is_empty() {
                name.clone()
            } else {
                format!("{rel_prefix}/{name}")
            };
            if meta.is_dir() {
                if skip_dirs.contains(&name.as_str()) {
                    continue;
                }
                if let Ok(real) = fs::canonicalize(&full) {
                    if excluded_real.iter().any(|ex| ex == &real) {
                        continue;
                    }
                }
                visit(&full, &rel, excluded_real, skip_dirs, skip_exts, out)?;
            } else if meta.is_file() {
                let lower = name.to_ascii_lowercase();
                if lower == "vibeslayer.manifest.json" {
                    continue;
                }
                if skip_exts.iter().any(|s| lower.ends_with(s)) {
                    continue;
                }
                out.push((full, rel.replace('\\', "/"), meta.len()));
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    visit(root_dir, "", excluded_real, SKIP_DIRS, SKIP_EXTS, &mut files)?;
    Ok(files)
}

/* =============================== Scan Command =============================== */

pub fn scan_target(input_path: &Path, opts: &CliOpts) -> Result<JsonVal, String> {
    let abs_in = abs_path_clean(input_path)?;
    if !abs_in.exists() {
        return Err(format!("Input path does not exist: {}", abs_in.display()));
    }
    let is_dir = abs_in.is_dir();
    let entries = if is_dir {
        walk_repo_files(&abs_in, &[])?
    } else {
        let len = fs::metadata(&abs_in).map_err(|e| e.to_string())?.len();
        let name = abs_in
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        vec![(abs_in.clone(), name, len)]
    };

    let mut items = Vec::new();
    let mut warnings = Vec::new();
    for (full, rel, _) in entries {
        let buf = fs::read(&full).map_err(|e| e.to_string())?;
        let cls = classify_file(&full, &rel, &buf, is_dir, opts.seal_all, opts.force_vault);
        items.push(JsonVal::obj(vec![
            ("relPath", JsonVal::Str(rel)),
            ("inputBytes", JsonVal::Int(buf.len() as i64)),
            ("engine", JsonVal::Str(cls.engine.to_string())),
            ("domain", JsonVal::Str(cls.domain.to_string())),
            (
                "secretFindingsCount",
                JsonVal::Int(cls.secrets.len() as i64),
            ),
        ]));
        for w in cls.secrets {
            warnings.push(w.to_json());
        }
    }

    Ok(JsonVal::obj(vec![
        ("ok", JsonVal::Bool(true)),
        ("mode", JsonVal::Str(if is_dir { "directory" } else { "file" }.to_string())),
        ("inputPath", JsonVal::Str(abs_in.to_string_lossy().to_string())),
        ("fileCount", JsonVal::Int(items.len() as i64)),
        ("secretWarnings", JsonVal::Arr(warnings)),
        ("items", JsonVal::Arr(items)),
    ]))
}

/* =============================== Protect Engine =============================== */

fn derive_asset_id(rel_path: &str) -> String {
    let clean = rel_path.replace('\\', "/");
    let trimmed = clean.trim_start_matches('/');
    let clipped: String = trimmed.chars().take(120).collect();
    if clipped.is_empty() {
        "asset".to_string()
    } else {
        clipped
    }
}

fn default_single_out_path(abs_in: &Path, engine: &str) -> PathBuf {
    let s = abs_in.to_string_lossy();
    if engine == "wrap-elf" {
        PathBuf::from(format!("{s}.protected"))
    } else if engine == "freestanding-vault" {
        if s.to_ascii_lowercase().ends_with(".vault") {
            PathBuf::from(format!("{s}.elf"))
        } else {
            PathBuf::from(format!("{s}.vault.elf"))
        }
    } else {
        PathBuf::from(format!("{s}.vspk3"))
    }
}

fn resolve_crypto_header_for_core() -> PathBuf {
    if let Some(ws) = detect_workspace_root() {
        let p = ws.join("vibeslayer-suite/native_src/vs_crypto_core.h");
        if p.is_file() {
            return p;
        }
    }
    PathBuf::new() // Fallback uses embedded header inside v100_zero_overhead.rs
}

struct ProtectedOne {
    meta: JsonVal,
    companion_vs3d: Option<JsonVal>,
    to_record: Vec<JsonVal>,
}

fn protect_one_file_mem(
    in_file: &Path,
    mut plain: Vec<u8>,
    rel_path: &str,
    out_path: &Path,
    cls: &Classification,
    master_key: &[u8; 32],
    keys_path: &Path,
    context: &str,
    standalone: bool,
) -> Result<ProtectedOne, String> {
    let orig_sha = sha256_hex(&plain);
    let plain_len = plain.len();
    let asset_id = derive_asset_id(rel_path);
    let orig_name = in_file
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    if let Some(p) = out_path.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }

    let warn_arr: Vec<JsonVal> = cls.secrets.iter().map(|s| s.to_json()).collect();

    if cls.engine == "copy-public" {
        fs::write(out_path, &plain).map_err(|e| e.to_string())?;
        let ent = shannon_entropy(&plain);
        secure_zero(&mut plain);
        let abs_out = abs_path_clean(out_path)?;
        return Ok(ProtectedOne {
            meta: JsonVal::obj(vec![
                ("relPath", JsonVal::Str(rel_path.to_string())),
                ("assetId", JsonVal::Str(asset_id)),
                ("domain", JsonVal::Str(cls.domain.to_string())),
                ("context", JsonVal::Str(context.to_string())),
                ("originalName", JsonVal::Str(orig_name)),
                ("originalSha256", JsonVal::Str(orig_sha.clone())),
                ("inputBytes", JsonVal::Int(plain_len as i64)),
                ("secretWarnings", JsonVal::Arr(warn_arr)),
                ("engine", JsonVal::Str("copy-public".to_string())),
                ("absOutPath", JsonVal::Str(abs_out.to_string_lossy().to_string())),
                ("outputBytes", JsonVal::Int(plain_len as i64)),
                ("outputSha256", JsonVal::Str(orig_sha)),
                ("entropyBitsPerByte", JsonVal::Num(ent)),
            ]),
            companion_vs3d: None,
            to_record: Vec::new(),
        });
    }

    if cls.engine == "wrap-elf" {
        let hdr = resolve_crypto_header_for_core();
        let (lease_hex, rx_hex) =
            wrap_elf_freestanding(master_key, &hdr, &asset_id, &plain, standalone, out_path)?;
        secure_zero(&mut plain);
        make_executable(out_path);
        let out_buf = fs::read(out_path).map_err(|e| e.to_string())?;
        let abs_out = abs_path_clean(out_path)?;
        let meta = JsonVal::obj(vec![
            ("relPath", JsonVal::Str(rel_path.to_string())),
            ("assetId", JsonVal::Str(asset_id)),
            ("domain", JsonVal::Str(cls.domain.to_string())),
            ("context", JsonVal::Str(context.to_string())),
            ("originalName", JsonVal::Str(orig_name)),
            ("originalSha256", JsonVal::Str(orig_sha)),
            ("inputBytes", JsonVal::Int(plain_len as i64)),
            ("secretWarnings", JsonVal::Arr(warn_arr)),
            ("engine", JsonVal::Str("wrap-elf".to_string())),
            ("standalone", JsonVal::Bool(standalone)),
            (
                "leaseKeyHex",
                if lease_hex.is_empty() {
                    JsonVal::Null
                } else {
                    JsonVal::Str(lease_hex)
                },
            ),
            ("rxSha256Hex", JsonVal::Str(rx_hex)),
            ("absOutPath", JsonVal::Str(abs_out.to_string_lossy().to_string())),
            ("outputBytes", JsonVal::Int(out_buf.len() as i64)),
            ("outputSha256", JsonVal::Str(sha256_hex(&out_buf))),
            ("entropyBitsPerByte", JsonVal::Num(shannon_entropy(&out_buf))),
        ]);
        return Ok(ProtectedOne {
            meta: meta.clone(),
            companion_vs3d: None,
            to_record: vec![meta],
        });
    }

    if cls.engine == "freestanding-vault" {
        let hdr = resolve_crypto_header_for_core();
        let (lease_hex, rx_hex) =
            build_protected_elf_freestanding(master_key, &hdr, &asset_id, &plain, out_path)?;
        secure_zero(&mut plain);
        make_executable(out_path);
        let out_buf = fs::read(out_path).map_err(|e| e.to_string())?;
        let abs_out = abs_path_clean(out_path)?;
        let meta = JsonVal::obj(vec![
            ("relPath", JsonVal::Str(rel_path.to_string())),
            ("assetId", JsonVal::Str(asset_id)),
            ("domain", JsonVal::Str(cls.domain.to_string())),
            ("context", JsonVal::Str(context.to_string())),
            ("originalName", JsonVal::Str(orig_name)),
            ("originalSha256", JsonVal::Str(orig_sha)),
            ("inputBytes", JsonVal::Int(plain_len as i64)),
            ("secretWarnings", JsonVal::Arr(warn_arr)),
            ("engine", JsonVal::Str("freestanding-vault".to_string())),
            ("standalone", JsonVal::Bool(false)),
            ("leaseKeyHex", JsonVal::Str(lease_hex)),
            ("rxSha256Hex", JsonVal::Str(rx_hex)),
            ("absOutPath", JsonVal::Str(abs_out.to_string_lossy().to_string())),
            ("outputBytes", JsonVal::Int(out_buf.len() as i64)),
            ("outputSha256", JsonVal::Str(sha256_hex(&out_buf))),
            ("entropyBitsPerByte", JsonVal::Num(shannon_entropy(&out_buf))),
        ]);
        return Ok(ProtectedOne {
            meta: meta.clone(),
            companion_vs3d: None,
            to_record: vec![meta],
        });
    }

    if cls.engine == "glb-dual" {
        let out_str = out_path.to_string_lossy().to_string();
        let vspk_out = if out_str.ends_with(".vs3d") {
            PathBuf::from(format!("{out_str}.vspk3"))
        } else {
            out_path.to_path_buf()
        };
        let vspk_str = vspk_out.to_string_lossy().to_string();
        let vs3d_out = if out_str.ends_with(".vs3d") {
            out_path.to_path_buf()
        } else if let Some(stem) = vspk_str.strip_suffix(".vspk3") {
            PathBuf::from(format!("{stem}.vs3d"))
        } else {
            PathBuf::from(format!("{vspk_str}.vs3d"))
        };

        let vspk_bytes = pack_vspk3(master_key, "spatial-3d", &asset_id, context, &plain)?;
        fs::write(&vspk_out, &vspk_bytes).map_err(|e| e.to_string())?;
        let abs_vspk = abs_path_clean(&vspk_out)?;
        let vspk_meta = JsonVal::obj(vec![
            ("relPath", JsonVal::Str(rel_path.to_string())),
            ("assetId", JsonVal::Str(asset_id.clone())),
            ("domain", JsonVal::Str("spatial-3d".to_string())),
            ("context", JsonVal::Str(context.to_string())),
            ("originalName", JsonVal::Str(orig_name.clone())),
            ("originalSha256", JsonVal::Str(orig_sha.clone())),
            ("inputBytes", JsonVal::Int(plain_len as i64)),
            ("secretWarnings", JsonVal::Arr(warn_arr.clone())),
            ("engine", JsonVal::Str("vspk3".to_string())),
            ("absOutPath", JsonVal::Str(abs_vspk.to_string_lossy().to_string())),
            ("outputBytes", JsonVal::Int(vspk_bytes.len() as i64)),
            ("outputSha256", JsonVal::Str(sha256_hex(&vspk_bytes))),
            ("entropyBitsPerByte", JsonVal::Num(shannon_entropy(&vspk_bytes))),
        ]);

        let ref_dir = keys_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("refs");
        fs::create_dir_all(&ref_dir).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&ref_dir, fs::Permissions::from_mode(0o700));
        }
        let asset_hash = &sha256_hex(asset_id.as_bytes())[..16];
        let owner_ref_path = ref_dir.join(format!("{asset_hash}.owner_ref.bin"));

        let (sealed_vs3d, owner_ref) = cook_glb_vspk2(master_key, &asset_id, context, &plain)?;
        secure_zero(&mut plain);
        fs::write(&vs3d_out, &sealed_vs3d).map_err(|e| e.to_string())?;
        let mut ref_bytes = Vec::with_capacity(owner_ref.len() * 2);
        for v in &owner_ref {
            ref_bytes.extend_from_slice(&v.to_le_bytes());
        }
        fs::write(&owner_ref_path, &ref_bytes).map_err(|e| e.to_string())?;
        let abs_vs3d = abs_path_clean(&vs3d_out)?;
        let abs_ref = abs_path_clean(&owner_ref_path)?;
        let vs3d_meta = JsonVal::obj(vec![
            ("relPath", JsonVal::Str(rel_path.to_string())),
            ("assetId", JsonVal::Str(asset_id)),
            ("domain", JsonVal::Str("spatial-3d".to_string())),
            ("context", JsonVal::Str(context.to_string())),
            ("originalName", JsonVal::Str(orig_name)),
            ("originalSha256", JsonVal::Str(orig_sha)),
            ("inputBytes", JsonVal::Int(plain_len as i64)),
            ("secretWarnings", JsonVal::Arr(warn_arr)),
            ("engine", JsonVal::Str("cook-glb-vs3d".to_string())),
            ("absOutPath", JsonVal::Str(abs_vs3d.to_string_lossy().to_string())),
            ("outputBytes", JsonVal::Int(sealed_vs3d.len() as i64)),
            ("coords", JsonVal::Int(owner_ref.len() as i64)),
            ("ownerRefPath", JsonVal::Str(abs_ref.to_string_lossy().to_string())),
            ("companionVspk3Path", JsonVal::Str(abs_vspk.to_string_lossy().to_string())),
            ("outputSha256", JsonVal::Str(sha256_hex(&sealed_vs3d))),
            ("entropyBitsPerByte", JsonVal::Num(shannon_entropy(&sealed_vs3d))),
        ]);
        return Ok(ProtectedOne {
            meta: vspk_meta.clone(),
            companion_vs3d: Some(vs3d_meta.clone()),
            to_record: vec![vspk_meta, vs3d_meta],
        });
    }

    // Default VSPK3
    let vspk_bytes = pack_vspk3(master_key, cls.domain, &asset_id, context, &plain)?;
    secure_zero(&mut plain);
    fs::write(out_path, &vspk_bytes).map_err(|e| e.to_string())?;
    let abs_out = abs_path_clean(out_path)?;
    let meta = JsonVal::obj(vec![
        ("relPath", JsonVal::Str(rel_path.to_string())),
        ("assetId", JsonVal::Str(asset_id)),
        ("domain", JsonVal::Str(cls.domain.to_string())),
        ("context", JsonVal::Str(context.to_string())),
        ("originalName", JsonVal::Str(orig_name)),
        ("originalSha256", JsonVal::Str(orig_sha)),
        ("inputBytes", JsonVal::Int(plain_len as i64)),
        ("secretWarnings", JsonVal::Arr(warn_arr)),
        ("engine", JsonVal::Str("vspk3".to_string())),
        ("absOutPath", JsonVal::Str(abs_out.to_string_lossy().to_string())),
        ("outputBytes", JsonVal::Int(vspk_bytes.len() as i64)),
        ("outputSha256", JsonVal::Str(sha256_hex(&vspk_bytes))),
        ("entropyBitsPerByte", JsonVal::Num(shannon_entropy(&vspk_bytes))),
    ]);
    Ok(ProtectedOne {
        meta: meta.clone(),
        companion_vs3d: None,
        to_record: vec![meta],
    })
}

fn protect_one_file(
    in_file: &Path,
    rel_path: &str,
    out_path: &Path,
    cls: &Classification,
    vault: &mut JsonVal,
    master_key: &[u8; 32],
    keys_path: &Path,
    reg_path: &Path,
    reg: &mut JsonVal,
    context: &str,
    standalone: bool,
) -> Result<ProtectedOne, String> {
    let plain = fs::read(in_file).map_err(|e| e.to_string())?;
    let one = protect_one_file_mem(
        in_file, plain, rel_path, out_path, cls, master_key, keys_path, context, standalone,
    )?;
    if !one.to_record.is_empty() {
        let keys_abs = abs_path_clean(keys_path)?;
        for m in &one.to_record {
            record_artifact_mem(vault, &keys_abs, reg, m.clone())?;
        }
        write_private_json(keys_path, vault)?;
        save_workspace_registry(reg_path, reg)?;
    }
    Ok(one)
}

pub fn protect_target(input_path: &Path, opts: &CliOpts) -> Result<JsonVal, String> {
    let abs_in = abs_path_clean(input_path)?;
    if !abs_in.exists() {
        return Err(format!("Input path does not exist: {}", abs_in.display()));
    }
    let is_dir = abs_in.is_dir();
    let context = opts
        .context
        .as_deref()
        .unwrap_or("vibeslayer:auto");
    let standalone = opts.standalone;

    let keys_path = resolve_default_keys_path(&abs_in, opts.keys_file.as_deref());
    let proj_root = if is_dir {
        abs_in.clone()
    } else {
        abs_in
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
    };
    let mut vault = load_or_create_vault(&keys_path, Some(&proj_root), is_dir, opts.no_gitignore)?;
    let mut master_key = parse_key_hex_32(
        vault
            .get("masterKeyHex")
            .and_then(|v| v.as_str())
            .ok_or("VAULT_MISSING_MASTER_KEY")?,
    )?;
    let reg_path = resolve_registry_path(opts.registry_path.as_deref());
    let mut reg = load_workspace_registry(&reg_path);

    if !is_dir {
        let plain_buf = fs::read(&abs_in).map_err(|e| e.to_string())?;
        let base_name = abs_in
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let cls = classify_file(&abs_in, &base_name, &plain_buf, false, true, opts.force_vault);
        drop(plain_buf);
        let out_path = match &opts.out_path {
            Some(p) => abs_path_clean(p)?,
            None => default_single_out_path(&abs_in, cls.engine),
        };
        if out_path == abs_in {
            secure_zero(&mut master_key);
            return Err(
                "Refusing to overwrite input file in-place; choose a different --out path."
                    .to_string(),
            );
        }
        let res = protect_one_file(
            &abs_in,
            &base_name,
            &out_path,
            &cls,
            &mut vault,
            &master_key,
            &keys_path,
            &reg_path,
            &mut reg,
            context,
            standalone,
        );
        secure_zero(&mut master_key);
        let one = res?;

        let check_opts = CliOpts {
            keys_file: Some(keys_path.clone()),
            registry_path: Some(reg_path.clone()),
            ..CliOpts::default()
        };
        let self_check = test_protected_target(&out_path, &check_opts)?;
        if self_check.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            return Err(format!("Auto-verification failed for {}", out_path.display()));
        }
        let comp_path = one
            .companion_vs3d
            .as_ref()
            .and_then(|c| c.get("absOutPath"))
            .cloned()
            .unwrap_or(JsonVal::Null);
        let warns = one
            .meta
            .get("secretWarnings")
            .cloned()
            .unwrap_or_else(|| JsonVal::Arr(Vec::new()));
        let engine = one
            .meta
            .get("engine")
            .cloned()
            .unwrap_or_else(|| JsonVal::Str(cls.engine.to_string()));
        let domain = one
            .meta
            .get("domain")
            .cloned()
            .unwrap_or_else(|| JsonVal::Str(cls.domain.to_string()));

        return Ok(JsonVal::obj(vec![
            ("ok", JsonVal::Bool(true)),
            ("mode", JsonVal::Str("file".to_string())),
            ("inputPath", JsonVal::Str(abs_in.to_string_lossy().to_string())),
            ("outputPath", JsonVal::Str(out_path.to_string_lossy().to_string())),
            ("companionVs3dPath", comp_path),
            ("keysFile", JsonVal::Str(keys_path.to_string_lossy().to_string())),
            ("engine", engine),
            ("domain", domain),
            ("standalone", JsonVal::Bool(standalone)),
            ("secretWarnings", warns),
            ("selfCheck", self_check),
            ("artifact", one.meta),
        ]));
    }

    let out_dir = match &opts.out_path {
        Some(p) => abs_path_clean(p)?,
        None => PathBuf::from(format!("{}-protected", abs_in.display())),
    };
    if out_dir == abs_in {
        secure_zero(&mut master_key);
        return Err("Output directory must differ from input directory.".to_string());
    }
    fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let abs_out_dir = fs::canonicalize(&out_dir).map_err(|e| e.to_string())?;
    let entries = walk_repo_files(&abs_in, &[abs_out_dir.clone()])?;

    let total_entries = entries.len();
    let num_threads = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(16)
        .min(total_entries.max(1));
    let next_idx = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<Result<(String, Vec<SecretWarning>, ProtectedOne), String>>>> =
        (0..total_entries).map(|_| Mutex::new(None)).collect();

    thread::scope(|s| {
        for _ in 0..num_threads {
            s.spawn(|| loop {
                let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                if idx >= total_entries {
                    break;
                }
                let (ref full, ref rel, _) = entries[idx];
                let res = (|| -> Result<(String, Vec<SecretWarning>, ProtectedOne), String> {
                    let buf = fs::read(full).map_err(|e| e.to_string())?;
                    let cls = classify_file(full, rel, &buf, true, opts.seal_all, false);
                    let dest = if cls.engine == "vspk3" || cls.engine == "glb-dual" {
                        abs_out_dir.join(format!("{rel}.vspk3"))
                    } else {
                        abs_out_dir.join(rel)
                    };
                    let one = protect_one_file_mem(
                        full,
                        buf,
                        rel,
                        &dest,
                        &cls,
                        &master_key,
                        &keys_path,
                        context,
                        standalone,
                    )?;
                    Ok((rel.clone(), cls.secrets, one))
                })();
                *slots[idx].lock().unwrap() = Some(res);
            });
        }
    });

    let mut manifest_files = Vec::with_capacity(total_entries);
    let mut all_warnings = Vec::new();
    let (mut c_total, mut c_vspk3, mut c_wrap, mut c_vault, mut c_vs3d, mut c_pub) =
        (0i64, 0i64, 0i64, 0i64, 0i64, 0i64);
    let keys_abs = abs_path_clean(&keys_path)?;
    let mut any_recorded = false;

    for idx in 0..total_entries {
        let (rel, secrets, one) = match slots[idx].lock().unwrap().take().unwrap() {
            Ok(v) => v,
            Err(e) => {
                secure_zero(&mut master_key);
                return Err(e);
            }
        };
        for w in &secrets {
            all_warnings.push(w.to_json());
        }
        for m in &one.to_record {
            if let Err(e) = record_artifact_mem(&mut vault, &keys_abs, &mut reg, m.clone()) {
                secure_zero(&mut master_key);
                return Err(e);
            }
            any_recorded = true;
        }

        c_total += 1;
        let eng = one
            .meta
            .get("engine")
            .and_then(|v| v.as_str())
            .unwrap_or("vspk3");
        match eng {
            "copy-public" => c_pub += 1,
            "wrap-elf" => c_wrap += 1,
            "freestanding-vault" => c_vault += 1,
            _ => c_vspk3 += 1,
        }

        let push_mf = |m: &JsonVal, list: &mut Vec<JsonVal>| {
            let abs_out_p = m.get("absOutPath").and_then(|v| v.as_str()).unwrap_or("");
            let out_rel = Path::new(abs_out_p)
                .strip_prefix(&abs_out_dir)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| rel.clone());
            list.push(JsonVal::obj(vec![
                ("relPath", JsonVal::Str(rel.clone())),
                ("outRelPath", JsonVal::Str(out_rel)),
                (
                    "engine",
                    m.get("engine").cloned().unwrap_or(JsonVal::Str(String::new())),
                ),
                (
                    "domain",
                    m.get("domain").cloned().unwrap_or(JsonVal::Str(String::new())),
                ),
                (
                    "assetId",
                    m.get("assetId").cloned().unwrap_or(JsonVal::Str(String::new())),
                ),
                ("context", JsonVal::Str(context.to_string())),
                (
                    "standalone",
                    JsonVal::Bool(m.get("standalone").and_then(|v| v.as_bool()).unwrap_or(false)),
                ),
                (
                    "inputBytes",
                    m.get("inputBytes").cloned().unwrap_or(JsonVal::Int(0)),
                ),
                (
                    "outputBytes",
                    m.get("outputBytes").cloned().unwrap_or(JsonVal::Int(0)),
                ),
                (
                    "outputSha256",
                    m.get("outputSha256").cloned().unwrap_or(JsonVal::Str(String::new())),
                ),
                (
                    "entropyBitsPerByte",
                    m.get("entropyBitsPerByte").cloned().unwrap_or(JsonVal::Num(0.0)),
                ),
            ]));
        };
        push_mf(&one.meta, &mut manifest_files);
        if let Some(ref c3d) = one.companion_vs3d {
            c_vs3d += 1;
            push_mf(c3d, &mut manifest_files);
        }
    }
    secure_zero(&mut master_key);
    if any_recorded {
        write_private_json(&keys_path, &vault)?;
        save_workspace_registry(&reg_path, &reg)?;
    }

    let counts = JsonVal::obj(vec![
        ("total", JsonVal::Int(c_total)),
        ("vspk3", JsonVal::Int(c_vspk3)),
        ("wrapElf", JsonVal::Int(c_wrap)),
        ("freestandingVault", JsonVal::Int(c_vault)),
        ("vs3d", JsonVal::Int(c_vs3d)),
        ("publicCopied", JsonVal::Int(c_pub)),
    ]);

    let manifest_path = abs_out_dir.join("vibeslayer.manifest.json");
    let manifest_doc = JsonVal::obj(vec![
        ("version", JsonVal::Str("1.0.0-beta.3".to_string())),
        ("context", JsonVal::Str(context.to_string())),
        ("standalone", JsonVal::Bool(standalone)),
        ("counts", counts.clone()),
        ("files", JsonVal::Arr(manifest_files)),
    ]);
    fs::write(&manifest_path, to_json_pretty(&manifest_doc).as_bytes())
        .map_err(|e| e.to_string())?;

    let self_check = test_protected_dir_loaded(
        &abs_out_dir,
        &manifest_doc,
        Some(&vault),
        Some(&keys_path),
        Some(&reg_path),
    )?;
    if self_check.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return Err(format!(
            "Auto-verification failed for directory {}",
            abs_out_dir.display()
        ));
    }

    Ok(JsonVal::obj(vec![
        ("ok", JsonVal::Bool(true)),
        ("mode", JsonVal::Str("directory".to_string())),
        ("inputPath", JsonVal::Str(abs_in.to_string_lossy().to_string())),
        ("outputDir", JsonVal::Str(abs_out_dir.to_string_lossy().to_string())),
        ("manifestPath", JsonVal::Str(manifest_path.to_string_lossy().to_string())),
        ("keysFile", JsonVal::Str(keys_path.to_string_lossy().to_string())),
        ("counts", counts),
        ("secretWarnings", JsonVal::Arr(all_warnings)),
        ("selfCheck", self_check),
    ]))
}

/* =============================== Self-Test Engine =============================== */

fn inspect_elf_hardening(buf: &[u8]) -> (bool, bool, bool, bool) {
    if buf.len() < 64 || &buf[0..4] != b"\x7fELF" {
        return (false, false, false, false);
    }
    let e_phoff = u64::from_le_bytes(buf[32..40].try_into().unwrap()) as usize;
    let e_shoff = u64::from_le_bytes(buf[40..48].try_into().unwrap()) as usize;
    let e_phentsize = u16::from_le_bytes([buf[54], buf[55]]) as usize;
    let e_phnum = u16::from_le_bytes([buf[56], buf[57]]) as usize;
    let e_shentsize = u16::from_le_bytes([buf[58], buf[59]]) as usize;
    let e_shnum = u16::from_le_bytes([buf[60], buf[61]]) as usize;

    let mut has_interp = false;
    let mut cet_feat = 0u32;

    for i in 0..e_phnum {
        let Some(off) = e_phoff.checked_add(i * e_phentsize) else { break };
        let Some(ph) = buf.get(off..off + 56) else { break };
        let p_type = u32::from_le_bytes(ph[0..4].try_into().unwrap());
        let p_offset = u64::from_le_bytes(ph[8..16].try_into().unwrap()) as usize;
        let p_filesz = u64::from_le_bytes(ph[32..40].try_into().unwrap()) as usize;
        if p_type == 3 {
            has_interp = true;
        } else if p_type == 4 {
            if let Some(note_sec) = buf.get(p_offset..p_offset.saturating_add(p_filesz)) {
                cet_feat |= extract_cet_feature_bits(note_sec);
            }
        }
    }

    let mut has_relocs = false;
    for i in 0..e_shnum {
        let Some(off) = e_shoff.checked_add(i * e_shentsize) else { break };
        let Some(sh) = buf.get(off..off + 64) else { break };
        let sh_type = u32::from_le_bytes(sh[4..8].try_into().unwrap());
        let sh_offset = u64::from_le_bytes(sh[24..32].try_into().unwrap()) as usize;
        let sh_size = u64::from_le_bytes(sh[32..40].try_into().unwrap()) as usize;
        if (sh_type == 4 || sh_type == 9) && sh_size > 0 {
            has_relocs = true;
        } else if sh_type == 7 {
            if let Some(note_sec) = buf.get(sh_offset..sh_offset.saturating_add(sh_size)) {
                cet_feat |= extract_cet_feature_bits(note_sec);
            }
        }
    }

    let clean_strings = !buf.windows(11).any(|w| w == b"VS_LEASE_FD")
        && !buf.windows(17).any(|w| w == b"/proc/self/status")
        && !buf.windows(9).any(|w| w == b"TracerPid");

    (!has_interp, !has_relocs, (cet_feat & 0x3) == 0x3, clean_strings)
}

fn extract_cet_feature_bits(note_bytes: &[u8]) -> u32 {
    let mut feats = 0u32;
    let mut pos = 0usize;
    while pos + 12 <= note_bytes.len() {
        let n_namesz = u32::from_le_bytes(note_bytes[pos..pos + 4].try_into().unwrap()) as usize;
        let n_descsz = u32::from_le_bytes(note_bytes[pos + 4..pos + 8].try_into().unwrap()) as usize;
        let n_type = u32::from_le_bytes(note_bytes[pos + 8..pos + 12].try_into().unwrap());
        let name_off = pos + 12;
        let name_end = match name_off.checked_add(n_namesz) {
            Some(v) if v <= note_bytes.len() => v,
            _ => break,
        };
        let desc_off = (name_end + 7) & !7;
        let desc_off_4 = (name_end + 3) & !3;
        let actual_desc_off = if desc_off + n_descsz <= note_bytes.len() && &note_bytes[name_off..name_end] == b"GNU\0" && n_type == 5 {
            desc_off
        } else {
            desc_off_4
        };
        let Some(desc_end) = actual_desc_off.checked_add(n_descsz) else { break };
        if desc_end > note_bytes.len() {
            break;
        }
        if &note_bytes[name_off..name_end] == b"GNU\0" && n_type == 5 {
            let desc = &note_bytes[actual_desc_off..desc_end];
            let mut dpos = 0usize;
            while dpos + 8 <= desc.len() {
                let pr_type = u32::from_le_bytes(desc[dpos..dpos + 4].try_into().unwrap());
                let pr_datasz = u32::from_le_bytes(desc[dpos + 4..dpos + 8].try_into().unwrap()) as usize;
                let data_off = dpos + 8;
                if data_off + pr_datasz > desc.len() {
                    break;
                }
                if pr_type == 0xc000_0002 && pr_datasz >= 4 {
                    feats |= u32::from_le_bytes(desc[data_off..data_off + 4].try_into().unwrap());
                }
                dpos = (data_off + pr_datasz + 7) & !7;
            }
        }
        pos = if n_type == 5 && &note_bytes[name_off..name_end] == b"GNU\0" {
            (desc_end + 7) & !7
        } else {
            (desc_end + 3) & !3
        };
    }
    feats
}

/* Serialize temporary executable writes against child-process fork/exec windows
 * so parallel test threads cannot inherit a transient O_WRONLY fd and trigger ETXTBSY. */
static EXEC_SPAWN_LOCK: RwLock<()> = RwLock::new(());

fn write_executable_synced(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let _write_guard = EXEC_SPAWN_LOCK.write().unwrap_or_else(|e| e.into_inner());
    fs::write(path, bytes).map_err(|e| e.to_string())?;
    make_executable(path);
    Ok(())
}

fn run_status_code_synced(exe_path: &Path, args: &[String]) -> i32 {
    for _ in 0..50 {
        let res = {
            let _exec_guard = EXEC_SPAWN_LOCK.read().unwrap_or_else(|e| e.into_inner());
            Command::new(exe_path)
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
        };
        match res {
            Ok(s) => return s.code().unwrap_or(99),
            Err(e) if e.raw_os_error() == Some(26) => thread::sleep(Duration::from_millis(1)),
            Err(_) => return 99,
        }
    }
    99
}

#[cfg(target_os = "linux")]
fn run_ptrace_attach_check(exe_path: &Path, args: &[String]) -> Option<bool> {
    use std::ffi::CString;
    use std::os::raw::c_char;
    extern "C" {
        fn fork() -> i32;
        fn ptrace(req: u32, pid: i32, addr: usize, data: usize) -> isize;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn execv(path: *const c_char, argv: *const *const c_char) -> i32;
        fn _exit(status: i32) -> !;
    }
    const PTRACE_TRACEME: u32 = 0;
    const PTRACE_CONT: u32 = 7;

    let c_exe = CString::new(exe_path.to_string_lossy().as_bytes()).ok()?;
    let mut c_args = Vec::with_capacity(1 + args.len());
    c_args.push(c_exe.clone());
    for a in args {
        c_args.push(CString::new(a.as_bytes()).ok()?);
    }
    let mut ptrs: Vec<*const c_char> = c_args.iter().map(|s| s.as_ptr()).collect();
    ptrs.push(std::ptr::null());

    let _exec_guard = EXEC_SPAWN_LOCK.read().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let pid = fork();
        if pid < 0 {
            return None;
        }
        if pid == 0 {
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            execv(c_exe.as_ptr(), ptrs.as_ptr());
            _exit(127);
        }
        let mut status: i32 = 0;
        if waitpid(pid, &mut status, 0) < 0 {
            return None;
        }
        // WIFSTOPPED: (status & 0xff) == 0x7f
        while (status & 0xff) == 0x7f {
            ptrace(PTRACE_CONT, pid, 0, 0);
            if waitpid(pid, &mut status, 0) < 0 {
                return None;
            }
        }
        // WIFEXITED: (status & 0x7f) == 0; exit code = (status >> 8) & 0xff
        let rc = if (status & 0x7f) == 0 {
            (status >> 8) & 0xff
        } else {
            99
        };
        Some(rc != 0)
    }
}

#[cfg(not(target_os = "linux"))]
fn run_ptrace_attach_check(_exe_path: &Path, _args: &[String]) -> Option<bool> {
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn test_freestanding_elf(file_path: &Path, buf: &[u8], entry: Option<&JsonVal>) -> Result<JsonVal, String> {
    let abs_file = abs_path_clean(file_path)?;
    let ent = shannon_entropy(buf);
    let entropy_ok = ent >= 5.5;
    let (no_pt_interp, no_relocs, cet_enabled, clean_strings) = inspect_elf_hardening(buf);

    let mut checks = vec![
        ("entropyBitsPerByte", JsonVal::Num(ent)),
        ("entropyOk", JsonVal::Bool(entropy_ok)),
        ("noPtInterp", JsonVal::Bool(no_pt_interp)),
        ("noRelocations", JsonVal::Bool(no_relocs)),
        ("cetEnabled", JsonVal::Bool(cet_enabled)),
        ("cleanStrings", JsonVal::Bool(clean_strings)),
    ];

    let engine = entry
        .and_then(|e| e.get("engine"))
        .and_then(|v| v.as_str())
        .unwrap_or("freestanding-elf");
    let lease_key = entry
        .and_then(|e| e.get("leaseKeyHex"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    let is_standalone = entry
        .and_then(|e| e.get("standalone"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let has_run_key = is_standalone || lease_key.is_some();

    let tmp_dir = env::temp_dir().join(format!(
        "vs-verify-elf-{}-{}",
        std::process::id(),
        sha256_hex(abs_file.to_string_lossy().as_bytes())[..16].to_string()
    ));
    fs::create_dir_all(&tmp_dir).map_err(|e| e.to_string())?;

    if !is_standalone && entry.is_some() {
        let zero_key = "0".repeat(64);
        let wrong_args: Vec<String> = if engine == "wrap-elf" {
            vec!["--vs-key".to_string(), zero_key]
        } else {
            vec![zero_key]
        };
        let st = run_status_code_synced(&abs_file, &wrong_args);
        checks.push(("wrongKeyRejected", JsonVal::Bool(st == 2 || st == 3)));
    }

    if has_run_key {
        let mut run_args: Vec<String> = Vec::new();
        if let Some(ref lk) = lease_key {
            if engine == "wrap-elf" {
                run_args.push("--vs-key".to_string());
            }
            run_args.push(lk.clone());
        }

        let ro_marker = [0x98, 0x2f, 0x8a, 0x42, 0x91, 0x44, 0x37, 0x71];
        let mut tamper_ro_ok = true;
        if let Some(pos) = find_subslice(buf, &ro_marker) {
            let mut tampered = buf.to_vec();
            tampered[pos] ^= 0x01;
            let tp = tmp_dir.join("tamper_ro");
            write_executable_synced(&tp, &tampered)?;
            let rc = run_status_code_synced(&tp, &run_args);
            tamper_ro_ok = rc == 3;
        }
        checks.push(("tamperRoRejected", JsonVal::Bool(tamper_ro_ok)));

        if engine == "wrap-elf" && buf.len() > 32 {
            let mut tampered_ct = buf.to_vec();
            let idx = tampered_ct.len() - 17;
            tampered_ct[idx] ^= 0x01;
            let tp = tmp_dir.join("tamper_ct");
            write_executable_synced(&tp, &tampered_ct)?;
            let rc = run_status_code_synced(&tp, &run_args);
            checks.push(("tamperPayloadRejected", JsonVal::Bool(rc == 3)));
        }

        if let Some(pt_ok) = run_ptrace_attach_check(&abs_file, &run_args) {
            checks.push(("ptraceRejected", JsonVal::Bool(pt_ok)));
        }

        if engine == "freestanding-vault" && lease_key.is_some() {
            let extra_env = vec![("LD_PRELOAD".to_string(), "/nonexistent_vibeslayer_evil.so".to_string())];
            let (rc, stdout_s, _) = run_protected_capture(&abs_file, &[], lease_key.as_deref(), is_standalone, &extra_env)?;
            if rc == 0 {
                let parsed = parse_json(stdout_s.trim())?;
                let dmp_zero = parsed.get("dumpable").and_then(|v| v.as_i64()) == Some(0);
                let sec_ok = matches!(
                    parsed.get("secretmem").and_then(|v| v.as_i64()),
                    Some(0) | Some(1)
                );
                let orig_sha = entry.and_then(|e| e.get("originalSha256")).and_then(|v| v.as_str());
                let p_sha = parsed.get("payloadSha256").and_then(|v| v.as_str());
                let sha_ok = match (orig_sha, p_sha) {
                    (Some(es), Some(ps)) if !es.is_empty() => es == ps,
                    _ => true,
                };
                checks.push(("dumpableZero", JsonVal::Bool(dmp_zero)));
                checks.push(("memfdSecretActive", JsonVal::Bool(sec_ok)));
                checks.push(("payloadSha256Match", JsonVal::Bool(sha_ok)));
            } else {
                checks.push(("vaultExecOk", JsonVal::Bool(false)));
            }
        }
    }

    let _ = fs::remove_dir_all(&tmp_dir);
    let ok = checks
        .iter()
        .all(|(_, v)| v.as_bool().unwrap_or(true));
    Ok(JsonVal::obj(vec![
        ("ok", JsonVal::Bool(ok)),
        ("type", JsonVal::Str(engine.to_string())),
        ("checks", JsonVal::obj(checks)),
    ]))
}

fn test_vspk3_file(
    buf: &[u8],
    entry: Option<&JsonVal>,
    vault: Option<&JsonVal>,
) -> Result<JsonVal, String> {
    let ent = shannon_entropy(buf);
    let no_plain = !buf.windows(4).any(|w| w == b"\x00asm" || w == b"glTF")
        && !buf.windows(16).any(|w| w == b"PRIVATE KEY-----")
        && !buf.windows(5).any(|w| w == b"VSPK1" || w == b"VSPK2");

    let mut checks = vec![
        ("entropyBitsPerByte", JsonVal::Num(ent)),
        ("entropyOk", JsonVal::Bool(ent >= 7.0)),
        ("noPlaintextMagic", JsonVal::Bool(no_plain)),
    ];

    if let (Some(v), Some(e)) = (vault, entry) {
        if let (Some(mk_hex), Some(asset_id)) = (
            v.get("masterKeyHex").and_then(|x| x.as_str()),
            e.get("assetId").and_then(|x| x.as_str()),
        ) {
            let mut mk = parse_key_hex_32(mk_hex)?;
            let domain = e.get("domain").and_then(|x| x.as_str()).unwrap_or("asset");
            let ctx = e.get("context").and_then(|x| x.as_str()).unwrap_or("");

            let mut tampered = buf.to_vec();
            if tampered.len() >= 17 {
                let idx = tampered.len() - 17;
                tampered[idx] ^= 0x01;
            }
            checks.push((
                "tamperRejected",
                JsonVal::Bool(unseal_vspk3(&mk, domain, asset_id, ctx, &tampered).is_err()),
            ));

            let wrong_asset = format!("{asset_id}__wrong");
            checks.push((
                "wrongAssetRejected",
                JsonVal::Bool(unseal_vspk3(&mk, domain, &wrong_asset, ctx, buf).is_err()),
            ));

            let round_ok = match unseal_vspk3(&mk, domain, asset_id, ctx, buf) {
                Ok(mut rec) => {
                    let rec_sha = sha256_hex(&rec);
                    secure_zero(&mut rec);
                    match e.get("originalSha256").and_then(|x| x.as_str()) {
                        Some(exp) if !exp.is_empty() => rec_sha == exp,
                        _ => true,
                    }
                }
                Err(_) => false,
            };
            secure_zero(&mut mk);
            checks.push(("roundTripUnsealOk", JsonVal::Bool(round_ok)));
        }
    }

    let ok = checks.iter().all(|(_, v)| v.as_bool().unwrap_or(true));
    Ok(JsonVal::obj(vec![
        ("ok", JsonVal::Bool(ok)),
        ("type", JsonVal::Str("vspk3".to_string())),
        ("checks", JsonVal::obj(checks)),
    ]))
}

fn test_vs3d_file(
    buf: &[u8],
    entry: Option<&JsonVal>,
    vault: Option<&JsonVal>,
) -> Result<JsonVal, String> {
    let ent = shannon_entropy(buf);
    let no_plain = !buf.windows(4).any(|w| w == b"glTF" || w == b"VS3D");
    let mut checks = vec![
        ("entropyBitsPerByte", JsonVal::Num(ent)),
        ("entropyOk", JsonVal::Bool(ent >= 7.0)),
        ("noPlainGlbLeaked", JsonVal::Bool(no_plain)),
    ];

    if let (Some(v), Some(e)) = (vault, entry) {
        if let (Some(mk_hex), Some(asset_id), Some(ref_path_s)) = (
            v.get("masterKeyHex").and_then(|x| x.as_str()),
            e.get("assetId").and_then(|x| x.as_str()),
            e.get("ownerRefPath").and_then(|x| x.as_str()),
        ) {
            let ref_path = Path::new(ref_path_s);
            if ref_path.is_file() {
                let mut mk = parse_key_hex_32(mk_hex)?;
                let ctx = e.get("context").and_then(|x| x.as_str()).unwrap_or("");
                let wm_id: u64 = 0xcafe_2026_dead_beef;
                let mut positions = embed_wm64_for_lease(&mk, asset_id, ctx, wm_id, buf)?;
                for (i, p) in positions.iter_mut().enumerate() {
                    let delta = if (i % 3) == 0 { 2 } else { -2 };
                    *p = (*p as i32 + delta).clamp(-32767, 32767) as i16;
                }
                let owner_bytes = fs::read(ref_path).map_err(|err| err.to_string())?;
                let mut owner_ref = Vec::with_capacity(owner_bytes.len() / 2);
                for ch in owner_bytes.chunks_exact(2) {
                    owner_ref.push(i16::from_le_bytes([ch[0], ch[1]]));
                }
                let (dec_id, conf) = decode_wm64_o1(&mk, asset_id, &owner_ref, &positions)?;
                secure_zero(&mut mk);
                checks.push((
                    "wm64SurvivesNoise",
                    JsonVal::Bool(dec_id == wm_id && conf >= 0.45),
                ));
            }
        }
    }

    let ok = checks.iter().all(|(_, v)| v.as_bool().unwrap_or(true));
    Ok(JsonVal::obj(vec![
        ("ok", JsonVal::Bool(ok)),
        ("type", JsonVal::Str("vs3d".to_string())),
        ("checks", JsonVal::obj(checks)),
    ]))
}

fn lookup_entry_in_memory(
    abs_file: &Path,
    file_sha: &str,
    map_doc: Option<&JsonVal>,
) -> Option<JsonVal> {
    let doc = map_doc?;
    if let Some(ent) = doc.get("artifacts").and_then(|a| a.get(file_sha)) {
        return Some(ent.clone());
    }
    let abs_str = abs_file.to_string_lossy().to_string();
    let sk = doc
        .get("byPath")
        .and_then(|bp| bp.get(&abs_str))
        .and_then(|x| x.as_str())?;
    doc.get("artifacts").and_then(|a| a.get(sk)).cloned()
}

fn test_protected_dir_loaded(
    abs_target: &Path,
    manifest: &JsonVal,
    vault: Option<&JsonVal>,
    keys_opt: Option<&Path>,
    reg_opt: Option<&Path>,
) -> Result<JsonVal, String> {
    let files = manifest
        .get("files")
        .and_then(|v| v.as_arr())
        .ok_or("MALFORMED_MANIFEST_FILES")?;

    let total_files = files.len();
    let num_threads = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(16)
        .min(total_files.max(1));
    let next_idx = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<Result<JsonVal, String>>>> =
        (0..total_files).map(|_| Mutex::new(None)).collect();

    thread::scope(|s| {
        for _ in 0..num_threads {
            s.spawn(|| loop {
                let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                if idx >= total_files {
                    break;
                }
                let mf = &files[idx];
                let res = (|| -> Result<JsonVal, String> {
                    let out_rel = mf.get("outRelPath").and_then(|v| v.as_str()).unwrap_or("");
                    let engine = mf.get("engine").and_then(|v| v.as_str()).unwrap_or("vspk3");
                    let f_path = abs_target.join(out_rel);
                    if !f_path.is_file() {
                        return Ok(JsonVal::obj(vec![
                            ("relPath", JsonVal::Str(out_rel.to_string())),
                            ("ok", JsonVal::Bool(false)),
                            ("error", JsonVal::Str("MISSING_FILE".to_string())),
                        ]));
                    }
                    if engine == "copy-public" {
                        return Ok(JsonVal::obj(vec![
                            ("relPath", JsonVal::Str(out_rel.to_string())),
                            ("ok", JsonVal::Bool(true)),
                            ("type", JsonVal::Str("copy-public".to_string())),
                        ]));
                    }
                    let buf = fs::read(&f_path).map_err(|e| e.to_string())?;
                    let file_sha = sha256_hex(&buf);
                    let mem_entry = lookup_entry_in_memory(&f_path, &file_sha, vault);
                    let fallback_ctx;
                    let (entry_ref, vault_ref) = if mem_entry.is_some() {
                        (mem_entry.as_ref(), vault)
                    } else {
                        fallback_ctx = resolve_known_metadata(&f_path, keys_opt, reg_opt);
                        (fallback_ctx.entry.as_ref(), fallback_ctx.vault.as_ref().or(vault))
                    };
                    let mut rep = if engine == "wrap-elf" || engine == "freestanding-vault" {
                        test_freestanding_elf(&f_path, &buf, entry_ref)?
                    } else if engine == "cook-glb-vs3d" {
                        test_vs3d_file(&buf, entry_ref, vault_ref)?
                    } else {
                        test_vspk3_file(&buf, entry_ref, vault_ref)?
                    };
                    rep.insert("relPath", JsonVal::Str(out_rel.to_string()));
                    Ok(rep)
                })();
                *slots[idx].lock().unwrap() = Some(res);
            });
        }
    });

    let mut reports = Vec::with_capacity(total_files);
    let mut all_ok = total_files > 0;
    for idx in 0..total_files {
        let rep = slots[idx].lock().unwrap().take().unwrap()?;
        if rep.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            all_ok = false;
        }
        reports.push(rep);
    }

    Ok(JsonVal::obj(vec![
        ("ok", JsonVal::Bool(all_ok)),
        ("mode", JsonVal::Str("directory".to_string())),
        ("targetPath", JsonVal::Str(abs_target.to_string_lossy().to_string())),
        ("testedCount", JsonVal::Int(reports.len() as i64)),
        ("files", JsonVal::Arr(reports)),
    ]))
}

pub fn test_protected_target(target_path: &Path, opts: &CliOpts) -> Result<JsonVal, String> {
    let ctx = resolve_known_metadata(
        target_path,
        opts.keys_file.as_deref(),
        opts.registry_path.as_deref(),
    );
    let abs_target = &ctx.abs_target;
    if !abs_target.exists() {
        return Err(format!("Protected target does not exist: {}", abs_target.display()));
    }
    if !abs_target.is_dir() {
        let buf = fs::read(abs_target).map_err(|e| e.to_string())?;
        let base_lower = abs_target
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_ascii_lowercase();
        let mut rep = if is_runnable_elf64_x86_64(&buf, &base_lower) {
            test_freestanding_elf(abs_target, &buf, ctx.entry.as_ref())?
        } else if base_lower.ends_with(".vs3d")
            || ctx
                .entry
                .as_ref()
                .and_then(|e| e.get("engine"))
                .and_then(|v| v.as_str())
                == Some("cook-glb-vs3d")
        {
            test_vs3d_file(&buf, ctx.entry.as_ref(), ctx.vault.as_ref())?
        } else {
            test_vspk3_file(&buf, ctx.entry.as_ref(), ctx.vault.as_ref())?
        };
        rep.insert("mode", JsonVal::Str("file".to_string()));
        rep.insert(
            "targetPath",
            JsonVal::Str(abs_target.to_string_lossy().to_string()),
        );
        return Ok(rep);
    }

    let manifest_path = abs_target.join("vibeslayer.manifest.json");
    let manifest = load_json_if_exists(&manifest_path).ok_or_else(|| {
        format!(
            "No vibeslayer.manifest.json found in directory: {}",
            abs_target.display()
        )
    })?;
    test_protected_dir_loaded(
        abs_target,
        &manifest,
        ctx.vault.as_ref(),
        ctx.keys_path.as_deref().or(opts.keys_file.as_deref()),
        opts.registry_path.as_deref(),
    )
}

/* =============================== FD 3 Runner =============================== */

#[cfg(unix)]
fn spawn_with_fd3(
    exe: &Path,
    pass_args: &[String],
    lease_key_hex: Option<&str>,
    standalone: bool,
    extra_env: &[(String, String)],
    inherit_stdio: bool,
) -> Result<(i32, String, String), String> {
    use std::os::unix::process::CommandExt;

    extern "C" {
        #[cfg(target_os = "linux")]
        fn pipe2(fds: *mut i32, flags: i32) -> i32;
        #[cfg(not(target_os = "linux"))]
        fn pipe(fds: *mut i32) -> i32;
        fn dup2(oldfd: i32, newfd: i32) -> i32;
        fn close(fd: i32) -> i32;
        fn write(fd: i32, buf: *const u8, count: usize) -> isize;
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    }
    const F_SETFD: i32 = 2;
    #[cfg(not(target_os = "linux"))]
    const FD_CLOEXEC: i32 = 1;
    #[cfg(target_os = "linux")]
    const O_CLOEXEC_LINUX: i32 = 0x80000;

    if standalone {
        let mut cmd = Command::new(exe);
        cmd.args(pass_args);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        if inherit_stdio {
            let st = {
                let _exec_guard = EXEC_SPAWN_LOCK.read().unwrap_or_else(|e| e.into_inner());
                cmd.status()
            }
            .map_err(|e| e.to_string())?;
            return Ok((st.code().unwrap_or(1), String::new(), String::new()));
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = {
            let _exec_guard = EXEC_SPAWN_LOCK.read().unwrap_or_else(|e| e.into_inner());
            cmd.spawn()
        }
        .map_err(|e| e.to_string())?;
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        return Ok((
            out.status.code().unwrap_or(1),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        ));
    }

    let lk = lease_key_hex.ok_or_else(|| {
        format!(
            "No lease key found for {}. Pass --keys <path/to/.vibeslayer/keys.json> or rebuild with --standalone.",
            exe.display()
        )
    })?;

    let exec_guard = EXEC_SPAWN_LOCK.read().unwrap_or_else(|e| e.into_inner());
    let mut fds = [-1i32; 2];
    unsafe {
        #[cfg(target_os = "linux")]
        if pipe2(fds.as_mut_ptr(), O_CLOEXEC_LINUX) != 0 {
            return Err("PIPE_CREATE_FAILED".to_string());
        }
        #[cfg(not(target_os = "linux"))]
        {
            if pipe(fds.as_mut_ptr()) != 0 {
                return Err("PIPE_CREATE_FAILED".to_string());
            }
            fcntl(fds[0], F_SETFD, FD_CLOEXEC);
            fcntl(fds[1], F_SETFD, FD_CLOEXEC);
        }
        let bytes = lk.as_bytes();
        let mut written = 0usize;
        while written < bytes.len() {
            let n = write(fds[1], bytes[written..].as_ptr(), bytes.len() - written);
            if n <= 0 {
                close(fds[0]);
                close(fds[1]);
                return Err("PIPE_WRITE_FAILED".to_string());
            }
            written += n as usize;
        }
        close(fds[1]);
    }
    let read_fd = fds[0];

    let mut cmd = Command::new(exe);
    cmd.args(pass_args);
    cmd.env("VS_LEASE_FD", "3");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    if inherit_stdio {
        cmd.stdin(Stdio::inherit());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
    } else {
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
    }
    unsafe {
        cmd.pre_exec(move || {
            if dup2(read_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if fcntl(3, F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if read_fd != 3 {
                close(read_fd);
            }
            Ok(())
        });
    }

    let child_res = cmd.spawn();
    unsafe {
        close(read_fd);
    }
    drop(exec_guard);
    let child = child_res.map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    Ok((
        out.status.code().unwrap_or(1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    ))
}

#[cfg(not(unix))]
fn spawn_with_fd3(
    exe: &Path,
    pass_args: &[String],
    lease_key_hex: Option<&str>,
    standalone: bool,
    extra_env: &[(String, String)],
    inherit_stdio: bool,
) -> Result<(i32, String, String), String> {
    let mut cmd = Command::new(exe);
    if !standalone {
        if let Some(lk) = lease_key_hex {
            cmd.arg("--vs-key").arg(lk);
        } else {
            return Err("No lease key found for executable".to_string());
        }
    }
    cmd.args(pass_args);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    if inherit_stdio {
        let st = {
            let _exec_guard = EXEC_SPAWN_LOCK.read().unwrap_or_else(|e| e.into_inner());
            cmd.status()
        }
        .map_err(|e| e.to_string())?;
        return Ok((st.code().unwrap_or(1), String::new(), String::new()));
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = {
        let _exec_guard = EXEC_SPAWN_LOCK.read().unwrap_or_else(|e| e.into_inner());
        cmd.spawn()
    }
    .map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    Ok((
        out.status.code().unwrap_or(1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    ))
}

fn run_protected_capture(
    exe: &Path,
    pass_args: &[String],
    lease_key_hex: Option<&str>,
    standalone: bool,
    extra_env: &[(String, String)],
) -> Result<(i32, String, String), String> {
    spawn_with_fd3(exe, pass_args, lease_key_hex, standalone, extra_env, false)
}

pub fn spawn_protected(
    target_path: &Path,
    pass_args: &[String],
    opts: &CliOpts,
) -> Result<i32, String> {
    let ctx = resolve_known_metadata(
        target_path,
        opts.keys_file.as_deref(),
        opts.registry_path.as_deref(),
    );
    if !ctx.abs_target.exists() {
        return Err(format!("Executable not found: {}", ctx.abs_target.display()));
    }
    let standalone = ctx
        .entry
        .as_ref()
        .and_then(|e| e.get("standalone"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let lease_key = ctx
        .entry
        .as_ref()
        .and_then(|e| e.get("leaseKeyHex"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    let (code, _, _) = spawn_with_fd3(&ctx.abs_target, pass_args, lease_key, standalone, &[], true)?;
    Ok(code)
}

/* =============================== Unseal Engine =============================== */

pub fn unseal_target(target_path: &Path, opts: &CliOpts) -> Result<JsonVal, String> {
    let ctx = resolve_known_metadata(
        target_path,
        opts.keys_file.as_deref(),
        opts.registry_path.as_deref(),
    );
    let abs_target = &ctx.abs_target;
    if !abs_target.exists() {
        return Err(format!(
            "Protected target does not exist: {}",
            abs_target.display()
        ));
    }

    if !abs_target.is_dir() {
        let vault = ctx.vault.ok_or_else(|| {
            format!(
                "No keys/metadata found for {}. Pass --keys <path/to/.vibeslayer/keys.json>.",
                abs_target.display()
            )
        })?;
        let entry = ctx.entry.ok_or_else(|| {
            format!(
                "No keys/metadata found for {}. Pass --keys <path/to/.vibeslayer/keys.json>.",
                abs_target.display()
            )
        })?;
        let engine = entry.get("engine").and_then(|v| v.as_str()).unwrap_or("");
        if engine != "vspk3" {
            return Err(format!(
                "{} is a hardened executable ({engine}). Run it with './vibe-slayer run' instead of unsealing to disk.",
                abs_target.display()
            ));
        }
        let mk_hex = vault
            .get("masterKeyHex")
            .and_then(|v| v.as_str())
            .ok_or("VAULT_MISSING_MASTER_KEY")?;
        let mut mk = parse_key_hex_32(mk_hex)?;
        let domain = entry.get("domain").and_then(|v| v.as_str()).unwrap_or("asset");
        let asset_id = entry
            .get("assetId")
            .and_then(|v| v.as_str())
            .ok_or("ENTRY_MISSING_ASSET_ID")?;
        let context = entry.get("context").and_then(|v| v.as_str()).unwrap_or("");
        let blob = fs::read(abs_target).map_err(|e| e.to_string())?;
        let res = unseal_vspk3(&mk, domain, asset_id, context, &blob);
        secure_zero(&mut mk);
        let mut plain = res?;

        let out_path = match &opts.out_path {
            Some(p) => abs_path_clean(p)?,
            None => {
                let s = abs_target.to_string_lossy();
                if let Some(stem) = s.strip_suffix(".vspk3") {
                    PathBuf::from(format!("{stem}.unsealed"))
                } else {
                    PathBuf::from(format!("{s}.unsealed"))
                }
            }
        };
        if let Some(p) = out_path.parent() {
            fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        fs::write(&out_path, &plain).map_err(|e| e.to_string())?;
        let restored_sha = sha256_hex(&plain);
        secure_zero(&mut plain);

        let exp_sha = entry.get("originalSha256").and_then(|v| v.as_str()).unwrap_or("");
        if !exp_sha.is_empty() && restored_sha != exp_sha {
            return Err(format!(
                "SHA-256 mismatch on unsealed output {}",
                out_path.display()
            ));
        }
        return Ok(JsonVal::obj(vec![
            ("ok", JsonVal::Bool(true)),
            ("mode", JsonVal::Str("file".to_string())),
            ("outputPath", JsonVal::Str(out_path.to_string_lossy().to_string())),
            ("sha256", JsonVal::Str(restored_sha.clone())),
            (
                "verifiedSha256Match",
                JsonVal::Bool(exp_sha.is_empty() || restored_sha == exp_sha),
            ),
        ]));
    }

    let manifest = load_json_if_exists(&abs_target.join("vibeslayer.manifest.json"))
        .ok_or_else(|| format!("No vibeslayer.manifest.json found in {}", abs_target.display()))?;
    let files = manifest
        .get("files")
        .and_then(|v| v.as_arr())
        .ok_or("MALFORMED_MANIFEST")?;
    let vault = ctx.vault.ok_or_else(|| {
        format!(
            "No keys.json found for {}. Pass --keys <path/to/.vibeslayer/keys.json>.",
            abs_target.display()
        )
    })?;
    let mut mk = parse_key_hex_32(
        vault
            .get("masterKeyHex")
            .and_then(|v| v.as_str())
            .ok_or("VAULT_MISSING_MASTER_KEY")?,
    )?;

    let dest_dir = match &opts.out_path {
        Some(p) => abs_path_clean(p)?,
        None => {
            let s = abs_target.to_string_lossy();
            if let Some(stem) = s.strip_suffix("-protected") {
                PathBuf::from(format!("{stem}-unsealed"))
            } else {
                PathBuf::from(format!("{s}-unsealed"))
            }
        }
    };
    fs::create_dir_all(&dest_dir).map_err(|e| e.to_string())?;

    enum UnsealSlot {
        Ignore,
        Skip(JsonVal),
        Done(JsonVal),
    }

    let total_files = files.len();
    let num_threads = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(16)
        .min(total_files.max(1));
    let next_idx = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<Result<UnsealSlot, String>>>> =
        (0..total_files).map(|_| Mutex::new(None)).collect();
    let keys_opt_ref = ctx.keys_path.as_deref().or(opts.keys_file.as_deref());
    let reg_opt_ref = opts.registry_path.as_deref();
    let vault_ref = &vault;
    let reg_ref = &ctx.registry;

    thread::scope(|s| {
        for _ in 0..num_threads {
            s.spawn(|| loop {
                let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                if idx >= total_files {
                    break;
                }
                let mf = &files[idx];
                let res = (|| -> Result<UnsealSlot, String> {
                    let rel = mf.get("relPath").and_then(|v| v.as_str()).unwrap_or("");
                    let out_rel = mf.get("outRelPath").and_then(|v| v.as_str()).unwrap_or("");
                    let engine = mf.get("engine").and_then(|v| v.as_str()).unwrap_or("vspk3");
                    if engine == "cook-glb-vs3d" {
                        return Ok(UnsealSlot::Ignore);
                    }
                    let src = abs_target.join(out_rel);
                    if engine == "wrap-elf" || engine == "freestanding-vault" {
                        return Ok(UnsealSlot::Skip(JsonVal::obj(vec![
                            ("relPath", JsonVal::Str(rel.to_string())),
                            ("outRelPath", JsonVal::Str(out_rel.to_string())),
                            ("engine", JsonVal::Str(engine.to_string())),
                            (
                                "status",
                                JsonVal::Str("hardened-executable-kept-protected".to_string()),
                            ),
                        ])));
                    }
                    let dst = dest_dir.join(rel);
                    if let Some(p) = dst.parent() {
                        fs::create_dir_all(p).map_err(|e| e.to_string())?;
                    }
                    if engine == "copy-public" {
                        fs::copy(&src, &dst).map_err(|e| e.to_string())?;
                        return Ok(UnsealSlot::Done(JsonVal::obj(vec![
                            ("relPath", JsonVal::Str(rel.to_string())),
                            ("status", JsonVal::Str("copied".to_string())),
                            ("sha256Match", JsonVal::Bool(true)),
                        ])));
                    }

                    let domain = mf.get("domain").and_then(|v| v.as_str()).unwrap_or("asset");
                    let asset_id = mf.get("assetId").and_then(|v| v.as_str()).unwrap_or(rel);
                    let context = mf.get("context").and_then(|v| v.as_str()).unwrap_or("");
                    let blob = fs::read(&src).map_err(|e| e.to_string())?;
                    let blob_sha = sha256_hex(&blob);
                    let mut plain = crate::unseal_vspk3_owned(&mk, domain, asset_id, context, blob)?;
                    let actual_sha = sha256_hex(&plain);
                    fs::write(&dst, &plain).map_err(|e| e.to_string())?;
                    secure_zero(&mut plain);
                    let mem_ent = lookup_entry_in_memory(&src, &blob_sha, Some(vault_ref))
                        .or_else(|| lookup_entry_in_memory(&src, &blob_sha, Some(reg_ref)))
                        .or_else(|| resolve_known_metadata(&src, keys_opt_ref, reg_opt_ref).entry);
                    let exp_sha = mem_ent
                        .as_ref()
                        .and_then(|e| e.get("originalSha256"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if !exp_sha.is_empty() && actual_sha != exp_sha {
                        return Err(format!("Restored SHA-256 mismatch for {rel}"));
                    }
                    Ok(UnsealSlot::Done(JsonVal::obj(vec![
                        ("relPath", JsonVal::Str(rel.to_string())),
                        ("status", JsonVal::Str("unsealed".to_string())),
                        (
                            "sha256Match",
                            JsonVal::Bool(exp_sha.is_empty() || actual_sha == exp_sha),
                        ),
                    ])))
                })();
                *slots[idx].lock().unwrap() = Some(res);
            });
        }
    });

    secure_zero(&mut mk);
    let mut restored = Vec::new();
    let mut skipped = Vec::new();
    for idx in 0..total_files {
        match slots[idx].lock().unwrap().take().unwrap()? {
            UnsealSlot::Ignore => {}
            UnsealSlot::Skip(v) => skipped.push(v),
            UnsealSlot::Done(v) => restored.push(v),
        }
    }

    Ok(JsonVal::obj(vec![
        ("ok", JsonVal::Bool(true)),
        ("mode", JsonVal::Str("directory".to_string())),
        ("outputDir", JsonVal::Str(dest_dir.to_string_lossy().to_string())),
        ("restoredCount", JsonVal::Int(restored.len() as i64)),
        ("skippedExecutables", JsonVal::Arr(skipped)),
        ("restored", JsonVal::Arr(restored)),
    ]))
}

/* =========================== Watermark & Trace 3D =========================== */

pub fn watermark_model(vs3d_path: &Path, opts: &CliOpts) -> Result<JsonVal, String> {
    let mut ctx = resolve_known_metadata(
        vs3d_path,
        opts.keys_file.as_deref(),
        opts.registry_path.as_deref(),
    );
    let mut vault = ctx.vault.clone().ok_or_else(|| {
        format!(
            "No keys/metadata found for {}. Pass --keys <path/to/.vibeslayer/keys.json>.",
            ctx.abs_target.display()
        )
    })?;
    let entry = ctx.entry.as_ref().ok_or_else(|| {
        format!(
            "No keys/metadata found for {}. Pass --keys <path/to/.vibeslayer/keys.json>.",
            ctx.abs_target.display()
        )
    })?;
    let asset_id = entry
        .get("assetId")
        .and_then(|v| v.as_str())
        .ok_or("ENTRY_MISSING_ASSET_ID")?
        .to_string();
    let context = entry.get("context").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let mut mk = parse_key_hex_32(
        vault
            .get("masterKeyHex")
            .and_then(|v| v.as_str())
            .ok_or("VAULT_MISSING_MASTER_KEY")?,
    )?;

    let wm_id_hex = match &opts.wm_id_hex {
        Some(h) => {
            let low = h.to_ascii_lowercase();
            let decoded = hex_decode(&low)?;
            if decoded.len() != 8 {
                secure_zero(&mut mk);
                return Err("--id must be 16 hex characters (64-bit watermark ID)".to_string());
            }
            low
        }
        None => {
            if let Some(ref b) = opts.buyer {
                let mac = hmac_sha256(&mk, format!("VS_BUYER_WM64|{b}").as_bytes());
                hex_encode(&mac[..8])
            } else {
                let mut r = [0u8; 8];
                os_random_bytes(&mut r)?;
                hex_encode(&r)
            }
        }
    };
    let wm_bytes = hex_decode(&wm_id_hex)?;
    let wm_u64 = u64::from_be_bytes(wm_bytes.try_into().unwrap());

    let vspk = fs::read(&ctx.abs_target).map_err(|e| e.to_string())?;
    let positions = embed_wm64_for_lease(&mk, &asset_id, &context, wm_u64, &vspk)?;
    secure_zero(&mut mk);

    let out_pos = match &opts.out_path {
        Some(p) => abs_path_clean(p)?,
        None => PathBuf::from(format!("{}.{}.positions.bin", ctx.abs_target.display(), wm_id_hex)),
    };
    if let Some(p) = out_pos.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let mut out_bytes = Vec::with_capacity(positions.len() * 2);
    for v in &positions {
        out_bytes.extend_from_slice(&v.to_le_bytes());
    }
    fs::write(&out_pos, &out_bytes).map_err(|e| e.to_string())?;
    let pos_sha = sha256_hex(&out_bytes);

    if let (Some(ref buyer), Some(ref kp)) = (&opts.buyer, &ctx.keys_path) {
        vault.ensure_obj("buyers").insert(wm_id_hex.clone(), JsonVal::Str(buyer.clone()));
        let owner_ref_val = entry.get("ownerRefPath").cloned().unwrap_or(JsonVal::Null);
        let wm_rec = JsonVal::obj(vec![
            ("keysFile", JsonVal::Str(kp.to_string_lossy().to_string())),
            ("assetId", JsonVal::Str(asset_id.clone())),
            ("ownerRefPath", owner_ref_val),
            ("wmIdHex", JsonVal::Str(wm_id_hex.clone())),
            ("buyer", JsonVal::Str(buyer.clone())),
            ("coords", JsonVal::Int(positions.len() as i64)),
        ]);
        vault.ensure_obj("watermarks").insert(pos_sha.clone(), wm_rec.clone());
        write_private_json(kp, &vault)?;
        ctx.registry.ensure_obj("watermarks").insert(pos_sha, wm_rec);
        save_workspace_registry(&ctx.reg_path, &ctx.registry)?;
    }

    Ok(JsonVal::obj(vec![
        ("ok", JsonVal::Bool(true)),
        ("modelPath", JsonVal::Str(ctx.abs_target.to_string_lossy().to_string())),
        ("outPositions", JsonVal::Str(out_pos.to_string_lossy().to_string())),
        ("wmIdHex", JsonVal::Str(wm_id_hex)),
        (
            "buyer",
            opts.buyer
                .as_ref()
                .map(|b| JsonVal::Str(b.clone()))
                .unwrap_or(JsonVal::Null),
        ),
        ("coords", JsonVal::Int(positions.len() as i64)),
    ]))
}

pub fn trace_leaked_positions(captured_path: &Path, opts: &CliOpts) -> Result<JsonVal, String> {
    let abs_cap = abs_path_clean(captured_path)?;
    if !abs_cap.is_file() {
        return Err(format!(
            "Captured positions file not found: {}",
            abs_cap.display()
        ));
    }
    let cap_bytes = fs::read(&abs_cap).map_err(|e| e.to_string())?;
    if cap_bytes.len() % 2 != 0 {
        return Err("INVALID_CAPTURED_POSITIONS_SIZE".to_string());
    }
    let cap_sha = sha256_hex(&cap_bytes);
    let cap_coords = (cap_bytes.len() / 2) as i64;
    let mut captured = Vec::with_capacity(cap_coords as usize);
    for ch in cap_bytes.chunks_exact(2) {
        captured.push(i16::from_le_bytes([ch[0], ch[1]]));
    }

    let mut chosen_vault: Option<JsonVal> = None;
    let mut chosen_asset_id: Option<String> = None;
    let mut chosen_owner_ref: Option<PathBuf> = None;

    let pick_from_vault = |v: &JsonVal| -> Option<(JsonVal, String, PathBuf)> {
        if let Some(wm_hit) = v.get("watermarks").and_then(|w| w.get(&cap_sha)) {
            if let (Some(aid), Some(rp)) = (
                wm_hit.get("assetId").and_then(|x| x.as_str()),
                wm_hit.get("ownerRefPath").and_then(|x| x.as_str()),
            ) {
                if Path::new(rp).is_file() {
                    return Some((v.clone(), aid.to_string(), PathBuf::from(rp)));
                }
            }
        }
        if let Some(arts) = v.get("artifacts").and_then(|a| a.as_obj()) {
            for (_, art) in arts.iter().rev() {
                if art.get("engine").and_then(|x| x.as_str()) == Some("cook-glb-vs3d") {
                    if let (Some(aid), Some(rp)) = (
                        art.get("assetId").and_then(|x| x.as_str()),
                        art.get("ownerRefPath").and_then(|x| x.as_str()),
                    ) {
                        let coords_ok = art
                            .get("coords")
                            .and_then(|x| x.as_i64())
                            .map(|c| c == cap_coords)
                            .unwrap_or(true);
                        if coords_ok && Path::new(rp).is_file() {
                            return Some((v.clone(), aid.to_string(), PathBuf::from(rp)));
                        }
                    }
                }
            }
        }
        None
    };

    if let Some(ref mp) = opts.model_path {
        let mc = resolve_known_metadata(
            mp,
            opts.keys_file.as_deref(),
            opts.registry_path.as_deref(),
        );
        if let (Some(v), Some(e)) = (mc.vault, mc.entry) {
            if let (Some(aid), Some(rp)) = (
                e.get("assetId").and_then(|x| x.as_str()),
                e.get("ownerRefPath").and_then(|x| x.as_str()),
            ) {
                chosen_vault = Some(v);
                chosen_asset_id = Some(aid.to_string());
                chosen_owner_ref = Some(PathBuf::from(rp));
            }
        }
    }

    if chosen_vault.is_none() {
        if let Some(ref kf) = opts.keys_file {
            if let Ok(ak) = abs_path_clean(kf) {
                if let Some(kv) = load_json_if_exists(&ak) {
                    if let Some((v, a, r)) = pick_from_vault(&kv) {
                        chosen_vault = Some(v);
                        chosen_asset_id = Some(a);
                        chosen_owner_ref = Some(r);
                    }
                }
            }
        }
    }

    if chosen_vault.is_none() {
        let rp = resolve_registry_path(opts.registry_path.as_deref());
        let reg = load_workspace_registry(&rp);
        if let Some(wm_hit) = reg.get("watermarks").and_then(|w| w.get(&cap_sha)) {
            if let (Some(kf), Some(aid), Some(ref_p)) = (
                wm_hit.get("keysFile").and_then(|x| x.as_str()),
                wm_hit.get("assetId").and_then(|x| x.as_str()),
                wm_hit.get("ownerRefPath").and_then(|x| x.as_str()),
            ) {
                if let Some(kv) = load_json_if_exists(Path::new(kf)) {
                    chosen_vault = Some(kv);
                    chosen_asset_id = Some(aid.to_string());
                    chosen_owner_ref = Some(PathBuf::from(ref_p));
                }
            }
        }
        if chosen_vault.is_none() {
            if let Some(arts) = reg.get("artifacts").and_then(|a| a.as_obj()) {
                for (_, art) in arts.iter().rev() {
                    if art.get("engine").and_then(|x| x.as_str()) == Some("cook-glb-vs3d") {
                        if let (Some(kf), Some(aid), Some(ref_p)) = (
                            art.get("keysFile").and_then(|x| x.as_str()),
                            art.get("assetId").and_then(|x| x.as_str()),
                            art.get("ownerRefPath").and_then(|x| x.as_str()),
                        ) {
                            let coords_ok = art
                                .get("coords")
                                .and_then(|x| x.as_i64())
                                .map(|c| c == cap_coords)
                                .unwrap_or(true);
                            if coords_ok && Path::new(ref_p).is_file() {
                                if let Some(kv) = load_json_if_exists(Path::new(kf)) {
                                    chosen_vault = Some(kv);
                                    chosen_asset_id = Some(aid.to_string());
                                    chosen_owner_ref = Some(PathBuf::from(ref_p));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let vault = chosen_vault.ok_or_else(|| {
        "Could not auto-locate model/owner_ref for this capture. Pass --model <file.vs3d> and --keys <keys.json>.".to_string()
    })?;
    let asset_id = chosen_asset_id.ok_or("MISSING_ASSET_ID")?;
    let owner_ref_path = chosen_owner_ref.ok_or("MISSING_OWNER_REF")?;

    let mut mk = parse_key_hex_32(
        vault
            .get("masterKeyHex")
            .and_then(|v| v.as_str())
            .ok_or("VAULT_MISSING_MASTER_KEY")?,
    )?;
    let ref_bytes = fs::read(&owner_ref_path).map_err(|e| e.to_string())?;
    let mut owner_ref = Vec::with_capacity(ref_bytes.len() / 2);
    for ch in ref_bytes.chunks_exact(2) {
        owner_ref.push(i16::from_le_bytes([ch[0], ch[1]]));
    }
    let (dec_u64, conf) = decode_wm64_o1(&mk, &asset_id, &owner_ref, &captured)?;
    secure_zero(&mut mk);
    let wm_hex = format!("{dec_u64:016x}");
    let buyer = vault
        .get("buyers")
        .and_then(|b| b.get(&wm_hex))
        .cloned()
        .unwrap_or(JsonVal::Null);

    Ok(JsonVal::obj(vec![
        ("ok", JsonVal::Bool(true)),
        ("capturedPath", JsonVal::Str(abs_cap.to_string_lossy().to_string())),
        ("assetId", JsonVal::Str(asset_id)),
        ("decodedWatermarkIdHex", JsonVal::Str(wm_hex)),
        ("buyer", buyer),
        (
            "meanChipConfidence",
            JsonVal::Num((conf * 1_000_000.0).round() / 1_000_000.0),
        ),
    ]))
}

/* =============================== Demo Generator =============================== */

fn create_sample_glb() -> Vec<u8> {
    let json_raw = br#"{"asset":{"version":"2.0"},"buffers":[{"byteLength":64}]}"#;
    let pad = (4 - (json_raw.len() % 4)) % 4;
    let mut padded_json = json_raw.to_vec();
    padded_json.resize(json_raw.len() + pad, b' ');

    let mut bin_buf = Vec::with_capacity(64);
    for i in 0..16 {
        let f = ((i as i32) * 4 - 32) as f32 * 0.25;
        bin_buf.extend_from_slice(&f.to_le_bytes());
    }
    let total_len = 12 + 8 + padded_json.len() + 8 + bin_buf.len();
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(b"glTF");
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(total_len as u32).to_le_bytes());
    out.extend_from_slice(&(padded_json.len() as u32).to_le_bytes());
    out.extend_from_slice(&0x4e4f_534au32.to_le_bytes());
    out.extend_from_slice(&padded_json);
    out.extend_from_slice(&(bin_buf.len() as u32).to_le_bytes());
    out.extend_from_slice(&0x004e_4942u32.to_le_bytes());
    out.extend_from_slice(&bin_buf);
    out
}

fn create_sample_wasm() -> &'static [u8] {
    &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
        0x03, 0x02, 0x01, 0x00,
        0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
        0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
    ]
}

pub fn run_beginner_demo(opts: &CliOpts) -> Result<JsonVal, String> {
    let demo_dir = match &opts.dir_path {
        Some(p) => abs_path_clean(p)?,
        None => detect_workspace_root()
            .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
            .join("vibeslayer-demo-app"),
    };
    let out_dir = match &opts.out_path {
        Some(p) => abs_path_clean(p)?,
        None => PathBuf::from(format!("{}-protected", demo_dir.display())),
    };
    let restored_dir = PathBuf::from(format!("{}-restored", demo_dir.display()));

    for sub in ["src", "compute", "models", "assets", "bin", "secrets"] {
        fs::create_dir_all(demo_dir.join(sub)).map_err(|e| e.to_string())?;
    }
    fs::write(
        demo_dir.join("README.md"),
        b"# Sample Beginner Repo\nPublic README stays readable.\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        demo_dir.join("src/pricing.py"),
        b"def compute_price(seats):\n    return seats * 49\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        demo_dir.join(".env"),
        b"STRIPE_SECRET_KEY=sk-proj-demo_0123456789abcdefghijklmnopqrstuvwxyz\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        demo_dir.join("secrets/api.vault"),
        b"VAULT_MASTER_SEED_DEMO_2026",
    )
    .map_err(|e| e.to_string())?;
    fs::write(demo_dir.join("compute/kernel.wasm"), create_sample_wasm())
        .map_err(|e| e.to_string())?;
    fs::write(demo_dir.join("assets/character.glb"), create_sample_glb())
        .map_err(|e| e.to_string())?;

    let mut weights = Vec::with_capacity(1024);
    for i in 0..256usize {
        weights.extend_from_slice(&((i as f32) * 0.125).to_le_bytes());
    }
    fs::write(demo_dir.join("models/weights.safetensors"), &weights).map_err(|e| e.to_string())?;

    let src_c = demo_dir.join("bin/license_tool.c");
    let bin_exe = demo_dir.join("bin/license_tool");
    fs::write(
        &src_c,
        b"#include <stdio.h>\nint main(int argc, char **argv){ printf(\"DEMO_ELF_OK seats=%s\\n\", argc>1?argv[1]:\"1\"); return 0; }\n",
    )
    .map_err(|e| e.to_string())?;
    let st = Command::new("gcc")
        .args([
            "-O2",
            "-fPIE",
            "-pie",
            src_c.to_str().unwrap(),
            "-o",
            bin_exe.to_str().unwrap(),
        ])
        .status()
        .map_err(|e| e.to_string())?;
    let _ = fs::remove_file(&src_c);
    if !st.success() {
        return Err("DEMO_GCC_COMPILE_FAILED".to_string());
    }

    let mut prot_opts = opts.clone();
    prot_opts.out_path = Some(out_dir.clone());
    let protected_res = protect_target(&demo_dir, &prot_opts)?;
    let keys_file = PathBuf::from(
        protected_res
            .get("keysFile")
            .and_then(|v| v.as_str())
            .ok_or("DEMO_MISSING_KEYS_FILE")?,
    );

    let bin_protected = out_dir.join("bin/license_tool");
    let bin_ctx = resolve_known_metadata(
        &bin_protected,
        Some(&keys_file),
        opts.registry_path.as_deref(),
    );
    let lease_key = bin_ctx
        .entry
        .as_ref()
        .and_then(|e| e.get("leaseKeyHex"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let standalone = bin_ctx
        .entry
        .as_ref()
        .and_then(|e| e.get("standalone"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let (rc, exec_stdout, _) = run_protected_capture(
        &bin_protected,
        &["42".to_string()],
        lease_key.as_deref(),
        standalone,
        &[],
    )?;
    if rc != 0 || !exec_stdout.contains("DEMO_ELF_OK seats=42") {
        return Err(format!("Demo protected executable failed: status={rc}"));
    }

    let vs3d_path = out_dir.join("assets/character.glb.vs3d");
    let wm_pos_path = out_dir.join("alice_positions.bin");
    let wm_res = watermark_model(
        &vs3d_path,
        &CliOpts {
            buyer: Some("alice@demo.local".to_string()),
            out_path: Some(wm_pos_path.clone()),
            keys_file: Some(keys_file.clone()),
            registry_path: opts.registry_path.clone(),
            ..CliOpts::default()
        },
    )?;
    let trace_res = trace_leaked_positions(
        &wm_pos_path,
        &CliOpts {
            model_path: Some(vs3d_path),
            keys_file: Some(keys_file.clone()),
            registry_path: opts.registry_path.clone(),
            ..CliOpts::default()
        },
    )?;
    if trace_res.get("buyer").and_then(|v| v.as_str()) != Some("alice@demo.local")
        || trace_res.get("decodedWatermarkIdHex") != wm_res.get("wmIdHex")
    {
        return Err("Demo watermark/trace mismatch".to_string());
    }

    let unseal_res = unseal_target(
        &out_dir,
        &CliOpts {
            out_path: Some(restored_dir.clone()),
            keys_file: Some(keys_file.clone()),
            registry_path: opts.registry_path.clone(),
            ..CliOpts::default()
        },
    )?;
    if unseal_res.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return Err("Demo unseal verification failed".to_string());
    }

    let self_check_ok = protected_res
        .get("selfCheck")
        .and_then(|s| s.get("ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let warn_count = protected_res
        .get("secretWarnings")
        .and_then(|v| v.as_arr())
        .map(|a| a.len() as i64)
        .unwrap_or(0);

    Ok(JsonVal::obj(vec![
        ("ok", JsonVal::Bool(true)),
        ("demoDir", JsonVal::Str(demo_dir.to_string_lossy().to_string())),
        ("protectedDir", JsonVal::Str(out_dir.to_string_lossy().to_string())),
        ("restoredDir", JsonVal::Str(restored_dir.to_string_lossy().to_string())),
        ("keysFile", JsonVal::Str(keys_file.to_string_lossy().to_string())),
        (
            "counts",
            protected_res.get("counts").cloned().unwrap_or(JsonVal::Null),
        ),
        ("secretWarningsCount", JsonVal::Int(warn_count)),
        ("selfCheckOk", JsonVal::Bool(self_check_ok)),
        ("execCheckOutput", JsonVal::Str(exec_stdout.trim().to_string())),
        ("watermarkBuyer", JsonVal::Str("alice@demo.local".to_string())),
        (
            "watermarkIdHex",
            trace_res
                .get("decodedWatermarkIdHex")
                .cloned()
                .unwrap_or(JsonVal::Null),
        ),
        (
            "unsealedFilesCount",
            unseal_res.get("restoredCount").cloned().unwrap_or(JsonVal::Int(0)),
        ),
    ]))
}

/* ================================ CLI Router ================================ */

pub fn print_beginner_help() {
    println!(
        "Vibe-Slayer v1.0.0-beta.3 — Zero-Node Native Repo, Binary, Website & 3D Protection

Beginner Natural-Language Mode (Plain English -> Exact Verified Command):
  ./vibe-slayer ask \"protect my website ./dist and block cloakbrowser\"
  ./vibe-slayer ask \"stream my 3d model ./hero.glb without sending geometry\"
  ./vibe-slayer ask \"scan ./my-repo for leaked api keys\"
  ./vibe-slayer explain \"serve ./dist-protected on port 9000 behind nginx\"  (dry-run preview)

Quick Start — Easy Presets & Config File:
  ./vibe-slayer init-config [--preset fast|balanced|paranoid] [-o vibeslayer.config.json]
  Use --preset <fast|balanced|paranoid> or --config <file.json> on website, serve, shield-3d, serve-3d.
  Precedence: CLI flags > --config JSON > VIBESLAYER_* env vars > --preset defaults.

Everyday repo / binary commands:
  ./vibe-slayer demo                         Build, protect, test, run, watermark, and unseal a sample repo
  ./vibe-slayer scan <dir>                   Dry-run audit: file classifications & leaked secret warnings
  ./vibe-slayer <dir|file> [-o <out>]        Auto-protect repo or single file (.protected/.vspk3/.vs3d/.vault.elf)
  ./vibe-slayer test <protected>             Verify encryption, tamper rejection, ptrace rejection & CET
  ./vibe-slayer run <protected-bin> [-- ...] Run a protected executable safely (FD 3 lease key)
  ./vibe-slayer unseal <protected> [-o dest] Restore original files and verify every SHA-256
  ./vibe-slayer watermark <file.vs3d> --buyer \"alice@co\" [-o pos.bin]
  ./vibe-slayer trace <pos.bin> [--model <file.vs3d>]

Live Website Runtime Protection (zero Node.js, pure Rust server + browser WebCrypto):
  ./vibe-slayer website <site-dir> [-o <out>] [--preset fast|balanced|paranoid] [--config <cfg.json>]
                        [--origin https://your.site] [--harden-js | --no-harden-js] [--min-str-len 4]
                        [--js-bloat-kb 0..512] [--anti-hook on|off] [--anti-cdp on|off] [--anti-stealth off|balanced|strict] [--title \"My Protected App\"]
  ./vibe-slayer serve <protected-site-dir> [--preset fast|balanced|paranoid] [--config <cfg.json>]
                      [--addr 127.0.0.1:8080] [--origin https://your.site] [--csp strict|relaxed|off]
                      [--anti-stealth off|balanced|strict] [--auth-secret <tok>] [--auth-hmac-key <64-hex>] [--trust-proxy <ip1,ip2>]
                      [--ticket-ttl 30] [--max-leases-per-min 60] [--max-conns-per-ip 32]
                      [--header-timeout-ms 3000] [--body-timeout-ms 5000] [--workers 0]

Live 3D GPU Shield & Zero-Geometry Stream Server:
  ./vibe-slayer shield-3d --in <model.glb> --out <dir> [--preset fast|balanced|paranoid] [--config <cfg.json>]
                          [--key-file <secret.key>] [--gpu-stages 96] [--chaff-pct 37.5]
                          [--max-tex-dim 4096] [--tile-grid 0|4|8|16] [--png-mode fast|optimal]
                          [--tex-format auto|jpeg|png] [--tex-quality 90]
  ./vibe-slayer serve-3d <shielded-dir> [--mode gpu|stream] [--preset fast|balanced|paranoid] [--config <cfg.json>]
                         [--stream-width 960] [--stream-height 640] [--stream-quality 84]
                         [--addr 127.0.0.1:8790] [--origin https://your.site] [--key-file <secret.key>]
                         [--title \"My 3D Model\"] [--watermark on|off] [--wm-strength 1.2]
                         [--anti-hook on|off] [--anti-cdp on|off] [--anti-stealth off|balanced|strict] [--csp strict|relaxed|off] [--camera-jitter 1.0]
                         [--auth-secret <tok>] [--auth-hmac-key <64-hex>] [--trust-proxy <ip1,ip2>]
                         [--ticket-ttl 30] [--session-ttl 600] [--camera-budget 12000] [--asset-budget 24]
                         [--max-leases-per-min 60] [--max-sessions 4096] [--max-conns-per-ip 32]
                         [--max-tex-concurrency 4] [--header-timeout-ms 3000] [--body-timeout-ms 5000] [--workers 0]
  ./vibe-slayer trace-shield-3d --dir <shielded-dir> --ripped-wp <wp.bin> [--key-file <secret.key>]
  ./vibe-slayer trace-stream-frame --dir <shielded-dir> --rgb <frame.rgb> --width W --height H [--key-file <secret.key>]
  ./vibe-slayer mint-token --key <64-hex> --buyer <id> [--ttl 3600]

Environment Variable Fallbacks (avoid leaking secrets in process argv):
  VIBESLAYER_PRESET, VIBESLAYER_AUTH_SECRET, VIBESLAYER_AUTH_HMAC_KEY,
  VIBESLAYER_KEY_FILE, VIBESLAYER_ORIGIN, VIBESLAYER_TRUST_PROXY

Common repo options:
  --standalone       Allow wrapped executables to run without .vibeslayer/keys.json
  --seal-all         In repo mode, encrypt public files (README, CSS, etc.) too
  --vault            Force small secrets (<=4096B) into memfd_secret ELF vault
  --keys <file>      Use a custom keys.json instead of auto .vibeslayer/keys.json
  --json             Machine-readable JSON output"
    );
}

fn print_warnings(res: &JsonVal) {
    let Some(warnings) = res.get("secretWarnings").and_then(|v| v.as_arr()) else {
        return;
    };
    if warnings.is_empty() {
        return;
    }
    println!(
        "\n[!] Secret Scanner Warnings ({} found — sealed in protected output):",
        warnings.len()
    );
    for w in warnings.iter().take(15) {
        let rp = w.get("relPath").and_then(|v| v.as_str()).unwrap_or("");
        let ln = w.get("line").and_then(|v| v.as_i64()).unwrap_or(0);
        let kd = w.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let pv = w.get("preview").and_then(|v| v.as_str()).unwrap_or("");
        println!("    - {rp}:{ln} [{kd}] {pv}");
    }
    if warnings.len() > 15 {
        println!("    ... and {} more", warnings.len() - 15);
    }
}

fn parse_cli_flags(args: &[String]) -> Result<(CliOpts, Vec<String>), String> {
    let mut opts = CliOpts::default();
    let mut positionals = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-o" | "--out" if i + 1 < args.len() => {
                opts.out_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--keys" if i + 1 < args.len() => {
                opts.keys_file = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--registry" if i + 1 < args.len() => {
                opts.registry_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--config" if i + 1 < args.len() => {
                opts.config_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--preset" if i + 1 < args.len() => {
                opts.preset = Some(args[i + 1].clone());
                i += 2;
            }
            "--context" if i + 1 < args.len() => {
                opts.context = Some(args[i + 1].clone());
                i += 2;
            }
            "--origin" if i + 1 < args.len() => {
                opts.origin = Some(args[i + 1].clone());
                i += 2;
            }
            "--addr" if i + 1 < args.len() => {
                opts.addr = Some(args[i + 1].clone());
                i += 2;
            }
            "--buyer" if i + 1 < args.len() => {
                opts.buyer = Some(args[i + 1].clone());
                i += 2;
            }
            "--id" if i + 1 < args.len() => {
                opts.wm_id_hex = Some(args[i + 1].clone());
                i += 2;
            }
            "--model" if i + 1 < args.len() => {
                opts.model_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--dir" if i + 1 < args.len() => {
                opts.dir_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--max-leases-per-min" if i + 1 < args.len() => {
                let n = args[i + 1]
                    .parse::<usize>()
                    .map_err(|_| format!("Invalid --max-leases-per-min '{}': expected positive integer", args[i + 1]))?;
                opts.max_leases_per_min = n;
                opts.max_leases_override = Some(n);
                i += 2;
            }
            "--auth-secret" if i + 1 < args.len() => {
                opts.auth_secret = Some(args[i + 1].clone());
                i += 2;
            }
            "--auth-hmac-key" if i + 1 < args.len() => {
                opts.auth_hmac_key = Some(args[i + 1].clone());
                i += 2;
            }
            "--trust-proxy" if i + 1 < args.len() => {
                opts.trust_proxy = Some(args[i + 1].clone());
                i += 2;
            }
            "--title" if i + 1 < args.len() => {
                opts.title = Some(args[i + 1].clone());
                i += 2;
            }
            "--csp" if i + 1 < args.len() => {
                opts.csp = Some(args[i + 1].clone());
                i += 2;
            }
            "--anti-hook" if i + 1 < args.len() => {
                opts.anti_hook = Some(args[i + 1].clone());
                i += 2;
            }
            "--anti-cdp" if i + 1 < args.len() => {
                opts.anti_cdp = Some(args[i + 1].clone());
                i += 2;
            }
            "--anti-stealth" if i + 1 < args.len() => {
                opts.anti_stealth = Some(args[i + 1].clone());
                i += 2;
            }
            "--min-str-len" if i + 1 < args.len() => {
                let n = args[i + 1]
                    .parse::<usize>()
                    .map_err(|_| format!("Invalid --min-str-len '{}': expected integer in 2..=64", args[i + 1]))?;
                opts.min_str_len = Some(n);
                i += 2;
            }
            "--js-bloat-kb" if i + 1 < args.len() => {
                let n = args[i + 1]
                    .parse::<usize>()
                    .map_err(|_| format!("Invalid --js-bloat-kb '{}': expected integer in 0..=512", args[i + 1]))?;
                opts.js_bloat_kb = Some(n);
                i += 2;
            }
            "--ticket-ttl" if i + 1 < args.len() => {
                let n = args[i + 1]
                    .parse::<u64>()
                    .map_err(|_| format!("Invalid --ticket-ttl '{}': expected integer in 5..=300", args[i + 1]))?;
                opts.ticket_ttl = Some(n);
                i += 2;
            }
            "--max-conns-per-ip" if i + 1 < args.len() => {
                let n = args[i + 1]
                    .parse::<usize>()
                    .map_err(|_| format!("Invalid --max-conns-per-ip '{}': expected integer in 2..=1024", args[i + 1]))?;
                opts.max_conns_per_ip = Some(n);
                i += 2;
            }
            "--header-timeout-ms" if i + 1 < args.len() => {
                let n = args[i + 1]
                    .parse::<u64>()
                    .map_err(|_| format!("Invalid --header-timeout-ms '{}': expected integer in 500..=30000", args[i + 1]))?;
                opts.header_timeout_ms = Some(n);
                i += 2;
            }
            "--body-timeout-ms" if i + 1 < args.len() => {
                let n = args[i + 1]
                    .parse::<u64>()
                    .map_err(|_| format!("Invalid --body-timeout-ms '{}': expected integer in 500..=60000", args[i + 1]))?;
                opts.body_timeout_ms = Some(n);
                i += 2;
            }
            "--workers" if i + 1 < args.len() => {
                let n = args[i + 1]
                    .parse::<usize>()
                    .map_err(|_| format!("Invalid --workers '{}': expected 0 (auto) or 4..=128", args[i + 1]))?;
                opts.workers = Some(n);
                i += 2;
            }
            "--harden-js" => {
                opts.harden_js = true;
                opts.harden_js_override = Some(true);
                i += 1;
            }
            "--no-harden-js" => {
                opts.harden_js = false;
                opts.harden_js_override = Some(false);
                i += 1;
            }
            "--standalone" => {
                opts.standalone = true;
                i += 1;
            }
            "--seal-all" => {
                opts.seal_all = true;
                i += 1;
            }
            "--vault" => {
                opts.force_vault = true;
                i += 1;
            }
            "--no-gitignore" => {
                opts.no_gitignore = true;
                i += 1;
            }
            "--json" => {
                opts.json = true;
                i += 1;
            }
            _ => {
                positionals.push(args[i].clone());
                i += 1;
            }
        }
    }
    Ok((opts, positionals))
}

fn parse_run_args(args: &[String]) -> (Option<PathBuf>, Vec<String>, CliOpts) {
    let mut opts = CliOpts::default();
    let dash_pos = args.iter().position(|a| a == "--");
    let (head, tail) = match dash_pos {
        Some(idx) => (&args[..idx], &args[idx + 1..]),
        None => (args, &[][..]),
    };

    let mut target: Option<PathBuf> = None;
    let mut pass = Vec::new();
    let mut i = 0usize;
    while i < head.len() {
        let a = head[i].as_str();
        if a == "--keys" && i + 1 < head.len() {
            opts.keys_file = Some(PathBuf::from(&head[i + 1]));
            i += 2;
        } else if a == "--registry" && i + 1 < head.len() {
            opts.registry_path = Some(PathBuf::from(&head[i + 1]));
            i += 2;
        } else if target.is_none() {
            target = Some(PathBuf::from(&head[i]));
            i += 1;
        } else {
            pass.push(head[i].clone());
            i += 1;
        }
    }
    pass.extend(tail.iter().cloned());
    (target, pass, opts)
}

pub fn run_beginner_subcommand(cmd: &str, rest: &[String]) -> Result<i32, (i32, String)> {
    if cmd == "help" || cmd == "--help" || cmd == "-h" {
        print_beginner_help();
        return Ok(0);
    }

    if cmd == "run" {
        let (target, pass_args, opts) = parse_run_args(rest);
        let t = target.ok_or_else(|| {
            (
                1,
                "Usage: ./vibe-slayer run <protected-executable> [-- args...]".to_string(),
            )
        })?;
        let code = spawn_protected(&t, &pass_args, &opts).map_err(|e| (1, e))?;
        return Ok(code);
    }

    let (opts, positionals) = parse_cli_flags(rest).map_err(|e| (1, e))?;
    let target = positionals.first().map(PathBuf::from);

    match cmd {
        "protect" | "auto" => {
            let t = target.ok_or_else(|| {
                (
                    1,
                    "Usage: ./vibe-slayer <file-or-dir> [-o <output>] [--standalone] [--seal-all]"
                        .to_string(),
                )
            })?;
            let res = protect_target(&t, &opts).map_err(|e| (1, e))?;
            if opts.json {
                println!("{}", to_json_pretty(&res));
                return Ok(0);
            }
            if res.get("mode").and_then(|v| v.as_str()) == Some("file") {
                let engine = res.get("engine").and_then(|v| v.as_str()).unwrap_or("");
                let domain = res.get("domain").and_then(|v| v.as_str()).unwrap_or("");
                let out_p = res.get("outputPath").and_then(|v| v.as_str()).unwrap_or("");
                let keys_f = res.get("keysFile").and_then(|v| v.as_str()).unwrap_or("");
                let ent = res
                    .get("selfCheck")
                    .and_then(|s| s.get("checks"))
                    .and_then(|c| c.get("entropyBitsPerByte"))
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                println!("[+] Protected ({engine}, {domain}): {out_p}");
                if let Some(c3d) = res.get("companionVs3dPath").and_then(|v| v.as_str()) {
                    println!("[+] Watermarkable 3D stream: {c3d}");
                }
                println!("[+] Keys saved (0600, gitignored): {keys_f}");
                println!("[+] Self-test verified: PASS (entropy {ent} bits/B)");
                print_warnings(&res);
                println!("\nNext commands you can run:");
                println!("  ./vibe-slayer test {out_p:?}");
                if engine == "wrap-elf" || engine == "freestanding-vault" {
                    println!("  ./vibe-slayer run {out_p:?}");
                } else {
                    println!("  ./vibe-slayer unseal {out_p:?}");
                }
                if let Some(c3d) = res.get("companionVs3dPath").and_then(|v| v.as_str()) {
                    println!("  ./vibe-slayer watermark {c3d:?} --buyer \"alice\"");
                }
            } else {
                let total = res
                    .get("counts")
                    .and_then(|c| c.get("total"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let out_d = res.get("outputDir").and_then(|v| v.as_str()).unwrap_or("");
                let manifest_p = res.get("manifestPath").and_then(|v| v.as_str()).unwrap_or("");
                let keys_f = res.get("keysFile").and_then(|v| v.as_str()).unwrap_or("");
                let tested = res
                    .get("selfCheck")
                    .and_then(|s| s.get("testedCount"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let cv = res.get("counts").and_then(|c| c.get("vspk3")).and_then(|v| v.as_i64()).unwrap_or(0);
                let cw = res.get("counts").and_then(|c| c.get("wrapElf")).and_then(|v| v.as_i64()).unwrap_or(0);
                let cf = res.get("counts").and_then(|c| c.get("freestandingVault")).and_then(|v| v.as_i64()).unwrap_or(0);
                let c3 = res.get("counts").and_then(|c| c.get("vs3d")).and_then(|v| v.as_i64()).unwrap_or(0);
                let cp = res.get("counts").and_then(|c| c.get("publicCopied")).and_then(|v| v.as_i64()).unwrap_or(0);
                println!("[+] Protected repo ({total} files): {out_d}");
                println!("    Engines: vspk3={cv}, wrap-elf={cw}, vault-elf={cf}, vs3d={c3}, public={cp}");
                println!("[+] Manifest (no secrets): {manifest_p}");
                println!("[+] Keys saved (0600, gitignored): {keys_f}");
                println!("[+] Auto-verification across {tested} outputs: PASS");
                print_warnings(&res);
                println!("\nNext commands you can run:");
                println!("  ./vibe-slayer test {out_d:?}");
                println!("  ./vibe-slayer unseal {out_d:?}");
            }
            Ok(0)
        }
        "scan" => {
            let t = target.ok_or_else(|| (1, "Usage: ./vibe-slayer scan <file-or-dir>".to_string()))?;
            let res = scan_target(&t, &opts).map_err(|e| (1, e))?;
            if opts.json {
                println!("{}", to_json_pretty(&res));
                return Ok(0);
            }
            let mode = res.get("mode").and_then(|v| v.as_str()).unwrap_or("");
            let inp = res.get("inputPath").and_then(|v| v.as_str()).unwrap_or("");
            let cnt = res.get("fileCount").and_then(|v| v.as_i64()).unwrap_or(0);
            println!("[+] Scan ({mode}): {inp} ({cnt} files)");
            if let Some(items) = res.get("items").and_then(|v| v.as_arr()) {
                for it in items.iter().take(25) {
                    let rp = it.get("relPath").and_then(|v| v.as_str()).unwrap_or("");
                    let b = it.get("inputBytes").and_then(|v| v.as_i64()).unwrap_or(0);
                    let e = it.get("engine").and_then(|v| v.as_str()).unwrap_or("");
                    let d = it.get("domain").and_then(|v| v.as_str()).unwrap_or("");
                    println!("    - {rp} ({b} B) -> {e} [{d}]");
                }
                if items.len() > 25 {
                    println!("    ... and {} more", items.len() - 25);
                }
            }
            print_warnings(&res);
            Ok(0)
        }
        "test" | "verify-auto" => {
            let t = target.ok_or_else(|| (1, "Usage: ./vibe-slayer test <protected-file-or-dir>".to_string()))?;
            let res = test_protected_target(&t, &opts).map_err(|e| (1, e))?;
            let ok = res.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
            if opts.json {
                println!("{}", to_json_pretty(&res));
            } else if res.get("mode").and_then(|v| v.as_str()) == Some("file") {
                let tp = res.get("targetPath").and_then(|v| v.as_str()).unwrap_or("");
                let ty = res.get("type").and_then(|v| v.as_str()).unwrap_or("");
                println!("[{}] {tp} ({ty})", if ok { "PASS" } else { "FAIL" });
                if let Some(chks) = res.get("checks").and_then(|v| v.as_obj()) {
                    for (k, v) in chks {
                        println!("    - {k}: {}", crate::mini_json::to_json_compact(v));
                    }
                }
            } else {
                let tp = res.get("targetPath").and_then(|v| v.as_str()).unwrap_or("");
                let tc = res.get("testedCount").and_then(|v| v.as_i64()).unwrap_or(0);
                println!("[{}] {tp} ({tc} files verified)", if ok { "PASS" } else { "FAIL" });
                if let Some(fs_arr) = res.get("files").and_then(|v| v.as_arr()) {
                    for f in fs_arr {
                        let fok = f.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                        let rp = f.get("relPath").and_then(|v| v.as_str()).unwrap_or("");
                        let ty = f.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        println!("    - {} {rp} ({ty})", if fok { "PASS" } else { "FAIL" });
                    }
                }
            }
            Ok(if ok { 0 } else { 1 })
        }
        "unseal" => {
            let t = target.ok_or_else(|| {
                (
                    1,
                    "Usage: ./vibe-slayer unseal <protected-file-or-dir> [-o <dest>]".to_string(),
                )
            })?;
            let res = unseal_target(&t, &opts).map_err(|e| (1, e))?;
            if opts.json {
                println!("{}", to_json_pretty(&res));
                return Ok(0);
            }
            if res.get("mode").and_then(|v| v.as_str()) == Some("file") {
                let op = res.get("outputPath").and_then(|v| v.as_str()).unwrap_or("");
                println!("[+] Unsealed & SHA-256 verified: {op}");
            } else {
                let rc = res.get("restoredCount").and_then(|v| v.as_i64()).unwrap_or(0);
                let od = res.get("outputDir").and_then(|v| v.as_str()).unwrap_or("");
                println!("[+] Unsealed {rc} files into: {od}");
                if let Some(sk) = res.get("skippedExecutables").and_then(|v| v.as_arr()) {
                    if !sk.is_empty() {
                        println!(
                            "    Note: {} hardened executable(s) kept protected (use './vibe-slayer run <file>')",
                            sk.len()
                        );
                    }
                }
            }
            Ok(0)
        }
        "watermark" => {
            let t = target.ok_or_else(|| {
                (
                    1,
                    "Usage: ./vibe-slayer watermark <model.vs3d> [--buyer <name> | --id <16hex>]".to_string(),
                )
            })?;
            let res = watermark_model(&t, &opts).map_err(|e| (1, e))?;
            if opts.json {
                println!("{}", to_json_pretty(&res));
                return Ok(0);
            }
            let wid = res.get("wmIdHex").and_then(|v| v.as_str()).unwrap_or("");
            let op = res.get("outPositions").and_then(|v| v.as_str()).unwrap_or("");
            let b_note = res
                .get("buyer")
                .and_then(|v| v.as_str())
                .map(|b| format!(" / buyer={b}"))
                .unwrap_or_default();
            println!("[+] Embedded 64-bit WM64 watermark ({wid}{b_note})");
            println!("[+] Output positions: {op}");
            println!("    Test trace: ./vibe-slayer trace {op:?}");
            Ok(0)
        }
        "trace" => {
            let t = target.ok_or_else(|| {
                (
                    1,
                    "Usage: ./vibe-slayer trace <positions.bin> [--model <file.vs3d>]".to_string(),
                )
            })?;
            let res = trace_leaked_positions(&t, &opts).map_err(|e| (1, e))?;
            if opts.json {
                println!("{}", to_json_pretty(&res));
                return Ok(0);
            }
            let wid = res
                .get("decodedWatermarkIdHex")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let conf = res
                .get("meanChipConfidence")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let b_note = res
                .get("buyer")
                .and_then(|v| v.as_str())
                .map(|b| format!(" (buyer: {b})"))
                .unwrap_or_default();
            println!("[+] Traced WM64 ID: {wid}{b_note}");
            println!("    Mean chip confidence: {conf}");
            Ok(0)
        }
        "demo" => {
            let res = run_beginner_demo(&opts).map_err(|e| (1, e))?;
            if opts.json {
                println!("{}", to_json_pretty(&res));
                return Ok(0);
            }
            let dd = res.get("demoDir").and_then(|v| v.as_str()).unwrap_or("");
            let pd = res.get("protectedDir").and_then(|v| v.as_str()).unwrap_or("");
            let rd = res.get("restoredDir").and_then(|v| v.as_str()).unwrap_or("");
            let kf = res.get("keysFile").and_then(|v| v.as_str()).unwrap_or("");
            let ex = res.get("execCheckOutput").and_then(|v| v.as_str()).unwrap_or("");
            let wb = res.get("watermarkBuyer").and_then(|v| v.as_str()).unwrap_or("");
            let wid = res.get("watermarkIdHex").and_then(|v| v.as_str()).unwrap_or("");
            let uc = res.get("unsealedFilesCount").and_then(|v| v.as_i64()).unwrap_or(0);
            println!("[+] Sample beginner repo created:   {dd}");
            println!("[+] Protected repo output:          {pd}");
            println!("[+] Restored (unsealed) repo copy:  {rd}");
            println!("[+] Keys saved (0600, gitignored):  {kf}");
            println!(
                "[+] Verified end-to-end: test=PASS, exec={ex:?}, watermark={wb} ({wid}), unsealed={uc} files"
            );
            Ok(0)
        }
        "website" => {
            let t = target.ok_or_else(|| {
                (
                    1,
                    "Usage: ./vibe-slayer website <site-dir> [-o <out-dir>] [--preset fast|balanced|paranoid] [--config <cfg.json>] [--origin https://yourdomain.com] [--harden-js]".to_string(),
                )
            })?;
            let cfg_json = match opts.config_path.as_deref() {
                Some(p) => Some(crate::params::load_config_json(p).map_err(|e| (1, e))?),
                None => None,
            };
            let preset = crate::params::detect_preset_from_sources(
                opts.preset.as_deref(),
                cfg_json.as_ref(),
                "website",
            )
            .map_err(|e| (1, e))?;
            let mut wparams = crate::params::WebsiteBuildParams::from_preset(preset);
            if let Some(ref cfg) = cfg_json {
                wparams.apply_json(cfg).map_err(|e| (1, e))?;
            }
            if let Some(h) = opts.harden_js_override {
                wparams.harden_js = h;
            }
            if let Some(msl) = opts.min_str_len {
                wparams.min_str_len = msl;
            }
            if let Some(bk) = opts.js_bloat_kb {
                wparams.js_bloat_kb = bk;
            }
            if let Some(ref ah) = opts.anti_hook {
                wparams.anti_hook =
                    crate::params::parse_bool_flag(ah, "--anti-hook").map_err(|e| (1, e))?;
            }
            if let Some(ref ac) = opts.anti_cdp {
                wparams.anti_cdp =
                    crate::params::parse_bool_flag(ac, "--anti-cdp").map_err(|e| (1, e))?;
            }
            if let Some(ref ast) = opts.anti_stealth {
                wparams.anti_stealth =
                    crate::params::AntiStealthMode::parse(ast).map_err(|e| (1, e))?;
            }
            if let Some(ref title) = opts.title {
                wparams.title = title.clone();
            }
            wparams.validate().map_err(|e| (1, e))?;

            let res = crate::web_runtime::protect_website_with_params(
                &t,
                opts.out_path.as_deref(),
                opts.origin.as_deref(),
                opts.keys_file.as_deref(),
                opts.registry_path.as_deref(),
                opts.no_gitignore,
                &wparams,
            )
            .map_err(|e| (1, e))?;
            if opts.json {
                println!("{}", to_json_pretty(&res));
                return Ok(0);
            }
            let od = res.get("outputDir").and_then(|v| v.as_str()).unwrap_or("");
            let cnt = res.get("sealedFiles").and_then(|v| v.as_i64()).unwrap_or(0);
            let kf = res.get("keysFile").and_then(|v| v.as_str()).unwrap_or("");
            println!(
                "[+] Protected live website bundle ({cnt} encrypted assets, preset={}, hardenJs={}): {od}",
                wparams.preset.as_str(),
                wparams.harden_js
            );
            println!("[+] Keys saved (0600, gitignored): {kf}");
            println!("\nStart the zero-Node live runtime server:");
            println!("  ./vibe-slayer serve {od:?} --addr 127.0.0.1:8080");
            Ok(0)
        }
        "serve" => {
            let t = target.ok_or_else(|| {
                (
                    1,
                    "Usage: ./vibe-slayer serve <protected-site-dir> [--preset fast|balanced|paranoid] [--config <cfg.json>] [--addr 127.0.0.1:8080] [--origin https://yourdomain.com] [--auth-secret <token>] [--auth-hmac-key <64-hex>] [--trust-proxy <ip1,ip2>]".to_string(),
                )
            })?;
            let cfg_json = match opts.config_path.as_deref() {
                Some(p) => Some(crate::params::load_config_json(p).map_err(|e| (1, e))?),
                None => None,
            };
            let preset = crate::params::detect_preset_from_sources(
                opts.preset.as_deref(),
                cfg_json.as_ref(),
                "serve",
            )
            .map_err(|e| (1, e))?;
            let mut sparams = crate::params::ServeWebParams::from_preset(preset);
            if let Some(ref cfg) = cfg_json {
                sparams.apply_json(cfg).map_err(|e| (1, e))?;
            }
            if let Some(ref a) = opts.addr {
                sparams.addr = a.clone();
            }
            if let Some(ref o) = opts.origin {
                sparams.origin = Some(o.clone());
            }
            if let Some(ref s) = opts.auth_secret {
                sparams.auth_secret = Some(s.clone());
            }
            if let Some(ref h) = opts.auth_hmac_key {
                sparams.auth_hmac_key = Some(h.clone());
            }
            if let Some(ref tp) = opts.trust_proxy {
                sparams.trust_proxy = Some(tp.clone());
            }
            if let Some(ref c) = opts.csp {
                sparams.csp = crate::params::CspMode::parse(c).map_err(|e| (1, e))?;
            }
            if let Some(ref ast) = opts.anti_stealth {
                sparams.anti_stealth =
                    crate::params::AntiStealthMode::parse(ast).map_err(|e| (1, e))?;
            }
            if let Some(ttl) = opts.ticket_ttl {
                sparams.ticket_ttl_sec = ttl;
            }
            if let Some(ml) = opts.max_leases_override {
                sparams.max_leases_per_min = ml;
            }
            if let Some(mc) = opts.max_conns_per_ip {
                sparams.max_conns_per_ip = mc;
            }
            if let Some(ht) = opts.header_timeout_ms {
                sparams.header_timeout_ms = ht;
            }
            if let Some(bt) = opts.body_timeout_ms {
                sparams.body_timeout_ms = bt;
            }
            if let Some(w) = opts.workers {
                sparams.workers = w;
            }
            sparams.validate().map_err(|e| (1, e))?;

            crate::web_runtime::serve_website_with_params(
                &t,
                opts.keys_file.as_deref(),
                opts.registry_path.as_deref(),
                &sparams,
            )
            .map_err(|e| (1, e))?;
            Ok(0)
        }
        _ => Err((1, format!("Unknown command: {cmd}"))),
    }
}
