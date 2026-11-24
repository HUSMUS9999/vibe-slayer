//! Deterministic, zero-dependency Natural-Language CLI Abstraction (`nl_cli.rs`)
//! Lets beginners run Vibe-Slayer using plain English sentences:
//!   ./vibe-slayer ask "protect my website ./dist and block cloakbrowser"
//!   ./vibe-slayer explain "stream my 3d model ./hero.glb without sending geometry"
//!   ./vibe-slayer do "scan ./my-repo for leaked api keys"

use std::path::Path;

use crate::mini_json::{to_json_pretty, JsonVal};

#[derive(Clone, Debug)]
pub struct NaturalPlan {
    pub input: String,
    pub intent: &'static str,
    pub goal: String,
    pub argv: Vec<String>,
    pub reasons: Vec<String>,
    pub next_command: Option<String>,
}

impl NaturalPlan {
    pub fn display_command(&self) -> String {
        let mut parts = Vec::with_capacity(self.argv.len() + 1);
        parts.push("./vibe-slayer".to_string());
        for a in &self.argv {
            if a.contains(' ') || a.is_empty() {
                parts.push(format!("\"{}\"", a.replace('"', "\\\"")));
            } else {
                parts.push(a.clone());
            }
        }
        parts.join(" ")
    }

    pub fn to_json(&self, dry_run: bool) -> JsonVal {
        JsonVal::obj(vec![
            ("ok", JsonVal::Bool(true)),
            ("input", JsonVal::Str(self.input.clone())),
            ("intent", JsonVal::Str(self.intent.to_string())),
            ("goal", JsonVal::Str(self.goal.clone())),
            ("dryRun", JsonVal::Bool(dry_run)),
            ("command", JsonVal::Str(self.display_command())),
            (
                "argv",
                JsonVal::Arr(self.argv.iter().cloned().map(JsonVal::Str).collect()),
            ),
            (
                "reasons",
                JsonVal::Arr(self.reasons.iter().cloned().map(JsonVal::Str).collect()),
            ),
            (
                "nextCommand",
                match &self.next_command {
                    Some(nc) => JsonVal::Str(nc.clone()),
                    None => JsonVal::Null,
                },
            ),
        ])
    }
}

fn tokenize_sentence(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote: Option<char> = None;
    for ch in s.chars() {
        match in_quote {
            Some(q) if ch == q => {
                in_quote = None;
            }
            Some(_) => cur.push(ch),
            None => {
                if ch == '"' || ch == '\'' {
                    in_quote = Some(ch);
                } else if ch.is_whitespace() || ch == ',' || ch == ';' {
                    if !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                    }
                } else {
                    cur.push(ch);
                }
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn clean_token(tok: &str) -> &str {
    tok.trim_matches(|c: char| matches!(c, ',' | ';' | '!' | '?' | '(' | ')' | '[' | ']' | '"'))
        .trim_end_matches('.')
}

fn looks_like_url(t: &str) -> bool {
    t.starts_with("http://") || t.starts_with("https://")
}

fn is_english_stopword_or_verb(t: &str) -> bool {
    matches!(
        t.to_ascii_lowercase().as_str(),
        "a" | "an"
            | "the"
            | "my"
            | "our"
            | "this"
            | "that"
            | "and"
            | "or"
            | "for"
            | "on"
            | "in"
            | "at"
            | "to"
            | "into"
            | "from"
            | "with"
            | "without"
            | "using"
            | "protect"
            | "seal"
            | "encrypt"
            | "lock"
            | "hide"
            | "block"
            | "deny"
            | "stop"
            | "scan"
            | "audit"
            | "check"
            | "test"
            | "verify"
            | "validate"
            | "run"
            | "execute"
            | "launch"
            | "start"
            | "serve"
            | "host"
            | "stream"
            | "unseal"
            | "decrypt"
            | "restore"
            | "recover"
            | "watermark"
            | "trace"
            | "demo"
            | "create"
            | "generate"
            | "make"
            | "init"
            | "website"
            | "site"
            | "app"
            | "folder"
            | "dir"
            | "directory"
            | "file"
            | "repo"
            | "binary"
            | "model"
            | "3d"
            | "port"
            | "behind"
            | "nginx"
            | "caddy"
            | "proxy"
            | "cloakbrowser"
            | "brave"
            | "fast"
            | "balanced"
            | "paranoid"
            | "strict"
            | "gpu"
            | "webgl"
            | "standalone"
            | "vault"
            | "config"
            | "secrets"
            | "secret"
            | "keys"
            | "key"
            | "buyer"
            | "user"
            | "customer"
    )
}

fn looks_like_explicit_path(t: &str) -> bool {
    if t.is_empty() || looks_like_url(t) || t.starts_with("--") {
        return false;
    }
    if t.starts_with("./")
        || t.starts_with("../")
        || t.starts_with('/')
        || t.starts_with("~/")
        || t.contains('/')
    {
        return true;
    }
    let low = t.to_ascii_lowercase();
    for ext in [
        ".glb",
        ".vs3d",
        ".vspk3",
        ".vspk",
        ".protected",
        ".json",
        ".rgb",
        ".bin",
        ".py",
        ".js",
        ".mjs",
        ".ts",
        ".rs",
        ".go",
        ".c",
        ".cpp",
        ".wasm",
        ".env",
        ".key",
        ".pem",
        ".html",
        ".safetensors",
        ".onnx",
        ".gguf",
    ] {
        if low.ends_with(ext) && low.len() > ext.len() {
            return true;
        }
    }
    false
}

fn looks_like_path(t: &str) -> bool {
    if looks_like_explicit_path(t) {
        return true;
    }
    if t.is_empty() || looks_like_url(t) || t.starts_with('-') || is_english_stopword_or_verb(t) {
        return false;
    }
    Path::new(t).exists()
}

fn has_any(hay: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| hay.contains(n))
}

fn extract_port(tokens: &[String]) -> Option<u16> {
    for (i, raw) in tokens.iter().enumerate() {
        let t = clean_token(raw);
        let low = t.to_ascii_lowercase();
        if (low == "port" || low == "on" || low == "at") && i + 1 < tokens.len() {
            let nxt = clean_token(&tokens[i + 1]);
            if let Ok(p) = nxt.parse::<u16>() {
                if p >= 80 {
                    return Some(p);
                }
            }
        }
        if let Some(rest) = t.strip_prefix(':') {
            if let Ok(p) = rest.parse::<u16>() {
                if p >= 80 {
                    return Some(p);
                }
            }
        }
    }
    None
}

fn extract_resolution(tokens: &[String]) -> Option<(usize, usize)> {
    for raw in tokens {
        let t = clean_token(raw).to_ascii_lowercase();
        if let Some((a, b)) = t.split_once('x') {
            if let (Ok(w), Ok(h)) = (a.parse::<usize>(), b.parse::<usize>()) {
                if (320..=1920).contains(&w) && (240..=1080).contains(&h) {
                    return Some((w, h));
                }
            }
        }
    }
    None
}

fn extract_buyer(tokens: &[String]) -> Option<String> {
    for i in 0..tokens.len() {
        let low = clean_token(&tokens[i]).to_ascii_lowercase();
        if (low == "buyer" || low == "user" || low == "customer" || low == "for")
            && i + 1 < tokens.len()
        {
            let cand = clean_token(&tokens[i + 1]);
            let clow = cand.to_ascii_lowercase();
            if matches!(
                clow.as_str(),
                "buyer" | "user" | "customer" | "my" | "the" | "a" | "an" | "leaked" | "secrets" | "api"
            ) {
                if i + 2 < tokens.len()
                    && matches!(clow.as_str(), "buyer" | "user" | "customer")
                {
                    let c2 = clean_token(&tokens[i + 2]);
                    if !c2.is_empty() && !looks_like_path(c2) {
                        return Some(c2.to_string());
                    }
                }
                continue;
            }
            if !cand.is_empty() && !looks_like_path(cand) && !looks_like_url(cand) {
                return Some(cand.to_string());
            }
        }
    }
    None
}

fn extract_output_and_targets(tokens: &[String]) -> (Vec<String>, Option<String>) {
    let mut targets = Vec::new();
    let mut out_path: Option<String> = None;
    let mut i = 0usize;
    while i < tokens.len() {
        let raw = clean_token(&tokens[i]);
        let low = raw.to_ascii_lowercase();
        if matches!(low.as_str(), "to" | "into" | "output" | "out" | "save" | "as" | "-o" | "--out")
            && i + 1 < tokens.len()
        {
            let mut j = i + 1;
            let mut nxt = clean_token(&tokens[j]);
            if matches!(nxt.to_ascii_lowercase().as_str(), "folder" | "dir" | "directory" | "file" | "path")
                && j + 1 < tokens.len()
            {
                j += 1;
                nxt = clean_token(&tokens[j]);
            }
            if !nxt.starts_with('-')
                && (looks_like_path(nxt) || nxt.contains('.') || nxt.contains('_'))
            {
                if !matches!(
                    nxt.to_ascii_lowercase().as_str(),
                    "fast" | "balanced" | "paranoid" | "strict" | "stream" | "gpu"
                ) {
                    out_path = Some(nxt.to_string());
                    i = j + 1;
                    continue;
                }
            }
        }
        if !raw.starts_with('-') && looks_like_path(raw) {
            targets.push(raw.to_string());
        }
        i += 1;
    }
    (targets, out_path)
}

fn detect_preset(low: &str) -> (&'static str, &'static str) {
    let blocking_automation = has_any(
        low,
        &[
            "block playwright",
            "deny playwright",
            "stop playwright",
            "block puppeteer",
            "block selenium",
            "block cypress",
        ],
    );
    let wants_fast = !blocking_automation
        && has_any(
            low,
            &[
                "fast",
                "dev mode",
                "local dev",
                "development",
                "for playwright",
                "allow playwright",
                "playwright test",
                "cypress",
                "ci test",
                "lightweight",
                "disable anti",
            ],
        );
    if wants_fast {
        ("fast", "Fast/dev preset selected for local testing or CI automation compatibility")
    } else if blocking_automation
        || has_any(
            low,
            &[
                "paranoid",
                "strict",
                "maximum",
                "max security",
                "strongest",
                "bulletproof",
                "hardcore",
                "cloakbrowser",
                "cloak browser",
                "anti-detect",
                "antidetect",
                "stealth browser",
                "zero geometry",
                "no geometry",
                "without sending geometry",
                "ai agent",
                "vibe revers",
                "harden js",
                "obfuscat",
            ],
        )
    {
        if has_any(low, &["brave", "privacy browser", "librewolf", "balanced"]) {
            (
                "balanced",
                "Balanced preset selected (score >= 4 anti-stealth threshold for higher privacy-browser tolerance)",
            )
        } else {
            (
                "paranoid",
                "Paranoid preset selected for maximum defense (strict anti-stealth, anti-CDP, JS rtKey hardening, zero-geometry 3D stream)",
            )
        }
    } else {
        (
            "balanced",
            "Balanced preset selected (strong default protection with zero false positives on clean Chrome/Firefox)",
        )
    }
}

fn infer_sibling_vsshield_key(dir: &str) -> Option<String> {
    let trimmed = dir.trim_end_matches('/');
    if let Some(stem) = trimmed.strip_suffix(".shielded") {
        let candidate = format!("{stem}.vsshield.key");
        if std::path::Path::new(&candidate).is_file() || trimmed.ends_with(".glb.shielded") {
            return Some(candidate);
        }
    }
    None
}

/// Translates a plain-English request into a concrete, explainable `vibe-slayer` CLI invocation.
pub fn compile_natural_language(sentence: &str) -> Result<NaturalPlan, String> {
    let trimmed = sentence.trim();
    if trimmed.is_empty() {
        return Err(
            "Please describe what you want in plain English. Example:\n  ./vibe-slayer ask \"protect my website ./dist and block stealth browsers\""
                .to_string(),
        );
    }

    let low = trimmed.to_ascii_lowercase();
    let tokens = tokenize_sentence(trimmed);
    let urls: Vec<String> = tokens
        .iter()
        .map(|t| clean_token(t))
        .filter(|t| looks_like_url(t))
        .map(|t| t.trim_end_matches('/').to_string())
        .collect();
    let (targets, out_path) = extract_output_and_targets(&tokens);
    let port = extract_port(&tokens);
    let res_wh = extract_resolution(&tokens);
    let buyer = extract_buyer(&tokens);
    let (preset, preset_reason) = detect_preset(&low);

    let negated_proxy = has_any(
        &low,
        &["without proxy", "without a proxy", "no proxy", "block proxy", "deny proxy"],
    );
    let behind_proxy = !negated_proxy
        && has_any(
            &low,
            &[
                "nginx",
                "caddy",
                "cloudflare",
                "reverse proxy",
                "behind proxy",
                "behind a proxy",
                "trust proxy",
            ],
        );

    // 1. Demo / walkthrough
    if has_any(&low, &["demo", "example", "try it", "walkthrough", "sandbox"])
        && targets.is_empty()
    {
        return Ok(NaturalPlan {
            input: trimmed.to_string(),
            intent: "demo",
            goal: "Run the built-in end-to-end Vibe-Slayer sandbox demo".to_string(),
            argv: vec!["demo".to_string()],
            reasons: vec![
                "Generates a temporary sample repo, scans secrets, protects code/binary/3D, verifies, and restores everything safely".to_string(),
            ],
            next_command: None,
        });
    }

    // 2. Generate config file
    if has_any(&low, &["config", "vibeslayer.config", "template", "settings file"])
        && has_any(&low, &["init", "create", "generate", "make", "write", "new"])
    {
        let out = out_path.unwrap_or_else(|| "vibeslayer.config.json".to_string());
        return Ok(NaturalPlan {
            input: trimmed.to_string(),
            intent: "init-config",
            goal: format!("Generate an editable '{preset}' configuration file at {out}"),
            argv: vec![
                "init-config".to_string(),
                "--preset".to_string(),
                preset.to_string(),
                "-o".to_string(),
                out.clone(),
            ],
            reasons: vec![
                preset_reason.to_string(),
                format!("Writes all website, serve, shield-3d, and serve-3d defaults into {out}"),
            ],
            next_command: Some(format!(
                "./vibe-slayer website ./your-site -o ./your-site-protected --config {out}"
            )),
        });
    }

    // 3. Scan / secret audit
    if has_any(&low, &["scan", "audit", "leak", "secret", "api key", "credential"])
        && !has_any(&low, &["protect", "encrypt", "seal", "website", "serve", "3d", "glb"])
    {
        let target = targets.first().cloned().ok_or_else(|| {
            "Tell me which folder or file to scan. Example:\n  ./vibe-slayer ask \"scan ./my-repo for leaked api keys\"".to_string()
        })?;
        return Ok(NaturalPlan {
            input: trimmed.to_string(),
            intent: "scan",
            goal: format!("Dry-run security scan and leaked-secret audit on {target}"),
            argv: vec!["scan".to_string(), target.clone()],
            reasons: vec![
                "Does not modify any files — inspects file types and flags exposed API keys, .env secrets, and private keys".to_string(),
            ],
            next_command: Some(format!("./vibe-slayer ask \"protect {target}\"")),
        });
    }

    // 4. Verify / test protected output
    if has_any(&low, &["test", "verify", "check if", "validate"])
        && !has_any(&low, &["website", "serve", "3d", "glb", "demo", "scan"])
    {
        let target = targets.first().cloned().ok_or_else(|| {
            "Tell me which protected file or folder to verify. Example:\n  ./vibe-slayer ask \"verify ./my-repo-protected\"".to_string()
        })?;
        return Ok(NaturalPlan {
            input: trimmed.to_string(),
            intent: "test",
            goal: format!("Run full cryptographic & tamper self-tests on {target}"),
            argv: vec!["test".to_string(), target],
            reasons: vec![
                "Verifies high entropy, 1-byte tamper rejection, wrong-key failure, ELF CET/anti-debug, and lossless SHA-256 restore".to_string(),
            ],
            next_command: None,
        });
    }

    // 5. Unseal / decrypt / restore (ignore negated phrases like "so nobody can decrypt" or "do not unseal")
    let wants_protect_not_unseal = has_any(
        &low,
        &[
            "protect ",
            "encrypt ",
            "seal ",
            "nobody can decrypt",
            "cannot decrypt",
            "can't decrypt",
            "do not unseal",
            "don't unseal",
        ],
    );
    if !wants_protect_not_unseal
        && has_any(&low, &["unseal", "decrypt", "restore", "recover", "unpack"])
    {
        let target = targets.first().cloned().ok_or_else(|| {
            "Tell me which protected file or folder to restore. Example:\n  ./vibe-slayer ask \"restore ./my-repo-protected to ./restored\"".to_string()
        })?;
        let mut argv = vec!["unseal".to_string(), target.clone()];
        let mut reasons = vec!["Losslessly restores original plaintext and verifies every SHA-256 digest".to_string()];
        if let Some(dest) = out_path {
            argv.push("-o".to_string());
            argv.push(dest.clone());
            reasons.push(format!("Writes restored files into {dest}"));
        }
        return Ok(NaturalPlan {
            input: trimmed.to_string(),
            intent: "unseal",
            goal: format!("Restore {target} back to verified plaintext"),
            argv,
            reasons,
            next_command: None,
        });
    }

    // 6. Run protected binary
    if has_any(&low, &["run ", "execute ", "launch "])
        && !has_any(&low, &["website", "site", "web", "serve", "3d", "model", "demo"])
    {
        let target = targets.first().cloned().ok_or_else(|| {
            "Tell me which protected executable to run. Example:\n  ./vibe-slayer ask \"run ./my_program.protected\"".to_string()
        })?;
        return Ok(NaturalPlan {
            input: trimmed.to_string(),
            intent: "run",
            goal: format!("Execute protected Linux binary {target} with private FD 3 lease"),
            argv: vec!["run".to_string(), target],
            reasons: vec![
                "Scrubs LD_PRELOAD/LD_AUDIT and injects the lease key over a private kernel pipe FD".to_string(),
            ],
            next_command: None,
        });
    }

    // 7. Trace leaked 3D stream frame or ripped geometry or WM64 positions
    if has_any(&low, &["trace", "find leaker", "identify buyer", "who leaked"]) {
        if let Some(rgb) = targets.iter().find(|p| p.to_ascii_lowercase().ends_with(".rgb")) {
            let explicit_key = targets
                .iter()
                .find(|p| p.to_ascii_lowercase().ends_with(".key"))
                .cloned();
            let dir = targets
                .iter()
                .find(|p| *p != rgb && explicit_key.as_deref() != Some(p.as_str()))
                .cloned()
                .ok_or_else(|| {
                    "Include both the shielded 3D directory and the .rgb frame path. Example:\n  ./vibe-slayer ask \"trace leaked frame ./frame.rgb 960x640 from ./hero.glb.shielded\"".to_string()
                })?;
            let key_opt = explicit_key.or_else(|| infer_sibling_vsshield_key(&dir));
            let (w, h) = res_wh.unwrap_or((960, 640));
            let mut argv = vec![
                "trace-stream-frame".to_string(),
                "--dir".to_string(),
                dir,
                "--rgb".to_string(),
                rgb.clone(),
                "--width".to_string(),
                w.to_string(),
                "--height".to_string(),
                h.to_string(),
            ];
            let mut reasons = vec![
                "Extracts the imperceptible post-JPEG 64-bit forensic buyer ID from raw RGB pixels".to_string(),
            ];
            if let Some(kf) = key_opt {
                argv.push("--key-file".to_string());
                argv.push(kf.clone());
                reasons.push(format!("Uses external 3D master key at {kf}"));
            }
            return Ok(NaturalPlan {
                input: trimmed.to_string(),
                intent: "trace-stream-frame",
                goal: format!("Blind-decode the 64-bit buyer watermark from 2D stream frame {rgb} ({w}x{h})"),
                argv,
                reasons,
                next_command: None,
            });
        }
        let target = targets.first().cloned().ok_or_else(|| {
            "Tell me which leaked positions file (.bin) or stream frame (.rgb) to trace.".to_string()
        })?;
        return Ok(NaturalPlan {
            input: trimmed.to_string(),
            intent: "trace",
            goal: format!("Decode 64-bit WM64 forensic buyer watermark from {target}"),
            argv: vec!["trace".to_string(), target],
            reasons: vec![
                "Runs O(1) BPSK spread-spectrum correlation (survives +/-2 LSB coordinate noise)".to_string(),
            ],
            next_command: None,
        });
    }

    // 8. Watermark 3D VS3D model
    if has_any(&low, &["watermark", "fingerprint 3d", "tag model"]) {
        let target = targets.first().cloned().ok_or_else(|| {
            "Tell me which .vs3d file to watermark. Example:\n  ./vibe-slayer ask \"watermark ./model.vs3d for buyer alice\"".to_string()
        })?;
        let b = buyer.unwrap_or_else(|| "customer_1".to_string());
        let mut argv = vec![
            "watermark".to_string(),
            target.clone(),
            "--buyer".to_string(),
            b.clone(),
        ];
        if let Some(dest) = out_path {
            argv.push("-o".to_string());
            argv.push(dest);
        }
        return Ok(NaturalPlan {
            input: trimmed.to_string(),
            intent: "watermark",
            goal: format!("Embed a 64-bit buyer watermark ({b}) into {target}"),
            argv,
            reasons: vec![
                format!("Binds a 64-bit spread-spectrum traitor ID to buyer '{b}' with 0 frame overhead"),
            ],
            next_command: None,
        });
    }

    // 9. 3D Shield / Zero-Geometry Encrypted Stream (skip when user clearly targets AI weights)
    let is_ai_weights = has_any(
        &low,
        &[
            ".safetensors",
            ".onnx",
            ".gguf",
            ".ckpt",
            "ai model",
            "ml model",
            "llm",
            "weights",
            "tensor",
        ],
    ) || targets.iter().any(|p| {
        let lp = p.to_ascii_lowercase();
        lp.ends_with(".safetensors")
            || lp.ends_with(".onnx")
            || lp.ends_with(".gguf")
            || lp.ends_with(".pt")
            || lp.ends_with(".ckpt")
    });
    let is_3d = !is_ai_weights
        && has_any(&low, &["3d", ".glb", "glb", "mesh", "geometry", "stream", "model"]);
    if is_3d {
        let glb_target = targets
            .iter()
            .find(|p| p.to_ascii_lowercase().ends_with(".glb"))
            .cloned();
        let is_serve_3d = glb_target.is_none()
            && has_any(&low, &["serve", "host", "start", "launch", "viewer", "stream"]);

        if is_serve_3d {
            let explicit_key = targets
                .iter()
                .find(|p| p.to_ascii_lowercase().ends_with(".key"))
                .cloned();
            let dir = targets
                .iter()
                .find(|p| explicit_key.as_deref() != Some(p.as_str()))
                .cloned()
                .ok_or_else(|| {
                    "Tell me which shielded 3D directory to serve. Example:\n  ./vibe-slayer ask \"serve my 3d model ./hero.glb.shielded on port 8790\"".to_string()
                })?;
            let key_opt = explicit_key.or_else(|| infer_sibling_vsshield_key(&dir));
            let mode = if has_any(&low, &["gpu", "webgl", "60 fps", "60fps"]) {
                "gpu"
            } else if has_any(&low, &["stream", "zero geometry", "no geometry", "without sending geometry"])
                || preset == "paranoid"
            {
                "stream"
            } else {
                "gpu"
            };
            let p = port.unwrap_or(8790);
            let addr = format!("127.0.0.1:{p}");
            let origin = urls
                .first()
                .cloned()
                .unwrap_or_else(|| format!("http://{addr}"));
            let mut argv = vec![
                "serve-3d".to_string(),
                dir.clone(),
                "--preset".to_string(),
                preset.to_string(),
                "--mode".to_string(),
                mode.to_string(),
                "--addr".to_string(),
                addr.clone(),
                "--origin".to_string(),
                origin.clone(),
            ];
            let mut reasons = vec![
                preset_reason.to_string(),
                if mode == "stream" {
                    "--mode stream: renders frames server-side with AES-256-GCM wire encryption and 0 geometry sent to the browser".to_string()
                } else {
                    "--mode gpu: native 60 FPS encrypted WebGL2 shader viewer with scrambled tiles & server-baked watermark".to_string()
                },
            ];
            if let Some(kf) = key_opt {
                argv.push("--key-file".to_string());
                argv.push(kf.clone());
                reasons.push(format!("--key-file {kf}: loads the external 32-byte 3D master key"));
            }
            if let Some((w, h)) = res_wh {
                argv.push("--stream-width".to_string());
                argv.push(w.to_string());
                argv.push("--stream-height".to_string());
                argv.push(h.to_string());
                reasons.push(format!("Stream resolution set to {w}x{h}"));
            }
            if behind_proxy {
                argv.push("--trust-proxy".to_string());
                argv.push("127.0.0.1".to_string());
                reasons.push("--trust-proxy 127.0.0.1: trusts reverse proxy X-Forwarded-For/Host headers".to_string());
            }
            return Ok(NaturalPlan {
                input: trimmed.to_string(),
                intent: "serve-3d",
                goal: format!("Serve protected 3D viewer for {dir} in '{mode}' mode at {origin}"),
                argv,
                reasons,
                next_command: None,
            });
        }

        let glb = glb_target.or_else(|| targets.first().cloned()).ok_or_else(|| {
            "Tell me which .glb 3D model file to protect. Example:\n  ./vibe-slayer ask \"protect and stream my 3d model ./hero.glb without sending geometry\"".to_string()
        })?;
        let out_dir = out_path.unwrap_or_else(|| format!("{glb}.shielded"));
        let key_file = format!("{glb}.vsshield.key");
        let p = port.unwrap_or(8790);
        let serve_mode = if has_any(&low, &["gpu", "webgl", "60 fps"]) {
            "gpu"
        } else if has_any(&low, &["stream", "zero geometry", "no geometry", "without sending geometry"])
            || preset == "paranoid"
        {
            "stream"
        } else {
            "gpu"
        };
        let next = format!(
            "./vibe-slayer serve-3d {out_dir} --preset {preset} --mode {serve_mode} --key-file {key_file} --addr 127.0.0.1:{p} --origin http://127.0.0.1:{p}"
        );
        return Ok(NaturalPlan {
            input: trimmed.to_string(),
            intent: "shield-3d",
            goal: format!("Cook encrypted 3D bundle for {glb} (key stored outside bundle at {key_file})"),
            argv: vec![
                "shield-3d".to_string(),
                "--in".to_string(),
                glb,
                "--out".to_string(),
                out_dir,
                "--key-file".to_string(),
                key_file,
                "--preset".to_string(),
                preset.to_string(),
            ],
            reasons: vec![
                preset_reason.to_string(),
                "--key-file keeps the master 32-byte key safely outside the served bundle directory".to_string(),
                format!("Ready to launch in '--mode {serve_mode}' right after cooking"),
            ],
            next_command: Some(next),
        });
    }

    // 10. Live Website & Web Components (serve vs website build)
    let is_web = has_any(
        &low,
        &[
            "website",
            "web site",
            "web app",
            "webapp",
            "web component",
            "webcomponent",
            "frontend",
            "spa",
            "react",
            "vue",
            "svelte",
            "html",
            "site",
            "cloakbrowser",
            "cloak browser",
        ],
    );
    let wants_serve = has_any(&low, &["serve ", "host ", "start server", "run server", "launch server"])
        || (low.starts_with("serve") || low.starts_with("host"));

    if is_web && wants_serve && !has_any(&low, &["protect ", "seal ", "build ", "encrypt "]) {
        let dir = targets.first().cloned().ok_or_else(|| {
            "Tell me which protected website directory to serve. Example:\n  ./vibe-slayer ask \"serve my website ./dist-protected on port 8080\"".to_string()
        })?;
        let p = port.unwrap_or(8080);
        let addr = format!("127.0.0.1:{p}");
        let origin = urls
            .first()
            .cloned()
            .unwrap_or_else(|| format!("http://{addr}"));
        let mut argv = vec![
            "serve".to_string(),
            dir.clone(),
            "--preset".to_string(),
            preset.to_string(),
            "--addr".to_string(),
            addr,
            "--origin".to_string(),
            origin.clone(),
        ];
        let mut reasons = vec![preset_reason.to_string()];
        if has_any(&low, &["cloakbrowser", "cloak browser", "anti-detect", "stealth"]) {
            let st = if has_any(&low, &["brave", "privacy", "balanced"]) {
                "balanced"
            } else {
                "strict"
            };
            argv.push("--anti-stealth".to_string());
            argv.push(st.to_string());
            reasons.push(format!(
                "--anti-stealth {st}: enforces server-side anti-detect / stealth browser & OS-header checks"
            ));
        }
        if behind_proxy {
            argv.push("--trust-proxy".to_string());
            argv.push("127.0.0.1".to_string());
            reasons.push("--trust-proxy 127.0.0.1: honors X-Forwarded-For and X-Forwarded-Host from your local reverse proxy".to_string());
        }
        return Ok(NaturalPlan {
            input: trimmed.to_string(),
            intent: "serve",
            goal: format!("Start zero-Node encrypted web runtime server for {dir} at {origin}"),
            argv,
            reasons,
            next_command: None,
        });
    }

    if is_web {
        let dir = targets.first().cloned().ok_or_else(|| {
            "Tell me which website folder to protect. Example:\n  ./vibe-slayer ask \"protect my website ./dist and block cloakbrowser\"".to_string()
        })?;
        let out_dir = out_path.unwrap_or_else(|| format!("{}-protected", dir.trim_end_matches('/')));
        let p = port.unwrap_or(8080);
        let origin = urls
            .first()
            .cloned()
            .unwrap_or_else(|| format!("http://127.0.0.1:{p}"));

        let mut argv = vec![
            "website".to_string(),
            dir.clone(),
            "-o".to_string(),
            out_dir.clone(),
            "--preset".to_string(),
            preset.to_string(),
            "--origin".to_string(),
            origin.clone(),
        ];
        let mut reasons = vec![preset_reason.to_string()];

        let stealth_mode = if has_any(&low, &["cloakbrowser", "cloak browser", "anti-detect", "stealth"]) {
            if has_any(&low, &["brave", "privacy", "balanced"]) {
                Some("balanced")
            } else {
                Some("strict")
            }
        } else {
            None
        };
        if let Some(st) = stealth_mode {
            argv.push("--anti-stealth".to_string());
            argv.push(st.to_string());
            if preset != "paranoid" {
                argv.push("--harden-js".to_string());
                reasons.push("--harden-js: embeds inline synchronous anti-stealth self-defense guard inside every .js/.mjs Web Component".to_string());
            }
            reasons.push(format!(
                "--anti-stealth {st}: blocks anti-detect / stealth browsers (e.g. CloakBrowser) via 6 rendering & OS invariants before any lease or Custom Element mounts"
            ));
        }

        let mut next = format!(
            "./vibe-slayer serve {out_dir} --preset {preset} --addr 127.0.0.1:{p} --origin {origin}"
        );
        if let Some(st) = stealth_mode {
            next.push_str(&format!(" --anti-stealth {st}"));
        }
        if behind_proxy {
            next.push_str(" --trust-proxy 127.0.0.1");
        }

        return Ok(NaturalPlan {
            input: trimmed.to_string(),
            intent: "website",
            goal: format!("Encrypt website & Web Components in {dir} -> {out_dir}"),
            argv,
            reasons,
            next_command: Some(next),
        });
    }

    // 11. Default: Repository, File, or Native Binary Protection
    let target = targets.first().cloned().ok_or_else(|| {
        "I couldn't find a file or folder path in your request.\n\
Examples you can try:\n\
  ./vibe-slayer ask \"show me a demo\"\n\
  ./vibe-slayer ask \"scan ./my-repo for leaked secrets\"\n\
  ./vibe-slayer ask \"protect my website ./dist and block cloakbrowser\"\n\
  ./vibe-slayer ask \"stream my 3d model ./hero.glb without sending geometry\"\n\
  ./vibe-slayer ask \"protect ./my-repo\""
            .to_string()
    })?;

    let mut argv = vec!["protect".to_string(), target.clone()];
    let mut reasons = vec![
        "Auto-classifies code, secrets, .wasm, AI weights (VSPK3), Linux ELF64 binaries (static-PIE CET), and .glb models".to_string(),
    ];
    let custom_out = out_path.clone();
    if let Some(dest) = out_path {
        argv.push("-o".to_string());
        argv.push(dest);
    }
    let negated_standalone = has_any(&low, &["without standalone", "no standalone", "not standalone"]);
    if !negated_standalone
        && has_any(&low, &["standalone", "without keys", "self-contained", "no keys file"])
    {
        argv.push("--standalone".to_string());
        reasons.push("--standalone: wrapped ELF executable runs directly without ./vibe-slayer run".to_string());
    }
    if has_any(&low, &["everything", "all files", "seal all", "seal-all", "including readme"]) {
        argv.push("--seal-all".to_string());
        reasons.push("--seal-all: encrypts even public scaffold files (README, CSS, images)".to_string());
    }
    let is_vault = has_any(&low, &["vault", "memfd_secret", "small secret"]);
    if is_vault {
        argv.push("--vault".to_string());
        reasons.push("--vault: packs small secret (<=4096 B) into a freestanding memfd_secret ELF vault".to_string());
    }

    let next_target = if let Some(dest) = custom_out {
        dest
    } else if is_vault {
        format!("{target}.vault.elf")
    } else {
        let p = std::path::Path::new(&target);
        let tlow = target.to_ascii_lowercase();
        if tlow.ends_with(".glb") {
            format!("{target}.vs3d")
        } else if p.is_dir() {
            format!("{target}-protected")
        } else if has_any(&low, &["binary", "executable", "elf"])
            || tlow.ends_with(".elf")
            || tlow.ends_with(".out")
        {
            format!("{target}.protected")
        } else if p.extension().is_some() {
            format!("{target}.vspk3")
        } else {
            format!("{target}-protected")
        }
    };

    Ok(NaturalPlan {
        input: trimmed.to_string(),
        intent: "protect",
        goal: format!("Auto-protect {target} and run immediate cryptographic self-verification"),
        argv,
        reasons,
        next_command: Some(format!("./vibe-slayer test {next_target}")),
    })
}

pub fn print_plan_human(plan: &NaturalPlan, dry_run: bool) {
    println!("[vibe-slayer natural language]");
    println!("  You asked: \"{}\"", plan.input);
    println!("  Goal:      {}", plan.goal);
    println!("  Command:   {}", plan.display_command());
    if !plan.reasons.is_empty() {
        println!("  Why:");
        for r in &plan.reasons {
            println!("    - {r}");
        }
    }
    if let Some(ref next) = plan.next_command {
        println!("  Next step:");
        println!("    {next}");
    }
    if dry_run {
        println!("  Mode:      DRY-RUN (remove --dry-run or use './vibe-slayer ask ...' to execute)");
    } else {
        println!();
    }
}

pub fn parse_nl_cli_args(rest: &[String], force_dry_run: bool) -> (String, bool, bool) {
    let mut dry_run = force_dry_run;
    let mut as_json = false;
    let mut words = Vec::new();
    for a in rest {
        match a.as_str() {
            "--dry-run" | "--explain" | "-n" => dry_run = true,
            "--yes" | "-y" | "--exec" => {
                if !force_dry_run {
                    dry_run = false;
                }
            }
            "--json" => as_json = true,
            _ => words.push(a.clone()),
        }
    }
    (words.join(" "), dry_run, as_json)
}

pub fn format_plan_json(plan: &NaturalPlan, dry_run: bool) -> String {
    to_json_pretty(&plan.to_json(dry_run))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nl_translates_website_cloakbrowser_and_3d_stream_and_repo() {
        let p1 = compile_natural_language(
            "protect my website ./dist and block cloakbrowser on port 9090",
        )
        .unwrap();
        assert_eq!(p1.intent, "website");
        assert!(p1.argv.contains(&"website".to_string()));
        assert!(p1.argv.contains(&"./dist".to_string()));
        assert!(p1.argv.contains(&"paranoid".to_string()));
        assert!(p1.argv.contains(&"strict".to_string()));
        assert!(p1.next_command.as_deref().unwrap().contains("127.0.0.1:9090"));

        let p2 = compile_natural_language(
            "protect my website ./dist and block cloakbrowser while keeping brave working",
        )
        .unwrap();
        assert_eq!(p2.intent, "website");
        assert!(p2.argv.contains(&"balanced".to_string()));
        assert!(p2.argv.contains(&"--harden-js".to_string()));

        let p3 = compile_natural_language(
            "stream my 3d model ./hero.glb without sending geometry",
        )
        .unwrap();
        assert_eq!(p3.intent, "shield-3d");
        assert!(p3.argv.contains(&"./hero.glb".to_string()));
        assert!(p3.argv.contains(&"paranoid".to_string()));
        assert!(p3.next_command.as_deref().unwrap().contains("--mode stream"));

        let p4 = compile_natural_language("serve my protected website ./dist-protected on port 9000 behind nginx").unwrap();
        assert_eq!(p4.intent, "serve");
        assert!(p4.argv.contains(&"--trust-proxy".to_string()));
        assert!(p4.argv.contains(&"127.0.0.1:9000".to_string()));

        let p5 = compile_natural_language("scan ./my-repo for leaked api keys").unwrap();
        assert_eq!(p5.intent, "scan");
        assert_eq!(p5.argv, vec!["scan", "./my-repo"]);

        let p6 = compile_natural_language("restore ./my-repo-protected to ./clean-copy").unwrap();
        assert_eq!(p6.intent, "unseal");
        assert_eq!(p6.argv, vec!["unseal", "./my-repo-protected", "-o", "./clean-copy"]);

        let p7 = compile_natural_language("show me a demo").unwrap();
        assert_eq!(p7.intent, "demo");
        assert_eq!(p7.argv, vec!["demo"]);

        // Regression tests from multi-persona review
        let p8 = compile_natural_language("protect my website ./dist and block playwright").unwrap();
        assert_eq!(p8.intent, "website");
        assert!(p8.argv.contains(&"paranoid".to_string()));

        let p9 = compile_natural_language("protect my ai model ./weights.safetensors").unwrap();
        assert_eq!(p9.intent, "protect");
        assert!(p9.argv.contains(&"./weights.safetensors".to_string()));

        let p10 = compile_natural_language("protect ./app so nobody can decrypt it").unwrap();
        assert_eq!(p10.intent, "protect");

        let p11 = compile_natural_language("serve my 3d model ./hero.glb.shielded on port 8790 without sending geometry").unwrap();
        assert_eq!(p11.intent, "serve-3d");
        assert!(p11.argv.contains(&"--key-file".to_string()));
        assert!(p11.argv.contains(&"./hero.glb.vsshield.key".to_string()));

        let p12 = compile_natural_language("trace leaked frame ./frame.rgb 960x640 from ./hero.glb.shielded").unwrap();
        assert_eq!(p12.intent, "trace-stream-frame");
        assert!(p12.argv.contains(&"--key-file".to_string()));
        assert!(p12.argv.contains(&"./hero.glb.vsshield.key".to_string()));
    }
}
