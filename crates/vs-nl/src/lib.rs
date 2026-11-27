//! `vs-nl`: Compact, modular, offline deterministic natural-language command builder.
//!
//! Design (`#![forbid(unsafe_code)]`):
//! - Tokenizes quoted paths (`"./my model.glb"`) without letting mid-word apostrophes (`let's`)
//!   break quoting, rejects hyphen-prefixed flag injection tokens (`--in=...`), and POSIX-quotes
//!   display/next commands safely against shell metacharacters.
//! - Strips extracted path tokens BEFORE whole-word verb classification, trims trailing sentence
//!   punctuation (`"run demo."`), and avoids CWD-filename hijacking.
//! - Emits canonical v2 CLI invocations (`serve-3d --bind`, `trace-3d`, `vault seal/unseal/inspect`,
//!   `website`, `serve`, `token mint`, `scan`, `demo`) guaranteed to parse cleanly in `vibe-slayer`.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NaturalPlan {
    pub input: String,
    pub intent: String,
    pub goal: String,
    pub argv: Vec<String>,
    pub reasons: Vec<String>,
    pub next_command: Option<String>,
}

fn shell_quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_./:@=-".contains(&b))
    {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

impl NaturalPlan {
    pub fn display_command(&self) -> String {
        let mut out = String::from("./vibe-slayer");
        for arg in &self.argv {
            out.push(' ');
            out.push_str(&shell_quote(arg));
        }
        out
    }
}

fn tokenize_shell_like(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for ch in input.chars() {
        match quote {
            Some(q) if ch == q => {
                quote = None;
            }
            Some(_) => cur.push(ch),
            // Only enter quote mode at start of token so contractions ("let's", "bob's") stay intact (Loop 3 MED-14)
            None if (ch == '"' || ch == '\'') && cur.is_empty() => {
                quote = Some(ch);
            }
            None if ch.is_whitespace() => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            None => cur.push(ch),
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

fn is_path_token(w: &str) -> bool {
    let clean = w.trim_matches(|c: char| matches!(c, ',' | ';' | '(' | ')'));
    // Reject hyphen-prefixed flag injection tokens (e.g. `--in=/etc/passwd.vsp3`, `-h.bin` — Loop 3 MED-13)
    if clean.is_empty() || clean.starts_with('-') {
        return false;
    }
    clean.starts_with("./")
        || clean.starts_with("../")
        || clean.starts_with('/')
        || [
            ".glb",
            ".vspk3",
            ".vsp3",
            ".vsweb",
            ".safetensors",
            ".png",
            ".jpg",
            ".jpeg",
            ".webp",
            ".bin",
        ]
        .iter()
        .any(|ext| clean.to_ascii_lowercase().ends_with(ext))
}

fn has_word(words: &[String], candidates: &[&str]) -> bool {
    words
        .iter()
        .any(|w| candidates.iter().any(|c| w.eq_ignore_ascii_case(c)))
}

fn extract_port(words: &[String], default_port: u16) -> u16 {
    for w in words.windows(2) {
        if w[0].eq_ignore_ascii_case("port") || w[0].eq_ignore_ascii_case("on") {
            if let Ok(p) = w[1]
                .trim_matches(|c: char| !c.is_ascii_digit())
                .parse::<u16>()
            {
                if p >= 80 {
                    return p;
                }
            }
        }
    }
    default_port
}

/// Translate plain English into an auditable Vibe-Slayer v2 CLI plan (offline and deterministic).
pub fn translate(input: &str) -> Result<NaturalPlan, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(
            "Provide a plain-English request, e.g.: explain \"stream ./hero.glb on port 8790\""
                .into(),
        );
    }

    let raw_tokens = tokenize_shell_like(trimmed);
    let mut paths = Vec::new();
    let mut prose_words = Vec::new();
    for tok in raw_tokens {
        let path_clean = tok
            .trim_matches(|c: char| matches!(c, ',' | ';' | '(' | ')'))
            .to_string();
        if is_path_token(&path_clean) {
            paths.push(path_clean);
        } else {
            let word_clean = tok
                .trim_matches(|c: char| matches!(c, ',' | ';' | '(' | ')' | '.' | '!' | '?'))
                .to_ascii_lowercase();
            if !word_clean.is_empty() {
                prose_words.push(word_clean);
            }
        }
    }

    // 1. Token minting first so "mint token for ./hero.glb" routes to `token mint` (Loop 3 MED-15)
    if has_word(&prose_words, &["token", "grant", "mint"]) {
        let asset_id = paths
            .first()
            .and_then(|p| {
                std::path::Path::new(p)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .filter(|s| !s.is_empty() && !s.starts_with('-'))
                    .map(String::from)
            })
            .unwrap_or_else(|| "model".to_string());
        return Ok(NaturalPlan {
            input: trimmed.into(),
            intent: "token-mint".into(),
            goal: format!("Mint an IP-agnostic HMAC-SHA256 session grant token for {asset_id}"),
            argv: vec![
                "token".into(),
                "mint".into(),
                "--subject".into(),
                "viewer-1".into(),
                "--asset-id".into(),
                asset_id,
            ],
            reasons: vec![
                "Binds subject, origin audience, asset_id, scope, and jti with expiry".into(),
            ],
            next_command: None,
        });
    }

    // 2. Explicit scan/audit verbs ONLY (never bare nouns "secrets"/"leaks" — Loop 3 MED-15)
    if has_word(&prose_words, &["scan", "audit"]) {
        let target = paths
            .first()
            .cloned()
            .unwrap_or_else(|| ".".to_string());
        return Ok(NaturalPlan {
            input: trimmed.into(),
            intent: "scan".into(),
            goal: format!("Scan {target} for hardcoded secrets and private keys"),
            argv: vec!["scan".into(), target],
            reasons: vec!["Read-only static secret & key audit across source files".into()],
            next_command: None,
        });
    }

    // 3. Blind forensic watermark tracing (only trigger on bare "watermark" if NOT streaming/serving 3D)
    let is_streaming_3d = has_word(&prose_words, &["stream", "serve", "3d", "mesh", "cad"]);
    if has_word(&prose_words, &["trace", "attribute"])
        || (has_word(&prose_words, &["watermark"]) && !is_streaming_3d)
    {
        let img = paths
            .first()
            .cloned()
            .ok_or_else(|| "Specify the leaked image path (e.g. ./leaked.png)".to_string())?;
        return Ok(NaturalPlan {
            input: trimmed.into(),
            intent: "trace-3d".into(),
            goal: format!("Extract blind crop/scale-resilient 64-bit forensic watermark from {img}"),
            argv: vec!["trace-3d".into(), "--image".into(), img],
            reasons: vec![
                "Runs 128x128 2D-FFT phase-correlation sync + mid-band DCT blind decoder with 32-bit MAC".into(),
                "Reads key from VIBESLAYER_KEY env or pass --key-file <path>".into(),
            ],
            next_command: None,
        });
    }

    // 4. Vault inspect
    if has_word(&prose_words, &["inspect"]) {
        let target = paths
            .first()
            .cloned()
            .ok_or_else(|| "Specify the VSPK3 v2 vault path (e.g. ./asset.vsp3)".to_string())?;
        return Ok(NaturalPlan {
            input: trimmed.into(),
            intent: "vault-inspect".into(),
            goal: format!("Verify header commitment and chunk layout of {target}"),
            argv: vec!["vault".into(), "inspect".into(), target],
            reasons: vec![
                "Authenticates 64-byte header commitment and terminal chunk in O(1)".into(),
            ],
            next_command: None,
        });
    }

    // 5. Vault unseal
    if has_word(&prose_words, &["unseal", "decrypt", "restore"]) {
        let target = paths
            .first()
            .cloned()
            .ok_or_else(|| "Specify the sealed vault file (e.g. ./asset.vsp3)".to_string())?;
        let out = target
            .strip_suffix(".vsp3")
            .or_else(|| target.strip_suffix(".vspk3"))
            .map(|s| format!("{s}.restored"))
            .unwrap_or_else(|| format!("{target}.restored"));
        return Ok(NaturalPlan {
            input: trimmed.into(),
            intent: "vault-unseal".into(),
            goal: format!("Stream-unseal VSPK3 v2 vault {target} -> {out}"),
            argv: vec!["vault".into(), "unseal".into(), target, "-o".into(), out],
            reasons: vec![
                "64-bit STREAM chunked AEAD + atomic 0600 temp staging + constant-time CMT-4".into(),
                "Reads key from VIBESLAYER_KEY env or pass --key-file <path>".into(),
            ],
            next_command: None,
        });
    }

    // 6. Serve .vsweb BEFORE `website` bundling so "serve website ./app.vsweb" routes to `serve`!
    if has_word(&prose_words, &["serve"])
        && paths.iter().any(|p| p.to_ascii_lowercase().ends_with(".vsweb"))
    {
        let bundle = paths
            .iter()
            .find(|p| p.to_ascii_lowercase().ends_with(".vsweb"))
            .cloned()
            .unwrap_or_default();
        let port = extract_port(&prose_words, 8080);
        return Ok(NaturalPlan {
            input: trimmed.into(),
            intent: "serve".into(),
            goal: format!("Serve authenticated .vsweb v2 bundle {bundle} on port {port}"),
            argv: vec![
                "serve".into(),
                bundle,
                "--bind".into(),
                format!("127.0.0.1:{port}"),
            ],
            reasons: vec![
                "Async Tokio/Axum server with ephemeral ECDH lease handshakes & immutable /assets/*".into(),
            ],
            next_command: None,
        });
    }

    // 7. Website bundling BEFORE generic `seal`/`protect` so "protect website ./dist" routes to `website`!
    if has_word(&prose_words, &["bundle", "website", "pack-site"]) {
        let dir = paths
            .first()
            .cloned()
            .ok_or_else(|| "Specify the web build directory (e.g. ./dist)".to_string())?;
        let out = format!("{}.vsweb", dir.trim_end_matches('/'));
        return Ok(NaturalPlan {
            input: trimmed.into(),
            intent: "website".into(),
            goal: format!("Bundle web directory {dir} into authenticated .vsweb v2 archive -> {out}"),
            argv: vec!["website".into(), dir, "--out".into(), out.clone()],
            reasons: vec![
                "Per-asset HKDF AES-256-GCM sealing + HMAC-SHA256 manifest authenticator".into(),
            ],
            next_command: Some(format!(
                "./vibe-slayer serve {} --bind 127.0.0.1:8080",
                shell_quote(&out)
            )),
        });
    }

    // 8. Generic file sealing into VSPK3 v2 STREAM
    if has_word(&prose_words, &["seal", "encrypt", "vault", "protect"])
        && !paths.iter().any(|p| p.to_ascii_lowercase().ends_with(".glb"))
    {
        let target = paths
            .first()
            .cloned()
            .ok_or_else(|| "Specify a file to seal (e.g. ./weights.safetensors)".to_string())?;
        let out = format!("{target}.vsp3");
        return Ok(NaturalPlan {
            input: trimmed.into(),
            intent: "vault-seal".into(),
            goal: format!("Seal {target} into 64-bit VSPK3 v2 streaming AEAD vault -> {out}"),
            argv: vec![
                "vault".into(),
                "seal".into(),
                target,
                "-o".into(),
                out.clone(),
            ],
            reasons: vec![
                "Headerless 64-bit Rogaway-Zhang STREAM + proved Bellare-Hoang CMT-4 (supports >4 GiB)".into(),
                "Reads key from VIBESLAYER_KEY env or pass --key-file <path>".into(),
            ],
            next_command: Some(format!(
                "./vibe-slayer vault unseal {} -o {}",
                shell_quote(&out),
                shell_quote(&format!("{out}.verified"))
            )),
        });
    }

    // 9. Server-side 3D pixel streaming
    if is_streaming_3d
        || has_word(&prose_words, &["model"])
        || paths.iter().any(|p| p.to_ascii_lowercase().ends_with(".glb"))
    {
        let target = paths.first().cloned().ok_or_else(|| {
            "Specify a .glb file or directory of .glb models (e.g. ./hero.glb)".to_string()
        })?;
        let port = extract_port(&prose_words, 8790);
        return Ok(NaturalPlan {
            input: trimmed.into(),
            intent: "serve-3d".into(),
            goal: format!("Stream server-rendered encrypted 3D frames for {target} on port {port}"),
            argv: vec![
                "serve-3d".into(),
                target,
                "--bind".into(),
                format!("127.0.0.1:{port}"),
            ],
            reasons: vec![
                "Async Tokio/Axum multi-SKU PBR stream server (geometry, UVs, and shaders stay on the server)".into(),
                "Includes crop/scale-resilient 32-bit-MAC watermark + spherical anti-3DGS view budget".into(),
            ],
            next_command: Some(format!("Open http://127.0.0.1:{port}/v1/models")),
        });
    }

    // 10. Built-in demo
    if has_word(&prose_words, &["demo", "example", "sandbox", "self-check"]) {
        return Ok(NaturalPlan {
            input: trimmed.into(),
            intent: "demo".into(),
            goal: "Run built-in cryptographic & watermark self-verification demo".into(),
            argv: vec!["demo".into()],
            reasons: vec![
                "Runs VSPK3 v2 STREAM, blind watermark 32-bit MAC, and sanity checks".into(),
            ],
            next_command: None,
        });
    }

    Err(format!(
        "Could not classify request '{trimmed}'. Try:\n  \
         - explain \"stream ./hero.glb on port 8790\"\n  \
         - explain \"trace watermark in ./leaked.png\"\n  \
         - explain \"seal ./weights.safetensors\"\n  \
         - explain \"scan ./my-repo\"\n  \
         - explain \"run demo\""
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn translates_core_intents_without_filename_hijacking() {
        let p1 = translate("stream ./hero.glb on port 9090").unwrap();
        assert_eq!(p1.intent, "serve-3d");
        assert_eq!(
            p1.argv,
            vec!["serve-3d", "./hero.glb", "--bind", "127.0.0.1:9090"]
        );

        let p2 = translate("seal ./model.safetensors").unwrap();
        assert_eq!(p2.intent, "vault-seal");
        assert_eq!(p2.argv[0], "vault");
        assert_eq!(p2.argv[1], "seal");

        let p3 = translate("scan ./demo-repo").unwrap();
        assert_eq!(p3.intent, "scan");
        assert_eq!(p3.argv, vec!["scan", "./demo-repo"]);

        let p4 = translate("trace watermark in ./leaked.webp").unwrap();
        assert_eq!(p4.intent, "trace-3d");
        assert_eq!(p4.argv, vec!["trace-3d", "--image", "./leaked.webp"]);

        let p5 = translate("run demo.").unwrap();
        assert_eq!(p5.intent, "demo");

        // Loop 3 regressions: contractions, precedence, flag injection, POSIX shell escaping
        assert_eq!(translate("let's stream ./hero.glb with watermark").unwrap().intent, "serve-3d");
        assert_eq!(translate("encrypt secrets in ./keys.bin").unwrap().intent, "vault-seal");
        assert_eq!(translate("trace leaks in ./leaked.png").unwrap().intent, "trace-3d");
        assert_eq!(translate("serve website ./app.vsweb on port 8080").unwrap().intent, "serve");
        assert_eq!(translate("protect website ./dist").unwrap().intent, "website");
        assert_eq!(translate("mint token for ./hero.glb").unwrap().intent, "token-mint");
        assert!(translate("inspect --in=/etc/passwd.vsp3").is_err());
        let p_shell = translate("seal \"./a.bin; id\"").unwrap();
        assert!(p_shell.display_command().contains("'./a.bin; id'"));
    }
}
