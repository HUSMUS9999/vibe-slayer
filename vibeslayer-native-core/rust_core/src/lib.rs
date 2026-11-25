//! `vibeslayer-core` (`v2.0.0-alpha.1`) — Modular, `#![forbid(unsafe_code)]` library facade.
//!
//! All core capabilities live in standalone, reusable workspace crates:
//! - [`vs_crypto`]: Audited `ring` (BoringSSL) P-256 ECDH, AES-256-GCM, ChaCha20-Poly1305, HKDF,
//!   HMAC, latched monotonic `SessionAead`, pre-expanded `StreamAeadKey`, and session grants.
//! - [`vs_vault`]: 64-bit STREAM `VSPK3 v2` (constant RAM, CMT-4 key commitment, unified opaque
//!   auth errors, O(1) random access, `KmsProvider`) + audited `VSPK3 v1` and `VSPK2`.
//! - [`vs_watermark`]: Blind crop-, scale-, and JPEG-resilient forensic watermarker (32-bit MAC +
//!   2D FFT phase correlation + Chase decoding) + Tardos collusion-resistant fingerprinting.
//! - [`vs_3d`]: Spec-compliant glTF 2.0 PBR renderer, bounded multi-SKU `AssetCatalog`, smooth
//!   harmonic anti-3DGS perturbation, and 192-bin spherical view-coverage budgets.
//! - `vs_server` & `vs_nl` (enabled via default `cli` feature).

#![forbid(unsafe_code)]

pub use vs_3d;
pub use vs_crypto;
#[cfg(feature = "cli")]
pub use vs_nl;
#[cfg(feature = "cli")]
pub use vs_server;
pub use vs_vault;
pub use vs_watermark;

pub use vs_vault::{pack_vspk2, unseal_vspk2, MAGIC_VSPK2};

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use vs_crypto::SecretKey32;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_ENABLED: bool = false;

#[derive(Clone, Debug)]
pub enum ParamRule {
    Int { min: i64, max: i64 },
    Str { min_len: usize, max_len: usize },
    Bool,
    Enum(Vec<String>),
}

#[derive(Clone, Debug)]
pub enum ParamValue {
    Int(i64),
    Str(String),
    Bool(bool),
}

#[derive(Clone, Debug)]
pub struct ActionRule {
    pub domain: String,
    pub context: String,
    pub params: HashMap<String, ParamRule>,
}

/// Source-code configured fail-closed action policy (`enabled = false` by default).
pub struct Policy {
    pub enabled: bool,
    pub master_key: SecretKey32,
    pub actions: HashMap<String, ActionRule>,
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("enabled", &self.enabled)
            .field("master_key", &"[REDACTED]")
            .field("actions", &self.actions)
            .finish()
    }
}

impl Policy {
    pub fn new_disabled(master_key: SecretKey32) -> Self {
        Self {
            enabled: DEFAULT_ENABLED,
            master_key,
            actions: HashMap::new(),
        }
    }

    pub fn validate_call(
        &self,
        action_name: &str,
        supplied: &HashMap<String, ParamValue>,
    ) -> Result<&ActionRule, String> {
        if !self.enabled {
            return Err("POLICY_DISABLED".to_string());
        }
        let act = self
            .actions
            .get(action_name)
            .ok_or_else(|| format!("UNKNOWN_ACTION:{action_name}"))?;
        for k in supplied.keys() {
            if !act.params.contains_key(k) {
                return Err(format!("UNKNOWN_PARAM:{k}"));
            }
        }
        for (name, rule) in &act.params {
            let val = supplied
                .get(name)
                .ok_or_else(|| format!("MISSING_PARAM:{name}"))?;
            match (rule, val) {
                (ParamRule::Int { min, max }, ParamValue::Int(v)) => {
                    if v < min || v > max {
                        return Err(format!("PARAM_OUT_OF_RANGE:{name}"));
                    }
                }
                (ParamRule::Str { min_len, max_len }, ParamValue::Str(s)) => {
                    if s.len() < *min_len || s.len() > *max_len {
                        return Err(format!("PARAM_OUT_OF_RANGE:{name}"));
                    }
                }
                (ParamRule::Bool, ParamValue::Bool(_)) => {}
                (ParamRule::Enum(vals), ParamValue::Str(s)) => {
                    if !vals.iter().any(|allowed| allowed == s) {
                        return Err(format!("PARAM_OUT_OF_RANGE:{name}"));
                    }
                }
                _ => return Err(format!("BAD_PARAM_TYPE:{name}")),
            }
        }
        Ok(act)
    }
}

/// Static secret & credential leak scanner for source files and project directories.
pub mod scan {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ScanFinding {
        pub file: String,
        pub line: usize,
        pub rule: String,
        pub severity: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ScanReport {
        pub scanned_files: usize,
        pub findings: Vec<ScanFinding>,
    }

    const RULES: &[(&str, &str, &str)] = &[
        ("PRIVATE_KEY_PEM", "HIGH", "-----BEGIN PRIVATE KEY-----"),
        ("RSA_PRIVATE_KEY_PEM", "HIGH", "-----BEGIN RSA PRIVATE KEY-----"),
        ("EC_PRIVATE_KEY_PEM", "HIGH", "-----BEGIN EC PRIVATE KEY-----"),
        ("AWS_ACCESS_KEY", "HIGH", "AKIA"),
        ("GITHUB_PAT", "HIGH", "ghp_"),
        ("STRIPE_LIVE_SECRET", "HIGH", "sk_live_"),
        ("OPENAI_KEY", "MEDIUM", "sk-proj-"),
    ];

    fn is_skipped_dir(name: &str) -> bool {
        matches!(name, ".git" | "node_modules" | "target" | ".vibeslayer" | "dist")
    }

    fn scan_file_inner(path: &Path, findings: &mut Vec<ScanFinding>) -> usize {
        let Ok(meta) = fs::symlink_metadata(path) else {
            return 0;
        };
        if !meta.is_file() || meta.len() > 4 * 1024 * 1024 {
            return 0;
        }
        let Ok(bytes) = fs::read(path) else {
            return 0;
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return 0;
        };
        for (idx, line) in text.lines().enumerate() {
            for (rule, sev, needle) in RULES {
                if *rule == "AWS_ACCESS_KEY" {
                    let matched = line.match_indices(needle).any(|(pos, _)| {
                        let tail = &line[pos + 4..];
                        tail.len() >= 16
                            && tail
                                .bytes()
                                .take(16)
                                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
                    });
                    if !matched {
                        continue;
                    }
                    findings.push(ScanFinding {
                        file: path.display().to_string(),
                        line: idx + 1,
                        rule: (*rule).to_string(),
                        severity: (*sev).to_string(),
                    });
                } else if line.contains(needle) {
                    findings.push(ScanFinding {
                        file: path.display().to_string(),
                        line: idx + 1,
                        rule: (*rule).to_string(),
                        severity: (*sev).to_string(),
                    });
                }
            }
        }
        1
    }

    pub fn scan_path(root: &Path) -> ScanReport {
        let mut findings = Vec::new();
        let mut scanned_files = 0usize;
        if let Ok(meta) = fs::symlink_metadata(root) {
            if meta.is_file() {
                scanned_files += scan_file_inner(root, &mut findings);
            } else if meta.is_dir() {
                let mut stack = vec![root.to_path_buf()];
                while let Some(dir) = stack.pop() {
                    let Ok(rd) = fs::read_dir(&dir) else {
                        continue;
                    };
                    for entry in rd.flatten() {
                        let Ok(ft) = entry.file_type() else {
                            continue;
                        };
                        if ft.is_symlink() {
                            continue;
                        }
                        let p = entry.path();
                        if ft.is_dir() {
                            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                                if !is_skipped_dir(name) {
                                    stack.push(p);
                                }
                            }
                        } else if ft.is_file() {
                            scanned_files += scan_file_inner(&p, &mut findings);
                        }
                    }
                }
            }
        }
        ScanReport {
            scanned_files,
            findings,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn vspk2_audited_ring_roundtrip_and_asset_binding() {
        let key = SecretKey32::generate().unwrap();
        let plain = b"audited-vspk2-interop-payload";
        let blob = pack_vspk2(&key, "backend", "cfg-v1", "prod", plain).unwrap();
        let out = unseal_vspk2(&key, "backend", Some("cfg-v1"), "prod", &blob).unwrap();
        assert_eq!(out, plain);
        assert!(unseal_vspk2(&key, "backend", Some("wrong-asset"), "prod", &blob).is_err());
        let mut tampered = blob.clone();
        tampered[blob.len() - 1] ^= 0x01;
        assert!(unseal_vspk2(&key, "backend", Some("cfg-v1"), "prod", &tampered).is_err());
    }

    #[test]
    fn policy_defaults_fail_closed_and_enforces_typed_bounds() {
        let mut p = Policy::new_disabled(SecretKey32::generate().unwrap());
        p.actions.insert(
            "cfg.read".into(),
            ActionRule {
                domain: "backend".into(),
                context: "prod".into(),
                params: HashMap::from([("seats".into(), ParamRule::Int { min: 1, max: 50 })]),
            },
        );
        let good = HashMap::from([("seats".into(), ParamValue::Int(10))]);
        assert!(p.validate_call("cfg.read", &good).is_err());
        p.enabled = true;
        assert!(p.validate_call("cfg.read", &good).is_ok());
        let bad = HashMap::from([("seats".into(), ParamValue::Int(999))]);
        assert!(p.validate_call("cfg.read", &bad).is_err());
    }
}
