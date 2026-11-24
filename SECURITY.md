# Security Policy

## Cryptographic & Audit Status

Vibe-Slayer (`v1.0.0-beta.3`) is pre-1.0 software. Before deploying it in high-assurance or regulated environments, note the following:

- **Custom, unaudited implementations:** The standalone Rust binary (`vibeslayer-native-core/rust_core`) implements its own P-256 ECDH, AES-256-GCM, ChaCha20-Poly1305, HKDF-SHA256, SHA-256, and RFC 9112 HTTP/1.1 parser with zero external crates. None of these implementations have undergone an independent third-party cryptographic audit.
- **Constant-time status:** Hardware AES-NI and PCLMULQDQ are used for AES block rounds and GHASH on supported `x86_64` CPUs, while AES key expansion (`aes256_expand_key`) and the software AES fallback use `AES_SBOX` lookup tables, and P-256 scalar multiplication (`web_runtime.rs`) contains secret-dependent table indexing and branches. Do not assume side-channel constant-time guarantees against local co-resident cache-timing adversaries.
- **Experimental subcommands:** The `homo-keygen`, `homo-encrypt`, `homo-eval`, and `homo-decrypt` subcommands implement a small-parameter (`N=256`) Ring-LWE BFV prototype for experimentation only and must not be used to protect production data.

## Threat Boundaries (In Scope vs. Out of Scope)

### In Scope
- Cryptographic or protocol flaws in `.vsweb` ECDH P-256 leases, `VSPK2`/`VSPK3`/`VSRA` AEAD authentication, or single-use HMAC ticket verification
- HTTP request smuggling or parser differentials in `vibe-slayer serve` / `serve-3d`
- Server-side information disclosure (e.g., serving unencrypted source assets, raw `.glb` meshes, or master key files)
- Memory safety bugs or crashes in the Rust binary or C99 SDK (`libvibeslayer.so`)

### Out of Scope (Known Architectural Limits)
- **Live V8/browser RAM dumps by an authorized custom Chromium build (Tier 4b):** Any JavaScript executed on a client controlled by an attacker can be read from V8 RAM along with in-session `rtKey`. Keep true secrets server-side with `vibeslayer-policy-kit` (`server-only`) or use `serve-3d --mode stream`.
- **Unkeyed `VS_ATTEST_V1` spoofing:** `VS_ATTEST_V1` is an unkeyed SHA-256 probe digest, not proof of client possession. Pair with `--auth-hmac-key` or `--auth-secret` for authenticated sessions.
- **Root / kernel debugging of wrapped ELF64 binaries:** Userspace wrappers (`memfd_create`, `memfd_secret`, `PR_SET_DUMPABLE`) cannot resist a privileged kernel or root `ptrace` adversary; `--standalone` embeds an obfuscated self-derived key for tamper deterrence only.
- **Decoy VM stripping (`--js-bloat-kb`):** Dead-code chaff can be removed by AST dead-code eliminators once decrypted.

## Reporting a Vulnerability

Please report suspected security issues via GitHub Security Advisories on [`HUSMUS9999/vibe-slayer`](https://github.com/HUSMUS9999/vibe-slayer/security/advisories/new). Include reproduction steps, affected component/version, and impact.
