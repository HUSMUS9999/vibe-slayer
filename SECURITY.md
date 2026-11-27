# Security Policy

## Cryptographic & Audit Status

Vibe-Slayer (`v2.0.0-alpha.1`) is modular Rust (`#![forbid(unsafe_code)]` across all 7 workspace crates) paired with wire-compatible C99, Go, Python, and zero-dependency Node.js SDKs.

- **Audited cryptographic primitives:** All Rust crates (`vs-crypto`, `vs-vault`, `vs-watermark`, `vs-3d`, `vs-server`, `vibeslayer-core`) delegate AES-256-GCM, ChaCha20-Poly1305, P-256 ECDH, HKDF-SHA256, HMAC-SHA256, SHA-256, and CSPRNG exclusively to [`ring`](https://github.com/briansmith/ring) (BoringSSL constant-time assembly). No custom/DIY elliptic-curve, block-cipher, or HTTP/1.1 parser code remains in the Rust workspace.
- **Memory safety & hygiene:** Workspace-level `#![forbid(unsafe_code)]` is enforced on every Rust crate, `cargo clippy --workspace --all-targets -- -D warnings` passes cleanly, secret keys are wrapped in `Zeroizing` / `SecretKey32` with `Drop` zeroization, and atomic `0600` sibling temporary staging (`mkstemp` + `fchmod(0600)` on POSIX; `CreateFileA` + `MoveFileExA` on Windows; RAII `TempFileGuard` in Rust) ensures failed unseals never truncate existing files or leak partial plaintext.
- **Async HTTP/1.1 & HTTP/2 server:** `vs-server` runs on `tokio`, `hyper`, `axum`, and `tower-http` with per-route body caps (`16 KiB` JSON / `4 MiB` forensics), 20s request timeouts, bounded render/forensics semaphores (`503` backpressure), decompression-bomb limits (`2048×2048` / `32 MiB`), fail-closed scoped bearer grants (`stream:3d`, `web:lease`, `forensics:trace`) with `jti` replay tracking, and full multi-header `X-Forwarded-For` trusted-proxy CIDR resolution.
- **Independent external audit status & crypto provenance:** All Rust workspace crates delegate cryptographic primitives to audited `ring` (BoringSSL constant-time assembly), Node.js packages use Node's built-in OpenSSL/WebCrypto, and the Go SDK's `VSPK3 v2 STREAM` path uses Go stdlib `crypto/aes`, `crypto/cipher`, `crypto/hmac`, and `crypto/sha256`. By contrast, the C99 SDK (`libvibeslayer.so`), the Python `ctypes` wrapper (`sdk_python/vibeslayer.py`), the `vibeslayer-suite/native_src/` C reference templates (`vs_crypto_core.h`), and Go's legacy `VSPK2`/`VSPK3 v1` ChaCha20-Poly1305 path use custom in-tree implementations. Neither those C/legacy implementations nor the higher-level protocol glue (`VSPK3 v2 STREAM`, `.vsweb v2`, `VSR2`, `vs-server`) have undergone a formal third-party external audit. Evaluate accordingly before regulated or high-assurance production deployment.

## Threat Boundaries (In Scope vs. Out of Scope)

### In Scope
- Cryptographic or protocol flaws in `VSPK3 v2 STREAM` (`66,656 B` atomic lookahead, CMT-4 header/chunk commitments, chunk ordering/truncation), `.vsweb v2` HMAC-authenticated bundles & ECDH P-256 pubkey-bound leases, `VSR2` metadata-authenticated AI weight chunks, or bearer grant / `jti` replay verification
- Authentication, authorization, CORS, CSP, or decompression-bomb/DoS flaws in `vs-server` (`3d` / `web`) or `vibeslayer-policy-kit`
- Path-normalization bypasses, header-smuggling, or memory-safety bugs in the Rust workspace, C99 SDK (`libvibeslayer.so`), Go SDK, or JS/Python companions

### Out of Scope (Known Architectural Limits)
- **Live V8/browser RAM dumps on attacker-controlled clients:** Any JavaScript or decrypted asset executed inside a browser fully controlled by an attacker can be read from process memory. Keep true secrets and proprietary geometry strictly server-side via `vs-server` (`serve-3d`) or `vibeslayer-policy-kit` (`server-only`).
- **Physical screen capture of rendered pixels:** Server-side 3D pixel streaming prevents geometry/UV/shader extraction (`0` vertices sent), and `vs-watermark` embeds a blind 64-bit payload + 32-bit keyed HMAC-SHA256 watermark resilient to JPEG Q70, 20% cropping, and 85% downscaling for leak attribution, but cannot physically prevent a human from photographing their monitor.
- **Root / kernel debugging of local CLI key material:** Userspace `0600` key files and memory zeroization cannot defend against a privileged root/kernel adversary with `ptrace` or physical RAM access on the host running `vibe-slayer`.

## Reporting a Vulnerability

Please report suspected security issues via GitHub Security Advisories on [`HusX99/vibe-slayer`](https://github.com/HusX99/vibe-slayer/security/advisories/new). Include reproduction steps, affected crate/package version, and concrete impact.
