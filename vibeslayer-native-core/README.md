# `vibeslayer-native-core` (`v2.0.0-alpha.1`)

[← Root README](../README.md) · [Native Binaries & SDKs](../docs/native-binaries-and-sdks.md) · [Security Policy](../SECURITY.md)

Thin feature-gated **Rust** CLI (`vibe-slayer`) built on the `#![forbid(unsafe_code)]` workspace crates (`vs-crypto`, `vs-vault`, `vs-watermark`, `vs-3d`, `vs-server`, `vs-nl`), paired with wire-compatible **Go**, **C99** (`libvibeslayer.so`), and **Python** `VSPK3 v2 STREAM` SDKs.

## Artifacts (`bin/` & `target/release/`)

- `target/release/vibe-slayer` (and `bin/vibe-slayer` via `Makefile`) — Standalone CLI facade (`demo`, `vault`, `website`, `serve`, `token`, `scan`, `serve-3d`, `trace-3d`, `explain`, `ask`, plus legacy `pack`/`unseal`/`pack-v3`/`unseal-v3`).
- `bin/libvibeslayer.so` (or `vibeslayer.dll` on Windows) — C99 shared library (`VSPK2`, `VSPK3 v1`, and `VSPK3 v2 STREAM` ChaCha20-Poly1305 unseal) consumed by C/C++ and Python `ctypes`.

## Polyglot `VSPK3 v2 STREAM` Wire Parity

| SDK | Location | Supported `VSPK3 v2 STREAM` Operations | Crypto Backend |
| :--- | :--- | :--- | :--- |
| **Rust (`vs-vault`)** | `crates/vs-vault`, `rust_core/` | Seal, Unseal, Inspect, `O(1)` Random Access (`AES-256-GCM` & `ChaCha20-Poly1305`) | `ring` (BoringSSL) |
| **Go** | `sdk_go/vibeslayer.go` | Seal & Unseal (`AES-256-GCM`) + legacy `VSPK2`/`VSPK3 v1` | Go stdlib `crypto/aes` + `crypto/cipher` (v2); in-tree ChaCha20-Poly1305 (legacy v1) |
| **C99** | `sdk_c/vibeslayer.c` | Unseal (`ChaCha20-Poly1305`) + legacy `VSPK2`/`VSPK3 v1` | In-tree C99 (`vs_crypto_core.h`) |
| **Python** | `sdk_python/vibeslayer.py` | Unseal (`ChaCha20-Poly1305`) + legacy `VSPK2`/`VSPK3 v1` | `ctypes` wrapper around `libvibeslayer.so` |

## Build & Verify

```bash
# Build native CLI + C99 shared library
make -C vibeslayer-native-core all

# Workspace lint & Rust unit/integration tests
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --release

# Polyglot VSPK3 v2 STREAM parity tests (Rust <-> Go, Rust <-> C99 <-> Python)
python3 vibeslayer-native-core/tests/test_v2_polyglot.py
(cd vibeslayer-native-core/sdk_go && go test -v ./...)
```
