# `vibeslayer-native-core` (`v1.0.0-beta.3`)

[← Root README](../README.md) · [CLI & Configuration](../docs/cli-and-configuration.md) · [Native Binaries & SDKs](../docs/native-binaries-and-sdks.md)

Zero-Node.js compiled **Rust + C99** CLI, RFC 9112 live HTTP/1.1 runtime servers (`serve` & `serve-3d`), and wire-compatible native SDKs for **Rust, C/C++, Go, and Python** — built with **zero external Rust crates** and **zero compiler warnings**.

## Compiled Native Artifacts (`bin/`)

- `bin/vibe-slayer` (and top-level `../vibe-slayer`, created by build) — Standalone Linux `ELF64` Rust CLI & live website/3D runtime server
- `bin/vibe-slayer.exe` — Optional cross-compiled Windows `PE32+` x64 standalone Rust CLI (`make windows`)
- `bin/vibeslayer` & `bin/vibeslayer.exe` — Backward-compatible CLI aliases
- `bin/libvibeslayer.so` & `bin/vibeslayer.dll` — C99 shared library (`VSPK2` & `VSPK3`) for C/C++ and Python `ctypes`

## Core Engines & Protocols

- **Unified Parameterization (`rust_core/src/params.rs`)**: `--preset fast | balanced | paranoid`, `init-config`, `--config vibeslayer.config.json`, environment variable fallbacks, and strict fail-closed validation.
- **Live Website & Web Components Runtime (`rust_core/src/web_runtime.rs`)**: `website` & `serve` using pure-Rust AES-NI `AES-256-GCM`, Solinas `ECDH P-256`, `HKDF-SHA256`, single-use HMAC tickets, RFC 9112 proxy compliance (`Transfer-Encoding: chunked`, `Expect: 100-continue`, `CL+TE` smuggling rejection), `--harden-js` (runtime-keyed strings + optional decoy VM + inline Web Component stealth guard), `--anti-cdp`, and `--anti-stealth`.
- **3D Shield & Encrypted Stream (`rust_core/src/shield_viewer.rs`, `raster_stream.rs`)**: `shield-3d`, `serve-3d` (`--mode stream` zero-geometry AES-256-GCM pixel stream & `--mode gpu` WebGL2 encrypted-vertex viewer), `trace-shield-3d`, and `trace-stream-frame`.
- **Auto-Protection & Native Crypto (`rust_core/src/auto_cli.rs`, `v090_elite.rs`, `v100_zero_overhead.rs`)**: `VSPK2`, headerless whole-file key-committing `VSPK3`, cooked `VS3D`, 64-bit BPSK `WM64`, and freestanding `-nostdlib` static-PIE `ELF64` wrappers (`wrap-elf` via sealed `memfd_create` + `execveat` with Intel CET) and `<= 4 KiB` `memfd_secret` data vaults (`--vault`).

All four native SDKs (`rust_core`, `sdk_c`, `sdk_go`, `sdk_python`) share the exact binary **`VSPK2`** and **`VSPK3`** wire formats (`HKDF-SHA256` + `RFC 8439 ChaCha20-Poly1305`).

## Build & Verify

```bash
# Build native host Linux binary + C SDK (zero crates, zero compiler warnings)
make -C vibeslayer-native-core all

# Optional: cross-compile Windows PE32+ artifacts (requires x86_64-w64-mingw32-gcc + x86_64-pc-windows-gnu)
make -C vibeslayer-native-core windows

# Run Rust unit tests & polyglot/security suites
cargo test --manifest-path vibeslayer-native-core/rust_core/Cargo.toml --release
make -C vibeslayer-native-core test

# Optional: run high-throughput loopback SOTA benchmarks
make -C vibeslayer-native-core bench
```
