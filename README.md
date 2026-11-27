<p align="center">
  <img src="assets/vibeslayer-hero-dark.svg#gh-dark-mode-only" alt="Vibe-Slayer" width="240" />
  <img src="assets/vibeslayer-hero-light.svg#gh-light-mode-only" alt="Vibe-Slayer" width="240" />
</p>

<p align="center">
  <strong>Stop AI-driven "vibe reverse engineering" with <code>ring</code>-backed AEAD vaults, server-side execution, and blind forensic watermarking.</strong>
</p>

<p align="center">
  <a href="https://github.com/HusX99/vibe-slayer/releases"><img src="https://img.shields.io/github/v/release/HusX99/vibe-slayer?include_prereleases&style=flat&logo=github&logoColor=white&label=release&labelColor=21262d&color=0284c7" alt="Release" /></a>
  <a href="https://github.com/HusX99/vibe-slayer/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/HusX99/vibe-slayer/ci.yml?branch=main&style=flat&logo=githubactions&logoColor=white&label=CI&labelColor=21262d" alt="CI Status" /></a>
  <a href="#architecture"><img src="https://img.shields.io/badge/rust-forbid(unsafe__code)-b7410e?style=flat&logo=rust&logoColor=white&labelColor=21262d" alt="Rust: forbid(unsafe_code)" /></a>
  <a href="#architecture"><img src="https://img.shields.io/badge/crypto-ring%20(BoringSSL)-0e7490?style=flat&labelColor=21262d" alt="Crypto: ring (BoringSSL)" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/HusX99/vibe-slayer?style=flat&logo=opensourceinitiative&logoColor=white&label=license&labelColor=21262d&color=0f766e" alt="License: MIT" /></a>
</p>

<p align="center">
  <a href="#protected-assets"><strong>Protected Assets</strong></a> &nbsp;&middot;&nbsp;
  <a href="#quickstart"><strong>Quickstart</strong></a> &nbsp;&middot;&nbsp;
  <a href="#architecture"><strong>Architecture</strong></a> &nbsp;&middot;&nbsp;
  <a href="#performance"><strong>Performance</strong></a> &nbsp;&middot;&nbsp;
  <a href="#security-model--limits"><strong>Security Model</strong></a> &nbsp;&middot;&nbsp;
  <a href="#documentation"><strong>Docs</strong></a>
</p>

**Vibe-Slayer** defends proprietary software assets against **"vibe reverse engineering"**: automated pipelines and coding agents (such as **Reverse Engineer Anything / REA**, Playwright/CDP rippers, Frida instrumentation, and LLM decompilers) that bypass static obfuscation in minutes by dumping bundles offline, hooking runtime APIs (`fetch`, `WebAssembly.instantiate`, `gl.bufferData`), and reconstructing logic automatically.

Vibe-Slayer eliminates plaintext at rest with AEAD encryption, keeps true secrets and 3D geometry off the client via server-side execution and streaming (where Frida and CDP cannot reach), and embeds blind forensic watermarks for post-leak attribution. Built as a `#![forbid(unsafe_code)]` Rust CLI and crate workspace with Go, C99, Python, and Node.js (`>= 20`) SDKs.

## Protected Assets

| Asset Class | Automated AI / Vibe-RE Threat | Vibe-Slayer Defense |
| :--- | :--- | :--- |
| **Web Apps & JS Bundles** | Offline scraping, static JS dumps, headless browser ripping | Encrypted `.vsweb v2` bundles, fail-closed `web:lease` grants, pubkey-bound ECDH P-256 non-extractable WebCrypto keys; opt-in heuristic `antiStealth` in JS packages |
| **AI Weights & Datasets** | Direct `.safetensors`/`.onnx`/`.gguf` theft and redistribution | 64-bit `VSPK3 v2 STREAM` AEAD + CMT-4 vaults (`O(1)` RAM, >4 GiB) and `VSR2` chunked weights (`F32` watermarking; `BF16`/quantized pass through unmodified) |
| **APIs & Proprietary Logic** | Automated script replay, client-side formula extraction, schema probing | Source-configured `definePolicy()` gateway (`server-only`, `public-preview`, `client-sealed`), strict param schemas, field redaction, replay and `antiStealth` guards |
| **WebAssembly (`.wasm`)** | Static `\0asm` scraping and offline `wasm2wat`/LLM decompilation | Encrypted `.vspk` delivery (no plaintext `\0asm` bytes at rest or on the wire) with ephemeral WebCrypto unsealing and native ABI speed |
| **Native, Desktop & Mobile (Reference Kits)** | Offline `.rodata`/ASAR/APK extraction, renderer DevTools inspection, naive repackaging | Linux PIE + Intel CET C template (`<= 4 KiB` `.vsblob` bound to live `PF_X` SHA-256, `PR_SET_DUMPABLE=0`); `Ed25519` `.vsasar` C enclave sidecar; C `.so` bound to caller-supplied APK cert for NDK/JNI |
| **Interactive 3D Models (Optional Module)** | WebGL buffer hooks, Transform Feedback dumps, 3DGS/photogrammetry sweeps | Server-side PBR pixel streaming (mesh geometry, UVs, and shaders stay on the server), anti-3DGS camera defense, 192-bin view budget, blind 64-bit MAC watermarking |

## Quickstart

New to the CLI? See the **[Plain-English Beginner's Guide](docs/getting-started-beginners.md)**.

### 1. Build & Run the Local Self-Verification Demo

Requires Rust (`cargo`). Add `gcc` for the C99 shared library (`libvibeslayer.so`).

```bash
git clone https://github.com/HusX99/vibe-slayer.git
cd vibe-slayer
cargo build --release --bin vibe-slayer
cp target/release/vibe-slayer ./vibe-slayer

# Runs a local VSPK3 v2 STREAM seal/unseal + blind watermark embed/trace round-trip
./vibe-slayer demo
```

### 2. Core Multi-Asset CLI Workflows

Supply keys via `--key-file <0600-path>`, `--key-stdin`, or `VIBESLAYER_KEY` (avoiding process-list exposure). All vault outputs commit atomically through `0600` sibling temporary files.

```bash
# Generate 0600 master keys
openssl rand -hex 32 > vault.key && chmod 600 vault.key
openssl rand -hex 32 > auth.key  && chmod 600 auth.key

# 1) Seal any binary, dataset, or AI model weight into a VSPK3 v2 STREAM AEAD + CMT-4 vault
#    O(1) RAM, >4 GiB capable; AES-256-GCM (default, Rust<->Go) or --cipher chacha20 (Rust<->C99/Python unseal)
./vibe-slayer vault seal ./weights.safetensors -o ./weights.vsp3 \
  --key-file ./vault.key --asset-id llama-7b
./vibe-slayer vault inspect ./weights.vsp3 --key-file ./vault.key --asset-id llama-7b
./vibe-slayer vault unseal ./weights.vsp3 -o ./weights.restored \
  --key-file ./vault.key --asset-id llama-7b

# 2) Pack & serve an authenticated .vsweb v2 web app bundle (fail-closed ECDH P-256 leases)
./vibe-slayer website ./dist --out ./site.vsweb --site-id my-app --key-out ./site.key
./vibe-slayer serve ./site.vsweb --bind 127.0.0.1:8080 \
  --key-file ./site.key --auth-key-file ./auth.key

# 3) Mint a site-wide scoped bearer grant (omit --asset-id for full bundle) & scan repos for leaked secrets
./vibe-slayer token mint --key-file ./auth.key --subject buyer-42 \
  --origin my-app --scope web:lease --ttl 300
./vibe-slayer scan ./my-repo

# 4) Optional 3D asset module: server-side pixel streaming + blind forensic leak attribution
./vibe-slayer serve-3d ./models-dir --bind 127.0.0.1:8790 \
  --key-file ./wm.key --auth-key-file ./auth.key --allow-origin https://app.example.com
./vibe-slayer trace-3d --image ./leaked.png --key-file ./wm.key
```

You can also translate plain English locally via `vs-nl` (deterministic offline parser):

```bash
./vibe-slayer explain "protect website ./dist"
./vibe-slayer ask --dry-run "seal ./weights.safetensors"
```

### 3. Node.js API Policy Gateway (`vibeslayer-policy-kit`)

Keep proprietary business logic strictly server-side so browser/CDP/Frida hooks never see secret formulas or raw fields:

```js
const { definePolicy, createGateway } = require("./vibeslayer-policy-kit");

const policy = definePolicy({
  enabled: true,
  signingSecret: process.env.POLICY_SECRET,
  actions: {
    "pricing.evaluate": {
      mode: "server-only",
      requiredScopes: ["pricing:quote"],
      redactFields: ["costBasisUsd"],
      params: { seats: { type: "int", min: 1, max: 5000 } },
      handler: async ({ params }) => ({ quoteUsd: params.seats * 49, costBasisUsd: params.seats * 12 }),
    },
  },
});

const gateway = createGateway(policy); // Mount with Node http/Express or Web Fetch API
```

## Architecture

<p align="center">
  <img src="assets/vibeslayer-arch-dark.svg" alt="Vibe-Slayer v2 Modular Protection Architecture and Trust Boundaries" width="100%" />
</p>

### Modular Workspace & Packages

| Crate / Package | Role | Key Capabilities |
| :--- | :--- | :--- |
| [`crates/vs-crypto`](crates/vs-crypto/Cargo.toml) | `ring`-Backed Crypto Core | AES-256-GCM, ChaCha20-Poly1305, pubkey-bound P-256 ECDH, monotonic session AEAD, constant-time bearer grant verification. |
| [`crates/vs-vault`](crates/vs-vault/Cargo.toml) | Streaming Asset Vault | 64-bit STREAM AEAD + Bellare-Hoang CMT-4 (`VSPK3 v2`), `O(1)` RAM random access, legacy `VSPK2`/`VSPK3 v1` support. |
| [`crates/vs-server`](crates/vs-server/Cargo.toml) | Async Tokio/Axum Server | Feature-split (`web`, `3d`) `.vsweb v2` asset server and optional 3D streamer, closure-scoped WebCrypto loader, bounded backpressure. |
| [`crates/vs-watermark`](crates/vs-watermark/Cargo.toml) | Blind Forensic Watermarking | 128×128 2D-FFT sync, mid-band DCT payload + 32-bit keyed HMAC-SHA256 MAC, Chase soft decoding, Tardos collusion codebook. |
| [`crates/vs-3d`](crates/vs-3d/Cargo.toml) | Optional 3D Module | glTF 2.0 PBR renderer, anti-3DGS camera perturbation, 192-bin spherical view budget, bounded multi-SKU catalog. |
| [`crates/vs-nl`](crates/vs-nl/Cargo.toml) | Offline NL Translator | Deterministic flag-injection-safe English-to-CLI compiler with POSIX-safe command quoting. |
| [`vibeslayer-native-core/`](vibeslayer-native-core/README.md) | CLI + Polyglot SDKs | `vibe-slayer` CLI facade + wire-compatible **Go** (AES-256-GCM seal/unseal) and **C99/Python** (`libvibeslayer.so` ChaCha20-Poly1305 unseal) SDKs. |
| [`vibeslayer-suite/`](vibeslayer-suite/README.md) | Multi-Asset JS Suite | Node.js `>= 20` (built-in modules only) subpath exports: Web, WASM, `VSR2` AI weights, 3D Spatial, plus Native/Desktop/Mobile reference kits. |
| [`vibeslayer-policy-kit/`](vibeslayer-policy-kit/README.md) | API Policy Gateway | Node.js `>= 20` (built-in modules only) policy gateway + `.d.ts` types: `server-only`, `public-preview`, `client-sealed`, Express/Fetch adapters, opt-in `antiStealth`. |

## Performance

Measured on Linux `x86_64` release builds (`v2.0.0-alpha.1`):

| Workload | Throughput / Latency | Peak RSS | Notes |
| :--- | :--- | :--- | :--- |
| **`VSPK3 v2 STREAM` Seal (`256 MiB`, `--cipher chacha20`)** | **`1,856–2,085 MiB/s`** (`122.8–137.9 ms`) | `12.82 MiB` | Full AEAD + CMT-4 in `O(1)` RAM (`ring`, `#![forbid(unsafe_code)]`) |
| **`VSPK3 v2 STREAM` Unseal (`256 MiB`, `--cipher chacha20`)** | **`1,991–2,106 MiB/s`** (`121.5–128.6 ms`) | `13.12 MiB` | Includes `66,656 B` atomic lookahead + `fsync` commit; 1.3× faster than unauthenticated `openssl enc -aes-256-ctr` (`1,512 MiB/s`) |
| **Built-in `demo` (STREAM + Blind WM + MAC)** | **`5.91 ms` end-to-end** | — | `41.0 dB` PSNR; 64-bit payload + 32-bit keyed MAC verified blind |

Suite verification (`cargo test --workspace --release`): blind watermark torture passes intact, 20% crop, 85% downscale, and JPEG Q70 recompression (`0.50 s`); async `vs-server` handles `200` idle keep-alive sockets with instant `/healthz` (`0.08 s`); `vs-3d` PBR + anti-3DGS + JPEG Q70 trace passes (`0.10 s`). See [Vision & Benchmarks](docs/vision-and-benchmarks.md) for head-to-head comparisons against `esbuild`, `terser`, `javascript-obfuscator`, `js-confuser`, `strip`, `UPX`, and `OpenSSL`.

## Security Model & Limits

- **What Vibe-Slayer stops:** Eliminates offline scraping and static reversing of sealed web bundles, WASM, AI weights, and 3D assets (payloads stay encrypted at rest with no embedded keys); keeps proprietary logic and sensitive geometry off the client via `vibeslayer-policy-kit` (`server-only`) and `serve-3d`; enforces fail-closed scoped bearer grants (`web:lease`, `stream:3d`, `forensics:trace`); and adds opt-in heuristic detection (`antiStealth`) in `vibeslayer-policy-kit` and `vibeslayer-suite/web` for headless/CDP markers and synthetic-noise anti-detect browsers (defense-in-depth; bypassable if an attacker modifies browser JS/telemetry).
- **Primitive audit scope vs. pre-1.0 protocol glue ([SECURITY.md](SECURITY.md)):** All Rust crates run on audited `ring` (BoringSSL constant-time assembly) with `#![forbid(unsafe_code)]`, Node.js packages use Node's OpenSSL/WebCrypto, and Go `VSPK3 v2` uses Go stdlib `crypto/aes` + `crypto/cipher`. The C99 SDK (`libvibeslayer.so`), the Python `ctypes` wrapper, `vibeslayer-suite/native_src/` C templates (`vs_crypto_core.h`), and Go's legacy `VSPK2`/`VSPK3 v1` ChaCha20-Poly1305 path use custom in-tree implementations. None of the higher-level wire formats (`VSPK3 v2`, `.vsweb v2`, `VSR2`) or servers have undergone a third-party external audit.
- **Irreducible live-client boundary:** Any JavaScript, WASM module, or unsealed buffer executing inside a browser or host fully controlled by an attacker (custom Chromium inspecting V8 RAM, dynamic `WebAssembly.Module` hooks, or root/Frida instrumentation during an authorized session) can be captured at runtime. Keep true secrets strictly server-side (`server-only` actions or server-side 3D pixel streaming), and use per-session forensic watermarking (`vs-watermark`, `VSR2` F32 tensor watermarks) for post-leak attribution.
- **`.vsweb v2` scope:** Built for authenticated app/asset bundles (not public SEO/SSR pages). `/__vibeslayer/lease` fails closed (`401`) unless valid `web:lease` bearer tokens are supplied or `--allow-anonymous-public-site` is explicitly enabled.

## Documentation

- [Security Policy & Threat Boundaries](SECURITY.md): Cryptographic provenance, audit status, and explicit limits.
- [Vision & Benchmarks](docs/vision-and-benchmarks.md): Why static obfuscation loses to AI reversing agents, plus head-to-head benchmarks.
- [Threat Model & Anti-Stealth Analysis](docs/threat-model-and-benchmarks.md): Adversary tier matrix across scrapers, AI agents, and stealth browsers.
- [Beginner's Guide](docs/getting-started-beginners.md): Local `ask` and `explain` recipes.
- [Websites & Web Components](docs/web-and-web-components.md): `.vsweb` runtime and WebCrypto leases.
- [Native Binaries & SDKs](docs/native-binaries-and-sdks.md): Rust, C99, Go, and Python SDK integration.
- [3D Shield & Stream](docs/3d-shield-and-stream.md): Optional server-side 3D pixel streaming and blind forensic tracing.
- [Deployment & Proxies](docs/deployment-and-security-proxies.md): Reverse-proxy deployment and `--trust-proxy` CIDR rules (`serve-3d`).

## Development & Verification

Prerequisites: Rust (`cargo`), `gcc`, `Node.js >= 20`, `Go >= 1.21`, and `Python >= 3.10` (stdlib only for v2 polyglot tests).

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --release
make -C vibeslayer-native-core all
python3 vibeslayer-native-core/tests/test_v2_polyglot.py
(cd vibeslayer-native-core/sdk_go && go test -v ./...)
npm test --prefix vibeslayer-policy-kit
npm test --prefix vibeslayer-suite
```

## Related Projects

- [ProxySnare](https://github.com/HusX99/proxysnare): Middleware, reverse proxy, browser guard, and Python verifier for detecting and blocking intercepting HTTP proxies and repeaters.
- [VeilBreak](https://github.com/HusX99/veilbreak): Browser integrity SDK, `<veil-break>` Shadow DOM Web Component, reverse-proxy middleware, and Python verifier for anti-detect browsers across Chromium and Gecko.

## License

MIT — see [LICENSE](LICENSE).
