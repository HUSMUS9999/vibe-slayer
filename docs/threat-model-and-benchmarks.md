# Threat Model, Anti-CloakBrowser Analysis & Benchmarks

[← Back to README](../README.md) · [Web & Web Components](./web-and-web-components.md) · [3D Shield & Stream](./3d-shield-and-stream.md)

Security tools fail engineers when they exaggerate what client-side protection can achieve. This document gives an **unbiased, empirically tested assessment** of what Vibe-Slayer blocks across adversary tiers, how it detects and denies anti-detect browsers like **CloakBrowser**, and where irreducible browser-physics boundaries begin.

---

## 1. Adversary Tier Matrix (Honest Assessment)

| Adversary Tier | Website & Web Components (`--preset paranoid`) | 3D Shield `--mode gpu` (`balanced`) | 3D Encrypted Stream `--mode stream` (`paranoid`) |
| :--- | :--- | :--- | :--- |
| **Tier 1: Scrapers, `curl`, `wget`, HTTrack, Static Rippers** | **100% Blocked.** `GET /` returns an empty shell; assets are `AES-256-GCM` `.vsweb` blobs; manifest fails closed (`403`). | **100% Blocked.** No `.glb`/`.gltf` served; geometry & textures encrypted at rest. | **100% Blocked.** Zero 3D files or WebGL endpoints exist. |
| **Tier 2: Standard Headless Automation (Playwright, Puppeteer, Selenium, Vibe-Coding Scrapers)** | **100% Blocked before lease.** `--anti-cdp` catches `navigator.webdriver` & `Runtime.enable`; `strict` blocks `HeadlessChrome` UAs server-side (`0` leases, `0` components mounted). | **100% Blocked before init.** `AUTOMATION_DENIED`, `0` WebGL buffers uploaded. | **100% Blocked before init.** `AUTOMATION_DENIED`, `0` frames rendered. |
| **Tier 3: AI-Agent Reversers (CDP `Fetch.enable` / `Debugger.getScriptSource` + Transform Feedback)** | **Blocked by default (`Runtime.enable` caught).** If an attacker manually patches out `Runtime.enable` and dumps `blob:` JS from V8, dumped `.mjs`/`.js` is **offline-dead** (`VS_RUNTIME_KEY_REQUIRED` without live ECDH `rtKey`), carries `96 KB` (`~48K+` tokens) of decoy VM per file, and runs the inline `STEALTH_BROWSER_DENIED` guard. | **Normal-oracle killed; server-baked watermark survives.** Transform Feedback / GPU capture still cannot recover original UVs/materials cleanly, and ripped world positions remain **64/64-bit forensically traceable** (`trace-shield-3d`) even if shader uniforms are stripped. | **~100% Geometry Theft Blocked.** `0` vertices, `0` indices, `0` UVs, `0` textures, `0` shaders, `0` WebGL contexts. Wire frames are `AES-256-GCM` ciphertext; every decoded JPEG carries a visually invisible **`0.999+`-confidence 64-bit buyer watermark**. |
| **Tier 4a: C++-Patched Anti-Detect Browsers (CloakBrowser 146, fingerprint-noise Chromium forks)** | **100% Denied (`STEALTH_BROWSER_DENIED`).** Blocked at loader (score `11/11`, `0` leases), server attestation (`403`), AND inline inside extracted hardened Web Component `.mjs` files before `customElements.define(...)`. | **100% Denied (`STEALTH_BROWSER_DENIED`, `0` handshakes).** | **100% Denied (`STEALTH_BROWSER_DENIED`, `0` handshakes).** |
| **Tier 4b: Custom Zero-Noise Patched Chromium + Human-In-The-Loop / Photogrammetry (3DGS / COLMAP)** | **Irreducible client-JS boundary.** Any code that executes in a browser the attacker compiles from C++ source with zero synthetic noise and human-like I/O can eventually be read from V8 RAM during an authorized session. Keep truly secret formulas/keys **server-only** (`vibeslayer-policy-kit`). | **Multi-view / GPU driver dump possible by authorized user**, mitigated by chaff, scrambled tiles, budgets, and **64-bit server-baked buyer watermarking** for legal/forensic attribution. | **No mesh/UV/PBR recovery.** Attacker obtains only rate-limited, single-in-flight, focal/light-drifted, tilt-shifted 2D frames — every single frame permanently carries the authenticated **64-bit blind buyer watermark** (`trace-stream-frame`). |

---

## 2. How CloakBrowser Was Tested & Blocked (6 Hardware/Physics Invariants)

Before `--anti-stealth`, **CloakBrowser** (`chromium-146.0.7680.177.5` with C++ fingerprint spoofing) bypassed `navigator.webdriver` and `Runtime.enable` traps because it strips Playwright/CDP signals directly inside the browser binary.

Empirical side-by-side probing of live **CloakBrowser 146** versus unmodified **Google Chrome 158** uncovered **6 physical/hardware invariants** that anti-detect noise injectors violate while real desktop browsers never do:

| # | Hardware / Physics Invariant | Unmodified Chrome 158 | CloakBrowser 146 (Live Measured) | Score Weight |
| :---: | :--- | :--- | :--- | :---: |
| 1 | **2D Canvas Solid `#808080` `fillRect`** | `1` unique RGB (`128,128,128`) | `5` unique RGBs (synthetic pixel noise) | `+2` |
| 2 | **WebGL `gl.clear(0.5, 0.5, 0.5, 1)` `readPixels`** | `1` unique RGB (`128,128,128`) | `5` unique RGBs (synthetic readback noise) | `+2` |
| 3 | **Silent `OfflineAudioContext` (0.0 input buffer)** | `0 / 512` non-zero samples | `512 / 512` non-zero samples (audio noise) | `+2` |
| 4 | **Integer-DPR `getBoundingClientRect()`** (`left:10, top:20`) | Exact `[10, 20]` | Poisoned `[9.953125, 19.984375]` | `+2` |
| 5 | **OS Platform vs. Core System Fonts** (`Win32` / `MacIntel`) | Real OS matches installed core fonts | Spoofs `Win32` on Linux with `0/4` Windows fonts (`Segoe UI`, `Tahoma`, `Consolas`, `Calibri`) | `+2` |
| 6 | **D3D11 NVIDIA/RTX WebGL Extension Parity** | Real D3D11 exposes `KHR_parallel_shader_compile` (`30+` exts) | Spoofed D3D11 RTX string missing `KHR_parallel_shader_compile` (`< 30` exts) | `+1` |
| | **Total Anomaly Score** | **`0 / 11` (Zero False Positives)** | **`11 / 11` (or `8 / 11` even with `--fingerprint-platform=linux`)** | Threshold: `balanced >= 4`, `strict >= 2` |

### Why CloakBrowser Cannot Evade This With Flags Alone
- Passing `--fingerprint-platform=linux` eliminates invariants #5 and #6, yet CloakBrowser still scores **`8 / 11`** (Canvas2D + WebGL + Audio + DOMRect) — exceeding both `strict` (`>= 2`) and `balanced` (`>= 4`).
- In `--mode stream` (where WebGL is intentionally absent from the client loader), CloakBrowser still scores **`8 / 8`** (or `6 / 6` on Linux spoof), comfortably exceeding both thresholds.
- Turning off CloakBrowser's entire noise engine reduces it back to a detectable headless/automation fingerprint unless the attacker builds a custom C++ browser from scratch (Tier 4b).

---

## 3. Measured Performance Benchmarks

All benchmarks are reproducible directly from this repository using `make -C vibeslayer-native-core test` and `python3 vibeslayer-native-core/tests/bench_sota_performance.py`.

### Core Runtime & Cryptographic Throughput

| Subsystem | Measured Performance | Notes |
| :--- | :--- | :--- |
| **`vibe-slayer serve` — ECDH P-256 Lease Handshake** | **`58,619 leases/sec`** | Pure-Rust Solinas P-256 + HKDF-SHA256 + AES-NI GCM |
| **`vibe-slayer serve` — Encrypted `.vsweb` Asset Throughput** | **`196,205 req/sec`** | Multi-threaded Rust HTTP/1.1 keep-alive pool |
| **C SDK (`libvibeslayer.so`) `vs_unseal_vspk3`** | **`3,294 MiB/s`** | `ChaCha20-Poly1305` + `CMT4` key-committing AEAD |
| **`serve-3d --mode stream` (`1280×820`, 52,965-tri PBR mesh)** | **`23.7 ms` RTT** (`~42 FPS` cap) | Full software PBR raster + blind WM64 + JPEG + AES-256-GCM |
| **Stream Post-JPEG Blind Watermark (`trace-stream-frame`)** | **`0.999394` mean conf** (`64/64` bits) | Visually spotless Weber-Fechner `±1`/`±2` amplitude clamp |
| **Hardened Web Component JS Runtime Overhead** | **`~0 ms`** execution penalty | V8 lazily skips uncalled decoy VM; string table cached in `Map` |

### `vibeslayer-suite` Footprint vs. Classical Obfuscation

| Target | Raw Size | Sealed Size | Overhead | Cold Unseal Latency |
| :--- | ---: | ---: | ---: | ---: |
| **Web Asset (`.vspk`)** | `116 B` | `233 B` | `2.01×` | `2.46 ms` |
| **WASM Module (`.vspk`)** | `100 B` | `220 B` | `2.20×` (`0` `\0asm` bytes) | `0.97 ms` (unseal + instantiate) |
| **3D Spatial (`.vs3d.vspk`)** | `581,260 B` | `749,679 B` | `1.29×` (`7.9998` bits/B) | `4.71 ms` (`0` frame ops) |
| **AI Weights (`.vsra`, 64 KiB chunks)** | `262,231 B` | `262,303 B` | `1.0003×` (`+72 B`) | `1.45 ms` (`O(1)` chunk) |

---

## 4. Reproducing All Audits & Benchmarks Locally

```bash
# Build Linux ELF64, Windows PE32+, and C SDK shared libraries (0 warnings)
make -C vibeslayer-native-core all

# Rust unit tests (crypto vectors, AES-NI/Solinas parity, JPEG/PNG, WM64, presets)
cargo test --manifest-path vibeslayer-native-core/rust_core/Cargo.toml --release

# Full native + polyglot + adversarial red-team + SOTA benchmark suite
make -C vibeslayer-native-core test

# Companion JavaScript packages (including Web Component antiStealth tests)
npm test --prefix vibeslayer-suite
npm test --prefix vibeslayer-policy-kit
```
