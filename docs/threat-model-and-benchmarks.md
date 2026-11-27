# Threat Model, Anti-Stealth Analysis & Benchmarks

[← Back to README](../README.md) · [Web & Web Components](./web-and-web-components.md) · [3D Shield & Stream](./3d-shield-and-stream.md)

This document outlines what Vibe-Slayer blocks across adversary tiers, how its anti-stealth checks behave against **CloakBrowser 146** and unmodified desktop browsers, and where client-side protection boundaries end.

---

## 1. Adversary Tier Matrix

| Adversary Tier | Website & Web Components (`--preset paranoid`) | 3D Shield `--mode gpu` (`balanced`) | 3D Encrypted Stream `--mode stream` (`paranoid`) |
| :--- | :--- | :--- | :--- |
| **Tier 1: Scrapers, `curl`, `wget`, HTTrack, Static Rippers** | **Blocked (no plaintext served).** `GET /` returns an empty shell; assets are `AES-256-GCM` `.vsweb` blobs; manifest fails closed (`403`). | **Blocked.** No `.glb`/`.gltf` served; geometry & textures encrypted at rest. | **Blocked.** No 3D files or WebGL endpoints exist. |
| **Tier 2: Standard Headless Automation (Playwright, Puppeteer, Selenium)** | **Blocked before lease.** `--anti-cdp` catches `navigator.webdriver` & `Runtime.enable`; `strict` blocks `HeadlessChrome` UAs server-side (no leases issued, no components mounted). | **Blocked before init.** `AUTOMATION_DENIED`, no WebGL buffers uploaded. | **Blocked before init.** `AUTOMATION_DENIED`, no frames rendered. |
| **Tier 3: AI-Agent Reversers (CDP `Fetch.enable` / `Debugger.getScriptSource` + Transform Feedback)** | **Blocked by default (`Runtime.enable` caught).** If an attacker patches out `Runtime.enable` and dumps `blob:` JS from V8, dumped `.mjs`/`.js` is **offline-dead** (`VS_RUNTIME_KEY_REQUIRED` without live ECDH `rtKey`), carries the optional `96 KB` (`--js-bloat-kb`) decoy VM per file, and runs the inline `STEALTH_BROWSER_DENIED` guard. | **Normal-oracle killed; server-baked watermark survives.** Multi-view Transform Feedback / GPU capture can still approximate unwatermarked geometry up to Kruppa/SVD error (~1–6% Frobenius residual), while ripped world positions remain **64/64-bit forensically traceable** (`trace-shield-3d`) even if shader uniforms are stripped. | **Geometry withheld on server.** No vertices, indices, UVs, textures, or shaders are sent to the browser, and the viewer never creates a WebGL context. Wire frames are `AES-256-GCM` ciphertext; every decoded JPEG carries a visually invisible **`0.999`-confidence 64-bit buyer watermark**. |
| **Tier 4a: Fingerprint-Noise Anti-Detect Browsers (CloakBrowser 146)** | **Denied (`STEALTH_BROWSER_DENIED`).** Blocked at loader (score `11/11`, no leases issued), server attestation (`403`), and inline inside extracted hardened Web Component `.mjs` files before `customElements.define(...)`. | **Denied (`STEALTH_BROWSER_DENIED`, blocked before handshake).** | **Denied (`STEALTH_BROWSER_DENIED`, blocked before handshake).** |
| **Tier 4b: Custom Patched Chromium (No Fingerprint Noise) + Human-In-The-Loop / Photogrammetry (3DGS / COLMAP)** | **Irreducible client-JS boundary.** Any code executing in a browser the attacker builds from C++ source without synthetic noise and with human I/O can be read from V8 RAM during an authorized session. Keep truly secret formulas/keys **server-only** (`vibeslayer-policy-kit`). | **Multi-view / GPU driver dump possible by authorized user**, mitigated by chaff, scrambled tiles, budgets, and **64-bit server-baked buyer watermarking** for attribution. | **No mesh/UV/PBR recovery.** Attacker obtains only rate-limited, single-in-flight, focal/light-drifted, tilt-shifted 2D frames — every frame carries the **64-bit blind buyer watermark** (`trace-stream-frame`). |

---

## 2. How Anti-Detect Browsers Were Tested & Blocked (6 Invariants)

Before `--anti-stealth`, **CloakBrowser** (`chromium-146.0.7680.177.5` with C++ fingerprint spoofing) bypassed `navigator.webdriver` and `Runtime.enable` traps because it strips Playwright/CDP signals directly inside the browser binary.

Empirical side-by-side probing of live **CloakBrowser 146** versus unmodified **Google Chrome 158** and **Firefox 153 ESR** identified **6 invariants** that synthetic fingerprint-noise injectors violate while unmodified desktop browsers do not:

| # | Hardware / Rendering Invariant | Unmodified Desktop Chrome 158 | CloakBrowser 146 (Live Measured) | Score Weight |
| :---: | :--- | :--- | :--- | :---: |
| 1 | **2D Canvas Solid `#808080` `fillRect`** | `1` unique RGB (`128,128,128`) | `5` unique RGBs (synthetic pixel noise) | `+2` |
| 2 | **WebGL `gl.clear(128/255, ...)` `readPixels` (`DITHER` off)** | `1` unique RGB (`128,128,128`) | `5` unique RGBs (synthetic readback noise) | `+2` |
| 3 | **Silent `OfflineAudioContext(1, 256, 44100)`** | `0 / 256` non-zero samples | `256 / 256` non-zero samples (audio noise) | `+2` |
| 4 | **Integer-DPR `getBoundingClientRect()`** (`left:10, top:20`) | Exact `[10, 20]` | Poisoned `[9.953125, 19.984375]` | `+2` |
| 5 | **OS Platform vs. Core System Fonts** (`Win32` / `MacIntel`) | Real OS matches installed core fonts | Spoofs `Win32` on Linux with `0/4` Windows fonts (`Segoe UI`, `Tahoma`, `Consolas`, `Calibri`) | `+2` |
| 6 | **D3D11 NVIDIA/RTX WebGL Extension Parity** | Real D3D11 exposes `KHR_parallel_shader_compile` (`30+` exts) | Spoofed D3D11 RTX string missing `KHR_parallel_shader_compile` (`< 30` exts) | `+1` |
| | **Total Anomaly Score** | **`0 / 11` (No False Positives)** | **`11 / 11` (`8 / 11` even with `--fingerprint-platform=linux`)** | Threshold: `balanced >= 4`, `strict >= 2` |

### Why Flag Tweaks Alone Do Not Evade Detection
- Passing `--fingerprint-platform=linux` eliminates invariants #5 and #6, yet CloakBrowser still scores **`8 / 11`** (Canvas2D + WebGL + Audio + DOMRect) — exceeding both `strict` (`>= 2`) and `balanced` (`>= 4`).
- In `--mode stream` (where WebGL is intentionally absent from the client loader), CloakBrowser still scores **`8 / 8`** (or `6 / 6` on Linux spoof), exceeding both thresholds.
- Disabling the noise engine completely leaves a standard headless/automation profile unless the adversary builds a custom noise-free browser from scratch (Tier 4b). For multi-engine coverage across 19 live browsers (including Camoufox, Patchright, Rebrowser, SeleniumBase UC, and Nodriver), see **[VeilBreak](https://github.com/HusX99/veilbreak)**.

---

## 3. Operational Caveats & Cryptographic Scope

1. **`VS_ATTEST_V1` Attestation vs. Authenticated Sessions**:
   - The browser-computed `VS_ATTEST_V1` SHA-256 digest binds probe outputs to the server-issued nonce and `User-Agent` to catch naive replay or header tampering. Because the digest algorithm is public and unkeyed on the client, it is **telemetry integrity**, not a secret client proof of possession. When stronger request authorization is required, enable `--auth-hmac-key` (or place behind your authenticated application session / [`vibeslayer-policy-kit`](../vibeslayer-policy-kit/README.md)).
2. **Privacy-Hardened Browsers & Open DevTools**:
   - `--anti-stealth strict` (`>= 2`) will intentionally flag browsers that inject synthetic Canvas, Audio, or DOMRect noise. `--preset balanced` (`--anti-stealth balanced`, threshold `>= 4`) tolerates single-API farbling (score `2`), whereas multi-API privacy modes (Tor Browser, LibreWolf, Firefox `privacy.resistFingerprinting`, Brave Shields Aggressive) can score `4–6` and trigger **both** `strict` and `balanced` — use `--anti-stealth off` if those browsers must pass.
   - `--anti-cdp on` intentionally traps DevTools `Runtime.enable`; legitimate developers or users with DevTools open will trigger the trap. Disable via `--anti-cdp off` in development or staging environments.
3. **Native ELF64 Memory Boundaries (`wrap-elf` vs. `build-elf-freestanding`)**:
   - `wrap-elf` (used by repository auto-protect) executes the decrypted payload via a sealed `memfd_create` + `execveat` inside a static-PIE Intel CET wrapper (no `PT_INTERP`/`DT_NEEDED`, `LD_*` env scrubbing).
   - `build-elf-freestanding` (`--vault`) additionally maps secret key/payload buffers via Linux `SYS_memfd_secret` (with automatic `mmap` + `MADV_DONTDUMP` + `mlock` fallback when the kernel does not expose `memfd_secret`).
   - On a machine where the adversary holds `root` / kernel privileges, live physical RAM inspection remains outside any userspace protector's boundary.

---

## 4. Measured Performance Benchmarks

Reproducible locally with `make -C vibeslayer-native-core bench` and `npm run bench --prefix vibeslayer-suite`.

### Core Runtime & Cryptographic Throughput

| Subsystem | Measured Performance | Notes |
| :--- | :--- | :--- |
| **`vibe-slayer serve` — ECDH P-256 Lease Handshake** | **`58,619 leases/sec`** | Pure-Rust Solinas P-256 + HKDF-SHA256 + AES-NI GCM (`localhost`) |
| **`vibe-slayer serve` — Encrypted `.vsweb` Asset Throughput** | **`196,205 req/sec`** | Multi-threaded Rust HTTP/1.1 keep-alive pool (`localhost`) |
| **C SDK (`libvibeslayer.so`) `vs_unseal_vspk3`** | **`3,294 MiB/s`** | L3-hot in-process `ChaCha20-Poly1305` + `CMT4` key-committing AEAD |
| **`serve-3d --mode stream` (`1280×820`, 52,965-tri PBR mesh)** | **`23.7 ms` RTT** (`~42 FPS` cap) | Server software PBR raster + blind WM64 + JPEG + AES-256-GCM |
| **Stream Post-JPEG Blind Watermark (`trace-stream-frame`)** | **`0.999` mean conf** (`64/64` bits) | Visually imperceptible Weber-Fechner `±1`/`±2` amplitude clamp |
| **Hardened Web Component JS Runtime Overhead** | **`~0 ms`** steady-state penalty | V8 lazily skips uncalled decoy VM; decoded string table cached in `Map` |

### `vibeslayer-suite` 7-Product Footprint & Latency (`npm run bench --prefix vibeslayer-suite`)

| Target | Raw Size | Sealed Size | Overhead | Cold Unseal Latency |
| :--- | ---: | ---: | ---: | ---: |
| **Web Asset (`.vspk`)** | `116 B` | `233 B` | `2.01×` | `2.46 ms` |
| **WASM Module (`.vspk`)** | `100 B` | `220 B` | `2.20×` (no plaintext `\0asm` bytes) | `0.97 ms` (unseal + instantiate) |
| **3D Spatial (`.vs3d.vspk`)** | `581,260 B` | `749,679 B` | `1.29×` (`7.9998` bits/B) | `4.71 ms` (no per-frame overhead) |
| **AI Weights (`.vsra`, 64 KiB chunks)** | `262,231 B` | `262,303 B` | `1.0003×` (`+72 B`) | `1.45 ms` (`O(1)` chunk) |

---

## 5. Reproducing All Audits & Benchmarks Locally

```bash
# Build Linux ELF64 binary and C99 SDK shared library
make -C vibeslayer-native-core all

# Rust unit tests (crypto vectors, AES-NI/Solinas parity, JPEG/PNG, WM64, presets, NL parser)
cargo test --manifest-path vibeslayer-native-core/rust_core/Cargo.toml --release

# Full native + polyglot + adversarial red-team + proxy compliance test suite
make -C vibeslayer-native-core test

# Optional loopback throughput microbenchmarks
make -C vibeslayer-native-core bench

# Companion JavaScript packages (including Web Component antiStealth tests)
npm test --prefix vibeslayer-suite
npm test --prefix vibeslayer-policy-kit

# Public multi-domain tool comparison (esbuild, terser, javascript-obfuscator, js-confuser, strip, UPX, OpenSSL)
npm --prefix benchmarks install
python3 benchmarks/run_unbiased_benchmark.py
```
