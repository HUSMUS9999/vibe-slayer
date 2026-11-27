# Vision, Architecture Rationale & Benchmarks

[← Back to README](../README.md) · [Beginner's Guide](./getting-started-beginners.md) · [Threat Model](./threat-model-and-benchmarks.md)

---

## 1. The Vision & The Need

### Why Traditional Static Obfuscation Struggles Against AI Reversing Agents

For two decades, client-side software protection leaned heavily on **static obfuscation**: renaming variables, inserting dead code, flattening control flow, and inflating small scripts or binaries into walls of chaff.

That model breaks down against **AI reversing agents** and **instrumented stealth browsers**:

1. **Agents Write Dynamic Dumpers Instead of Reading Obfuscated Code**: Point a reversing agent at a statically obfuscated JS bundle, WASM binary, or `.glb` viewer. Rather than manually reading 130 KB of control-flow chaff, it runs a short Node/Playwright/CDP script to hook `eval`, `WebAssembly.instantiate`, `gl.bufferData`, or `fetch`, or simply calls the exported function offline via `require()`.
2. **Dead-Section Chaff Penalizes Legitimate Users**: Heavy AST obfuscators inflate an `878 B` script to `147 KB` (`168×`) with `42.8 ms` execution time while remaining callable offline. Classical binary packers can balloon a `16 KB` binary past `1 MB` while leaving `.rodata` secrets or `\0asm` headers intact.
3. **Anti-Detect Browsers Bypass Naive Bot Checks**: C++-patched Chromium forks such as **CloakBrowser** strip `navigator.webdriver` and Chrome DevTools Protocol (CDP) signals directly inside the browser binary, slipping past basic automation checks.
4. **3D & AI Assets Rarely Receive Real Protection**: Standard web 3D viewers transmit complete `.glb` meshes, UVs, and PBR textures directly to the client GPU, and AI weight files (`.safetensors`, `.onnx`, `.gguf`) sit unencrypted on disk.

### The Vibe-Slayer Design: Four Concrete Engineering Principles

Vibe-Slayer replaces static obscurity with **four verifiable architectural boundaries**:

1. **Encrypted At Rest and On First Fetch**: Protected source files, `.env`, `.wasm`, AI tensor chunks, web assets (`.vsweb`), and 3D bundles are encrypted with standard 256-bit AEAD (`AES-256-GCM`, headerless key-committing `VSPK3` `HKDF-SHA256` + `CMT4` + `ChaCha20-Poly1305`, or 64 KiB `VSRA` chunks) with no embedded keys and no plaintext payload bytes (and headerless ciphertext with no container magic bytes for `VSPK3`).
2. **Server-Side 3D Rendering Where Secrecy Is Absolute**: If a 3D mesh must never be extracted by a GPU debugger, Transform-Feedback hook, or AI agent, `--mode stream` keeps **all geometry, UVs, textures, and shaders on the server**, delivering only per-session `AES-256-GCM`-encrypted 2D frames carrying an invisible post-JPEG 64-bit forensic buyer watermark.
3. **Hardware-Invariant Anti-Stealth & Inline Component Self-Defense**: Rather than relying solely on spoofable User-Agent strings, `--anti-stealth` checks **6 rendering/audio/geometry/font/GPU invariants** violated by synthetic noise injectors — enforced in the loader, at the server via attestation, and inline inside every hardened Web Component `.js`/`.mjs` module.
4. **Native Speed + Beginner Accessibility**: Compiles to a standalone Rust CLI binary (paired with an optional C99 shared library, `libvibeslayer.so`) and local natural-language workflows (`./vibe-slayer ask "..."`).

---

## 2. Measured Head-to-Head Benchmarks

All tables below report **live, reproducible measurements** on identical inputs on the same Linux `x86_64` machine.

### A. Multi-Domain Comparison vs. Standard Public Tools (`benchmarks/results.json`)

Reproduce with `npm --prefix benchmarks install && python3 benchmarks/run_unbiased_benchmark.py`. Node.js JS tools run inside a single warm process so V8 startup is not billed to `esbuild` or `terser`.

#### 1. JavaScript Delivery & Protection (`878 B` pricing & license module)

| Tool | Asset Size | Shared Loader | Warm Build | Offline Callable? | Static CDN? | Trade-Off |
| :--- | ---: | ---: | :-: | :-: | :-: | :--- |
| **Raw Unprotected JS** | `878 B` (`1.00×`) | `0 B` | `0.00 ms` | Yes | **Yes** | Baseline control; unprotected |
| **`esbuild` (`--minify`)** | **`527 B`** (`0.60×`) | `0 B` | `2.39 ms` | Yes | **Yes** | Fastest & smallest static bundle; minification only |
| **`terser` (`compress+mangle`)** | `534 B` (`0.61×`) | `0 B` | `8.89 ms` | Yes | **Yes** | Standard minifier; no offline defense |
| **`javascript-obfuscator` (default)** | `2,169 B` (`2.47×`) | `0 B` | `48.88 ms` | Yes | **Yes** | Static CDN; literals remain visible & callable offline |
| **`javascript-obfuscator` (high)** | `5,733 B` (`6.53×`) | `0 B` | `35.66 ms` | Yes | **Yes** | Hides static literals (`3.43 ms` exec); still callable offline |
| **`js-confuser` (`medium`)** | `147,313 B` (`167.78×`) | `0 B` | `889.10 ms` | Yes | **Yes** | Heavy AST/CF bloat (`42.75 ms` exec); still callable offline |
| **`Vibe-Slayer` (`.vsweb fast`)** | **`906 B`** (`1.03×`) | `+8,441 B` | **`1.60 ms`** | **No (encrypted)** | No (`serve`) | `+28 B`/asset AES-256-GCM + one-time `loader.js`; needs runtime server |
| **`Vibe-Slayer` (`.vsweb paranoid`)** | `102,783 B` (`117.06×`) | `+12,068 B` | `1.90 ms` | **No (encrypted)** | No (`serve`) | Adds fixed `96 KB` opt-out decoy VM (`--js-bloat-kb`) + `rtKey` JS + inline anti-stealth guard |

#### 2. Native Linux `ELF64` Binary (`15,992 B` `gcc -O2` C binary)

| Tool | Size | Ratio | Cold Start (Median) | `.rodata` Leaked? | Trivially Unpackable? | Trade-Off |
| :--- | ---: | :-: | :-: | :-: | :-: | :--- |
| **Raw `gcc -O2` ELF64** | `15,992 B` | `1.00×` | `0.388 ms` | Yes | Yes | Baseline unstripped binary |
| **`strip --strip-all`** | `14,480 B` | `0.91×` | **`0.349 ms`** | Yes | Yes | No runtime cost; `.rodata` & `.text` remain plaintext |
| **`UPX 4.2.4` (`--best`)** | **`5,348 B`** | **`0.33×`** | `0.442 ms` | **No** | Yes (`upx -d` in `9.67 ms`) | Best compression; trivially reversed with `upx -d` |
| **`Vibe-Slayer` (Static-PIE + CET)** | `273,544 B` | `17.11×` | `2.169 ms`* | **No** | **No** | No `PT_INTERP`/`DT_NEEDED`, Intel CET + sealed `memfd_create` `execveat`; adds ~`260 KB` stub & needs lease key |

*\*End-to-end via `./vibe-slayer run` CLI launcher; direct freestanding FD-3 unseal (`build-elf-freestanding` with `SYS_memfd_secret`) measures `0.891 ms`.*

#### 3. AI Model Weights (`.safetensors`, `262,240 B` FP32 tensor)

| Tool | Size | Ratio | Median Time | `O(1)` Random Access? | Raw FP32 Exposed? | Trade-Off |
| :--- | ---: | :-: | :-: | :-: | :-: | :--- |
| **Raw `.safetensors`** | `262,240 B` | `1.0000×` | **`0.022 ms`** | **Yes** | Yes | In-process baseline; plaintext weights |
| **OpenSSL Whole-File AES-256-CBC** | `262,256 B` | `1.0001×` | `2.761 ms` | No (`O(N)`) | **No** | Unauthenticated CBC; full-file CLI decrypt required |
| **`Vibe-Slayer` `VSPK3` (Whole-File CMT4)** | `263,260 B` | `1.0039×` | `1.661 ms`* | No (`O(N)`) | **No** | Headerless key-committing `CMT4` + `ChaCha20-Poly1305` (C SDK peak `3,294 MiB/s` L3-hot) |
| **`Vibe-Slayer` `VSRA` (64 KiB Chunks)** | `327,869 B` | `1.2503×`† | `1.670 ms` | **Yes (`O(1)`)** | **No** | `vibeslayer-suite` 64 KiB `ChaCha20-Poly1305` chunk seek + per-lease watermark (in-process) |

*\*CLI time includes Rust process spawn. †`262,240 B` = `4 × 64 KiB + 96 B` `.safetensors` header; the 5th partial chunk pads to 64 KiB (for multi-GB models the trailing partial chunk is `< 0.01%`).*

---

### B. `vibeslayer-suite` 7-Target Footprint & Unseal Matrix

Canonical measurements from `npm run bench --prefix vibeslayer-suite` (matched to [`vibeslayer-suite/README.md`](../vibeslayer-suite/README.md)):

| Product Target (`vibeslayer-suite`) | Raw Size | Sealed Output & Measured Latency | Security Properties |
| :--- | ---: | :--- | :--- |
| **1. Web Asset (`.vspk`)** | `116 B` | **`233 B` (`2.01×`)** · `2.46 ms` cold unseal | `AES-256-GCM` + non-extractable WebCrypto `ECDH P-256` |
| **2. WebAssembly (`.wasm`)** | `100 B` | **`220 B` (`2.20×`)** · `0.97 ms` unseal+instantiate | `\0asm` header hidden; ABI preserved |
| **3. 3D Spatial (`.glb`, external mesh)** | `581,260 B` | **`749,679 B` (`1.29×`)** · `4.71 ms` unseal | `7.9998` bits/B + `WM64` (or `serve-3d --mode stream`, mesh stays on server) |
| **4. Native Linux `ELF64`** | `15,992 B` | **`25,656 B`** (`vibeslayer-suite`, `2.01 ms`) or **`169,008 B`** (`build-elf-freestanding` `--vault`, `0.891 ms`) | `.rodata` encrypted; freestanding vault uses Intel CET + `memfd_secret` |
| **5. Desktop App Rules** | `67 B` | **`649 B`** `Ed25519` `.vsasar` · `0.095 ms` IPC | Native C out-of-process enclave sidecar (`PR_SET_DUMPABLE=0`) |
| **6. Mobile Asset** | `44 B` | **`24,056 B`** `libvsmobile.so` + `143 B` `.vsmb` · `1.30 ms` | APK signing-cert HKDF + `ChaCha20-Poly1305` binding |
| **7. AI Weights (`VSRA` raw FP32)** | `262,231 B` | **`262,303 B` (`1.0003×`)** · `1.45 ms` chunk unseal | `O(1)` 64 KiB `ChaCha20-Poly1305` chunk seek + per-lease watermark |

---

### C. Standalone Native Server & Runtime Throughput (`vibe-slayer` Rust + C99 SDK)

Reproduce loopback server & C SDK microbenchmarks with `make -C vibeslayer-native-core bench` (measured on multi-core Linux `x86_64` with AVX-512 / AES-NI / SHA-NI):

| Benchmark Workload | Measured Result | Notes |
| :--- | :--- | :--- |
| **`vibe-slayer serve` — ECDH P-256 + HKDF + AES-GCM Lease** | **`58,619 leases/sec`** | Pure-Rust Solinas P-256 + AES-NI GCM (`localhost`, 16 keep-alive workers) |
| **`vibe-slayer serve` — Encrypted `.vsweb` Asset Delivery** | **`196,205 req/sec`** | Multi-threaded RFC 9112 HTTP/1.1 keep-alive worker pool (`localhost`) |
| **C SDK (`libvibeslayer.so`) `vs_unseal_vspk3` (peak)** | **`3,294 MiB/s`** | L3-hot in-process `CMT4` + `ChaCha20-Poly1305` (Rust/C/Go/Python wire-compatible) |
| **`serve-3d --mode stream` (`1280×820`, 52,965-tri external mesh)** | **`23.7 ms` RTT** (`~42 FPS` cap) | Server software PBR raster + blind 64-bit WM (`0.999` conf) + JPEG + AES-256-GCM |
| **`VS3D` `decode-wm64` (`±2` LSB coordinate noise, external mesh)** | **`0.984 ms` median** (`64/64` bits) | `O(1)` candidate-free, reference-assisted (`--owner-ref`) correlation (`0.968` mean chip confidence) |
| **Live Anti-Stealth Verification** | CloakBrowser 146: **denied (anomaly score `11/11`; no leases issued)** · Chrome 158 & Firefox 153 ESR: **no false positives** | Desktop Chrome & Firefox ESR (Firefox via VeilBreak harness); excludes Safari/WebKit & mobile |

---

## 3. Design Evolution

- Early prototypes (`v0.5.x`) left suffixes exposed under partial encryption or returned raw `.glb` buffers in client-side unsealers.
- Subsequent revisions moved to headerless key-committing `VSPK3` (and streaming `VSPK3 v2` on `ring`), **server-rendered AES-256-GCM 3D pixel streaming**, offline-dead `rtKey` JS hardening, strict proxy compliance, and 6-invariant anti-stealth checks.

---

## 4. Security Boundaries

No client-side tool can make JavaScript or local pixels mathematically unreadable to an adversary who compiles a custom C++ Chromium build without fingerprint noise and inspects V8 RAM during a legitimately authorized session. Vibe-Slayer is built to:
1. **Eliminate** offline scraping, static reversing, Playwright/Puppeteer/CDP AI-agent ripping, and off-the-shelf fingerprint-noise anti-detect browsers (such as CloakBrowser).
2. **Keep secrets and 3D geometry strictly server-side** whenever absolute confidentiality is required (`serve-3d --mode stream` and `vibeslayer-policy-kit` `server-only` actions).
3. **Attach forensic 64-bit buyer watermarks** to every authorized 3D mesh, stream frame, and AI tensor chunk so authorized-session leaks remain attributable.
