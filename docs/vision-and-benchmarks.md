# Vision, Why Vibe-Slayer Exists & Head-to-Head Benchmarks

[← Back to README](../README.md) · [Beginner's Guide](./getting-started-beginners.md) · [Threat Model](./threat-model-and-benchmarks.md)

---

## 1. The Vision & The Need

### Why Traditional Obfuscation Collapsed in the Age of "Vibe Reversing"

For two decades, client-side software protection relied on **static obfuscation**: renaming variables, inserting dead code, flattening control flow, and inflating 100-byte scripts into 5-megabyte walls of JavaScript or ELF chaff.

That era ended when **AI coding/reversing agents** and **instrumented stealth browsers** became ubiquitous:

1. **LLMs Don't Read Variable Names — They Write Dynamic Dumpers**: Point an autonomous reversing agent at a statically obfuscated JS bundle, WASM binary, or `.glb` viewer. Rather than manually deobfuscating 130 KB of control-flow chaff, the agent runs a 15-line Node/Playwright/CDP script to hook `eval`, `WebAssembly.instantiate`, `gl.bufferData`, or `fetch`, dumping the original plaintext in seconds.
2. **Dead-Section Chaff Burns Your Users, Not Attackers**: Classic packers bloat a `100 B` WebAssembly module to **`6.88 MB` (`68,801×` larger!)** or a `16 KB` Linux binary to **`1.18 MB` (`73.8×` larger!)** while leaving `.rodata` secrets, `\0asm` headers, or raw AI model floats readable at rest.
3. **Anti-Detect Browsers Bypass Naive Bot Checks**: C++-patched Chromium forks such as **CloakBrowser** strip `navigator.webdriver` and Chrome DevTools Protocol (CDP) leaks directly inside the browser binary, slipping right past standard anti-scraping checks.
4. **3D & AI Assets Are Completely Unprotected**: Standard web 3D viewers transmit complete `.glb` meshes, UVs, and PBR textures directly to the client GPU; AI weight files (`.safetensors`, `.onnx`, `.gguf`) sit unencrypted on disk; and most binary protectors simply return an unsupported error on 3D or ML assets.

### The Vibe-Slayer Architecture: Cryptographic Boundaries + Hardware Physics

Vibe-Slayer replaces security-by-obscurity with **four concrete engineering principles**:

1. **Zero Plaintext At Rest or On First Fetch**: Every protected source file, `.env`, `.wasm`, AI tensor chunk, web asset (`.vsweb`), and 3D bundle is encrypted with standard 256-bit AEAD (`AES-256-GCM` or key-committing `VSPK3` `HKDF-SHA256` + `CMT4` + `ChaCha20-Poly1305`) — zero plaintext magic headers, zero keys embedded in served bundles.
2. **Zero-Geometry Server Rendering Where Secrecy Is Absolute**: If a 3D mesh must never be ripped by *any* GPU debugger, Transform-Feedback hook, or AI agent, `--mode stream` keeps **100% of geometry, UVs, textures, and shaders on the server**, delivering only per-session `AES-256-GCM`-encrypted 2D frames tagged with an imperceptible post-JPEG 64-bit forensic buyer watermark.
3. **Physics-Invariant Anti-Stealth & Inline Component Self-Defense**: Rather than chasing easily spoofed User-Agent strings, `--anti-stealth` measures **6 hardware/physics invariants** (Canvas2D flat fill, WebGL flat clear, silent audio, integer-DPR `DOMRect`, OS-vs-font presence, and D3D11 extension parity) that anti-detect noise injectors like CloakBrowser cannot hide — enforced at the loader, at the server via SHA-256 attestation, and inline inside every hardened Web Component `.js`/`.mjs` module.
4. **Zero-Dependency Native Speed + Beginner Accessibility**: Built as a single standalone Rust + C99 binary with **zero external Rust crates** and **zero Node.js runtime dependency**, yet accessible to complete beginners through **presets** (`fast` / `balanced` / `paranoid`) and **plain-English commands** (`./vibe-slayer ask "..."`).

---

## 2. Real, Measured Head-to-Head Benchmarks vs. Other Tools

All numbers below come from **real, executed benchmark runs** on identical unprotected inputs — never simulated or extrapolated. Comparison baseline: **Unprotected inputs** and **`BLA v3.2.1`** (`--intensity bankrupt`, a production AI-resistant obfuscation tool), alongside Vibe-Slayer's measured native server and C SDK benchmarks.

### A. Multi-Target Footprint, Security & Latency (`vibeslayer-suite` vs. `BLA v3.2.1`)

| Target Asset | Raw Size | `BLA v3.2.1` (`--intensity bankrupt`) | `Vibe-Slayer` (Real Measured) | Key Takeaway |
| :--- | ---: | :--- | :--- | :--- |
| **Web JS Bundle** | `116 B` | `130,098 B` (**`1,121.5×`** bloat); self-contained plaintext runtime (`quote(100)` callable offline via 1-line dynamic import) | **`233 B` (`2.01×`)**; `AES-256-GCM` + non-extractable WebCrypto `ECDH P-256`; **`2.11 ms`** cold unseal; **`0` offline bits** | **`558×` smaller**; offline unrecoverable without live lease |
| **WebAssembly (`.wasm`)** | `100 B` | `6,880,116 B` (**`68,801×`** bloat); `\0asm` header exposed (`true`); **`9.34 ms`** cold instantiate; default mode renames exports | **`220 B` (`2.20×`)**; `\0asm` exposed: **`false`**; **`0.91 ms`** unseal + instantiate; ABI preserved by default | **`31,273×` smaller** and **`10.2×` faster** cold boot |
| **3D Model (`.glb`)** | `581,260 B` | **Unsupported (`exit 1`)** | **`749,679 B` (`1.29×`)** cooked `VS3D` (`7.9998` bits/B); **`5.55 ms`** unseal; `0` frame ops; **`64/64`** WM64 trace under `±2` LSB noise; or **`--mode stream`** (`0` mesh bytes sent) | Full 3D encryption + forensic buyer tracing + zero-geometry streaming |
| **Native Linux `ELF64`** | `15,992 B` | `1,180,912 B` (**`73.84×`** bloat); `.rodata` secrets left plaintext (`true`); `1,952` live `.text` tokens | **`169,008 B`** (`build-elf-freestanding`, **`6.99×` smaller**); `0` `PT_INTERP`/`DT_NEEDED`; Intel CET `IBT+SHSTK`; `SYS_memfd_secret`; `PR_SET_DUMPABLE=0`; **`0.891 ms`** cold start; **`902,988`** live `.text` tokens (**`462.6×`** more real code tokens) | Zero dynamic linker, zero `.rodata` leak, immune to `LD_PRELOAD` & `ptrace` |
| **Desktop App Rules (Electron/Tauri)** | `67 B` | In-process JS chaff; visible to Renderer DevTools | **`649 B`** Ed25519 `.vsasar` + native C out-of-process enclave (`PR_SET_DUMPABLE=0`, **`0.092 ms`** IPC); `0` secrets in renderer | Keeps master secrets out of Renderer DevTools |
| **Mobile Asset (Android/iOS)** | `44 B` | `1,188,883 B` `.so` chaff; **no APK signing-cert binding (`false`)** | **`24,056 B`** `libvsmobile.so` + `143 B` `.vsmb`; HKDF+ChaCha20-Poly1305 bound to APK cert (**`1.64 ms`**); repackaged APK rejected | **`49×` smaller** with cryptographic APK cert pinning |
| **AI Weights (`.safetensors` / FP32)** | `262,231 B` | `272,184 B` (`1.04×`); **raw FP32 weights left 100% plaintext (`true`)** | **`262,303 B` (`1.0003×`, `+72 B`)**; `O(1)` 64 KiB random-access AEAD (**`1.56 ms`**); `0` raw floats exposed; per-lease server-side watermark | Encrypts real tensor bytes at `+0.03%` size overhead |

### B. Standalone Native Server & Runtime Throughput (`vibe-slayer` Pure Rust + C99)

| Benchmark Workload | Measured Throughput / Latency | Comparison Context |
| :--- | :--- | :--- |
| **`vibe-slayer serve` — ECDH P-256 + HKDF + AES-GCM Lease** | **`58,619 leases/sec`** | Pure-Rust Solinas P-256 + AES-NI GCM, zero external crates, zero Node.js |
| **`vibe-slayer serve` — Encrypted `.vsweb` Asset Delivery** | **`196,205 req/sec`** | Multi-threaded RFC 9112 HTTP/1.1 keep-alive worker pool |
| **C SDK (`libvibeslayer.so`) `vs_unseal_vspk3` (peak)** | **`3,294 MiB/s`** | Wire-compatible `CMT4` + `ChaCha20-Poly1305` across Rust, C, Go, Python |
| **`serve-3d --mode stream` (`1280×820`, 52,965-tri PBR mesh)** | **`23.7 ms` RTT** (`~42 FPS` cap) | Full software PBR raster + blind 64-bit WM (`0.999394` conf) + JPEG + AES-256-GCM |
| **3D `WM64` O(1) Blind Decode (`±2` LSB coordinate noise)** | **`0.984 ms`** median (`64/64` bits) | Candidate-free correlation (`0.968` mean chip confidence) |
| **Live CloakBrowser 146 vs. Unmodified Chrome 158** | CloakBrowser: **`100%` Denied (`11/11`, `0` leases)** · Chrome 158: **`0/11` (`0` false positives)** | Verified on Web Components (`strict` & `balanced`), extracted `.mjs`, and 3D Stream/GPU |

---

## 3. Architectural Evolution: Lessons From Adversarial Self-Audits

Vibe-Slayer was hardened iteratively through blind red-team audits rather than marketing claims:
- Early prototypes (`v0.5.x`) failed blind extraction tests when partial encryption left suffixes exposed or client-side unsealers returned raw `.glb` buffers.
- Those failures drove the full redesign to **`v1.0.0-beta.3`**: headerless key-committing `VSPK3`, freestanding `-nostdlib` static-PIE `ELF64` binaries with `SYS_memfd_secret` and Intel CET, **zero-geometry AES-256-GCM 3D pixel streaming**, offline-dead `rtKey` JS hardening, RFC 9112 proxy compliance, and empirically verified **6-invariant anti-CloakBrowser enforcement**.

---

## 4. Honest Boundary Statement

No client-side tool can make JavaScript or local pixels mathematically unreadable to an adversary who compiles a custom zero-noise C++ Chromium browser from source and inspects V8 RAM during a legitimately authorized session. Vibe-Slayer is built to:
1. **Eliminate** offline scraping, static reversing, Playwright/Puppeteer/CDP AI-agent ripping, and off-the-shelf anti-detect browsers (CloakBrowser).
2. **Keep secrets and 3D geometry strictly server-side** whenever absolute confidentiality is required (`serve-3d --mode stream` and `vibeslayer-policy-kit` `server-only` actions).
3. **Attach forensic 64-bit buyer watermarks** to every authorized 3D mesh, stream frame, and AI tensor chunk so leaks remain provably attributable.
