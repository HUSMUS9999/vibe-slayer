<p align="center">
  <img src="assets/vibeslayer-hero-dark.svg#gh-dark-mode-only" alt="Vibe-Slayer" width="320" />
  <img src="assets/vibeslayer-hero-light.svg#gh-light-mode-only" alt="Vibe-Slayer" width="320" />
</p>

<p align="center">
  <strong>Cryptographic delivery, server-side 3D streaming, and binary sealing in a standalone Rust &amp; C99 core.</strong>
</p>

<p align="center">
  <a href="https://github.com/HUSMUS9999/vibe-slayer/releases"><img src="https://img.shields.io/github/v/release/HUSMUS9999/vibe-slayer?include_prereleases&style=flat&logo=github&logoColor=white&label=release&labelColor=21262d&color=0284c7" alt="Release" /></a>
  <a href="https://github.com/HUSMUS9999/vibe-slayer/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/HUSMUS9999/vibe-slayer/ci.yml?branch=main&style=flat&logo=githubactions&logoColor=white&label=CI&labelColor=21262d" alt="CI Status" /></a>
  <a href="#architecture"><img src="https://img.shields.io/badge/core-Rust%20%2B%20C99-b7410e?style=flat&logo=rust&logoColor=white&labelColor=21262d" alt="Core: Rust + C99" /></a>
  <a href="#architecture"><img src="https://img.shields.io/badge/crates-0-0e7490?style=flat&labelColor=21262d&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjZmZmZmZmIiBzdHJva2Utd2lkdGg9IjIuMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNMTIgMkwzIDd2MTBsOSA1IDktNVY3bC05LTV6Ii8+PHBhdGggZD0iTTEyIDIyVjEyIi8+PHBhdGggZD0iTTMgN2w5IDUgOS01Ii8+PC9zdmc%2B" alt="Rust Crates: 0" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/HUSMUS9999/vibe-slayer?style=flat&logo=opensourceinitiative&logoColor=white&label=license&labelColor=21262d&color=0f766e" alt="License: MIT" /></a>
</p>

<p align="center">
  <a href="#quickstart"><strong>Quickstart</strong></a> &nbsp;&middot;&nbsp;
  <a href="#architecture"><strong>Architecture</strong></a> &nbsp;&middot;&nbsp;
  <a href="#performance"><strong>Performance</strong></a> &nbsp;&middot;&nbsp;
  <a href="#security-model--limits"><strong>Security Model</strong></a> &nbsp;&middot;&nbsp;
  <a href="#documentation"><strong>Docs</strong></a>
</p>

**Vibe-Slayer** stops static scrapers, WebGL mesh rippers, and automated browser/CDP agents from extracting live websites, interactive 3D models, Linux `ELF64` binaries, AI weights, and source repositories.

Instead of static obfuscation that breaks under offline `require()` or DevTools dumps, it puts cryptographic leases and server-side boundaries in front of every asset — see [Vision & Benchmarks](docs/vision-and-benchmarks.md) for rationale and head-to-head data.

## Quickstart

New to the CLI? Start with the **[Plain-English Beginner's Guide](docs/getting-started-beginners.md)**.

### 1. Build & Run the Sandbox Demo

Requires Rust (`cargo`). Websites, 3D models, and `VSPK3` vaults build with no external tools; `demo` and Linux `ELF64` binary wrapping also require Linux `x86_64` + `gcc`.

```bash
git clone https://github.com/HUSMUS9999/vibe-slayer.git
cd vibe-slayer
cargo build --release --manifest-path vibeslayer-native-core/rust_core/Cargo.toml
cp vibeslayer-native-core/rust_core/target/release/vibe-slayer ./vibe-slayer

./vibe-slayer demo
```

### 2. Core Workflows

Original files are never modified in place; protected outputs are written beside them with a `0600` key vault.

```bash
# Live website / Web Components (expects a pre-built static or bundled ./dist folder)
./vibe-slayer website ./dist -o ./dist-protected \
  --preset paranoid --origin http://127.0.0.1:8080
./vibe-slayer serve ./dist-protected \
  --preset paranoid --addr 127.0.0.1:8080 --origin http://127.0.0.1:8080

# Interactive 3D .glb as encrypted 2D frames (0 client geometry/WebGL; key auto-generated)
./vibe-slayer shield-3d --in ./hero.glb --out ./hero-shielded \
  --key-file ./hero.vsshield.key --preset paranoid
./vibe-slayer serve-3d ./hero-shielded --key-file ./hero.vsshield.key \
  --preset paranoid --addr 127.0.0.1:8790 --origin http://127.0.0.1:8790

# Repositories, Linux x86_64 ELF64 binaries, and AI weights (.safetensors -> .vspk3)
./vibe-slayer scan ./my-repo
./vibe-slayer ./my-repo && ./vibe-slayer test ./my-repo-protected
./vibe-slayer ./my_app && ./vibe-slayer run ./my_app.protected
./vibe-slayer ./weights.safetensors
```

**Presets:** `fast` (local dev & CI), `balanced` (general web traffic & 60 FPS WebGL2), `paranoid` (maximum web hardening & zero-geometry 3D streaming). Testing `--preset paranoid` locally? Close browser DevTools (triggers `--anti-cdp`) or develop with `--preset fast`.

### 3. Plain-English Commands (`explain` & `ask`)

Runs **100% locally in Rust** — deterministic rule-based parser, zero LLM APIs, zero network calls (prefix paths with `./`). Preview safely with `explain`, or run with `ask`:

```bash
./vibe-slayer explain "protect my website ./dist and block stealth browsers on port 8080"
./vibe-slayer ask "stream my 3d model ./hero.glb without sending geometry"
```

```text
[vibe-slayer natural language]
  Goal:      Encrypt website & Web Components in ./dist -> ./dist-protected
  Command:   ./vibe-slayer website ./dist -o ./dist-protected --preset paranoid --origin http://127.0.0.1:8080 --anti-stealth strict
  Next step: ./vibe-slayer serve ./dist-protected --preset paranoid --addr 127.0.0.1:8080 --origin http://127.0.0.1:8080 --anti-stealth strict
  Mode:      DRY-RUN (use './vibe-slayer ask ...' to execute)
```

## Architecture

<p align="center">
  <img src="assets/vibeslayer-arch-dark.svg" alt="Vibe-Slayer Protection Architecture and Trust Boundaries" width="100%" />
</p>

- **Websites & Web Components (`.vsweb`):** Serves `AES-256-GCM` assets unlocked via non-extractable WebCrypto `ECDH P-256` leases, with Shadow DOM support, runtime-keyed JS that refuses to run offline, V8 `Runtime.enable` CDP traps, and `--anti-stealth` probes (plus synchronous inline `.js`/`.mjs` guards under `--harden-js`).
- **3D Models (`--mode stream` / `--mode gpu`):** Renders PBR frames server-side and streams `AES-256-GCM` frames tagged with an invisible 64-bit per-user watermark (`0` vertices, UVs, shaders, or WebGL sent to clients), or serves 60 FPS encrypted WebGL2.
- **Binaries, WASM, Repos & AI Weights:** Wraps Linux `x86_64` `ELF64` binaries in static-PIE Intel CET stubs (`memfd_create` / `memfd_secret`), seals repos, `.wasm`, and `.safetensors` in headerless `VSPK3` (`CMT4` + `ChaCha20-Poly1305`) vaults, and provides `O(1)` 64 KiB random-access `VSRA` AI weight chunking in `vibeslayer-suite`.
- **Server & SDKs:** Built-in multi-threaded RFC 9112 HTTP/1.1 server (Nginx, Caddy, Cloudflare compatible), wire-compatible `VSPK2`/`VSPK3` SDKs in Rust, C99, Go, and Python, plus zero-dep companion Node.js packages.

| Package | Status | Runtime & Deps | Ownership |
| :--- | :--- | :--- | :--- |
| [`vibeslayer-native-core/`](vibeslayer-native-core/README.md) | `v1.0.0-beta.3` | Pure Rust CLI (`0` crates) + C99 SDK (`gcc` for `ELF64` wrapping) | `./vibe-slayer`, `serve`, `serve-3d`, `VSPK2`/`VSPK3`, `ELF64`, Rust/C/Go/Python SDKs |
| [`vibeslayer-suite/`](vibeslayer-suite/README.md) | `v0.8.0-beta.2` | Node.js `>= 20` (`0` npm deps) | Companion 7-target JS suite (Web, WASM, 3D `VS3D`, Native, Desktop, Mobile, `O(1)` `VSRA` AI chunks) |
| [`vibeslayer-policy-kit/`](vibeslayer-policy-kit/README.md) | `v0.6.0-beta.1` | Node.js `>= 20` (`0` npm deps) | Code-configured `public-preview` / `server-only` / `client-sealed` API gateway + `antiStealth` |

## Performance

Public tool comparisons (`esbuild`, `terser`, `javascript-obfuscator`, `js-confuser`, `strip`, `UPX`, `OpenSSL`) are reproducible via `python3 benchmarks/run_unbiased_benchmark.py` ([raw data](benchmarks/results.json)); throughput rows come from `make -C vibeslayer-native-core bench` and external 3D test meshes on a multi-core Linux `x86_64` host (`AVX-512` / `AES-NI` / `SHA-NI`). Full tables and methodology live in [Vision & Benchmarks](docs/vision-and-benchmarks.md).

| Workload | Measured Result | Scope & Trade-Off |
| :--- | :--- | :--- |
| **Web `.vsweb` (`fast`)** (`878 B` JS) | `906 B` (`1.03×`) `+8,441 B` shared loader · `1.6 ms` build | `0` offline bits; requires `vibe-slayer serve` (not static CDN) |
| **Web `.vsweb` (`paranoid`)** (`878 B` JS) | `102,783 B` (`117.1×`) `+12,068 B` loader · `1.9 ms` build | Adds opt-out `96 KiB` decoy VM (`--js-bloat-kb 0` for lean prod) + inline guard |
| **`serve` HTTP/1.1 throughput** | `58,619` ECDH leases/s · `196,205` req/s | `make bench`, 16 forked loopback keep-alive workers (`balanced`) |
| **Linux `ELF64` (`15,992 B` C bin)** | `273,544 B` (`17.1×`) · `2.17 ms` via `./vibe-slayer run` | Static-PIE + Intel CET + sealed `memfd_create`; `~260 KB` stub\* |
| **AI weights (`.safetensors`, `262 KB`)** | `VSPK3` `1.66 ms` CLI (`3,294 MiB/s` C SDK) · `VSRA` `1.67 ms` | `VSPK3` full-file CLI vs. `vibeslayer-suite` `O(1)` 64 KiB chunk (in-process) |
| **3D stream (`1280×820`, 53k tris)** | `23.7 ms` RTT (`~42 FPS` cap) · `0.999` WM conf | External PBR mesh; server software render + blind 64-bit WM + JPEG + AES-GCM |
| **Anti-stealth live check** | CloakBrowser 146: denied (anomaly score `11/11`) · Chrome / Firefox ESR: `0` FP | Desktop Chrome 158 & Firefox 153 ESR (via [VeilBreak](https://github.com/HUSMUS9999/veilbreak)); excludes Safari & mobile |

*\*Separately, freestanding vault mode (`./vibe-slayer <secret> --vault` / `build-elf-freestanding`, `<= 4 KiB` secret unseal via `memfd_secret` without `execveat`) measures `0.891 ms`.*

## Security Model & Limits

In `paranoid` mode, Vibe-Slayer blocks static scrapers (`curl`/`wget`), standard automation (Playwright, Puppeteer, Selenium), V8 `Runtime.enable` CDP dumpers, and fingerprint-noise anti-detect browsers (verified against CloakBrowser 146). Full Tier 1–4 adversary matrix and the 6 anti-stealth invariants live in [Threat Model & Empirical Proofs](docs/threat-model-and-benchmarks.md).

Hard boundaries to design around:

- **Unaudited custom cryptography ([SECURITY.md](SECURITY.md)):** The Rust core implements custom P-256 ECDH, AES-GCM, ChaCha20-Poly1305, and HTTP/1.1 with no third-party audit; P-256 scalar multiplication, AES key expansion, and the software AES fallback are not yet constant-time verified.
- **Client-side JS is not DRM:** An attacker compiling a custom zero-noise Chromium binary from C++ source can read executed JS and in-session `rtKey` from V8 RAM. Keep true secrets server-side with [`vibeslayer-policy-kit`](vibeslayer-policy-kit/README.md).
- **No SEO, SSR, or static CDN caching for `.vsweb`:** `GET /` serves an empty loader shell and mounts assets via in-memory `blob:` URLs; multi-file ES module apps must be pre-bundled (relative `import` across `blob:` URLs is unsupported).
- **`VS_ATTEST_V1`, privacy browsers & DevTools:** `VS_ATTEST_V1` is an unkeyed SHA-256 digest (pair with `--auth-hmac-key` for authenticated sessions). Multi-API privacy modes (Tor Browser, Firefox `privacy.resistFingerprinting`, Brave Shields Aggressive) can score `4–6` and trigger **both** `strict` (`>= 2`) and `balanced` (`>= 4`) — use `--anti-stealth off` if those must pass. Open DevTools triggers V8 `--anti-cdp`.
- **3D `--mode gpu` vs. `--mode stream` & watermarks:** `--mode stream` keeps all geometry server-side and embeds a blind post-JPEG pixel watermark (requires uncropped, unscaled frame dimensions). `--mode gpu` preserves 60 FPS WebGL2, but multi-view capture can approximate rendered geometry (losing the raw pre-MVP `int32` lattice coordinates/vertex order required by `trace-shield-3d`, which is reference-assisted `O(1)`).

## Documentation

- [Beginner's Guide](docs/getting-started-beginners.md) — Local `ask` and `explain` recipes.
- [Vision & Benchmarks](docs/vision-and-benchmarks.md) — Design rationale and full comparison tables.
- [Websites & Web Components](docs/web-and-web-components.md) — `.vsweb` runtime, Shadow DOM, `--harden-js`, `--anti-cdp`, `--anti-stealth`.
- [3D Shield & Stream](docs/3d-shield-and-stream.md) — `--mode stream` vs. `--mode gpu` and 64-bit forensic tracing.
- [Native Binaries & SDKs](docs/native-binaries-and-sdks.md) — Repo auto-protection, static-PIE ELF64, and Rust/C/Go/Python SDKs.
- [Deployment & Proxies](docs/deployment-and-security-proxies.md) — RFC 9112 behavior, Nginx/Caddy configs, `--trust-proxy`.
- [CLI & Configuration](docs/cli-and-configuration.md) — Subcommands, presets, `vibeslayer.config.json`, environment variables.
- [Threat Model & Proofs](docs/threat-model-and-benchmarks.md) — Tier 1–4 adversary matrix, anti-stealth invariants, and caveats.

## Development

Prerequisites: Rust (`cargo`), `gcc` + GNU binutils (`readelf`, `objdump`, `strings`, `strip`), `Node.js >= 20`, `Go >= 1.21`, `openssl`, and Python `>= 3.10` (`cryptography`, `Pillow`, `tiktoken`) for the full polyglot/red-team test suite. Optional Windows `PE32+` cross-build (`make windows`) needs `x86_64-w64-mingw32-gcc` and `x86_64-pc-windows-gnu`.

```bash
make -C vibeslayer-native-core all          # Linux ELF64 CLI + C99 SDK (libvibeslayer.so)
cargo test --manifest-path vibeslayer-native-core/rust_core/Cargo.toml --release
make -C vibeslayer-native-core test         # Polyglot, 3D, red-team, and proxy tests
npm test --prefix vibeslayer-suite          # Requires ./vibe-slayer built above
npm test --prefix vibeslayer-policy-kit

# Reproduce multi-domain benchmarks (optional: npm --prefix benchmarks install)
python3 benchmarks/run_unbiased_benchmark.py
```

## Related Projects

- [ProxySnare](https://github.com/HUSMUS9999/proxysnare) — Middleware and CLI for detecting intercepting HTTP proxies and automated repeaters.
- [VeilBreak](https://github.com/HUSMUS9999/veilbreak) — Browser SDK, Shadow DOM Web Component, and proxy middleware for anti-detect browser detection across Chromium and Gecko.

## License

MIT — see [LICENSE](LICENSE).
