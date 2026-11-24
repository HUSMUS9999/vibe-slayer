# CLI Reference & Configuration

[← Back to README](../README.md)

`vibe-slayer` is a standalone, zero-dependency Rust binary (zero external crates, zero Node.js runtime). Every build and runtime command supports **one-flag security presets** (`--preset fast | balanced | paranoid`), **human-editable JSON config files** (`--config vibeslayer.config.json`), **environment variables**, and **per-flag CLI overrides** with strict fail-closed validation.

---

## Configuration Precedence

Settings resolve deterministically in the following order (highest priority first):

```text
1. Explicit CLI flags       (--anti-stealth strict, --mode stream, ...)
2. --config <file.json>     (section-specific key, falling back to root key)
3. Environment variables    (VIBESLAYER_PRESET, VIBESLAYER_ORIGIN, ...)
4. --preset defaults        (fast | balanced | paranoid; defaults to balanced)
```

### Supported Environment Variables

| Environment Variable | Applies To | Description |
| :--- | :--- | :--- |
| `VIBESLAYER_PRESET` | `website`, `serve`, `shield-3d`, `serve-3d` | Default preset (`fast`, `balanced`, `paranoid`) when `--preset` and `config.preset` are unset |
| `VIBESLAYER_KEY_FILE` | `shield-3d`, `serve-3d` | Path to the 32-byte `.vsshield.key` file stored outside the webroot |
| `VIBESLAYER_ORIGIN` | `serve`, `serve-3d` | Strict `Origin` allow-list target (e.g. `https://app.example.com`) |
| `VIBESLAYER_AUTH_SECRET` | `serve`, `serve-3d` | Static shared bearer/header secret for gating leases |
| `VIBESLAYER_AUTH_HMAC_KEY` | `serve`, `serve-3d` | 64-hex-char (32-byte) HMAC-SHA256 signing key for per-buyer tokens minted via `mint-token` |
| `VIBESLAYER_TRUST_PROXY` | `serve`, `serve-3d` | Comma-separated trusted reverse-proxy IPs (e.g. `127.0.0.1,10.0.0.2`) enabling `X-Forwarded-For` and `X-Forwarded-Host` |

---

## Security Presets at a Glance

| Parameter | `--preset fast` | `--preset balanced` (default) | `--preset paranoid` |
| :--- | :--- | :--- | :--- |
| **Aliases** | `dev`, `light` | `default`, `standard` | `max`, `strict`, `hardened` |
| **Website: `--harden-js`** | `off` | `off` | `on` (`rtKey` offline-dead strings) |
| **Website: `--min-str-len`** | `6` | `4` | `3` |
| **Website: `--js-bloat-kb`** | `0` KB | `0` KB | `96` KB (~48K+ LLM decoy tokens/file) |
| **Website / 3D: `--anti-hook`** | `off` | `on` | `on` |
| **Website / 3D: `--anti-cdp`** | `off` | `on` | `on` |
| **Website / 3D: `--anti-stealth`** | `off` | `balanced` (score ≥ 4) | `strict` (score ≥ 2 + server SHA-256 attest + headless UA block) |
| **Website / 3D: `--csp`** | `relaxed` | `strict` | `strict` |
| **3D Build: `--gpu-stages` / `--chaff-pct`** | `32` / `20%` | `96` / `37.5%` | `128` / `50%` |
| **3D Build: `--tile-grid` / `--tex-quality`** | `8` / `85` | `16` / `90` | `16` / `92` |
| **3D Serve: `--mode`** | `gpu` (WebGL2) | `gpu` (WebGL2) | `stream` (Zero-Geometry AES-256-GCM frames) |
| **3D Serve: `--stream-width` × `--stream-height`** | `800×540` (q `80`) | `960×640` (q `84`) | `960×640` (q `86`) |
| **3D Serve: `--wm-strength` / `--camera-jitter`** | `1.0` / `0.5` | `1.2` / `1.0` | `1.8` / `1.5` |
| **Runtime: `--ticket-ttl` / `--session-ttl`** | `60s` / `1800s` | `30s` / `600s` | `20s` / `180s` |
| **Runtime: `--max-leases-per-min` / `--max-conns-per-ip`** | `180` / `64` | `60` / `32` | `30` / `16` |
| **Runtime: `--header-timeout-ms` / `--body-timeout-ms`** | `5000` / `8000` | `3000` / `5000` | `2000` / `4000` |

---

## Generating & Editing `vibeslayer.config.json`

Generate a ready-to-edit config file for any preset with `init-config`:

```bash
./vibe-slayer init-config --preset paranoid -o vibeslayer.config.json
```

All four top-level sections (`shield3d`, `serve3d`, `website`, `serve`) can live in one shared config file:

```json
{
  "preset": "paranoid",
  "shield3d": {
    "gpuStages": 128,
    "chaffPercent": 50,
    "maxTexDim": 4096,
    "tileGrid": 16,
    "pngMode": "optimal",
    "texFormat": "auto",
    "texQuality": 92,
    "keyFile": null
  },
  "serve3d": {
    "renderMode": "stream",
    "streamWidth": 960,
    "streamHeight": 640,
    "streamQuality": 86,
    "addr": "127.0.0.1:8790",
    "origin": null,
    "title": null,
    "watermark": true,
    "watermarkStrength": 1.8,
    "antiHook": true,
    "antiCdp": true,
    "antiStealth": "strict",
    "cspMode": "strict",
    "cameraJitter": 1.5,
    "ticketTtlSec": 20,
    "sessionTtlSec": 180,
    "cameraBudget": 4000,
    "assetBudget": 12,
    "maxLeasesPerMin": 30,
    "maxSessions": 2048,
    "maxConnsPerIp": 16,
    "maxTexConcurrency": 2,
    "headerTimeoutMs": 2000,
    "bodyTimeoutMs": 4000,
    "workers": 0,
    "trustProxy": null
  },
  "website": {
    "hardenJs": true,
    "minStrLen": 3,
    "jsBloatKb": 96,
    "antiHook": true,
    "antiCdp": true,
    "antiStealth": "strict",
    "title": "Protected by Vibe-Slayer"
  },
  "serve": {
    "addr": "127.0.0.1:8080",
    "origin": null,
    "cspMode": "strict",
    "antiStealth": "strict",
    "ticketTtlSec": 20,
    "maxLeasesPerMin": 30,
    "maxConnsPerIp": 16,
    "headerTimeoutMs": 2000,
    "bodyTimeoutMs": 4000,
    "workers": 0,
    "trustProxy": null
  }
}
```

Pass the config file to any command and optionally override individual flags on the command line:

```bash
./vibe-slayer website ./dist -o ./dist-protected --config vibeslayer.config.json --js-bloat-kb 64
./vibe-slayer serve ./dist-protected --config vibeslayer.config.json --origin https://app.example.com
```

---

## Subcommand Reference

### 0. Plain-English Natural-Language Commands (Beginners)

Translate everyday English requests into exact, verified `vibe-slayer` commands (100% local in Rust, zero API keys):

| Command | Usage | Purpose |
| :--- | :--- | :--- |
| **`ask`** / **`do`** / **`nl`** | `./vibe-slayer ask "<plain English>" [--dry-run] [--json]` | Prints the translated command + plain-English explanation of each option, then executes it |
| **`explain`** | `./vibe-slayer explain "<plain English>" [--json]` | Always dry-run: previews the exact command, rationale, and follow-up step without modifying files |

See the **[Beginner's Guide](./getting-started-beginners.md)** for copy-paste examples.

### 1. High-Level Repository & File Auto-Protection

| Command | Usage | Purpose |
| :--- | :--- | :--- |
| **`demo`** | `./vibe-slayer demo [--json]` | Creates a sample repo, protects it, verifies outputs, executes wrapped ELF, watermarks & traces a 3D leak, and restores files |
| **`scan`** | `./vibe-slayer scan <target> [--json]` | Dry-run classification and secret scanner (AWS, OpenAI, GitHub, Google, private keys, `.env`) |
| **`protect`** / **`auto`** | `./vibe-slayer <target> [-o <out>] [--standalone] [--seal-all] [--vault] [--no-gitignore] [--keys <path>] [--registry <path>] [--json]` | Auto-protects a file or repository and immediately runs cryptographic self-verification |
| **`test`** | `./vibe-slayer test <protected-target> [--keys <path>] [--registry <path>] [--json]` | Runs entropy, tamper rejection, wrong-key, ELF anti-debug/CET, and lossless unseal checks |
| **`run`** | `./vibe-slayer run <protected-elf> [--keys <path>] [-- args...]` | Executes a protected ELF binary by injecting its lease key over private FD 3 (with `LD_PRELOAD` scrubbed) |
| **`unseal`** | `./vibe-slayer unseal <protected-target> [-o <dest>] [--keys <path>] [--registry <path>] [--json]` | Losslessly restores encrypted files and verifies original SHA-256 digests |
| **`watermark`** | `./vibe-slayer watermark <model.vs3d> [--buyer <id> \| --id <16hex>] [-o <pos.bin>] [--json]` | Embeds a 64-bit BPSK spread-spectrum `WM64` watermark into cooked `VS3D` vertex positions |
| **`trace`** | `./vibe-slayer trace <positions.bin> [--model <file.vs3d>] [--json]` | Decodes a `WM64` watermark back to the leaking buyer ID (`O(1)` correlation, survives `±2` LSB noise) |

### 2. Live Website & Web Components Protection

#### `website`

```bash
./vibe-slayer website <site-dir> [-o <out-dir>] [options]
```

| Flag | Config Key (`website.*`) | Valid Values / Range | Description |
| :--- | :--- | :--- | :--- |
| `--preset` | `preset` | `fast`, `balanced`, `paranoid` | Base preset |
| `--config` | — | File path | Load JSON configuration |
| `--origin` | — | Origin URL | Bind default expected `Origin` in metadata |
| `--harden-js` / `--no-harden-js` | `hardenJs` | boolean | Enable/disable `rtKey`-masked string tables, decoy VM, and inline Web Component anti-stealth guard |
| `--min-str-len` | `minStrLen` | `2..=64` | Minimum JS string literal length to encrypt when `--harden-js` is enabled |
| `--js-bloat-kb` | `jsBloatKb` | `0..=512` | Polymorphic unreachable decoy state-machine size (KB) appended per hardened JS/MJS file |
| `--anti-hook` | `antiHook` | `on` \| `off` | Native WebCrypto prototype tampering check in boot loader |
| `--anti-cdp` | `antiCdp` | `on` \| `off` | Block `navigator.webdriver` and active CDP `Runtime.enable` / DevTools consoles before leasing |
| `--anti-stealth` | `antiStealth` | `off` \| `balanced` \| `strict` | Tier-4 anti-CloakBrowser physics probes in loader (protects all Web Components pre-lease); when `--harden-js` is also enabled, embeds an inline synchronous self-defense guard inside every `.js`/`.mjs` Web Component |
| `--title` | `title` | string (HTML-escaped) | Bootstrap `<title>` displayed prior to decryption |
| `--keys`, `--registry`, `--no-gitignore`, `--json` | — | path / flag | Vault/registry location, `.gitignore` toggle, JSON output |

#### `serve`

```bash
./vibe-slayer serve <protected-site-dir> [options]
```

| Flag | Config Key (`serve.*`) | Valid Values / Range | Description |
| :--- | :--- | :--- | :--- |
| `--preset` / `--config` | `preset` | `fast`, `balanced`, `paranoid` | Base preset and/or JSON config file |
| `--addr` | `addr` | `host:port` (default `127.0.0.1:8080`) | Bind address |
| `--origin` | `origin` | `https://...` | Strict allowed `Origin` header |
| `--auth-secret` | `authSecret` | string | Shared secret checked via `Authorization: Bearer` / `X-VS-Auth` / `vs_auth` cookie |
| `--auth-hmac-key` | `authHmacKey` | 64 hex chars | Verify per-buyer signed tokens minted by `mint-token` |
| `--trust-proxy` | `trustProxy` | `ip1,ip2` | Trust `X-Forwarded-For` and `X-Forwarded-Host` only from these peer IPs |
| `--csp` | `cspMode` | `strict`, `relaxed`, `off` | `Content-Security-Policy` header profile |
| `--anti-stealth` | `antiStealth` | `off`, `balanced`, `strict` | Enforce server-side OS-header consistency, headless UA denial (`strict`), and SHA-256 hardware attestation |
| `--ticket-ttl` | `ticketTtlSec` | `5..=300` | Single-use HMAC ticket lifetime in seconds |
| `--max-leases-per-min` | `maxLeasesPerMin` | `1..=100000000` | Per-IP lease rate limit per 60-second window |
| `--max-conns-per-ip` | `maxConnsPerIp` | `2..=1024` | Concurrent TCP connections allowed per client IP |
| `--header-timeout-ms` | `headerTimeoutMs` | `500..=30000` | Slowloris HTTP header read timeout |
| `--body-timeout-ms` | `bodyTimeoutMs` | `500..=60000` | HTTP request body read timeout |
| `--workers` | `workers` | `0` (auto) or `4..=128` | HTTP worker thread pool size (`0` = `clamp(cores * 4, 32, 64)`) |

### 3. 3D Shield & Encrypted Stream Commands

#### `shield-3d`

```bash
./vibe-slayer shield-3d --in <model.glb> --out <out-dir> [options]
```

| Flag | Config Key (`shield3d.*`) | Valid Values / Range | Description |
| :--- | :--- | :--- | :--- |
| `--in` (or positional) | — | `.glb` path | Input glTF 2.0 binary model |
| `--out` / `-o` | — | directory | Output bundle directory (default `<in>.shielded`) |
| `--asset-id` | — | string | Asset identifier (default file stem) |
| `--key` | — | 64 hex chars | Explicit 32-byte master key (otherwise CSPRNG-generated) |
| `--key-file` | `keyFile` | file path | Store `.vsshield.key` (`0600`) outside the served bundle directory |
| `--gpu-stages` | `gpuStages` | `16..=192` | Nonlinear GPU vertex cipher stages for `--mode gpu` |
| `--chaff-pct` | `chaffPercent` | `0..=75` | Decoy triangle ratio injected into encrypted geometry |
| `--max-tex-dim` | `maxTexDim` | `256..=8192` | Maximum texture dimension during cooking |
| `--tile-grid` | `tileGrid` | `0`, `4`, `8`, `16` | Scrambled texture tile grid (`0` disables tiling) |
| `--png-mode` | `pngMode` | `fast`, `optimal` | PNG compression effort for alpha/lossless textures |
| `--tex-format` | `texFormat` | `auto`, `jpeg`, `png` | Texture encoding (`auto` uses JPEG for opaque, PNG for alpha) |
| `--tex-quality` | `texQuality` | `50..=98` | JPEG quality for scrambled opaque textures |

#### `serve-3d`

```bash
./vibe-slayer serve-3d <shielded-dir> [options]
```

Supports the shared HTTP/security runtime flags (`--preset`, `--config`, `--addr` [default `127.0.0.1:8790`], `--origin`, `--auth-secret`, `--auth-hmac-key`, `--trust-proxy`, `--csp`, `--anti-stealth`, `--ticket-ttl`, `--max-leases-per-min`, `--max-conns-per-ip`, `--header-timeout-ms`, `--body-timeout-ms`, `--workers`) plus the following 3D-specific options:

| Flag | Config Key (`serve3d.*`) | Valid Values / Range | Description |
| :--- | :--- | :--- | :--- |
| `--mode` | `renderMode` | `gpu`, `stream` | `gpu`: WebGL2 encrypted-vertex viewer; `stream`: Zero-Geometry server-rasterized AES-256-GCM pixel stream |
| `--stream-width` | `streamWidth` | `320..=1920` | Stream frame width in pixels |
| `--stream-height` | `streamHeight` | `240..=1080` | Stream frame height in pixels |
| `--stream-quality` | `streamQuality` | `50..=96` | Stream JPEG quality before AES-256-GCM frame encryption |
| `--key-file` | `keyFile` | file path | External `.vsshield.key` path (replaces `--keys`/`--registry` used by `serve`) |
| `--title` | `title` | string | Viewer page title (HTML-escaped) |
| `--watermark` | `watermark` | `on` \| `off` | Enable per-buyer 64-bit forensic watermarking |
| `--wm-strength` | `watermarkStrength` | `0.0..=5.0` | Watermark amplitude multiplier |
| `--anti-hook` | `antiHook` | `on` \| `off` | Prototype/WebGL hook detection |
| `--anti-cdp` | `antiCdp` | `on` \| `off` | Block `navigator.webdriver` and CDP `Runtime.enable` |
| `--camera-jitter` | `cameraJitter` | `0.0..=3.0` | Anti-photogrammetry view/focal perturbation scale |
| `--session-ttl` | `sessionTtlSec` | `30..=86400` | Session lease TTL in seconds |
| `--camera-budget` | `cameraBudget` | `100..=1000000` | Maximum camera/frame updates per session |
| `--asset-budget` | `assetBudget` | `6..=1000` | Maximum protected asset fetches per session |
| `--max-sessions` | `maxSessions` | `16..=65536` | Global active session cap |
| `--max-tex-concurrency` | `maxTexConcurrency` | `1..=32` | Max concurrent server-side texture scramblers |

#### Forensic Tracing & Token Minting

```bash
# Mint a per-buyer HMAC-SHA256 signed access token
# Note: --buyer accepts 1..=128 ASCII alphanumeric or [-_@:] characters (no '.' dots)
./vibe-slayer mint-token --key <64-hex-hmac-key> --buyer "alice@acme" --ttl 3600

# Trace a 64-bit buyer ID from ripped WebGL2 int32 world positions (12 bytes/vertex)
./vibe-slayer trace-shield-3d --dir <shielded-dir> [--key-file <key>] --ripped-wp <wp.bin>

# Blind-trace a 64-bit buyer ID from a captured 2D RGB stream frame (3 bytes/pixel)
./vibe-slayer trace-stream-frame --dir <shielded-dir> [--key-file <key>] --rgb <frame.rgb> --width 960 --height 640
```

### 4. Low-Level Cryptographic & Binary Primitives

| Command | Purpose |
| :--- | :--- |
| `pack` / `unseal` | Pack or unseal `VSPK2` containers (`HKDF-SHA256` + `ChaCha20-Poly1305`) |
| `pack-v3` / `unseal-v3` | Pack or unseal headerless key-committing `VSPK3` (`CMT4` + `1024 B` padding) |
| `cook-glb` / `unseal-glb-lease` / `trace-glb` | Low-level `VS3D` cooking and 1,024-chip watermark tracing |
| `embed-wm64` / `decode-wm64` | Low-level 64-bit `O(1)` BPSK coordinate watermarking |
| `build-elf` / `build-elf-elite` / `build-elf-freestanding` / `wrap-elf` | Build hardened Linux x86-64 static-PIE ELF64 vaults and executable wrappers |
| `homo-keygen` / `homo-encrypt` / `homo-eval` / `homo-decrypt` | Additively homomorphic integer computation over ciphertexts (no secret key on evaluator) |
| `version` | Print binary version JSON (`{"version":"1.0.0-beta.3"}`) |
