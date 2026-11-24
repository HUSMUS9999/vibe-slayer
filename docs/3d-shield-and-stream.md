# 3D Model Shield & Encrypted Zero-Geometry Stream

[← Back to README](../README.md) · [CLI & Configuration](./cli-and-configuration.md) · [Threat Model](./threat-model-and-benchmarks.md)

Standard 3D web viewers ship raw `.glb`/`.gltf` files directly into browser RAM and WebGL buffers, where a 10-line DevTools hook or Playwright script recovers the entire mesh, UVs, and PBR textures in seconds.

Vibe-Slayer provides **two interactive 3D delivery modes** from the exact same `shield-3d` cooked bundle:

1. **`--mode stream` (Default in `--preset paranoid`) — Zero-Geometry Encrypted Pixel Stream**:
   - **0 vertices, 0 indices, 0 UVs, 0 textures, 0 GLSL shaders, 0 WebGL contexts, and 0 projection matrices** ever reach the browser.
   - A multi-threaded pure-Rust software PBR rasterizer renders frames server-side, embeds an imperceptible **post-JPEG blind 64-bit forensic buyer watermark**, and encrypts each frame with per-session **ECDH P-256 + HKDF-SHA256 + AES-256-GCM** (`Content-Type: application/octet-stream`).
2. **`--mode gpu` (Default in `--preset balanced` and `--preset fast`) — Hardened WebGL2 Encrypted-Vertex Viewer**:
   - Runs at native 60 FPS on the client GPU while keeping geometry encrypted at rest (`model.vsshield`), injecting decoy chaff triangles (`20%`–`50%`), scrambling textures into per-session shuffled JPEG/PNG tile grids (`4×4`, `8×8`, `16×16`), hiding world-space matrices behind server-side camera step leases, and baking a **server-side 64-bit BPSK forensic buyer watermark** directly into the vertex stream so ripped geometry remains 100% traceable even if an attacker edits the shader.

---

## 1. Choosing Between `--mode stream` and `--mode gpu`

| Property | `--mode stream` (`paranoid` default) | `--mode gpu` (`balanced` / `fast` default) |
| :--- | :--- | :--- |
| **Mesh / UVs / Textures in Browser** | **Zero** (never leaves the server) | Encrypted + chaff + scrambled tiles (rendered in WebGL2) |
| **Wire Payload** | `application/octet-stream`: `seq(8) \|\| iv(12) \|\| AES-256-GCM(JPEG) \|\| tag(16)` | Encrypted vertex chunks + per-session scrambled tile atlases + ephemeral view uniforms |
| **Defense vs. WebGL / Transform-Feedback / RenderDoc / AI-Agent Mesh Ripping** | **Total** (`0` vertices exist on client) | High against casual/automated rippers; residual matrix/clip extraction mitigated by zero-normal-oracle + server-baked 64-bit watermark |
| **Defense vs. Photogrammetry / Multi-View 3DGS** | Compensated tilt-shift `(cx, cy)` + focal/lighting drift + single-in-flight frame serialization + session camera budget | Per-frame camera jitter + session camera budget + zero-normal-oracle |
| **Forensic Buyer Watermark** | Blind post-JPEG 64-bit Weber-Fechner pixel watermark (`trace-stream-frame`, `0.999+` conf) | Server-baked 64-bit BPSK vertex watermark (`trace-shield-3d`, `64/64` bits even if shader uniform deleted) |
| **Rendering Latency** | `~20–25 ms` RTT at `1280×820` on 53K-tri PBR mesh (`~40+` interactive FPS) | Native `60 FPS` client GPU |
| **Anti-CDP & Anti-CloakBrowser** | Yes (`--anti-cdp`, `--anti-stealth`, no WebGL required on client) | Yes (`--anti-cdp`, `--anti-stealth`) |

---

## 2. Step-by-Step Workflow

### Step 1: Cook the Protected 3D Bundle (`shield-3d`)

Store the `.vsshield.key` file **outside** the bundle output directory using `--key-file`:

```bash
./vibe-slayer shield-3d \
  --in ./assets/hero_character.glb \
  --out ./dist/hero_shielded \
  --key-file ./secrets/hero.vsshield.key \
  --preset paranoid
```

The command automatically verifies real-vertex accuracy (`maxClipSpaceError`) and chaff triangle clipping immediately after cooking and prints a JSON build report.

### Step 2: Serve in Zero-Geometry Encrypted Stream Mode (`paranoid`)

```bash
./vibe-slayer serve-3d ./dist/hero_shielded \
  --preset paranoid \
  --key-file ./secrets/hero.vsshield.key \
  --addr 127.0.0.1:8790 \
  --origin https://models.example.com \
  --stream-width 1280 \
  --stream-height 820 \
  --title "Hero Character — Protected Preview"
```

### Or Serve in Native 60 FPS Encrypted WebGL2 Mode (`balanced`)

```bash
./vibe-slayer serve-3d ./dist/hero_shielded \
  --preset balanced \
  --mode gpu \
  --anti-stealth strict \
  --key-file ./secrets/hero.vsshield.key \
  --addr 127.0.0.1:8790 \
  --origin https://models.example.com
```

### Optional: Require Per-Buyer Signed Authentication Tokens

With `--auth-hmac-key` (or `VIBESLAYER_AUTH_HMAC_KEY`), each viewer session derives its 64-bit forensic watermark deterministically from the authenticated `buyerId`:

```bash
export VIBESLAYER_AUTH_HMAC_KEY=$(openssl rand -hex 32)

./vibe-slayer serve-3d ./dist/hero_shielded \
  --preset paranoid \
  --key-file ./secrets/hero.vsshield.key \
  --origin https://models.example.com

# Mint a buyer-bound token
./vibe-slayer mint-token --key "$VIBESLAYER_AUTH_HMAC_KEY" --buyer "studio-client-42" --ttl 1800
```

---

## 3. Security Architecture Deep-Dive

### Encrypted Zero-Geometry Stream (`--mode stream`)

```mermaid
flowchart LR
    A["Browser Canvas2D (0 WebGL, 0 Geometry)"] -->|"1. ECDH P-256 + Ticket + Tier-4 Attest"| B["POST /__vibeslayer/stream-init"]
    B -->|"2. HKDF-SHA256 Session Key (non-extractable)"| A
    A -->|"3. POST /__vibeslayer/frame (yaw, pitch, zoom)"| C["Pure-Rust Multi-Threaded PBR Rasterizer"]
    C -->|"4. Compensated Tilt-Shift + Light Drift"| D["Weber-Fechner ±1/±2 64-Bit Blind Watermark"]
    D -->|"5. JPEG -> AES-256-GCM Envelope"| A
```

- **Encrypted Wire Protocol**: Every frame response uses `Content-Type: application/octet-stream` carrying `seq_be(8) || iv(12) || AES-256-GCM(jpeg_bytes) || tag(16)` with AAD bound to `(sessionId, seq, width, height)`. Network proxies and CDP `Fetch.enable` interceptors only see opaque ciphertext — never plaintext JPEGs.
- **Single-In-Flight Concurrency Guard**: Each session enforces strictly serialized frame rendering (1 in-flight request per session) so an automated scraper cannot fan out parallel multi-view orbit sweeps.
- **Anti-Photogrammetry Perturbation**: Subtle focal-length jitter, lighting drift, and compensated principal-point tilt-shift `(cx, cy)` preserve visual fidelity for human inspection while degrading automated Structure-from-Motion (COLMAP) and 3D Gaussian Splatting camera calibration.
- **Visually Invisible Post-JPEG Blind Watermark**: Embeds a 64-bit buyer ID directly in spatial luminance blocks with Weber-Fechner amplitude clamping (`±1` on dark pixels where `luma < 34`, `±1..±2` elsewhere) so frames remain visually clean while surviving JPEG compression with `>0.999` blind decode confidence.

### Encrypted WebGL2 Viewer (`--mode gpu`)
- **Multi-Stage GPU Vertex Cipher**: Vertices are encrypted into `model.vsshield` and decrypted inside the WebGL2 vertex shader across `16..=192` nonlinear stages (`--gpu-stages`) paired with `0..=75%` decoy chaff triangles (`--chaff-pct`) clipped out of NDC view.
- **Zero-Normal-Oracle Lighting**: Fragment shading uses screen-space derivatives (`dFdx`/`dFdy`) and tangent/normal decoupling without exposing raw object-space normal attributes as a linear camera-inversion oracle.
- **Per-Session Scrambled Tile Atlases**: Opaque PBR textures are JPEG-encoded (`--tex-format auto`) and alpha textures PNG-encoded, then permuted into a per-session `tileGrid × tileGrid` atlas (up to `16×16 = 256` shuffled tiles) unscrambled on the fly in the fragment shader via an ephemeral lookup table.
- **Server-Baked Watermark**: The 64-bit BPSK watermark is baked into vertex positions **on the server before encryption**, not merely added via a client shader uniform. Deleting or zeroing client uniforms cannot strip buyer attribution.

---

## 4. Forensic Leak Tracing

### Tracing a Leaked Stream Screenshot / Frame (`--mode stream`)

Convert any suspect PNG/JPEG screenshot back to raw 24-bit `RGB` bytes at the stream dimensions (`width × height × 3`) and run `trace-stream-frame`:

```bash
# Example: convert a captured PNG to raw RGB with Python/Pillow
python3 -c 'from PIL import Image; open("frame.rgb","wb").write(Image.open("leaked.png").convert("RGB").tobytes())'

./vibe-slayer trace-stream-frame \
  --dir ./dist/hero_shielded \
  --key-file ./secrets/hero.vsshield.key \
  --rgb ./frame.rgb \
  --width 1280 \
  --height 820
```

Output:
```json
{"ok":true,"decodedWm64Hex":"a4f19c28b703e511","meanConfidence":0.999394}
```

### Tracing Ripped WebGL2 Geometry (`--mode gpu`)

Pass captured world-space `int32` `(x, y, z)` vertex positions (12 bytes per vertex) to `trace-shield-3d`:

```bash
./vibe-slayer trace-shield-3d \
  --dir ./dist/hero_shielded \
  --key-file ./secrets/hero.vsshield.key \
  --ripped-wp ./ripped_positions.bin
```

### Tracing Offline Cooked `VS3D` Meshes (`protect` / `watermark`)

```bash
./vibe-slayer watermark ./my-repo-protected/assets/model.glb.vs3d \
  --buyer "alice@acme.com" \
  -o ./alice_positions.bin

./vibe-slayer trace ./alice_positions.bin
```

---

## 5. Measured Performance (52,965-Triangle Textured PBR Asset)

Benchmarked on the real **Luminous Warden** model (`52,965` triangles, `4096×4096` PBR textures):

| Metric | Measured Value |
| :--- | :--- |
| **`shield-3d` build (`--preset paranoid`)** | `0` plaintext glTF/PNG/JPEG headers; `maxClipSpaceError <= 1e-6` |
| **`serve-3d --mode stream` (`1280×820`, AES-256-GCM)** | **`23.7 ms`** end-to-end render + watermark + JPEG + AES-GCM RTT |
| **Post-JPEG blind 64-bit watermark confidence** | **`0.999394`** (`64/64` bits exact match, visually spotless) |
| **Client-exposed geometry / shaders / WebGL contexts (`stream`)** | **`0`** |
| **CloakBrowser 146 blocked (`strict` & `balanced`)** | **`100%`** (`0` handshakes, `STEALTH_BROWSER_DENIED`) |
