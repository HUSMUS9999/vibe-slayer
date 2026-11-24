# `vibeslayer-suite` (`v0.8.0-beta.2`)

[← Root README](../README.md) · [Web & Web Components Guide](../docs/web-and-web-components.md) · [Threat Model](../docs/threat-model-and-benchmarks.md)

End-to-end multi-platform protection suite for **client-downloaded assets & local native-speed execution** across **7 product targets**, plus a unified CLI (`cli/vs.js`), programmatic policy/lease authority (`src/index.js`), and Tier-4 **`antiStealth`** CloakBrowser denial for Web Components (`webProduct.createBrowserEphemeralSession`, `unsealWebAssetWithSession`, `collectStealthAttestation`, `verifyStealthAttestation`).

---

## 1. How Client-Downloaded Assets Stay Smooth (`0` Frame Overhead) Without Being Stolen or Re-Hosted

1. **Offline / CDN / Bundle / APK / ASAR Theft -> Standard 256-Bit AEAD (`AES-256-GCM` & `RFC 8439 ChaCha20-Poly1305`)**:
   - Every shipped client file (`.vspk`, `.vs3d.vspk`, `.vsasar`, `.vsmb`, `.vsra`, ELF `.vsblob`) contains **zero key material** and **zero plaintext headers/tails** (`0` `\0asm` bytes, `0` `glTF` strings).
   - Static scraping or offline AI reverse engineering of the downloaded bundle recovers **0 plaintext bytes**.
2. **"Only Run As Supposed To Run" -> Ephemeral Non-Extractable Keys & Cryptographic Environment Binding**:
   - **Web / WASM / 3D (`src/client/*.js`)**: Generates an ephemeral `ECDH P-256` keypair inside WebCrypto with **`extractable: false`**, derives a non-extractable `HKDF-SHA256` -> `AES-GCM` `unwrapKey` key, and unwraps the content key directly into a non-extractable `CryptoKey` (`extractable: false`) bound via `AAD` to `(product, assetId, origin)`.
   - **Native Binary (`vs_protected_elf`)**: Hashes its own live mapped `PF_X` executable code segment in RAM (`__ehdr_start`) into `HKDF-SHA256` before `ChaCha20-Poly1305` authentication (`0` `if (debugged)` branches to NOP out; patching 1 byte of `.text` or placing a `0xCC` breakpoint fails MAC with `rc=3`), sets `prctl(PR_SET_DUMPABLE, 0)`, and maps secrets with `MADV_DONTDUMP`.
   - **Desktop (`vs_desktop_enclave` + `vs_desktop_enclave_win64.exe`)**: Verifies `Ed25519` bundle signatures and runs sensitive rules inside an out-of-process native C sidecar (`PR_SET_DUMPABLE=0`) so Electron/Tauri Renderer DevTools (`Ctrl+Shift+I`) never holds master secrets.
   - **Mobile (`libvsmobile.so`)**: Compiled JNI/C shared library binding `ChaCha20-Poly1305` asset decryption via `HKDF-SHA256` to `(packageName, runtimeApkSigningCertSha256, assetId)`—repackaged APKs fail with `MOBILE_AUTH_TAG_FAILED` (`rc=2`).
3. **Live Authorized-Session Extraction Mitigation -> Cooked Runtime Streams + 64-Bit Traitor Watermarking**:
   - Any asset rendered locally exists in that authorized device's RAM/VRAM while active. To prevent clean re-authoring and trace leaks:
     * **3D Spatial (`spatial3dProduct`)**: Strips all scene/node/mesh/material names, bakes `int16` SNORM GPU buffers (`VS3D`), and embeds an imperceptible **1,024-chip spread-spectrum $\pm 1\text{ LSB}$ watermark** (`100%` `1024/1024` bit attribution back to the leaking `leaseId`/account).
     * **Data & AI (`dataAiProduct`)**: `64 KiB` `O(1)` random-access `ChaCha20-Poly1305` tensor chunks (`VSRA`) + `±2e-6` FP32 spread-spectrum tensor watermark (`100%` leaker attribution, `0` inference loop ops).

## 2. Measured Footprint & Unseal Latency (`vibeslayer-suite v0.8.0-beta.2`)

Measured across all 7 exported product modules from `vibeslayer-suite` (`src/index.js`) on identical raw unprotected inputs (`npm run bench --prefix vibeslayer-suite`). For head-to-head comparisons against public tools (`esbuild`, `terser`, `javascript-obfuscator`, `js-confuser`, `strip`, `UPX`, `OpenSSL`), see [`../benchmarks/results.json`](../benchmarks/results.json) and [Vision & Benchmarks](../docs/vision-and-benchmarks.md).

| Product Module (`src/index.js`) | Raw Size | Sealed Output & Measured Latency | Security Properties |
| :--- | ---: | :--- | :--- |
| **1. Web (`webProduct`)** | `116 B` | **`233 B` (`2.01×`)** · `2.46 ms` cold unseal | `AES-256-GCM` + non-extractable WebCrypto `ECDH P-256` |
| **2. WASM (`wasmProduct`)** | `100 B` | **`220 B` (`2.20×`)** · `0.97 ms` unseal+instantiate | `\0asm` header hidden (`false`); ABI preserved by default |
| **3. 3D Spatial (`spatial3dProduct`)** | `581,260 B` | **`749,679 B` (`1.29×`)** · `4.71 ms` unseal | `0` raw chunks exposed (`7.9998` bits/B); `0` frame ops; 1024-chip watermark |
| **4. Native Binary (`nativeProduct`)** | `15,992 B` | **`25,656 B` (`1.60×`)** · `2.01 ms` cold start | `.rodata` encrypted (`7.94` bits/B `.vsblob`); live `.text` SHA-256 + `PR_SET_DUMPABLE=0` |
| **5. Desktop (`desktopProduct`)** | `67 B` rules | **`649 B` `.vsasar`** · `0.095 ms` IPC | `Ed25519`-signed bundle + native out-of-process enclave sidecar (`PR_SET_DUMPABLE=0`) |
| **6. Mobile (`mobileProduct`)** | `44 B` shader | **`24,056 B` `libvsmobile.so`** + `143 B` `.vsmb` · `1.30 ms` | APK signing-cert HKDF + `ChaCha20-Poly1305` binding |
| **7. Data & AI (`dataAiProduct`)** | `262,231 B` | **`262,303 B` (`1.0003×`, `+72 B`)** · `1.45 ms` chunk unseal | Real `O(1)` 64 KiB random-access `VSRA` `ChaCha20-Poly1305` chunks; raw FP32 hidden |

## 3. Verification & Isolation Checks

- Pure client loaders are separated into `src/client/*.js` with CSPRNG-padded `.vsblob` outputs so build-time packers never leak into client-shipped files.
- Automated verification confirms `0` `\0asm` magic hits, `0` `glTF` header hits, and `0` embedded keys across sealed outputs in all 7 product targets.

## 4. Build, Test & Benchmark Commands

```bash
npm run build:native --prefix vibeslayer-suite
npm run coverage --prefix vibeslayer-suite
npm run bench --prefix vibeslayer-suite
```
