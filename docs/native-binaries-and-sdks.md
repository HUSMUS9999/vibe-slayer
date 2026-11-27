# Native Binaries, Repository Auto-Protection & Polyglot SDKs

[← Back to README](../README.md) · [Beginner's Guide](./getting-started-beginners.md) · [Web & Web Components](./web-and-web-components.md) · [CLI & Configuration](./cli-and-configuration.md) · [Threat Model](./threat-model-and-benchmarks.md)

Beyond live websites and 3D streams, Vibe-Slayer protects entire source repositories, `.env` secrets, compiled Linux x86-64 `ELF64` binaries (requires host `gcc` + `libc6-dev` at protection time), WebAssembly modules, and AI weights — and ships **wire-compatible `VSPK2` / `VSPK3` native SDKs** across **Rust, C/C++, Go, Python**, plus companion **Node.js** packages (`vibeslayer-suite` including `O(1)` 64 KiB chunked `.vsra` AI weights, and `vibeslayer-policy-kit`).

---

## 1. Repository & File Auto-Protection

Point `./vibe-slayer` at any directory or individual file:

```bash
# Audit first (dry run: shows file classifications & redacted credential warnings)
./vibe-slayer scan ./my-repo

# Protect an entire repository -> outputs ./my-repo-protected + 0600 keys vault
./vibe-slayer ./my-repo

# Encrypt even public scaffold files (README.md, CSS, images)
./vibe-slayer ./my-repo --seal-all

# Protect a single source file or compiled Linux ELF64 executable
./vibe-slayer ./app.py                 # -> ./app.py.vspk3
./vibe-slayer ./my_program             # -> ./my_program.protected (lease-bound)
./vibe-slayer ./my_program --standalone # -> ./my_program.protected (runs directly)

# Verify integrity & restore losslessly
./vibe-slayer test ./my-repo-protected
./vibe-slayer unseal ./my-repo-protected -o ./my-repo-restored
```

### Automatic Engine Routing

| Input Type | Output / Engine | Cryptographic & Runtime Properties |
| :--- | :--- | :--- |
| **Source Code, Configs, `.wasm`, AI Weights** (`.py`, `.rs`, `.go`, `.c`, `.cpp`, `.js`, `.ts`, `.java`, `.cs`, `.wasm`, `.safetensors`, `.onnx`, `.gguf`, `.pt`, `.ckpt`) | `VSPK3` (`.vspk3`) | Whole-file headerless key-committing AEAD (`HKDF-SHA256` + `HMAC-SHA256` `CMT4` + `ChaCha20-Poly1305`), `1024 B` pad-then-encrypt, no plaintext magic bytes, `>= 7.0` bits/B entropy *(for `O(1)` 64 KiB random-access chunked AI weights, use `.vsra` in `vibeslayer-suite`)* |
| **Compiled Linux `ELF64` Executables** (excluding `.so`/`.node`/`.o`/`.a`) | `wrap-elf` (`.protected`) | Freestanding `-nostdlib` static-PIE wrapper stub (no `PT_INTERP`/`DT_NEEDED`, Intel CET `IBT` + `SHSTK`), scrubs all `LD_*` (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, etc.) + `GCONV_PATH`/`LOCPATH`/`HOSTALIASES`/`VS_LEASE_FD`, blocks pre-exec `ptrace` (`TracerPid` + `PR_SET_DUMPABLE=0`), hashes non-writable `PT_LOAD` segment, executes from sealed `memfd_create` via `SYS_execveat(AT_EMPTY_PATH)` *(note: Linux resets `PR_SET_DUMPABLE` on `execveat`; call `vs_harden_process()` inside the inner binary if post-exec dump hardening is needed)* |
| **Small Secrets (`<= 4096 B`)** (`.vault`, `.secret`, or `--vault`) | `freestanding-vault` | Static-PIE ELF data vault allocating decrypted payload inside kernel `SYS_memfd_secret(0)` (with `MADV_DONTDUMP` + `mlock` fallback) |
| **3D Models (`.glb`)** | Dual `VSPK3` + keyed `VS3D` | Lossless `.glb.vspk3` for exact SHA-256 restoration + keyed `.glb.vs3d` coordinate stream supporting `WM64` 64-bit spread-spectrum watermarking (use `shield-3d` for full glTF 2.0 web/stream rendering) |
| **Secrets & Private Keys** (`.env`, `.pem`, `.key`, `.p12`, `.pfx`, or detected credentials) | `VSPK3` (`.vspk3`) | Automatically forced into encryption even if filename looks public; vault keys stored in `<project>/.vibeslayer/keys.json` (`0600`) and auto-added to `.gitignore` |

### Executing Protected Linux Binaries

```bash
# Lease-bound binary (master/lease key stays out of the executable, passed via private FD 3 pipe)
./vibe-slayer run ./my_program.protected -- --port 9000

# Standalone binary (compiled with --standalone; self-contained wrapper — key is derived inside the binary, so treat --standalone as obfuscated deterrence rather than external-key encryption)
./my_program.protected --port 9000
```

---

## 2. Wire-Compatible Container Formats (`VSPK2` & `VSPK3`)

All four native SDKs (`Rust`, `C/C++`, `Go`, `Python`) interoperate over the exact same binary wire formats:

- **`VSPK2`**: Self-describing domain/asset/context header + `HKDF-SHA256` per-asset key derivation + `RFC 8439 ChaCha20-Poly1305` AEAD.
- **`VSPK3`**: Headerless `92 B` prefix (`salt(32) || nonce(12) || CMT4_HMAC(32) || Poly1305_tag(16)`) + `1024 B`-padded ciphertext. Omits plaintext magic bytes and metadata on disk; verifies key-committing `CMT4` in constant time before decrypting.

Pack an asset once from the CLI and unseal it in any language:

```bash
KEY_HEX=$(openssl rand -hex 32)
./vibe-slayer pack-v3 \
  --key "$KEY_HEX" \
  --domain "billing" \
  --asset-id "pricing-rules-v1" \
  --context "prod-eu" \
  --in ./rules.json \
  --out ./rules.vspk3
```

---

## 3. Native SDK Usage Examples

### C / C++ (`vibeslayer-native-core/sdk_c/vibeslayer.h`)

Build the shared library with `make -C vibeslayer-native-core all` and link against `vibeslayer-native-core/bin/libvibeslayer.so` (Linux) or `bin/vibeslayer.dll` (Windows):

```bash
gcc -O2 my_app.c -Ivibeslayer-native-core/sdk_c -Lvibeslayer-native-core/bin -lvibeslayer -Wl,-rpath,'$ORIGIN/vibeslayer-native-core/bin' -o my_app
```

```c
#include <stdio.h>
#include <stdint.h>
#include "vibeslayer.h"

int load_rules(const uint8_t master_key[32], const uint8_t *vspk3, size_t vspk3_len) {
    /* Sets PR_SET_DUMPABLE=0 on Linux to harden against core dumps / ptrace */
    vs_harden_process();

    uint8_t plain[4096];
    int n = vs_unseal_vspk3(
        master_key,
        "billing",          /* expected_domain */
        "pricing-rules-v1", /* asset_id */
        "prod-eu",          /* expected_context */
        vspk3,
        vspk3_len,
        plain,
        sizeof(plain)
    );
    if (n < 0) {
        /* VS_ERR_AUTH (-1) on any auth, commitment, padding, or bounds failure */
        return n;
    }
    /* Use plain[0..n], then zeroize before returning */
    return n;
}
```

Available C exports:
- `int vs_harden_process(void)`
- `int vs_unseal_vspk2(master_key32, expected_domain, expected_context, vspk_bytes, vspk_len, plain_out, plain_cap)`
- `int vs_unseal_vspk2_for_asset(master_key32, expected_domain, expected_asset_id, expected_context, vspk_bytes, vspk_len, plain_out, plain_cap)`
- `int vs_unseal_vspk3(master_key32, expected_domain, asset_id, expected_context, vspk_bytes, vspk_len, plain_out, plain_cap)`

### Python (`vibeslayer-native-core/sdk_python/vibeslayer.py`)

Backed directly by compiled `../bin/libvibeslayer.so` via Python's standard-library `ctypes` (build first with `make -C vibeslayer-native-core all` and run with `PYTHONPATH=vibeslayer-native-core/sdk_python`):

```python
from pathlib import Path
from vibeslayer import ActionRule, ParamSpec, Policy

policy = Policy(
    master_key_hex=KEY_HEX,
    enabled=True,  # Fail-closed default is False
    actions={
        "billing.load": ActionRule(
            domain="billing",
            context="prod-eu",
            params={
                "seats": ParamSpec(kind="int", min_val=1, max_val=1000),
                "tier": ParamSpec(kind="enum", values=["pro", "enterprise"]),
            },
        )
    },
)

try:
    vspk3_bytes = Path("rules.vspk3").read_bytes()
    plaintext = policy.unseal_action_vspk3(
        action="billing.load",
        params={"seats": 25, "tier": "enterprise"},
        asset_id="pricing-rules-v1",
        vspk_bytes=vspk3_bytes,
    )
finally:
    policy.zeroize()
```

### Go (`vibeslayer-native-core/sdk_go/vibeslayer.go`)

Pure Go standard library implementation (no `cgo` required):

```go
policy := &vibeslayer.Policy{
    Enabled:   true,
    MasterKey: masterKey32,
    Actions: map[string]vibeslayer.ActionRule{
        "billing.load": {
            Domain:  "billing",
            Context: "prod-eu",
            AssetID: "pricing-rules-v1",
            Params: map[string]vibeslayer.ParamRule{
                "seats": {Kind: vibeslayer.ParamInt, Min: 1, Max: 1000},
                "tier":  {Kind: vibeslayer.ParamEnum, Values: []string{"pro", "enterprise"}},
            },
        },
    },
}

plain, err := policy.UnsealActionVspk3(
    "billing.load",
    map[string]any{"seats": int64(25), "tier": "enterprise"},
    "pricing-rules-v1",
    vspk3Bytes,
)
```

### Rust (`crates/vs-vault`)

Import `vs-vault` and `vs-crypto` directly from the workspace:

```rust
use std::io::Cursor;
use vs_crypto::{AeadAlg, SecretKey32};
use vs_vault::{seal_vspk3_v2_stream, unseal_vspk3_v2_stream};

let mut sealed = Vec::new();
seal_vspk3_v2_stream(
    &master_key, AeadAlg::Aes256Gcm, "billing", "pricing-rules-v1", "prod-eu",
    Cursor::new(plaintext), &mut sealed,
)?;
let mut opened = Vec::new();
unseal_vspk3_v2_stream(
    &master_key, "billing", "pricing-rules-v1", "prod-eu",
    Cursor::new(&sealed), &mut opened,
)?;
```

---

## 4. Companion Node.js Packages

| Package | Path | Purpose |
| :--- | :--- | :--- |
| **`vibeslayer-suite`** | [`vibeslayer-suite/`](../vibeslayer-suite/README.md) | Programmatic lease authority + 7 product engines (`webProduct`, `wasmProduct`, `spatial3dProduct`, `nativeProduct`, `desktopProduct`, `mobileProduct`, `dataAiProduct`) + `antiStealth` Web Component CloakBrowser denial |
| **`vibeslayer-policy-kit`** | [`vibeslayer-policy-kit/`](../vibeslayer-policy-kit/README.md) | Source-configured HTTP policy gateway (`public-preview`, `server-only`, `client-sealed`) with typed param schemas, replay/rate limits, field redaction, and `antiStealth` CloakBrowser denial |
