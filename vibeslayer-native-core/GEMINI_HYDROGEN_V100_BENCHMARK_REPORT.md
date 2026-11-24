# Vibe-Slayer `v1.0.0-beta.3` + `vibeslayer-suite@0.8.0-beta.2` — Comprehensive Benchmark & Security Audit Report

**Benchmark Harness:** `vibeslayer-native-core/tests/bench_v100_hydrogen.py` (`full-30run`, 30 cold-start runs per ELF64 target)  
**REA Engine & Tokenizers:** `morluto/rea` (`rea-agents@6.9.0`) + OpenAI `tiktoken` (`o200k_base` & `cl100k_base`)  
**Machine-Readable Telemetry:** `vibeslayer-native-core/REA_TOKEN_BURN_BENCHMARK.json`  
**Versions:** `vibeslayer-native-core@1.0.0-beta.3`, `vibeslayer-suite@0.8.0-beta.2`, `vibeslayer-policy-kit@0.6.0-beta.1`  
**Independent Swarm Sign-Off:** 2 closed-loop adversarial audit & remediation rounds completed; explicit zero-finding sign-off issued by `@auditor` (`seq #8`).

---

## 1. Five-Way Benchmark Across All Four Target Classes

Every measurement below was captured directly from `bench_v100_hydrogen.py --write-rea-json` (`REA_TOKEN_BURN_BENCHMARK.json`) comparing **Unprotected Baseline**, **`BLA v3.2.1 --intensity bankrupt`**, **`Vibe-Slayer v0.8.1-beta.1`**, **`Vibe-Slayer v0.9.0-beta.3`**, and **`Vibe-Slayer v1.0.0-beta.3`**.

### Target 1: Web / Polyglot JS + `VSPK3`

| Variant | Artifact Bytes | Entropy (bits/B) | `rea` CLI `o200k` Tokens | `rea` CLI `cl100k` Tokens | Metadata/Magic Leak? | Offline Breakable? |
| :--- | ---: | ---: | ---: | ---: | :---: | :--- |
| **Unprotected Baseline** | `131` | `5.1924` | `20,228` | `20,052` | Plaintext | **YES (`1,048` bits)** |
| **`BLA v3.2.1` (`bankrupt`)** | `130,052` | `5.45772` | `8,933,884` | `8,864,977` | Plaintext runtime | **YES (`quote(100) -> 7277` via 1-line dynamic Node import)** |
| **`Vibe-Slayer v0.8.1-beta.1`** | `5,009` JS + `211` `VSPK2` | `6.95731` | `438,835` | `436,456` | `true` (`"VSPK2"` + meta) | **NO (`0` bits)** |
| **`Vibe-Slayer v0.9.0-beta.3`** | `5,009` JS + `1,116` `VSPK3` | `7.80185` | `438,835` | `436,456` | `false` | **NO (`0` bits)** |
| **`Vibe-Slayer v1.0.0-beta.3`** | `5,009` JS + `1,116` `VSPK3` | `7.80185` | `438,835` | `436,456` | `false` | **NO (`0` bits)** |

**Polyglot C (`libvibeslayer.so` `vs_unseal_vspk3`) Unseal Throughput (`v1.0.0-beta.3`):**
- `1 KiB` (`2,140 B` sealed, `300` iters): **`11.77 us` median (`79.58 MB/s`)**
- `64 KiB` (`66,652 B` sealed, `100` iters): **`172.6 us` median (`353.63 MB/s`)**
- `1 MiB` (`1,049,692 B` sealed, `20` iters): **`2,591.74 us` median (`384.6 MB/s`)**
- Polyglot `VSPK2` + `VSPK3` cross-language interop and wrong-domain / wrong-asset / wrong-context / CMT-4 / 1-byte ciphertext tamper rejection verified across Rust CLI, C SDK (`vs_unseal_vspk3`, `vs_unseal_vspk2_for_asset`), Go SDK (`UnsealActionVspk3`, `UnsealActionVspk`), and Python SDK (`unseal_action_vspk3`, `unseal_action_vspk`).

---

### Target 2: Native Linux ELF64 (30-Run Cold-Start Latency & Live `.text` Token Burn)

| Variant | Binary Bytes | Entropy (bits/B) | Live `.text` `o200k` Tokens | `rea_audit` `o200k` Tokens | Cold-Start Median (`30` runs) | Cold-Start p95 (`30` runs) | Steady-State Overhead |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Unprotected Baseline** | `15,984` | `1.47419` | `1,952` (`2,550` exec) | `2,334` | `0.422 ms` | `0.499 ms` | `0.0 ns` |
| **`BLA v3.2.1` (`bankrupt`)** | `1,180,912` | `1.03802` | `1,952` (`2,550` exec) | `2,394` | `0.357 ms` | `0.505 ms` | `0.0 ns` |
| **`Vibe-Slayer v0.8.1-beta.1`** (`build-elf`) | `26,824` | `5.20714` | `59,806` (`63,066` exec) | `2,315` | `0.423 ms` | `0.562 ms` | `0.0 ns` |
| **`Vibe-Slayer v0.9.0-beta.3`** (`build-elf-elite`) | `141,512` | `6.26469` | `687,206` (`688,989` exec) | `2,324` | `1.055 ms` | `1.288 ms` | `0.0 ns` |
| **`Vibe-Slayer v1.0.0-beta.3`** (`build-elf-freestanding`) | **`169,008`** | **`6.41608`** | **`902,988`** (`902,988` exec) | `2,314` | **`0.891 ms`** | **`1.184 ms`** | **`0.0 ns`** |

**Native ELF64 Hardening & Adversarial Probe Matrix:**

| Security Check | Unprotected / `BLA v3.2.1` | `v0.8.1-beta.1` | `v0.9.0-beta.3` | `v1.0.0-beta.3` (Freestanding) |
| :--- | :---: | :---: | :---: | :---: |
| **`PT_INTERP` / `ld-linux`** | `true` | `true` | `true` | **`false` (Zero dynamic linker)** |
| **`DT_NEEDED` imports** | `["libc.so.6"]` | `["libc.so.6"]` | `["libc.so.6"]` | **`[]` (Zero imports / relocs)** |
| **Intel CET `IBT+SHSTK` (`0x3`)** | `disabled` | `enabled` | `enabled` | **`enabled`** |
| **PIE / NX / Full RELRO / Stripped** | PIE/NX, `partial` RELRO, unstripped | All `enabled` | All `enabled` | **All `enabled`** |
| **`PR_GET_DUMPABLE`** | N/A | `0` | `0` | **`0`** |
| **`SYS_memfd_secret(447)`** | N/A | N/A | `0` | **`1` (`secretmem` protected vault)** |
| **`LD_PRELOAD` Hook Surface** | Loaded | Loaded | Loaded (`immune`) | **`ld_preload_loaded=false` (`immune`)** |
| **Live `ptrace` Reject (`rc`)** | Runs plaintext | N/A | `rc = 3` | **`rc = 3` (fail-closed)** |
| **Newline `TracerPid: 0` Spoof under `ptrace`** | Runs plaintext | N/A | `rc = 3` | **`rc = 3` (fail-closed)** |
| **1-Byte `.rodata` Tamper (`VS_SHA256_K` / jump table)** | Runs plaintext | N/A | `rc = 3` | **`rc = 3` (fail-closed)** |
| **1-Byte `.text` Tamper** | Runs plaintext | N/A | `rc = 3` | **`rc = 3` (fail-closed)** |
| **Offline Breakability** | **YES (`432` bits)** | **NO (`0` bits)** | **NO (`0` bits)** | **NO (`0` bits)** |

Key `v1.0.0-beta.3` architectural highlights:
- `build-elf-freestanding` ships `169,008 B` (`6.99×` smaller than `BLA`'s `1,180,912 B`) while driving **`902,988` `o200k_base` tokens** (`901,472` `cl100k_base` tokens) in live executable `.text` disassembly—**`462.6×` more real `.text` code tokens than `BLA` (`1,952`)**, zero dead-section chaff.
- Eliminating `PT_INTERP` / `libc.so.6` and switching SHA-256 to word-aligned 64-byte loops makes cold-start faster (`0.891 ms` median vs `1.055 ms` in `v0.9.0-beta.3`) even while evaluating 128 key-entangled ARX lattice stages.

---

### Target 3: AI Model `.safetensors` (`VSPK2` / `VSPK3` / `VSRA`)

| Variant | Bytes | Entropy (bits/B) | `rea` `o200k` / `cl100k` Tokens | Raw Floats Exposed? | Offline Breakable? |
| :--- | ---: | ---: | ---: | :---: | :--- |
| **Unprotected Baseline** | `65,628` | `7.23516` | `652` / `643` | **Yes** | **YES (`524,288` bits)** |
| **`BLA v3.2.1` (`bankrupt`)** | `75,688` | `7.27654` | `106` / `110` (`rc=1`) | **Yes (`100%` unencrypted)** | **YES** |
| **`Vibe-Slayer v0.8.1-beta.1`** | `65,701` | `7.997` | — (`rc=1`) | **No** | **NO (`0` bits)** |
| **`Vibe-Slayer v0.9.0-beta.3`** | `66,652` | `7.99731` | `111` / `110` (`rc=1`) | **No** | **NO (`0` bits)** |
| **`Vibe-Slayer v1.0.0-beta.3`** | `66,652` | `7.99731` | `111` / `110` (`rc=1`) | **No** | **NO (`0` bits)** |

**O(1) Random-Access Watermarked `VSRA` Slice (`vibeslayer-suite@0.8.0-beta.2`, `256 KiB` tensor):**
- `vsraBytes`: `262,301 B`
- `wmSeedHexLeaked`: `false` (server-side `sealWatermarkedChunkForGrant` embeds watermark under per-lease `chunkKeyHex`)
- `chunkFloats`: `16,384` FP32 floats (`64 KiB` chunk)
- `roundtripUs` (server watermark + re-seal + client O(1) unseal): **`2,888.4 us`**

---

### Target 4: 3D Spatial `.glb` (`white-exarch-web-v4.glb`, `85,455` Coordinates, `±2` LSB Noise)

| Variant | Bytes | Entropy (bits/B) | Noise Tested | Candidate-Free O(1) WM64 Decode | Bit Accuracy | Confidence | Offline Breakable? |
| :--- | ---: | ---: | :---: | :---: | :---: | :---: | :--- |
| **Unprotected Baseline** | `581,260` | `7.39544` | — | — | — | — | **YES (`4,650,080` bits)** |
| **`BLA v3.2.1`** | — | — | — | Unsupported (`rc=1`) | — | — | **YES** |
| **`Vibe-Slayer v0.8.1-beta.1`** | `171,014` | `7.99904` | — | — | — | — | **NO (`0` bits)** |
| **`Vibe-Slayer v0.9.0-beta.3`** | `171,014` | `7.99904` | — | (`WM_AMPLITUDE = 4`) | — | — | **NO (`0` bits)** |
| **`Vibe-Slayer v1.0.0-beta.3`** | `171,014` | `7.99904` | **`±2` LSB** | **`0.984 ms` CLI med (`1.531 ms` p95) / `7.019 ms` Node** | **`64/64` exact** | **`0.968018`** | **NO (`0` bits)** |

---

## 2. Two-Round Closed-Loop Hardening & Security Remediations Summary

| Round | Target / Scope | Summary of Implemented & Audited Fixes |
| :---: | :--- | :--- |
| **R1** | `v100_zero_overhead.rs`, `v090_elite.rs` | Hashed all non-writable `PT_LOAD` (`(p_flags & PF_W) == 0`, including `.rodata` jump tables & `VS_SHA256_K`), excluding only `[RO_VAULT, RO_VAULT + VAULT_BYTES)`. Added EINTR-safe `read_all_fd`, `close(lfd)` + `envp` zeroization, `VS_LEASE_FD` digit/overflow validation (`1..=6` digits), `TracerPid` overflow cap, `PR_SET_NO_NEW_PRIVS` + `PR_SET_PTRACER(0)`, dual pre/post `TracerPid` evaluation (`tr_pre \| tr_post`), stack-protector via `SYS_getrandom(318)`, CET `IBT+SHSTK` (`-fuse-ld=bfd`), `SYS_memfd_secret(447)` vault allocation, 128 ARX lattice stages, and `0` ELF relocations. |
| **R1** | `sdk_c`, `sdk_go`, `sdk_python` | Added full `VSPK3` parity (`vs_unseal_vspk3`, `UnsealActionVspk3`, `unseal_action_vspk3`) with canonical `u32_le` `VSPK3_CMT4` transcript, constant-time HMAC-SHA256 CMT-4 verify prior to ChaCha20-Poly1305 open, `1,024`-byte pad-then-encrypt unframing, and zeroization. |
| **R1** | `vibeslayer-suite@0.8.0-beta.1` | Moved AI tensor watermarking strictly server-side (`sealWatermarkedChunkForGrant`, per-lease `chunkKeyHex`, stripped `wmSeedHex`); enforced strict `VSRA` header/chunk bounds; verified Ed25519 grant tokens & used verified claims only in `web.js`/`web-client.js`; aligned `spatial3d.js` `WM_AMPLITUDE = 4` (`[-32750, 32750]`) + O(1) `embedLeaseWatermark64` / `decodeLeaseWatermark64O1`; added `--stdin` mode in `vs_mobile_runner`, `mlock` + `ct_len < alloc_len` guard in `vs_desktop_enclave.c`, and CET `IBT+SHSTK` flags in `scripts/build-native.js`. |
| **R2** | `web-client.js`, `web.js`, `spatial3d.js` (`0.8.0-beta.2`) | **[HIGH]** Eliminated `grant?.authorityPublicKeySpkiB64` fallback completely across `verifyGrantEd25519Client`, `resolvePinnedGrantPublicKey`, and `unsealToGpuBuffers`: client helpers strictly require explicit caller `authorityPublicKeySpkiB64`; server helpers resolve only caller key or `SERVER_ONLY_GRANT_SEEDS` (`Test 11` passes rejecting wire self-signed attacker grants across all 5 entrypoints). |
| **R2** | `sdk_c`, `sdk_python`, `lib.rs`, `main.rs` (`1.0.0-beta.3`) | **[MEDIUM]** Added `vs_unseal_vspk2_for_asset` & `unseal_vspk2_for_asset` preserving `VSPK2` ABI while binding & rejecting mismatched `asset_id` across `test_c_sdk`, `sdk_python`, and `vibeslayer unseal --asset-id` (rebuilt Linux & Windows `bin/*`). |
| **R2** | `desktop.js`, `vs_desktop_enclave.c`, `data-ai-client.js`, `v100`/`v090` | **[LOW]** Rejected pending `nextLine()` IPC waiters on child `error`/`close`/`rl.close`/`stdin` error/bad JSON and made `enclave.close()` idempotent on exited children (`vs_desktop_enclave` returns `BAD_IPC_FRAME` when `sscanf != 2`); enforced `16 + idLen + chunkCount * recordStride <= buf.length` in `parseVsraForGrant`; rejected stdio FDs `0`/`1`/`2` in `VS_LEASE_FD`. |

---

## 3. Reproducible Verification Suite Results (Finalized Workspace)

All verification suites passed with zero failures or skipped assertions on the finalized codebase and rebuilt binaries:
- `make -C vibeslayer-native-core test`: **`9/9` PASS** (`run_polyglot_suite.py` `4/4`, `test_v090_elite.py` `3/3`, `test_v100_zero_overhead.py` `2/2`, including Go `TestInteropWithRustVspk2` & `TestInteropWithRustVspk3`, C `test_c_sdk`, and `cargo test` `2/2`)
- `npm test --prefix vibeslayer-suite`: **`13/13` PASS**
- `npm test --prefix vibeslayer-policy-kit`: **`7/7` PASS**
- `python3 vibeslayer-native-core/tests/bench_v100_hydrogen.py --verify-only`: deterministic verification pass across all 4 targets
- `rea inspect-binary-hardening` across all 6 shipped Linux ELFs (`bin/vibeslayer`, `bin/libvibeslayer.so`, `bin/test_c_sdk`, `dist_bin/vs_desktop_enclave`, `dist_bin/vs_mobile_runner`, `dist_bin/libvsmobile.so`): all report `cet_ibt_shstk: enabled`, `nx: enabled`, `relro: enabled`, `stripped: enabled`.
