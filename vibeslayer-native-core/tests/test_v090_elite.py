#!/usr/bin/env python3
"""
TDD Spec for `vibeslayer-native-core` `v0.9.0-beta.1`:
1. Headerless indistinguishable-from-random `VSPK3` container (CMT-4 key-committing,
   zero `"VSPK"` magic, zero plaintext metadata strings, entropy > 7.8 bits/B).
2. 64-stage entangled call-graph native ELF64 (`build-elf-v090`):
   - Zero `.vsblob` section name (scatter-sharded into `.rodata`).
   - Zero diagnostic ASCII error strings (`MISSING_NATIVE_LEASE`, etc. absent).
   - Live `PF_X` `.text` 64-stage indirect call-graph transcript (`> 150,000` `o200k` disassembly tokens).
   - Branchless `/proc/self/status` `TracerPid` key-transcript entanglement:
     running the binary WITH THE REAL VALID LEASE KEY under `ptrace` (`TracerPid != 0`)
     silently shifts the HKDF key so Poly1305 fails (`rc != 0`) and plaintext NEVER enters RAM!
"""

import hashlib
import json
import math
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import tiktoken

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bin" / "vibeslayer"
ENC = tiktoken.get_encoding("o200k_base")


def shannon_entropy(data: bytes) -> float:
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


class TestV090EliteHardening(unittest.TestCase):
    def test_01_vspk3_headerless_key_committing_indistinguishable_from_random(self):
        with tempfile.TemporaryDirectory(prefix="vs090-vspk3-") as td:
            tdir = Path(td)
            key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            plain = b"SECRET_FORMULA_V090=" + (b"A" * 512)
            in_p = tdir / "in.bin"
            out_p = tdir / "out.vspk3"
            dec_p = tdir / "dec.bin"
            in_p.write_bytes(plain)

            res = json.loads(
                subprocess.check_output(
                    [
                        str(BIN), "pack-v3",
                        "--key", key,
                        "--domain", "web-elite",
                        "--asset-id", "shader-core-v9",
                        "--context", "https://app.vibeslayer.test",
                        "--in", str(in_p),
                        "--out", str(out_p),
                    ],
                    text=True,
                )
            )
            self.assertTrue(res["ok"])
            blob = out_p.read_bytes()

            # Zero magic headers & zero metadata substrings anywhere in VSPK3!
            for leaked in (b"VSPK", b"web-elite", b"shader-core-v9", b"vibeslayer", b"SECRET_FORMULA"):
                self.assertNotIn(leaked, blob)
            self.assertGreater(shannon_entropy(blob), 7.80)

            # Valid unseal roundtrip
            subprocess.check_call(
                [
                    str(BIN), "unseal-v3",
                    "--key", key,
                    "--domain", "web-elite",
                    "--asset-id", "shader-core-v9",
                    "--context", "https://app.vibeslayer.test",
                    "--in", str(out_p),
                    "--out", str(dec_p),
                ]
            )
            self.assertEqual(dec_p.read_bytes(), plain)

            # 1-bit flip in CMT-4 commitment tag must fail authentication
            tampered = bytearray(blob)
            tampered[44] ^= 0x01
            bad_p = tdir / "bad.vspk3"
            bad_p.write_bytes(bytes(tampered))
            r_bad = subprocess.run(
                [
                    str(BIN), "unseal-v3",
                    "--key", key,
                    "--domain", "web-elite",
                    "--asset-id", "shader-core-v9",
                    "--context", "https://app.vibeslayer.test",
                    "--in", str(bad_p),
                    "--out", str(dec_p),
                ],
                capture_output=True,
            )
            self.assertNotEqual(r_bad.returncode, 0)

    def test_02_elite_elf64_scatter_shards_high_token_cost_and_ptrace_poisoning(self):
        with tempfile.TemporaryDirectory(prefix="vs090-elf-") as td:
            tdir = Path(td)
            key = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
            secret = b"ELITE_V090_KERNEL_WEIGHTS=91,103,127,139;ZERO_LEAK"
            in_p = tdir / "sec.bin"
            elf_p = tdir / "elite_vault"
            in_p.write_bytes(secret)

            built = json.loads(
                subprocess.check_output(
                    [
                        str(BIN), "build-elf-elite",
                        "--key", key,
                        "--asset-id", "elite-avx-v9",
                        "--in", str(in_p),
                        "--out", str(elf_p),
                    ],
                    text=True,
                )
            )
            self.assertTrue(built["ok"])
            elf_bytes = elf_p.read_bytes()

            # 1. Zero `.vsblob` section name, zero `VSBLB`, zero diagnostic strings!
            sections_out = subprocess.check_output(["readelf", "-SW", str(elf_p)], text=True)
            self.assertNotIn(".vsblob", sections_out)
            for marker in (
                b"VSBLB",
                b"MISSING_NATIVE_LEASE",
                b"NATIVE_AEAD",
                b"elite-avx-v9",
                b"ELITE_V090_KERNEL_WEIGHTS",
            ):
                self.assertNotIn(marker, elf_bytes)

            # 2. Disassembly token cost > 150,000 `o200k_base` tokens of live entangled `.text`!
            disasm = subprocess.check_output(["objdump", "-d", str(elf_p)], text=True)
            disasm_tokens = len(ENC.encode(disasm, disallowed_special=()))
            self.assertGreater(
                disasm_tokens,
                150_000,
                f"Expected >150,000 live disassembly o200k tokens, got {disasm_tokens}",
            )

            # 3. Clean execution with valid lease key succeeds
            out_ok = json.loads(
                subprocess.check_output([str(elf_p), built["leaseKeyHex"]], text=True).strip()
            )
            self.assertTrue(out_ok["ok"])
            self.assertEqual(out_ok["payloadSha256"], hashlib.sha256(secret).hexdigest())

            # 4. Ptrace / Debugger attach WITH THE EXACT SAME VALID LEASE KEY fails to decrypt!
            # Use a tiny Python ctypes `PTRACE_TRACEME` wrapper so `TracerPid != 0` in `/proc/self/status`
            ptrace_py = (
                "import ctypes, os, sys; "
                "libc = ctypes.CDLL(None); "
                "pid = os.fork();\n"
                "if pid == 0:\n"
                "    libc.ptrace(0, 0, None, None)\n"
                f"    os.execv({str(elf_p)!r}, [{str(elf_p)!r}, {built['leaseKeyHex']!r}])\n"
                "else:\n"
                "    _, st = os.waitpid(pid, 0)\n"
                "    if os.WIFSTOPPED(st):\n"
                "        libc.ptrace(7, pid, None, None)\n"
                "        _, st = os.waitpid(pid, 0)\n"
                "    sys.exit(os.WEXITSTATUS(st) if os.WIFEXITED(st) else 99)\n"
            )
            traced = subprocess.run(["python3", "-c", ptrace_py], capture_output=True, text=True)
            self.assertNotEqual(
                traced.returncode,
                0,
                "Expected ptrace-attached run with valid lease to fail Poly1305 due to TracerPid HKDF entanglement!",
            )

            # 5. VS_LEASE_FD pipe delivery succeeds with ZERO argv[1] secret argument!
            pipe_py = (
                "import json, os, subprocess;\n"
                "rfd, wfd = os.pipe()\n"
                f"os.write(wfd, {built['leaseKeyHex'].encode()!r})\n"
                "os.close(wfd)\n"
                "env = dict(os.environ, VS_LEASE_FD=str(rfd))\n"
                f"out = subprocess.check_output([{str(elf_p)!r}], pass_fds=(rfd,), env=env, text=True)\n"
                "os.close(rfd)\n"
                "print(out.strip())\n"
            )
            pipe_out = json.loads(subprocess.check_output(["python3", "-c", pipe_py], text=True).strip())
            self.assertTrue(pipe_out["ok"])
            self.assertEqual(pipe_out["payloadSha256"], hashlib.sha256(secret).hexdigest())

            # Reserved stdio FDs (0, 1, 2) or malformed VS_LEASE_FD must fail closed without closing stdout/stderr
            for bad_fd in ("0", "1", "2", "3evil", "1234567"):
                r_bad_fd = subprocess.run(
                    [str(elf_p)],
                    env={"VS_LEASE_FD": bad_fd},
                    input=built["leaseKeyHex"].encode("ascii"),
                    capture_output=True,
                )
                self.assertNotEqual(r_bad_fd.returncode, 0, f"Expected failure for VS_LEASE_FD={bad_fd}")

            # 6. LD_PRELOAD libc hook spoofing fopen/prctl CANNOT bypass direct kernel syscalls under ptrace!
            preload_c = tdir / "fake_libc.c"
            preload_so = tdir / "fake_libc.so"
            preload_c.write_text(
                "#include <stdio.h>\n"
                "int prctl(int o, ...) { (void)o; return 0; }\n"
                "FILE *fopen(const char *p, const char *m) { (void)p; (void)m; return NULL; }\n"
            )
            subprocess.check_call(["gcc", "-shared", "-fPIC", str(preload_c), "-o", str(preload_so)])
            ptrace_preload_py = (
                "import ctypes, os, sys; "
                "libc = ctypes.CDLL(None); "
                "pid = os.fork();\n"
                "if pid == 0:\n"
                f"    os.environ['LD_PRELOAD'] = {str(preload_so)!r}\n"
                "    libc.ptrace(0, 0, None, None)\n"
                f"    os.execv({str(elf_p)!r}, [{str(elf_p)!r}, {built['leaseKeyHex']!r}])\n"
                "else:\n"
                "    _, st = os.waitpid(pid, 0)\n"
                "    if os.WIFSTOPPED(st):\n"
                "        libc.ptrace(7, pid, None, None)\n"
                "        _, st = os.waitpid(pid, 0)\n"
                "    sys.exit(os.WEXITSTATUS(st) if os.WIFEXITED(st) else 99)\n"
            )
            traced_preload = subprocess.run(["python3", "-c", ptrace_preload_py], capture_output=True, text=True)
            self.assertNotEqual(traced_preload.returncode, 0)

            # 7. Newline-in-filename TracerPid:0 spoofing cannot bypass ptrace detection
            evil_name = tdir / "a\nTracerPid:\t0"
            shutil.copy2(elf_p, evil_name)
            evil_plain = subprocess.run([str(evil_name), built["leaseKeyHex"]], capture_output=True)
            self.assertEqual(evil_plain.returncode, 0)
            evil_ptrace_py = (
                "import ctypes, os, sys; "
                "libc = ctypes.CDLL(None); "
                "pid = os.fork();\n"
                "if pid == 0:\n"
                "    libc.ptrace(0, 0, None, None)\n"
                f"    os.execv({str(evil_name)!r}, [{str(evil_name)!r}, {built['leaseKeyHex']!r}])\n"
                "else:\n"
                "    _, st = os.waitpid(pid, 0)\n"
                "    if os.WIFSTOPPED(st):\n"
                "        libc.ptrace(7, pid, None, None)\n"
                "        _, st = os.waitpid(pid, 0)\n"
                "    sys.exit(os.WEXITSTATUS(st) if os.WIFEXITED(st) else 99)\n"
            )
            evil_traced = subprocess.run(["python3", "-c", evil_ptrace_py], capture_output=True)
            self.assertNotEqual(evil_traced.returncode, 0)

            # 8. Flipping 1 byte in .rodata (VS_SHA256_K outside RO_VAULT) fails closed (rc == 3)
            k_pos = elf_bytes.find(b"\x98\x2f\x8a\x42\x91\x44\x37\x71")
            self.assertGreater(k_pos, 0, "Expected SHA-256 constants in .rodata")
            tampered_ro = bytearray(elf_bytes)
            tampered_ro[k_pos] ^= 0x01
            ro_elf = tdir / "elite_tampered_ro"
            ro_elf.write_bytes(bytes(tampered_ro))
            ro_elf.chmod(0o755)
            r_ro = subprocess.run([str(ro_elf), built["leaseKeyHex"]], capture_output=True)
            self.assertEqual(r_ro.returncode, 3)

            # 9. Verify zero leaked parser strings in binary
            strings_out = subprocess.check_output(["strings", str(elf_p)], text=True)
            for s in ("VS_LEASE_FD", "/proc/self/status", "TracerPid"):
                self.assertNotIn(s, strings_out)

    def test_03_signed_correlation_watermark_survives_quantization_noise(self):
        sample_glb = ROOT / "tests" / "fixtures" / "sample_mesh.glb"
        with tempfile.TemporaryDirectory(prefix="vs090-wm-") as td:
            tdir = Path(td)
            key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            sealed_p = tdir / "cooked.vspk2"
            ref_p = tdir / "owner_ref.bin"
            pos_p = tdir / "lease_pos.bin"
            noisy_p = tdir / "noisy_pos.bin"

            subprocess.check_call([
                str(BIN), "cook-glb",
                "--key", key, "--asset-id", "exarch-v9", "--context", "https://app.test",
                "--in", str(sample_glb), "--out", str(sealed_p), "--owner-ref", str(ref_p),
            ])
            subprocess.check_call([
                str(BIN), "unseal-glb-lease",
                "--key", key, "--asset-id", "exarch-v9", "--context", "https://app.test",
                "--lease-id", "suspect_lease_7", "--in", str(sealed_p), "--out-positions", str(pos_p),
            ])

            # Perturb EVERY coordinate by +-2 LSB noise (which wiped out exact-equality watermarks!)
            import struct
            raw = pos_p.read_bytes()
            coords = list(struct.unpack(f"<{len(raw)//2}h", raw))
            noisy = [max(-32767, min(32767, v + (2 if (i & 1) == 0 else -2))) for i, v in enumerate(coords)]
            noisy_p.write_bytes(struct.pack(f"<{len(noisy)}h", *noisy))

            traced = json.loads(subprocess.check_output([
                str(BIN), "trace-glb",
                "--key", key, "--asset-id", "exarch-v9",
                "--owner-ref", str(ref_p), "--captured", str(noisy_p),
                "--candidates", "innocent_1,innocent_2,suspect_lease_7,innocent_3,innocent_4",
            ], text=True))
            self.assertEqual(traced["matchedLeaseId"], "suspect_lease_7")
            self.assertGreater(traced["chipMatchRatio"], 0.45)


if __name__ == "__main__":
    unittest.main(verbosity=2)
