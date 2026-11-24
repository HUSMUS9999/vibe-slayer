#!/usr/bin/env python3
"""
TDD Spec for `vibeslayer-native-core` `v1.0.0-beta.1` Zero-Overhead Hardening:
1. `build-elf-freestanding`:
   - Zero `PT_INTERP` (`ld-linux` absent) and zero `DT_NEEDED` (`libc` absent):
     `LD_PRELOAD` and `LD_AUDIT` are architecturally impossible at the OS kernel level!
   - Hardware Intel CET (`IBT` + `SHSTK` `.note.gnu.property`) enabled (`0` runtime overhead).
   - Kernel `SYS_memfd_secret(0)` (`447`) secret page unmapped from kernel direct map
     (with fallback to `mlock` + `MADV_DONTDUMP` + `MADV_WIPEONFORK`).
   - Faster cold-start than dynamic ELF while preserving `>500,000` `o200k_base` live `.text` tokens
     and fail-closed `TracerPid` key entanglement.
2. `embed-wm64` / `decode-wm64`:
   - Server-side `0.00 ms/frame` client-overhead 64-bit BPSK spread-spectrum watermark
     (`64 bits x 16 chips/bit = 1,024 chips`, `WM_AMPLITUDE = 4`).
   - Recovers exact 64-bit `watermarkIdHex` in `O(1)` WITHOUT any candidate list, even after
     every coordinate is perturbed by `+-2` LSB quantization noise!
"""

import hashlib
import json
import os
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import tiktoken

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bin" / "vibeslayer"
ENC = tiktoken.get_encoding("o200k_base")


class TestV100ZeroOverheadHardening(unittest.TestCase):
    def test_01_freestanding_static_pie_no_ld_linux_cet_and_memfd_secret(self):
        with tempfile.TemporaryDirectory(prefix="vs100-free-") as td:
            tdir = Path(td)
            key = "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"
            secret = b"FREESTANDING_ZERO_LIBC_MEMFD_SECRET_PAYLOAD_V100"
            in_p = tdir / "sec.bin"
            elf_p = tdir / "vault_freestanding"
            in_p.write_bytes(secret)

            built = json.loads(
                subprocess.check_output(
                    [
                        str(BIN),
                        "build-elf-freestanding",
                        "--key", key,
                        "--asset-id", "zero-libc-v100",
                        "--in", str(in_p),
                        "--out", str(elf_p),
                    ],
                    text=True,
                )
            )
            self.assertTrue(built["ok"])

            # 1. Verify ZERO PT_INTERP (no ld-linux!) -> LD_PRELOAD is kernel-impossible!
            phdrs = subprocess.check_output(["readelf", "-lW", str(elf_p)], text=True)
            self.assertNotIn("INTERP", phdrs)
            self.assertNotIn("ld-linux", phdrs)

            # 2. Verify Intel CET IBT + SHSTK GNU property note is present
            notes = subprocess.check_output(["readelf", "-n", str(elf_p)], text=True)
            self.assertIn("IBT", notes)
            self.assertIn("SHSTK", notes)

            # 3. Verify >800,000 o200k_base disassembly tokens, 0 dynamic relocs, and no leaked ASCII literals
            disasm = subprocess.check_output(["objdump", "-d", str(elf_p)], text=True)
            toks = len(ENC.encode(disasm, disallowed_special=()))
            self.assertGreater(toks, 800_000, f"Expected >800k tokens, got {toks}")
            relocs = subprocess.check_output(["readelf", "-rW", str(elf_p)], text=True)
            self.assertIn("no relocations", relocs.lower())
            strs_out = subprocess.check_output(["strings", str(elf_p)], text=True)
            for marker in ("VS_LEASE_FD", "/proc/self/status", "TracerPid"):
                self.assertNotIn(marker, strs_out)

            # 4. Execute via inherited pipe FD (FD 3) with LD_PRELOAD set to an invalid .so:
            #    a dynamic binary would crash or load LD_PRELOAD; freestanding ignores it completely!
            rfd, wfd = os.pipe()
            os.write(wfd, built["leaseKeyHex"].encode("ascii"))
            os.close(wfd)
            t0 = time.perf_counter()
            out_raw = subprocess.check_output(
                [str(elf_p)],
                pass_fds=(rfd,),
                env={"LD_PRELOAD": "/nonexistent_evil_hook.so", "VS_LEASE_FD": str(rfd)},
                text=True,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            os.close(rfd)

            res = json.loads(out_raw.strip())
            self.assertTrue(res["ok"])
            self.assertEqual(res["dumpable"], 0)
            self.assertEqual(res["secretmem"], 1)  # Kernel 6.12 SYS_memfd_secret active!
            self.assertEqual(res["payloadSha256"], hashlib.sha256(secret).hexdigest())
            self.assertLess(elapsed_ms, 25.0)

            # 5. Ptrace attach with valid key on pipe FD still fails closed (rc != 0)!
            ptrace_py = (
                "import ctypes, os, sys; "
                "libc = ctypes.CDLL(None); "
                "rfd, wfd = os.pipe(); "
                f"os.write(wfd, {built['leaseKeyHex'].encode()!r}); os.close(wfd); "
                "pid = os.fork();\n"
                "if pid == 0:\n"
                "    libc.ptrace(0, 0, None, None)\n"
                f"    os.execve({str(elf_p)!r}, [{str(elf_p)!r}], {{'VS_LEASE_FD': str(rfd)}})\n"
                "else:\n"
                "    os.close(rfd)\n"
                "    _, st = os.waitpid(pid, 0)\n"
                "    if os.WIFSTOPPED(st):\n"
                "        libc.ptrace(7, pid, None, None)\n"
                "        _, st = os.waitpid(pid, 0)\n"
                "    sys.exit(os.WEXITSTATUS(st) if os.WIFEXITED(st) else 99)\n"
            )
            traced = subprocess.run(["python3", "-c", ptrace_py], capture_output=True, text=True)
            self.assertNotEqual(traced.returncode, 0)

            # 6. Newline-in-filename TracerPid:0 spoofing cannot bypass ptrace detection
            import shutil
            evil_elf = tdir / "a\nTracerPid:\t0"
            shutil.copy2(elf_p, evil_elf)
            rfd_e, wfd_e = os.pipe()
            os.write(wfd_e, built["leaseKeyHex"].encode("ascii"))
            os.close(wfd_e)
            r_evil = subprocess.run(
                [str(evil_elf)],
                pass_fds=(rfd_e,),
                env={"VS_LEASE_FD": str(rfd_e)},
                capture_output=True,
            )
            os.close(rfd_e)
            self.assertEqual(r_evil.returncode, 0)

            evil_ptrace_py = (
                "import ctypes, os, sys; "
                "libc = ctypes.CDLL(None); "
                "rfd, wfd = os.pipe(); "
                f"os.write(wfd, {built['leaseKeyHex'].encode()!r}); os.close(wfd); "
                "pid = os.fork();\n"
                "if pid == 0:\n"
                "    libc.ptrace(0, 0, None, None)\n"
                f"    os.execve({str(evil_elf)!r}, [{str(evil_elf)!r}], {{'VS_LEASE_FD': str(rfd)}})\n"
                "else:\n"
                "    os.close(rfd)\n"
                "    _, st = os.waitpid(pid, 0)\n"
                "    if os.WIFSTOPPED(st):\n"
                "        libc.ptrace(7, pid, None, None)\n"
                "        _, st = os.waitpid(pid, 0)\n"
                "    sys.exit(os.WEXITSTATUS(st) if os.WIFEXITED(st) else 99)\n"
            )
            traced_evil = subprocess.run(["python3", "-c", evil_ptrace_py], capture_output=True)
            self.assertNotEqual(traced_evil.returncode, 0)

            # 7. Flipping 1 byte in .rodata outside RO_VAULT fails closed (rc == 3)
            raw_elf = elf_p.read_bytes()
            k_pos = raw_elf.find(b"\x98\x2f\x8a\x42\x91\x44\x37\x71")
            self.assertGreater(k_pos, 0, "Expected SHA-256 constants in .rodata")
            tampered_ro = bytearray(raw_elf)
            tampered_ro[k_pos] ^= 0x01
            ro_elf = tdir / "vault_ro_tampered"
            ro_elf.write_bytes(bytes(tampered_ro))
            ro_elf.chmod(0o755)
            rfd_t, wfd_t = os.pipe()
            os.write(wfd_t, built["leaseKeyHex"].encode("ascii"))
            os.close(wfd_t)
            r_tamper = subprocess.run(
                [str(ro_elf)],
                pass_fds=(rfd_t,),
                env={"VS_LEASE_FD": str(rfd_t)},
                capture_output=True,
            )
            os.close(rfd_t)
            self.assertEqual(r_tamper.returncode, 3)

            # 8. Malformed / reserved stdio descriptors in VS_LEASE_FD (0, 1, 2) must fail closed without closing stdout/stderr
            for bad_fd in ("0", "1", "2", "3evil", "1234567", "-3"):
                r_bad = subprocess.run(
                    [str(elf_p)],
                    env={"VS_LEASE_FD": bad_fd},
                    input=built["leaseKeyHex"].encode("ascii"),
                    capture_output=True,
                )
                self.assertEqual(r_bad.returncode, 2, f"Expected rc=2 for VS_LEASE_FD={bad_fd}, got {r_bad.returncode}")

    def test_02_o1_candidate_free_64bit_bpsk_watermark_survives_noise(self):
        sample_glb = ROOT / "tests" / "fixtures" / "sample_mesh.glb"
        with tempfile.TemporaryDirectory(prefix="vs100-wm64-") as td:
            tdir = Path(td)
            key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            wm_hex = "deadbeefcafe2026"
            sealed_p = tdir / "cooked.vspk2"
            ref_p = tdir / "owner_ref.bin"
            pos_p = tdir / "wm64_pos.bin"
            noisy_p = tdir / "wm64_noisy.bin"

            subprocess.check_call([
                str(BIN), "cook-glb",
                "--key", key, "--asset-id", "exarch-v100", "--context", "https://app.test",
                "--in", str(sample_glb), "--out", str(sealed_p), "--owner-ref", str(ref_p),
            ])
            subprocess.check_call([
                str(BIN), "embed-wm64",
                "--key", key, "--asset-id", "exarch-v100", "--context", "https://app.test",
                "--wm-id-hex", wm_hex, "--in", str(sealed_p), "--out-positions", str(pos_p),
            ])

            # Corrupt EVERY coordinate by +-2 LSB noise
            raw = pos_p.read_bytes()
            coords = list(struct.unpack(f"<{len(raw)//2}h", raw))
            noisy = [max(-32767, min(32767, v + (2 if (i % 3) == 0 else -2))) for i, v in enumerate(coords)]
            noisy_p.write_bytes(struct.pack(f"<{len(noisy)}h", *noisy))

            # Decode 64-bit traitor ID in O(1) WITHOUT passing any candidate list!
            t0 = time.perf_counter()
            decoded = json.loads(subprocess.check_output([
                str(BIN), "decode-wm64",
                "--key", key, "--asset-id", "exarch-v100",
                "--owner-ref", str(ref_p), "--captured", str(noisy_p),
            ], text=True))
            decode_ms = (time.perf_counter() - t0) * 1000.0

            self.assertEqual(decoded["decodedWatermarkIdHex"], wm_hex)
            self.assertGreaterEqual(decoded["meanChipConfidence"], 0.45)
            self.assertLess(decode_ms, 50.0)

    def test_03_wrap_elf_freestanding_executes_and_resists_attacks(self):
        with tempfile.TemporaryDirectory(prefix="vs100-wrap-") as td:
            tdir = Path(td)
            key = "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"
            src_c = tdir / "demo_app.c"
            plain_bin = tdir / "demo_app"
            src_c.write_text(
                '#include <stdio.h>\n'
                '#include <stdlib.h>\n'
                '#include <string.h>\n'
                'static const char SECRET_BANNER[] = "WRAP_TARGET_SECRET_BANNER_2026";\n'
                'int main(int argc, char **argv) {\n'
                '    const char *ldp = getenv("LD_PRELOAD");\n'
                '    printf("banner=%s;ld=%s;argc=%d;arg1=%s\\n", SECRET_BANNER, ldp ? ldp : "NONE", argc, argc > 1 ? argv[1] : "");\n'
                '    return (argc > 1 && strcmp(argv[1], "--exit7") == 0) ? 7 : 0;\n'
                '}\n'
            )
            subprocess.check_call(["gcc", "-O2", "-fPIE", "-pie", str(src_c), "-o", str(plain_bin)])

            wrapped = tdir / "demo_app.protected"
            built = json.loads(subprocess.check_output([
                str(BIN), "wrap-elf",
                "--key", key, "--asset-id", "wrap-demo-v100",
                "--in", str(plain_bin), "--out", str(wrapped),
            ], text=True))
            self.assertTrue(built["ok"])
            self.assertFalse(built["standalone"])
            self.assertEqual(len(built["leaseKeyHex"]), 64)

            phdrs = subprocess.check_output(["readelf", "-lW", str(wrapped)], text=True)
            self.assertNotIn("INTERP", phdrs)
            self.assertNotIn("ld-linux", phdrs)
            notes = subprocess.check_output(["readelf", "-n", str(wrapped)], text=True)
            self.assertIn("IBT", notes)
            self.assertIn("SHSTK", notes)
            relocs = subprocess.check_output(["readelf", "-rW", str(wrapped)], text=True)
            self.assertIn("no relocations", relocs.lower())
            strs_out = subprocess.check_output(["strings", str(wrapped)], text=True)
            for forbidden in ("VS_LEASE_FD", "/proc/self/status", "/proc/self/exe", "TracerPid", "WRAP_TARGET_SECRET_BANNER_2026"):
                self.assertNotIn(forbidden, strs_out)

            # 1. Lease via inherited FD + hostile LD_PRELOAD + argument/exit code forwarding
            rfd, wfd = os.pipe()
            os.write(wfd, built["leaseKeyHex"].encode("ascii"))
            os.close(wfd)
            r_fd = subprocess.run(
                [str(wrapped), "--exit7"],
                pass_fds=(rfd,),
                env={"LD_PRELOAD": "/nonexistent_evil.so", "VS_LEASE_FD": str(rfd)},
                capture_output=True, text=True,
            )
            os.close(rfd)
            self.assertEqual(r_fd.returncode, 7)
            self.assertIn("banner=WRAP_TARGET_SECRET_BANNER_2026;ld=NONE;argc=2;arg1=--exit7", r_fd.stdout)

            # 2. Lease via --vs-key strips wrapper flag from inner argv
            r_cli = subprocess.run(
                [str(wrapped), "--vs-key", built["leaseKeyHex"], "hello"],
                capture_output=True, text=True,
            )
            self.assertEqual(r_cli.returncode, 0)
            self.assertIn("argc=2;arg1=hello", r_cli.stdout)

            # 3. Standalone mode runs directly without key and strips LD_PRELOAD
            sa_bin = tdir / "demo_app.standalone"
            sa = json.loads(subprocess.check_output([
                str(BIN), "wrap-elf",
                "--key", key, "--asset-id", "wrap-demo-sa",
                "--in", str(plain_bin), "--out", str(sa_bin), "--standalone",
            ], text=True))
            self.assertTrue(sa["ok"])
            self.assertTrue(sa["standalone"])
            r_sa = subprocess.run(
                [str(sa_bin), "direct"],
                env={"LD_PRELOAD": "/nonexistent_evil.so"},
                capture_output=True, text=True,
            )
            self.assertEqual(r_sa.returncode, 0)
            self.assertIn("ld=NONE;argc=2;arg1=direct", r_sa.stdout)

            # 4. Wrong key fails closed (rc == 3)
            r_bad = subprocess.run(
                [str(wrapped), "--vs-key", "0" * 64],
                capture_output=True,
            )
            self.assertEqual(r_bad.returncode, 3)

            # 5. 1-byte tamper in .rodata or appended ciphertext fails closed (rc == 3)
            raw_elf = bytearray(wrapped.read_bytes())
            k_pos = raw_elf.find(b"\x98\x2f\x8a\x42\x91\x44\x37\x71")
            self.assertGreater(k_pos, 0)
            tamper_ro = bytearray(raw_elf)
            tamper_ro[k_pos] ^= 0x01
            ro_p = tdir / "tamper_ro"
            ro_p.write_bytes(bytes(tamper_ro))
            ro_p.chmod(0o755)
            self.assertEqual(
                subprocess.run([str(ro_p), "--vs-key", built["leaseKeyHex"]], capture_output=True).returncode,
                3,
            )
            tamper_ct = bytearray(raw_elf)
            tamper_ct[-17] ^= 0x01
            ct_p = tdir / "tamper_ct"
            ct_p.write_bytes(bytes(tamper_ct))
            ct_p.chmod(0o755)
            self.assertEqual(
                subprocess.run([str(ct_p), "--vs-key", built["leaseKeyHex"]], capture_output=True).returncode,
                3,
            )

            # 6. Ptrace attach fails closed (rc != 0)
            ptrace_py = (
                "import ctypes, os, sys; "
                "libc = ctypes.CDLL(None); "
                "rfd, wfd = os.pipe(); "
                f"os.write(wfd, {built['leaseKeyHex'].encode()!r}); os.close(wfd); "
                "pid = os.fork()\n"
                "if pid == 0:\n"
                "    libc.ptrace(0, 0, None, None)\n"
                f"    os.execve({str(wrapped)!r}, [{str(wrapped)!r}], {{'VS_LEASE_FD': str(rfd)}})\n"
                "else:\n"
                "    os.close(rfd)\n"
                "    _, st = os.waitpid(pid, 0)\n"
                "    if os.WIFSTOPPED(st):\n"
                "        libc.ptrace(7, pid, None, None)\n"
                "        _, st = os.waitpid(pid, 0)\n"
                "    sys.exit(os.WEXITSTATUS(st) if os.WIFEXITED(st) else 99)\n"
            )
            self.assertNotEqual(subprocess.run(["python3", "-c", ptrace_py], capture_output=True).returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
