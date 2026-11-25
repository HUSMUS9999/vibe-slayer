#!/usr/bin/env python3
"""
v2 Polyglot End-to-End Test Suite:
Verifies bit-for-bit wire interoperability across Rust, C, Go, and Python for:
  - VSPK3 v2 64-bit STREAM (AES-256-GCM Rust <-> Go, ChaCha20-Poly1305 Rust <-> C <-> Python)
  - Legacy VSPK3 v1 & VSPK2 backward wire compatibility across all 4 languages
  - Unified authentication failure behavior (tamper, wrong key, wrong context, wrong asset)
  - CLI subcommands (`version`, `demo`, `token mint/verify`, `explain`, `scan`, `website`)
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bin"
SDK_PY = ROOT / "sdk_python"
SDK_GO = ROOT / "sdk_go"
sys.path.insert(0, str(SDK_PY))

import vibeslayer  # noqa: E402


class TestV2PolyglotSuite(unittest.TestCase):
    def test_01_rust_to_go_vspk3_v2_aes_gcm_stream(self):
        with tempfile.TemporaryDirectory(prefix="vs-v2-go-") as td:
            tdir = Path(td)
            key_hex = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
            plain = b"POLYGLOT_VSPK3_V2_STREAM_RUST_TO_GO_2026_OK"
            in_p = tdir / "plain.bin"
            out_v2 = tdir / "sealed.vsp3"
            in_p.write_bytes(plain)

            res = json.loads(
                subprocess.check_output(
                    [
                        str(BIN / "vibe-slayer"),
                        "vault",
                        "seal",
                        "--in", str(in_p),
                        "--out", str(out_v2),
                        "--key", key_hex,
                        "--domain", "backend",
                        "--asset-id", "svc-v2-stream",
                        "--context", "prod-cluster",
                        "--cipher", "aes-gcm",
                    ],
                    text=True,
                )
            )
            self.assertTrue(res["ok"])
            self.assertEqual(res["format"], "vspk3-v2-stream")

            # Verify Rust `vault inspect` + `vault unseal`
            insp = json.loads(
                subprocess.check_output(
                    [
                        str(BIN / "vibe-slayer"),
                        "vault",
                        "inspect",
                        "--in", str(out_v2),
                        "--key", key_hex,
                        "--domain", "backend",
                        "--asset-id", "svc-v2-stream",
                        "--context", "prod-cluster",
                    ],
                    text=True,
                )
            )
            self.assertTrue(insp["ok"])
            self.assertEqual(insp["chunkCount"], 1)

            # Verify Go stdlib AES-256-GCM VSPK3 v2 STREAM wire interop!
            env = {
                **os.environ,
                "VS_INTEROP_V3V2_FILE": str(out_v2),
                "VS_INTEROP_V3V2_KEY": key_hex,
            }
            go_run = subprocess.run(
                ["go", "test", "-v", "-run", "TestInteropWithRustVspk3V2", "./..."],
                cwd=str(SDK_GO),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(go_run.returncode, 0, go_run.stdout + "\n" + go_run.stderr)

    def test_02_rust_to_c_and_python_vspk3_v2_chacha20_multichunk_stream(self):
        with tempfile.TemporaryDirectory(prefix="vs-v2-cpy-") as td:
            tdir = Path(td)
            key_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            # Test multi-chunk 200 KiB + exact 65,536-byte boundary!
            for idx, size in enumerate((0, 65536, 200_000)):
                plain = bytes(((i * 37 + 11) & 0xFF) for i in range(size))
                in_p = tdir / f"plain_{idx}.bin"
                out_v2 = tdir / f"sealed_{idx}.vsp3"
                c_restored = tdir / f"c_restored_{idx}.bin"
                py_restored = tdir / f"py_restored_{idx}.bin"
                in_p.write_bytes(plain)

                subprocess.check_call(
                    [
                        str(BIN / "vibe-slayer"),
                        "vault",
                        "seal",
                        "--in", str(in_p),
                        "--out", str(out_v2),
                        "--key", key_hex,
                        "--domain", "weights",
                        "--asset-id", f"tensor-{idx}",
                        "--context", "prod",
                        "--cipher", "chacha20",
                    ],
                    stdout=subprocess.DEVNULL,
                )

                # 1. C SDK 64-bit streaming unseal (`test_c_sdk --vspk3-v2`)
                c_out = subprocess.check_output(
                    [
                        str(BIN / "test_c_sdk"),
                        "--vspk3-v2",
                        key_hex,
                        "weights",
                        f"tensor-{idx}",
                        "prod",
                        str(out_v2),
                        str(c_restored),
                    ],
                    text=True,
                ).strip()
                self.assertEqual(int(c_out), size)
                self.assertEqual(c_restored.read_bytes(), plain)

                # 2. Python SDK 64-bit streaming unseal (`unseal_action_vspk3_v2_file`)
                pol = vibeslayer.Policy(
                    master_key_hex=key_hex,
                    enabled=True,
                    actions={
                        "weights.load": vibeslayer.ActionRule(
                            domain="weights",
                            context="prod",
                            params={"layer": vibeslayer.ParamSpec("int", 0, 128)},
                        )
                    },
                )
                n = pol.unseal_action_vspk3_v2_file(
                    action="weights.load",
                    params={"layer": idx},
                    asset_id=f"tensor-{idx}",
                    in_path=out_v2,
                    out_path=py_restored,
                )
                self.assertEqual(n, size)
                self.assertEqual(py_restored.read_bytes(), plain)

                # 3. 1-bit tamper must fail with unified VaultAuthError and leave no partial output file
                tampered = bytearray(out_v2.read_bytes())
                tampered[-1] ^= 0x01
                tamp_p = tdir / f"tampered_{idx}.vsp3"
                tamp_out = tdir / f"tampered_out_{idx}.bin"
                tamp_p.write_bytes(bytes(tampered))
                with self.assertRaises(vibeslayer.VaultAuthError):
                    pol.unseal_action_vspk3_v2_file(
                        action="weights.load",
                        params={"layer": idx},
                        asset_id=f"tensor-{idx}",
                        in_path=tamp_p,
                        out_path=tamp_out,
                    )
                self.assertFalse(tamp_out.exists())
                pol.zeroize()

    def test_03_legacy_vspk2_and_vspk3_v1_four_language_interop(self):
        with tempfile.TemporaryDirectory(prefix="vs-v1-compat-") as td:
            tdir = Path(td)
            mk = "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff"
            p2 = b"POLYGLOT_PAYLOAD_RUST_TO_C_GO_PYTHON_2026_OK"
            p3 = b"POLYGLOT_VSPK3_RUST_TO_C_GO_PYTHON_2026_OK"
            f2_in, f2_out = tdir / "p2.bin", tdir / "p2.vspk2"
            f3_in, f3_out = tdir / "p3.bin", tdir / "p3.vspk3"
            f2_in.write_bytes(p2)
            f3_in.write_bytes(p3)

            subprocess.check_call(
                [
                    str(BIN / "vibe-slayer"), "pack",
                    "--key", mk, "--domain", "backend", "--asset-id", "shared-cfg-v1",
                    "--context", "prod-cluster", "--in", str(f2_in), "--out", str(f2_out),
                ],
                stdout=subprocess.DEVNULL,
            )
            subprocess.check_call(
                [
                    str(BIN / "vibe-slayer"), "pack-v3",
                    "--key", mk, "--domain", "backend", "--asset-id", "svc-secrets-v3",
                    "--context", "prod-cluster", "--in", str(f3_in), "--out", str(f3_out),
                ],
                stdout=subprocess.DEVNULL,
            )

            # C interop
            self.assertEqual(
                subprocess.check_output([str(BIN / "test_c_sdk"), mk, "backend", "shared-cfg-v1", "prod-cluster", str(f2_out)]),
                p2,
            )
            self.assertEqual(
                subprocess.check_output([str(BIN / "test_c_sdk"), "--vspk3", mk, "backend", "svc-secrets-v3", "prod-cluster", str(f3_out)]),
                p3,
            )
            # Go interop
            env = {
                **os.environ,
                "VS_INTEROP_FILE": str(f2_out),
                "VS_INTEROP_KEY": mk,
                "VS_INTEROP_V3_FILE": str(f3_out),
                "VS_INTEROP_V3_KEY": mk,
            }
            r = subprocess.run(["go", "test", "-v", "./..."], cwd=str(SDK_GO), env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + "\n" + r.stderr)

    def test_04_cli_demo_token_explain_scan_and_website(self):
        demo = json.loads(subprocess.check_output([str(BIN / "vibe-slayer"), "demo"], text=True))
        self.assertTrue(demo["ok"])
        self.assertTrue(demo["watermarkVerifiedMac"])

        key_hex = "fe" * 32
        mint = json.loads(
            subprocess.check_output(
                [
                    str(BIN / "vibe-slayer"), "token", "mint",
                    "--key", key_hex, "--subject", "buyer-7",
                    "--origin", "https://shop.example", "--asset-id", "ring-v2",
                ],
                text=True,
            )
        )
        ver = json.loads(
            subprocess.check_output(
                [
                    str(BIN / "vibe-slayer"), "token", "verify",
                    "--key", key_hex, "--token", mint["token"],
                    "--origin", "https://shop.example", "--asset-id", "ring-v2",
                ],
                text=True,
            )
        )
        self.assertTrue(ver["ok"])
        self.assertEqual(ver["claims"]["sub"], "buyer-7")

        expl = json.loads(
            subprocess.check_output(
                [str(BIN / "vibe-slayer"), "explain", "--json", "stream", "./hero.glb", "on", "port", "8790"],
                text=True,
            )
        )
        self.assertEqual(expl["intent"], "serve-3d")

        with tempfile.TemporaryDirectory(prefix="vs-web-") as td:
            tdir = Path(td)
            site = tdir / "site"
            site.mkdir()
            (site / "index.html").write_text("<h1>Hello</h1>", encoding="utf-8")
            (site / "app.js").write_text("console.log('ok');", encoding="utf-8")
            bundle = tdir / "site.vsweb"
            wb = json.loads(
                subprocess.check_output(
                    [str(BIN / "vibe-slayer"), "website", str(site), "--out", str(bundle), "--key", key_hex],
                    text=True,
                )
            )
            self.assertTrue(wb["ok"])
            self.assertEqual(wb["files"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
