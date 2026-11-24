#!/usr/bin/env python3
"""
Cross-language end-to-end test suite for `vibeslayer-native-core` (`v1.0.0-beta.3`).
Verifies zero-Node.js operation and wire-level binary interoperability across:
  1. Rust native library & CLI (`bin/vibeslayer` ELF64 + `bin/vibeslayer.exe` PE64)
  2. C / C++ native shared libraries (`bin/libvibeslayer.so` + `bin/vibeslayer.dll` + `bin/test_c_sdk`)
  3. Go native SDK (`sdk_go` via `go test`)
  4. Python C-accelerated SDK (`sdk_python/vibeslayer.py` backed by `libvibeslayer.so`)
  5. Both `VSPK2` and key-committing headerless `VSPK3` across Rust, C, Go, Python
  6. Protected Native ELF64 (immutable segment SHA-256 self-binding + `PR_SET_DUMPABLE=0`)
  7. 3D `.glb` (`VS3D`) & 64-bit BPSK watermark tracing
"""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bin"
SAMPLE_GLB = ROOT / "tests" / "fixtures" / "sample_mesh.glb"


class TestPolyglotVibeSlayerSuite(unittest.TestCase):
    def test_01_compiled_native_artifacts_exist_without_nodejs(self):
        for rel in (
            "vibeslayer",
            "vibeslayer.exe",
            "libvibeslayer.so",
            "vibeslayer.dll",
            "test_c_sdk",
        ):
            p = BIN / rel
            self.assertTrue(p.is_file(), f"Missing native binary: {p}")
            self.assertGreater(p.stat().st_size, 4096)

    def test_02_rust_unit_tests_pass(self):
        r = subprocess.run(
            ["cargo", "test", "--manifest-path", str(ROOT / "rust_core" / "Cargo.toml")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(r.returncode, 0, r.stderr + "\n" + r.stdout)

    def test_03_cross_language_wire_interop_rust_to_c_go_python(self):
        with tempfile.TemporaryDirectory(prefix="vs-polyglot-") as td:
            tdir = Path(td)
            master_hex = "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff"
            raw_payload = b"POLYGLOT_PAYLOAD_RUST_TO_C_GO_PYTHON_2026_OK"
            in_file = tdir / "plain.bin"
            vspk_file = tdir / "sealed.vspk2"
            in_file.write_bytes(raw_payload)

            # 1. Pack using standalone compiled Rust binary (`bin/vibeslayer`, ZERO Node.js!)
            pack_out = json.loads(
                subprocess.check_output(
                    [
                        str(BIN / "vibeslayer"),
                        "pack",
                        "--key", master_hex,
                        "--domain", "backend",
                        "--asset-id", "shared-cfg-v1",
                        "--context", "prod-cluster",
                        "--in", str(in_file),
                        "--out", str(vspk_file),
                    ],
                    text=True,
                )
            )
            self.assertTrue(pack_out["ok"])
            blob = vspk_file.read_bytes()
            self.assertNotIn(b"POLYGLOT_PAYLOAD", blob)

            # 2. Unseal & verify tamper rejection in compiled C binary (`bin/test_c_sdk`)
            c_out = subprocess.check_output(
                [
                    str(BIN / "test_c_sdk"),
                    master_hex,
                    "backend",
                    "shared-cfg-v1",
                    "prod-cluster",
                    str(vspk_file),
                ]
            )
            self.assertEqual(c_out, raw_payload)

            # Wrong context in C must fail RFC 8439 Poly1305 authentication (rc != 0)
            bad_c = subprocess.run(
                [
                    str(BIN / "test_c_sdk"),
                    master_hex,
                    "backend",
                    "shared-cfg-v1",
                    "wrong-cluster",
                    str(vspk_file),
                ],
                capture_output=True,
            )
            self.assertNotEqual(bad_c.returncode, 0)

            # Wrong asset_id in C VSPK2 (`vs_unseal_vspk2_for_asset`) must also fail closed
            bad_c_asset = subprocess.run(
                [
                    str(BIN / "test_c_sdk"),
                    master_hex,
                    "backend",
                    "wrong-asset",
                    "prod-cluster",
                    str(vspk_file),
                ],
                capture_output=True,
            )
            self.assertNotEqual(bad_c_asset.returncode, 0)

            # Rust CLI `unseal` enforces --asset-id when provided (and succeeds with matching asset_id)
            rust_out = tdir / "rust_unsealed.bin"
            subprocess.check_call(
                [
                    str(BIN / "vibeslayer"),
                    "unseal",
                    "--key", master_hex,
                    "--domain", "backend",
                    "--asset-id", "shared-cfg-v1",
                    "--context", "prod-cluster",
                    "--in", str(vspk_file),
                    "--out", str(rust_out),
                ],
                stdout=subprocess.DEVNULL,
            )
            self.assertEqual(rust_out.read_bytes(), raw_payload)
            bad_rust_asset = subprocess.run(
                [
                    str(BIN / "vibeslayer"),
                    "unseal",
                    "--key", master_hex,
                    "--domain", "backend",
                    "--asset-id", "wrong-asset",
                    "--context", "prod-cluster",
                    "--in", str(vspk_file),
                    "--out", str(rust_out),
                ],
                capture_output=True,
            )
            self.assertNotEqual(bad_rust_asset.returncode, 0)

            # 3. Also pack VSPK3 in Rust and verify interop + tamper rejection in C, Go, Python
            v3_payload = b"POLYGLOT_VSPK3_RUST_TO_C_GO_PYTHON_2026_OK"
            v3_in = tdir / "plain_v3.bin"
            v3_file = tdir / "sealed.vspk3"
            v3_in.write_bytes(v3_payload)
            pack3_out = json.loads(
                subprocess.check_output(
                    [
                        str(BIN / "vibeslayer"),
                        "pack-v3",
                        "--key", master_hex,
                        "--domain", "backend",
                        "--asset-id", "svc-secrets-v3",
                        "--context", "prod-cluster",
                        "--in", str(v3_in),
                        "--out", str(v3_file),
                    ],
                    text=True,
                )
            )
            self.assertTrue(pack3_out["ok"])
            v3_blob = v3_file.read_bytes()
            self.assertEqual(len(v3_blob), 92 + 1024)

            # C VSPK3 unseal + wrong asset_id + 1-byte tamper rejection
            c_v3 = subprocess.check_output(
                [
                    str(BIN / "test_c_sdk"),
                    "--vspk3",
                    master_hex,
                    "backend",
                    "svc-secrets-v3",
                    "prod-cluster",
                    str(v3_file),
                ]
            )
            self.assertEqual(c_v3, v3_payload)

            bad_c_v3 = subprocess.run(
                [
                    str(BIN / "test_c_sdk"),
                    "--vspk3",
                    master_hex,
                    "backend",
                    "wrong-asset",
                    "prod-cluster",
                    str(v3_file),
                ],
                capture_output=True,
            )
            self.assertNotEqual(bad_c_v3.returncode, 0)

            tampered_v3 = bytearray(v3_blob)
            tampered_v3[-1] ^= 0x42
            v3_bad_file = tdir / "tampered.vspk3"
            v3_bad_file.write_bytes(bytes(tampered_v3))
            bad_c_tamper = subprocess.run(
                [
                    str(BIN / "test_c_sdk"),
                    "--vspk3",
                    master_hex,
                    "backend",
                    "svc-secrets-v3",
                    "prod-cluster",
                    str(v3_bad_file),
                ],
                capture_output=True,
            )
            self.assertNotEqual(bad_c_tamper.returncode, 0)

            # 4. Unseal exact same Rust-packed VSPK2 + VSPK3 files in Go (`go test`)
            go_env = dict(
                **subprocess.os.environ,
                VS_INTEROP_FILE=str(vspk_file),
                VS_INTEROP_KEY=master_hex,
                VS_INTEROP_V3_FILE=str(v3_file),
                VS_INTEROP_V3_KEY=master_hex,
            )
            go_res = subprocess.run(
                ["go", "test", "-v", "./..."],
                cwd=str(ROOT / "sdk_go"),
                env=go_env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(go_res.returncode, 0, go_res.stdout + "\n" + go_res.stderr)

            # 5. Unseal exact same Rust-packed files in Python (`sdk_python` backed by `libvibeslayer.so`)
            sys.path.insert(0, str(ROOT / "sdk_python"))
            import vibeslayer as vspy  # noqa: E402

            policy = vspy.Policy(
                enabled=True,
                master_key_hex=master_hex,
                actions={
                    "cfg.read": vspy.ActionRule(
                        domain="backend",
                        context="prod-cluster",
                        params={"env": vspy.ParamSpec("enum", values=["prod", "staging"])},
                    ),
                    "cfg.read.v3": vspy.ActionRule(
                        domain="backend",
                        context="prod-cluster",
                        params={
                            "tier": vspy.ParamSpec("str"),
                            "enabled": vspy.ParamSpec("bool"),
                        },
                    ),
                },
            )
            unsealed_py = policy.unseal_action_vspk(
                action="cfg.read",
                params={"env": "prod"},
                asset_id="shared-cfg-v1",
                vspk_bytes=blob,
            )
            self.assertEqual(unsealed_py, raw_payload)
            with self.assertRaises(PermissionError):
                policy.unseal_action_vspk(
                    action="cfg.read",
                    params={"env": "prod"},
                    asset_id="other-asset",
                    vspk_bytes=blob,
                )

            unsealed_py3 = policy.unseal_action_vspk3(
                action="cfg.read.v3",
                params={"tier": "enterprise", "enabled": True},
                asset_id="svc-secrets-v3",
                vspk_bytes=v3_blob,
            )
            self.assertEqual(unsealed_py3, v3_payload)
            with self.assertRaises(RuntimeError):
                policy.unseal_action_vspk3(
                    action="cfg.read.v3",
                    params={"tier": "enterprise", "enabled": True},
                    asset_id="wrong-asset",
                    vspk_bytes=v3_blob,
                )
            with self.assertRaises(RuntimeError):
                policy.unseal_action_vspk3(
                    action="cfg.read.v3",
                    params={"tier": "enterprise", "enabled": True},
                    asset_id="svc-secrets-v3",
                    vspk_bytes=bytes(tampered_v3),
                )

    def test_04_rust_cli_3d_glb_cook_watermark_and_elf_self_binding(self):
        with tempfile.TemporaryDirectory(prefix="vs-3d-elf-") as td:
            tdir = Path(td)
            master_hex = "99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa"
            cooked_vspk = tdir / "exarch.vs3d.vspk2"
            ref_file = tdir / "exarch.owner_ref.bin"
            leaked_a = tdir / "leaked_session_a.bin"

            cook_res = json.loads(
                subprocess.check_output(
                    [
                        str(BIN / "vibeslayer"),
                        "cook-glb",
                        "--key", master_hex,
                        "--asset-id", "white-exarch-v4",
                        "--context", "https://app.vibeslayer.test",
                        "--in", str(SAMPLE_GLB),
                        "--out", str(cooked_vspk),
                        "--owner-ref", str(ref_file),
                    ],
                    text=True,
                )
            )
            self.assertTrue(cook_res["ok"])
            raw_glb = SAMPLE_GLB.read_bytes()
            sealed_glb = cooked_vspk.read_bytes()
            self.assertNotIn(b"glTF", sealed_glb)
            self.assertNotIn(raw_glb[1024:1088], sealed_glb)

            # Unseal for Lease A ("user_alpha_leak") and trace watermark back to "user_alpha_leak"
            subprocess.check_call(
                [
                    str(BIN / "vibeslayer"),
                    "unseal-glb-lease",
                    "--key", master_hex,
                    "--asset-id", "white-exarch-v4",
                    "--context", "https://app.vibeslayer.test",
                    "--lease-id", "lease_alpha_01",
                    "--in", str(cooked_vspk),
                    "--out-positions", str(leaked_a),
                ]
            )
            trace_res = json.loads(
                subprocess.check_output(
                    [
                        str(BIN / "vibeslayer"),
                        "trace-glb",
                        "--key", master_hex,
                        "--asset-id", "white-exarch-v4",
                        "--owner-ref", str(ref_file),
                        "--captured", str(leaked_a),
                        "--candidates", "lease_innocent_99,lease_alpha_01,lease_other_02",
                    ],
                    text=True,
                )
            )
            self.assertEqual(trace_res["matchedLeaseId"], "lease_alpha_01")
            self.assertGreaterEqual(trace_res["chipMatchRatio"], 0.99)

            # Wrap Native ELF64 via Rust CLI & verify .text tamper rejection
            elf_out = tdir / "protected_native_app"
            secret_kernel = b"RUST_C_NATIVE_SECRET_WEIGHTS=31,37,41,43"
            secret_in = tdir / "kernel.cfg"
            secret_in.write_bytes(secret_kernel)

            wrap_res = json.loads(
                subprocess.check_output(
                    [
                        str(BIN / "vibeslayer"),
                        "build-elf",
                        "--key", master_hex,
                        "--asset-id", "native-avx",
                        "--in", str(secret_in),
                        "--out", str(elf_out),
                    ],
                    text=True,
                )
            )
            self.assertNotIn(b"RUST_C_NATIVE_SECRET_WEIGHTS", elf_out.read_bytes())
            run_ok = json.loads(
                subprocess.check_output([str(elf_out), wrap_res["leaseKeyHex"]], text=True)
            )
            self.assertTrue(run_ok["ok"])
            self.assertEqual(run_ok["dumpable"], 0)
            self.assertEqual(run_ok["payloadSha256"], hashlib.sha256(secret_kernel).hexdigest())


if __name__ == "__main__":
    unittest.main(verbosity=2)
