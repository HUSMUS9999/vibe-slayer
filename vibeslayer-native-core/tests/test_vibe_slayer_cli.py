#!/usr/bin/env python3
"""
End-to-end verification suite for the standalone zero-Node `vibe-slayer` CLI binary:
1. Standalone native ELF64 + Windows PE32+ verification (zero Node.js dependency).
2. Multi-language repo & binary auto-protection:
   - `scan` secret detection & engine routing
   - `protect` vault creation (0600), `.gitignore` update, key-free manifest
   - `test` cryptographic self-verification
   - `run` freestanding ELF execution with LD_PRELOAD scrubbed & pipe FD lease
   - `watermark` + noisy (±2 LSB) O(1) `trace` on 3D GLB stream
   - `unseal` lossless byte-for-byte restoration
3. Zero-Node live website runtime protection (`website` + `serve`):
   - Scraper HTML check (zero plaintext secrets leaked, single-use ticket issued)
   - Security rejection tests: missing/mismatched Origin (403), invalid ticket (403),
     off-curve P-256 client key (400), replayed ticket (403)
   - Live OpenSSL SECP256R1 ECDH + HKDF-SHA256 + AES-256-GCM key unwrap & asset decryption
"""

import hashlib
import http.client
import json
import os
import re
import socket
import stat
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


CORE_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = CORE_ROOT.parent
VIBE_SLAYER = REPO_ROOT / "vibe-slayer"
BIN_LINUX = CORE_ROOT / "bin" / "vibe-slayer"
BIN_WIN = CORE_ROOT / "bin" / "vibe-slayer.exe"
PROTECT_SHIM = REPO_ROOT / "protect"


def build_minimal_glb(num_floats: int = 1536) -> bytes:
    """Build a valid glTF 2.0 binary (.glb) container with deterministic float payload."""
    bin_buf = b"".join(
        struct.pack("<f", ((i % 251) - 125) * 0.125) for i in range(num_floats)
    )
    json_raw = json.dumps(
        {
            "asset": {"version": "2.0"},
            "buffers": [{"byteLength": len(bin_buf)}],
        },
        separators=(",", ":"),
    ).encode("utf-8")
    pad = (4 - (len(json_raw) % 4)) % 4
    json_padded = json_raw + (b" " * pad)
    total_len = 12 + 8 + len(json_padded) + 8 + len(bin_buf)
    return b"".join(
        [
            b"glTF",
            struct.pack("<II", 2, total_len),
            struct.pack("<II", len(json_padded), 0x4E4F534A),
            json_padded,
            struct.pack("<II", len(bin_buf), 0x004E4942),
            bin_buf,
        ]
    )


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_cli_json(args: list[str], cwd: Path | None = None) -> dict:
    proc = subprocess.run(
        [str(VIBE_SLAYER), *args],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"vibe-slayer {' '.join(args)} failed (rc={proc.returncode}):\n"
            f"stdout={proc.stdout}\nstderr={proc.stderr}"
        )
    return json.loads(proc.stdout)


class TestVibeSlayerCli(unittest.TestCase):
    def test_01_binary_is_standalone_native_elf_no_node(self):
        for p in (VIBE_SLAYER, BIN_LINUX):
            self.assertTrue(p.is_file(), f"Missing built binary: {p}")

        self.assertEqual(VIBE_SLAYER.read_bytes()[:4], b"\x7fELF")
        self.assertEqual(BIN_LINUX.read_bytes()[:4], b"\x7fELF")
        if BIN_WIN.is_file():
            self.assertEqual(BIN_WIN.read_bytes()[:2], b"MZ")

        help_res = subprocess.run(
            [str(VIBE_SLAYER), "--help"],
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("vibe-slayer", help_res.stdout)
        self.assertIn("website", help_res.stdout)
        self.assertIn("serve", help_res.stdout)

        shim_txt = PROTECT_SHIM.read_text(encoding="utf-8")
        self.assertTrue(shim_txt.startswith("#!/bin/sh"))
        self.assertIn("vibe-slayer", shim_txt)
        self.assertNotIn("node", shim_txt)

    def test_02_repo_auto_protect_run_watermark_trace_and_unseal(self):
        with tempfile.TemporaryDirectory(prefix="vs-repo-test-") as td:
            tdir = Path(td)
            reg = tdir / "registry.json"
            repo = tdir / "sample-repo"
            out_dir = tdir / "sample-repo-protected"
            restored_dir = tdir / "sample-repo-restored"

            for sub in ("src", "bin", "assets"):
                (repo / sub).mkdir(parents=True, exist_ok=True)

            files_plain = {
                "src/engine.py": b"def score(x: int) -> int:\n    return x * 42 + 7\n",
                "src/core.rs": b"pub fn kernel(v: u64) -> u64 { v ^ 0x55aa }\n",
                "src/worker.go": b"package main\nfunc Work(n int) int { return n + 9 }\n",
                ".env": b"OPENAI_API_KEY=sk-live1234567890abcdefghijklmnop\n",
                "assets/hero.glb": build_minimal_glb(),
            }
            for rel, content in files_plain.items():
                (repo / rel).write_bytes(content)
            (repo / "README.md").write_text("# Sample Repo\n", encoding="utf-8")

            tool_c = tdir / "secret_tool.c"
            tool_c.write_text(
                '#include <stdio.h>\n'
                'int main(int argc, char **argv) {\n'
                '  printf("NATIVE_TOOL_OK:%s\\n", argc > 1 ? argv[1] : "none");\n'
                '  return 0;\n'
                '}\n',
                encoding="utf-8",
            )
            subprocess.check_call(
                ["gcc", "-O2", "-fPIE", "-pie", str(tool_c), "-o", str(repo / "bin" / "secret_tool")]
            )

            # 1. Scan
            scan = run_cli_json(["scan", str(repo), "--json", "--registry", str(reg)])
            self.assertTrue(scan["ok"])
            self.assertGreaterEqual(len(scan["secretWarnings"]), 1)
            by_rel = {item["relPath"]: item for item in scan["items"]}
            self.assertEqual(by_rel["bin/secret_tool"]["engine"], "wrap-elf")
            self.assertEqual(by_rel["assets/hero.glb"]["engine"], "glb-dual")
            self.assertEqual(by_rel[".env"]["engine"], "vspk3")
            self.assertEqual(by_rel["README.md"]["engine"], "copy-public")

            # 2. Protect repo (default command when first arg is a path)
            prot = run_cli_json(
                [str(repo), "-o", str(out_dir), "--json", "--registry", str(reg)]
            )
            self.assertTrue(prot["ok"])

            keys_path = repo / ".vibeslayer" / "keys.json"
            self.assertTrue(keys_path.is_file())
            self.assertEqual(stat.S_IMODE(keys_path.stat().st_mode), 0o600)

            gitignore = (repo / ".gitignore").read_text(encoding="utf-8")
            self.assertIn(".vibeslayer/", gitignore)
            self.assertIn(".env", gitignore)

            manifest_txt = (out_dir / "vibeslayer.manifest.json").read_text(encoding="utf-8")
            self.assertNotIn("masterKeyHex", manifest_txt)
            self.assertNotIn("leaseKeyHex", manifest_txt)

            # 3. Auto-test protected directory
            tested = run_cli_json(["test", str(out_dir), "--json", "--registry", str(reg)])
            self.assertTrue(tested["ok"])

            # 4. Execute wrapped ELF via `vibe-slayer run` with LD_PRELOAD poisoning
            run_env = os.environ.copy()
            run_env["LD_PRELOAD"] = "/nonexistent_evil_hook.so"
            run_proc = subprocess.run(
                [
                    str(VIBE_SLAYER),
                    "run",
                    str(out_dir / "bin" / "secret_tool"),
                    "--registry",
                    str(reg),
                    "--",
                    "HELLO_RUST",
                ],
                env=run_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(run_proc.returncode, 0, run_proc.stderr)
            self.assertIn("NATIVE_TOOL_OK:HELLO_RUST", run_proc.stdout)

            # 5. Watermark & noisy O(1) trace
            pos_bin = tdir / "buyer42_pos.bin"
            noisy_bin = tdir / "buyer42_noisy.bin"
            wm = run_cli_json(
                [
                    "watermark",
                    str(out_dir / "assets" / "hero.glb.vs3d"),
                    "--buyer",
                    "buyer-42@example.com",
                    "-o",
                    str(pos_bin),
                    "--json",
                    "--registry",
                    str(reg),
                ]
            )
            self.assertTrue(wm["ok"])

            raw_pos = pos_bin.read_bytes()
            coords = list(struct.unpack(f"<{len(raw_pos) // 2}h", raw_pos))
            noisy = [
                max(-32767, min(32767, c + (2 if (i % 3) == 0 else -2)))
                for i, c in enumerate(coords)
            ]
            noisy_bin.write_bytes(struct.pack(f"<{len(noisy)}h", *noisy))

            traced = run_cli_json(["trace", str(noisy_bin), "--json", "--registry", str(reg)])
            self.assertTrue(traced["ok"])
            self.assertEqual(traced["decodedWatermarkIdHex"], wm["wmIdHex"])
            self.assertEqual(traced["buyer"], "buyer-42@example.com")
            self.assertGreaterEqual(traced["meanChipConfidence"], 0.45)

            # 6. Lossless unseal restoration
            unsealed = run_cli_json(
                [
                    "unseal",
                    str(out_dir),
                    "-o",
                    str(restored_dir),
                    "--json",
                    "--registry",
                    str(reg),
                ]
            )
            self.assertTrue(unsealed["ok"])
            for rel, expected in files_plain.items():
                restored_bytes = (restored_dir / rel).read_bytes()
                self.assertEqual(
                    hashlib.sha256(restored_bytes).hexdigest(),
                    hashlib.sha256(expected).hexdigest(),
                    f"Mismatch after unseal for {rel}",
                )

    def test_03_live_website_runtime_protection_and_ecdh_unwrap(self):
        with tempfile.TemporaryDirectory(prefix="vs-web-test-") as td:
            tdir = Path(td)
            reg = tdir / "registry.json"
            site_dir = tdir / "my-site"
            web_out = tdir / "my-site-protected"
            site_dir.mkdir(parents=True, exist_ok=True)

            site_files = {
                "index.html": b"<!doctype html><html><body><h1>TOP_SECRET_ALPHA_HTML_9911</h1></body></html>\n",
                "app.js": b'const SECRET_ALGO = "OMEGA_JS_7788";\nconsole.log(SECRET_ALGO);\n',
                "styles.css": b"/* SECRET_CSS_5566 */\nbody { background: #090d16; color: #f8fafc; }\n",
            }
            for rel, data in site_files.items():
                (site_dir / rel).write_bytes(data)

            port = pick_free_port()
            addr = f"127.0.0.1:{port}"
            origin = f"http://{addr}"

            # 1. Seal website bundle
            sealed = run_cli_json(
                [
                    "website",
                    str(site_dir),
                    "-o",
                    str(web_out),
                    "--origin",
                    origin,
                    "--json",
                    "--registry",
                    str(reg),
                ]
            )
            self.assertTrue(sealed["ok"])
            self.assertEqual(sealed["sealedFiles"], 3)

            boot_html = (web_out / "index.html").read_text(encoding="utf-8")
            manifest_txt = (web_out / "vibeslayer.web.json").read_text(encoding="utf-8")
            self.assertNotIn("masterKey", manifest_txt)
            self.assertNotIn("siteKey", manifest_txt)

            raw_assets = b"".join(p.read_bytes() for p in (web_out / "assets").glob("*.vsweb"))
            for secret_marker in (
                b"TOP_SECRET_ALPHA_HTML_9911",
                b"OMEGA_JS_7788",
                b"SECRET_CSS_5566",
            ):
                self.assertNotIn(secret_marker, boot_html.encode("utf-8"))
                self.assertNotIn(secret_marker, manifest_txt.encode("utf-8"))
                self.assertNotIn(secret_marker, raw_assets)

            # 2. Launch zero-Node runtime server
            srv = subprocess.Popen(
                [
                    str(VIBE_SLAYER),
                    "serve",
                    str(web_out),
                    "--addr",
                    addr,
                    "--origin",
                    origin,
                    "--registry",
                    str(reg),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                # Poll health endpoint until ready
                ready = False
                for _ in range(50):
                    if srv.poll() is not None:
                        out, err = srv.communicate(timeout=1)
                        raise AssertionError(
                            f"serve exited early ({srv.returncode}): stdout={out}\nstderr={err}"
                        )
                    try:
                        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=0.5)
                        conn.request("GET", "/__vibeslayer/health")
                        resp = conn.getresponse()
                        resp.read()
                        conn.close()
                        if resp.status == 200:
                            ready = True
                            break
                    except OSError:
                        time.sleep(0.05)
                self.assertTrue(ready, "Runtime server did not become ready in time")

                def http_req(method: str, path: str, body: bytes | None = None, headers: dict | None = None):
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2.0)
                    conn.request(method, path, body=body, headers=headers or {})
                    r = conn.getresponse()
                    data = r.read()
                    hdrs = {k.lower(): v for k, v in r.getheaders()}
                    conn.close()
                    return r.status, data, hdrs

                def fetch_ticket() -> str:
                    st, body, hdrs = http_req("GET", "/")
                    self.assertEqual(st, 200)
                    csp = hdrs.get("content-security-policy", "")
                    self.assertIn("default-src 'self'", csp)
                    self.assertIn("frame-ancestors 'none'", csp)
                    html = body.decode("utf-8")
                    self.assertNotIn("TOP_SECRET_ALPHA_HTML_9911", html)
                    self.assertNotIn("__VS_RUNTIME_TICKET__", html)
                    m = re.search(r'<meta\s+name="vs-ticket"\s+content="([^"]+)"', html)
                    self.assertIsNotNone(m, f"Missing vs-ticket meta tag in:\n{html}")
                    return m.group(1)

                # Verify loader.js masks all protocol property keys
                st, ldr_b, _ = http_req("GET", "/__vibeslayer/loader.js")
                self.assertEqual(st, 200)
                ldr_txt = ldr_b.decode("utf-8")
                for key_lit in (
                    "clientPublicKeyHex",
                    "serverPublicKeyHex",
                    "sealedManifestHex",
                    "manifestIvHex",
                    "wrappedKeyHex",
                    "/__vibeslayer/lease",
                ):
                    self.assertNotIn(key_lit, ldr_txt)

                # Generate valid SECP256R1 keypair + mutated off-curve key
                client_priv = ec.generate_private_key(ec.SECP256R1())
                client_pub = client_priv.public_key().public_bytes(
                    serialization.Encoding.X962,
                    serialization.PublicFormat.UncompressedPoint,
                )
                bad_pub = bytearray(client_pub)
                bad_pub[-1] ^= 0x01

                # Security check A: missing Origin -> 403 ORIGIN_DENIED
                t1 = fetch_ticket()
                st, data, _ = http_req(
                    "POST",
                    "/__vibeslayer/lease",
                    body=json.dumps(
                        {"clientPublicKeyHex": client_pub.hex(), "ticket": t1}
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                )
                self.assertEqual(st, 403)
                self.assertEqual(json.loads(data)["error"], "ORIGIN_DENIED")

                # Security check B: wrong Origin -> 403 ORIGIN_DENIED
                st, data, _ = http_req(
                    "POST",
                    "/__vibeslayer/lease",
                    body=json.dumps(
                        {"clientPublicKeyHex": client_pub.hex(), "ticket": t1}
                    ).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "Origin": "https://evil-cloner.example",
                    },
                )
                self.assertEqual(st, 403)
                self.assertEqual(json.loads(data)["error"], "ORIGIN_DENIED")

                # Security check C: invalid/missing ticket -> 403 TICKET_REPLAYED_OR_INVALID
                st, data, _ = http_req(
                    "POST",
                    "/__vibeslayer/lease",
                    body=json.dumps(
                        {"clientPublicKeyHex": client_pub.hex(), "ticket": "bad.ticket.val"}
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Origin": origin},
                )
                self.assertEqual(st, 403)
                self.assertEqual(json.loads(data)["error"], "TICKET_REPLAYED_OR_INVALID")

                # Security check D: off-curve P-256 client key -> 400 INVALID_CLIENT_PUBLIC_KEY
                st, data, _ = http_req(
                    "POST",
                    "/__vibeslayer/lease",
                    body=json.dumps(
                        {"clientPublicKeyHex": bytes(bad_pub).hex(), "ticket": t1}
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Origin": origin},
                )
                self.assertEqual(st, 400)
                self.assertEqual(json.loads(data)["error"], "INVALID_CLIENT_PUBLIC_KEY")

                # Positive check: valid fresh ticket + valid Origin + live ECDH P-256 handshake
                fresh_ticket = fetch_ticket()
                st, data, _ = http_req(
                    "POST",
                    "/__vibeslayer/lease",
                    body=json.dumps(
                        {"clientPublicKeyHex": client_pub.hex(), "ticket": fresh_ticket}
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Origin": origin},
                )
                self.assertEqual(st, 200, data.decode("utf-8", errors="replace"))
                lease = json.loads(data)
                self.assertTrue(lease["ok"])
                self.assertEqual(lease["origin"], origin)

                # Fresh per-lease manifestIvHex check (no static manifest IV across leases)
                fresh_ticket_2 = fetch_ticket()
                st2, data2, _ = http_req(
                    "POST",
                    "/__vibeslayer/lease",
                    body=json.dumps(
                        {"clientPublicKeyHex": client_pub.hex(), "ticket": fresh_ticket_2}
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Origin": origin},
                )
                self.assertEqual(st2, 200)
                lease2 = json.loads(data2)
                self.assertNotEqual(lease["manifestIvHex"], lease2["manifestIvHex"])
                self.assertNotEqual(lease["sealedManifestHex"], lease2["sealedManifestHex"])

                srv_pub_bytes = bytes.fromhex(lease["serverPublicKeyHex"])
                srv_pub = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), srv_pub_bytes
                )
                shared_32 = client_priv.exchange(ec.ECDH(), srv_pub)
                wrap_info = f"VSWEB1_WRAP|{origin}".encode("utf-8")
                wrap_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=lease["leaseId"].encode("utf-8"),
                    info=wrap_info,
                ).derive(shared_32)
                site_key = AESGCM(wrap_key).decrypt(
                    bytes.fromhex(lease["wrapIvHex"]),
                    bytes.fromhex(lease["wrappedKeyHex"]),
                    wrap_info,
                )
                self.assertEqual(len(site_key), 32)

                # Manifest endpoint is sealed and must fail closed over HTTP (403)
                st, m_err, _ = http_req("GET", "/__vibeslayer/vibeslayer.web.json")
                self.assertEqual(st, 403)
                self.assertEqual(json.loads(m_err)["error"], "MANIFEST_SEALED_IN_LEASE")

                # Decrypt sealed manifest from lease response & all 3 sealed assets via AES-256-GCM
                manifest_raw = AESGCM(site_key).decrypt(
                    bytes.fromhex(lease["manifestIvHex"]),
                    bytes.fromhex(lease["sealedManifestHex"]),
                    b"VSWEB1|__manifest__",
                )
                manifest = json.loads(manifest_raw)
                self.assertEqual(len(manifest["files"]), 3)

                for rel_path, info in manifest["files"].items():
                    st, blob, _ = http_req("GET", "/" + info["vsweb"])
                    self.assertEqual(st, 200)
                    plain = AESGCM(site_key).decrypt(
                        blob[:12],
                        blob[12:],
                        f"VSWEB1|{rel_path}".encode("utf-8"),
                    )
                    self.assertEqual(plain, site_files[rel_path])

                # Replay check: re-submitting the already-consumed ticket fails closed (403)
                st, data, _ = http_req(
                    "POST",
                    "/__vibeslayer/lease",
                    body=json.dumps(
                        {"clientPublicKeyHex": client_pub.hex(), "ticket": fresh_ticket}
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Origin": origin},
                )
                self.assertEqual(st, 403)
                self.assertEqual(json.loads(data)["error"], "TICKET_REPLAYED_OR_INVALID")
            finally:
                srv.terminate()
                try:
                    srv.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    srv.kill()
                    srv.wait(timeout=3)
                if srv.stdout:
                    srv.stdout.close()
                if srv.stderr:
                    srv.stderr.close()

    def test_04_website_harden_js_and_auth_gate(self):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        with tempfile.TemporaryDirectory(prefix="vs-web-hard-") as td:
            tdir = Path(td)
            reg = tdir / "registry.json"
            site_dir = tdir / "site-src"
            web_out = tdir / "site-hardened"
            site_dir.mkdir(parents=True, exist_ok=True)

            js_src = (
                '"use strict";\n'
                '// PRIVATE_DEV_COMMENT_9182\n'
                'export class DemoCard extends HTMLElement {\n'
                '  secret() {\n'
                '    const a = "OMEGA_WEBCOMP_SECRET_4419";\n'
                '    const b = "/assets/halo-mesh.json";\n'
                '    return a + "|" + b;\n'
                '  }\n'
                '}\n'
            )
            (site_dir / "index.html").write_text("<!doctype html><html><body>OK</body></html>\n", encoding="utf-8")
            (site_dir / "card.mjs").write_text(js_src, encoding="utf-8")

            port = pick_free_port()
            addr = f"127.0.0.1:{port}"
            origin = f"http://{addr}"

            sealed = run_cli_json(
                [
                    "website",
                    str(site_dir),
                    "-o",
                    str(web_out),
                    "--harden-js",
                    "--json",
                    "--registry",
                    str(reg),
                ]
            )
            self.assertTrue(sealed["ok"])
            self.assertEqual(sealed["sealedFiles"], 2)

            hmac_key_hex = "a5" * 32
            minted = run_cli_json(
                ["mint-token", "--key", hmac_key_hex, "--buyer", "buyer_4281", "--ttl", "300"]
            )
            self.assertTrue(minted["ok"])
            signed_tok = minted["token"]
            self.assertTrue(signed_tok.startswith("vs1.buyer_4281."))

            srv = subprocess.Popen(
                [
                    str(VIBE_SLAYER),
                    "serve",
                    str(web_out),
                    "--addr",
                    addr,
                    "--registry",
                    str(reg),
                    "--auth-secret",
                    "vs-site-gate-2026",
                    "--auth-hmac-key",
                    hmac_key_hex,
                    "--trust-proxy",
                    "127.0.0.1",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                ready = False
                for _ in range(50):
                    if srv.poll() is not None:
                        out, err = srv.communicate(timeout=1)
                        raise AssertionError(f"serve exited early: {out}\n{err}")
                    try:
                        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=0.5)
                        conn.request("GET", "/__vibeslayer/health")
                        resp = conn.getresponse()
                        resp.read()
                        conn.close()
                        if resp.status == 200:
                            ready = True
                            break
                    except OSError:
                        time.sleep(0.05)
                self.assertTrue(ready)

                def http_req(method: str, path: str, body: bytes | None = None, headers: dict | None = None):
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2.0)
                    conn.request(method, path, body=body, headers=headers or {})
                    r = conn.getresponse()
                    data = r.read()
                    conn.close()
                    return r.status, data

                # Unauthenticated probes rejected with 401 AUTH_REQUIRED (manifest always 403)
                for route in ["/", "/index.html", "/__vibeslayer/loader.js", "/assets/fake.vsweb"]:
                    st, data = http_req("GET", route)
                    self.assertEqual(st, 401, f"expected 401 on {route}")
                    self.assertEqual(json.loads(data)["error"], "AUTH_REQUIRED")

                # Tampered signed token rejected with 401
                bad_tok = signed_tok[:-1] + ("0" if signed_tok[-1] != "0" else "1")
                st, data = http_req("GET", "/", headers={"Authorization": f"Bearer {bad_tok}"})
                self.assertEqual(st, 401)

                st, data = http_req(
                    "POST",
                    "/__vibeslayer/lease",
                    body=b"{}",
                    headers={"Content-Type": "application/json", "Origin": origin},
                )
                self.assertEqual(st, 401)
                self.assertEqual(json.loads(data)["error"], "AUTH_REQUIRED")

                st, data = http_req("GET", "/__vibeslayer/vibeslayer.web.json")
                self.assertEqual(st, 403)
                self.assertEqual(json.loads(data)["error"], "MANIFEST_SEALED_IN_LEASE")

                # Unpinned --origin still rejects spoofed Host+Origin (`evil.com`) against bound SocketAddr
                st, html_b = http_req(
                    "GET",
                    "/",
                    headers={
                        "Authorization": f"Bearer {signed_tok}",
                        "X-Forwarded-For": "1.2.3.4, 203.0.113.10",
                    },
                )
                self.assertEqual(st, 200)
                m = re.search(r'<meta\s+name="vs-ticket"\s+content="([^"]+)"', html_b.decode("utf-8"))
                self.assertIsNotNone(m)
                ticket = m.group(1)

                client_priv = ec.generate_private_key(ec.SECP256R1())
                client_pub = client_priv.public_key().public_bytes(
                    serialization.Encoding.X962,
                    serialization.PublicFormat.UncompressedPoint,
                )

                # Spoofed Host: evil.com + Origin: http://evil.com must be rejected (403)
                st, evil_b = http_req(
                    "POST",
                    "/__vibeslayer/lease",
                    body=json.dumps({"clientPublicKeyHex": client_pub.hex(), "ticket": ticket}).encode("utf-8"),
                    headers={
                        "Host": "evil.com",
                        "Content-Type": "application/json",
                        "Origin": "http://evil.com",
                        "Authorization": f"Bearer {signed_tok}",
                    },
                )
                self.assertEqual(st, 403)
                self.assertEqual(json.loads(evil_b)["error"], "ORIGIN_DENIED")

                # Right-to-left XFF binding: wrong right-most IP fails (403), spoofed left IP ignored -> succeeds!
                st, wrong_ip_b = http_req(
                    "POST",
                    "/__vibeslayer/lease",
                    body=json.dumps({"clientPublicKeyHex": client_pub.hex(), "ticket": ticket}).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "Origin": origin,
                        "Authorization": f"Bearer {signed_tok}",
                        "X-Forwarded-For": "1.2.3.4, 203.0.113.99",
                    },
                )
                self.assertEqual(st, 403)
                self.assertEqual(json.loads(wrong_ip_b)["error"], "TICKET_REPLAYED_OR_INVALID")

                st, data = http_req(
                    "POST",
                    "/__vibeslayer/lease",
                    body=json.dumps({"clientPublicKeyHex": client_pub.hex(), "ticket": ticket}).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "Origin": origin,
                        "Authorization": f"Bearer {signed_tok}",
                        "X-Forwarded-For": "9.9.9.9, 203.0.113.10",
                    },
                )
                self.assertEqual(st, 200, data.decode("utf-8", errors="replace"))
                lease = json.loads(data)
                srv_pub = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), bytes.fromhex(lease["serverPublicKeyHex"])
                )
                shared_32 = client_priv.exchange(ec.ECDH(), srv_pub)
                wrap_info = f"VSWEB1_WRAP|{origin}".encode("utf-8")
                wrap_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=lease["leaseId"].encode("utf-8"),
                    info=wrap_info,
                ).derive(shared_32)
                site_key = AESGCM(wrap_key).decrypt(
                    bytes.fromhex(lease["wrapIvHex"]),
                    bytes.fromhex(lease["wrappedKeyHex"]),
                    wrap_info,
                )
                manifest = json.loads(
                    AESGCM(site_key).decrypt(
                        bytes.fromhex(lease["manifestIvHex"]),
                        bytes.fromhex(lease["sealedManifestHex"]),
                        b"VSWEB1|__manifest__",
                    )
                )
                card_vsweb = manifest["files"]["card.mjs"]["vsweb"]
                # Cookie auth with static secret also still works
                st, card_blob = http_req("GET", "/" + card_vsweb, headers={"Cookie": "vs_auth=vs-site-gate-2026"})
                self.assertEqual(st, 200)
                card_plain = AESGCM(site_key).decrypt(
                    card_blob[:12], card_blob[12:], b"VSWEB1|card.mjs"
                ).decode("utf-8")
                self.assertNotIn("PRIVATE_DEV_COMMENT_9182", card_plain)
                self.assertNotIn("OMEGA_WEBCOMP_SECRET_4419", card_plain)
                self.assertNotIn("/assets/halo-mesh.json", card_plain)
                self.assertIn("_vsm", card_plain)
                self.assertIn("_vsd", card_plain)
            finally:
                srv.terminate()
                try:
                    srv.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    srv.kill()
                    srv.wait(timeout=3)
                if srv.stdout:
                    srv.stdout.close()
                if srv.stderr:
                    srv.stderr.close()

    def test_parametrized_website_and_serve_config_presets(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vs-web-param-") as td:
            tdir = Path(td)
            reg = tdir / "registry.json"
            cfg = tdir / "vibeslayer.config.json"
            site_dir = tdir / "site-src"
            web_out = tdir / "site-param-out"
            site_dir.mkdir(parents=True, exist_ok=True)
            (site_dir / "index.html").write_text("<!doctype html><html><body>Hi</body></html>\n", encoding="utf-8")
            (site_dir / "app.js").write_text('export const tag = "XYZ";\n', encoding="utf-8")

            # Generate paranoid config template
            init_out = run_cli_json(["init-config", "--preset", "paranoid", "-o", str(cfg)])
            self.assertTrue(init_out["ok"])
            self.assertEqual(init_out["preset"], "paranoid")

            # Apply config + CLI overrides (--title HTML escaped, --anti-hook off, --min-str-len 3)
            sealed = run_cli_json(
                [
                    "website",
                    str(site_dir),
                    "-o",
                    str(web_out),
                    "--config",
                    str(cfg),
                    "--title",
                    "<b>SafeTitle</b>",
                    "--anti-hook",
                    "off",
                    "--min-str-len",
                    "3",
                    "--json",
                    "--registry",
                    str(reg),
                ]
            )
            self.assertTrue(sealed["ok"])
            self.assertTrue(sealed["params"]["hardenJs"])
            self.assertEqual(sealed["params"]["minStrLen"], 3)
            self.assertFalse(sealed["params"]["antiHook"])

            boot_html = (web_out / "index.html").read_text(encoding="utf-8")
            self.assertIn("&lt;b&gt;SafeTitle&lt;/b&gt;", boot_html)
            self.assertNotIn("<b>SafeTitle</b>", boot_html)
            loader_js = (web_out / "vibe-slayer-loader.js").read_text(encoding="utf-8")
            self.assertNotIn("_chk(", loader_js)

            # Invalid numeric / enum flags fail closed with non-zero exit
            for bad in [
                ["website", str(site_dir), "--preset", "invalid_mode"],
                ["website", str(site_dir), "--min-str-len", "abc"],
                ["serve", str(web_out), "--csp", "bogus"],
            ]:
                p = subprocess.run([str(VIBE_SLAYER), *bad], capture_output=True, text=True)
                self.assertNotEqual(p.returncode, 0, f"expected failure for {bad}")

            # Serve with --csp relaxed and verify header contains https:
            port = pick_free_port()
            srv = subprocess.Popen(
                [
                    str(VIBE_SLAYER),
                    "serve",
                    str(web_out),
                    "--config",
                    str(cfg),
                    "--addr",
                    f"127.0.0.1:{port}",
                    "--csp",
                    "relaxed",
                    "--ticket-ttl",
                    "45",
                    "--registry",
                    str(reg),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                ready = False
                for _ in range(50):
                    if srv.poll() is not None:
                        out, err = srv.communicate(timeout=1)
                        raise AssertionError(f"serve exited early: {out}\n{err}")
                    try:
                        c = http.client.HTTPConnection("127.0.0.1", port, timeout=0.5)
                        c.request("GET", "/__vibeslayer/health")
                        r = c.getresponse()
                        r.read()
                        c.close()
                        if r.status == 200:
                            ready = True
                            break
                    except OSError:
                        time.sleep(0.05)
                self.assertTrue(ready)
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=2.0)
                c.request("GET", "/")
                r = c.getresponse()
                r.read()
                csp_hdr = r.getheader("Content-Security-Policy", "")
                c.close()
                self.assertEqual(r.status, 200)
                self.assertIn("default-src 'self' https:", csp_hdr)
            finally:
                srv.terminate()
                try:
                    srv.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    srv.kill()
                    srv.wait(timeout=3)
                if srv.stdout:
                    srv.stdout.close()
                if srv.stderr:
                    srv.stderr.close()

    def test_natural_language_ask_and_explain(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vs-nl-test-") as td:
            tdir = Path(td)
            src = tdir / "site"
            src.mkdir()
            (src / "index.html").write_text("<html><body>NL OK</body></html>\n", encoding="utf-8")
            (src / "app.mjs").write_text('export const S = "NL_SECRET_TOKEN_42";\n', encoding="utf-8")

            # 1. explain -> dry-run JSON plan, does not create output dir
            plan = run_cli_json([
                "explain",
                f"protect my website {src} and block cloakbrowser on port 9123",
                "--json",
            ])
            self.assertTrue(plan["ok"])
            self.assertTrue(plan["dryRun"])
            self.assertEqual(plan["intent"], "website")
            self.assertIn("paranoid", plan["argv"])
            self.assertIn("strict", plan["argv"])
            self.assertFalse(Path(f"{src}-protected").exists())

            # 2. ask -> actually executes and produces sealed output
            out_dir = tdir / "site-sealed"
            res = run_cli_json([
                "ask",
                f"protect my website {src} to {out_dir} and block cloakbrowser on port 9123",
                "--json",
            ])
            self.assertTrue(res["ok"])
            self.assertEqual(res["mode"], "website")
            self.assertTrue((out_dir / "vibe-slayer-loader.js").is_file())
            self.assertEqual(res["params"]["antiStealth"], "strict")


if __name__ == "__main__":
    unittest.main(verbosity=2)
