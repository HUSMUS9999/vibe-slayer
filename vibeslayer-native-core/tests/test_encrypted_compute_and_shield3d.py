#!/usr/bin/env python3
"""
Verification & Benchmark Suite for:
  1. `VSHomo` Ring-LWE (BFV) Homomorphic Encrypted Computation (0 secret key / 0 plaintext in client RAM)
  2. `VS3D-SHIELD` Zero-CPU/VRAM-Plaintext + Chaff-Poisoned + AI-Bloating Polymorphic WebGL2 3D Shield
"""

from __future__ import annotations

import json
import math
import os
import pathlib
import re
import shutil
import statistics
import subprocess
import tempfile
import time
import unittest

import tiktoken

CORE_DIR = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = CORE_DIR.parent
VS_BIN = REPO_ROOT / "vibe-slayer"
SAMPLE_GLB = CORE_DIR / "tests" / "fixtures" / "sample_mesh.glb"
ENC_O200K = tiktoken.get_encoding("o200k_base")
ENC_CL100K = tiktoken.get_encoding("cl100k_base")


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 4)


class TestEncryptedComputeAndShield3D(unittest.TestCase):
    def test_01_homomorphic_compute_while_encrypted_without_secret_key(self):
        with tempfile.TemporaryDirectory(prefix="vs_homo_") as tmp:
            work = pathlib.Path(tmp)
            server_dir = work / "owner_server_vault"
            client_dir = work / "untrusted_client_ram"
            server_dir.mkdir()
            client_dir.mkdir()

            sk_path = server_dir / "owner.sk"
            pk_path = client_dir / "client.pk"

            # 1. Keygen (sk stays strictly in owner_server_vault!)
            t0 = time.perf_counter()
            kg = json.loads(
                subprocess.check_output(
                    [str(VS_BIN), "homo-keygen", "--sk", str(sk_path), "--pk", str(pk_path)],
                    text=True,
                )
            )
            keygen_ms = (time.perf_counter() - t0) * 1000.0
            self.assertTrue(kg["ok"])
            self.assertEqual(kg["ringDegree"], 256)
            self.assertFalse((client_dir / "owner.sk").exists())

            # 2. Encrypt secret formula weights (c2=7, c1=-13, c0=250) & input (x=-9, y=14)
            def enc_val(v: int, name: str) -> pathlib.Path:
                out = client_dir / f"{name}.hct"
                subprocess.run(
                    [
                        str(VS_BIN),
                        "homo-encrypt",
                        "--pk",
                        str(pk_path),
                        "--value",
                        str(v),
                        "--out",
                        str(out),
                    ],
                    check=True,
                    capture_output=True,
                )
                return out

            ct_x = enc_val(-9, "x")
            ct_y = enc_val(14, "y")
            ct_c2 = enc_val(7, "c2")
            ct_c1 = enc_val(-13, "c1")
            ct_c0 = enc_val(250, "c0")

            # Verify ciphertext high entropy (~7.95+ bits/byte)
            self.assertGreater(shannon_entropy(ct_x.read_bytes()[8:]), 7.90)

            # 3. Run Add, Sub, Mul, and Quadratic Formula ENTIRELY WHILE ENCRYPTED on client
            #    (owner_server_vault is completely untouched during evaluation!)
            ct_add = client_dir / "res_add.hct"
            ct_mul = client_dir / "res_mul.hct"
            ct_quad = client_dir / "res_quad.hct"

            add_samples = []
            mul_samples = []
            quad_samples = []
            for i in range(6):
                s0 = time.perf_counter()
                subprocess.run(
                    [
                        str(VS_BIN),
                        "homo-eval",
                        "--pk",
                        str(pk_path),
                        "--op",
                        "add",
                        "--a",
                        str(ct_x),
                        "--b",
                        str(ct_y),
                        "--out",
                        str(ct_add),
                    ],
                    check=True,
                    capture_output=True,
                )
                if i >= 1:
                    add_samples.append((time.perf_counter() - s0) * 1000.0)

                s1 = time.perf_counter()
                subprocess.run(
                    [
                        str(VS_BIN),
                        "homo-eval",
                        "--pk",
                        str(pk_path),
                        "--op",
                        "mul",
                        "--a",
                        str(ct_x),
                        "--b",
                        str(ct_y),
                        "--out",
                        str(ct_mul),
                    ],
                    check=True,
                    capture_output=True,
                )
                if i >= 1:
                    mul_samples.append((time.perf_counter() - s1) * 1000.0)

                s2 = time.perf_counter()
                ev_q = json.loads(
                    subprocess.check_output(
                        [
                            str(VS_BIN),
                            "homo-eval",
                            "--pk",
                            str(pk_path),
                            "--op",
                            "quad",
                            "--x",
                            str(ct_x),
                            "--c2",
                            str(ct_c2),
                            "--c1",
                            str(ct_c1),
                            "--c0",
                            str(ct_c0),
                            "--out",
                            str(ct_quad),
                        ],
                        text=True,
                    )
                )
                self.assertFalse(ev_q["secretKeyUsed"])
                if i >= 1:
                    quad_samples.append((time.perf_counter() - s2) * 1000.0)

            # 4. Decrypt ONLY on owner_server_vault and verify exact integer answers!
            def dec_val(p: pathlib.Path) -> int:
                d = json.loads(
                    subprocess.check_output(
                        [str(VS_BIN), "homo-decrypt", "--sk", str(sk_path), "--in", str(p)],
                        text=True,
                    )
                )
                return d["value"]

            self.assertEqual(dec_val(ct_add), 5)        # -9 + 14 = 5
            self.assertEqual(dec_val(ct_mul), -126)     # -9 * 14 = -126
            self.assertEqual(dec_val(ct_quad), 934)     # 7*(-9)^2 + (-13)*(-9) + 250 = 934

            print(
                json.dumps(
                    {
                        "engine": "VSHomo-RingLWE-BFV",
                        "keygen_ms": round(keygen_ms, 2),
                        "sk_bytes_on_server": sk_path.stat().st_size,
                        "sk_bytes_on_client": 0,
                        "pk_evk_bytes": pk_path.stat().st_size,
                        "ciphertext_bytes": ct_quad.stat().st_size,
                        "ciphertext_entropy": shannon_entropy(ct_quad.read_bytes()[8:]),
                        "encrypted_add_cli_median_ms": round(statistics.median(add_samples), 2),
                        "encrypted_mul_cli_median_ms": round(statistics.median(mul_samples), 2),
                        "encrypted_quadratic_cli_median_ms": round(statistics.median(quad_samples), 2),
                        "verified_results": {"add": 5, "mul": -126, "quad": 934},
                    }
                )
            )

    def test_02_shield_3d_zero_vram_plaintext_chaff_and_shader_token_bloat(self):
        self.assertTrue(SAMPLE_GLB.exists(), f"Missing sample GLB: {SAMPLE_GLB}")
        with tempfile.TemporaryDirectory(prefix="vs_shield3d_") as tmp:
            out_dir = pathlib.Path(tmp) / "exarch_shielded"
            samples_ms = []
            meta = {}
            for i in range(4):
                if out_dir.exists():
                    shutil.rmtree(out_dir)
                t0 = time.perf_counter()
                out_txt = subprocess.check_output(
                    [
                        str(VS_BIN),
                        "shield-3d",
                        "--in",
                        str(SAMPLE_GLB),
                        "--out",
                        str(out_dir),
                    ],
                    text=True,
                )
                dt_ms = (time.perf_counter() - t0) * 1000.0
                if i >= 1:
                    samples_ms.append(dt_ms)
                meta = json.loads(out_txt)

            self.assertTrue(meta["ok"])
            self.assertEqual(meta["verifiedRealVerts"], meta["realTriangles"] * 3)
            self.assertEqual(meta["verifiedChaffClipped"], meta["chaffTriangles"] * 3)
            self.assertLess(meta["maxClipSpaceError"], 1e-4)

            shield_bytes = (out_dir / "model.vsshield").read_bytes()
            shader_src = (out_dir / "shield.vert.glsl").read_text()
            manifest = json.loads((out_dir / "shield.manifest.json").read_text())

            self.assertEqual(manifest["cpuPlaintextVertices"], 0)
            self.assertEqual(manifest["vramPlaintextVertices"], 0)
            self.assertNotIn(b"glTF", shield_bytes)

            # Verify VRAM stream is high-entropy ciphertext
            vram_entropy = shannon_entropy(shield_bytes[24:])
            self.assertGreater(vram_entropy, 7.98)

            # Verify zero repeating golden-ratio beacon and measure LLM token bloat of the shader alone!
            self.assertNotIn("9e3779b9", shader_src.lower())
            shader_o200k = len(ENC_O200K.encode(shader_src, disallowed_special=()))
            shader_cl100k = len(ENC_CL100K.encode(shader_src, disallowed_special=()))
            self.assertGreater(shader_o200k, 140_000)

            # Verify all 96 shader stages have distinct function bodies
            stage_bodies = re.findall(
                r"uvec4 vs_gpu_s\d{3}\(uvec4 v, uint vid\)\{(.*?)\n\}",
                shader_src,
                flags=re.DOTALL,
            )
            self.assertEqual(len(stage_bodies), 96)
            self.assertEqual(len(set(stage_bodies)), 96)

            print(
                json.dumps(
                    {
                        "engine": "VS3D-SHIELD-WebGL2",
                        "orig_glb_bytes": SAMPLE_GLB.stat().st_size,
                        "shield_vram_bytes": len(shield_bytes),
                        "vram_ciphertext_entropy": vram_entropy,
                        "build_median_ms": round(statistics.median(samples_ms), 2),
                        "real_triangles": meta["realTriangles"],
                        "poison_chaff_triangles": meta["chaffTriangles"],
                        "cpu_plaintext_vertices": 0,
                        "vram_plaintext_vertices": 0,
                        "post_vs_3d_world_coords_emitted": 0,
                        "shader_bytes": len(shader_src),
                        "shader_o200k_tokens": shader_o200k,
                        "shader_cl100k_tokens": shader_cl100k,
                        "unique_gpu_stages": f"{len(set(stage_bodies))}/96",
                        "max_clip_space_error": meta["maxClipSpaceError"],
                    }
                )
            )

    def test_03_hardened_serve_3d_blocks_unauth_and_completes_ecdh_session(self):
        import http.client
        import socket
        import struct
        import zlib
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        def make_gradient_png_32() -> bytes:
            def chunk(tag: bytes, payload: bytes) -> bytes:
                return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
            w, h = 32, 32
            ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
            rows = bytearray()
            for y in range(h):
                rows.append(0)
                for x in range(w):
                    rows.extend([(x * 8) & 0xFF, (y * 8) & 0xFF, ((x ^ y) * 7) & 0xFF])
            idat = zlib.compress(bytes(rows))
            return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")

        orig_png = make_gradient_png_32()

        def make_standard_glb() -> bytes:
            pos = struct.pack("<9f", 0.0, 0.5, 0.0, -0.5, -0.5, 0.0, 0.5, -0.5, 0.0)
            uvs = struct.pack("<6f", 0.5, 0.1, 0.1, 0.9, 0.9, 0.9)
            png = orig_png
            pos_len = len(pos)
            uv_off = pos_len
            uv_len = len(uvs)
            png_off = uv_off + uv_len
            png_len = len(png)
            bin_buf = bytearray(pos + uvs + png)
            while len(bin_buf) % 4 != 0:
                bin_buf.append(0)
            gltf = {
                "asset": {"version": "2.0"},
                "buffers": [{"byteLength": len(bin_buf)}],
                "bufferViews": [
                    {"buffer": 0, "byteOffset": 0, "byteLength": pos_len},
                    {"buffer": 0, "byteOffset": uv_off, "byteLength": uv_len},
                    {"buffer": 0, "byteOffset": png_off, "byteLength": png_len},
                ],
                "accessors": [
                    {"bufferView": 0, "componentType": 5126, "count": 3, "type": "VEC3"},
                    {"bufferView": 1, "componentType": 5126, "count": 3, "type": "VEC2"},
                ],
                "images": [{"bufferView": 2, "mimeType": "image/png"}],
                "meshes": [{"primitives": [{"attributes": {"POSITION": 0, "TEXCOORD_0": 1}}]}],
            }
            json_b = bytearray(json.dumps(gltf, separators=(",", ":")).encode("utf-8"))
            while len(json_b) % 4 != 0:
                json_b.extend(b" ")
            total_len = 12 + 8 + len(json_b) + 8 + len(bin_buf)
            return (
                b"glTF"
                + struct.pack("<II", 2, total_len)
                + struct.pack("<I", len(json_b)) + b"JSON" + bytes(json_b)
                + struct.pack("<I", len(bin_buf)) + b"BIN\x00" + bytes(bin_buf)
            )

        with tempfile.TemporaryDirectory(prefix="vs_serve3d_sec_") as tmp:
            glb_path = pathlib.Path(tmp) / "tiny_viewer.glb"
            glb_path.write_bytes(make_standard_glb())
            out_dir = pathlib.Path(tmp) / "exarch_shielded"
            sep_key_file = pathlib.Path(tmp) / "vault_secret.key"
            subprocess.check_call(
                [
                    str(VS_BIN),
                    "shield-3d",
                    "--in",
                    str(glb_path),
                    "--out",
                    str(out_dir),
                    "--key-file",
                    str(sep_key_file),
                ],
                stdout=subprocess.DEVNULL,
            )
            # --key-file must keep master key OUT of bundle output directory
            self.assertTrue(sep_key_file.is_file())
            self.assertFalse((out_dir / ".vsshield.key").exists())

            viewer_meta = json.loads((out_dir / "viewer.meta.json").read_text())
            self.assertEqual(viewer_meta["latticeVersion"], 2)
            self.assertTrue(viewer_meta["tileScrambled"])
            self.assertEqual(viewer_meta["tileScrambledMask"], 1)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
            origin = f"http://127.0.0.1:{port}"
            srv = subprocess.Popen(
                [
                    str(VS_BIN),
                    "serve-3d",
                    "--dir",
                    str(out_dir),
                    "--key-file",
                    str(sep_key_file),
                    "--addr",
                    f"127.0.0.1:{port}",
                    "--origin",
                    origin,
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
                        raise AssertionError(f"serve-3d exited early: {out}\n{err}")
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

                def req(method: str, path: str, body: bytes | None = None, headers: dict | None = None):
                    c = http.client.HTTPConnection("127.0.0.1", port, timeout=3.0)
                    c.request(method, path, body=body, headers=headers or {})
                    r = c.getresponse()
                    data = r.read()
                    ctype = r.getheader("Content-Type", "")
                    c.close()
                    return r.status, ctype, data

                # 1. All unauthenticated resource & API endpoints must fail closed (403)
                st, _, data = req("POST", "/__vibeslayer/session", body=b"{}", headers={"Content-Type": "application/json"})
                self.assertEqual(st, 403)
                self.assertEqual(json.loads(data)["error"], "ORIGIN_DENIED")

                for protected_get in ["/shield_pbr.vert.glsl", "/shield_pbr.frag.glsl", "/scene.vsshield2"]:
                    st, _, data = req("GET", protected_get)
                    self.assertEqual(st, 403, f"expected 403 on {protected_get}")
                    self.assertEqual(json.loads(data)["error"], "SESSION_REQUIRED")

                if viewer_meta["textureCount"] > 0:
                    st, _, data = req("GET", "/__vibeslayer/tex/0")
                    self.assertEqual(st, 403)
                    self.assertEqual(json.loads(data)["error"], "SESSION_REQUIRED")

                st, _, data = req(
                    "POST",
                    "/__vibeslayer/camera",
                    body=b"{}",
                    headers={"Content-Type": "application/json", "Origin": origin},
                )
                self.assertEqual(st, 403)
                self.assertEqual(json.loads(data)["error"], "SESSION_REQUIRED")

                # 2. Fetch HTML + hardened 3d-loader.js and verify zero plaintext API routes or protocol keys
                st, _, html_b = req("GET", "/")
                self.assertEqual(st, 200)
                html = html_b.decode("utf-8")
                self.assertNotIn("/shield_pbr.vert.glsl", html)
                self.assertNotIn("/__vibeslayer/camera", html)
                m = re.search(r'<meta\s+name="vs-ticket"\s+content="([^"]+)"', html)
                self.assertIsNotNone(m)
                ticket = m.group(1)

                st, _, js_b = req("GET", "/__vibeslayer/3d-loader.js")
                self.assertEqual(st, 200)
                loader_js = js_b.decode("utf-8")
                for secret_lit in [
                    "/shield_pbr.vert.glsl",
                    "/scene.vsshield2",
                    "/__vibeslayer/session",
                    "/__vibeslayer/camera",
                    "ephemeralUniformWords",
                    "tileMap",
                    "tileGrid",
                    "u_tile_grid",
                    "wmUniform",
                    "sealedSessionHex",
                    "fusedMvp",
                    "camDir",
                ]:
                    self.assertNotIn(secret_lit, loader_js)

                # 3. Complete ECDH P-256 session handshake and unwrap non-extractable asset key
                client_priv = ec.generate_private_key(ec.SECP256R1())
                client_pub = client_priv.public_key().public_bytes(
                    serialization.Encoding.X962,
                    serialization.PublicFormat.UncompressedPoint,
                )
                st, _, sess_b = req(
                    "POST",
                    "/__vibeslayer/session",
                    body=json.dumps({"clientPublicKeyHex": client_pub.hex(), "ticket": ticket}).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Origin": origin},
                )
                self.assertEqual(st, 200, sess_b.decode("utf-8", errors="replace"))
                sess = json.loads(sess_b)
                self.assertNotIn("ephemeralUniformWords", sess)

                srv_pub = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), bytes.fromhex(sess["serverPublicKeyHex"])
                )
                shared_32 = client_priv.exchange(ec.ECDH(), srv_pub)
                wrap_info = f"VS3D_WRAP|{origin}".encode("utf-8")
                wrap_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=sess["sessionId"].encode("utf-8"),
                    info=wrap_info,
                ).derive(shared_32)
                asset_key = AESGCM(wrap_key).decrypt(
                    bytes.fromhex(sess["wrapIvHex"]),
                    bytes.fromhex(sess["wrappedKeyHex"]),
                    wrap_info,
                )
                sess_plain = AESGCM(asset_key).decrypt(
                    bytes.fromhex(sess["sessionIvHex"]),
                    bytes.fromhex(sess["sealedSessionHex"]),
                    f"VS3D_SESSION|{sess['sessionId']}".encode("utf-8"),
                )
                sd = json.loads(sess_plain)
                sess_tok = sd["sessionToken"]
                self.assertEqual(len(sd["ephemeralUniformWords"]), 64)
                self.assertEqual(len(sd["tileMap"]), 256)
                self.assertEqual(sd["tileMask"], 1)
                self.assertEqual(sd["tileGrid"], 16)
                self.assertEqual(len(sd["wmUniform"]), 4)
                self.assertEqual(sd["wmUniform"][3], 12)

                # Replay check on session ticket
                st, _, r_b = req(
                    "POST",
                    "/__vibeslayer/session",
                    body=json.dumps({"clientPublicKeyHex": client_pub.hex(), "ticket": ticket}).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Origin": origin},
                )
                self.assertEqual(st, 403)
                self.assertEqual(json.loads(r_b)["error"], "TICKET_REPLAYED_OR_INVALID")

                # 4. Decrypt protected shaders/mesh/texture with session token
                st, ctype, vert_blob = req("GET", "/shield_pbr.vert.glsl", headers={"X-VS-Session": sess_tok})
                self.assertEqual(st, 200)
                vert_src = AESGCM(asset_key).decrypt(
                    vert_blob[:12], vert_blob[12:], b"VS3D_ASSET|/shield_pbr.vert.glsl"
                ).decode("utf-8")
                self.assertIn("uniform uvec4 u_vs_wm;", vert_src)

                st, ctype, frag_blob = req("GET", "/shield_pbr.frag.glsl", headers={"X-VS-Session": sess_tok})
                self.assertEqual(st, 200)
                self.assertIn("application/octet-stream", ctype)
                frag_src = AESGCM(asset_key).decrypt(
                    frag_blob[:12], frag_blob[12:], b"VS3D_ASSET|/shield_pbr.frag.glsl"
                ).decode("utf-8")
                self.assertIn("uniform uvec4 u_vs_tmap[64];", frag_src)
                self.assertIn("uniform uint u_tile_mask;", frag_src)
                self.assertIn("vs_unscramble_uv", frag_src)

                if viewer_meta["textureCount"] > 0:
                    st, ctype, tex_blob = req("GET", "/__vibeslayer/tex/0", headers={"X-VS-Session": sess_tok})
                    self.assertEqual(st, 200)
                    self.assertIn("application/octet-stream", ctype)
                    self.assertNotIn("image/png", ctype)
                    tex_plain = AESGCM(asset_key).decrypt(
                        tex_blob[:12], tex_blob[12:], b"VS3D_TEX|0"
                    )
                    self.assertTrue(tex_plain.startswith(b"\x89PNG\r\n\x1a\n"))
                    # Server-scrambled PNG must NOT equal original unscrambled PNG bytes
                    self.assertNotEqual(tex_plain, orig_png)

                # Mismatched Origin on asset GET must be blocked
                st, _, o_err = req(
                    "GET",
                    "/shield_pbr.vert.glsl",
                    headers={"X-VS-Session": sess_tok, "Origin": "https://evil.example"},
                )
                self.assertEqual(st, 403)
                self.assertEqual(json.loads(o_err)["error"], "ORIGIN_DENIED")

                # 5. Camera fusion: 4-col W_lat entanglement (non-zero fused[12..13]), unbiased camDir, random lambda
                cam_body_1 = json.dumps({"yaw": 0.1, "pitch": 0.08, "zoom": 3.30, "panY": 0.0, "aspect": 1.5, "thiefMode": False}).encode("utf-8")
                cam_body_2 = json.dumps({"yaw": 0.1, "pitch": 0.08, "zoom": 3.30, "panY": 0.0, "aspect": 1.5, "thiefMode": True}).encode("utf-8")
                st, _, c1 = req("POST", "/__vibeslayer/camera", body=cam_body_1, headers={"Content-Type": "application/json", "Origin": origin, "X-VS-Session": sess_tok})
                self.assertEqual(st, 200)
                st, _, c2 = req("POST", "/__vibeslayer/camera", body=cam_body_2, headers={"Content-Type": "application/json", "Origin": origin, "X-VS-Session": sess_tok})
                self.assertEqual(st, 200)
                j1 = json.loads(c1)
                j2 = json.loads(c2)
                m1 = j1["fusedMvp"]
                m2 = j2["fusedMvp"]
                self.assertEqual(len(m1), 16)
                self.assertNotEqual(m1, m2)
                # 4-col W_lat mixes L^-1 * t_lat into column 3 -> fused[12] & fused[13] are non-zero!
                self.assertGreater(abs(m1[12]) + abs(m1[13]), 1e-4)
                # camDir must strictly equal unbiased (yaw=0.1, pitch=0.08) -> zero session bias oracle!
                exp_cd = [math.cos(0.08) * math.sin(0.1), math.sin(0.08), math.cos(0.08) * math.cos(0.1)]
                for got_c, exp_c in zip(j1["camDir"], exp_cd):
                    self.assertAlmostEqual(got_c, exp_c, places=4)
                def norm16(v):
                    n = math.sqrt(sum(x * x for x in v))
                    return [x / n for x in v]
                for a, b in zip(norm16(m1), norm16(m2)):
                    self.assertAlmostEqual(a, b, places=4)

                # 5b. Per-session asset call budget cap (24 max -> 429 ASSET_BUDGET_EXHAUSTED)
                got_429 = False
                for _ in range(30):
                    st_a, _, body_a = req("GET", "/shield_pbr.frag.glsl", headers={"X-VS-Session": sess_tok})
                    if st_a == 429:
                        self.assertEqual(json.loads(body_a)["error"], "ASSET_BUDGET_EXHAUSTED")
                        got_429 = True
                        break
                self.assertTrue(got_429, "expected 429 ASSET_BUDGET_EXHAUSTED after >24 asset calls")

                # 5c. Slowloris header trickle must be severed by wall-clock deadline (~3s)
                t_slow = time.perf_counter()
                with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sl:
                    sl.sendall(b"GET / HTTP/1.1\r\n")
                    sl.settimeout(1.0)
                    closed = False
                    for _ in range(12):
                        time.sleep(0.45)
                        try:
                            sl.sendall(b"X-Slow: a\r\n")
                        except OSError:
                            closed = True
                            break
                        try:
                            peek = sl.recv(64, socket.MSG_DONTWAIT)
                            if peek == b"":
                                closed = True
                                break
                        except BlockingIOError:
                            pass
                        except OSError:
                            closed = True
                            break
                    self.assertTrue(closed, "Slowloris trickle connection was not closed by server deadline")
                self.assertLess(time.perf_counter() - t_slow, 6.0)
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

            # 6. Verify --auth-secret + --auth-hmac-key signed buyer tokens & distinct per-buyer GPU watermarks
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                port2 = s.getsockname()[1]
            hmac_key_hex = "3b" * 32
            tok_a = json.loads(
                subprocess.check_output(
                    [str(VS_BIN), "mint-token", "--key", hmac_key_hex, "--buyer", "buyer-alpha", "--ttl", "300"],
                    text=True,
                )
            )["token"]
            tok_b = json.loads(
                subprocess.check_output(
                    [str(VS_BIN), "mint-token", "--key", hmac_key_hex, "--buyer", "buyer-beta", "--ttl", "300"],
                    text=True,
                )
            )["token"]
            origin2 = f"http://127.0.0.1:{port2}"
            auth_srv = subprocess.Popen(
                [
                    str(VS_BIN),
                    "serve-3d",
                    "--dir",
                    str(out_dir),
                    "--key-file",
                    str(sep_key_file),
                    "--addr",
                    f"127.0.0.1:{port2}",
                    "--origin",
                    origin2,
                    "--auth-secret",
                    "vs-3d-secret-2026",
                    "--auth-hmac-key",
                    hmac_key_hex,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                ready2 = False
                for _ in range(50):
                    if auth_srv.poll() is not None:
                        break
                    try:
                        c = http.client.HTTPConnection("127.0.0.1", port2, timeout=0.5)
                        c.request("GET", "/__vibeslayer/health")
                        r = c.getresponse()
                        r.read()
                        c.close()
                        if r.status == 200:
                            ready2 = True
                            break
                    except OSError:
                        time.sleep(0.05)
                self.assertTrue(ready2)
                c = http.client.HTTPConnection("127.0.0.1", port2, timeout=2.0)
                c.request("GET", "/")
                r = c.getresponse()
                err_b = r.read()
                c.close()
                self.assertEqual(r.status, 401)
                self.assertEqual(json.loads(err_b)["error"], "AUTH_REQUIRED")

                def open_buyer_wm(auth_tok: str) -> list[int]:
                    c1 = http.client.HTTPConnection("127.0.0.1", port2, timeout=2.0)
                    c1.request("GET", "/", headers={"Authorization": f"Bearer {auth_tok}"})
                    r1 = c1.getresponse()
                    hb = r1.read().decode("utf-8")
                    c1.close()
                    self.assertEqual(r1.status, 200)
                    tk = re.search(r'<meta\s+name="vs-ticket"\s+content="([^"]+)"', hb).group(1)
                    cp = ec.generate_private_key(ec.SECP256R1())
                    cpub = cp.public_key().public_bytes(
                        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
                    )
                    c2 = http.client.HTTPConnection("127.0.0.1", port2, timeout=2.0)
                    c2.request(
                        "POST",
                        "/__vibeslayer/session",
                        body=json.dumps({"clientPublicKeyHex": cpub.hex(), "ticket": tk}).encode("utf-8"),
                        headers={"Content-Type": "application/json", "Origin": origin2, "Authorization": f"Bearer {auth_tok}"},
                    )
                    r2 = c2.getresponse()
                    sb = json.loads(r2.read())
                    c2.close()
                    self.assertEqual(r2.status, 200)
                    sp = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(sb["serverPublicKeyHex"]))
                    sh = cp.exchange(ec.ECDH(), sp)
                    wi = f"VS3D_WRAP|{origin2}".encode("utf-8")
                    wk = HKDF(algorithm=hashes.SHA256(), length=32, salt=sb["sessionId"].encode("utf-8"), info=wi).derive(sh)
                    ak = AESGCM(wk).decrypt(bytes.fromhex(sb["wrapIvHex"]), bytes.fromhex(sb["wrappedKeyHex"]), wi)
                    sd_i = json.loads(
                        AESGCM(ak).decrypt(
                            bytes.fromhex(sb["sessionIvHex"]),
                            bytes.fromhex(sb["sealedSessionHex"]),
                            f"VS3D_SESSION|{sb['sessionId']}".encode("utf-8"),
                        )
                    )
                    return sd_i["wmUniform"]

                wm_a1 = open_buyer_wm(tok_a)
                wm_a2 = open_buyer_wm(tok_a)
                wm_b = open_buyer_wm(tok_b)
                # Same buyer gets identical deterministic GPU watermark; different buyer gets distinct watermark!
                self.assertEqual(wm_a1, wm_a2)
                self.assertNotEqual(wm_a1, wm_b)
            finally:
                auth_srv.terminate()
                try:
                    auth_srv.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    auth_srv.kill()
                    auth_srv.wait(timeout=3)
                if auth_srv.stdout:
                    auth_srv.stdout.close()
                if auth_srv.stderr:
                    auth_srv.stderr.close()

    def test_04_parametrized_presets_config_and_runtime_knobs(self):
        import http.client
        import socket
        import struct
        import zlib
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        def make_small_glb() -> bytes:
            def chunk(tag: bytes, payload: bytes) -> bytes:
                return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
            w, h = 32, 32
            ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
            rows = bytearray()
            for y in range(h):
                rows.append(0)
                for x in range(w):
                    rows.extend([(x * 7) & 0xFF, (y * 7) & 0xFF, ((x + y) * 3) & 0xFF])
            png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(bytes(rows))) + chunk(b"IEND", b"")
            pos = struct.pack("<9f", 0.0, 0.5, 0.0, -0.5, -0.5, 0.0, 0.5, -0.5, 0.0)
            uvs = struct.pack("<6f", 0.5, 0.1, 0.1, 0.9, 0.9, 0.9)
            bin_buf = bytearray(pos + uvs + png)
            while len(bin_buf) % 4 != 0:
                bin_buf.append(0)
            gltf = {
                "asset": {"version": "2.0"},
                "buffers": [{"byteLength": len(bin_buf)}],
                "bufferViews": [
                    {"buffer": 0, "byteOffset": 0, "byteLength": len(pos)},
                    {"buffer": 0, "byteOffset": len(pos), "byteLength": len(uvs)},
                    {"buffer": 0, "byteOffset": len(pos) + len(uvs), "byteLength": len(png)},
                ],
                "accessors": [
                    {"bufferView": 0, "componentType": 5126, "count": 3, "type": "VEC3"},
                    {"bufferView": 1, "componentType": 5126, "count": 3, "type": "VEC2"},
                ],
                "images": [{"bufferView": 2, "mimeType": "image/png"}],
                "meshes": [{"primitives": [{"attributes": {"POSITION": 0, "TEXCOORD_0": 1}}]}],
            }
            json_b = bytearray(json.dumps(gltf, separators=(",", ":")).encode("utf-8"))
            while len(json_b) % 4 != 0:
                json_b.extend(b" ")
            total_len = 12 + 8 + len(json_b) + 8 + len(bin_buf)
            return (
                b"glTF"
                + struct.pack("<II", 2, total_len)
                + struct.pack("<I", len(json_b)) + b"JSON" + bytes(json_b)
                + struct.pack("<I", len(bin_buf)) + b"BIN\x00" + bytes(bin_buf)
            )

        with tempfile.TemporaryDirectory(prefix="vs_param_3d_") as tmp:
            tdir = pathlib.Path(tmp)
            glb_path = tdir / "mini_param.glb"
            glb_path.write_bytes(make_small_glb())

            # 1. init-config --preset fast
            cfg_path = tdir / "vibeslayer.config.json"
            init_res = json.loads(
                subprocess.check_output(
                    [str(VS_BIN), "init-config", "--preset", "fast", "-o", str(cfg_path)],
                    text=True,
                )
            )
            self.assertTrue(init_res["ok"])
            self.assertEqual(init_res["preset"], "fast")
            cfg_obj = json.loads(cfg_path.read_text())
            self.assertEqual(cfg_obj["shield3d"]["gpuStages"], 32)
            self.assertEqual(cfg_obj["shield3d"]["tileGrid"], 8)
            self.assertEqual(cfg_obj["shield3d"]["pngMode"], "fast")

            # 2. shield-3d --preset fast
            fast_dir = tdir / "fast_out"
            fast_res = json.loads(
                subprocess.check_output(
                    [str(VS_BIN), "shield-3d", "--in", str(glb_path), "--out", str(fast_dir), "--preset", "fast"],
                    text=True,
                )
            )
            self.assertTrue(fast_res["ok"])
            self.assertEqual(fast_res["preset"], "fast")
            self.assertEqual(fast_res["params"]["gpuStages"], 32)
            self.assertEqual(fast_res["params"]["tileGrid"], 8)
            self.assertEqual(fast_res["params"]["pngMode"], "fast")
            fast_vmeta = json.loads((fast_dir / "viewer.meta.json").read_text())
            self.assertEqual(fast_vmeta["gpuStages"], 32)
            self.assertEqual(fast_vmeta["tileGrid"], 8)
            fast_shader = (fast_dir / "shield_pbr.vert.glsl").read_text()
            self.assertEqual(len(re.findall(r"uvec4 vs_gpu_s\d{3}\(", fast_shader)), 32)

            # 3. shield-3d --config + CLI override precedence (CLI > config > preset)
            ov_dir = tdir / "ov_out"
            ov_res = json.loads(
                subprocess.check_output(
                    [
                        str(VS_BIN),
                        "shield-3d",
                        "--in",
                        str(glb_path),
                        "--out",
                        str(ov_dir),
                        "--config",
                        str(cfg_path),
                        "--gpu-stages",
                        "48",
                        "--tile-grid",
                        "4",
                        "--png-mode",
                        "optimal",
                    ],
                    text=True,
                )
            )
            self.assertTrue(ov_res["ok"])
            self.assertEqual(ov_res["params"]["gpuStages"], 48)
            self.assertEqual(ov_res["params"]["tileGrid"], 4)
            self.assertEqual(ov_res["params"]["pngMode"], "optimal")

            # 4. Invalid params rejected cleanly with non-zero exit
            for bad_args in [
                ["shield-3d", "--in", str(glb_path), "--out", str(tdir / "bad1"), "--tile-grid", "12"],
                ["shield-3d", "--in", str(glb_path), "--out", str(tdir / "bad2"), "--gpu-stages", "999"],
                ["shield-3d", "--in", str(glb_path), "--out", str(tdir / "bad3"), "--preset", "nope"],
                ["shield-3d", "--in", str(glb_path), "--out", str(tdir / "bad4"), "--chaff-pct", "abc"],
            ]:
                p_bad = subprocess.run([str(VS_BIN), *bad_args], capture_output=True, text=True)
                self.assertNotEqual(p_bad.returncode, 0, f"expected failure for {bad_args}")

            # 5. serve-3d runtime params: HTML-escaped --title, --watermark off, --asset-budget 8, --csp off, --anti-hook off
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
            origin = f"http://127.0.0.1:{port}"
            srv = subprocess.Popen(
                [
                    str(VS_BIN),
                    "serve-3d",
                    str(ov_dir),
                    "--addr",
                    f"127.0.0.1:{port}",
                    "--origin",
                    origin,
                    "--title",
                    "<script>alert(1)</script>Custom3D",
                    "--watermark",
                    "off",
                    "--asset-budget",
                    "8",
                    "--csp",
                    "off",
                    "--anti-hook",
                    "off",
                    "--camera-jitter",
                    "0",
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
                        raise AssertionError(f"serve-3d exited early: {out}\n{err}")
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

                def req(method: str, path: str, body: bytes | None = None, headers: dict | None = None):
                    c = http.client.HTTPConnection("127.0.0.1", port, timeout=2.0)
                    c.request(method, path, body=body, headers=headers or {})
                    r = c.getresponse()
                    data = r.read()
                    hdrs = {k.lower(): v for k, v in r.getheaders()}
                    c.close()
                    return r.status, hdrs, data

                st, hdrs, html_b = req("GET", "/")
                self.assertEqual(st, 200)
                self.assertNotIn("content-security-policy", hdrs)
                html = html_b.decode("utf-8")
                self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;Custom3D", html)
                self.assertNotIn("<script>alert(1)</script>", html)
                self.assertIn("(48 stg)", html)
                tk = re.search(r'<meta\s+name="vs-ticket"\s+content="([^"]+)"', html).group(1)

                st, _, js_b = req("GET", "/__vibeslayer/3d-loader.js")
                self.assertEqual(st, 200)
                js_txt = js_b.decode("utf-8")
                self.assertNotIn("_chk(", js_txt)
                self.assertNotIn("u_tile_grid", js_txt)
                self.assertNotIn("tileGrid", js_txt)
                self.assertIn("48-Stage", js_txt)

                cp = ec.generate_private_key(ec.SECP256R1())
                cpub = cp.public_key().public_bytes(
                    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
                )
                st, _, sb = req(
                    "POST",
                    "/__vibeslayer/session",
                    body=json.dumps({"clientPublicKeyHex": cpub.hex(), "ticket": tk}).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Origin": origin},
                )
                self.assertEqual(st, 200)
                sj = json.loads(sb)
                sp = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), bytes.fromhex(sj["serverPublicKeyHex"])
                )
                sh = cp.exchange(ec.ECDH(), sp)
                wi = f"VS3D_WRAP|{origin}".encode("utf-8")
                wk = HKDF(algorithm=hashes.SHA256(), length=32, salt=sj["sessionId"].encode("utf-8"), info=wi).derive(sh)
                ak = AESGCM(wk).decrypt(bytes.fromhex(sj["wrapIvHex"]), bytes.fromhex(sj["wrappedKeyHex"]), wi)
                sd = json.loads(
                    AESGCM(ak).decrypt(
                        bytes.fromhex(sj["sessionIvHex"]),
                        bytes.fromhex(sj["sealedSessionHex"]),
                        f"VS3D_SESSION|{sj['sessionId']}".encode("utf-8"),
                    )
                )
                self.assertEqual(sd["tileGrid"], 4)
                self.assertEqual(sd["wmUniform"][3], 0)  # --watermark off!

                # --asset-budget 8 -> first 8 pass, 9th returns 429 ASSET_BUDGET_EXHAUSTED
                sess_tok = sd["sessionToken"]
                for idx in range(8):
                    st_a, _, _ = req("GET", "/shield_pbr.frag.glsl", headers={"X-VS-Session": sess_tok})
                    self.assertEqual(st_a, 200, f"call {idx+1} should succeed")
                st_9, _, b_9 = req("GET", "/shield_pbr.frag.glsl", headers={"X-VS-Session": sess_tok})
                self.assertEqual(st_9, 429)
                self.assertEqual(json.loads(b_9)["error"], "ASSET_BUDGET_EXHAUSTED")
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
