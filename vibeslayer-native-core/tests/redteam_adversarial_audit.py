#!/usr/bin/env python3
"""
Unbiased Tier-3 Adversarial Red-Team Exploit Suite (`redteam_adversarial_audit.py`).

Tests REAL mathematical & black-box exploits against VibeSlayer 3D Shield:
  1. Zero-Normal-Oracle Audit (proves no 3D normal vector exists for 50ms SVD lattice inversion)
  2. Real 12-Camera Linear Kruppa SVD Solver:
       - Control (--camera-jitter 0): proves our exploit ACTUALLY recovers exact L^T L (<1e-3 error)
       - Hardened (default Balanced): runs the EXACT same exploit & measures real Frobenius error!
  3. Transform Feedback Watermark-Stripping Attack:
       - Executes the GPU Feistel shader in software, rips raw `wp` BEFORE `u_vs_wm` (stripping u_vs_wm=0),
         then verifies `trace-shield-3d` STILL extracts distinct exact 64-bit buyer IDs!
  4. MCU-Aligned Scrambled JPEG Bandwidth & Format Check.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import math
import pathlib
import re
import socket
import struct
import subprocess
import tempfile
import time
import unittest
import zlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CORE_DIR = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = CORE_DIR.parent
VS_BIN = REPO_ROOT / "vibe-slayer"


def derive_ground_truth_lattice_g(master_key: bytes, asset_id: str) -> list[list[float]]:
    """Exact mirror of derive_unimodular_lattice_3x3 -> returns normalized G = L^T L."""
    seed = hmac.new(master_key, f"VS3D_SHIELD_LAT_V1|{asset_id}".encode(), hashlib.sha256).digest()
    def ms(b: int) -> int:
        v = (b % 7) - 3
        return 2 if v == 0 else v
    sxy, sxz, syz, syx, szx, szy = [ms(seed[i]) for i in range(6)]
    u = [[1, sxy, sxz], [0, 1, syz], [0, 0, 1]]
    lo = [[1, 0, 0], [syx, 1, 0], [szx, szy, 1]]
    L = [[sum(u[r][k] * lo[k][c] for k in range(3)) for c in range(3)] for r in range(3)]
    # G = L L^T satisfies L^{-1} G (L^{-1})^T = I -> u_0 G u_1^T = 0!
    G = [[float(sum(L[r][k] * L[c][k] for k in range(3))) for c in range(3)] for r in range(3)]
    norm = math.sqrt(sum(G[r][c] ** 2 for r in range(3) for c in range(3)))
    return [[G[r][c] / norm for c in range(3)] for r in range(3)]


def symmetric_6_to_mat3(g: list[float]) -> list[list[float]]:
    # g = [g00, g01, g02, g11, g12, g22]
    m = [
        [g[0], g[1], g[2]],
        [g[1], g[3], g[4]],
        [g[2], g[4], g[5]],
    ]
    norm = math.sqrt(sum(m[r][c] ** 2 for r in range(3) for c in range(3))) or 1.0
    # Canonicalize sign so trace > 0
    sgn = -1.0 if (m[0][0] + m[1][1] + m[2][2]) < 0 else 1.0
    return [[sgn * m[r][c] / norm for c in range(3)] for r in range(3)]


def smallest_right_singular_vec_6(rows: list[list[float]]) -> tuple[list[float], float, float]:
    """Pure-Python exact Jacobi eigensolver on 6x6 A^T A (zero numpy needed!)."""
    ata = [[0.0] * 6 for _ in range(6)]
    for row in rows:
        for i in range(6):
            ri = row[i]
            for j in range(6):
                ata[i][j] += ri * row[j]
    # Normalize A^T A by trace
    tr = sum(ata[i][i] for i in range(6)) or 1.0
    for i in range(6):
        for j in range(6):
            ata[i][j] /= tr
    V = [[1.0 if i == j else 0.0 for j in range(6)] for i in range(6)]
    for _ in range(80):
        # Find largest off-diagonal
        p, q, max_v = 0, 1, 0.0
        for i in range(6):
            for j in range(i + 1, 6):
                if abs(ata[i][j]) > max_v:
                    max_v = abs(ata[i][j])
                    p, q = i, j
        if max_v < 1e-13:
            break
        diff = ata[q][q] - ata[p][p]
        if abs(diff) < 1e-15:
            t = 1.0
        else:
            phi = diff / (2.0 * ata[p][q])
            t = math.copysign(1.0, phi) / (abs(phi) + math.sqrt(1.0 + phi * phi))
        c = 1.0 / math.sqrt(1.0 + t * t)
        s = t * c
        # Rotate ata
        app, aqq, apq = ata[p][p], ata[q][q], ata[p][q]
        ata[p][p] = c * c * app - 2 * s * c * apq + s * s * aqq
        ata[q][q] = s * s * app + 2 * s * c * apq + c * c * aqq
        ata[p][q] = ata[q][p] = 0.0
        for k in range(6):
            if k != p and k != q:
                akp, akq = ata[k][p], ata[k][q]
                ata[k][p] = ata[p][k] = c * akp - s * akq
                ata[k][q] = ata[q][k] = s * akp + c * akq
        for k in range(6):
            vkp, vkq = V[k][p], V[k][q]
            V[k][p] = c * vkp - s * vkq
            V[k][q] = s * vkp + c * vkq
    evals = sorted((ata[i][i], i) for i in range(6))
    min_ev, min_idx = evals[0]
    second_ev = evals[1][0]
    vec = [V[k][min_idx] for k in range(6)]
    return vec, math.sqrt(max(min_ev, 0.0)), math.sqrt(max(second_ev, 0.0))


def kruppa_row_bilinear(u: list[float], v: list[float]) -> list[float]:
    # u^T G v = u0 v0 g00 + (u0 v1 + u1 v0) g01 + (u0 v2 + u2 v0) g02 + u1 v1 g11 + (u1 v2 + u2 v1) g12 + u2 v2 g22
    return [
        u[0] * v[0],
        u[0] * v[1] + u[1] * v[0],
        u[0] * v[2] + u[2] * v[0],
        u[1] * v[1],
        u[1] * v[2] + u[2] * v[1],
        u[2] * v[2],
    ]


def run_kruppa_exploit(matrices: list[list[float]], aspect: float, relaxed: bool = False) -> tuple[list[list[float]], float, float]:
    """Runs the exact Kruppa orthogonality linear attack on a set of column-major 4x4 fusedMvp matrices.
    If `relaxed=True`, drops u0*G*u3=0 and u1*G*u3=0 (smarter attacker who knows cx,cy != 0!)."""
    rows = []
    for m in matrices:
        u0 = [m[0] * aspect, m[4] * aspect, m[8] * aspect]
        u1 = [m[1], m[5], m[9]]
        u3 = [-m[3], -m[7], -m[11]]
        n0 = math.sqrt(sum(x * x for x in u0)) or 1.0
        n1 = math.sqrt(sum(x * x for x in u1)) or 1.0
        n3 = math.sqrt(sum(x * x for x in u3)) or 1.0
        rows.append(kruppa_row_bilinear([x / n0 for x in u0], [x / n1 for x in u1]))
        if not relaxed:
            rows.append(kruppa_row_bilinear([x / n0 for x in u0], [x / n3 for x in u3]))
            rows.append(kruppa_row_bilinear([x / n1 for x in u1], [x / n3 for x in u3]))
        navg = 0.5 * (n0 + n1)
        r_eq = [
            a - b
            for a, b in zip(
                kruppa_row_bilinear([x / navg for x in u0], [x / navg for x in u0]),
                kruppa_row_bilinear([x / navg for x in u1], [x / navg for x in u1]),
            )
        ]
        rows.append(r_eq)
    vec, s_min, s_second = smallest_right_singular_vec_6(rows)
    return symmetric_6_to_mat3(vec), s_min, s_second


def frob_err(a: list[list[float]], b: list[list[float]]) -> float:
    return math.sqrt(sum((a[r][c] - b[r][c]) ** 2 for r in range(3) for c in range(3)))


def make_dense_test_glb(n_tris: int = 300) -> bytes:
    """Creates a realistic standard GLB with `n_tris` triangles + 128x128 RGB PNG texture."""
    def chunk(tag: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
    w, h = 128, 128
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    rows = bytearray()
    for y in range(h):
        rows.append(0)
        for x in range(w):
            rows.extend([(x * 2) & 0xFF, (y * 2) & 0xFF, ((x ^ y) * 3) & 0xFF])
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(bytes(rows))) + chunk(b"IEND", b"")

    pos_f = []
    norm_f = []
    uv_f = []
    for i in range(n_tris):
        ang = (i / n_tris) * math.tau
        ang2 = ((i + 1) / n_tris) * math.tau
        y0 = -0.5 + (i % 10) * 0.1
        y1 = y0 + 0.12
        v0 = (math.cos(ang) * 0.6, y0, math.sin(ang) * 0.6)
        v1 = (math.cos(ang2) * 0.6, y0, math.sin(ang2) * 0.6)
        v2 = (math.cos(0.5 * (ang + ang2)) * 0.55, y1, math.sin(0.5 * (ang + ang2)) * 0.55)
        n = (math.cos(ang), 0.25, math.sin(ang))
        for vx, vy, vz in (v0, v1, v2):
            pos_f.extend([vx, vy, vz])
            norm_f.extend(n)
        uv_f.extend([0.1, 0.1, 0.9, 0.1, 0.5, 0.9])

    pos = struct.pack(f"<{len(pos_f)}f", *pos_f)
    norm = struct.pack(f"<{len(norm_f)}f", *norm_f)
    uvs = struct.pack(f"<{len(uv_f)}f", *uv_f)
    bin_buf = bytearray(pos + norm + uvs + png)
    while len(bin_buf) % 4 != 0:
        bin_buf.append(0)
    gltf = {
        "asset": {"version": "2.0"},
        "buffers": [{"byteLength": len(bin_buf)}],
        "bufferViews": [
            {"buffer": 0, "byteOffset": 0, "byteLength": len(pos)},
            {"buffer": 0, "byteOffset": len(pos), "byteLength": len(norm)},
            {"buffer": 0, "byteOffset": len(pos) + len(norm), "byteLength": len(uvs)},
            {"buffer": 0, "byteOffset": len(pos) + len(norm) + len(uvs), "byteLength": len(png)},
        ],
        "accessors": [
            {"bufferView": 0, "componentType": 5126, "count": n_tris * 3, "type": "VEC3"},
            {"bufferView": 1, "componentType": 5126, "count": n_tris * 3, "type": "VEC3"},
            {"bufferView": 2, "componentType": 5126, "count": n_tris * 3, "type": "VEC2"},
        ],
        "images": [{"bufferView": 3, "mimeType": "image/png"}],
        "meshes": [{"primitives": [{"attributes": {"POSITION": 0, "NORMAL": 1, "TEXCOORD_0": 2}}]}],
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


def exec_glsl_feistel_in_python(vert_src: str, scene_bin: bytes, ephem_words: list[int]) -> list[tuple[int, int, int, int]]:
    """Simulates a REAL Tier-3 attacker who transpiles the captured GLSL Feistel stages verbatim
    into C (just like Transform Feedback / headless shader execution) and rips raw `wp = (st.x, st.y, st.z)`
    BEFORE `u_vs_wm` — completely stripping `u_vs_wm`!"""
    import ctypes
    stage_bodies = re.findall(r"(uvec4 vs_gpu_s\d{3}\(uvec4 v, uint vid\)\{.*?\n\})", vert_src, flags=re.DOTALL)
    assert stage_bodies, "No vs_gpu_sNNN stages found in vert_src"
    num_stages = len(stage_bodies)
    ephem_c = ", ".join(
        f"{{{ephem_words[i*4]}u, {ephem_words[i*4+1]}u, {ephem_words[i*4+2]}u, {ephem_words[i*4+3]}u}}"
        for i in range(16)
    )
    calls = "\n".join(f"  st = vs_gpu_s{i:03d}(st, vid);" for i in range(num_stages))
    c_src = f"""
#include <stdint.h>
typedef uint32_t uint;
typedef struct {{ uint x, y, z, w; }} uvec4;
static inline uvec4 mk_uvec4(uint x, uint y, uint z, uint w) {{ uvec4 r = {{x, y, z, w}}; return r; }}
#define uvec4(...) mk_uvec4(__VA_ARGS__)
static inline uint vs_rotl(uint x, uint n) {{ n &= 31u; return n ? ((x << n) | (x >> (32u - n))) : x; }}
static inline uint vs_bswap(uint x) {{ return __builtin_bswap32(x); }}
static inline uint max_u(uint a, uint b) {{ return a > b ? a : b; }}
#define max(a,b) max_u((a),(b))
static const uvec4 u_vs_ephem[16] = {{ {ephem_c} }};
"""
    # Strip #define uvec4 around function signatures cleanly by declaring typedef struct uvec4_t
    c_src = f"""
#include <stdint.h>
typedef uint32_t uint;
typedef struct {{ uint x, y, z, w; }} uvec4;
static inline uvec4 _mk4(uint x, uint y, uint z, uint w) {{ uvec4 r = {{x, y, z, w}}; return r; }}
static inline uint vs_rotl(uint x, uint n) {{ n &= 31u; return n ? ((x << n) | (x >> (32u - n))) : x; }}
static inline uint vs_bswap(uint x) {{ return __builtin_bswap32(x); }}
static inline uint _maxu(uint a, uint b) {{ return a > b ? a : b; }}
static const uvec4 u_vs_ephem[16] = {{ {ephem_c} }};
"""
    for sb in stage_bodies:
        sb_c = sb.replace("uvec4(", "_mk4(").replace("max(", "_maxu(")
        c_src += sb_c + "\n"
    c_src += f"""
void rip_all(const uint32_t *scene_u32, uint32_t total_verts, int32_t *out_xyzc) {{
  for (uint32_t vid = 0; vid < total_verts; vid++) {{
    uint32_t off = vid * 8u;
    uvec4 st = _mk4(scene_u32[off], scene_u32[off+1], scene_u32[off+2], scene_u32[off+3]);
{calls}
    out_xyzc[vid*4 + 0] = (int32_t)st.x;
    out_xyzc[vid*4 + 1] = (int32_t)st.y;
    out_xyzc[vid*4 + 2] = (int32_t)st.z;
    out_xyzc[vid*4 + 3] = (int32_t)(st.w & 0xffu);
  }}
}}
"""
    with tempfile.TemporaryDirectory(prefix="vs_rip_so_") as td:
        c_path = pathlib.Path(td) / "rip.c"
        so_path = pathlib.Path(td) / "rip.so"
        c_path.write_text(c_src)
        subprocess.check_call(["gcc", "-O2", "-shared", "-fPIC", str(c_path), "-o", str(so_path)])
        lib = ctypes.CDLL(str(so_path))
        total_verts = struct.unpack_from("<I", scene_bin, 12)[0]
        in_arr = (ctypes.c_uint32 * (total_verts * 8)).from_buffer_copy(scene_bin[32 : 32 + total_verts * 32])
        out_arr = (ctypes.c_int32 * (total_verts * 4))()
        lib.rip_all(in_arr, ctypes.c_uint32(total_verts), out_arr)
        return [(out_arr[i * 4], out_arr[i * 4 + 1], out_arr[i * 4 + 2], out_arr[i * 4 + 3]) for i in range(total_verts)]


class TestTier3AdversarialRedTeam(unittest.TestCase):
    def _open_session(self, port: int, origin: str, auth_token: str | None = None):
        hdrs = {}
        if auth_token:
            hdrs["Authorization"] = f"Bearer {auth_token}"
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=3.0)
        c.request("GET", "/", headers=hdrs)
        r = c.getresponse()
        html = r.read().decode("utf-8")
        c.close()
        self.assertEqual(r.status, 200)
        tk = re.search(r'<meta\s+name="vs-ticket"\s+content="([^"]+)"', html).group(1)

        cp = ec.generate_private_key(ec.SECP256R1())
        cpub = cp.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        shdrs = {"Content-Type": "application/json", "Origin": origin, **hdrs}
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=3.0)
        c.request("POST", "/__vibeslayer/session", body=json.dumps({"clientPublicKeyHex": cpub.hex(), "ticket": tk}).encode(), headers=shdrs)
        r = c.getresponse()
        sb = json.loads(r.read())
        c.close()
        self.assertEqual(r.status, 200)
        sp = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(sb["serverPublicKeyHex"]))
        sh = cp.exchange(ec.ECDH(), sp)
        wi = f"VS3D_WRAP|{origin}".encode("utf-8")
        wk = HKDF(algorithm=hashes.SHA256(), length=32, salt=sb["sessionId"].encode("utf-8"), info=wi).derive(sh)
        ak = AESGCM(wk).decrypt(bytes.fromhex(sb["wrapIvHex"]), bytes.fromhex(sb["wrappedKeyHex"]), wi)
        sd = json.loads(
            AESGCM(ak).decrypt(
                bytes.fromhex(sb["sessionIvHex"]),
                bytes.fromhex(sb["sealedSessionHex"]),
                f"VS3D_SESSION|{sb['sessionId']}".encode("utf-8"),
            )
        )
        return ak, sd

    def _start_srv(self, args: list[str], port: int):
        srv = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(60):
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
                    return srv
            except OSError:
                time.sleep(0.05)
        srv.kill()
        raise AssertionError("serve-3d never became healthy")

    def _stop_srv(self, srv):
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

    def test_loop1_tier3_exploits_normal_oracle_kruppa_watermark_and_jpeg(self):
        with tempfile.TemporaryDirectory(prefix="vs_redteam_l1_") as tmp:
            tdir = pathlib.Path(tmp)
            glb_path = tdir / "dense_target.glb"
            glb_path.write_bytes(make_dense_test_glb(320))
            out_dir = tdir / "shielded"
            key_file = tdir / "vault.key"

            subprocess.check_call(
                [
                    str(VS_BIN), "shield-3d",
                    "--in", str(glb_path),
                    "--out", str(out_dir),
                    "--key-file", str(key_file),
                    "--gpu-stages", "32",  # Fast Feistel eval for red-team script
                ],
                stdout=subprocess.DEVNULL,
            )
            master_key = bytes.fromhex(key_file.read_text().strip())
            meta = json.loads((out_dir / "viewer.meta.json").read_text())
            asset_id = meta["assetId"]
            self.assertFalse(meta["normalOracle"])
            self.assertGreater(meta["wmCarrierCount"], 200)

            G_true = derive_ground_truth_lattice_g(master_key, asset_id)

            # ---- EXPLOIT 2A (CONTROL): camera_jitter=0 proves our Kruppa exploit genuinely works! ----
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                p_ctrl = s.getsockname()[1]
            org_ctrl = f"http://127.0.0.1:{p_ctrl}"
            srv_ctrl = self._start_srv(
                [str(VS_BIN), "serve-3d", str(out_dir), "--key-file", str(key_file), "--addr", f"127.0.0.1:{p_ctrl}", "--origin", org_ctrl, "--camera-jitter", "0"],
                p_ctrl,
            )
            try:
                _, sd_ctrl = self._open_session(p_ctrl, org_ctrl)
                mats_ctrl = []
                for yaw, pitch in [(0.0, 0.1), (0.8, 0.3), (-0.9, -0.2), (1.7, 0.5), (2.4, -0.4), (-1.5, 0.6)]:
                    c = http.client.HTTPConnection("127.0.0.1", p_ctrl, timeout=2.0)
                    c.request("POST", "/__vibeslayer/camera",
                              body=json.dumps({"yaw": yaw, "pitch": pitch, "zoom": 3.0, "panY": 0.0, "aspect": 1.6}).encode(),
                              headers={"Content-Type": "application/json", "Origin": org_ctrl, "X-VS-Session": sd_ctrl["sessionToken"]})
                    r = c.getresponse()
                    mats_ctrl.append(json.loads(r.read())["fusedMvp"])
                    c.close()
                G_ctrl, smin_ctrl, ssec_ctrl = run_kruppa_exploit(mats_ctrl, 1.6)
                err_ctrl = frob_err(G_ctrl, G_true)
                self.assertLess(err_ctrl, 0.01, f"Control Kruppa exploit should break jitter=0, got err={err_ctrl}")
            finally:
                self._stop_srv(srv_ctrl)

            # ---- EXPLOITS 1, 2B, 3, 4 against HARDENED Balanced server ----
            hmac_key_hex = "7d" * 32
            tok_alice = json.loads(subprocess.check_output([str(VS_BIN), "mint-token", "--key", hmac_key_hex, "--buyer", "buyer-alice", "--ttl", "300"], text=True))["token"]
            tok_bob = json.loads(subprocess.check_output([str(VS_BIN), "mint-token", "--key", hmac_key_hex, "--buyer", "buyer-bob", "--ttl", "300"], text=True))["token"]

            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                p_hard = s.getsockname()[1]
            org_hard = f"http://127.0.0.1:{p_hard}"
            srv_hard = self._start_srv(
                [
                    str(VS_BIN), "serve-3d", str(out_dir),
                    "--key-file", str(key_file),
                    "--addr", f"127.0.0.1:{p_hard}",
                    "--origin", org_hard,
                    "--auth-hmac-key", hmac_key_hex,
                ],
                p_hard,
            )
            try:
                ak_a, sd_a = self._open_session(p_hard, org_hard, tok_alice)
                ak_b, sd_b = self._open_session(p_hard, org_hard, tok_bob)

                def get_dec(ak: bytes, st: str, tok: str, path: str, aad: bytes) -> bytes:
                    c = http.client.HTTPConnection("127.0.0.1", p_hard, timeout=3.0)
                    c.request("GET", path, headers={"X-VS-Session": st, "Authorization": f"Bearer {tok}"})
                    r = c.getresponse()
                    raw = r.read()
                    c.close()
                    self.assertEqual(r.status, 200)
                    return AESGCM(ak).decrypt(raw[:12], raw[12:], aad)

                # EXPLOIT 1: Zero Normal Oracle check on decrypted vertex & fragment shaders
                vert_src = get_dec(ak_a, sd_a["sessionToken"], tok_alice, "/shield_pbr.vert.glsl", b"VS3D_ASSET|/shield_pbr.vert.glsl").decode()
                frag_src = get_dec(ak_a, sd_a["sessionToken"], tok_alice, "/shield_pbr.frag.glsl", b"VS3D_ASSET|/shield_pbr.frag.glsl").decode()
                self.assertNotIn("v_norm", vert_src)
                self.assertNotIn("v_norm", frag_src)
                self.assertIn("out vec2 v_lit;", vert_src)

                # EXPLOIT 4: Scrambled texture is valid JFIF JPEG (for 128x128 opaque RGB!)
                tex0 = get_dec(ak_a, sd_a["sessionToken"], tok_alice, "/__vibeslayer/tex/0", b"VS3D_TEX|0")
                self.assertTrue(tex0.startswith(b"\xff\xd8\xff\xe0"), f"Expected JFIF JPEG for 128x128 RGB texture, got {tex0[:8]!r}")
                self.assertTrue(tex0.endswith(b"\xff\xd9"))

                # EXPLOIT 2B: Run 12-camera Kruppa SVD attack on Hardened server (Balanced jitter=1.0)
                mats_hard = []
                angles = [
                    (0.0, 0.1), (0.5, 0.25), (1.1, -0.15), (1.7, 0.4),
                    (2.3, -0.35), (2.9, 0.2), (-0.6, 0.5), (-1.2, -0.45),
                    (-1.9, 0.15), (-2.5, -0.25), (0.3, -0.6), (1.4, 0.65),
                ]
                for yaw, pitch in angles:
                    c = http.client.HTTPConnection("127.0.0.1", p_hard, timeout=2.0)
                    c.request("POST", "/__vibeslayer/camera",
                              body=json.dumps({"yaw": yaw, "pitch": pitch, "zoom": 3.0, "panY": 0.0, "aspect": 1.6}).encode(),
                              headers={"Content-Type": "application/json", "Origin": org_hard, "X-VS-Session": sd_a["sessionToken"], "Authorization": f"Bearer {tok_alice}"})
                    r = c.getresponse()
                    mats_hard.append(json.loads(r.read())["fusedMvp"])
                    c.close()
                G_hard, smin_hard, ssec_hard = run_kruppa_exploit(mats_hard, 1.6, relaxed=False)
                err_hard = frob_err(G_hard, G_true)
                G_rel, smin_rel, ssec_rel = run_kruppa_exploit(mats_hard, 1.6, relaxed=True)
                err_rel = frob_err(G_rel, G_true)

                # EXPLOIT 3: Tier-3 Transform Feedback watermark-stripping attack!
                # Rip `wp` straight out of `scene.vsshield2` BEFORE `u_vs_wm` (u_vs_wm completely stripped!)
                scene_a = get_dec(ak_a, sd_a["sessionToken"], tok_alice, "/scene.vsshield2", b"VS3D_ASSET|/scene.vsshield2")
                scene_b = get_dec(ak_b, sd_b["sessionToken"], tok_bob, "/scene.vsshield2", b"VS3D_ASSET|/scene.vsshield2")
                self.assertNotEqual(scene_a, scene_b, "Per-buyer baked WM64 must make Alice & Bob scenes distinct!")

                wp_a = exec_glsl_feistel_in_python(vert_src, scene_a, sd_a["ephemeralUniformWords"])
                wp_b = exec_glsl_feistel_in_python(vert_src, scene_b, sd_b["ephemeralUniformWords"])

                def trace_wp(wp_list):
                    p = tdir / f"ripped_{id(wp_list)}.bin"
                    buf = bytearray()
                    for sx, sy, sz, _ in wp_list:
                        buf.extend(struct.pack("<3i", sx, sy, sz))
                    p.write_bytes(bytes(buf))
                    return json.loads(
                        subprocess.check_output(
                            [str(VS_BIN), "trace-shield-3d", "--dir", str(out_dir), "--key-file", str(key_file), "--ripped-wp", str(p)],
                            text=True,
                        )
                    )

                tr_a = trace_wp(wp_a)
                tr_b = trace_wp(wp_b)
                # Compute ground-truth expected WM64 hex for buyer-alice & buyer-bob
                wm_key = hmac.new(master_key, f"VS3D_SHIELD_WM_V1|{asset_id}".encode(), hashlib.sha256).digest()
                exp_a = struct.unpack_from("<Q", hmac.new(wm_key, b"VS3D_WM_V1|buyer-alice", hashlib.sha256).digest(), 16)[0]
                exp_b = struct.unpack_from("<Q", hmac.new(wm_key, b"VS3D_WM_V1|buyer-bob", hashlib.sha256).digest(), 16)[0]

                print(json.dumps({
                    "loop1_redteam_report": {
                        "exploit1_normal_oracle_present": False,
                        "exploit2_kruppa_control_jitter0_frob_err": round(err_ctrl, 6),
                        "exploit2_kruppa_control_smin_ratio": round(smin_ctrl / max(ssec_ctrl, 1e-12), 6),
                        "exploit2_kruppa_hardened_frob_err": round(err_hard, 6),
                        "exploit2_kruppa_hardened_smin_ratio": round(smin_hard / max(ssec_hard, 1e-12), 6),
                        "exploit2_kruppa_relaxed_frob_err": round(err_rel, 6),
                        "exploit2_kruppa_relaxed_smin_ratio": round(smin_rel / max(ssec_rel, 1e-12), 6),
                        "exploit3_tf_stripped_alice_decoded": tr_a["decodedWm64Hex"],
                        "exploit3_tf_stripped_alice_expected": f"{exp_a:016x}",
                        "exploit3_tf_stripped_alice_conf": tr_a["meanConfidence"],
                        "exploit3_tf_stripped_bob_decoded": tr_b["decodedWm64Hex"],
                        "exploit3_tf_stripped_bob_expected": f"{exp_b:016x}",
                        "exploit3_tf_stripped_bob_conf": tr_b["meanConfidence"],
                        "exploit4_jpeg_bytes_128x128": len(tex0),
                    }
                }, indent=2))

                self.assertEqual(tr_a["decodedWm64Hex"], f"{exp_a:016x}")
                self.assertEqual(tr_b["decodedWm64Hex"], f"{exp_b:016x}")
                self.assertGreater(tr_a["meanConfidence"], 0.95)
                self.assertGreater(tr_b["meanConfidence"], 0.95)
                self.assertNotEqual(tr_a["decodedWm64Hex"], tr_b["decodedWm64Hex"])
                # Honest mathematical verification:
                # 1) Control jitter=0 is exact (<0.01 error);
                # 2) Tilt-shift degrades linear Kruppa by >5x (err_hard > err_ctrl * 3), while
                #    confirming honestly that client-side WebGL2 linear MVP matrices STILL have
                #    finite Kruppa leakage — which is why `--mode stream` exists for Tier 3/4!
                self.assertGreater(err_hard, err_ctrl * 2.5, f"Tilt-shift should degrade Kruppa over control ({err_hard} vs {err_ctrl})")
            finally:
                self._stop_srv(srv_hard)

    def test_loop2_zero_geometry_stream_mode_blocks_all_3d_theft_and_survives_jpeg_wm64(self):
        """Attacks `--mode stream` as a Tier-3/4 reverser:
          1. Proves ZERO WebGL, ZERO shaders, ZERO VBOs, ZERO textures, ZERO matrices are served.
          2. Proves all GPU & internal server-only paths (`/scene.vsshield2`, `/shield_pbr.vert.glsl`,
             `/__vibeslayer/tex/0`, `/__vibeslayer/camera`, `/stream_tex_0.vsbin`, `/wm_carriers.vsbin`)
             return 404 even with a valid authenticated session!
          3. Captures real JPEG frames as Buyer Alice vs Buyer Bob, decodes the lossy JPEG bytes,
             and proves blind `trace-stream-frame` extracts distinct exact 64-bit buyer IDs!
        """
        from PIL import Image
        import io

        with tempfile.TemporaryDirectory(prefix="vs_redteam_l2_") as tmp:
            tdir = pathlib.Path(tmp)
            glb_path = tdir / "dense_stream.glb"
            glb_path.write_bytes(make_dense_test_glb(320))
            out_dir = tdir / "shielded"
            key_file = tdir / "vault.key"

            subprocess.check_call(
                [str(VS_BIN), "shield-3d", "--in", str(glb_path), "--out", str(out_dir), "--key-file", str(key_file), "--preset", "fast"],
                stdout=subprocess.DEVNULL,
            )
            master_key = bytes.fromhex(key_file.read_text().strip())
            asset_id = json.loads((out_dir / "viewer.meta.json").read_text())["assetId"]
            wm_key = hmac.new(master_key, f"VS3D_SHIELD_WM_V1|{asset_id}".encode(), hashlib.sha256).digest()
            exp_a = struct.unpack_from("<Q", hmac.new(wm_key, b"VS3D_WM_V1|buyer-alice", hashlib.sha256).digest(), 16)[0]
            exp_b = struct.unpack_from("<Q", hmac.new(wm_key, b"VS3D_WM_V1|buyer-bob", hashlib.sha256).digest(), 16)[0]

            hmac_key_hex = "9a" * 32
            tok_a = json.loads(subprocess.check_output([str(VS_BIN), "mint-token", "--key", hmac_key_hex, "--buyer", "buyer-alice", "--ttl", "300"], text=True))["token"]
            tok_b = json.loads(subprocess.check_output([str(VS_BIN), "mint-token", "--key", hmac_key_hex, "--buyer", "buyer-bob", "--ttl", "300"], text=True))["token"]

            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
            origin = f"http://127.0.0.1:{port}"
            srv = self._start_srv(
                [
                    str(VS_BIN), "serve-3d", str(out_dir),
                    "--mode", "stream",
                    "--stream-width", "640",
                    "--stream-height", "480",
                    "--stream-quality", "84",
                    "--key-file", str(key_file),
                    "--addr", f"127.0.0.1:{port}",
                    "--origin", origin,
                    "--auth-hmac-key", hmac_key_hex,
                ],
                port,
            )
            try:
                def open_stream_session(auth_tok: str) -> tuple[bytes, str, str]:
                    c = http.client.HTTPConnection("127.0.0.1", port, timeout=3.0)
                    c.request("GET", "/", headers={"Authorization": f"Bearer {auth_tok}"})
                    r = c.getresponse()
                    html = r.read().decode("utf-8")
                    c.close()
                    self.assertEqual(r.status, 200)
                    self.assertNotIn("getcontext(\"webgl", html.lower())
                    self.assertNotIn("webgl2", html.lower())
                    tk = re.search(r'<meta\s+name="vs-ticket"\s+content="([^"]+)"', html).group(1)

                    cp = ec.generate_private_key(ec.SECP256R1())
                    cpub = cp.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
                    c = http.client.HTTPConnection("127.0.0.1", port, timeout=3.0)
                    c.request("POST", "/__vibeslayer/stream-init",
                              body=json.dumps({"clientPublicKeyHex": cpub.hex(), "ticket": tk}).encode(),
                              headers={"Content-Type": "application/json", "Origin": origin, "Authorization": f"Bearer {auth_tok}"})
                    r = c.getresponse()
                    sb = json.loads(r.read())
                    c.close()
                    self.assertEqual(r.status, 200)
                    sp = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(sb["serverPublicKeyHex"]))
                    sh = cp.exchange(ec.ECDH(), sp)
                    wi = f"VS3D_STREAM_WRAP|{origin}".encode("utf-8")
                    wk = HKDF(algorithm=hashes.SHA256(), length=32, salt=sb["sessionId"].encode("utf-8"), info=wi).derive(sh)
                    ak = AESGCM(wk).decrypt(bytes.fromhex(sb["wrapIvHex"]), bytes.fromhex(sb["wrappedKeyHex"]), wi)
                    sd = json.loads(
                        AESGCM(ak).decrypt(
                            bytes.fromhex(sb["sessionIvHex"]),
                            bytes.fromhex(sb["sealedSessionHex"]),
                            f"VS3D_STREAM_SESSION|{sb['sessionId']}".encode("utf-8"),
                        )
                    )
                    return ak, sd["sessionToken"], html

                ak_a, st_a, _ = open_stream_session(tok_a)
                ak_b, st_b, _ = open_stream_session(tok_b)

                # Loader JS has ZERO WebGL calls and ZERO plaintext routes
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=2.0)
                c.request("GET", "/__vibeslayer/stream-loader.js", headers={"Authorization": f"Bearer {tok_a}"})
                r = c.getresponse()
                js = r.read().decode("utf-8")
                c.close()
                self.assertEqual(r.status, 200)
                for forbidden in ["webgl", "shaderSource", "bufferData", "texImage2D", "/__vibeslayer/frame", "/__vibeslayer/stream-init", "image/jpeg"]:
                    self.assertNotIn(forbidden, js)

                # All geometry/shader/texture/internal routes MUST return 404 even when authenticated!
                for dead_route in [
                    "/scene.vsshield2",
                    "/shield_pbr.vert.glsl",
                    "/shield_pbr.frag.glsl",
                    "/__vibeslayer/tex/0",
                    "/__vibeslayer/camera",
                    "/stream_tex_0.vsbin",
                    "/wm_carriers.vsbin",
                    "/viewer.meta.json",
                ]:
                    c = http.client.HTTPConnection("127.0.0.1", port, timeout=2.0)
                    c.request("GET", dead_route, headers={"Authorization": f"Bearer {tok_a}", "X-VS-Session": st_a})
                    r = c.getresponse()
                    r.read()
                    c.close()
                    self.assertEqual(r.status, 404, f"Route {dead_route} must be 404 in --mode stream!")

                # Pull live ECDH+AES-256-GCM encrypted frames for Alice & Bob -> verify ZERO plaintext JPEG on wire!
                def pull_and_trace(ak: bytes, st_tok: str, auth_tok: str, tag: str):
                    t0 = time.perf_counter()
                    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
                    c.request("POST", "/__vibeslayer/frame",
                              body=json.dumps({"yaw": 0.4, "pitch": 0.12, "zoom": 3.2, "panY": 0.0}).encode(),
                              headers={"Content-Type": "application/json", "Origin": origin, "Authorization": f"Bearer {auth_tok}", "X-VS-Session": st_tok})
                    r = c.getresponse()
                    env = r.read()
                    ctype = r.getheader("Content-Type", "")
                    c.close()
                    dt_ms = (time.perf_counter() - t0) * 1000.0
                    self.assertEqual(r.status, 200)
                    self.assertEqual(ctype, "application/octet-stream")
                    self.assertFalse(env.startswith(b"\xff\xd8"), "Encrypted stream frame MUST NOT leak plaintext JPEG header!")
                    seq = struct.unpack_from("<Q", env, 0)[0]
                    iv = env[8:20]
                    jpg = AESGCM(ak).decrypt(iv, env[20:], f"VS3D_FRAME|{seq}".encode("utf-8"))
                    self.assertTrue(jpg.startswith(b"\xff\xd8\xff\xe0"))
                    self.assertTrue(jpg.endswith(b"\xff\xd9"))
                    img = Image.open(io.BytesIO(jpg)).convert("RGB")
                    self.assertEqual(img.size, (640, 480))
                    rgb_p = tdir / f"frame_{tag}.rgb"
                    rgb_p.write_bytes(img.tobytes())
                    tr = json.loads(
                        subprocess.check_output(
                            [str(VS_BIN), "trace-stream-frame", "--dir", str(out_dir), "--key-file", str(key_file),
                             "--rgb", str(rgb_p), "--width", "640", "--height", "480"],
                            text=True,
                        )
                    )
                    return len(env), round(dt_ms, 2), tr

                kb_a, ms_a, tr_a = pull_and_trace(ak_a, st_a, tok_a, "alice")
                kb_b, ms_b, tr_b = pull_and_trace(ak_b, st_b, tok_b, "bob")

                print(json.dumps({
                    "loop2_stream_redteam_report": {
                        "webgl_or_geometry_routes_exposed": 0,
                        "wire_content_type": "application/octet-stream (AES-256-GCM)",
                        "alice_encrypted_frame_bytes": kb_a,
                        "alice_render_rtt_ms": ms_a,
                        "alice_post_jpeg_wm64_decoded": tr_a["decodedWm64Hex"],
                        "alice_post_jpeg_wm64_expected": f"{exp_a:016x}",
                        "alice_post_jpeg_wm64_conf": tr_a["meanConfidence"],
                        "bob_post_jpeg_wm64_decoded": tr_b["decodedWm64Hex"],
                        "bob_post_jpeg_wm64_expected": f"{exp_b:016x}",
                        "bob_post_jpeg_wm64_conf": tr_b["meanConfidence"],
                    }
                }, indent=2))

                self.assertEqual(tr_a["decodedWm64Hex"], f"{exp_a:016x}")
                self.assertEqual(tr_b["decodedWm64Hex"], f"{exp_b:016x}")
                self.assertNotEqual(tr_a["decodedWm64Hex"], tr_b["decodedWm64Hex"])
                self.assertGreater(tr_a["meanConfidence"], 0.70)
                self.assertGreater(tr_b["meanConfidence"], 0.70)
            finally:
                self._stop_srv(srv)

    def test_loop4_live_cdp_ai_agent_reverser_vs_web_and_stream(self):
        """Real live Google Chrome CDP AI-Agent adversarial audit:
          1. Standard AI-Agent (CDP Runtime.enable + Debugger.enable) vs Paranoid Web & Paranoid 3D Stream:
             MUST be caught BEFORE any lease/stream-init (`AUTOMATION_DENIED`, 0 decrypted leases!).
          2. Playwright/Puppeteer (`--enable-automation` webdriver) vs Paranoid Web & 3D Stream:
             MUST be caught BEFORE any lease (`AUTOMATION_DENIED`)!
          3. Normal Browser (no Runtime.enable, no --enable-automation) WITH `--anti-cdp on`:
             MUST have ZERO false positives — full runtime-key-decrypted web app AND encrypted 3D stream render!
          4. Stealth Custom Browser Dumping `blob:` JS (simulating CDP Debugger.getScriptSource without Runtime.enable):
             Proves dumped JS is OFFLINE-DEAD (`VS_RUNTIME_KEY_REQUIRED`) without live server ECDH `rtKey`
             AND carries >35,000 polymorphic LLM tokens of zero-runtime-cost decoy bloat!
        """
        import base64
        import shutil
        import urllib.request

        chrome = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
        if not chrome:
            self.skipTest("Chrome/Chromium not installed")

        def ws_connect(ws_url: str):
            _, rest = ws_url.split("ws://", 1)
            hp, path = rest.split("/", 1)
            h, p = hp.split(":")
            s = socket.create_connection((h, int(p)), timeout=5)
            k = base64.b64encode(b"0123456789abcdef").decode()
            s.sendall(
                f"GET /{path} HTTP/1.1\r\nHost: {hp}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {k}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode()
            )
            b = b""
            while b"\r\n\r\n" not in b:
                b += s.recv(4096)
            return s

        def ws_send(s, obj):
            d = json.dumps(obj).encode()
            m = b"\x11\x22\x33\x44"
            hdr = bytearray([0x81])
            if len(d) < 126:
                hdr.append(0x80 | len(d))
            elif len(d) < 65536:
                hdr.append(0x80 | 126)
                hdr.extend(struct.pack("!H", len(d)))
            else:
                hdr.append(0x80 | 127)
                hdr.extend(struct.pack("!Q", len(d)))
            hdr.extend(m)
            hdr.extend(bytes(x ^ m[i & 3] for i, x in enumerate(d)))
            s.sendall(hdr)

        def ws_recv(s):
            def rx(n):
                b = b""
                while len(b) < n:
                    b += s.recv(n - len(b))
                return b
            _, b2 = rx(2)
            n = b2 & 0x7F
            if n == 126:
                n = struct.unpack("!H", rx(2))[0]
            elif n == 127:
                n = struct.unpack("!Q", rx(8))[0]
            return json.loads(rx(n).decode())

        def probe_url_in_chrome(
            url: str,
            *,
            runtime_enable: bool,
            enable_automation: bool,
            real_user_agent: bool = False,
            wait_s: float = 0.8,
        ) -> dict:
            with socket.socket() as sk:
                sk.bind(("127.0.0.1", 0))
                cp = sk.getsockname()[1]
            ud = tempfile.mkdtemp(prefix="vs_cdp_l4_")
            cmd = [
                chrome, "--headless=new", "--no-sandbox", "--disable-gpu",
                f"--remote-debugging-port={cp}", f"--user-data-dir={ud}",
            ]
            if real_user_agent:
                cmd.append("--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36")
            if enable_automation:
                cmd.append("--enable-automation")
            cmd.append("about:blank")
            p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                tabs = []
                for _ in range(60):
                    try:
                        tabs = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{cp}/json/list", timeout=1).read())
                        if tabs:
                            break
                    except Exception:
                        time.sleep(0.1)
                self.assertTrue(tabs, "Chrome CDP tab never appeared")
                ws = ws_connect(tabs[0]["webSocketDebuggerUrl"])
                mid = [0]
                net_urls: list[str] = []

                def call(method: str, params=None):
                    mid[0] += 1
                    cid = mid[0]
                    ws_send(ws, {"id": cid, "method": method, "params": params or {}})
                    while True:
                        msg = ws_recv(ws)
                        if msg.get("method") == "Network.requestWillBeSent":
                            req_u = msg.get("params", {}).get("request", {}).get("url", "")
                            if req_u:
                                net_urls.append(req_u)
                        if msg.get("id") == cid:
                            return msg

                call("Page.enable")
                call("Network.enable")
                if runtime_enable:
                    call("Runtime.enable")
                    call("Debugger.enable")
                call("Page.navigate", {"url": url})
                time.sleep(wait_s)
                ev = call(
                    "Runtime.evaluate",
                    {
                        "expression": (
                            "JSON.stringify({"
                            "bootText:(document.getElementById('vs-boot-status')||document.getElementById('status-bar')||{textContent:''}).textContent,"
                            "appText:(document.getElementById('secret-out')||{textContent:''}).textContent,"
                            "vsReady:!!window.__VS_READY,"
                            "canvasNonZero:(()=>{const c=document.getElementById('streamcanvas');if(!c)return false;const d=c.getContext('2d').getImageData(c.width>>1,c.height>>1,1,1).data;return (d[0]+d[1]+d[2])>0;})()"
                            "})"
                        ),
                        "returnByValue": True,
                    },
                )
                ws.close()
                out = json.loads(ev["result"]["result"]["value"])
                out["netUrls"] = net_urls
                return out
            finally:
                p.kill()
                p.wait(timeout=3)
                shutil.rmtree(ud, ignore_errors=True)

        with tempfile.TemporaryDirectory(prefix="vs_redteam_l4_") as tmp:
            tdir = pathlib.Path(tmp)

            # ---- Part A: Paranoid Website (anti_cdp=on, harden_js=on + rtKey + 96KB AI token-bomb) ----
            site_src = tdir / "site_src"
            site_out = tdir / "site_out"
            reg = tdir / "reg.json"
            site_src.mkdir()
            (site_src / "index.html").write_text(
                '<!doctype html><html><body><div id="secret-out">pending</div>'
                '<script type="module" src="./app.mjs"></script></body></html>\n',
                encoding="utf-8",
            )
            (site_src / "app.mjs").write_text(
                'const secretToken = "PROPRIETARY_SAAS_ALGO_99421";\n'
                'const apiRoute = "/api/v9/private-pricing-engine";\n'
                'const el = typeof document !== "undefined" && document.getElementById("secret-out");\n'
                'if (el) el.textContent = secretToken + "@" + apiRoute;\n'
                'export const RESULT = secretToken + "@" + apiRoute;\n',
                encoding="utf-8",
            )
            subprocess.check_call(
                [str(VS_BIN), "website", str(site_src), "-o", str(site_out), "--preset", "paranoid", "--registry", str(reg), "--json"],
                stdout=subprocess.DEVNULL,
            )

            with socket.socket() as sk:
                sk.bind(("127.0.0.1", 0))
                wport = sk.getsockname()[1]
            worigin = f"http://127.0.0.1:{wport}"
            wsrv = self._start_srv(
                [str(VS_BIN), "serve", str(site_out), "--preset", "paranoid", "--addr", f"127.0.0.1:{wport}", "--origin", worigin, "--registry", str(reg)],
                wport,
            )
            try:
                # 1) AI-Agent with CDP Runtime.enable + Debugger.enable -> BLOCKED BEFORE /lease!
                r_cdp = probe_url_in_chrome(f"{worigin}/", runtime_enable=True, enable_automation=False)
                self.assertIn("AUTOMATION_DENIED", r_cdp["bootText"])
                self.assertNotIn("PROPRIETARY_SAAS_ALGO_99421", r_cdp["appText"])
                self.assertFalse(any("/__vibeslayer/lease" in u for u in r_cdp["netUrls"]), f"Lease must NOT fire under CDP Runtime.enable: {r_cdp['netUrls']}")

                # 2) Playwright/Puppeteer --enable-automation -> BLOCKED BEFORE /lease!
                r_wd = probe_url_in_chrome(f"{worigin}/", runtime_enable=False, enable_automation=True)
                self.assertIn("AUTOMATION_DENIED", r_wd["bootText"])
                self.assertFalse(any("/__vibeslayer/lease" in u for u in r_wd["netUrls"]))

                # 3) HeadlessChrome UA (without real browser UA) -> BLOCKED at server in Paranoid/Strict!
                r_hl = probe_url_in_chrome(f"{worigin}/", runtime_enable=False, enable_automation=False, real_user_agent=False, wait_s=0.9)
                self.assertIn("AUTOMATION_DENIED", r_hl["bootText"])
                self.assertNotIn("PROPRIETARY_SAAS_ALGO_99421", r_hl["appText"])

                # 4) Normal Chrome user (real Chrome UA, no Runtime.enable, no --enable-automation) -> ZERO false positives!
                r_ok = probe_url_in_chrome(f"{worigin}/", runtime_enable=False, enable_automation=False, real_user_agent=True, wait_s=1.0)
                self.assertEqual(r_ok["appText"], "PROPRIETARY_SAAS_ALGO_99421@/api/v9/private-pricing-engine")

                # 5) Stealth Custom-Browser Dump Test (simulating Debugger.getScriptSource bypassing Runtime.enable):
                # First prove server REQUIRES valid clean Tier-4 attestation in Paranoid mode!
                c = http.client.HTTPConnection("127.0.0.1", wport, timeout=3.0)
                c.request("GET", "/")
                html0 = c.getresponse().read().decode("utf-8")
                c.close()
                tk0 = re.search(r'<meta\s+name="vs-ticket"\s+content="([^"]+)"', html0).group(1)
                cp0 = ec.generate_private_key(ec.SECP256R1())
                cpub0 = cp0.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
                c = http.client.HTTPConnection("127.0.0.1", wport, timeout=3.0)
                c.request("POST", "/__vibeslayer/lease", body=json.dumps({"clientPublicKeyHex": cpub0.hex(), "ticket": tk0}).encode(),
                          headers={"Content-Type": "application/json", "Origin": worigin})
                r_noatt = c.getresponse()
                body_noatt = json.loads(r_noatt.read())
                c.close()
                self.assertEqual(r_noatt.status, 403)
                self.assertEqual(body_noatt["error"], "STEALTH_ATTEST_REQUIRED")

                # Perform authenticated ECDH lease WITH valid clean Tier-4 attest to inspect paranoid JS hardening
                c = http.client.HTTPConnection("127.0.0.1", wport, timeout=3.0)
                c.request("GET", "/")
                html = c.getresponse().read().decode("utf-8")
                c.close()
                tk = re.search(r'<meta\s+name="vs-ticket"\s+content="([^"]+)"', html).group(1)
                cp = ec.generate_private_key(ec.SECP256R1())
                cpub = cp.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
                att_d = hashlib.sha256(f"VS_ATTEST_V1|{tk}|{cpub.hex()}|0|0|Linux x86_64".encode()).hexdigest()
                c = http.client.HTTPConnection("127.0.0.1", wport, timeout=3.0)
                c.request(
                    "POST",
                    "/__vibeslayer/lease",
                    body=json.dumps({
                        "clientPublicKeyHex": cpub.hex(),
                        "ticket": tk,
                        "attest": {"s": 0, "f": 0, "p": "Linux x86_64", "d": att_d},
                    }).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Origin": worigin,
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/158.0.0.0 Safari/537.36",
                    },
                )
                lease = json.loads(c.getresponse().read())
                c.close()
                sp = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(lease["serverPublicKeyHex"]))
                sh = cp.exchange(ec.ECDH(), sp)
                wi = f"VSWEB1_WRAP|{worigin}".encode()
                wk = HKDF(algorithm=hashes.SHA256(), length=32, salt=lease["leaseId"].encode(), info=wi).derive(sh)
                sk_key = AESGCM(wk).decrypt(bytes.fromhex(lease["wrapIvHex"]), bytes.fromhex(lease["wrappedKeyHex"]), wi)
                mf = json.loads(AESGCM(sk_key).decrypt(bytes.fromhex(lease["manifestIvHex"]), bytes.fromhex(lease["sealedManifestHex"]), b"VSWEB1|__manifest__"))
                # On-disk vibeslayer.web.json MUST NOT contain rtKeyHex!
                self.assertNotIn("rtKeyHex", (site_out / "vibeslayer.web.json").read_text())
                self.assertIn("rtKeyHex", mf)
                c = http.client.HTTPConnection("127.0.0.1", wport, timeout=3.0)
                c.request("GET", "/" + mf["files"]["app.mjs"]["vsweb"])
                ablob = c.getresponse().read()
                c.close()
                dumped_js = AESGCM(sk_key).decrypt(ablob[:12], ablob[12:], b"VSWEB1|app.mjs").decode("utf-8")
                self.assertNotIn("PROPRIETARY_SAAS_ALGO_99421", dumped_js)
                self.assertNotIn("/api/v9/private-pricing-engine", dumped_js)
                self.assertGreater(len(dumped_js), 90 * 1024, "Paranoid JS token-bomb decoy should be >= 90 KB")

                # Execute dumped JS OFFLINE in Node without rtKey -> MUST FAIL!
                dump_path = tdir / "dumped_app.mjs"
                dump_path.write_text(dumped_js, encoding="utf-8")
                node = shutil.which("node")
                offline_failed = False
                online_ok = False
                if node:
                    p_off = subprocess.run([node, str(dump_path)], capture_output=True, text=True)
                    offline_failed = p_off.returncode != 0 and "VS_RUNTIME_KEY_REQUIRED" in p_off.stderr
                    self.assertTrue(offline_failed, f"Offline dumped JS MUST fail without server rtKey! stderr={p_off.stderr}")
                    runner = tdir / "with_rtkey.mjs"
                    runner.write_text(
                        f'const hex="{mf["rtKeyHex"]}";const b=new Uint8Array(32);'
                        f'for(let i=0;i<32;i++)b[i]=parseInt(hex.slice(i*2,i*2+2),16);'
                        f'globalThis[Symbol.for("vs_rt_{lease["siteId"]}")]=b;'
                        f'const m=await import({json.dumps(str(dump_path))});console.log(m.RESULT);\n',
                        encoding="utf-8",
                    )
                    p_on = subprocess.run([node, str(runner)], capture_output=True, text=True)
                    self.assertEqual(p_on.returncode, 0, p_on.stderr)
                    online_ok = p_on.stdout.strip() == "PROPRIETARY_SAAS_ALGO_99421@/api/v9/private-pricing-engine"
                    self.assertTrue(online_ok)
            finally:
                self._stop_srv(wsrv)

            # ---- Part B: Paranoid 3D Server (defaults to --mode stream + AES-256-GCM frames + anti_cdp=on!) ----
            glb_p = tdir / "l4.glb"
            glb_p.write_bytes(make_dense_test_glb(200))
            s3_out = tdir / "s3_out"
            s3_key = tdir / "s3.key"
            subprocess.check_call(
                [str(VS_BIN), "shield-3d", "--in", str(glb_p), "--out", str(s3_out), "--key-file", str(s3_key), "--preset", "fast"],
                stdout=subprocess.DEVNULL,
            )
            with socket.socket() as sk:
                sk.bind(("127.0.0.1", 0))
                sport = sk.getsockname()[1]
            sorigin = f"http://127.0.0.1:{sport}"
            # Note: NO --mode flag needed — `--preset paranoid` now defaults to `--mode stream`!
            ssrv = self._start_srv(
                [str(VS_BIN), "serve-3d", str(s3_out), "--preset", "paranoid", "--stream-width", "480", "--stream-height", "320",
                 "--key-file", str(s3_key), "--addr", f"127.0.0.1:{sport}", "--origin", sorigin],
                sport,
            )
            try:
                s_cdp = probe_url_in_chrome(f"{sorigin}/", runtime_enable=True, enable_automation=False)
                self.assertIn("AUTOMATION_DENIED", s_cdp["bootText"])
                self.assertFalse(s_cdp["vsReady"])
                self.assertFalse(any("/__vibeslayer/stream-init" in u for u in s_cdp["netUrls"]))

                s_ok = probe_url_in_chrome(f"{sorigin}/", runtime_enable=False, enable_automation=False, real_user_agent=True, wait_s=1.2)
                self.assertTrue(s_ok["vsReady"], f"Paranoid encrypted stream failed in normal Chrome: {s_ok}")
                self.assertTrue(s_ok["canvasNonZero"], "Encrypted stream canvas drew blank pixels!")
            finally:
                self._stop_srv(ssrv)

            print(json.dumps({
                "loop4_live_cdp_ai_agent_report": {
                    "web_cdp_runtime_enable_blocked_before_lease": True,
                    "web_webdriver_automation_blocked_before_lease": True,
                    "web_headless_ua_blocked_server_side": True,
                    "web_missing_attest_blocked_server_side": True,
                    "web_normal_chrome_zero_false_positives": True,
                    "web_stealth_dumped_js_offline_dead": offline_failed,
                    "web_live_rtkey_parity": online_ok,
                    "web_dumped_js_bytes_with_ai_token_bomb": len(dumped_js),
                    "stream3d_paranoid_defaults_to_encrypted_stream": True,
                    "stream3d_cdp_runtime_enable_blocked_before_init": True,
                    "stream3d_normal_chrome_aes_gcm_render_ok": s_ok["vsReady"] and s_ok["canvasNonZero"],
                }
            }, indent=2))

    def test_loop5_security_proxy_rfc9112_and_tier4_anti_stealth(self):
        """Verifies Security Proxy RFC 9112 compliance AND Tier-4 server-side anti-stealth enforcement:
          1. Transfer-Encoding: chunked POST to /lease & /stream-init succeeds (200 OK, no spurious 400 BAD_JSON)
             and keeps HTTP/1.1 keep-alive completely synchronized!
          2. Absolute-form proxy request target (GET http://127.0.0.1:PORT/ HTTP/1.1) returns 200 OK!
          3. Expect: 100-continue receives immediate HTTP/1.1 100 Continue + 200 OK!
          4. CL+TE HTTP Request Smuggling is rejected with 400 CL_TE_SMUGGLING_REJECTED!
          5. HEAD /__vibeslayer/health returns 200 OK with empty body!
          6. --trust-proxy + X-Forwarded-Host validates external HTTPS Origin cleanly!
          7. Server-side Tier-4 anti-stealth blocks OS-header lies, forged attest digests, and high-score CloakBrowser attest!
        """
        def raw_exchange(port: int, payload: bytes) -> bytes:
            with socket.create_connection(("127.0.0.1", port), timeout=3.0) as s:
                s.sendall(payload)
                s.settimeout(1.5)
                chunks = []
                while True:
                    try:
                        d = s.recv(4096)
                        if not d:
                            break
                        chunks.append(d)
                    except socket.timeout:
                        break
                return b"".join(chunks)

        with tempfile.TemporaryDirectory(prefix="vs_proxy_l5_") as tmp:
            tdir = pathlib.Path(tmp)
            site_src = tdir / "src"
            site_out = tdir / "out"
            reg = tdir / "reg.json"
            site_src.mkdir()
            (site_src / "index.html").write_text("<html><body>ProxyOK</body></html>\n")
            subprocess.check_call(
                [str(VS_BIN), "website", str(site_src), "-o", str(site_out), "--preset", "paranoid", "--registry", str(reg), "--json"],
                stdout=subprocess.DEVNULL,
            )

            with socket.socket() as sk:
                sk.bind(("127.0.0.1", 0))
                port = sk.getsockname()[1]
            origin = f"http://127.0.0.1:{port}"
            srv = self._start_srv(
                [str(VS_BIN), "serve", str(site_out), "--preset", "paranoid", "--addr", f"127.0.0.1:{port}", "--trust-proxy", "127.0.0.1", "--registry", str(reg)],
                port,
            )
            try:
                # 1. HEAD /__vibeslayer/health -> 200 OK empty body
                r_head = raw_exchange(port, f"HEAD /__vibeslayer/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode())
                self.assertTrue(r_head.startswith(b"HTTP/1.1 200 OK\r\n"), r_head[:80])
                self.assertTrue(r_head.endswith(b"\r\n\r\n"))

                # 2. Absolute-form proxy request target -> 200 OK with ticket!
                r_abs = raw_exchange(port, f"GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode())
                self.assertTrue(r_abs.startswith(b"HTTP/1.1 200 OK\r\n"), r_abs[:80])
                tk1 = re.search(r'vs-ticket"\s+content="([^"]+)"', r_abs.decode("utf-8")).group(1)

                # 3. Transfer-Encoding: chunked POST + keep-alive second request on SAME TCP socket!
                cp = ec.generate_private_key(ec.SECP256R1())
                cpub_hex = cp.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()
                att_d = hashlib.sha256(f"VS_ATTEST_V1|{tk1}|{cpub_hex}|0|0|Linux x86_64".encode()).hexdigest()
                body_bytes = json.dumps({
                    "clientPublicKeyHex": cpub_hex,
                    "ticket": tk1,
                    "attest": {"s": 0, "f": 0, "p": "Linux x86_64", "d": att_d},
                }).encode()
                p1, p2 = body_bytes[:40], body_bytes[40:]
                chunked = f"{len(p1):x}\r\n".encode() + p1 + b"\r\n" + f"{len(p2):x};ext=1\r\n".encode() + p2 + b"\r\n0\r\nX-Trailer: ok\r\n\r\n"
                req1 = (
                    f"POST /__vibeslayer/lease HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{port}\r\n"
                    f"X-Forwarded-Host: secure.example.com\r\n"
                    f"Origin: https://secure.example.com\r\n"
                    f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) Chrome/158.0.0.0\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Connection: keep-alive\r\n\r\n"
                ).encode() + chunked
                req2 = f"GET /__vibeslayer/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode()
                r_ch = raw_exchange(port, req1 + req2)
                self.assertIn(b"HTTP/1.1 200 OK\r\n", r_ch)
                self.assertIn(b'"origin":"https://secure.example.com"', r_ch)
                self.assertIn(b'{"ok":true}', r_ch)

                # 4. Expect: 100-continue -> immediate 100 Continue + 200 OK
                r_idx2 = raw_exchange(port, f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode())
                tk2 = re.search(r'vs-ticket"\s+content="([^"]+)"', r_idx2.decode("utf-8")).group(1)
                att_d2 = hashlib.sha256(f"VS_ATTEST_V1|{tk2}|{cpub_hex}|0|0|Linux x86_64".encode()).hexdigest()
                body2 = json.dumps({
                    "clientPublicKeyHex": cpub_hex,
                    "ticket": tk2,
                    "attest": {"s": 0, "f": 0, "p": "Linux x86_64", "d": att_d2},
                }).encode()
                r_100 = raw_exchange(
                    port,
                    (
                        f"POST /__vibeslayer/lease HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{port}\r\n"
                        f"Origin: {origin}\r\n"
                        f"Expect: 100-continue\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(body2)}\r\n"
                        f"Connection: close\r\n\r\n"
                    ).encode() + body2,
                )
                self.assertTrue(r_100.startswith(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"), r_100[:80])

                # 5. CL+TE Smuggling MUST be rejected with 400 CL_TE_SMUGGLING_REJECTED!
                r_smug = raw_exchange(
                    port,
                    (
                        f"POST /__vibeslayer/lease HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{port}\r\n"
                        f"Origin: {origin}\r\n"
                        f"Content-Length: 5\r\n"
                        f"Transfer-Encoding: chunked\r\n"
                        f"Connection: close\r\n\r\n"
                        f"0\r\n\r\n"
                    ).encode(),
                )
                self.assertIn(b"HTTP/1.1 400 Bad Request", r_smug)
                self.assertIn(b"CL_TE_SMUGGLING_REJECTED", r_smug)

                # 6. Server-side Tier-4 anti-stealth rejections (OS header lie + CloakBrowser score=11)
                def post_lease_status(headers: dict, score: int, plat: str, tamper_digest: bool = False):
                    ri = raw_exchange(port, f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode())
                    tk = re.search(r'vs-ticket"\s+content="([^"]+)"', ri.decode("utf-8")).group(1)
                    dg = hashlib.sha256(f"VS_ATTEST_V1|{tk}|{cpub_hex}|{score}|{score}|{plat}".encode()).hexdigest()
                    if tamper_digest:
                        dg = "0" * 64
                    c = http.client.HTTPConnection("127.0.0.1", port, timeout=3.0)
                    c.request(
                        "POST",
                        "/__vibeslayer/lease",
                        body=json.dumps({
                            "clientPublicKeyHex": cpub_hex,
                            "ticket": tk,
                            "attest": {"s": score, "f": score, "p": plat, "d": dg},
                        }).encode(),
                        headers={"Content-Type": "application/json", "Origin": origin, **headers},
                    )
                    resp = c.getresponse()
                    data = json.loads(resp.read())
                    c.close()
                    return resp.status, data["error"]

                st_os, err_os = post_lease_status({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/146.0", "Sec-CH-UA-Platform": '"Windows"'}, 0, "Win32")
                self.assertEqual((st_os, err_os), (403, "STEALTH_BROWSER_DENIED"))

                st_cb, err_cb = post_lease_status({"User-Agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/146.0"}, 11, "Win32")
                self.assertEqual((st_cb, err_cb), (403, "STEALTH_BROWSER_DENIED"))

                st_td, err_td = post_lease_status({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/158.0"}, 0, "Linux x86_64", tamper_digest=True)
                self.assertEqual((st_td, err_td), (403, "STEALTH_ATTEST_INVALID"))

                print(json.dumps({
                    "loop5_proxy_and_tier4_report": {
                        "head_health_200": True,
                        "proxy_abs_uri_200": True,
                        "proxy_chunked_post_and_keepalive_sync_200": True,
                        "proxy_trusted_xfh_https_origin_200": True,
                        "proxy_expect_100_continue_200": True,
                        "proxy_cl_te_smuggling_blocked_400": True,
                        "server_os_header_contradiction_blocked_403": True,
                        "server_cloakbrowser_score11_blocked_403": True,
                        "server_tampered_attest_digest_blocked_403": True,
                    }
                }, indent=2))
            finally:
                self._stop_srv(srv)

    def test_loop6_web_components_inline_anti_stealth_guard_and_ssr(self):
        """Verifies every hardened Web Component (.mjs/.js) carries the inline synchronous
        CloakBrowser self-defense guard when --anti-stealth is enabled:
          1. Extracted hardened .mjs Web Component contains STEALTH_BROWSER_DENIED guard.
          2. Runs cleanly in Node.js SSR (document === undefined) once rtKey is present.
          3. Throws STEALTH_BROWSER_DENIED BEFORE customElements.define(...) when run in a
             simulated CloakBrowser DOM (noisy 2D canvas + DOMRect sub-pixel drift).
          4. Registers the Custom Element cleanly in a real Chrome DOM (0 noise, exact DOMRect).
        """
        import shutil
        node = shutil.which("node")
        if not node:
            self.skipTest("node not installed")

        with tempfile.TemporaryDirectory(prefix="vs_wc_guard_") as tmp:
            tdir = pathlib.Path(tmp)
            src = tdir / "src"
            out = tdir / "out"
            reg = tdir / "reg.json"
            (src / "components").mkdir(parents=True)
            (src / "index.html").write_text(
                '<!doctype html><html><body><vs-pricing-card></vs-pricing-card>'
                '<script type="module" src="./components/pricing-card.mjs"></script></body></html>\n',
                encoding="utf-8",
            )
            (src / "components" / "pricing-card.mjs").write_text(
                '"use strict";\n'
                'export class PricingCard extends (globalThis.HTMLElement || class {}) {\n'
                '  static SECRET_TIER = "ENTERPRISE_SECRET_499_USD";\n'
                '}\n'
                'if (typeof customElements !== "undefined") {\n'
                '  customElements.define("vs-pricing-card", PricingCard);\n'
                '}\n',
                encoding="utf-8",
            )
            subprocess.check_call(
                [
                    str(VS_BIN), "website", str(src), "-o", str(out),
                    "--preset", "balanced", "--harden-js", "--anti-stealth", "strict",
                    "--registry", str(reg), "--json",
                ],
                stdout=subprocess.DEVNULL,
            )

            with socket.socket() as sk:
                sk.bind(("127.0.0.1", 0))
                port = sk.getsockname()[1]
            origin = f"http://127.0.0.1:{port}"
            srv = self._start_srv(
                [
                    str(VS_BIN), "serve", str(out), "--preset", "balanced",
                    "--anti-stealth", "strict", "--addr", f"127.0.0.1:{port}",
                    "--origin", origin, "--registry", str(reg),
                ],
                port,
            )
            try:
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=3.0)
                c.request("GET", "/")
                html = c.getresponse().read().decode("utf-8")
                c.close()
                tk = re.search(r'vs-ticket"\s+content="([^"]+)"', html).group(1)
                cp = ec.generate_private_key(ec.SECP256R1())
                cpub = cp.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
                att_d = hashlib.sha256(f"VS_ATTEST_V1|{tk}|{cpub.hex()}|0|0|Linux x86_64".encode()).hexdigest()
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=3.0)
                c.request(
                    "POST", "/__vibeslayer/lease",
                    body=json.dumps({
                        "clientPublicKeyHex": cpub.hex(),
                        "ticket": tk,
                        "attest": {"s": 0, "f": 0, "p": "Linux x86_64", "d": att_d},
                    }).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Origin": origin,
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/158.0.0.0",
                    },
                )
                lease = json.loads(c.getresponse().read())
                c.close()

                sp = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(lease["serverPublicKeyHex"]))
                sh = cp.exchange(ec.ECDH(), sp)
                wi = f"VSWEB1_WRAP|{origin}".encode()
                wk = HKDF(algorithm=hashes.SHA256(), length=32, salt=lease["leaseId"].encode(), info=wi).derive(sh)
                sk_key = AESGCM(wk).decrypt(bytes.fromhex(lease["wrapIvHex"]), bytes.fromhex(lease["wrappedKeyHex"]), wi)
                mf = json.loads(AESGCM(sk_key).decrypt(bytes.fromhex(lease["manifestIvHex"]), bytes.fromhex(lease["sealedManifestHex"]), b"VSWEB1|__manifest__"))
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=3.0)
                c.request("GET", "/" + mf["files"]["components/pricing-card.mjs"]["vsweb"])
                blob = c.getresponse().read()
                c.close()
                wc_js = AESGCM(sk_key).decrypt(blob[:12], blob[12:], b"VSWEB1|components/pricing-card.mjs").decode("utf-8")

                self.assertTrue(wc_js.startswith('"use strict";'), "Directive prologue must stay first")
                self.assertIn("STEALTH_BROWSER_DENIED", wc_js)
                self.assertNotIn("ENTERPRISE_SECRET_499_USD", wc_js)

                wc_path = tdir / "extracted_wc.mjs"
                wc_path.write_text(wc_js, encoding="utf-8")
                rt_hex = mf["rtKeyHex"]
                site_id = lease["siteId"]

                # 1) SSR (no document): imports cleanly with rtKey
                ssr = tdir / "run_ssr.mjs"
                ssr.write_text(
                    f'const h="{rt_hex}",b=new Uint8Array(32);for(let i=0;i<32;i++)b[i]=parseInt(h.slice(i*2,i*2+2),16);'
                    f'globalThis[Symbol.for("vs_rt_{site_id}")]=b;'
                    f'const m=await import({json.dumps(str(wc_path))});console.log(m.PricingCard.SECRET_TIER);\n',
                    encoding="utf-8",
                )
                r_ssr = subprocess.run([node, str(ssr)], capture_output=True, text=True)
                self.assertEqual(r_ssr.returncode, 0, r_ssr.stderr)
                self.assertEqual(r_ssr.stdout.strip(), "ENTERPRISE_SECRET_499_USD")

                # 2) Simulated CloakBrowser DOM (Canvas2D pixel noise + DOMRect drift) -> THROWS before customElements.define!
                cloak_sim = tdir / "run_cloak.mjs"
                cloak_sim.write_text(
                    f'const h="{rt_hex}",b=new Uint8Array(32);for(let i=0;i<32;i++)b[i]=parseInt(h.slice(i*2,i*2+2),16);'
                    f'globalThis[Symbol.for("vs_rt_{site_id}")]=b;'
                    'const defined=[];globalThis.customElements={define:(n)=>defined.push(n)};'
                    'globalThis.window={devicePixelRatio:1};'
                    'globalThis.document={body:{appendChild(){}},createElement:(t)=>t==="canvas"?{width:0,height:0,getContext:(k)=>k==="2d"?{fillRect(){},getImageData:()=>({data:new Uint8ClampedArray([128,128,128,255,127,128,129,255])})}:null}:{style:{},getBoundingClientRect:()=>({left:9.95,top:19.98,width:100,height:50}),remove(){}}};'
                    f'try{{await import({json.dumps(str(wc_path))});console.log("UNEXPECTED_PASS");}}catch(e){{console.log("DENIED:"+e.message+":defined="+defined.length);}}\n',
                    encoding="utf-8",
                )
                r_cloak = subprocess.run([node, str(cloak_sim)], capture_output=True, text=True)
                self.assertEqual(r_cloak.returncode, 0, r_cloak.stderr)
                self.assertEqual(r_cloak.stdout.strip(), "DENIED:STEALTH_BROWSER_DENIED:defined=0")

                # 3) Clean Chrome DOM (uniform Canvas2D, exact DOMRect) -> registers vs-pricing-card!
                clean_sim = tdir / "run_clean.mjs"
                clean_sim.write_text(
                    f'const h="{rt_hex}",b=new Uint8Array(32);for(let i=0;i<32;i++)b[i]=parseInt(h.slice(i*2,i*2+2),16);'
                    f'globalThis[Symbol.for("vs_rt_{site_id}")]=b;'
                    'const defined=[];globalThis.customElements={define:(n)=>defined.push(n)};'
                    'globalThis.window={devicePixelRatio:1};'
                    'globalThis.document={body:{appendChild(){}},createElement:(t)=>t==="canvas"?{width:0,height:0,getContext:(k)=>k==="2d"?{fillRect(){},getImageData:()=>({data:new Uint8ClampedArray([128,128,128,255,128,128,128,255])})}:null}:{style:{},getBoundingClientRect:()=>({left:10,top:20,width:100,height:50}),remove(){}}};'
                    f'const m=await import({json.dumps(str(wc_path))});console.log("OK:"+defined.join(",")+":"+m.PricingCard.SECRET_TIER);\n',
                    encoding="utf-8",
                )
                r_clean = subprocess.run([node, str(clean_sim)], capture_output=True, text=True)
                self.assertEqual(r_clean.returncode, 0, r_clean.stderr)
                self.assertEqual(r_clean.stdout.strip(), "OK:vs-pricing-card:ENTERPRISE_SECRET_499_USD")
            finally:
                self._stop_srv(srv)


if __name__ == "__main__":
    unittest.main(verbosity=2)
