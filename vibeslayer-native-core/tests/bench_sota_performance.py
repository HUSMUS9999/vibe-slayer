#!/usr/bin/env python3
"""
State-of-the-Art (SOTA) performance & correctness benchmark gate for `vibe-slayer`
and `libvibeslayer.so`.

Enforced SOTA budgets (hardware: x86_64 with AES-NI/PCLMULQDQ/SHA-NI/AVX2/AVX-512):
  1. Website 16 MiB AES-256-GCM seal (`./vibe-slayer website`):
     median wall time < 32.0 ms (>= 500.0 MiB/s)
  2. Live ECDH P-256 runtime lease (`./vibe-slayer serve`):
      - Keep-Alive sequential POST /__vibeslayer/lease median RTT < 0.60 ms (> 1,666 leases/s)
      - 16-worker concurrent Keep-Alive leases > 10,000 leases/s
      - 16-worker concurrent Keep-Alive cached .vsweb GET > 25,000 req/s
  3. VSPK3 symmetric decryption:
     - C SDK `libvibeslayer.so::vs_unseal_vspk3` (1 MiB): median < 500.0 us (> 2,000.0 MiB/s)
     - CLI 16 MiB `unseal-v3` end-to-end: median <= 32.0 ms (>= 500.0 MiB/s)
  4. Parallel 48-file polyglot repo `./vibe-slayer <repo>` (scan + seal + selfCheck):
     median wall time < 250.0 ms
"""

import ctypes
import hashlib
import http.client
import json
import multiprocessing
import os
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = CORE_ROOT.parent
VS_BIN = REPO_ROOT / "vibe-slayer"
VS_LIB = CORE_ROOT / "bin" / "libvibeslayer.so"

# NIST P-256 base point G (uncompressed 65-byte SEC1 public key)
P256_G_HEX = (
    "04"
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
TICKET_RE = re.compile(r'<meta name="vs-ticket" content="([^"]+)"')


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def extract_ticket(html: bytes) -> str:
    m = TICKET_RE.search(html.decode("utf-8", errors="replace"))
    if not m:
        raise RuntimeError("Failed to find vs-ticket in bootstrap index.html")
    return m.group(1)


def bench_website_seal(tmp: Path) -> tuple[dict, Path, Path, Path]:
    site_dir = tmp / "site_src"
    site_dir.mkdir(parents=True, exist_ok=True)

    html = (
        "<!doctype html><html><head><title>SOTA</title></head>"
        "<body><h1>Protected App</h1><script src=\"app.js\"></script></body></html>\n"
    ).encode("utf-8")
    js = b"console.log('sota-web-runtime');\n" * 32
    payload_16m = os.urandom(16 * 1024 * 1024)
    (site_dir / "index.html").write_bytes(html)
    (site_dir / "app.js").write_bytes(js)
    (site_dir / "payload.bin").write_bytes(payload_16m)
    total_bytes = len(html) + len(js) + len(payload_16m)
    total_mib = total_bytes / (1024.0 * 1024.0)

    def run_once(out_dir: Path, kf: Path, rf: Path) -> float:
        t0 = time.perf_counter()
        subprocess.run(
            [
                str(VS_BIN),
                "website",
                str(site_dir),
                "-o",
                str(out_dir),
                "--keys",
                str(kf),
                "--registry",
                str(rf),
                "--no-gitignore",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        return (time.perf_counter() - t0) * 1000.0

    warm_out = tmp / "site_warm"
    run_once(warm_out, tmp / "web_keys_warm.json", tmp / "web_reg_warm.json")

    times_ms: list[float] = []
    last_out = warm_out
    last_keys = tmp / "web_keys_0.json"
    last_reg = tmp / "web_reg_0.json"
    for i in range(5):
        out_i = tmp / f"site_out_{i}"
        keys_i = tmp / f"web_keys_{i}.json"
        reg_i = tmp / f"web_reg_{i}.json"
        dt_ms = run_once(out_i, keys_i, reg_i)
        times_ms.append(dt_ms)
        if last_out != warm_out and last_out.exists():
            shutil.rmtree(last_out, ignore_errors=True)
        last_out = out_i
        last_keys = keys_i
        last_reg = reg_i
    shutil.rmtree(warm_out, ignore_errors=True)

    med_ms = statistics.median(times_ms)
    mib_s = total_mib / (med_ms / 1000.0)
    assert med_ms < 32.0 and mib_s >= 500.0, (
        f"Website 16 MiB AES-256-GCM seal missed SOTA target: {med_ms:.2f} ms ({mib_s:.1f} MiB/s)"
    )
    return (
        {
            "bytes": total_bytes,
            "samples_ms": [round(x, 2) for x in times_ms],
            "median_ms": round(med_ms, 2),
            "throughput_mib_s": round(mib_s, 1),
        },
        last_out,
        last_keys,
        last_reg,
    )


def fetch_tickets_batch(port: int, count: int) -> list[str]:
    workers = 8
    per_w = [(count // workers) + (1 if i < (count % workers) else 0) for i in range(workers)]
    buckets: list[list[str]] = [[] for _ in range(workers)]

    def worker(idx: int, n: int) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10.0)
        out = buckets[idx]
        for _ in range(n):
            conn.request("GET", "/", headers={"Connection": "keep-alive"})
            resp = conn.getresponse()
            body = resp.read()
            if resp.status != 200:
                raise RuntimeError(f"GET / failed with status {resp.status}")
            out.append(extract_ticket(body))
        conn.close()

    threads = [threading.Thread(target=worker, args=(i, per_w[i])) for i in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    tickets: list[str] = []
    for b in buckets:
        tickets.extend(b)
    return tickets


def bench_live_web_runtime(site_out: Path, keys_file: Path, reg_file: Path) -> dict:
    port = pick_free_port()
    origin = f"http://127.0.0.1:{port}"
    vsweb_candidates = sorted(
        (site_out / "assets").glob("*.vsweb"),
        key=lambda p: p.stat().st_size,
    )
    if not vsweb_candidates:
        raise RuntimeError(f"No .vsweb asset found in {site_out / 'assets'}")
    small_asset_path = f"/assets/{vsweb_candidates[0].name}"

    proc = subprocess.Popen(
        [
            str(VS_BIN),
            "serve",
            str(site_out),
            "--addr",
            f"127.0.0.1:{port}",
            "--keys",
            str(keys_file),
            "--registry",
            str(reg_file),
            "--max-leases-per-min",
            "10000000",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        # Wait for health endpoint
        deadline = time.perf_counter() + 5.0
        while time.perf_counter() < deadline:
            try:
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=1.0)
                c.request("GET", "/__vibeslayer/health")
                r = c.getresponse()
                r.read()
                c.close()
                if r.status == 200:
                    break
            except OSError:
                time.sleep(0.02)
        else:
            raise RuntimeError("vibe-slayer serve did not become ready within 5s")

        # 1) Sequential Keep-Alive ECDH P-256 leases
        seq_warm = 30
        seq_iters = 200
        seq_tickets = fetch_tickets_batch(port, seq_warm + seq_iters)
        lease_hdrs = {
            "Content-Type": "application/json",
            "Origin": origin,
            "Connection": "keep-alive",
        }
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10.0)
        seq_rtts_ms: list[float] = []
        for idx, tkt in enumerate(seq_tickets):
            body = json.dumps({"clientPublicKeyHex": P256_G_HEX, "ticket": tkt}).encode("utf-8")
            t0 = time.perf_counter()
            conn.request("POST", "/__vibeslayer/lease", body=body, headers=lease_hdrs)
            resp = conn.getresponse()
            raw = resp.read()
            dt_ms = (time.perf_counter() - t0) * 1000.0
            if resp.status != 200:
                raise RuntimeError(f"Sequential lease failed ({resp.status}): {raw!r}")
            if idx >= seq_warm:
                seq_rtts_ms.append(dt_ms)
        conn.close()

        seq_med_ms = statistics.median(seq_rtts_ms)
        seq_rate = 1000.0 / seq_med_ms
        assert seq_med_ms < 0.60, (
            f"Sequential Keep-Alive ECDH P-256 lease RTT too high: {seq_med_ms:.3f} ms ({seq_rate:.1f}/s)"
        )

        # 2) 16-process concurrent Keep-Alive ECDH P-256 leases (multiprocess avoids Python GIL)
        n_workers = 16
        per_worker_leases = 300
        conc_tickets = fetch_tickets_batch(port, n_workers * per_worker_leases)
        lease_payloads = [
            json.dumps({"clientPublicKeyHex": P256_G_HEX, "ticket": t}).encode("utf-8")
            for t in conc_tickets
        ]
        mp_ctx = multiprocessing.get_context("fork")
        start_b = mp_ctx.Barrier(n_workers + 1)
        done_b = mp_ctx.Barrier(n_workers + 1)
        err_q = mp_ctx.Queue()

        def lease_worker(wid: int) -> None:
            start = wid * per_worker_leases
            end = start + per_worker_leases
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=15.0)
            c.request("GET", "/__vibeslayer/health", headers={"Connection": "keep-alive"})
            c.getresponse().read()
            start_b.wait()
            for j in range(start, end):
                c.request("POST", "/__vibeslayer/lease", body=lease_payloads[j], headers=lease_hdrs)
                r = c.getresponse()
                r.read()
                if r.status != 200:
                    err_q.put(f"w={wid} status={r.status}")
                    break
            done_b.wait()
            c.close()

        procs = [mp_ctx.Process(target=lease_worker, args=(i,)) for i in range(n_workers)]
        for p in procs:
            p.start()
        start_b.wait()
        t_start = time.perf_counter()
        done_b.wait()
        conc_dt = time.perf_counter() - t_start
        for p in procs:
            p.join(timeout=5.0)
            if p.exitcode != 0:
                err_q.put(f"worker exitcode={p.exitcode}")
        if not err_q.empty():
            raise RuntimeError(f"Concurrent lease error: {err_q.get()}")
        conc_leases_s = (n_workers * per_worker_leases) / conc_dt
        assert conc_leases_s > 10_000.0, (
            f"16-worker Keep-Alive leases/s below SOTA target: {conc_leases_s:.1f} leases/s"
        )

        # 3) 16-process concurrent Keep-Alive cached .vsweb GET
        per_worker_assets = 1000
        start_a = mp_ctx.Barrier(n_workers + 1)
        done_a = mp_ctx.Barrier(n_workers + 1)
        asset_err_q = mp_ctx.Queue()

        def asset_worker(wid: int) -> None:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=15.0)
            c.request("GET", small_asset_path, headers={"Connection": "keep-alive"})
            r0 = c.getresponse()
            r0.read()
            if r0.status != 200:
                asset_err_q.put(f"w={wid} warm status={r0.status}")
            start_a.wait()
            for _ in range(per_worker_assets):
                c.request("GET", small_asset_path, headers={"Connection": "keep-alive"})
                r = c.getresponse()
                r.read()
                if r.status != 200:
                    asset_err_q.put(f"w={wid} status={r.status}")
                    break
            done_a.wait()
            c.close()

        a_procs = [mp_ctx.Process(target=asset_worker, args=(i,)) for i in range(n_workers)]
        for p in a_procs:
            p.start()
        start_a.wait()
        t_a0 = time.perf_counter()
        done_a.wait()
        asset_dt = time.perf_counter() - t_a0
        for p in a_procs:
            p.join(timeout=5.0)
            if p.exitcode != 0:
                asset_err_q.put(f"asset worker exitcode={p.exitcode}")
        if not asset_err_q.empty():
            raise RuntimeError(f"Concurrent asset GET error: {asset_err_q.get()}")
        asset_req_s = (n_workers * per_worker_assets) / asset_dt
        assert asset_req_s > 25_000.0, (
            f"16-worker Keep-Alive cached asset req/s below SOTA target: {asset_req_s:.1f} req/s"
        )

        return {
            "seq_lease_median_ms": round(seq_med_ms, 3),
            "seq_leases_per_sec": round(seq_rate, 1),
            "concurrent_16w_leases_per_sec": round(conc_leases_s, 1),
            "concurrent_16w_asset_req_per_sec": round(asset_req_s, 1),
        }
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def bench_vspk3_throughput(tmp: Path) -> dict:
    master_hex = os.urandom(32).hex()
    key_buf = (ctypes.c_uint8 * 32).from_buffer_copy(bytes.fromhex(master_hex))

    lib = ctypes.CDLL(str(VS_LIB))
    lib.vs_unseal_vspk3.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
    ]
    lib.vs_unseal_vspk3.restype = ctypes.c_int

    # 1 MiB C SDK vs_unseal_vspk3
    size_1m = 1024 * 1024
    in_1m = tmp / "p1m.bin"
    out_1m = tmp / "p1m.vspk3"
    plain_1m = bytes((i * 131 + 17) & 0xFF for i in range(size_1m))
    in_1m.write_bytes(plain_1m)
    subprocess.run(
        [
            str(VS_BIN),
            "pack-v3",
            "--key",
            master_hex,
            "--domain",
            "web",
            "--asset-id",
            "sota-1m",
            "--context",
            "https://sota.test",
            "--in",
            str(in_1m),
            "--out",
            str(out_1m),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    sealed_1m = out_1m.read_bytes()
    in_buf = (ctypes.c_uint8 * len(sealed_1m)).from_buffer_copy(sealed_1m)
    out_buf = (ctypes.c_uint8 * len(sealed_1m))()

    n_w = lib.vs_unseal_vspk3(
        key_buf, b"web", b"sota-1m", b"https://sota.test",
        in_buf, len(sealed_1m), out_buf, len(sealed_1m),
    )
    assert n_w == size_1m and bytes(out_buf[:n_w]) == plain_1m

    samples_us: list[float] = []
    for _ in range(100):
        s0 = time.perf_counter()
        n_o = lib.vs_unseal_vspk3(
            key_buf, b"web", b"sota-1m", b"https://sota.test",
            in_buf, len(sealed_1m), out_buf, len(sealed_1m),
        )
        samples_us.append((time.perf_counter() - s0) * 1e6)
        assert n_o == size_1m

    c_med_us = statistics.median(samples_us)
    c_mib_s = 1.0 / (c_med_us / 1e6)
    assert c_med_us < 500.0 and c_mib_s > 2000.0, (
        f"C SDK vs_unseal_vspk3 (1 MiB) missed SOTA target: {c_med_us:.2f} us ({c_mib_s:.1f} MiB/s)"
    )

    # 16 MiB CLI unseal-v3 end-to-end
    size_16m = 16 * 1024 * 1024
    in_16m = tmp / "p16m.bin"
    sealed_16m = tmp / "p16m.vspk3"
    restored_16m = tmp / "p16m.restored"
    plain_16m = os.urandom(size_16m)
    exp_sha = hashlib.sha256(plain_16m).hexdigest()
    in_16m.write_bytes(plain_16m)
    subprocess.run(
        [
            str(VS_BIN),
            "pack-v3",
            "--key",
            master_hex,
            "--domain",
            "binary",
            "--asset-id",
            "sota-16m",
            "--context",
            "sota-cli",
            "--in",
            str(in_16m),
            "--out",
            str(sealed_16m),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )

    def run_unseal_cli() -> float:
        t0 = time.perf_counter()
        subprocess.run(
            [
                str(VS_BIN),
                "unseal-v3",
                "--key",
                master_hex,
                "--domain",
                "binary",
                "--asset-id",
                "sota-16m",
                "--context",
                "sota-cli",
                "--in",
                str(sealed_16m),
                "--out",
                str(restored_16m),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        return (time.perf_counter() - t0) * 1000.0

    run_unseal_cli()
    assert hashlib.sha256(restored_16m.read_bytes()).hexdigest() == exp_sha

    cli_times_ms = [run_unseal_cli() for _ in range(5)]
    cli_med_ms = statistics.median(cli_times_ms)
    cli_mib_s = 16.0 / (cli_med_ms / 1000.0)
    assert cli_mib_s >= 500.0, (
        f"CLI 16 MiB unseal-v3 missed SOTA target: {cli_med_ms:.2f} ms ({cli_mib_s:.1f} MiB/s)"
    )

    return {
        "c_sdk_1m_median_us": round(c_med_us, 2),
        "c_sdk_1m_mib_s": round(c_mib_s, 1),
        "cli_16m_unseal_median_ms": round(cli_med_ms, 2),
        "cli_16m_unseal_mib_s": round(cli_mib_s, 1),
    }


def bench_polyglot_repo_48(tmp: Path) -> dict:
    repo = tmp / "poly_48_repo"
    exts = [
        ("src", "py", lambda i: f"def compute_{i}(x):\n    return (x * {i + 7}) ^ 0x5a\n" * 60),
        ("src", "rs", lambda i: f"pub fn f_{i}(x: u64) -> u64 {{ x.wrapping_mul({i + 11}) }}\n" * 60),
        ("src", "go", lambda i: f"package main\nfunc G{i}(x int) int {{ return x + {i} }}\n" * 60),
        ("web", "js", lambda i: f"export const v{i} = (n) => (n + {i}) >>> 1;\n" * 60),
        ("web", "ts", lambda i: f"export function t{i}(x: number): number {{ return x * {i + 3}; }}\n" * 60),
        ("shaders", "glsl", lambda i: f"vec3 shade_{i}(vec3 n) {{ return normalize(n + vec3(0.{i % 9 + 1})); }}\n" * 60),
        ("scripts", "sh", lambda i: f"echo 'module {i} active'\n" * 60),
        ("config", "json", lambda i: json.dumps({"service": f"svc-{i}", "replicas": i + 1}) * 20 + "\n"),
    ]
    count = 0
    for round_idx in range(6):
        for sub, ext, gen in exts:
            d = repo / sub
            d.mkdir(parents=True, exist_ok=True)
            (d / f"mod_{count:02d}.{ext}").write_text(gen(count + round_idx), encoding="utf-8")
            count += 1
    assert count == 48

    def run_once(out_dir: Path, kf: Path, rf: Path) -> tuple[float, dict]:
        t0 = time.perf_counter()
        p = subprocess.run(
            [
                str(VS_BIN),
                str(repo),
                "-o",
                str(out_dir),
                "--keys",
                str(kf),
                "--registry",
                str(rf),
                "--no-gitignore",
                "--json",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        dt_ms = (time.perf_counter() - t0) * 1000.0
        doc = json.loads(p.stdout)
        return dt_ms, doc

    warm = tmp / "repo_warm"
    _, warm_doc = run_once(warm, tmp / "repo_keys_warm.json", tmp / "repo_reg_warm.json")
    assert warm_doc.get("ok") is True and warm_doc.get("selfCheck", {}).get("ok") is True
    assert warm_doc.get("counts", {}).get("total") == 48
    shutil.rmtree(warm, ignore_errors=True)

    times_ms: list[float] = []
    for i in range(3):
        out_i = tmp / f"repo_out_{i}"
        dt_ms, doc = run_once(out_i, tmp / f"repo_keys_{i}.json", tmp / f"repo_reg_{i}.json")
        assert doc.get("ok") is True and doc.get("selfCheck", {}).get("ok") is True
        assert doc.get("counts", {}).get("total") == 48
        times_ms.append(dt_ms)
        shutil.rmtree(out_i, ignore_errors=True)

    med_ms = statistics.median(times_ms)
    assert med_ms < 250.0, (
        f"48-file polyglot repo protection missed SOTA target: {med_ms:.2f} ms"
    )
    return {
        "files": 48,
        "samples_ms": [round(x, 2) for x in times_ms],
        "median_ms": round(med_ms, 2),
    }


def main() -> int:
    if not VS_BIN.is_file() or not VS_LIB.is_file():
        print(f"Missing build artifacts: {VS_BIN} / {VS_LIB}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="vs-sota-bench-") as td:
        tmp = Path(td)
        web_seal_res, site_out, keys_file, reg_file = bench_website_seal(tmp)
        live_web_res = bench_live_web_runtime(site_out, keys_file, reg_file)
        vspk3_res = bench_vspk3_throughput(tmp)
        repo48_res = bench_polyglot_repo_48(tmp)

    summary = {
        "ok": True,
        "website_seal_16m": web_seal_res,
        "live_web_runtime": live_web_res,
        "vspk3_throughput": vspk3_res,
        "polyglot_repo_48": repo48_res,
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
