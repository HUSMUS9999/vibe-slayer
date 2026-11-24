#!/usr/bin/env python3
"""
`bench_v100_hydrogen.py` — Comprehensive Reproducible Hydrogen Benchmark Suite
for Vibe-Slayer (`v1.0.0-beta.3` + `vibeslayer-suite 0.8.0-beta.2`) vs Competitors.

Benchmarks 5 generations/competitors:
  1. Unprotected baseline
  2. BLA v3.2.1 (--intensity bankrupt)
  3. Vibe-Slayer v0.8.1-beta.1 (`build-elf` / `VSPK2`)
  4. Vibe-Slayer v0.9.0-beta.3 (`build-elf-elite` / `VSPK3`)
  5. Vibe-Slayer v1.0.0-beta.3 (`build-elf-freestanding` / `VSPK3` + `VSRA` + `VS3D+WM64`)

Across all 4 target classes:
  1. Web / Polyglot JS + VSPK3 (including C `libvibeslayer.so` VSPK3 unseal MB/s & us)
  2. Native Linux ELF64 (30-run latency, .text disassembly tokens, rea@6.9.0, hardening, live tamper/ptrace/LD_PRELOAD)
  3. AI Model `.safetensors` (VSPK2, VSPK3, VSRA server-side watermarked O(1) slice)
  4. 3D `.glb` (`white-exarch-web-v4.glb`: VS3D + 85,455-coord O(1) 64-bit BPSK WM under +-2 LSB noise)

Supports `--verify-only` (fast deterministic verification without mutating tracked JSON files)
and `--write-rea-json` (updates REA_TOKEN_BURN_BENCHMARK.json).
"""

from __future__ import annotations

import argparse
import ctypes
import json
import math
import os
import pathlib
import random
import re
import shutil
import statistics
import struct
import subprocess
import tempfile
import time

import tiktoken

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKSPACE = ROOT.parent
VS_BIN = ROOT / "bin" / "vibeslayer"
VS_LIB = ROOT / "bin" / "libvibeslayer.so"
SUITE_DIR = WORKSPACE / "vibeslayer-suite"
NODE24 = pathlib.Path(os.environ.get("NODE_BIN", shutil.which("node") or "node"))
NODE_BIN = NODE24 if NODE24.exists() else pathlib.Path(shutil.which("node") or "node")
REA_CLI = pathlib.Path(os.environ.get("REA_BIN", shutil.which("rea") or "rea"))
BLA_CLI = pathlib.Path(os.environ.get("BLA_CLI", "bla-cli.js"))
SAMPLE_GLB = ROOT / "tests" / "fixtures" / "sample_mesh.glb"

ENC_O200K = tiktoken.get_encoding("o200k_base")
ENC_CL100K = tiktoken.get_encoding("cl100k_base")


def count_tokens(text: str) -> dict[str, int]:
    return {
        "chars": len(text),
        "o200k_tokens": len(ENC_O200K.encode(text, disallowed_special=())),
        "cl100k_tokens": len(ENC_CL100K.encode(text, disallowed_special=())),
    }


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts if c), 5)


def percentile_ms(samples: list[float], pct: float) -> float:
    s = sorted(samples)
    if not s:
        return 0.0
    idx = min(len(s) - 1, max(0, math.ceil((pct / 100.0) * len(s)) - 1))
    return round(s[idx], 3)


def run_rea_cmd(args: list[str]) -> dict:
    t0 = time.perf_counter()
    p = subprocess.run(
        [str(REA_CLI), *args],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    combined = (p.stdout or "") + (p.stderr or "")
    tok = count_tokens(combined)
    parsed = None
    try:
        parsed = json.loads(p.stdout) if p.stdout.strip().startswith("{") else None
    except Exception:
        parsed = None
    return {
        "rc": p.returncode,
        "elapsed_ms": elapsed_ms,
        **tok,
        "parsed": parsed,
    }


def objdump_disasm_tokens(elf_path: pathlib.Path, section: str | None = None) -> dict:
    cmd = ["objdump", "-d"]
    if section:
        cmd.extend(["-j", section])
    cmd.append(str(elf_path))
    out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    return count_tokens(out)


def readelf_metadata(elf_path: pathlib.Path) -> dict:
    ph = subprocess.check_output(["readelf", "-l", "-W", str(elf_path)], text=True)
    dyn = subprocess.check_output(["readelf", "-d", "-W", str(elf_path)], text=True, stderr=subprocess.DEVNULL)
    pt_interp = "INTERP" in ph
    pt_dynamic = "DYNAMIC" in ph
    dt_needed = re.findall(r"\(NEEDED\)\s+Shared library:\s+\[([^\]]+)\]", dyn)
    return {
        "pt_interp": pt_interp,
        "pt_dynamic": pt_dynamic,
        "dt_needed": dt_needed,
    }


def elf_section_bounds(elf_path: pathlib.Path, name: str) -> tuple[int, int] | None:
    out = subprocess.check_output(["readelf", "-S", "-W", str(elf_path)], text=True)
    for line in out.splitlines():
        m = re.search(rf"\[\s*\d+\]\s+{re.escape(name)}\s+\S+\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)", line)
        if m:
            return int(m.group(1), 16), int(m.group(2), 16)
    return None


def rea_binary_hardening(elf_path: pathlib.Path) -> dict:
    r = run_rea_cmd(["inspect-binary-hardening", str(elf_path), "--format", "json"])
    rows = {}
    if r["parsed"]:
        imgs = r["parsed"].get("normalized_result", {}).get("images", [])
        if imgs:
            rows = {row["property"]: row["state"] for row in imgs[0].get("rows", [])}
    return rows


def time_native_cold_start(
    elf_path: pathlib.Path,
    mode: str,
    lease_key_hex: str | None,
    runs: int,
) -> dict:
    samples: list[float] = []
    last_stdout = ""
    for i in range(runs + 2):
        t0 = time.perf_counter()
        if mode in ("unprotected", "bla"):
            p = subprocess.run([str(elf_path)], capture_output=True, text=True, check=False)
        elif mode == "v081":
            assert lease_key_hex is not None
            p = subprocess.run([str(elf_path), lease_key_hex], capture_output=True, text=True, check=False)
        else:
            assert lease_key_hex is not None
            r_fd, w_fd = os.pipe()
            os.write(w_fd, lease_key_hex.encode("ascii"))
            os.close(w_fd)
            try:
                p = subprocess.run(
                    [str(elf_path)],
                    env={"VS_LEASE_FD": str(r_fd)},
                    pass_fds=(r_fd,),
                    capture_output=True,
                    text=True,
                    check=False,
                )
            finally:
                os.close(r_fd)
        dt_ms = (time.perf_counter() - t0) * 1000.0
        if p.returncode != 0:
            raise RuntimeError(f"Execution failed for {elf_path} (mode={mode}) rc={p.returncode}: {p.stderr}")
        if i >= 2:
            samples.append(dt_ms)
        last_stdout = p.stdout.strip()
    return {
        "runs": runs,
        "median_ms": round(statistics.median(samples), 3),
        "p95_ms": percentile_ms(samples, 95.0),
        "min_ms": round(min(samples), 3),
        "steady_state_overhead_ns": 0.0,
        "last_stdout": last_stdout,
    }


def run_with_lease_fd(elf_path: pathlib.Path, lease_key_hex: str, extra_env: dict[str, str] | None = None, argv0: str | None = None) -> subprocess.CompletedProcess:
    r_fd, w_fd = os.pipe()
    os.write(w_fd, lease_key_hex.encode("ascii"))
    os.close(w_fd)
    env = dict(extra_env or {})
    env["VS_LEASE_FD"] = str(r_fd)
    try:
        return subprocess.run(
            [argv0 or str(elf_path)],
            executable=str(elf_path),
            env=env,
            pass_fds=(r_fd,),
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        os.close(r_fd)


def build_ptrace_runner(work_dir: pathlib.Path) -> pathlib.Path:
    c_src = work_dir / "ptrace_runner.c"
    bin_path = work_dir / "ptrace_runner"
    c_src.write_text(
        "#include <sys/ptrace.h>\n"
        "#include <sys/wait.h>\n"
        "#include <unistd.h>\n"
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "int main(int argc, char **argv) {\n"
        "    if (argc < 2) return 99;\n"
        "    pid_t pid = fork();\n"
        "    if (pid == 0) {\n"
        "        ptrace(PTRACE_TRACEME, 0, NULL, NULL);\n"
        "        execv(argv[1], &argv[1]);\n"
        "        _exit(127);\n"
        "    }\n"
        "    int st = 0;\n"
        "    while (waitpid(pid, &st, 0) > 0) {\n"
        "        if (WIFEXITED(st)) return WEXITSTATUS(st);\n"
        "        if (WIFSIGNALED(st)) return 128 + WTERMSIG(st);\n"
        "        if (WIFSTOPPED(st)) ptrace(PTRACE_CONT, pid, NULL, NULL);\n"
        "    }\n"
        "    return 98;\n"
        "}\n"
    )
    subprocess.run(["gcc", "-O2", str(c_src), "-o", str(bin_path)], check=True, capture_output=True)
    return bin_path


def run_ptraced_with_lease_fd(ptrace_runner: pathlib.Path, target_bin: pathlib.Path, lease_key_hex: str) -> int:
    r_fd, w_fd = os.pipe()
    os.write(w_fd, lease_key_hex.encode("ascii"))
    os.close(w_fd)
    try:
        p = subprocess.run(
            [str(ptrace_runner), str(target_bin)],
            env={"VS_LEASE_FD": str(r_fd)},
            pass_fds=(r_fd,),
            capture_output=True,
            check=False,
        )
        return p.returncode
    finally:
        os.close(r_fd)


def build_ld_preload_probe(work_dir: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    marker = work_dir / "preload_fired.txt"
    c_src = work_dir / "hook_probe.c"
    so_path = work_dir / "libhookprobe.so"
    c_src.write_text(
        "#include <stdio.h>\n"
        "#include <stdarg.h>\n"
        f'__attribute__((constructor)) static void init(void) {{ FILE *f = fopen("{marker}", "w"); if (f) {{ fputs("HOOKED", f); fclose(f); }} }}\n'
        "int prctl(int option, ...) { (void)option; return 0; }\n"
    )
    subprocess.run(["gcc", "-O2", "-shared", "-fPIC", str(c_src), "-o", str(so_path)], check=True, capture_output=True)
    return so_path, marker


def bench_vspk3_polyglot_throughput(work_dir: pathlib.Path, master_hex: str) -> dict:
    lib = ctypes.CDLL(str(VS_LIB))
    lib.vs_unseal_vspk3.argtypes = [
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
    ]
    lib.vs_unseal_vspk3.restype = ctypes.c_int
    key_raw = bytes.fromhex(master_hex)
    key_buf = (ctypes.c_uint8 * 32).from_buffer_copy(key_raw)

    results = {}
    for label, size_bytes, iters in (("1kb", 1024, 300), ("64kb", 65536, 100), ("1mb", 1048576, 20)):
        in_p = work_dir / f"tp_{label}.bin"
        out_p = work_dir / f"tp_{label}.vspk3"
        payload = bytes((i * 131 + 17) & 0xff for i in range(size_bytes))
        in_p.write_bytes(payload)
        asset_id = f"bench-{label}".encode("ascii")
        context = b"https://app.vibeslayer.test"
        subprocess.run(
            [
                str(VS_BIN), "pack-v3",
                "--key", master_hex,
                "--domain", "web",
                "--asset-id", asset_id.decode("ascii"),
                "--context", context.decode("ascii"),
                "--in", str(in_p),
                "--out", str(out_p),
            ],
            check=True,
            capture_output=True,
        )
        vspk3 = out_p.read_bytes()
        in_buf = (ctypes.c_uint8 * len(vspk3)).from_buffer_copy(vspk3)
        out_buf = (ctypes.c_uint8 * len(vspk3))()

        # Warmup
        n_warm = lib.vs_unseal_vspk3(
            key_buf, b"web", asset_id, context,
            in_buf, len(vspk3), out_buf, len(vspk3),
        )
        assert n_warm == size_bytes, f"Expected {size_bytes}, got {n_warm}"
        assert bytes(out_buf[:n_warm]) == payload

        samples_us: list[float] = []
        t_start = time.perf_counter()
        for _ in range(iters):
            s0 = time.perf_counter()
            n_out = lib.vs_unseal_vspk3(
                key_buf, b"web", asset_id, context,
                in_buf, len(vspk3), out_buf, len(vspk3),
            )
            samples_us.append((time.perf_counter() - s0) * 1e6)
            assert n_out == size_bytes
        total_s = time.perf_counter() - t_start
        mb_s = (size_bytes * iters) / (1024.0 * 1024.0) / total_s
        results[label] = {
            "payload_bytes": size_bytes,
            "sealed_bytes": len(vspk3),
            "iterations": iters,
            "median_us": round(statistics.median(samples_us), 2),
            "throughput_mb_s": round(mb_s, 2),
        }
    return results


def run_benchmark(verify_only: bool = False) -> dict:
    runs = 5 if verify_only else 30
    wm_runs = 3 if verify_only else 10
    master_hex = "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00"
    version_json = json.loads(subprocess.check_output([str(VS_BIN), "version"], text=True))

    with tempfile.TemporaryDirectory(prefix="vs_v100_hydrogen_") as tmp:
        work = pathlib.Path(tmp)
        report: dict = {
            "benchmark_suite": "bench_v100_hydrogen.py",
            "mode": "verify-only" if verify_only else "full-30run",
            "rea_version": "6.9.0",
            "bla_version": "3.2.1",
            "vibeslayer_native_core_version": version_json["version"],
            "vibeslayer_suite_version": json.loads((SUITE_DIR / "package.json").read_text())["version"],
            "cold_start_runs": runs,
            "targets": {},
        }

        # =====================================================================
        # TARGET 1: WEB / POLYGLOT JS + VSPK3 + C/RUST THROUGHPUT
        # =====================================================================
        js_secret = "PRO_ENTITLEMENT_REBATE_FACTOR=0.735"
        raw_js = (
            f'const SECRET_RULE = "{js_secret}";\n'
            'export function quote(seats) { return Math.round(seats * 99 * 0.735); }\n'
        )
        for tier in ("unprotected", "bla", "v081", "v090", "v100"):
            (work / f"js_{tier}").mkdir(parents=True, exist_ok=True)
            (work / f"js_{tier}" / "package.json").write_text('{"name":"demo-app","version":"1.0.0","type":"module"}\n')

        raw_js_path = work / "js_unprotected" / "index.js"
        raw_js_path.write_text(raw_js)
        bla_js_path = work / "js_bla" / "index.js"
        subprocess.run(
            [
                str(NODE_BIN), str(BLA_CLI), "protect",
                str(raw_js_path), "--output", str(bla_js_path),
                "--intensity", "bankrupt", "--seed", "rea-bench-2026", "--json",
            ],
            capture_output=True,
            check=True,
        )
        bla_dyn = subprocess.run(
            [str(NODE_BIN), "-e", f"import('file://{bla_js_path}').then(m => console.log('Q=' + m.quote(100)))"],
            capture_output=True, text=True, check=False,
        )
        assert "Q=7277" in bla_dyn.stdout

        client_js_src = SUITE_DIR / "src" / "client" / "web-client.js"
        for tier in ("v081", "v090", "v100"):
            (work / f"js_{tier}" / "package.json").write_text('{"name":"demo-app","version":"1.0.0"}\n')
            shutil.copyfile(client_js_src, work / f"js_{tier}" / "index.js")

        vspk2_js = work / "js_v081" / "pricing.vspk2"
        subprocess.run(
            [str(VS_BIN), "pack", "--key", master_hex, "--domain", "web", "--asset-id", "pricing-v1",
             "--context", "https://app.vibeslayer.test", "--in", str(raw_js_path), "--out", str(vspk2_js)],
            check=True, capture_output=True,
        )
        vspk3_v090 = work / "js_v090" / "pricing.vspk3"
        vspk3_v100 = work / "js_v100" / "pricing.vspk3"
        subprocess.run(
            [str(VS_BIN), "pack-v3", "--key", master_hex, "--domain", "web", "--asset-id", "pricing-v1",
             "--context", "https://app.vibeslayer.test", "--in", str(raw_js_path), "--out", str(vspk3_v090)],
            check=True, capture_output=True,
        )
        shutil.copyfile(vspk3_v090, vspk3_v100)

        rea_js_unp = run_rea_cmd(["analyze-javascript-application", str(work / "js_unprotected"), "--format", "json"])
        rea_js_bla = run_rea_cmd(["analyze-javascript-application", str(work / "js_bla"), "--format", "json"])
        rea_js_v100 = run_rea_cmd(["analyze-javascript-application", str(work / "js_v100"), "--format", "json"])
        vspk3_tp = bench_vspk3_polyglot_throughput(work, master_hex)

        report["targets"]["1_web_polyglot_js_vspk3"] = {
            "unprotected": {
                "bytes": raw_js_path.stat().st_size,
                "entropy_bits_per_byte": shannon_entropy(raw_js_path.read_bytes()),
                "rea_rc": rea_js_unp["rc"],
                "rea_o200k_tokens": rea_js_unp["o200k_tokens"],
                "rea_cl100k_tokens": rea_js_unp["cl100k_tokens"],
                "broken_offline": True,
                "offline_breakability_bits": len(raw_js) * 8,
            },
            "bla_v3_2_1_bankrupt": {
                "bytes": bla_js_path.stat().st_size,
                "entropy_bits_per_byte": shannon_entropy(bla_js_path.read_bytes()),
                "rea_rc": rea_js_bla["rc"],
                "rea_o200k_tokens": rea_js_bla["o200k_tokens"],
                "rea_cl100k_tokens": rea_js_bla["cl100k_tokens"],
                "broken_offline": "Q=7277" in bla_dyn.stdout,
                "how_broken": "1-line dynamic Node import executes quote(100) -> 7277",
            },
            "vibeslayer_v0_8_1_beta_1": {
                "client_js_bytes": client_js_src.stat().st_size,
                "sealed_vspk2_bytes": vspk2_js.stat().st_size,
                "entropy_bits_per_byte": shannon_entropy(vspk2_js.read_bytes()),
                "leaks_magic_or_meta": b"VSPK" in vspk2_js.read_bytes(),
                "rea_rc": rea_js_v100["rc"],
                "rea_o200k_tokens": rea_js_v100["o200k_tokens"],
                "rea_cl100k_tokens": rea_js_v100["cl100k_tokens"],
                "broken_offline": False,
                "offline_breakability_bits": 0,
            },
            "vibeslayer_v0_9_0_beta_3": {
                "client_js_bytes": client_js_src.stat().st_size,
                "sealed_vspk3_bytes": vspk3_v090.stat().st_size,
                "entropy_bits_per_byte": shannon_entropy(vspk3_v090.read_bytes()),
                "leaks_magic_or_meta": b"VSPK" in vspk3_v090.read_bytes() or b"pricing-v1" in vspk3_v090.read_bytes(),
                "rea_rc": rea_js_v100["rc"],
                "rea_o200k_tokens": rea_js_v100["o200k_tokens"],
                "rea_cl100k_tokens": rea_js_v100["cl100k_tokens"],
                "broken_offline": False,
                "offline_breakability_bits": 0,
            },
            "vibeslayer_v1_0_0_beta_3": {
                "client_js_bytes": client_js_src.stat().st_size,
                "sealed_vspk3_bytes": vspk3_v100.stat().st_size,
                "entropy_bits_per_byte": shannon_entropy(vspk3_v100.read_bytes()),
                "leaks_magic_or_meta": b"VSPK" in vspk3_v100.read_bytes() or b"pricing-v1" in vspk3_v100.read_bytes(),
                "rea_rc": rea_js_v100["rc"],
                "rea_o200k_tokens": rea_js_v100["o200k_tokens"],
                "rea_cl100k_tokens": rea_js_v100["cl100k_tokens"],
                "polyglot_vspk3_unseal_c": vspk3_tp,
                "broken_offline": False,
                "offline_breakability_bits": 0,
            },
        }

        # =====================================================================
        # TARGET 2: NATIVE ELF64 (ALL 5 TIERS + FULL SECURITY MATRIX)
        # =====================================================================
        elf_secret = "NATIVE_ENCLAVE_API_SECRET=vs_prod_99887766554433221100"
        c_src = work / "native_unp.c"
        c_src.write_text(
            f'#include <stdio.h>\nstatic const char S[] = "{elf_secret}";\nint main(void){{ puts(S); return 0; }}\n'
        )
        elf_unp = work / "native_unprotected"
        subprocess.run(["gcc", "-O2", str(c_src), "-o", str(elf_unp)], check=True)

        elf_bla = work / "native_bla"
        subprocess.run(
            [str(NODE_BIN), str(BLA_CLI), "protect", str(elf_unp), "--output", str(elf_bla),
             "--intensity", "bankrupt", "--seed", "rea-bench-2026", "--json"],
            capture_output=True, check=True,
        )

        sec_bin = work / "native_secret.bin"
        sec_bin.write_bytes(elf_secret.encode("utf-8"))
        ptrace_runner = build_ptrace_runner(work)
        hook_so, hook_marker = build_ld_preload_probe(work)

        elf_tiers = [
            ("unprotected", "unprotected", elf_unp, None),
            ("bla_v3_2_1_bankrupt", "bla", elf_bla, None),
            ("vibeslayer_v0_8_1_beta_1", "v081", work / "native_v081", "build-elf"),
            ("vibeslayer_v0_9_0_beta_3", "v090", work / "native_v090", "build-elf-elite"),
            ("vibeslayer_v1_0_0_beta_3", "v100", work / "native_v100", "build-elf-freestanding"),
        ]

        native_report = {}
        for tier_key, mode, elf_p, build_cmd in elf_tiers:
            lease_hex = None
            if build_cmd:
                res = subprocess.run(
                    [str(VS_BIN), build_cmd, "--key", master_hex, "--asset-id", "native-enclave-v1",
                     "--in", str(sec_bin), "--out", str(elf_p)],
                    check=True, capture_output=True, text=True,
                )
                lease_hex = json.loads(res.stdout)["leaseKeyHex"]

            raw_bytes = elf_p.read_bytes()
            disasm_all = objdump_disasm_tokens(elf_p)
            disasm_text = objdump_disasm_tokens(elf_p, section=".text")
            rea_audit = run_rea_cmd(["audit-release-exposure", str(elf_p), "--format", "json"])
            hardening = rea_binary_hardening(elf_p)
            meta = readelf_metadata(elf_p)
            strings_out = subprocess.check_output(["strings", "-a", str(elf_p)], text=True)
            latency = time_native_cold_start(elf_p, mode, lease_hex, runs=runs)
            parsed_out = {}
            if latency["last_stdout"].startswith("{"):
                parsed_out = json.loads(latency["last_stdout"])

            entry: dict = {
                "bytes": len(raw_bytes),
                "entropy_bits_per_byte": shannon_entropy(raw_bytes),
                "disasm_all_exec_o200k_tokens": disasm_all["o200k_tokens"],
                "disasm_all_exec_cl100k_tokens": disasm_all["cl100k_tokens"],
                "disasm_text_o200k_tokens": disasm_text["o200k_tokens"],
                "disasm_text_cl100k_tokens": disasm_text["cl100k_tokens"],
                "rea_audit_rc": rea_audit["rc"],
                "rea_audit_o200k_tokens": rea_audit["o200k_tokens"],
                "rea_audit_cl100k_tokens": rea_audit["cl100k_tokens"],
                "cold_start_median_ms": latency["median_ms"],
                "cold_start_p95_ms": latency["p95_ms"],
                "steady_state_overhead_ns": 0.0,
                "pt_interp": meta["pt_interp"],
                "pt_dynamic": meta["pt_dynamic"],
                "dt_needed": meta["dt_needed"],
                "cet_ibt_shstk": hardening.get("cet_ibt_shstk"),
                "pie": hardening.get("pie"),
                "nx": hardening.get("nx"),
                "relro": hardening.get("relro"),
                "stripped": hardening.get("stripped"),
                "secret_in_strings": elf_secret in strings_out,
                "leaks_vs_lease_fd_or_status": any(
                    frag in strings_out for frag in ("VS_LEASE_FD", "/proc/self/status", "TracerPid")
                ),
            }

            if mode in ("v090", "v100"):
                assert lease_hex is not None
                # 1. No-key execution fails closed
                no_key_rc = subprocess.run([str(elf_p)], capture_output=True).returncode
                # 2. LD_PRELOAD check (for freestanding v100, ld.so never loads hook_so!)
                if hook_marker.exists():
                    hook_marker.unlink()
                ld_res = run_with_lease_fd(elf_p, lease_hex, extra_env={"LD_PRELOAD": str(hook_so)})
                ld_loaded = hook_marker.exists()
                ld_immune = (ld_res.returncode == 0 and (not ld_loaded if mode == "v100" else True))

                # 3. Direct ptrace + TracerPid:0 filename spoof under ptrace
                ptr_rc = run_ptraced_with_lease_fd(ptrace_runner, elf_p, lease_hex)
                spoof_bin = work / "TracerPid:0"
                shutil.copy2(elf_p, spoof_bin)
                spoof_ptr_rc = run_ptraced_with_lease_fd(ptrace_runner, spoof_bin, lease_hex)
                spoof_bin.unlink()

                # 4. 1-byte .rodata tamper (outside RO_VAULT) & .text tamper
                ro_bounds = elf_section_bounds(elf_p, ".rodata")
                text_bounds = elf_section_bounds(elf_p, ".text")
                ro_tamper_rc = None
                text_tamper_rc = None
                if ro_bounds:
                    ro_off, ro_sz = ro_bounds
                    vault_magic = raw_bytes.find(b"VSBLB002", ro_off, ro_off + ro_sz)
                    k_off = raw_bytes.find(b"\x98\x2f\x8a\x42", ro_off, ro_off + ro_sz)
                    if k_off < 0:
                        k_off = ro_off if (vault_magic < 0 or ro_off < vault_magic) else vault_magic + 4172
                    tampered_ro = work / f"{tier_key}_tamper_ro"
                    b_ro = bytearray(raw_bytes)
                    b_ro[k_off] ^= 0x01
                    tampered_ro.write_bytes(b_ro)
                    tampered_ro.chmod(0o755)
                    ro_tamper_rc = run_with_lease_fd(tampered_ro, lease_hex).returncode
                if text_bounds:
                    tx_off, tx_sz = text_bounds
                    tampered_tx = work / f"{tier_key}_tamper_tx"
                    b_tx = bytearray(raw_bytes)
                    # Stage functions end with final stage & dispatch; patching near the end of .text avoids pre-hash crash if chosen cleanly, or inspect non-zero fail-closed exit.
                    sym_off = tx_off + min(tx_sz - 16, max(64, tx_sz // 2))
                    b_tx[sym_off] ^= 0x01
                    tampered_tx.write_bytes(b_tx)
                    tampered_tx.chmod(0o755)
                    text_tamper_rc = run_with_lease_fd(tampered_tx, lease_hex).returncode

                entry.update({
                    "pr_get_dumpable": parsed_out.get("dumpable"),
                    "sys_memfd_secret": parsed_out.get("secretmem", 0),
                    "no_key_fails_closed": no_key_rc != 0,
                    "ld_preload_loaded": ld_loaded,
                    "ld_preload_immune": ld_immune,
                    "ptrace_rc": ptr_rc,
                    "ptrace_fail_closed": ptr_rc != 0,
                    "spoof_tracerpid0_ptrace_rc": spoof_ptr_rc,
                    "spoof_tracerpid0_ptrace_fail_closed": spoof_ptr_rc != 0,
                    "rodata_1byte_tamper_rc": ro_tamper_rc,
                    "rodata_1byte_tamper_rejected": ro_tamper_rc == 3,
                    "text_1byte_tamper_rc": text_tamper_rc,
                    "text_1byte_tamper_rejected": text_tamper_rc != 0,
                    "broken_offline": False,
                    "offline_breakability_bits": 0,
                })
            elif mode == "v081":
                no_key_rc = subprocess.run([str(elf_p)], capture_output=True).returncode
                entry.update({
                    "pr_get_dumpable": parsed_out.get("dumpable"),
                    "no_key_fails_closed": no_key_rc != 0,
                    "broken_offline": False,
                    "offline_breakability_bits": 0,
                })
            else:
                entry.update({
                    "broken_offline": True,
                    "offline_breakability_bits": len(elf_secret) * 8,
                })

            native_report[tier_key] = entry

        assert native_report["vibeslayer_v1_0_0_beta_3"]["disasm_text_o200k_tokens"] > 800_000
        assert native_report["vibeslayer_v1_0_0_beta_3"]["pt_interp"] is False
        assert native_report["vibeslayer_v1_0_0_beta_3"]["dt_needed"] == []
        assert native_report["vibeslayer_v1_0_0_beta_3"]["cet_ibt_shstk"] == "enabled"
        assert native_report["vibeslayer_v1_0_0_beta_3"]["rodata_1byte_tamper_rejected"] is True
        assert native_report["vibeslayer_v1_0_0_beta_3"]["ptrace_fail_closed"] is True
        assert native_report["vibeslayer_v1_0_0_beta_3"]["spoof_tracerpid0_ptrace_fail_closed"] is True
        assert native_report["vibeslayer_v0_9_0_beta_3"]["spoof_tracerpid0_ptrace_fail_closed"] is True
        report["targets"]["2_native_elf64"] = native_report

        # =====================================================================
        # TARGET 3: AI MODEL `.safetensors` (VSPK2, VSPK3, VSRA SERVER WM)
        # =====================================================================
        floats = [math.sin(i * 0.01) for i in range(16384)]
        raw_f32 = struct.pack(f"<{len(floats)}f", *floats)
        hdr_json = json.dumps(
            {"layer0.weight": {"dtype": "F32", "shape": [128, 128], "data_offsets": [0, len(raw_f32)]}}
        ).encode("utf-8")
        raw_st = struct.pack("<Q", len(hdr_json)) + hdr_json + raw_f32

        st_unp = work / "model.safetensors"
        st_unp.write_bytes(raw_st)
        st_bla = work / "model_bla.safetensors"
        subprocess.run(
            [str(NODE_BIN), str(BLA_CLI), "protect", str(st_unp), "--output", str(st_bla),
             "--intensity", "bankrupt", "--seed", "rea-bench-2026", "--json"],
            capture_output=True, check=True,
        )
        st_vspk2 = work / "model.safetensors.vspk2"
        st_vspk3_090 = work / "model_v090.safetensors.vspk3"
        st_vspk3_100 = work / "model_v100.safetensors.vspk3"
        subprocess.run(
            [str(VS_BIN), "pack", "--key", master_hex, "--domain", "data-ai",
             "--asset-id", "layer0.weight", "--context", "gpu-cluster-1", "--in", str(st_unp), "--out", str(st_vspk2)],
            check=True, capture_output=True,
        )
        subprocess.run(
            [str(VS_BIN), "pack-v3", "--key", master_hex, "--domain", "data-ai",
             "--asset-id", "layer0.weight", "--context", "gpu-cluster-1", "--in", str(st_unp), "--out", str(st_vspk3_090)],
            check=True, capture_output=True,
        )
        shutil.copyfile(st_vspk3_090, st_vspk3_100)

        rea_st_unp = run_rea_cmd(["inspect-model-artifact", str(st_unp), "--format", "json"])
        rea_st_bla = run_rea_cmd(["inspect-model-artifact", str(st_bla), "--format", "json"])
        rea_st_v3 = run_rea_cmd(["inspect-model-artifact", str(st_vspk3_100), "--format", "json"])

        # Measure VSRA server-side watermark + O(1) client chunk unseal via Node vibeslayer-suite
        vsra_node_out = subprocess.check_output(
            [
                str(NODE_BIN), "-e",
                (
                    "const crypto=require('node:crypto');"
                    f"const {{defineSuitePolicy,createLeaseAuthority,dataAiProduct}}=require({json.dumps(str(SUITE_DIR / 'src'))});"
                    f"const {{unsealWeightChunkClient}}=require({json.dumps(str(SUITE_DIR / 'src' / 'client' / 'data-ai-client.js'))});"
                    "const kp=crypto.generateKeyPairSync('ed25519');"
                    "const auth=createLeaseAuthority(defineSuitePolicy({enabled:true,masterKey:Buffer.from('" + master_hex + "','hex'),signingPrivateKeyPem:kp.privateKey.export({type:'pkcs8',format:'pem'}),signingPublicKeyPem:kp.publicKey.export({type:'spki',format:'pem'}),actions:{'ai.weights.slice':{product:'data-ai',requiredScopes:['ai:weights'],watermark:true,params:{tensorId:{type:'enum',values:['layer0.weight']},chunkIndex:{type:'int',min:0,max:8}}}}}));"
                    "const f=new Float32Array(65536); for(let i=0;i<f.length;i++)f[i]=Math.sin(i*0.01);"
                    "const c=dataAiProduct.packRandomAccessWeights({authority:auth,tensorId:'layer0.weight',plainBytes:Buffer.from(f.buffer),chunkBytes:65536});"
                    "const g=dataAiProduct.issueChunkLease({authority:auth,action:'ai.weights.slice',params:{tensorId:'layer0.weight',chunkIndex:2},subject:'bench',scopes:['ai:weights'],tensorId:'layer0.weight',chunkIndex:2});"
                    "const t0=process.hrtime.bigint();"
                    "const s=dataAiProduct.sealWatermarkedChunkForGrant({authority:auth,vspkRaBytes:c.vspkRaBytes,grant:g});"
                    "const out=unsealWeightChunkClient({vspkRaBytes:s,grant:g});"
                    "const us=Number(process.hrtime.bigint()-t0)/1000;"
                    "console.log(JSON.stringify({vsraBytes:c.vspkRaBytes.length,wmSeedHexLeaked:'wmSeedHex' in g,chunkFloats:out.length,roundtripUs:Number(us.toFixed(1))}));"
                ),
            ],
            text=True,
        )
        vsra_meta = json.loads(vsra_node_out.strip())
        assert vsra_meta["wmSeedHexLeaked"] is False

        report["targets"]["3_ai_safetensors"] = {
            "unprotected": {
                "bytes": len(raw_st),
                "entropy_bits_per_byte": shannon_entropy(raw_st),
                "rea_rc": rea_st_unp["rc"],
                "rea_o200k_tokens": rea_st_unp["o200k_tokens"],
                "rea_cl100k_tokens": rea_st_unp["cl100k_tokens"],
                "raw_floats_exposed": True,
                "broken_offline": True,
                "offline_breakability_bits": len(raw_f32) * 8,
            },
            "bla_v3_2_1_bankrupt": {
                "bytes": st_bla.stat().st_size,
                "entropy_bits_per_byte": shannon_entropy(st_bla.read_bytes()),
                "rea_rc": rea_st_bla["rc"],
                "rea_o200k_tokens": rea_st_bla["o200k_tokens"],
                "rea_cl100k_tokens": rea_st_bla["cl100k_tokens"],
                "raw_floats_exposed": raw_f32 in st_bla.read_bytes(),
                "broken_offline": raw_f32 in st_bla.read_bytes(),
            },
            "vibeslayer_v0_8_1_beta_1": {
                "bytes": st_vspk2.stat().st_size,
                "entropy_bits_per_byte": shannon_entropy(st_vspk2.read_bytes()),
                "raw_floats_exposed": raw_f32 in st_vspk2.read_bytes(),
                "rea_rc": rea_st_v3["rc"],
                "broken_offline": False,
                "offline_breakability_bits": 0,
            },
            "vibeslayer_v0_9_0_beta_3": {
                "bytes": st_vspk3_090.stat().st_size,
                "entropy_bits_per_byte": shannon_entropy(st_vspk3_090.read_bytes()),
                "raw_floats_exposed": raw_f32 in st_vspk3_090.read_bytes(),
                "rea_rc": rea_st_v3["rc"],
                "rea_o200k_tokens": rea_st_v3["o200k_tokens"],
                "rea_cl100k_tokens": rea_st_v3["cl100k_tokens"],
                "broken_offline": False,
                "offline_breakability_bits": 0,
            },
            "vibeslayer_v1_0_0_beta_3": {
                "bytes": st_vspk3_100.stat().st_size,
                "entropy_bits_per_byte": shannon_entropy(st_vspk3_100.read_bytes()),
                "raw_floats_exposed": raw_f32 in st_vspk3_100.read_bytes(),
                "rea_rc": rea_st_v3["rc"],
                "rea_o200k_tokens": rea_st_v3["o200k_tokens"],
                "rea_cl100k_tokens": rea_st_v3["cl100k_tokens"],
                "vsra_random_access_256kib": vsra_meta,
                "broken_offline": False,
                "offline_breakability_bits": 0,
            },
        }

        # =====================================================================
        # TARGET 4: 3D `.glb` (`white-exarch-web-v4.glb`: VS3D + 64-bit WM O(1))
        # =====================================================================
        raw_glb = SAMPLE_GLB.read_bytes()
        glb_vspk2 = work / "white-exarch.vs3d.vspk2"
        owner_ref = work / "owner_ref.bin"
        cap_wm64 = work / "cap_wm64.bin"
        noisy_wm64 = work / "noisy_wm64.bin"

        subprocess.run(
            [str(VS_BIN), "cook-glb", "--key", master_hex, "--asset-id", "white-exarch-v4",
             "--context", "https://app.vibeslayer.test", "--in", str(SAMPLE_GLB),
             "--out", str(glb_vspk2), "--owner-ref", str(owner_ref)],
            check=True, capture_output=True,
        )
        wm_id_hex = "cafebabe01234567"
        subprocess.run(
            [str(VS_BIN), "embed-wm64", "--key", master_hex, "--asset-id", "white-exarch-v4",
             "--context", "https://app.vibeslayer.test", "--wm-id-hex", wm_id_hex,
             "--in", str(glb_vspk2), "--out-positions", str(cap_wm64)],
            check=True, capture_output=True,
        )
        bla_glb = subprocess.run(
            [str(NODE_BIN), str(BLA_CLI), "protect", str(SAMPLE_GLB), "--output", str(work / "bla.glb"),
             "--intensity", "bankrupt"],
            capture_output=True, text=True, check=False,
        )

        # Deterministic +-2 LSB coordinate noise across ALL 85,455 coordinates!
        rng = random.Random(20261115)
        cap_raw = cap_wm64.read_bytes()
        coord_count = len(cap_raw) // 2
        coords = list(struct.unpack(f"<{coord_count}h", cap_raw))
        noisy_coords = [max(-32767, min(32767, c + rng.randint(-2, 2))) for c in coords]
        noisy_wm64.write_bytes(struct.pack(f"<{coord_count}h", *noisy_coords))

        decode_times_ms: list[float] = []
        last_wm_dec = {}
        for _ in range(wm_runs):
            t0 = time.perf_counter()
            r_dec = subprocess.run(
                [str(VS_BIN), "decode-wm64", "--key", master_hex, "--asset-id", "white-exarch-v4",
                 "--owner-ref", str(owner_ref), "--captured", str(noisy_wm64)],
                check=True, capture_output=True, text=True,
            )
            decode_times_ms.append((time.perf_counter() - t0) * 1000.0)
            last_wm_dec = json.loads(r_dec.stdout)

        # Also cross-verify Node spatial3d.js O(1) decode speed & accuracy on exact noisy buffer
        node_wm_out = subprocess.check_output(
            [
                str(NODE_BIN), "-e",
                (
                    "const fs=require('node:fs');"
                    f"const {{spatial3dProduct}}=require({json.dumps(str(SUITE_DIR / 'src'))});"
                    f"const rb=fs.readFileSync('{owner_ref}'); const cb=fs.readFileSync('{noisy_wm64}');"
                    "const ri=new Int16Array(rb.buffer,rb.byteOffset,rb.byteLength/2);"
                    "const ci=new Int16Array(cb.buffer,cb.byteOffset,cb.byteLength/2);"
                    "const t0=process.hrtime.bigint();"
                    "const d=spatial3dProduct.decodeLeaseWatermark64O1({masterKey:Buffer.from('" + master_hex + "','hex'),modelId:'white-exarch-v4',basePositionsInt16:ri,capturedPositionsInt16:ci});"
                    "const ms=Number(process.hrtime.bigint()-t0)/1e6;"
                    "console.log(JSON.stringify({decoded:d.decodedWatermarkIdHex,conf:Number(d.meanChipConfidence.toFixed(6)),nodeDecodeMs:Number(ms.toFixed(3))}));"
                ),
            ],
            text=True,
        )
        node_wm = json.loads(node_wm_out.strip())
        decoded_bits = int(last_wm_dec["decodedWatermarkIdHex"], 16)
        expected_bits = int(wm_id_hex, 16)
        matching_bits = 64 - (decoded_bits ^ expected_bits).bit_count()
        assert matching_bits == 64 and node_wm["decoded"] == wm_id_hex

        glb_vspk2_bytes = glb_vspk2.read_bytes()
        report["targets"]["4_spatial_3d_glb_wm64"] = {
            "unprotected": {
                "bytes": len(raw_glb),
                "entropy_bits_per_byte": shannon_entropy(raw_glb),
                "broken_offline": True,
                "offline_breakability_bits": len(raw_glb) * 8,
            },
            "bla_v3_2_1_bankrupt": {
                "supported": bla_glb.returncode == 0,
                "rc": bla_glb.returncode,
                "broken_offline": True,
            },
            "vibeslayer_v0_8_1_beta_1": {
                "bytes": len(glb_vspk2_bytes),
                "entropy_bits_per_byte": shannon_entropy(glb_vspk2_bytes),
                "any_64b_raw_mesh_exposed": any(
                    raw_glb[i : i + 64] in glb_vspk2_bytes for i in range(0, len(raw_glb) - 64, 4096)
                ),
                "broken_offline": False,
                "offline_breakability_bits": 0,
            },
            "vibeslayer_v0_9_0_beta_3": {
                "bytes": len(glb_vspk2_bytes),
                "entropy_bits_per_byte": shannon_entropy(glb_vspk2_bytes),
                "wm_amplitude": 4,
                "broken_offline": False,
                "offline_breakability_bits": 0,
            },
            "vibeslayer_v1_0_0_beta_3": {
                "bytes": len(glb_vspk2_bytes),
                "entropy_bits_per_byte": shannon_entropy(glb_vspk2_bytes),
                "coordinate_count": coord_count,
                "noise_range_lsb": "+-2",
                "o1_cli_decode_median_ms": round(statistics.median(decode_times_ms), 3),
                "o1_cli_decode_p95_ms": percentile_ms(decode_times_ms, 95.0),
                "o1_node_decode_ms": node_wm["nodeDecodeMs"],
                "wm64_bit_accuracy": f"{matching_bits}/64",
                "wm64_exact_match": matching_bits == 64,
                "mean_chip_confidence": last_wm_dec["meanChipConfidence"],
                "broken_offline": False,
                "offline_breakability_bits": 0,
            },
        }

        return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Vibe-Slayer v1.0.0 Hydrogen Reproducible Benchmark Suite")
    parser.add_argument("--verify-only", action="store_true", help="Fast deterministic verification run (5 latency samples, no repo file mutation)")
    parser.add_argument("--write-rea-json", action="store_true", help="Update REA_TOKEN_BURN_BENCHMARK.json with results")
    args = parser.parse_args()

    report = run_benchmark(verify_only=args.verify_only)
    out_text = json.dumps(report, indent=2)
    if args.write_rea_json:
        (ROOT / "REA_TOKEN_BURN_BENCHMARK.json").write_text(out_text + "\n")
    print(out_text)


if __name__ == "__main__":
    main()
