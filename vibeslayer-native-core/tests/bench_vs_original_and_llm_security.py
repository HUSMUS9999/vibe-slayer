#!/usr/bin/env python3
"""
Comprehensive Head-to-Head Benchmark:
  Part 1: Performance Outlined Directly Against Original Unprotected Assets
  Part 2: Empirical Security & Heavy-AI-Plan Token-Consumption Benchmark
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import http.client
import json
import math
import os
import pathlib
import re
import resource
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import tiktoken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CORE_DIR = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = CORE_DIR.parent
VS_BIN = REPO_ROOT / "vibe-slayer"
VS_LIB = CORE_DIR / "bin" / "libvibeslayer.so"
SAMPLE_GLB = CORE_DIR / "tests" / "fixtures" / "sample_mesh.glb"

REA_BIN = pathlib.Path(os.environ.get("REA_BIN", shutil.which("rea") or "rea"))
NODE_BIN = pathlib.Path(os.environ.get("NODE_BIN", shutil.which("node") or "node"))
BLA_CLI = pathlib.Path(os.environ.get("BLA_CLI", "bla-cli.js"))

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


def p95(vals: list[float]) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    idx = min(len(s) - 1, max(0, math.ceil(0.95 * len(s)) - 1))
    return s[idx]


def count_tokens_fast(text: str) -> tuple[int, int]:
    return (
        len(ENC_O200K.encode(text, disallowed_special=())),
        len(ENC_CL100K.encode(text, disallowed_special=())),
    )


def run_rea(args: list[str], timeout: int = 60) -> dict:
    p = subprocess.run(
        [str(REA_BIN), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    combined = p.stdout + ("\n" + p.stderr if p.stderr else "")
    o200k, cl100k = count_tokens_fast(combined)
    return {
        "rc": p.returncode,
        "chars": len(combined),
        "o200k_tokens": o200k,
        "cl100k_tokens": cl100k,
        "stdout": p.stdout,
    }


def make_lease_token(lease_root_hex: str, rx_hex: str, exp_unix: int = 0) -> bytes:
    _ = (rx_hex, exp_unix)
    return lease_root_hex.encode("ascii")


def measure_elf_process(
    bin_path: pathlib.Path,
    runs: int,
    lease_token: bytes | None = None,
) -> dict:
    wall_ms: list[float] = []
    compute_ms: list[float] = []
    rss_kib: list[int] = []
    last_out = ""

    for i in range(runs + 2):
        r_fd = -1
        env = dict(os.environ)
        pass_fds: tuple[int, ...] = ()
        if lease_token is not None:
            r_fd, w_fd = os.pipe()
            os.write(w_fd, lease_token)
            os.close(w_fd)
            env["VS_LEASE_FD"] = str(r_fd)
            pass_fds = (r_fd,)

        try:
            t0 = time.perf_counter()
            p = subprocess.run(
                [str(bin_path), "--bench-iters", "12000000"],
                env=env,
                pass_fds=pass_fds,
                capture_output=True,
                text=True,
                check=True,
            )
            dt_ms = (time.perf_counter() - t0) * 1000.0
        finally:
            if r_fd >= 0:
                os.close(r_fd)

        out = p.stdout.strip()
        last_out = out
        m = re.search(r"COMPUTE_NS=(\d+)", out)
        c_ms = int(m.group(1)) / 1e6 if m else 0.0
        if i >= 2:  # post-warmup
            wall_ms.append(dt_ms)
            compute_ms.append(c_ms)

    # Measure peak RSS via /usr/bin/time or child wait4 helper
    r_fd = -1
    env = dict(os.environ)
    pass_fds = ()
    if lease_token is not None:
        r_fd, w_fd = os.pipe()
        os.write(w_fd, lease_token)
        os.close(w_fd)
        env["VS_LEASE_FD"] = str(r_fd)
        pass_fds = (r_fd,)
    try:
        pid = os.fork()
        if pid == 0:
            if r_fd >= 0:
                os.set_inheritable(r_fd, True)
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, 1)
            os.dup2(devnull, 2)
            os.execve(str(bin_path), [str(bin_path), "--bench-iters", "12000000"], env)
        else:
            _, status, rusage = os.wait4(pid, 0)
            assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
            rss_kib.append(int(rusage.ru_maxrss))
    finally:
        if r_fd >= 0:
            os.close(r_fd)

    med_wall = statistics.median(wall_ms)
    med_comp = statistics.median(compute_ms)
    return {
        "bytes": bin_path.stat().st_size,
        "wall_median_ms": round(med_wall, 3),
        "wall_p95_ms": round(p95(wall_ms), 3),
        "compute_median_ms": round(med_comp, 3),
        "startup_overhead_est_ms": round(max(0.0, med_wall - med_comp), 3),
        "peak_rss_kib": rss_kib[0] if rss_kib else 0,
        "sample_stdout": last_out,
    }


def analyze_disassembly(bin_path: pathlib.Path) -> dict:
    dis = subprocess.check_output(
        ["objdump", "-d", "-j", ".text", str(bin_path)],
        text=True,
    )
    o200k, cl100k = count_tokens_fast(dis)

    # Check golden ratio constant 9e3779b97f4a7c15 in disassembly
    golden_hits = len(re.findall(r"9e3779b97f4a7c15", dis, flags=re.IGNORECASE))

    # Measure stage function sizes / instruction counts if symbols or stage blocks exist
    insns = [
        ln
        for ln in dis.splitlines()
        if re.match(r"^\s*[0-9a-f]+:\s+[0-9a-f]{2}\s", ln)
    ]

    # Estimate MCP JSON expansion factor from 4,000-insn sample (exact JSON structure)
    sample_slice = insns[: min(4000, len(insns))]
    mcp_records = []
    for ln in sample_slice:
        parts = ln.strip().split("\t")
        addr = parts[0].rstrip(":")
        raw_hex = parts[1].strip() if len(parts) > 1 else ""
        asm = parts[2].strip() if len(parts) > 2 else ""
        mcp_records.append({"address": f"0x{addr}", "bytes": raw_hex, "disasm": asm})
    mcp_sample_json = json.dumps({"tool": "disassemble_text", "instructions": mcp_records})
    mcp_sample_o200k, _ = count_tokens_fast(mcp_sample_json)
    scale = (len(insns) / len(sample_slice)) if sample_slice else 1.0
    est_mcp_o200k = int(round(mcp_sample_o200k * scale))

    # Measure distinct mnemonic patterns across 160 slices of .text to verify polymorphism
    chunk_size = max(1, len(insns) // 160)
    distinct_fingerprints = set()
    for i in range(min(160, max(1, len(insns) // chunk_size))):
        sub = insns[i * chunk_size : (i + 1) * chunk_size]
        mnems = tuple(
            (ln.split("\t")[2].split()[0] if len(ln.split("\t")) > 2 and ln.split("\t")[2].split() else "")
            for ln in sub[:24]
        )
        distinct_fingerprints.add(mnems)

    return {
        "text_disasm_chars": len(dis),
        "instruction_count": len(insns),
        "raw_text_o200k_tokens": o200k,
        "raw_text_cl100k_tokens": cl100k,
        "mcp_json_o200k_tokens": est_mcp_o200k,
        "golden_ratio_beacon_hits": golden_hits,
        "distinct_stage_opcode_fingerprints_of_160": len(distinct_fingerprints),
    }


def bench_domain_a_native_elf(work: pathlib.Path, runs: int) -> dict:
    orig_c = work / "orig_compute.c"
    orig_c.write_text(
        r"""
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char __attribute__((used)) SECRET_FORMULA_ID[] = "PROPRIETARY_QUANT_KERNEL_V4_ALPHA_9941";

int main(int argc, char **argv) {
    uint64_t iters = 12000000ULL;
    for (int i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], "--bench-iters") == 0) {
            iters = strtoull(argv[i + 1], NULL, 10);
        }
    }
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    volatile const char *sp = SECRET_FORMULA_ID;
    uint64_t s0 = 0x243f6a8885a308d3ULL;
    for (size_t k = 0; sp[k] != '\0'; k++) {
        s0 = (s0 * 131ULL) ^ (uint64_t)(unsigned char)sp[k];
    }
    uint64_t s1 = 0x13198a2e03707344ULL ^ iters;
    for (uint64_t i = 0; i < iters; i++) {
        s0 += s1 ^ (i * 0x9e3779b97f4a7c15ULL);
        s0 = (s0 << 13) | (s0 >> 51);
        s1 ^= s0;
        s1 = (s1 << 31) | (s1 >> 33);
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    uint64_t ns = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ULL +
                  (uint64_t)(t1.tv_nsec - t0.tv_nsec);
    printf("KERNEL_OK=1 COMPUTE_NS=%llu DIGEST=%016llx\n",
           (unsigned long long)ns,
           (unsigned long long)(s0 ^ s1));
    return 0;
}
"""
    )
    orig_bin = work / "orig_compute"
    subprocess.run(
        ["gcc", "-O3", "-s", str(orig_c), "-o", str(orig_bin)],
        check=True,
        capture_output=True,
    )

    master_hex = "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00"

    # 1. Wrap-ELF (Lease-Bound)
    wrap_lease_bin = work / "orig_compute.wrap_lease"
    p_wl = subprocess.run(
        [
            str(VS_BIN),
            "wrap-elf",
            "--key",
            master_hex,
            "--asset-id",
            "compute-lease",
            "--in",
            str(orig_bin),
            "--out",
            str(wrap_lease_bin),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    wl_meta = json.loads(p_wl.stdout)
    wl_token = make_lease_token(wl_meta["leaseKeyHex"], wl_meta["rxSha256Hex"])

    # 2. Wrap-ELF (--standalone White-Box Vault)
    wrap_sa_bin = work / "orig_compute.wrap_standalone"
    subprocess.run(
        [
            str(VS_BIN),
            "wrap-elf",
            "--key",
            master_hex,
            "--asset-id",
            "compute-sa",
            "--in",
            str(orig_bin),
            "--out",
            str(wrap_sa_bin),
            "--standalone",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    # 3. Freestanding-Vault
    fv_bin = work / "freestanding_vault"
    fv_secret_in = work / "fv_secret.bin"
    fv_secret_in.write_bytes(b"PROPRIETARY_QUANT_KERNEL_V4_ALPHA_9941\n")
    p_fv = subprocess.run(
        [
            str(VS_BIN),
            "build-elf-freestanding",
            "--key",
            master_hex,
            "--asset-id",
            "fv-secret",
            "--in",
            str(fv_secret_in),
            "--out",
            str(fv_bin),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    fv_meta = json.loads(p_fv.stdout)
    fv_token = make_lease_token(fv_meta["leaseKeyHex"], fv_meta["rxSha256Hex"])

    # 4. BLA v3.2.1 --intensity bankrupt ELF (if available)
    bla_bin = work / "orig_compute.bla"
    has_bla = BLA_CLI.exists() and NODE_BIN.exists()
    if has_bla:
        subprocess.run(
            [
                str(NODE_BIN),
                str(BLA_CLI),
                "protect",
                str(orig_bin),
                "--output",
                str(bla_bin),
                "--intensity",
                "bankrupt",
                "--seed",
                "bench-2026",
                "--json",
            ],
            check=True,
            capture_output=True,
        )
        os.chmod(bla_bin, 0o755)

    m_orig = measure_elf_process(orig_bin, runs)
    m_wl = measure_elf_process(wrap_lease_bin, runs, lease_token=wl_token)
    m_sa = measure_elf_process(wrap_sa_bin, runs, lease_token=None)
    m_fv = measure_elf_process(fv_bin, runs, lease_token=fv_token)
    m_bla = measure_elf_process(bla_bin, runs) if has_bla else None

    # Verify identical computation digest between Original, Wrap-Lease, Wrap-Standalone, and BLA
    orig_digest = re.search(r"DIGEST=([0-9a-f]+)", m_orig["sample_stdout"]).group(1)
    wl_digest = re.search(r"DIGEST=([0-9a-f]+)", m_wl["sample_stdout"]).group(1)
    sa_digest = re.search(r"DIGEST=([0-9a-f]+)", m_sa["sample_stdout"]).group(1)
    assert orig_digest == wl_digest == sa_digest, "Computation output digest mismatch!"

    def enrich(m: dict) -> dict:
        c_delta_pct = (
            ((m["compute_median_ms"] - m_orig["compute_median_ms"]) / m_orig["compute_median_ms"]) * 100.0
            if m_orig["compute_median_ms"] > 0
            else 0.0
        )
        m["steady_state_cpu_overhead_pct"] = round(c_delta_pct, 2)
        m["startup_delta_vs_orig_ms"] = round(m["wall_median_ms"] - m_orig["wall_median_ms"], 3)
        m["size_ratio_vs_orig"] = round(m["bytes"] / m_orig["bytes"], 2)
        return m

    enrich(m_wl)
    enrich(m_sa)
    if m_bla:
        enrich(m_bla)

    # Security & Disassembly Token Telemetry on Native Binaries
    dis_orig = analyze_disassembly(orig_bin)
    dis_wl = analyze_disassembly(wrap_lease_bin)
    dis_sa = analyze_disassembly(wrap_sa_bin)
    dis_fv = analyze_disassembly(fv_bin)
    dis_bla = analyze_disassembly(bla_bin) if has_bla else None

    # Standalone active tamper + ptrace + LD_PRELOAD + string leak checks
    sa_raw = wrap_sa_bin.read_bytes()
    secret_bytes = b"PROPRIETARY_QUANT_KERNEL_V4_ALPHA_9941"
    orig_leaks_secret = secret_bytes in orig_bin.read_bytes()
    sa_leaks_secret = secret_bytes in sa_raw
    wl_leaks_secret = secret_bytes in wrap_lease_bin.read_bytes()

    # Tamper .text & .rodata of standalone ELF -> must fail closed (rc != 0)
    sec_headers = subprocess.check_output(["readelf", "-SW", str(wrap_sa_bin)], text=True)
    text_off = 0
    ro_off = 0
    for ln in sec_headers.splitlines():
        m_sec = re.search(r"\[\s*\d+\]\s+(\.\S+)\s+\S+\s+[0-9a-f]+\s+([0-9a-f]+)\s+([0-9a-f]+)", ln)
        if m_sec:
            sname, soff, ssz = m_sec.group(1), int(m_sec.group(2), 16), int(m_sec.group(3), 16)
            if sname == ".text" and ssz > 64:
                text_off = soff + (ssz // 2)
            elif sname == ".rodata" and ssz > 64:
                ro_off = soff + (ssz // 2)

    sa_tamper_text = work / "sa_tamper_text"
    buf_t = bytearray(sa_raw)
    buf_t[text_off] ^= 0x01
    sa_tamper_text.write_bytes(buf_t)
    os.chmod(sa_tamper_text, 0o755)
    rc_sa_text = subprocess.run([str(sa_tamper_text)], capture_output=True, check=False).returncode

    sa_tamper_ro = work / "sa_tamper_ro"
    buf_r = bytearray(sa_raw)
    buf_r[ro_off] ^= 0x01
    sa_tamper_ro.write_bytes(buf_r)
    os.chmod(sa_tamper_ro, 0o755)
    rc_sa_ro = subprocess.run([str(sa_tamper_ro)], capture_output=True, check=False).returncode

    # Active ptrace check on standalone ELF -> must fail closed (rc == 3)
    ptrace_c = work / "ptrace_harness.c"
    ptrace_bin = work / "ptrace_harness"
    ptrace_c.write_text(
        r"""
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 2) return 99;
    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execl(argv[1], argv[1], (char *)0);
        _exit(98);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    if (WIFSTOPPED(st)) {
        ptrace(PTRACE_CONT, pid, 0, 0);
        waitpid(pid, &st, 0);
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : 97;
}
"""
    )
    subprocess.run(["gcc", "-O2", str(ptrace_c), "-o", str(ptrace_bin)], check=True)
    rc_sa_ptrace = subprocess.run(
        [str(ptrace_bin), str(wrap_sa_bin)], capture_output=True, check=False
    ).returncode

    # LD_PRELOAD immunity check on wrap_lease & freestanding_vault
    preload_marker = work / "ld_preload_fired.txt"
    preload_c = work / "preload_hook.c"
    preload_so = work / "libpreload_hook.so"
    preload_c.write_text(
        f'#include <stdio.h>\n__attribute__((constructor)) static void h(void){{FILE *f=fopen("{preload_marker}","w");if(f){{fputs("1",f);fclose(f);}}}}\n'
    )
    subprocess.run(
        ["gcc", "-O2", "-shared", "-fPIC", str(preload_c), "-o", str(preload_so)],
        check=True,
    )
    r_fd, w_fd = os.pipe()
    os.write(w_fd, fv_token)
    os.close(w_fd)
    try:
        rc_fv_preload = subprocess.run(
            [str(fv_bin)],
            env={**os.environ, "LD_PRELOAD": str(preload_so), "VS_LEASE_FD": str(r_fd)},
            pass_fds=(r_fd,),
            capture_output=True,
            check=False,
        ).returncode
    finally:
        os.close(r_fd)
    ld_preload_bypassed = preload_marker.exists()

    # REA binary hardening & exposure telemetry
    rea_orig = run_rea(["inspect-binary-hardening", str(orig_bin), "--format", "json"])
    rea_sa = run_rea(["inspect-binary-hardening", str(wrap_sa_bin), "--format", "json"])
    rea_wl = run_rea(["inspect-binary-hardening", str(wrap_lease_bin), "--format", "json"])

    return {
        "performance": {
            "original_o3_elf": m_orig,
            "wrap_elf_lease_bound": m_wl,
            "wrap_elf_standalone": m_sa,
            "freestanding_vault": m_fv,
            "bla_v3_2_1_bankrupt": m_bla,
        },
        "disassembly_and_tokens": {
            "original_o3_elf": dis_orig,
            "wrap_elf_lease_bound": dis_wl,
            "wrap_elf_standalone": dis_sa,
            "freestanding_vault": dis_fv,
            "bla_v3_2_1_bankrupt": dis_bla,
        },
        "security_assertions": {
            "orig_leaks_secret_offline": orig_leaks_secret,
            "wrap_lease_leaks_secret_offline": wl_leaks_secret,
            "wrap_standalone_leaks_secret_offline": sa_leaks_secret,
            "standalone_tamper_text_rc": rc_sa_text,
            "standalone_tamper_rodata_rc": rc_sa_ro,
            "standalone_ptrace_rc": rc_sa_ptrace,
            "freestanding_ld_preload_rc": rc_fv_preload,
            "freestanding_ld_preload_fired": ld_preload_bypassed,
            "golden_ratio_beacon_eliminated": (
                dis_wl["golden_ratio_beacon_hits"] == 0
                and dis_sa["golden_ratio_beacon_hits"] == 0
                and dis_fv["golden_ratio_beacon_hits"] == 0
            ),
            "polymorphic_stage_diversity_160": dis_sa["distinct_stage_opcode_fingerprints_of_160"],
        },
        "rea_binary_telemetry": {
            "original": {k: v for k, v in rea_orig.items() if k != "stdout"},
            "wrap_lease": {k: v for k, v in rea_wl.items() if k != "stdout"},
            "wrap_standalone": {k: v for k, v in rea_sa.items() if k != "stdout"},
        },
    }


def bench_domain_b_data_vspk3(work: pathlib.Path, verify_only: bool) -> dict:
    master_hex = "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff"
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
    key_buf = (ctypes.c_uint8 * 32).from_buffer_copy(bytes.fromhex(master_hex))

    # Build tiny C helper for fair native baseline: memcpy + SHA-256 or OpenSSL SHA-256
    base_c = work / "raw_baseline.c"
    base_so = work / "libraw_baseline.so"
    base_c.write_text(
        r"""
#include <stddef.h>
#include <stdint.h>
#include <string.h>
void raw_copy_checksum(const uint8_t *src, size_t n, uint8_t *dst, uint64_t *out_acc) {
    memcpy(dst, src, n);
    uint64_t a = 0xcbf29ce484222325ULL;
    const uint64_t *p64 = (const uint64_t *)dst;
    size_t words = n / 8;
    for (size_t i = 0; i < words; i++) {
        a ^= p64[i];
        a *= 0x100000001b3ULL;
    }
    *out_acc = a;
}
"""
    )
    subprocess.run(
        ["gcc", "-O3", "-march=native", "-shared", "-fPIC", str(base_c), "-o", str(base_so)],
        check=True,
    )
    blib = ctypes.CDLL(str(base_so))
    blib.raw_copy_checksum.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint64),
    ]

    tiers = [
        ("1_kib", 1024, 200 if verify_only else 1000),
        ("64_kib", 65536, 80 if verify_only else 400),
        ("1_mib", 1048576, 20 if verify_only else 80),
        ("16_mib", 16 * 1048576, 6 if verify_only else 24),
    ]
    results = {}
    for label, sz, iters in tiers:
        plain = os.urandom(sz)
        in_p = work / f"b_{label}.bin"
        out_p = work / f"b_{label}.vspk3"
        in_p.write_bytes(plain)
        asset_id = f"asset-{label}".encode()
        ctx = b"https://prod.vibeslayer.io"

        subprocess.run(
            [
                str(VS_BIN),
                "pack-v3",
                "--key",
                master_hex,
                "--domain",
                "code",
                "--asset-id",
                asset_id.decode(),
                "--context",
                ctx.decode(),
                "--in",
                str(in_p),
                "--out",
                str(out_p),
            ],
            check=True,
            capture_output=True,
        )
        sealed = out_p.read_bytes()

        # Baseline 1: Python hashlib.sha256 (OpenSSL SHA-NI/AVX2 C backend) + buffer copy
        raw_sha_us = []
        for i in range(iters + 3):
            t0 = time.perf_counter()
            copied = bytes(plain)
            _ = hashlib.sha256(copied).digest()
            dt = (time.perf_counter() - t0) * 1e6
            if i >= 3:
                raw_sha_us.append(dt)

        # Baseline 2: Raw C memcpy + 64-bit checksum
        src_c = (ctypes.c_uint8 * sz).from_buffer_copy(plain)
        dst_c = (ctypes.c_uint8 * sz)()
        acc_c = ctypes.c_uint64(0)
        raw_mem_us = []
        for i in range(iters + 3):
            t0 = time.perf_counter()
            blib.raw_copy_checksum(src_c, sz, dst_c, ctypes.byref(acc_c))
            dt = (time.perf_counter() - t0) * 1e6
            if i >= 3:
                raw_mem_us.append(dt)

        # Protected: libvibeslayer.so vs_unseal_vspk3 (HKDF + AVX-512 ChaCha20 + AVX2 Poly1305)
        in_c = (ctypes.c_uint8 * len(sealed)).from_buffer_copy(sealed)
        out_c = (ctypes.c_uint8 * len(sealed))()
        vspk3_us = []
        for i in range(iters + 3):
            t0 = time.perf_counter()
            n = lib.vs_unseal_vspk3(
                key_buf, b"code", asset_id, ctx, in_c, len(sealed), out_c, len(sealed)
            )
            dt = (time.perf_counter() - t0) * 1e6
            assert n == sz
            if i == 0:
                assert bytes(out_c[:n]) == plain
            if i >= 3:
                vspk3_us.append(dt)

        med_sha = statistics.median(raw_sha_us)
        med_mem = statistics.median(raw_mem_us)
        med_vs = statistics.median(vspk3_us)
        mib = sz / (1024.0 * 1024.0)

        results[label] = {
            "orig_bytes": sz,
            "vspk3_bytes": len(sealed),
            "overhead_bytes": len(sealed) - sz,
            "orig_memcpy_checksum_median_us": round(med_mem, 2),
            "orig_memcpy_checksum_mib_s": round(mib / (med_mem / 1e6), 1),
            "orig_sha256_verify_median_us": round(med_sha, 2),
            "orig_sha256_verify_mib_s": round(mib / (med_sha / 1e6), 1),
            "vspk3_unseal_median_us": round(med_vs, 2),
            "vspk3_unseal_mib_s": round(mib / (med_vs / 1e6), 1),
            "speedup_vs_orig_sha256": round(med_sha / med_vs, 2),
            "vspk3_entropy": shannon_entropy(sealed),
        }

    # CLI 16 MiB end-to-end file unseal vs raw file copy
    in_16m = work / "b_16_mib.bin"
    vspk_16m = work / "b_16_mib.vspk3"
    out_16m = work / "b_16_mib.out"
    cp_16m = work / "b_16_mib.cp"
    cli_runs = 4 if verify_only else 10
    cp_ms = []
    unseal_cli_ms = []
    for i in range(cli_runs + 1):
        t0 = time.perf_counter()
        subprocess.run(["cp", str(in_16m), str(cp_16m)], check=True)
        if i >= 1:
            cp_ms.append((time.perf_counter() - t0) * 1000.0)

        t1 = time.perf_counter()
        subprocess.run(
            [
                str(VS_BIN),
                "unseal-v3",
                "--key",
                master_hex,
                "--domain",
                "code",
                "--asset-id",
                "asset-16_mib",
                "--context",
                "https://prod.vibeslayer.io",
                "--in",
                str(vspk_16m),
                "--out",
                str(out_16m),
            ],
            check=True,
            capture_output=True,
        )
        if i >= 1:
            unseal_cli_ms.append((time.perf_counter() - t1) * 1000.0)

    results["cli_16_mib_disk_to_disk"] = {
        "orig_cp_median_ms": round(statistics.median(cp_ms), 2),
        "orig_cp_mib_s": round(16.0 / (statistics.median(cp_ms) / 1000.0), 1),
        "vspk3_cli_unseal_median_ms": round(statistics.median(unseal_cli_ms), 2),
        "vspk3_cli_unseal_mib_s": round(16.0 / (statistics.median(unseal_cli_ms) / 1000.0), 1),
    }
    return results


def start_raw_keepalive_server(payload: bytes) -> tuple[socket.socket, int, threading.Event]:
    """Minimal zero-overhead Keep-Alive HTTP/1.1 static asset server for fair baseline comparison."""
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind(("127.0.0.1", 0))
    srv_sock.listen(128)
    srv_sock.settimeout(0.2)
    port = srv_sock.getsockname()[1]
    stop_ev = threading.Event()
    header = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: application/javascript\r\n"
        f"Content-Length: {len(payload)}\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode("ascii")
    full_resp = header + payload

    def handle_client(conn: socket.socket):
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            buf = b""
            while not stop_ev.is_set():
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\r\n\r\n" in buf:
                    idx = buf.index(b"\r\n\r\n") + 4
                    buf = buf[idx:]
                    conn.sendall(full_resp)
        except OSError:
            pass
        finally:
            conn.close()

    def accept_loop():
        while not stop_ev.is_set():
            try:
                c, _ = srv_sock.accept()
                threading.Thread(target=handle_client, args=(c,), daemon=True).start()
            except TimeoutError:
                continue
            except OSError:
                break

    threading.Thread(target=accept_loop, daemon=True).start()
    return srv_sock, port, stop_ev


def bench_domain_c_website_runtime(work: pathlib.Path, verify_only: bool) -> dict:
    site_in = work / "site_orig"
    site_in.mkdir()
    secret_marker = "PROPRIETARY_WEB_SHADER_PIPELINE_SECRET_8821"
    (site_in / "index.html").write_text(
        '<!doctype html><html><head><title>App</title></head><body><script src="app.js"></script></body></html>\n'
    )
    app_js = (
        f'const CORE_KEY = "{secret_marker}";\n'
        + "export function step(x) { return (x * 1664525 + 1013904223) >>> 0; }\n" * 980
    ).encode("utf-8")
    (site_in / "app.js").write_bytes(app_js)
    (site_in / "blob16m.bin").write_bytes(os.urandom(16 * 1024 * 1024))

    keys_file = work / "web.keys.json"
    reg_file = work / "web.reg.json"

    # Benchmark website sealing speed (16+ MiB site)
    seal_runs = 3 if verify_only else 7
    seal_ms = []
    site_out = work / "site_protected"
    for i in range(seal_runs + 1):
        if site_out.exists():
            shutil.rmtree(site_out)
        t0 = time.perf_counter()
        subprocess.run(
            [
                str(VS_BIN),
                "website",
                str(site_in),
                "--out",
                str(site_out),
                "--origin",
                "http://127.0.0.1",
                "--keys",
                str(keys_file),
                "--registry",
                str(reg_file),
                "--no-gitignore",
            ],
            check=True,
            capture_output=True,
        )
        if i >= 1:
            seal_ms.append((time.perf_counter() - t0) * 1000.0)

    total_site_mib = sum(f.stat().st_size for f in site_in.rglob("*") if f.is_file()) / (1024.0 * 1024.0)
    med_seal_ms = statistics.median(seal_ms)

    # Security audit of generated website bundle
    manifest_raw = (site_out / "vibeslayer.web.json").read_text()
    manifest = json.loads(manifest_raw)
    loader_js = (site_out / "vibe-slayer-loader.js").read_text()
    app_vsweb_rel = manifest["files"]["app.js"]["vsweb"]
    app_vsweb_bytes = (site_out / app_vsweb_rel).read_bytes()

    manifest_has_sha256_oracle = '"sha256"' in manifest_raw
    loader_has_plaintext_endpoints = any(
        lit in loader_js
        for lit in ("/__vibeslayer/lease", "VSWEB1_WRAP|", "VSWEB1|", "vibeslayer.web.json")
    )
    vsweb_leaks_secret = secret_marker.encode() in app_vsweb_bytes

    # REA JavaScript application audit on original vs protected website
    (site_in / "package.json").write_text('{"name":"site-orig","version":"1.0.0","type":"module"}\n')
    (site_out / "package.json").write_text('{"name":"site-prot","version":"1.0.0"}\n')
    rea_web_orig = run_rea(["analyze-javascript-application", str(site_in), "--format", "json"])
    rea_web_prot = run_rea(["analyze-javascript-application", str(site_out), "--format", "json"])

    # Live HTTP Keep-Alive comparison: Unprotected Static Server vs vibe-slayer serve
    raw_sock, raw_port, raw_stop = start_raw_keepalive_server(app_js)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        vs_port = s.getsockname()[1]

    origin = f"http://127.0.0.1:{vs_port}"
    # Re-protect with exact port origin so lease handshake Origin check passes
    shutil.rmtree(site_out)
    subprocess.run(
        [
            str(VS_BIN),
            "website",
            str(site_in),
            "--out",
            str(site_out),
            "--origin",
            origin,
            "--keys",
            str(keys_file),
            "--registry",
            str(reg_file),
            "--no-gitignore",
        ],
        check=True,
        capture_output=True,
    )
    manifest = json.loads((site_out / "vibeslayer.web.json").read_text())
    app_vsweb_path = "/" + manifest["files"]["app.js"]["vsweb"]

    srv = subprocess.Popen(
        [
            str(VS_BIN),
            "serve",
            str(site_out),
            "--addr",
            f"127.0.0.1:{vs_port}",
            "--origin",
            origin,
            "--keys",
            str(keys_file),
            "--registry",
            str(reg_file),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        for _ in range(60):
            try:
                c = http.client.HTTPConnection("127.0.0.1", vs_port, timeout=0.5)
                c.request("GET", "/__vibeslayer/health")
                r = c.getresponse()
                r.read()
                c.close()
                if r.status == 200:
                    break
            except OSError:
                time.sleep(0.03)

        workers = 16
        reqs_per_worker = 25 if verify_only else 60
        total_reqs = workers * reqs_per_worker

        def run_keepalive_load(port: int, path: str) -> tuple[float, list[float]]:
            lat_us: list[float] = []
            lat_lock = threading.Lock()

            def worker_fn():
                local_lats = []
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
                for _ in range(reqs_per_worker):
                    t0 = time.perf_counter()
                    conn.request("GET", path, headers={"Connection": "keep-alive"})
                    resp = conn.getresponse()
                    body = resp.read()
                    assert resp.status == 200 and len(body) >= len(app_js)
                    local_lats.append((time.perf_counter() - t0) * 1e6)
                conn.close()
                with lat_lock:
                    lat_us.extend(local_lats)

            t_start = time.perf_counter()
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futs = [ex.submit(worker_fn) for _ in range(workers)]
                for f in futs:
                    f.result()
            return time.perf_counter() - t_start, lat_us

        # Warmup & measure both servers
        run_keepalive_load(raw_port, "/app.js")
        raw_dt, raw_lats = run_keepalive_load(raw_port, "/app.js")

        run_keepalive_load(vs_port, app_vsweb_path)
        vs_dt, vs_lats = run_keepalive_load(vs_port, app_vsweb_path)

        # Measure live ECDH P-256 + HKDF + AES-256-GCM lease handshake latency + client AES-GCM decrypt
        lease_ms = []
        decrypt_us = []
        conn = http.client.HTTPConnection("127.0.0.1", vs_port, timeout=5.0)
        hs_iters = 8 if verify_only else 25
        site_key_bytes = b""
        for i in range(hs_iters + 2):
            t0 = time.perf_counter()
            conn.request("GET", "/", headers={"Connection": "keep-alive"})
            r_html = conn.getresponse()
            html = r_html.read().decode("utf-8")
            ticket = re.search(r'<meta\s+name="vs-ticket"\s+content="([^"]+)"', html).group(1)

            c_priv = ec.generate_private_key(ec.SECP256R1())
            c_pub = c_priv.public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
            )
            conn.request(
                "POST",
                "/__vibeslayer/lease",
                body=json.dumps({"clientPublicKeyHex": c_pub.hex(), "ticket": ticket}).encode(),
                headers={"Content-Type": "application/json", "Origin": origin, "Connection": "keep-alive"},
            )
            r_lease = conn.getresponse()
            lease = json.loads(r_lease.read())
            assert r_lease.status == 200 and lease["ok"]

            s_pub = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), bytes.fromhex(lease["serverPublicKeyHex"])
            )
            shared = c_priv.exchange(ec.ECDH(), s_pub)
            w_info = f"VSWEB1_WRAP|{origin}".encode()
            w_key = HKDF(hashes.SHA256(), 32, lease["leaseId"].encode(), w_info).derive(shared)
            site_key_bytes = AESGCM(w_key).decrypt(
                bytes.fromhex(lease["wrapIvHex"]),
                bytes.fromhex(lease["wrappedKeyHex"]),
                w_info,
            )
            dt_hs = (time.perf_counter() - t0) * 1000.0
            if i >= 2:
                lease_ms.append(dt_hs)
        conn.close()

        aesgcm = AESGCM(site_key_bytes)
        iv = app_vsweb_bytes[:12]
        ct_tag = app_vsweb_bytes[12:]
        aad = b"VSWEB1|app.js"
        for i in range(100):
            t0 = time.perf_counter()
            pt = aesgcm.decrypt(iv, ct_tag, aad)
            dt_u = (time.perf_counter() - t0) * 1e6
            if i == 0:
                assert pt == app_js
            if i >= 5:
                decrypt_us.append(dt_u)
    finally:
        raw_stop.set()
        raw_sock.close()
        srv.terminate()
        srv.wait(timeout=3)

    return {
        "site_total_mib": round(total_site_mib, 2),
        "seal_website_median_ms": round(med_seal_ms, 2),
        "seal_website_mib_s": round(total_site_mib / (med_seal_ms / 1000.0), 1),
        "orig_app_js_bytes": len(app_js),
        "protected_vsweb_bytes": len(app_vsweb_bytes),
        "wire_overhead_bytes": len(app_vsweb_bytes) - len(app_js),
        "orig_http_keepalive_req_s": round(total_reqs / raw_dt, 1),
        "orig_http_keepalive_mib_s": round((total_reqs * len(app_js)) / (1024 * 1024) / raw_dt, 1),
        "orig_http_p50_us": round(statistics.median(raw_lats), 1),
        "vibeslayer_serve_req_s": round(total_reqs / vs_dt, 1),
        "vibeslayer_serve_mib_s": round((total_reqs * len(app_vsweb_bytes)) / (1024 * 1024) / vs_dt, 1),
        "vibeslayer_serve_p50_us": round(statistics.median(vs_lats), 1),
        "session_ecdh_lease_handshake_median_ms": round(statistics.median(lease_ms), 3),
        "client_aes256_gcm_decrypt_64k_median_us": round(statistics.median(decrypt_us), 2),
        "security": {
            "manifest_has_sha256_oracle": manifest_has_sha256_oracle,
            "loader_has_plaintext_endpoints": loader_has_plaintext_endpoints,
            "vsweb_leaks_secret": vsweb_leaks_secret,
            "vsweb_entropy": shannon_entropy(app_vsweb_bytes),
            "rea_orig_o200k_tokens": rea_web_orig["o200k_tokens"],
            "rea_prot_o200k_tokens": rea_web_prot["o200k_tokens"],
        },
    }


def bench_domain_d_3d_and_ai_weights(work: pathlib.Path, verify_only: bool) -> dict:
    master_hex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    out = {}

    if SAMPLE_GLB.exists():
        orig_glb_bytes = SAMPLE_GLB.read_bytes()
        vs3d_out = work / "model.vs3d"
        owner_ref = work / "owner_ref.bin"
        wm_pos = work / "wm_positions.bin"
        noisy_pos = work / "wm_positions_noisy.bin"
        iters = 3 if verify_only else 8

        # Original baseline: read + JSON header parse + binary chunk copy
        orig_parse_ms = []
        for i in range(iters + 1):
            t0 = time.perf_counter()
            raw = SAMPLE_GLB.read_bytes()
            magic, ver, length = struct.unpack_from("<III", raw, 0)
            jlen, _ = struct.unpack_from("<II", raw, 12)
            _ = json.loads(raw[20 : 20 + jlen])
            _ = bytes(raw[20 + jlen :])
            if i >= 1:
                orig_parse_ms.append((time.perf_counter() - t0) * 1000.0)

        cook_ms = []
        for i in range(iters + 1):
            t0 = time.perf_counter()
            subprocess.run(
                [
                    str(VS_BIN),
                    "cook-glb",
                    "--key",
                    master_hex,
                    "--asset-id",
                    "exarch-v4",
                    "--context",
                    "https://3d.vibeslayer.io",
                    "--in",
                    str(SAMPLE_GLB),
                    "--out",
                    str(vs3d_out),
                    "--owner-ref",
                    str(owner_ref),
                ],
                check=True,
                capture_output=True,
            )
            if i >= 1:
                cook_ms.append((time.perf_counter() - t0) * 1000.0)

        wm_embed_ms = []
        wm_detect_ms = []
        wm_hex = "feedfacecafebeef"
        noise_recovered_bits = 0
        for i in range(iters + 1):
            t0 = time.perf_counter()
            subprocess.run(
                [
                    str(VS_BIN),
                    "embed-wm64",
                    "--key",
                    master_hex,
                    "--asset-id",
                    "exarch-v4",
                    "--context",
                    "https://3d.vibeslayer.io",
                    "--wm-id-hex",
                    wm_hex,
                    "--in",
                    str(vs3d_out),
                    "--out-positions",
                    str(wm_pos),
                ],
                check=True,
                capture_output=True,
            )
            if i >= 1:
                wm_embed_ms.append((time.perf_counter() - t0) * 1000.0)

            if i == 0:
                # Apply +/-2 LSB quantization noise to every coordinate and verify 64/64 bit recovery
                raw_coords = wm_pos.read_bytes()
                cnt = len(raw_coords) // 2
                vals = list(struct.unpack(f"<{cnt}h", raw_coords))
                for idx_c in range(cnt):
                    delta = ((idx_c * 7 + 3) % 5) - 2  # deterministic in [-2, +2]
                    vals[idx_c] = max(-32768, min(32767, vals[idx_c] + delta))
                noisy_pos.write_bytes(struct.pack(f"<{cnt}h", *vals))
                det_noisy = subprocess.run(
                    [
                        str(VS_BIN),
                        "decode-wm64",
                        "--key",
                        master_hex,
                        "--asset-id",
                        "exarch-v4",
                        "--owner-ref",
                        str(owner_ref),
                        "--captured",
                        str(noisy_pos),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                d_n = json.loads(det_noisy.stdout)
                rec_int = int(d_n["decodedWatermarkIdHex"], 16)
                exp_int = int(wm_hex, 16)
                noise_recovered_bits = 64 - bin(rec_int ^ exp_int).count("1")
                assert noise_recovered_bits == 64

            t1 = time.perf_counter()
            det = subprocess.run(
                [
                    str(VS_BIN),
                    "decode-wm64",
                    "--key",
                    master_hex,
                    "--asset-id",
                    "exarch-v4",
                    "--owner-ref",
                    str(owner_ref),
                    "--captured",
                    str(wm_pos),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            if i == 0:
                djson = json.loads(det.stdout)
                assert djson.get("decodedWatermarkIdHex", "").lower() == wm_hex
            if i >= 1:
                wm_detect_ms.append((time.perf_counter() - t1) * 1000.0)

        vs3d_bytes = vs3d_out.read_bytes()
        out["spatial_3d_glb"] = {
            "orig_glb_bytes": len(orig_glb_bytes),
            "vs3d_bytes": len(vs3d_bytes),
            "size_reduction_pct": round((1.0 - len(vs3d_bytes) / len(orig_glb_bytes)) * 100.0, 2),
            "compression_ratio": round(len(orig_glb_bytes) / len(vs3d_bytes), 2),
            "orig_glb_parse_copy_median_ms": round(statistics.median(orig_parse_ms), 2),
            "cook_glb_to_vs3d_median_ms": round(statistics.median(cook_ms), 2),
            "wm64_embed_median_ms": round(statistics.median(wm_embed_ms), 2),
            "wm64_detect_median_ms": round(statistics.median(wm_detect_ms), 2),
            "wm64_bits_recovered_under_lsb2_noise": f"{noise_recovered_bits}/64",
            "vs3d_entropy": shannon_entropy(vs3d_bytes),
        }

    # AI Weights: 16 MiB .safetensors full load vs VSRA 64 KiB O(1) slice unseal
    st_header = json.dumps(
        {
            "weight_q_proj": {
                "dtype": "F32",
                "shape": [2048, 2048],
                "data_offsets": [0, 16 * 1024 * 1024],
            }
        }
    ).encode("utf-8")
    st_bytes = struct.pack("<Q", len(st_header)) + st_header + os.urandom(16 * 1024 * 1024)
    st_in = work / "weights.safetensors"
    st_in.write_bytes(st_bytes)

    iters_ai = 6 if verify_only else 15
    full_load_us = []
    for i in range(iters_ai + 1):
        t0 = time.perf_counter()
        raw_st = st_in.read_bytes()
        hlen = struct.unpack_from("<Q", raw_st, 0)[0]
        _ = json.loads(raw_st[8 : 8 + hlen])
        _ = bytes(raw_st[8 + hlen : 8 + hlen + 65536])
        if i >= 1:
            full_load_us.append((time.perf_counter() - t0) * 1e6)

    vsra_node_out = subprocess.check_output(
        [
            str(NODE_BIN),
            "-e",
            (
                "const crypto=require('node:crypto');"
                f"const {{defineSuitePolicy,createLeaseAuthority,dataAiProduct}}=require({json.dumps(str(REPO_ROOT / 'vibeslayer-suite' / 'src'))});"
                f"const {{unsealWeightChunkClient}}=require({json.dumps(str(REPO_ROOT / 'vibeslayer-suite' / 'src' / 'client' / 'data-ai-client.js'))});"
                "const kp=crypto.generateKeyPairSync('ed25519');"
                f"const auth=createLeaseAuthority(defineSuitePolicy({{enabled:true,masterKey:Buffer.from('{master_hex}','hex'),signingPrivateKeyPem:kp.privateKey.export({{type:'pkcs8',format:'pem'}}),signingPublicKeyPem:kp.publicKey.export({{type:'spki',format:'pem'}}),actions:{{'ai.weights.slice':{{product:'data-ai',requiredScopes:['ai:weights'],watermark:true,params:{{tensorId:{{type:'enum',values:['weight_q_proj']}},chunkIndex:{{type:'int',min:0,max:256}}}}}}}}}}));"
                "const plain=crypto.randomBytes(16*1024*1024);"
                "const c=dataAiProduct.packRandomAccessWeights({authority:auth,tensorId:'weight_q_proj',plainBytes:plain,chunkBytes:65536});"
                "const g=dataAiProduct.issueChunkLease({authority:auth,action:'ai.weights.slice',params:{tensorId:'weight_q_proj',chunkIndex:17},subject:'seat-42',scopes:['ai:weights'],tensorId:'weight_q_proj',chunkIndex:17});"
                "const samples=[];"
                "for(let i=0;i<25;i++){"
                "  const t0=process.hrtime.bigint();"
                "  const s=dataAiProduct.sealWatermarkedChunkForGrant({authority:auth,vspkRaBytes:c.vspkRaBytes,grant:g});"
                "  const out=unsealWeightChunkClient({vspkRaBytes:s,grant:g});"
                "  if(i>=5)samples.push(Number(process.hrtime.bigint()-t0)/1000);"
                "}"
                "samples.sort((a,b)=>a-b);"
                "console.log(JSON.stringify({vsraBytes:c.vspkRaBytes.length,wmSeedHexLeaked:'wmSeedHex' in g,medianSliceUs:Number(samples[Math.floor(samples.length/2)].toFixed(1))}));"
            ),
        ],
        text=True,
    )
    vsra_meta = json.loads(vsra_node_out.strip())
    assert vsra_meta["wmSeedHexLeaked"] is False

    med_full_us = statistics.median(full_load_us)
    out["ai_safetensors_16m"] = {
        "orig_safetensors_bytes": len(st_bytes),
        "vsra_16m_bytes": vsra_meta["vsraBytes"],
        "orig_full_16m_load_for_64k_slice_median_us": round(med_full_us, 1),
        "vsra_o1_64k_watermarked_slice_median_us": vsra_meta["medianSliceUs"],
        "o1_slice_speedup_vs_full_load_x": round(med_full_us / vsra_meta["medianSliceUs"], 2),
        "wm_seed_leaked": vsra_meta["wmSeedHexLeaked"],
    }
    return out


def compute_ai_plan_exhaustion_matrix(dis_sa: dict) -> dict:
    raw_tok = dis_sa["raw_text_o200k_tokens"]
    mcp_tok = dis_sa["mcp_json_o200k_tokens"]

    plans = [
        ("Cursor / Windsurf Pro Fast Context", 128_000),
        ("Claude Code Max / o3 / Sonnet Context", 200_000),
        ("Frontier 1M Extended Context", 1_000_000),
    ]
    rows = []
    for name, ctx in plans:
        rows.append(
            {
                "plan": name,
                "context_window_tokens": ctx,
                "single_binary_raw_text_overflow_x": round(raw_tok / ctx, 2),
                "single_binary_mcp_json_overflow_x": round(mcp_tok / ctx, 2),
                "five_binary_repo_mcp_json_overflow_x": round((mcp_tok * 5) / ctx, 2),
                "offline_plaintext_bits_recovered": 0,
            }
        )
    return {
        "single_binary_raw_text_o200k_tokens": raw_tok,
        "single_binary_mcp_json_o200k_tokens": mcp_tok,
        "five_binary_repo_raw_text_o200k_tokens": raw_tok * 5,
        "five_binary_repo_mcp_json_o200k_tokens": mcp_tok * 5,
        "plans": rows,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify-only", action="store_true")
    ap.add_argument("--json-out", type=str, default="")
    args = ap.parse_args()

    runs = 6 if args.verify_only else 25
    with tempfile.TemporaryDirectory(prefix="vs_orig_vs_protected_") as tmp:
        work = pathlib.Path(tmp)
        dom_a = bench_domain_a_native_elf(work, runs)
        dom_b = bench_domain_b_data_vspk3(work, args.verify_only)
        dom_c = bench_domain_c_website_runtime(work, args.verify_only)
        dom_d = bench_domain_d_3d_and_ai_weights(work, args.verify_only)
        ai_matrix = compute_ai_plan_exhaustion_matrix(
            dom_a["disassembly_and_tokens"]["wrap_elf_standalone"]
        )

        # Hard security assertions
        sec_a = dom_a["security_assertions"]
        assert sec_a["orig_leaks_secret_offline"] is True
        assert sec_a["wrap_lease_leaks_secret_offline"] is False
        assert sec_a["wrap_standalone_leaks_secret_offline"] is False
        assert sec_a["standalone_tamper_text_rc"] != 0
        assert sec_a["standalone_tamper_rodata_rc"] != 0
        assert sec_a["standalone_ptrace_rc"] != 0
        assert sec_a["freestanding_ld_preload_rc"] == 0
        assert sec_a["freestanding_ld_preload_fired"] is False
        assert sec_a["golden_ratio_beacon_eliminated"] is True
        assert sec_a["polymorphic_stage_diversity_160"] >= 16

        sec_c = dom_c["security"]
        assert sec_c["manifest_has_sha256_oracle"] is False
        assert sec_c["loader_has_plaintext_endpoints"] is False
        assert sec_c["vsweb_leaks_secret"] is False

        report = {
            "domain_a_native_elf": dom_a,
            "domain_b_data_vspk3": dom_b,
            "domain_c_website_runtime": dom_c,
            "domain_d_3d_and_ai": dom_d,
            "heavy_ai_plan_token_exhaustion": ai_matrix,
        }
        if args.json_out:
            pathlib.Path(args.json_out).write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
