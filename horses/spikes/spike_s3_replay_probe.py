#!/usr/bin/env python3
"""Spike S3 (M0): is deterministic replay (rr / DynamoRIO) viable on this host?

rr needs hardware performance counters (Intel PEBS / AMD IBS) plus MSR access;
DynamoRIO relies on ptrace + page protections. This probe reports, without
installing either tracer:

  1. perf_event_paranoid level (rr wants <= 1 for full replay),
  2. MSR access (/dev/cpu/*/msr) — rr uses it to snapshot CPU state,
  3. ptrace_scope (0 = unrestricted, helps DynamoRIO),
  4. perf_event_open(2) smoke tests (software + hardware CPU events) via the
     raw syscall, the same call rr makes,
  5. whether rr / DynamoRIO binaries are present.

It prints a verdict: rr-viable / DynamoRIO-viable / neither. Exit code 0 if at
least one is viable, 1 if neither (a documented M0 outcome — the whitepaper
allows Frida as the iteration-fast tracer in that case).
"""
from __future__ import annotations

import ctypes
import glob
import os
import platform
import shutil
import struct
import subprocess
import sys


def read_int(path: str) -> int | None:
    try:
        with open(path) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def perf_event_smoke() -> list[tuple[str, bool, str]]:
    """perf_event_open(2) the way rr makes it, for software and hardware events."""
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.syscall.restype = ctypes.c_long
    libc.syscall.argtypes = [
        ctypes.c_long, ctypes.c_void_p,
        ctypes.c_long, ctypes.c_long, ctypes.c_long, ctypes.c_long,
    ]
    NR = 298  # __NR_perf_event_open, x86_64

    def one(ev_type: int, config: int, pid: int, cpu: int, label: str) -> tuple[str, bool, str]:
        # struct perf_event_attr (kernel 5.10, verified against a working C struct):
        #   type(u32)@0  size(u32)@4  config(u32)@8  pad@12  sample_period(u64)@16
        # NOTE: type is 32-bit and size is at offset 4 (NOT 8) — the kernel
        # validates `size` at offset 4; a wrong size yields EINVAL.
        attr = bytearray(136)
        struct.pack_into("<I", attr, 0, ev_type)
        struct.pack_into("<I", attr, 4, 136)   # size
        struct.pack_into("<I", attr, 8, config)
        struct.pack_into("<Q", attr, 16, 1)    # sample_period
        buf = ctypes.create_string_buffer(bytes(attr), 136)
        fd = libc.syscall(NR, buf, pid, cpu, -1, 0)
        err = ctypes.get_errno()
        if fd >= 0:
            os.close(fd)
            return label, True, "perf_event_open OK"
        return label, False, f"errno={err} ({os.strerror(err)})"

    # rr opens per-thread (pid=0) and per-CPU (cpu>=0) events; (-1,-1) system-wide
    # needs CAP_PERFMON and is not what rr uses.
    return [
        one(1, 0, 0, -1, "SW  cpu-clock   self    (pid=0)"),
        one(1, 0, -1, 0, "SW  cpu-clock   cpu0    (cpu=0)"),
        one(0, 0, 0, -1, "HW  CPU_CYCLES  self    (pid=0)"),
        one(0, 0, -1, 0, "HW  CPU_CYCLES  cpu0    (cpu=0)"),
        one(0, 3, 0, -1, "HW  INSTRUCTIONS self   (pid=0)"),
    ]


def probe(binary: str, *args: str) -> str | None:
    b = shutil.which(binary)
    if not b:
        return None
    try:
        r = subprocess.run([b, *args], capture_output=True, text=True, timeout=15)
        out = (r.stdout or r.stderr).strip()
        return out.splitlines()[0] if out else "(no output)"
    except Exception as e:  # noqa: BLE001
        return f"error: {e}"


def main() -> int:
    print(f"kernel: {platform.release()}  machine: {platform.machine()}")
    paranoid = read_int("/proc/sys/kernel/perf_event_paranoid")
    ptrace_scope = read_int("/proc/sys/kernel/yama/ptrace_scope")
    msr_globs = glob.glob("/dev/cpu/*/msr")
    msr = bool(msr_globs)
    print(f"perf_event_paranoid: {paranoid} (rr wants <= 1)")
    print(f"ptrace_scope: {ptrace_scope} (0 = unrestricted, helps DynamoRIO)")
    print(f"MSR devices: {'present (' + str(len(msr_globs)) + 'x)' if msr else 'ABSENT (needs msr module / permissions)'}")

    results = perf_event_smoke()
    hw_ok = any(ok for label, ok, _ in results if label.startswith("HW"))
    for label, ok, detail in results:
        print(f"  {'OK ' if ok else 'FAIL'} {label:32s} {detail}")

    rr = probe("rr", "--version")
    dr = None
    for cand in ("drrun", "dynamorio", "drrun-static"):
        v = probe(cand, "--version")
        if v:
            dr = f"{cand}: {v}"
            break
    print(f"rr: {rr or 'not installed'}")
    print(f"DynamoRIO: {dr or 'not installed'}")

    # --- verdict ---------------------------------------------------------
    rr_viable = hw_ok and (paranoid is not None and paranoid <= 2)
    rr_full = rr_viable and msr  # full fidelity needs MSR (rr PMU/register snapshot)
    dr_viable = (paranoid is not None and paranoid <= 1) and (ptrace_scope in (0, None))
    print()
    rr_state = "VIABLE (full)" if rr_full else ("VIABLE (counters OK; no MSR -> check rr fallback)" if rr_viable else "NOT viable here")
    print(f"VERDICT: rr {rr_state} | DynamoRIO {'VIABLE' if dr_viable else 'NOT viable here'}")
    if rr_full or dr_viable or rr_viable:
        print("=> deterministic replay available on this machine (install rr or DynamoRIO to use it).")
        return 0
    print("=> neither rr nor DynamoRIO viable as-is. Frida remains the FR-3 tracer "
          "(tracing/record_frida.py). Escalation options: load the msr kernel module, "
          "set perf_event_paranoid=0, or run on a host with PEBS/IBS + MSR access.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
