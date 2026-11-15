"""Integration test for lpex2 real-binary differential validation."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from humpty.king.lpex2_case import main as lpex2_main
from humpty.ingest import make_loadable_so
from humpty.king.harness_gen import generate_harness


def test_lpex2_case_main():
    """Verify that lpex2_case runs all 7 phases end-to-end on the real binary."""
    binary = ROOT / "lpex2"
    if not binary.exists():
        pytest.skip("lpex2 binary not present")
    rc = lpex2_main()
    assert rc == 0


def test_lpex2_daxpy_catches_buggy_candidate(tmp_path):
    """Verify that the differential harness detects real divergences on pointer/array memory."""
    binary = ROOT / "lpex2"
    if not binary.exists():
        pytest.skip("lpex2 binary not present")

    loadable_so = make_loadable_so(binary, tmp_path / "lpex2.so")
    cg = tmp_path / "cg.json"
    cg.write_text("""{
        "format": "fuz.call-graph/1",
        "binary": {"sha256": "00", "arch": "x86-64", "kind": "elf"},
        "functions": [
            {"name": "DAXPY", "address": "0xcb4f80", "size": 128,
             "demangled_sig": "void DAXPY(const int *, const double *, const double *, const int *, double *, const int *)"}
        ],
        "edges": []
    }""")

    # Candidate with deliberate +0.5 error
    buggy_src = """#include <stdint.h>
#include <stddef.h>
void DAXPY(const int *n, const double *alpha, const double *x,
           const int *incx, double *y, const int *incy) {
    if (!n || !alpha || !x || !incx || !y || !incy) return;
    int count = *n; double a = *alpha;
    for (int i = 0; i < count; i++) {
        y[i] += a * x[i] + 0.5;
    }
}
"""
    h_dir = tmp_path / "h"
    res = generate_harness(cg, str(binary), h_dir, root_symbol="DAXPY", root_candidate_src=buggy_src)
    harness_bin = h_dir / "harness_bin"
    cmd = ["clang", "-O1", "-g", "-fsanitize=fuzzer,address", "-D_GNU_SOURCE",
           str(res.harness_c), str(res.candidate_c), "-o", str(harness_bin), "-ldl", "-lm"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr

    env = os.environ.copy()
    env["HORSE_TOY_ELF"] = str(loadable_so)
    fuzz = subprocess.run([str(harness_bin), "-runs=500"], env=env, capture_output=True, text=True)
    # The buggy candidate MUST fail / abort with HORSE DIVERGENCE
    assert fuzz.returncode != 0
    assert "HORSE DIVERGENCE" in fuzz.stderr
