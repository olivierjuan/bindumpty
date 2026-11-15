"""humpty.king.harness_ctx — pluggable harness context for the CEGIS loop.

Decouples leaf_loop from the fnv1a-shaped M1 harness. A HarnessContext
bundles the per-function harness (write_candidate, run_fuzz, run_replay)
so leaf_loop can drive any function shape.

Default: M1HarnessContext (build_horse.sh, fnv1a-shaped).
Generated: harness_gen's per-binary harness for arbitrary binaries.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

__all__ = ["HarnessContext", "M1HarnessContext", "GeneratedHarnessContext"]


@dataclass
class HarnessContext:
    """Per-function harness operations used by the CEGIS loop."""
    write_candidate: callable  # (src: str) -> None
    run_fuzz: callable         # (budget_s: int) -> FuzzResult
    run_replay: callable       # (inputs: list[bytes]) -> list[Counterexample]
    persist_counterexample: callable  # (data: bytes) -> bool
    load_counterexamples: callable  # () -> list[bytes]


class M1HarnessContext:
    """The M1 fnv1a-shaped harness (backwards compat)."""

    def __init__(self):
        sys.path.insert(0, os.path.join(ROOT, "horses", "src"))
        import harness_driver as hd
        self._hd = hd
        self.write_candidate = hd.write_candidate
        self.run_fuzz = hd.run_fuzz
        self.run_replay = hd.run_replay
        self.persist_counterexample = hd.persist_counterexample
        self.load_counterexamples = hd.load_counterexamples


class GeneratedHarnessContext:
    """A per-binary generated harness (harness_gen output).

    Compiles the candidate .c into the generated harness and fuzzes it.
    Works for any function signature the ABI map covers.
    """

    def __init__(self, harness_dir: str, root_symbol: str,
                 original_so: str, budget_s: int = 15):
        self.harness_dir = harness_dir
        self.root_symbol = root_symbol
        self.original_so = original_so
        self.budget_s = budget_s
        self._cand_path = os.path.join(harness_dir, "candidate.c")
        self._so_path = os.path.join(harness_dir, "candidate.so")
        self._bin_path = os.path.join(harness_dir, "harness_bin")
        self._build = os.path.join(harness_dir, "build.sh")

    def write_candidate(self, src: str) -> None:
        with open(self._cand_path, "w") as f:
            f.write(src)
        r = subprocess.run(
            ["clang", "-O1", "-g", "-fsanitize=fuzzer,address",
             "-D_GNU_SOURCE", self._bin_path.replace("/harness_bin", "/harness.c"),
             self._cand_path, "-o", self._bin_path],
            capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise RuntimeError(f"harness build failed: {r.stderr[-300:]}")

    def run_fuzz(self, budget_s: int = 15) -> object:
        r = subprocess.run(
            [self._bin_path, f"-max_total_time={budget_s}"],
            capture_output=True, text=True, timeout=budget_s + 30)
        divergent = "DIVERGENCE" in (r.stdout + r.stderr)
        from dataclasses import dataclass as _dc, field as _f

        @_dc
        class _Result:
            divergent: bool = False
            counterexamples: list = _f(default_factory=list)
            execs: int = 0
            wall_s: float = 0.0
            crash_path: str | None = None

        res = _Result(divergent=divergent)
        return res

    def run_replay(self, inputs: list[bytes]) -> list:
        # run each input through the harness binary
        results = []
        for data in inputs:
            input_file = self._cand_path + ".input"
            with open(input_file, "wb") as f:
                f.write(data)
            r = subprocess.run(
                [self._bin_path, input_file, "-runs=0"],
                capture_output=True, text=True, timeout=30)
            if "DIVERGENCE" in (r.stdout + r.stderr):
                results.append({"input": data})
        return results

    def persist_counterexample(self, data: bytes) -> bool:
        ce_dir = os.path.join(self.harness_dir, "counterexamples")
        os.makedirs(ce_dir, exist_ok=True)
        path = os.path.join(ce_dir, f"ce_{len(data):05d}.bin")
        if os.path.exists(path):
            return False
        with open(path, "wb") as f:
            f.write(data)
        return True

    def load_counterexamples(self) -> list[bytes]:
        if not os.path.isdir(ce_dir):
            return []
        return [open(os.path.join(ce_dir, f), "rb").read()
                for f in sorted(os.listdir(ce_dir))
                if f.startswith("ce_")]

    @property
    def ce_dir(self) -> str:
        return os.path.join(self.harness_dir, "counterexamples")


import sys  # noqa: E402
