"""M1 differential harness driver (FR-6, FR-15, NFR-2).

Bridges the CEGIS loop (horses/spikes/s4_core.py) to the real libFuzzer
harness (horses/src/m1_harness.c + build_horse.sh):

  write_candidate(src) -> rebuild horse_candidate.so
  run_fuzz(budget_s)   -> run the built harness for a wall budget
  run_replay(inputs)   -> deterministic replay of specific inputs (NFR-2)

The harness's original is the ground-truth fnv1a linked from
horses/src/horse_original.c (same source as the binary the traces were
recorded on). Divergences are reported by the harness as
"HORSE DIVERGENCE len=N input=<hex> got=0x... want=0x..." and parsed here.

Counterexamples (FR-15): each distinct divergent input is stored once and
becomes a permanent regression case (replayed before every fuzz round and
before declaring a leaf trusted).
"""
from __future__ import annotations

import os
import re
import sys
import subprocess
import time
from dataclasses import dataclass

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
# the project tree holds the mutable artifacts: live candidate source,
# harness/candidate builds, corpus
from humpty.project import src_dir as _proj_src, build_dir as _proj_build

OUT = str(_proj_build())
HARNESS = os.path.join(OUT, "harness")
CAND_SO = os.path.join(OUT, "horse_candidate.so")
CAND_SRC = os.path.join(_proj_src(), "horse_candidate.c")
CORPUS = os.path.join(OUT, "corpus", "m1")

_DIVERGENCE_RE = re.compile(
    r"HORSE DIVERGENCE len=(\d+) input=([0-9a-f]*) got=0x([0-9A-F]+) want=0x([0-9A-F]+)"
)


@dataclass
class Counterexample:
    input_hex: str
    got: int
    want: int

    def as_input(self) -> bytes:
        return bytes.fromhex(self.input_hex) if self.input_hex else b""

    def describe(self) -> str:
        return (f"len={len(self.as_input())} got=0x{self.got:08X} "
                f"want=0x{self.want:08X}")


@dataclass
class FuzzResult:
    divergent: bool
    counterexamples: list  # of Counterexample
    execs: int = 0
    wall_s: float = 0.0
    crash_path: str | None = None


def write_candidate(src: str) -> None:
    """Persist the agent's source and rebuild the candidate .so.
    Compile failures raise with the compiler's stderr — a silent
    CalledProcessError hides the actual clang error."""
    with open(CAND_SRC, "w") as f:
        f.write(src)
    r = subprocess.run([os.path.join(ROOT, "horses", "src", "build_horse.sh")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("candidate build failed:\n"
                           + (r.stderr or r.stdout)[-1200:])


def _parse(lines: list[str]) -> tuple[list, list]:
    divergences, crashes = [], []
    for line in lines:
        m = _DIVERGENCE_RE.search(line)
        if m:
            divergences.append(Counterexample(
                input_hex=m.group(2), got=int(m.group(3), 16),
                want=int(m.group(4), 16)))
        if "crash-" in line:
            pm = re.search(r"\S*crash-\S+", line)
            if pm:
                crashes.append(pm.group(0))
    return divergences, crashes


def run_fuzz(budget_s: int = 30, max_len: int = 4096) -> FuzzResult:
    """Run the differential harness for a wall-clock budget.

    exit 0  -> no divergence in budget (the 'trusted' signal for this round)
    exit != 0 + divergence line -> counterexample found (FR-15)
    """
    os.makedirs(CORPUS, exist_ok=True)
    t0 = time.perf_counter()
    # the harness dlopens the candidate by env — point it at the
    # project build (the C default is the legacy relative path)
    env = dict(os.environ, HORSE_CANDIDATE_SO=CAND_SO)
    p = subprocess.run(
        [HARNESS, CORPUS, f"-max_len={max_len}",
         f"-max_total_time={budget_s}", "-print_final_stats=1"],
        capture_output=True, text=True, timeout=budget_s + 30,
        cwd=ROOT, env=env,
    )
    wall = time.perf_counter() - t0
    lines = (p.stdout + p.stderr).splitlines()
    divergences, crashes = _parse(lines)
    m = re.search(r"#(\d+)\s+(?:DONE|pulse)", "\n".join(lines))
    execs = int(m.group(1)) if m else 0
    return FuzzResult(divergent=bool(divergences), counterexamples=divergences,
                      execs=execs, wall_s=wall,
                      crash_path=crashes[0] if crashes else None)


def run_replay(inputs: list[bytes]) -> list[Counterexample]:
    """Deterministically replay specific inputs through the harness.

    libFuzzer runs each file in the corpus dir once (runs=N with -runs=1
    doesn't replay individual files), so we pass them as individual corpus
    entries in a temp dir and run with -runs=0 semantics: libFuzzer runs each
    corpus file once at INITED before fuzzing starts; aborting at the first
    divergence is enough for replay.
    """
    import tempfile

    os.makedirs(CORPUS, exist_ok=True)
    results = []
    for data in inputs:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "replay")
            with open(path, "wb") as f:
                f.write(data)
            env = dict(os.environ, HORSE_CANDIDATE_SO=CAND_SO)
            p = subprocess.run([HARNESS, path, "-runs=0"], capture_output=True,
                               text=True, timeout=30, cwd=ROOT, env=env)
            divs, _ = _parse((p.stdout + p.stderr).splitlines())
            if divs:
                # keep only divergences whose input matches what we replayed
                results.extend(d for d in divs if d.as_input() == data)
    return results


# --- counterexample persistence (FR-15) — canonical store -------------------

CE_DIR = os.path.join(CORPUS, "counterexamples")


def persist_counterexample(data: bytes) -> bool:
    """Store a distinct divergent input as a permanent regression case.
    Returns True if newly added (deduplicated by exact input bytes)."""
    os.makedirs(CE_DIR, exist_ok=True)
    path = ce_path(data)
    if os.path.exists(path):
        return False
    with open(path, "wb") as f:
        f.write(data)
    return True


def load_counterexamples() -> list[bytes]:
    if not os.path.isdir(CE_DIR):
        return []
    return [open(os.path.join(CE_DIR, f), "rb").read()
            for f in sorted(os.listdir(CE_DIR)) if f.startswith("ce_")]


def ce_path(data: bytes) -> str:
    return os.path.join(CE_DIR, f"ce_{len(data):05d}.bin")
