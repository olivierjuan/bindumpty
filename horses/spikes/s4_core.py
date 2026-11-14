"""S4 spike core (M0): agent-runtime-agnostic CEGIS leaf pipeline.

The M1 agent runtime (Pydantic AI vs. mini-SWE-agent, FR-4) must be a
*swappable* piece. This module defines the invariant the runtime satisfies and
the scoring harness the M1 developer worker reuses:

  develop(spec, counterexample=None) -> DevelopResult
      one LLM round-trip: the runtime returns C source for the leaf.

  score(candidate_source, leaf) -> ScoreResult
      generates one self-contained C program (candidate + reference + a main
      that compares them over curated + randomized cases), compiles it with
      clang, runs it. ok == no divergence. This is the M1 differential
      harness's pure-function core (the full M1 harness adds memory diff,
      FR-9).

  cegis_leaf(spec, develop, max_iter) -> LeafResult
      develop -> score; on divergence, feed the counterexample back.

The reference implementation is the ground-truth source (M0/M1 path). In M2+
it is replaced by the original binary's function via a trampoline (FR-7) — the
scorer interface does not change.
"""
from __future__ import annotations

import json
import os
import random
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# --- data types -------------------------------------------------------------

@dataclass
class LeafSpec:
    name: str
    signature: str
    args_layout: str
    ret_type: str
    notes: str
    test_vectors: list  # list of C expressions: ("hex_literal_args...")
    randomized_n: int = 256

    def cases_file(self) -> str:
        """C initializers + case table. Returns (c_source, n_cases)."""
        raise NotImplementedError


@dataclass
class DevelopResult:
    source: str
    iterations: int = 1
    input_tokens: int = 0
    output_tokens: int = 0
    wall_s: float = 0.0
    error: str | None = None


@dataclass
class ScoreResult:
    ok: bool
    n_cases: int = 0
    divergences: list = field(default_factory=list)  # (case_repr, got, expected)
    wall_s: float = 0.0
    build_error: str | None = None


@dataclass
class LeafResult:
    name: str
    verified: bool
    source: str
    develop: DevelopResult
    score: ScoreResult
    total_wall_s: float = 0.0


# --- prompt (minimal M1 developer prompt) -----------------------------------

def develop_prompt(spec: LeafSpec, counterexample: str | None = None) -> str:
    vec = "\n".join(spec.prompt_vectors()) or "  (none)"
    ce = (
        f"\nA previous attempt DIVERGED on this case:\n{counterexample}\nFix it.\n"
        if counterexample
        else ""
    )
    return f"""You are reimplementing one function from a stripped C binary.
Respond with ONLY a JSON object: {{"source": "<C source>"}}.
The source must define exactly this function (no main, no other functions):

{spec.signature}

Argument layout: {spec.args_layout}
Return type: {spec.ret_type}
Behavior: {spec.notes}

Known correct behavior (test vectors):
{vec}
{ce}"""


def parse_develop(text: str) -> str:
    """Extract C source from the model response (JSON or code fence or raw)."""
    text = text.strip()
    m = re.search(r"```(?:c|c\+\+)?\s*(.*?)```", text, re.S)
    if m:
        text = m.group(1).strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "source" in obj:
            return obj["source"].strip()
    except json.JSONDecodeError:
        pass
    return text


# --- concrete leaf specs for the toy ----------------------------------------

class Fnv1aSpec(LeafSpec):
    """fnv1a(const uint8_t*, size_t) -> uint32_t."""

    # Python reference used ONLY to mint the curated prompt vectors (the C
    # scorer computes its reference at runtime from source, independently).
    @staticmethod
    def _ref(data: bytes) -> int:
        h = 2166136261
        for b in data:
            h ^= b
            h = (h * 16777619) & 0xFFFFFFFF
        return h

    def __init__(self, randomized_n: int = 256, seed: int = 0):
        curated = ["", "61", "6161", "666f6f626172", "00", "01020304"]
        vectors = [(hx, len(hx) // 2, self._ref(bytes.fromhex(hx) if hx else b""))
                   for hx in curated]
        super().__init__(
            name="fnv1a",
            signature="uint32_t fnv1a(const uint8_t *data, size_t len)",
            args_layout="(data: bytes, len: u64)",
            ret_type="uint32_t",
            notes=(
                "FNV-1a 32-bit hash. h = 2166136261 (offset basis); for each byte: "
                "h ^= byte; h *= 16777619 (FNV prime). Return h. Empty input returns "
                "the offset basis."
            ),
            test_vectors=vectors,
            randomized_n=randomized_n,
        )

    def prompt_vectors(self) -> list[str]:
        return [
            f"  data=0x{hx} (len {ln}) -> 0x{exp:08X}" for hx, ln, exp in self.test_vectors
        ]

    def cases_file(self) -> str:
        """Return (c_source, n_cases). Emits REAL byte arrays decoded from hex
        (NOT the hex string as a literal — that would test on ASCII digits)."""
        rng = random.Random(0)
        cases = [(hx, len(hx) // 2) for hx, ln, exp in self.test_vectors]
        for _ in range(self.randomized_n):
            L = rng.randint(0, 128)
            hx = "".join(f"{rng.randint(0, 255):02x}" for _ in range(L))
            cases.append((hx, L))
        buf_lines, case_lines = [], []
        for i, (hx, n) in enumerate(cases):
            if n == 0:
                buf_lines.append(f"static const uint8_t B{i}[] = {{0}};")
            else:
                lit = ", ".join(f"0x{hx[j:j + 2]}" for j in range(0, len(hx), 2))
                buf_lines.append(f"static const uint8_t B{i}[] = {{{lit}}};")
            case_lines.append(f"{{ B{i}, {n} }}")
        src = "\n".join(buf_lines) + "\n" + \
            "static struct { const uint8_t *d; size_t n; } CASES[] = {\n" + \
            ",\n".join(case_lines) + "\n};\nstatic const int N_CASES = " + \
            str(len(cases)) + ";"
        return src, len(cases)


# --- scorer -----------------------------------------------------------------

def build_and_score(candidate_src: str, spec: Fnv1aSpec) -> ScoreResult:
    """Generate candidate+reference+main, compile with clang, run, compare."""
    ref_src = """
static uint32_t ref_fnv1a(const uint8_t *data, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) { h ^= (uint32_t)data[i]; h *= 16777619u; }
    return h;
}
"""
    cases_src, n = spec.cases_file()
    cand = candidate_src.replace("uint32_t fnv1a", "static uint32_t cand_fnv1a")
    main_src = """
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

""" + ref_src + "\n" + cases_src + "\n" + cand + """

int main(void) {
    int diverged = 0;
    for (int i = 0; i < N_CASES; i++) {
        uint32_t c = cand_fnv1a(CASES[i].d, CASES[i].n);
        uint32_t r = ref_fnv1a(CASES[i].d, CASES[i].n);
        if (c != r) {
            fprintf(stderr, "DIVERGENCE case=%d n=%zu cand=0x%08X ref=0x%08X\\n",
                    i, CASES[i].n, c, r);
            diverged++;
            if (diverged >= 5) break;
        }
    }
    printf("n=%d diverged=%d\\n", N_CASES, diverged);
    return diverged;
}
"""
    with tempfile.TemporaryDirectory() as td:
        prog = os.path.join(td, "score.c")
        with open(prog, "w") as f:
            f.write(main_src)
        exe = os.path.join(td, "score")
        t0 = time.perf_counter()
        b = subprocess.run(
            ["clang", "-O1", "-Wno-implicit-int", prog, "-o", exe],
            capture_output=True, text=True,
        )
        if b.returncode != 0:
            return ScoreResult(ok=False, n_cases=0, divergences=[],
                               wall_s=time.perf_counter() - t0,
                               build_error=b.stderr[-2000:])
        r = subprocess.run([exe], capture_output=True, text=True, timeout=30)
        wall = time.perf_counter() - t0
        divs = []
        for line in r.stderr.splitlines():
            m = re.search(r"case=(\d+) n=(\d+) cand=0x([0-9A-F]+) ref=0x([0-9A-F]+)", line)
            if m:
                divs.append((f"case={m.group(1)} n={m.group(2)}", m.group(3), m.group(4)))
        return ScoreResult(ok=(r.returncode == 0), n_cases=n,
                           divergences=divs, wall_s=wall)
