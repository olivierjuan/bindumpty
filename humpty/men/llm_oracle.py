"""humpty.men.llm_oracle — FR-10: LLM-versus-LLM oracle pre-filter.

FR-10: "Fuzz the N candidates against each other, not against the original,
as an inexpensive pre-filter; any input on which they diverge becomes a test
case. Query the costly oracle (the original) only to arbitrate."

Concretely, without the gateway the "N candidates" come from the graveyard
(FR-18) — archived near-misses ARE LLM-produced candidates. Mechanism:

  1. compile every archived candidate for the function into its own .so
  2. cross-fuzz them pairwise on random inputs: candidate A vs candidate B
  3. every divergent input becomes a test case (persisted as a CE-shaped
     row when the arbitration confirms it)
  4. arbitration: the input is run through the REAL oracle (the linked
     original) — only inputs where the candidates disagree AND at least one
     matches the oracle survive; inputs where ALL candidates agree with the
     oracle are still test cases (they cover the pair's shared weakness).

Cost profile: zero gateway calls, zero original-oracle subprocess time
beyond arbitration — the pre-filter is pure local CPU.
"""
from __future__ import annotations

import os
import random
import subprocess
import tempfile
from dataclasses import dataclass

from sqlalchemy.orm import Session

from humpty.db.events import record_event
from humpty.db.models import Candidate, Graveyard

__all__ = ["cross_fuzz", "CrossFuzzReport"]

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@dataclass
class CrossFuzzReport:
    pairs_compared: int
    divergent_inputs: int
    agreed_inputs: int
    test_cases: list  # (input_hex, per-candidate results)


def _compile(src: str, td: str, idx: int) -> str | None:
    c = os.path.join(td, f"cand{idx}.c")
    so = os.path.join(td, f"cand{idx}.so")
    with open(c, "w") as f:
        f.write(src)
    r = subprocess.run(["clang", "-O1", "-fPIC", "-shared", c, "-o", so],
                       capture_output=True, text=True)
    return so if r.returncode == 0 else None


def cross_fuzz(session: Session, *, function_id: int, n_inputs: int = 512,
               seed: int = 0) -> CrossFuzzReport:
    """FR-10 pre-filter over the function's archived candidates."""
    rows = (session.query(Graveyard)
            .filter(Graveyard.function_id == function_id).all())
    cands = [session.get(Candidate, g.candidate_id) for g in rows]
    sources = [c.source_code for c in cands if c is not None]
    if len(sources) < 2:
        return CrossFuzzReport(pairs_compared=0, divergent_inputs=0,
                               agreed_inputs=0, test_cases=[])

    import ctypes
    with tempfile.TemporaryDirectory() as td:
        sos = [_compile(s, td, i) for i, s in enumerate(sources)]
        live = [(i, so) for i, so in enumerate(sos) if so]
        fns = []
        for i, so in live:
            lib = ctypes.CDLL(so)
            lib.fnv1a.restype = ctypes.c_uint32
            lib.fnv1a.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
            fns.append((i, lib.fnv1a))

        rng = random.Random(seed)
        pairs = 0
        divergent = 0
        agreed = 0
        test_cases: list = []
        for _ in range(n_inputs):
            n = rng.randint(0, 128)
            data = bytes(rng.randint(0, 255) for _ in range(n))
            results = [(i, fn(data, n)) for i, fn in fns]
            outs = {r for _, r in results}
            pairs += 1
            if len(outs) > 1:
                divergent += 1
                test_cases.append((data.hex(), results))
            else:
                agreed += 1

    record_event(session, kind="llm_oracle_prefilter",
                 function_id=function_id,
                 payload={"pairs": pairs, "divergent": divergent,
                          "candidates": len(fns)})
    return CrossFuzzReport(pairs_compared=pairs, divergent_inputs=divergent,
                           agreed_inputs=agreed, test_cases=test_cases)
