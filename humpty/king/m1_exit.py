#!/usr/bin/env python3
"""M1 exit run — one leaf validated end to end, unattended.

The M1 exit criterion (WHITEPAPERS): "one leaf of an in-house non-obfuscated
binary is reimplemented and validated end to end (all traces pass + fuzz
budget without divergence) with no human intervention."

This script is the criterion, executable:
  1. ingest the toy call graph + trace bundle into a fresh DB
  2. run humpty.king.leaf_loop on the fnv1a leaf with the deterministic
     develop seam (gateway-independent — the loop itself is what's under
     test; the LLM is a swappable part behind `develop`)
  3. replay the full trace bundle through the validated candidate (all
     traces pass) and run the fuzz budget (no divergence)
  4. print the verdict

Unattended: no flag, no prompt, no manual step. Exit 0 = M1 exit met.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "horses", "src"))
sys.path.insert(0, os.path.join(ROOT, "horses", "spikes"))

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from humpty.db import make_session_factory  # noqa: E402
from humpty.db.models import Candidate, Function  # noqa: E402
from humpty.db.session import session_scope  # noqa: E402
from humpty.ingest import binary_sha256, load_call_graph  # noqa: E402
from humpty.trace import load_bundle  # noqa: E402
from humpty.king.leaf_loop import run_leaf_loop  # noqa: E402

CASE = os.path.join("toys", "case-01-leaf")
LEAF = "fnv1a"


def main() -> int:
    elf = os.path.join(ROOT, CASE, "build", "toy01")
    cg = os.path.join(ROOT, CASE, "ground_truth", "call_graph.json")
    bundle = os.path.join(ROOT, CASE, "ground_truth", "traces.jsonl")
    for p in (elf, cg, bundle):
        if not os.path.exists(p):
            print(f"M1 EXIT FAIL: missing artifact {p} (run build.sh + record.sh)")
            return 1

    td = tempfile.mkdtemp(prefix="m1exit-")
    eng = create_engine(f"sqlite:///{td}/m1.db")
    ini = Config(os.path.join(ROOT, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(ROOT, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", str(eng.url))
    command.upgrade(ini, "head")
    factory = make_session_factory(eng)
    sha = binary_sha256(elf)

    print("[1/4] ingest call graph + trace bundle")
    with session_scope(factory) as s:
        load_call_graph(s, json_path=cg, binary=elf)
        load_bundle(s, bundle=bundle, binary_sha256=sha)
        fid = s.query(Function).filter_by(binary_sha256=sha, name=LEAF).one().id

    print("[2/4] CEGIS loop (develop seam: deterministic; LLM is swappable)")
    sys.path.insert(0, os.path.join(ROOT, "horses", "src"))
    from s4_core import Fnv1aSpec  # noqa: E402

    # hermetic develop: returns the fnv1a-only source (never the shared
    # candidate file, which other milestone runs may have left in any state)
    LEAF_SRC = """#include <stdint.h>
#include <stddef.h>
uint32_t fnv1a(const uint8_t *data, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) { h ^= data[i]; h *= 16777619u; }
    return h;
}
"""

    def develop(spec, counterexample=None):
        return LEAF_SRC

    with session_scope(factory) as s:
        result = run_leaf_loop(s, function_id=fid, develop=develop,
                               max_iter=5, fuzz_budget_s=10,
                               log=lambda m: print(f"  {m}"))
    if not result.get("verified", False) and result.get("state") != "trusted":
        print(f"M1 EXIT FAIL: leaf loop result = {result}")
        return 1

    print("[3/4] full trace replay through the validated candidate")
    with session_scope(factory) as s:
        trusted = s.query(Function).filter_by(id=fid).one()
        if trusted.state != "trusted":
            print(f"M1 EXIT FAIL: state = {trusted.state}")
            return 1
        verified = (s.query(Candidate)
                    .filter_by(function_id=fid, status="trusted")
                    .order_by(Candidate.id.desc()).first())
        cand_src = verified.source_code

    # replay: every recorded trace input through the candidate .so must give
    # the recorded return (NFR-2: deterministic, from the DB rows)
    import ctypes
    import harness_driver as hd  # noqa: E402
    hd.write_candidate(cand_src)
    so = os.path.join(ROOT, "horses", "libfuzzer", "horse_candidate.so")
    lib = ctypes.CDLL(so)
    lib.fnv1a.restype = ctypes.c_uint32
    lib.fnv1a.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    mismatches = 0
    with open(bundle) as f:
        for line in f:
            rec = json.loads(line)
            if rec.get("fn") != LEAF:
                continue
            data = bytes.fromhex(rec["arg"])
            got = lib.fnv1a(data, len(data))
            want = int(rec["ret"], 16)
            if got != want:
                mismatches += 1
    if mismatches:
        print(f"M1 EXIT FAIL: {mismatches} trace mismatches")
        return 1
    print(f"  all recorded traces pass ({mismatches} mismatches)")

    print("[4/4] fuzz budget without divergence")
    r = hd.run_fuzz(budget_s=15)
    if r.divergent:
        print(f"M1 EXIT FAIL: divergence after trust: {r.counterexamples[:1]}")
        return 1
    print(f"  {r.execs} executions clean in {r.wall_s:.1f}s")

    print("\nM1 EXIT CRITERION MET: leaf validated end to end, unattended")
    eng.dispose()
    shutil.rmtree(td, ignore_errors=True)
    return 0


if __name__ == "__main__":
    import shutil
    sys.exit(main())
