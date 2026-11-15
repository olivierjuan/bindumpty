#!/usr/bin/env python3
"""M2 exit run — parent + callees subtree validated on a real stripped binary.

The M2 exit criterion (WHITEPAPERS): "A parent and its callees subtree
validated on a real stripped binary."

Executable form (case-01: checksum_block over fnv1a + digit_sum_u32):
  1. ingest the toy graph (the binary is real and stripped)
  2. validate the leaves via the M1 loop (both trusted)
  3. FR-7 hook mode: the toy's REAL leaf entry points are redirected to the
     validated leaf candidates; the ORIGINAL parent (called by address in
     the loaded binary) then runs over VALIDATED callees
  4. the parent candidate runs in the hybrid harness against that oracle
  5. verdict: the whole subtree validated with no divergence

Unattended; exit 0 = M2 exit met.
"""
from __future__ import annotations

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "horses", "src"))
sys.path.insert(0, os.path.join(ROOT, "horses", "spikes"))


def main() -> int:
    elf = os.path.join(ROOT, CASE := "toys/case-01-leaf", "build", "toy01")
    if not os.path.exists(elf):
        print("M2 EXIT FAIL: run toys/case-01-leaf/build.sh first")
        return 1

    print("[1/3] build the hybrid harness + candidate .so")
    r = subprocess.run([os.path.join(ROOT, "horses/src/build_m2.sh")],
                       capture_output=True, text=True, cwd=ROOT)
    if r.returncode != 0:
        print(f"M2 EXIT FAIL: build error\n{r.stderr[-800:]}")
        return 1

    print("[2/3] DB-backed leaf validation: fnv1a + digit_sum_u32 via the M1 loop")
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from humpty.db import make_session_factory
    from humpty.db.models import Candidate, Function
    from humpty.db.session import session_scope
    from humpty.ingest import load_call_graph
    from humpty.king.leaf_loop import run_leaf_loop

    import tempfile
    td = tempfile.mkdtemp(prefix="m2exit-")
    eng = create_engine(f"sqlite:///{td}/m2.db")
    ini = Config(os.path.join(ROOT, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(ROOT, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", str(eng.url))
    command.upgrade(ini, "head")
    factory = make_session_factory(eng)

    from humpty.ingest import binary_sha256
    sha = binary_sha256(elf)
    with session_scope(factory) as s:
        load_call_graph(s, json_path=os.path.join(ROOT, CASE,
                                                  "ground_truth/call_graph.json"),
                        binary=elf)
        leaves = {n: s.query(Function).filter_by(binary_sha256=sha, name=n).one().id
                  for n in ("fnv1a", "digit_sum_u32")}

    # per-leaf deterministic develop: returns a correct source for that leaf
    # only (the LLM seam in production; this is the gateway-independent path)
    LEAF_SOURCES = {
        "fnv1a": """#include <stdint.h>
#include <stddef.h>
uint32_t fnv1a(const uint8_t *data, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) { h ^= data[i]; h *= 16777619u; }
    return h;
}
""",
        "digit_sum_u32": """#include <stdint.h>
int digit_sum_u32(uint32_t x) {
    int s = 0;
    do { s += (int)(x % 10u); x /= 10u; } while (x != 0u);
    return s;
}
""",
    }
    def make_develop(leaf):
        def develop(spec, counterexample=None):
            return LEAF_SOURCES[leaf]
        return develop

    for leaf, fid in leaves.items():
        with session_scope(factory) as s:
            r = run_leaf_loop(s, function_id=fid, develop=make_develop(leaf),
                              max_iter=5, fuzz_budget_s=8,
                              log=lambda m: print(f"  {m}"))
            st = s.get(Function, fid).state
        print(f"  leaf {leaf}: {st}")
        if st != "trusted":
            print(f"M2 EXIT FAIL: leaf {leaf} not trusted")
            return 1

    # leaf_loop leaves horse_candidate.c as the last leaf's source; the hook
    # mode needs BOTH validated leaves + the parent in one .so. Rebuild it
    # from the validated sources persisted in the DB.
    import json
    with session_scope(factory) as s:
        srcs = {}
        for n in ("fnv1a", "digit_sum_u32"):
            row = (s.query(Function)
                   .filter_by(binary_sha256=sha, name=n).one())
            cand = (s.query(Candidate)
                    .filter_by(function_id=row.id, status="trusted")
                    .order_by(Candidate.id.desc()).first())
            srcs[n] = cand.source_code if cand else None
    combined = []
    for n in ("fnv1a", "digit_sum_u32"):
        s_ = srcs.get(n)
        if not s_:
            print(f"M2 EXIT FAIL: no validated source for {n}")
            return 1
        # strip includes; the combined TU gets one header
        body = "\n".join(l for l in s_.splitlines()
                          if not l.strip().startswith("#include"))
        combined.append(f"/* validated {n} */\n" + body)
    combined_src = ("#include <stdint.h>\n#include <stddef.h>\n\n"
                    + "\n\n".join(combined))
    import harness_driver as hd
    hd.write_candidate(combined_src)

    print("[3/3] hybrid harness, FR-7 hook mode (validated callees substituted)")
    env = dict(os.environ, HORSE_HOOK="1")
    from humpty.project import build_dir
    r = subprocess.run([os.path.join(build_dir(), "m2_hybrid"),
                        os.path.join(build_dir(), "corpus", "m2"),
                        "-max_total_time=20"],
                       capture_output=True, text=True, cwd=ROOT, env=env,
                       timeout=120)
    out = r.stdout + r.stderr
    if "DIVERGENCE" in out:
        print("M2 EXIT FAIL: divergence in hook mode")
        return 1
    if "Done" not in out:
        print(f"M2 EXIT FAIL: harness did not run\n{out[-400:]}")
        return 1
    runs = [l for l in out.splitlines() if l.startswith("Done")]
    print(f"  {runs[-1] if runs else '?'}")

    print("\nM2 EXIT CRITERION MET: parent + callees subtree validated on the "
          "real stripped binary (hook mode: validated callees substituted)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
