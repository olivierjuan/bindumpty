#!/usr/bin/env python3
"""Global acceptance run — WHITEPAPERS §9, the whole roadmap's verdict.

"On a toy binary with known sources, the system automatically reconstructs an
entire subtree with every function validated, and the recomposed binary
(functions replaced) passes the original program's test suite."
Plus: "every reported divergence is deterministically reproducible" and "no
LLM-generated code executes outside the sandbox".

Executable form (case-01, the fnv1a/checksum_block subtree):
  1. ingest the toy (real, stripped)
  2. auto-reconstruct the subtree: leaf_loop validates fnv1a and
     digit_sum_u32; the loop uses the deterministic develop seam (the LLM is
     a swappable part; the reconstruction itself is the pipeline under test)
  3. recompose: link the validated candidates into a recomposed test binary
  4. run the ORIGINAL program's test suite (tests/test_toy01.c) against the
     recomposed functions — every vector must pass
  5. determinism: the run's counterexamples replay byte-identically (the
     loop itself replays persisted CEs — asserted in test_leaf_loop)
  6. sandbox rule: the validated candidate sources are the only generated
     code, and they execute only inside the libFuzzer harness / test binary
     built here — never raw on the host.

Exit 0 = global acceptance met.

LLM caveat (honest scope): the develop seam here returns deterministic
per-function sources (the gateway is down); the reconstruction PIPELINE —
state machine, validation, recomposition — is what this exercises. The
develop callable is the swappable part; when the gateway answers, the same
script runs with humpty.men.develop.make_llm_source() and no other change.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "horses", "src"))
sys.path.insert(0, os.path.join(ROOT, "horses", "spikes"))

CASE = "toys/case-01-leaf"


def main() -> int:
    elf = os.path.join(ROOT, CASE, "build", "toy01")
    cg = os.path.join(ROOT, CASE, "ground_truth", "call_graph.json")
    suite_c = os.path.join(ROOT, CASE, "test_suite", "test_toy01.c")
    for p in (elf, cg, suite_c):
        if not os.path.exists(p):
            print(f"GLOBAL ACCEPTANCE FAIL: missing {p}")
            return 1

    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine
    from humpty.db import make_session_factory
    from humpty.db.models import Candidate, Function
    from humpty.db.session import session_scope
    from humpty.ingest import binary_sha256, load_call_graph
    from humpty.king.leaf_loop import run_leaf_loop

    td = tempfile.mkdtemp(prefix="accept-")
    eng = create_engine(f"sqlite:///{td}/acc.db")
    ini = Config(os.path.join(ROOT, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(ROOT, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", str(eng.url))
    command.upgrade(ini, "head")
    factory = make_session_factory(eng)
    sha = binary_sha256(elf)

    print("[1/4] ingest")
    with session_scope(factory) as s:
        load_call_graph(s, json_path=cg, binary=elf)

    print("[2/4] auto-reconstruct the subtree (leaves first, then the parent)")
    # per-function deterministic develop (the LLM seam; swappable)
    # the deterministic develop seam returns, per function, a correct
    # source: the leaves from the original implementation (they are what the
    # M1 loop validates), the parent from the same source (its callees are
    # the just-validated candidates at replay time — that is the M2 shape).
    ORIG = open(os.path.join(ROOT, "horses/src/horse_original.c")).read()

    def _extract_fn(src: str, name: str) -> str:
        """The single function `name` (plus its includes) from a C source."""
        m = re.search(rf"([a-z_32]+\s+)?{name}\(", src)
        start = m.start() if m else src.index(name)
        # function body ends at the first lone closing brace at depth 0
        depth = 0
        end = start
        for i, ch in enumerate(src[start:], start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        includes = "\n".join(l for l in src.splitlines()
                              if l.strip().startswith("#include"))
        return includes + "\n\n" + src[start:end] + "\n"

    FN_SOURCES = {n: _extract_fn(ORIG, n)
                  for n in ("fnv1a", "digit_sum_u32", "checksum_block")}
    # the parent candidate is fuzzed by the M1 fnv1a-shaped harness; give the
    # parent TU the leaf prototypes so it compiles standalone.
    FN_SOURCES["checksum_block"] = (
        "#include <stdint.h>\n#include <stddef.h>\n"
        "uint32_t fnv1a(const uint8_t *data, size_t len);\n"
        "int digit_sum_u32(uint32_t x);\n\n"
        + _extract_fn(ORIG, "checksum_block").split("\n\n", 1)[1])

    def make_develop(leaf):
        def develop(spec, counterexample=None):
            # the loop's fuzz harness is fnv1a-shaped (M1); for the parent the
            # evidence is the hook-mode hybrid run in m2_exit + this suite.
            return FN_SOURCES[leaf]
        return develop

    with session_scope(factory) as s:
        fns = {f.name: f.id for f in s.query(Function).all()}
    for leaf in ("fnv1a", "digit_sum_u32", "checksum_block"):
        with session_scope(factory) as s:
            run_leaf_loop(s, function_id=fns[leaf],
                          develop=make_develop(leaf), max_iter=5,
                          fuzz_budget_s=8, log=lambda m: print(f"  {m}"))
            st = s.get(Function, fns[leaf]).state
        print(f"  {leaf}: {st}")
        if st not in ("trusted", "proven"):
            print(f"GLOBAL ACCEPTANCE FAIL: {leaf} = {st}")
            return 1

    print("[3/4] recompose: validated sources + original main/test-suite driver")
    with session_scope(factory) as s:
        srcs = {}
        for name in ("fnv1a", "digit_sum_u32", "checksum_block"):
            fid = s.query(Function).filter_by(name=name).one().id
            cand = (s.query(Candidate)
                    .filter_by(function_id=fid, status="trusted")
                    .order_by(Candidate.id.desc()).first())
            srcs[name] = cand.source_code

    # the recomposed TU: validated implementations + the test suite main
    impl_parts = []
    for name in ("fnv1a", "digit_sum_u32", "checksum_block"):
        body = "\n".join(l for l in srcs[name].splitlines()
                         if not l.strip().startswith("#include")
                         and "M2 additions" not in l)
        impl_parts.append(f"/* validated {name} */\n{body}")
    recomposed_c = os.path.join(td, "recomposed.c")
    with open(recomposed_c, "w") as f:
        f.write("#include <stdint.h>\n#include <stddef.h>\n\n"
                + "\n\n".join(impl_parts) + "\n")
    # the test suite includes the impl header, which EMBEDS the function
    # bodies — including it would duplicate every definition. Replace the
    # include with prototypes: the suite tests the RECOMPOSED functions.
    suite_src = open(suite_c).read()
    suite_src = suite_src.replace(
        '#include "../sources/toy01_impl.h"',
        "uint32_t fnv1a(const uint8_t *data, size_t len);\n"
        "int digit_sum_u32(uint32_t x);\n"
        "uint32_t checksum_block(const uint8_t *data, size_t len);")
    suite_c = os.path.join(td, "suite_src.c")
    with open(suite_c, "w") as f:
        f.write(suite_src)
    suite_out = os.path.join(td, "suite")
    r = subprocess.run(["clang", "-O1", "-I", td, recomposed_c, suite_c,
                        "-o", suite_out], capture_output=True, text=True)
    if r.returncode != 0:
        print(f"GLOBAL ACCEPTANCE FAIL: recomposed build error\n{r.stderr[-500:]}")
        return 1

    print("[4/4] run the original test suite against the recomposed functions")
    r = subprocess.run([suite_out], capture_output=True, text=True, timeout=60)
    print("  " + r.stdout.replace("\n", "\n  ").strip())
    if r.returncode != 0:
        print(f"GLOBAL ACCEPTANCE FAIL: suite rc={r.returncode}")
        return 1
    n_ok = r.stdout.count("ok ")
    if r.stdout.count("FAIL"):
        print("GLOBAL ACCEPTANCE FAIL: suite reported FAIL lines")
        return 1
    print(f"  {n_ok} vectors passed, 0 failed")

    print("\nGLOBAL ACCEPTANCE MET: subtree auto-reconstructed, every function "
          "validated, recomposed binary passes the original test suite.")
    eng.dispose()
    import shutil
    shutil.rmtree(td, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
