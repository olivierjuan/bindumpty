#!/usr/bin/env python3
"""bindumpty run — reconstruct a subtree from any ingested binary.

General driver: fingerprint matches first (free), leaf-first CEGIS over the
rest, failed functions never block the tree (NFR-7). Works on ANY ingested
binary — the toy is just the validation baseline.

Usage:
  python -m humpty.king.run_main --binary <elf> [--cg call_graph.json]
                                 [--max-iter 5] [--fuzz-budget 15] [--llm]

--llm uses the live developer seam (needs ANTHROPIC_* env). Without it the
script refuses: a stripped binary has no source to extract — the LLM is the
synthesizer. Tests inject their own develop callable into
humpty.king.run.run_subtree directly.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "horses", "src"))
sys.path.insert(0, os.path.join(ROOT, "horses", "spikes"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True, help="the target ELF")
    ap.add_argument("--cg", help="fuz.call-graph/1 JSON (default: objdump backend)")
    ap.add_argument("--max-iter", type=int, default=5)
    ap.add_argument("--fuzz-budget", type=int, default=15)
    ap.add_argument("--llm", action="store_true",
                    help="use the live LLM develop (needs ANTHROPIC_* env)")
    args = ap.parse_args()

    if not os.path.exists(args.binary):
        print(f"binary not found: {args.binary}", file=sys.stderr)
        return 2

    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine

    from humpty.db import make_session_factory
    from humpty.db.session import session_scope
    from humpty.ingest import binary_sha256, load_call_graph
    from humpty.king.run import run_subtree

    cg = args.cg
    if cg is None:
        from analysis.exporters import export_with
        cg = os.path.join(tempfile.mkdtemp(prefix="bindumpty-"), "cg.json")
        res = export_with("objdump", args.binary, cg)
        print(f"[ingest] call graph via objdump: {len(res.functions)} fns, "
              f"{len(res.edges)} edges")
    else:
        print(f"[ingest] call graph: {cg}")

    td = tempfile.mkdtemp(prefix="bindumpty-run-")
    eng = create_engine(f"sqlite:///{td}/run.db")
    ini = Config(os.path.join(ROOT, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(ROOT, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", str(eng.url))
    command.upgrade(ini, "head")
    factory = make_session_factory(eng)
    sha = binary_sha256(args.binary)

    with session_scope(factory) as s:
        load_call_graph(s, json_path=cg, binary=args.binary)

    if not args.llm:
        print("[develop] the developer synthesizer is required: a stripped "
              "binary has no source to extract. Pass --llm (needs "
              "ANTHROPIC_* env) or call humpty.king.run.run_subtree with "
              "your own develop callable.", file=sys.stderr)
        return 2
    from humpty.men.develop import make_llm_source
    develop = make_llm_source()

    with session_scope(factory) as s:
        rep = run_subtree(s, binary_sha256=sha, develop=develop,
                          max_iter=args.max_iter,
                          fuzz_budget_s=args.fuzz_budget)

    print("\n=== run report ===")
    print(f"functions in order : {rep.order}")
    for name, v in rep.verdicts.items():
        print(f"  {name:24s} {v.state:10s} conf={v.confidence:.2f} "
              f"iters={v.iterations}")
    if rep.skipped:
        print(f"  fingerprint-skipped (free): {rep.skipped}")
    if rep.failed:
        print(f"  FAILED (original stands in, NFR-7): {rep.failed}")
    print(f"verified: {rep.verified_frac:.0%}")
    return 0 if not rep.failed else 1


if __name__ == "__main__":
    sys.exit(main())
