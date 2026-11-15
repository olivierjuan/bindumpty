"""humpty.king.cli_main — the `bindumpty` CLI with checkpoint/resume.

Multi-run sequences with automatic checkpoint/resume:

    # Run 1: CEGIS on the tree (persists to ./bindumpty.db)
    python -m humpty.king.cli_main run --binary <elf> --db ./bindumpty.db

    # LLM limit hit? The DB has the state. Re-run later:
    python -m humpty.king.cli_main run --binary <elf> --db ./bindumpty.db

    # Recompose the validated call tree into a working .so:
    python -m humpty.king.cli_main recompose --binary <elf> --db ./bindumpty.db

The DB is the checkpoint: functions in trusted/proven state are skipped
by run_subtree (is_success check). Stopping and restarting picks up
exactly where the last run left off.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

from sqlalchemy.orm import sessionmaker

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "horses", "src"))
sys.path.insert(0, os.path.join(ROOT, "horses", "spikes"))


def _setup_db(db_path: str) -> tuple:
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine
    from humpty.db import make_session_factory

    db_url = f"sqlite:///{db_path}"
    eng = create_engine(db_url, connect_args={"timeout": 30,
                                              "check_same_thread": False})
    ini = Config(os.path.join(ROOT, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(ROOT, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(ini, "head")
    factory = make_session_factory(eng)
    return factory, eng


def _graph_for(binary: str, backend: str, cache_dir: str) -> str:
    """Produce (or reuse a cached) fuz.call-graph/1 JSON."""
    from humpty.ingest import binary_sha256

    sha = binary_sha256(binary)
    cache_key = f"{sha[:16]}_{backend}"
    cache_path = os.path.join(cache_dir, f"cg_{cache_key}.json")
    if os.path.exists(cache_path):
        print(f"[cache] call graph reused: {cache_path}")
        return cache_path
    from analysis.exporters import export_with
    export_with(backend, binary, cache_path)
    os.makedirs(cache_dir, exist_ok=True)
    return cache_path


def cmd_run(args) -> int:
    """CEGIS on the call tree. Resumes from the DB checkpoint."""
    from sqlalchemy.orm import sessionmaker

    from humpty.ingest import binary_sha256, load_call_graph
    from humpty.king.run import run_subtree

    os.makedirs(args.db_dir, exist_ok=True)
    db_path = os.path.join(args.db_dir, "bindumpty.db")
    factory, eng = _setup_db(db_path)
    sha = __import__("humpty.ingest", fromlist=["binary_sha256"]).binary_sha256(
        args.binary)
    cg = _graph_for(args.binary, args.backend, args.db_dir)

    with sessionmaker(bind=eng)() as s:
        load_call_graph(s, json_path=cg, binary=args.binary)
        s.commit()

    if args.llm:
        from humpty.men.develop import make_llm_source
        develop = make_llm_source()
    else:
        print("[develop] no --llm: the developer seam is the synthesizer. "
              "For a deterministic test, inject a develop callable. "
              "Refusing to fake a reconstruction.", file=sys.stderr)
        return 2

    print(f"[run] CEGIS on {args.binary} (sha {sha[:12]}…), "
          f"resume from {db_path}")
    with sessionmaker(bind=eng)() as s:
        rep = run_subtree(s, binary_sha256=sha, develop=develop,
                          binary_path=args.binary, cg_json_path=cg,
                          max_iter=args.max_iter,
                          fuzz_budget_s=args.fuzz_budget, log=print)

    ok = sum(1 for v in rep.verdicts.values()
             if v.state in ("trusted", "proven"))
    print(f"\n[run] {ok}/{len(rep.verdicts)} validated "
          f"({rep.verified_frac:.0%})")
    if rep.failed:
        print(f"  failed: {rep.failed}")
    print(f"  DB: {db_path} — re-run to resume, or `recompose` to build")
    eng.dispose()
    return 0


def cmd_recompose(args) -> int:
    """Compile the validated call tree into a working .so."""
    from humpty.king.recompose import recompose

    os.makedirs(args.db_dir, exist_ok=True)
    db_path = os.path.join(args.db_dir, "bindumpty.db")
    factory, eng = _setup_db(db_path)
    sha = __import__("humpty.ingest", fromlist=["binary_sha256"]).binary_sha256(
        args.binary)
    out = os.path.join(args.db_dir, "recomposed")
    with sessionmaker(bind=eng)() as s:
        r = recompose(s, binary=args.binary, out_dir=out)

    print(f"[recompose] {len(r.functions_validated)} validated, "
          f"{len(r.functions_stub)} stubbed (NFR-7)")
    if r.build_rc != 0:
        print(f"  build error: {r.build_stderr}")
        return 1
    print(f"  output: {r.output_so}")
    print(f"  project: {r.project_dir}")
    eng.dispose()
    return 0


def cmd_status(args) -> int:
    """Show the current checkpoint state."""
    db_path = os.path.join(args.db_dir, "bindumpty.db")
    if not os.path.exists(db_path):
        print(f"no checkpoint at {db_path}")
        return 0
    from sqlalchemy import create_engine, text
    eng = create_engine(f"sqlite:///{db_path}")
    with eng.connect() as c:
        rows = c.execute(text(
            "SELECT state, COUNT(*) FROM functions "
            "GROUP BY state ORDER BY state")).fetchall()
        total = sum(r[1] for r in rows)
    print(f"checkpoint: {db_path} ({total} functions)")
    for state, n in rows:
        print(f"  {state:12s} {n}")
    eng.dispose()
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="bindumpty")
    sub = ap.add_subparsers(dest="command")

    # run
    run_p = sub.add_parser("run", help="CEGIS on the call tree (checkpoint/resume)")
    run_p.add_argument("--binary", required=True)
    run_p.add_argument("--db-dir", default=".", help="checkpoint directory")
    run_p.add_argument("--backend", default="objdump",
                       choices=["objdump", "ghidra", "rizin"])
    run_p.add_argument("--llm", action="store_true")
    run_p.add_argument("--provider", default=None)
    run_p.add_argument("--model", default=None)
    run_p.add_argument("--api-base", default=None)
    run_p.add_argument("--max-iter", type=int, default=5)
    run_p.add_argument("--fuzz-budget", type=int, default=15)
    run_p.add_argument("--exclude", action="append", default=[])
    run_p.add_argument("--yes", action="store_true")

    # recompose
    rec_p = sub.add_parser("recompose", help="build .so from validated sources")
    rec_p.add_argument("--binary", required=True)
    rec_p.add_argument("--db-dir", default=".")

    # status
    st_p = sub.add_parser("status", help="show checkpoint state")
    st_p.add_argument("--db-dir", default=".")

    args = ap.parse_args(argv)
    if not args.command:
        ap.print_help()
        return 0
    return {"run": cmd_run, "recompose": cmd_recompose,
            "status": cmd_status}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
