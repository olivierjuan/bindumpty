"""bindumpty dr-record — DynamoRIO record mode (RFC §8 seam).

python -m humpty.king.dr_record ./lpex2 --target-offset 0x8aba20 \
    [--arg model.mps] [--out-dir <project>/runs/dr-<ts>] [--edges]

Runs the target under DynamoRIO (two passes when both artifacts are
requested — see humpty.analyze.dynamorio.dr_record), ingests the
artifacts:
  a) snapshots  -> fuz.snapshot/2 files (differential replay oracle)
  b) structs.json -> a generated C header saved into the project tree
     (types pipeline, --types-dir compatible)
  c) indirect_edges.json -> call_edges table (indirect_resolved)
and prints a summary.
"""
from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="bindumpty dr-record")
    ap.add_argument("binary", help="target binary to run under DynamoRIO")
    ap.add_argument("--target-offset", type=lambda x: int(x, 0), required=True,
                    help="offset of the function to instrument (0x...)")
    ap.add_argument("--arg", action="append", default=[],
                    help="argument passed to the binary (repeatable)")
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--edges", action="store_true",
                    help="also run the indirect-edge pass")
    ap.add_argument("--no-snapshots", action="store_true",
                    help="skip the snapshot pass")
    args = ap.parse_args(argv)

    from humpty.analyze.dynamorio import (
        dr_record, load_snapshots, load_indirect_edges, structs_to_header)
    record_structs = not args.no_snapshots
    res = dr_record(args.binary, args.target_offset, args.arg,
                    out_dir=args.out_dir,
                    record_structs=record_structs,
                    record_vtables=args.edges)
    print(f"dr-record: out={res.out_dir} rc={res.exit_code} "
          f"{res.duration_s:.1f}s snapshots={len(res.snapshots)}")

    if res.exit_code != 0:
        print(res.stderr_tail, file=sys.stderr)
        return 1

    snaps = load_snapshots(res.snapshots)
    for s in snaps:
        print(f"  snapshot tid={s['thread']} inv={s['invocation']} "
              f"rax={s['return_rax']:#x} reads={len(s['reads'])} "
              f"writes={len(s['writes'])}")

    structs_path = res.out_dir / "structs.json"
    if structs_path.exists():
        from humpty.project import results_dir
        header = structs_to_header(
            json.loads(structs_path.read_text()),
            results_dir() / "structs_generated.h")
        print(f"  struct header: {header}")

    edges_path = res.out_dir / "indirect_edges.json"
    if edges_path.exists():
        edges = load_indirect_edges(edges_path)
        print(f"  indirect edges: {len(edges)}")
        if edges:
            from humpty.db import make_session_factory
            from humpty.db.session import session_scope
            from humpty.analyze.dynamorio import ingest_indirect_edges
            from humpty.ingest import binary_sha256
            from sqlalchemy import create_engine
            from alembic import command
            from alembic.config import Config
            from humpty.config import Config as HumptyConfig
            db_dir = res.out_dir
            eng = create_engine(f"sqlite:///{db_dir}/edges.db")
            ini = Config(str(__import__('pathlib').Path(__file__)
                             .resolve().parents[2] / "alembic.ini"))
            ini.set_main_option("script_location",
                                str(__import__('pathlib').Path(__file__)
                                    .resolve().parents[2] / "humpty/db/alembic"))
            ini.set_main_option("sqlalchemy.url", f"sqlite:///{db_dir}/edges.db")
            command.upgrade(ini, "head")
            factory = make_session_factory(eng)
            sha = binary_sha256(args.binary)
            with session_scope(factory) as s:
                ingest_indirect_edges(s, binary_sha256=sha, edges=edges,
                                      log=print)
            eng.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(main())
