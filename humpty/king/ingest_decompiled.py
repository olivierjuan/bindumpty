"""humpty.king.ingest_decompiled — D2.3: ingest pre-existing decompiled .c files.

Matches each .c file to a functions DB row by symbol name (from the file's
first-line comment "// Function: <name>" convention or the filename stem).
Saves the source into functions.decompiled_code.

Usage:
  python -m humpty.king.ingest_decompiled --binary <elf> --source-dir <dir> --db-dir <dir>
"""
from __future__ import annotations

import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="bindumpty ingest-decompiled")
    ap.add_argument("--binary", required=True, help="the target ELF")
    ap.add_argument("--source-dir", required=True,
                    help="directory containing decompiled .c files")
    ap.add_argument("--db-dir", required=True, help="bindumpty checkpoint dir")
    ap.add_argument("--pattern", default="*.c", help="glob for source files")
    args = ap.parse_args(argv)

    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine

    from humpty.db import make_session_factory
    from humpty.db.models import Function
    from humpty.db.session import session_scope
    from humpty.ingest import binary_sha256, load_call_graph

    db_path = os.path.join(args.db_dir, "bindumpty.db")
    eng = create_engine(f"sqlite:///{db_path}")
    ini = Config(os.path.join(ROOT, "alembic.ini"))
    ini.set_main_option("script_location",
                        os.path.join(ROOT, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    command.upgrade(ini, "head")
    factory = make_session_factory(eng)

    sha = binary_sha256(args.binary)

    # ensure the call graph is loaded
    cg = os.path.join(ROOT, CASE_DIR := os.path.join(
        "toys", "case-01-leaf"), "ground_truth", "call_graph.json")
    if os.path.exists(cg):
        with session_scope(factory) as s:
            load_call_graph(s, json_path=cg, binary=args.binary)

    # glob the source dir
    import glob
    files = sorted(glob.glob(os.path.join(args.source_dir, args.pattern)))
    if not files:
        print(f"no files matching {args.pattern} in {args.source_dir}")
        return 0

    matched, unmatched = 0, 0
    with session_scope(factory) as s:
        for path in files:
            text = open(path).read()
            # symbol name: first-line comment "// Function: <name>" or filename stem
            fname = os.path.basename(path)
            m = re.match(r"^\s*//\s*Function:\s*(\S+)", text)
            sym_name = m.group(1) if m else os.path.splitext(fname)[0]
            fn = s.query(Function).filter_by(
                binary_sha256=sha, name=sym_name).one_or_none()
            if fn is None:
                unmatched += 1
                continue
            fn.decompiled_code = text
            matched += 1
            print(f"  {sym_name}: {len(text)} bytes from {fname}")

    print(f"\ningested: {matched} matched, {unmatched} unmatched "
          f"(no matching function row)")
    eng.dispose()
    return 0


import re  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
