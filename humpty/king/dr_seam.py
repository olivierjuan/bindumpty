"""humpty.king.dr_seam — Directive 2: automatic DynamoRIO pass before develop.

When a leaf with pointer/struct arguments is about to enter the develop
stage and DynamoRIO is installed:
  1. run dr_record against a quick test run of the target (edge pass +
     snapshot pass),
  2. ingest discovered indirect_resolved edges into call_edges,
  3. generate the inferred struct header into
     <project>/results/structs_<fn>.h for the --types-dir pipeline.

Every step degrades gracefully: no DynamoRIO, no built client, or a
failing run leaves the loop untouched (the prompt just omits the
enrichment).
"""
from __future__ import annotations

import json
from pathlib import Path

from humpty.analyze.dynamorio import (
    dr_record, load_snapshots, load_indirect_edges, structs_to_header,
    snapshots_to_replay_pages)
from humpty.project import results_dir


def _dr_ready() -> bool:
    try:
        dr_home = None
        from humpty.analyze.dynamorio import dr_home as _dh
        dr_home = _dh()
        client_path = None
        from humpty.analyze.dynamorio import client_path as _cp
        client_path = _cp()
        return True
    except Exception:  # noqa: BLE001 — absence is a normal state
        return False


def enrich_leaf(session, fn, *, binary: str, binary_sha256: str,
                sample_argv: list[str] | None = None,
                log=print) -> dict:
    """Run the DR pass for one leaf and ingest everything.

    Returns a summary dict:
      {edges_ingested, struct_header, snapshots} — empty strings/zeroes
      when the pass was skipped or failed.
    """
    out = {"edges_ingested": 0, "struct_header": "", "snapshots": 0}
    if not _dr_ready():
        return out
    if fn.size is None or fn.size <= 0:
        return out

    try:
        res = dr_record(binary, fn.address, sample_argv or [],
                        record_structs=True, record_vtables=True,
                        target_size=fn.size)
    except Exception as e:  # noqa: BLE001
        log(f"  {fn.name}: DR pass failed: {e}")
        return out
    if res.exit_code != 0:
        log(f"  {fn.name}: DR pass rc={res.exit_code} — skipped")
        return out

    # a) indirect edges -> call_edges
    edges_path = res.out_dir / "indirect_edges.json"
    if edges_path.exists():
        edges = load_indirect_edges(edges_path)
        from humpty.analyze.dynamorio import ingest_indirect_edges
        out["edges_ingested"] = ingest_indirect_edges(
            session, binary_sha256=binary_sha256, edges=edges, log=log)

    # b) struct header -> project results (types pipeline)
    structs_path = res.out_dir / "structs.json"
    if structs_path.exists():
        structs = json.loads(structs_path.read_text())
        if structs:
            header = structs_to_header(
                structs, results_dir() / f"structs_{fn.name}.h")
            out["struct_header"] = str(header)
            log(f"  {fn.name}: struct header -> {header}")

    # c) snapshots -> count (the replay oracle consumes them by path)
    snaps = load_snapshots(res.snapshots) if res.snapshots else []
    out["snapshots"] = len(snaps)
    if out["snapshots"]:
        log(f"  {fn.name}: {out['snapshots']} DR snapshots captured")
    return out
