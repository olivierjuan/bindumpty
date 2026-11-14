"""Integration: duplicate call-graph edges collapse on ingest (FR-1).

An exporter may emit the same (caller, callee, kind) edge once per call site;
``load_call_graph`` must treat the edge list as a set: the JSON can carry a
duplicated edge entry, but exactly one ``call_edges`` row and one ``Graph``
edge must come out of a single load. Graph-level idempotence across repeated
ingests into one database is not required (and not asserted here).
"""
import json
import os

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine

from humpty.db import CallEdge, Function, make_session_factory, session_scope
from humpty.ingest import load_call_graph

CASE = os.path.join("toys", "case-01-leaf")


def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def factory(tmp_path):
    """The M0 factory pattern: alembic upgrade head on a tmp sqlite."""
    root = _repo_root()
    db_url = f"sqlite:///{tmp_path}/dedup.db"
    ini = Config(os.path.join(root, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(root, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", db_url)
    eng = create_engine(db_url)
    command.upgrade(ini, "head")
    yield make_session_factory(eng)
    eng.dispose()


def test_duplicate_edges_collapse(factory, tmp_path):
    """A duplicated edge entry in the JSON collapses: 3 edges, not 4."""
    root = _repo_root()
    elf = os.path.join(root, CASE, "build", "toy01")
    cg = os.path.join(root, CASE, "ground_truth", "call_graph.json")
    for p in (elf, cg):
        if not os.path.exists(p):
            pytest.skip(f"toy artifact missing: {p} (run build.sh + record.sh)")

    data = json.loads(open(cg).read())
    assert len(data["edges"]) == 3
    # Append the same edge dict again: 4 entries in, 3 must come out.
    data["edges"].append(dict(data["edges"][0]))
    dup_json = tmp_path / "call_graph_dup.json"
    dup_json.write_text(json.dumps(data))
    assert len(data["edges"]) == 4

    with session_scope(factory) as s:
        g = load_call_graph(s, json_path=str(dup_json), binary=elf)

    # The in-memory graph collapsed the duplicate.
    assert len(g.edges) == 3
    # And the session holds exactly 3 CallEdge rows (not 4).
    with session_scope(factory) as s:
        assert s.query(CallEdge).count() == 3

    # Second ingest of the same duplicated file, same session factory: it must
    # collapse the duplicate just as deterministically. The tables are cleared
    # first because a load into a *populated* DB trips uq_functions_binary_name
    # (function rows, not edges) before any edge is written — graph-level
    # idempotence is explicitly not required; only per-load dedupe is.
    with session_scope(factory) as s:
        s.query(CallEdge).delete(synchronize_session=False)
        s.query(Function).delete(synchronize_session=False)

    with session_scope(factory) as s:
        g2 = load_call_graph(s, json_path=str(dup_json), binary=elf)
    assert len(g2.edges) == 3
    with session_scope(factory) as s:
        assert s.query(CallEdge).count() == 3
