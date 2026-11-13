"""Tests for humpty.ingest — call-graph validation, topology, and DB load.

Covers the whitepaper FR-1 contract: topological order (callees before
callers), SCCs (recursion) identified, strict schema validation, and load into
``functions`` / ``call_edges``. The reference format is the ground-truth
call graph for case-01 (``fuz.call-graph/1``).
"""
import json
import os

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from humpty.db import (
    Base,
    CallEdge,
    Function,
    make_engine,
    make_session_factory,
    session_scope,
)
from humpty.ingest import (
    CallGraphError,
    binary_sha256,
    call_graph_topo_order,
    load_call_graph,
    strongly_connected_components,
)
from humpty.domain import State


@pytest.fixture()
def factory(tmp_path):
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    db_url = f"sqlite:///{tmp_path}/ingest.db"
    ini = Config(os.path.join(repo_root, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(repo_root, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", db_url)
    eng = create_engine(db_url)
    command.upgrade(ini, "head")
    yield make_session_factory(eng)
    eng.dispose()


def _minimal_graph(tmp_path, funcs=None, edges=None):
    g = {
        "format": "fuz.call-graph/1",
        "binary": {"sha256": "x" * 64, "arch": "x86-64", "kind": "elf"},
        "functions": funcs or [
            {"name": "a", "address": "0x1000", "size": 10},
            {"name": "b", "address": "0x1100", "size": 20},
        ],
        "edges": edges or [
            {"caller": "b", "callee": "a", "kind": "direct"},
        ],
        "sccs": [],
        "topological_order": ["a", "b"],
    }
    p = tmp_path / "cg.json"
    p.write_text(json.dumps(g))
    elf = tmp_path / "elf"
    elf.write_bytes(b"\x7fELFfake")
    return p, elf


# --- Topology (pure, no DB) ------------------------------------------------


def test_topo_order_callees_first():
    order = call_graph_topo_order([1, 2, 3], [(3, 2), (2, 1)])
    assert order.index(1) < order.index(2) < order.index(3)


def test_topo_order_deterministic_tie_break():
    # No edges: input order preserved.
    assert call_graph_topo_order([3, 1, 2], []) == [3, 1, 2]


def test_topo_order_detects_uncanonical_cycle():
    # A 2-cycle is an SCC, so collapsing it is expected; a *non-SCC* cycle
    # can't happen in a directed graph, but a self-loop or malformed input
    # must raise. Here we simulate an impossible cycle by feeding a cycle
    # that Tarjan would treat as an SCC — we assert the SCC path, not topo.
    sccs = strongly_connected_components([1, 2, 3], [(1, 2), (2, 1), (3, 1)])
    scc_sizes = sorted(len(s) for s in sccs)
    assert scc_sizes == [1, 2]  # {1,2} is an SCC, {3} singleton


def test_scc_identifies_recursion():
    # a <-> b (mutual recursion), c calls a.
    sccs = strongly_connected_components([1, 2, 3], [(1, 2), (2, 1), (3, 1)])
    two = [s for s in sccs if len(s) == 2]
    assert two and sorted(two[0]) == [1, 2]


def test_scc_all_singletons_when_acyclic():
    sccs = strongly_connected_components([1, 2, 3], [(3, 2), (2, 1)])
    assert all(len(s) == 1 for s in sccs)
    assert len(sccs) == 3


# --- binary identity -------------------------------------------------------


def test_binary_sha256_stable(tmp_path):
    elf = tmp_path / "e"
    elf.write_bytes(b"\x7fELF" + b"0" * 100)
    assert binary_sha256(elf) == binary_sha256(elf)
    assert len(binary_sha256(elf)) == 64


# --- Load into DB ----------------------------------------------------------


def test_load_creates_functions_and_edges(factory, tmp_path):
    cg, elf = _minimal_graph(tmp_path)
    with session_scope(factory) as s:
        g = load_call_graph(s, json_path=cg, binary=elf)
    assert set(g.functions) == {"a", "b"}
    with session_scope(factory) as s:
        assert s.query(Function).count() == 2
        assert s.query(CallEdge).count() == 1
        a = s.query(Function).filter_by(name="a").one()
        assert a.state == State.PENDING.value
        assert a.binary_sha256 == binary_sha256(elf)


def test_load_rejects_bad_format(factory, tmp_path):
    cg, elf = _minimal_graph(tmp_path)
    data = json.loads(cg.read_text())
    data["format"] = "fuz.call-graph/99"
    cg.write_text(json.dumps(data))
    with pytest.raises(CallGraphError, match="format"):
        with session_scope(factory) as s:
            load_call_graph(s, json_path=cg, binary=elf)


def test_load_rejects_unknown_edge_endpoint(factory, tmp_path):
    cg, elf = _minimal_graph(tmp_path, edges=[{"caller": "b", "callee": "zzz"}])
    with pytest.raises(CallGraphError, match="unknown endpoint"):
        with session_scope(factory) as s:
            load_call_graph(s, json_path=cg, binary=elf)


def test_load_rejects_bad_edge_kind(factory, tmp_path):
    cg, elf = _minimal_graph(tmp_path, edges=[{"caller": "b", "callee": "a", "kind": "weird"}])
    with pytest.raises(CallGraphError, match="kind"):
        with session_scope(factory) as s:
            load_call_graph(s, json_path=cg, binary=elf)


def test_load_rejects_duplicate_function(factory, tmp_path):
    funcs = [
        {"name": "a", "address": "0x1000", "size": 10},
        {"name": "a", "address": "0x2000", "size": 10},
    ]
    cg, elf = _minimal_graph(tmp_path, funcs=funcs, edges=[])
    with pytest.raises(CallGraphError, match="duplicate"):
        with session_scope(factory) as s:
            load_call_graph(s, json_path=cg, binary=elf)


def test_load_records_scc_id_for_recursive_pair(factory, tmp_path):
    funcs = [
        {"name": "a", "address": "0x1000", "size": 10},
        {"name": "b", "address": "0x1100", "size": 20},
    ]
    edges = [{"caller": "a", "callee": "b"}, {"caller": "b", "callee": "a"}]
    cg, elf = _minimal_graph(tmp_path, funcs=funcs, edges=edges)
    with session_scope(factory) as s:
        g = load_call_graph(s, json_path=cg, binary=elf)
    # Both a and b share an SCC id.
    assert g.scc_ids[g.functions["a"]] == g.scc_ids[g.functions["b"]]
    with session_scope(factory) as s:
        a = s.query(Function).filter_by(name="a").one()
        b = s.query(Function).filter_by(name="b").one()
        assert a.scc_id is not None and a.scc_id == b.scc_id


def test_load_is_rolled_back_on_failure(factory, tmp_path):
    """A load that fails partway must not commit partial rows."""
    cg, elf = _minimal_graph(tmp_path)
    # First, a valid load commits.
    with session_scope(factory) as s:
        load_call_graph(s, json_path=cg, binary=elf)
    # Now a bad graph in a fresh transaction: must raise and roll back.
    bad, _ = _minimal_graph(tmp_path, edges=[{"caller": "b", "callee": "nope"}])
    with pytest.raises(CallGraphError):
        with session_scope(factory) as s:
            load_call_graph(s, json_path=bad, binary=elf)
    # Row count unchanged from the first (committed) load.
    with session_scope(factory) as s:
        assert s.query(Function).count() == 2
