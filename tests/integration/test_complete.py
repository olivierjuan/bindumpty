"""Integration: FR-1 ext — trace-completed edges + SCC policy."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine

from humpty.analyze.complete import apply_scc_policy, complete_from_traces
from humpty.db import make_session_factory
from humpty.db.models import CallEdge, Event, Function
from humpty.db.session import session_scope
from humpty.ingest import load_call_graph

CASE = os.path.join("toys", "case-01-leaf")


@pytest.fixture()
def factory(tmp_path):
    db = f"sqlite:///{tmp_path}/complete.db"
    ini = Config(os.path.join(ROOT, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(ROOT, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", db)
    eng = create_engine(db)
    command.upgrade(ini, "head")
    yield make_session_factory(eng)
    eng.dispose()


@pytest.fixture()
def ingested(factory):
    elf = os.path.join(ROOT, CASE, "build", "toy01")
    cg = os.path.join(ROOT, CASE, "ground_truth", "call_graph.json")
    if not os.path.exists(elf):
        pytest.skip("toy01 not built")
    with session_scope(factory) as s:
        load_call_graph(s, json_path=cg, binary=elf)
        sha = os.popen(f"sha256sum {elf}").read().split()[0]
    return sha


def _addr_of(factory, sha, name):
    with session_scope(factory) as s:
        return s.query(Function).filter_by(
            binary_sha256=sha, name=name).one().address


def test_trace_completes_missing_edge(factory, ingested):
    """A runtime-observed call absent from the static graph is added."""
    sha = ingested
    main_a = _addr_of(factory, sha, "main")
    fnv_a = _addr_of(factory, sha, "fnv1a")
    with session_scope(factory) as s:
        n = complete_from_traces(s, binary_sha256=sha,
                                 observed_calls=[(main_a, fnv_a)])
        assert n == 1
        main_id = s.query(Function).filter_by(binary_sha256=sha, name="main").one().id
        fnv_id = s.query(Function).filter_by(binary_sha256=sha, name="fnv1a").one().id
        edge = s.query(CallEdge).filter_by(caller_id=main_id,
                                           callee_id=fnv_id).one_or_none()
        assert edge is not None and edge.kind == "direct"
        kinds = [e.kind for e in s.query(Event).all()]
        assert "edge_added_from_trace" in kinds


def test_trace_promotes_indirect(factory, ingested):
    """An existing indirect edge between two functions is promoted to direct
    by runtime evidence."""
    sha = ingested
    main_a = _addr_of(factory, sha, "main")
    fnv_a = _addr_of(factory, sha, "fnv1a")
    with session_scope(factory) as s:
        main_id = s.query(Function).filter_by(binary_sha256=sha, name="main").one().id
        fnv_id = s.query(Function).filter_by(binary_sha256=sha, name="fnv1a").one().id
        s.add(CallEdge(caller_id=main_id, callee_id=fnv_id, kind="indirect"))
        s.flush()
        n = complete_from_traces(s, binary_sha256=sha,
                                 observed_calls=[(main_a, fnv_a)])
        assert n == 1  # promoted, not added
        kinds = [e.kind for e in s.query(Event).all()]
        assert "edge_promoted_from_trace" in kinds


def test_scc_policy_indivisible_keeps_groups(factory, ingested):
    sha = ingested
    with session_scope(factory) as s:
        plan = apply_scc_policy(s, binary_sha256=sha, policy="indivisible")
        # the toy is acyclic: no indivisible groups, and the order is the
        # leaf-first topological order
        assert plan.indivisible == []
        names = [s.get(Function, i).name for i in plan.order]
        assert names.index("fnv1a") < names.index("checksum_block")
        assert names.index("digit_sum_u32") < names.index("checksum_block")


def test_scc_policy_unroll_gives_second_pass(factory, ingested):
    sha = ingested
    with session_scope(factory) as s:
        plan = apply_scc_policy(s, binary_sha256=sha, policy="unroll")
        # the toy is acyclic (no SCC members), so unroll adds no second pass
        assert plan.indivisible == []
        assert len(plan.order) == 4  # same as indivisible for an acyclic graph
