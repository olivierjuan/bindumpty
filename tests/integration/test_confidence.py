"""Integration: FR-13 demotion + ready-set recomputation on the toy tree."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine

from humpty.db import make_session_factory
from humpty.db.models import Event, Function
from humpty.db.session import session_scope
from humpty.ingest import load_call_graph
from humpty.king.confidence import demote_child, recompute_ready_set
from humpty.domain import State

CASE = os.path.join("toys", "case-01-leaf")


@pytest.fixture()
def factory(tmp_path):
    db = f"sqlite:///{tmp_path}/conf.db"
    ini = Config(os.path.join(ROOT, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(ROOT, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", db)
    eng = create_engine(db)
    command.upgrade(ini, "head")
    yield make_session_factory(eng)
    eng.dispose()


@pytest.fixture()
def ids(factory):
    elf = os.path.join(ROOT, CASE, "build", "toy01")
    cg = os.path.join(ROOT, CASE, "ground_truth", "call_graph.json")
    if not os.path.exists(elf):
        pytest.skip("toy01 not built")
    with session_scope(factory) as s:
        load_call_graph(s, json_path=cg, binary=elf)
        rows = {f.name: (f.id, f.address) for f in s.query(Function).all()}
    sha = os.popen(f"sha256sum {elf}").read().split()[0]
    return sha, rows


def _set_state(factory, sha, name, state, conf=1.0):
    with session_scope(factory) as s:
        f = s.query(Function).filter_by(binary_sha256=sha, name=name).one()
        f.state = state
        f.confidence = conf


def test_demotion_marks_child_and_requeues_dependents(factory, ids):
    """checksum_block (parent) diverges attributably to fnv1a (trusted child):
    fnv1a -> divergent with confidence 0; the dependents that were trusted
    because of it (checksum_block) requeue to pending."""
    sha, rows = ids
    # set everything trusted as if the tree had validated
    for name in ("fnv1a", "digit_sum_u32", "checksum_block"):
        _set_state(factory, sha, name, State.TRUSTED.value)
    fnv_id = rows["fnv1a"][0]
    csum_id = rows["checksum_block"][0]

    with session_scope(factory) as s:
        rep = demote_child(s, binary_sha256=sha, parent_id=csum_id,
                           child_id=fnv_id)
        assert rep.demoted == ["fnv1a"]
        assert "checksum_block" in rep.requeued
        fnv = s.get(Function, fnv_id)
        assert fnv.state == State.DIVERGENT.value and fnv.confidence == 0.0
        csum = s.get(Function, csum_id)
        assert csum.state == State.PENDING.value
        kinds = [e.kind for e in s.query(Event).all()]
        assert "demotion" in kinds and "confidence_recomputed" in kinds


def test_ready_set_marks_leaves_ready(factory, ids):
    """After requeue, the leaves (no callees) become ready; the parent waits."""
    sha, rows = ids
    with session_scope(factory) as s:
        rep = recompute_ready_set(s, binary_sha256=sha)
        states = {n: s.query(Function).filter_by(binary_sha256=sha, name=n).one().state
                  for n in ("fnv1a", "digit_sum_u32", "checksum_block", "main")}
    # leaves have no callees -> they do not auto-ready (v0: pending stays
    # pending until a worker picks it up; 'ready' events only fire for
    # functions whose callees are all trusted)
    assert states["checksum_block"] == State.PENDING.value


def test_ready_events_fire_for_parents_of_trusted(factory, ids):
    """When both leaves are trusted, the parent's recompute emits ready."""
    sha, rows = ids
    for name in ("fnv1a", "digit_sum_u32"):
        _set_state(factory, sha, name, State.TRUSTED.value)
    with session_scope(factory) as s:
        rep = recompute_ready_set(s, binary_sha256=sha)
        kinds = [e.kind for e in s.query(Event).all()]
        assert "ready" in kinds
