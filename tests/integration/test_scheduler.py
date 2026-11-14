"""Integration: M4 information-gain scheduler on the toy tree."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine

from humpty.db import make_session_factory
from humpty.db.models import Candidate, Function
from humpty.db.session import session_scope
from humpty.ingest import load_call_graph
from humpty.king.scheduler import expected_gain, rank_ready

CASE = os.path.join("toys", "case-01-leaf")


@pytest.fixture()
def factory(tmp_path):
    db = f"sqlite:///{tmp_path}/sched.db"
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
        ids = {f.name: f.id for f in s.query(Function).all()}
    return ids


def _add_candidate(session, fid, status):
    session.add(Candidate(function_id=fid, source_code=f"src-{status}",
                          created_by="dev", status=status))
    session.flush()


def test_rank_orders_by_gain(factory, ingested):
    """A function with a successful history outranks one that burned
    attempts, even when dependent counts are equal."""
    ids = ingested
    with session_scope(factory) as s:
        # fnv1a: two trusted candidates (good history)
        _add_candidate(s, ids["fnv1a"], "trusted")
        _add_candidate(s, ids["fnv1a"], "trusted")
        # digit_sum: three rejected (bad history)
        for _ in range(3):
            _add_candidate(s, ids["digit_sum_u32"], "rejected")
    with session_scope(factory) as s:
        ranked = rank_ready(s, binary_sha256=s.query(Function)
                            .filter_by(name="fnv1a").one().binary_sha256)
        names = [r.name for r in ranked]
        assert names[0] == "fnv1a"  # success history wins


def test_dependents_boost(factory, ingested):
    """Between two functions with identical (empty) history, the one with
    more dependents ranks first."""
    ids = ingested
    with session_scope(factory) as s:
        s.query(Function).filter_by(name="checksum_block").one().dependents_count = 5
        s.query(Function).filter_by(name="fnv1a").one().dependents_count = 1
        s.flush()
        ranked = rank_ready(s, binary_sha256=s.query(Function)
                            .filter_by(name="fnv1a").one().binary_sha256)
        assert ranked[0].name == "checksum_block"
