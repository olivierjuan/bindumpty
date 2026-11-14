"""Integration: FR-18 graveyard — archive, Pareto rank, retention, seeding."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine

from humpty.db import make_session_factory
from humpty.db.models import Candidate, Counterexample, Event, Function, Graveyard
from humpty.db.session import session_scope
from humpty.ingest import load_call_graph
from humpty.king.graveyard import archive_candidate, pareto_front, seed_for

CASE = os.path.join("toys", "case-01-leaf")


@pytest.fixture()
def factory(tmp_path):
    db = f"sqlite:///{tmp_path}/grave.db"
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
        fid = s.query(Function).filter_by(name="fnv1a").one().id
    return fid


def _add_candidate(session, fid, src, status="rejected"):
    from humpty.men.fixer import normalize_source
    c = Candidate(function_id=fid, source_code=src, created_by="dev",
                  status=status, source_hash=normalize_source(src))
    session.add(c)
    session.flush()
    return c


GOOD = "uint32_t fnv1a(const uint8_t*d,size_t l){uint32_t h=2166136261u;for(size_t i=0;i<l;i++){h^=d[i];h*=16777619u;}return h;}"
NEAR_MISS = GOOD + " /* v2: near miss, slightly longer */"


def test_pareto_front_basics():
    # all-axes vectors (the real shape): {a:2} dominates {a:1}; {a:3,b:0}
    # trades a for b — non-dominated against {a:2}.
    entries = [{"a": 2, "b": 1}, {"a": 1, "b": 1}, {"a": 3, "b": 0}]
    front = pareto_front(entries)
    assert set(front) == {0, 2}


def test_archive_rejected_candidate(factory, ingested):
    fid = ingested
    with session_scope(factory) as s:
        c = _add_candidate(s, fid, GOOD)
        gid = archive_candidate(s, candidate_id=c.id)
        assert gid is not None
        row = s.get(Graveyard, gid)
        assert row.pareto_rank >= 1
        kinds = [e.kind for e in s.query(Event).all()]
        assert "graveyard_archived" in kinds


def test_archive_skips_non_rejected(factory, ingested):
    fid = ingested
    with session_scope(factory) as s:
        c = _add_candidate(s, fid, GOOD, status="verified")
        assert archive_candidate(s, candidate_id=c.id) is None


def test_seed_returns_best_rank1(factory, ingested):
    fid = ingested
    with session_scope(factory) as s:
        c1 = _add_candidate(s, fid, GOOD)
        archive_candidate(s, candidate_id=c1.id)
        best = seed_for(s, function_id=fid)
        assert best is not None and best.id == c1.id


def test_retention_caps_per_function(factory, ingested):
    fid = ingested
    with session_scope(factory) as s:
        for i in range(40):
            c = _add_candidate(s, fid, GOOD + f" /* v{i} */")
            archive_candidate(s, candidate_id=c.id, max_per_function=32)
        n = s.query(Graveyard).filter_by(function_id=fid).count()
        assert n <= 32
