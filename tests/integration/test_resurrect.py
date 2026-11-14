"""Integration: FR-18 ext — graveyard crossover + resurrection."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine

from humpty.db import make_session_factory
from humpty.db.models import Candidate, Event, Function, Graveyard
from humpty.db.session import session_scope
from humpty.ingest import load_call_graph
from humpty.king.graveyard import archive_candidate
from humpty.king.resurrect import crossover, resurrect

CASE = os.path.join("toys", "case-01-leaf")

SRC_A = """#include <stdint.h>
uint32_t fnv1a(const uint8_t *d, size_t l) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < l; i++) { h ^= d[i]; h *= 16777619u; }
    return h;
}
"""
SRC_B = """#include <stdint.h>
uint32_t fnv1a(const uint8_t *d, size_t l) {
    /* variant with an early guard */
    if (d == 0 && l > 0) { return 0; }
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < l; i++) { h ^= d[i]; h *= 16777619u; }
    return h;
}
"""


@pytest.fixture()
def factory(tmp_path):
    db = f"sqlite:///{tmp_path}/res.db"
    ini = Config(os.path.join(ROOT, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(ROOT, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", db)
    eng = create_engine(db)
    command.upgrade(ini, "head")
    yield make_session_factory(eng)
    eng.dispose()


@pytest.fixture()
def failed_fn(factory):
    elf = os.path.join(ROOT, CASE, "build", "toy01")
    cg = os.path.join(ROOT, CASE, "ground_truth", "call_graph.json")
    if not os.path.exists(elf):
        pytest.skip("toy01 not built")
    with session_scope(factory) as s:
        load_call_graph(s, json_path=cg, binary=elf)
        fn = s.query(Function).filter_by(name="fnv1a").one()
        fid = fn.id
        fn.state = "failed"
        # archive two candidates
        from humpty.men.fixer import normalize_source
        for src in (SRC_A, SRC_B):
            c = Candidate(function_id=fid, source_code=src, created_by="dev",
                          status="rejected", source_hash=normalize_source(src))
            s.add(c)
            s.flush()
            archive_candidate(s, candidate_id=c.id)
    return fid


def test_crossover_merges_code_lines():
    out = crossover(None, function_id=0, src_a=SRC_A, src_b=SRC_B)
    assert "#include <stdint.h>" in out  # includes from A
    assert out.count("uint32_t fnv1a") == 1  # deduplicated
    assert "early guard" in out  # B's new lines present


def test_resurrect_requeues_with_seed(factory, failed_fn):
    fid = failed_fn
    with session_scope(factory) as s:
        rep = resurrect(s, function_id=fid, reason="callee fixed")
        assert rep.requeued
        assert rep.seeded_from_candidate is not None
        fn = s.get(Function, fid)
        assert fn.state == "pending"
        kinds = [e.kind for e in s.query(Event).all()]
        assert "resurrection" in kinds
        g = s.query(Graveyard).filter_by(candidate_id=rep.seeded_from_candidate).one()
        assert g.resurrected_count == 1
        # the seeded candidate is materialized as a live pending candidate
        live = (s.query(Candidate)
                .filter_by(function_id=fid, status="pending").all())
        assert live


def test_resurrect_noop_when_not_failed(factory, failed_fn):
    fid = failed_fn
    with session_scope(factory) as s:
        s.get(Function, fid).state = "trusted"
        s.flush()
        rep = resurrect(s, function_id=fid, reason="callee fixed")
        assert not rep.requeued and rep.notes
