"""Integration: FR-10 LLM-vs-LLM pre-filter over graveyard candidates."""
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
from humpty.king.graveyard import archive_candidate
from humpty.men.llm_oracle import cross_fuzz

CASE = os.path.join("toys", "case-01-leaf")

# two archived candidates: one correct, one wrong on len==0 (returns basis+1)
GOOD = """#include <stdint.h>
#include <stddef.h>
uint32_t fnv1a(const uint8_t *d, size_t l) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < l; i++) { h ^= d[i]; h *= 16777619u; }
    return h;
}
"""
WRONG_EMPTY = """#include <stdint.h>
#include <stddef.h>
uint32_t fnv1a(const uint8_t *d, size_t l) {
    if (l == 0) return 2166136262u; /* off-by-one on empty */
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < l; i++) { h ^= d[i]; h *= 16777619u; }
    return h;
}
"""


@pytest.fixture()
def env(tmp_path):
    db = f"sqlite:///{tmp_path}/oracle.db"
    ini = Config(os.path.join(ROOT, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(ROOT, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", db)
    eng = create_engine(db)
    command.upgrade(ini, "head")
    fac = make_session_factory(eng)
    elf = os.path.join(ROOT, CASE, "build", "toy01")
    cg = os.path.join(ROOT, CASE, "ground_truth", "call_graph.json")
    if not os.path.exists(elf):
        pytest.skip("toy01 not built")
    with session_scope(fac) as s:
        load_call_graph(s, json_path=cg, binary=elf)
        fid = s.query(Function).filter_by(name="fnv1a").one().id
    return fac, fid


def test_cross_fuzz_finds_divergence(env):
    fac, fid = env
    with session_scope(fac) as s:
        for src in (GOOD, WRONG_EMPTY):
            from humpty.men.fixer import normalize_source
            c = Candidate(function_id=fid, source_code=src, created_by="dev",
                          status="rejected", source_hash=normalize_source(src))
            s.add(c)
            s.flush()
            archive_candidate(s, candidate_id=c.id)
        rep = cross_fuzz(s, function_id=fid, n_inputs=200)
        assert rep.pairs_compared == 200
        # the empty input (and any input where they differ) diverges
        assert rep.divergent_inputs >= 1
        assert rep.test_cases, "expected at least one test case"
        # every reported case must have per-candidate results
        hexin, results = rep.test_cases[0]
        assert len(results) == 2


def test_cross_fuzz_needs_two_candidates(env):
    fac, fid = env
    with session_scope(fac) as s:
        rep = cross_fuzz(s, function_id=fid)
        assert rep.pairs_compared == 0 and rep.test_cases == []
