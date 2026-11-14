"""Unit tests: M1 differential harness driver (horses/src/harness_driver.py).

These exercise the REAL harness binary (libFuzzer + the real original fnv1a)
on the real candidate .so, with a short budget. Deterministic (NFR-2): the
seed candidate's bug fires at len==255 exactly.
"""
import os
import sys

import pytest

HORSES_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "horses", "src")
sys.path.insert(0, HORSES_SRC)

import cegis  # noqa: E402  (counterexample persistence lives there)
import harness_driver as hd  # noqa: E402

pytestmark = pytest.mark.skipif(
    not os.path.exists(hd.HARNESS),
    reason="harness not built (run horses/src/build_horse.sh)")


def test_counterexample_persistence_dedups():
    """FR-15: the same divergent input is stored once (idempotent)."""
    data = b"\x42" * 255
    try:
        cegis.persist_counterexample(data)  # ensure absent first
        p = cegis.ce_path(data)
        if os.path.exists(p):
            os.remove(p)
        first = cegis.persist_counterexample(data)
        second = cegis.persist_counterexample(data)
        assert first is True and second is False  # deduplicated
    finally:
        p = cegis.ce_path(data)
        if os.path.exists(p):
            os.remove(p)


@pytest.fixture()
def buggy_candidate():
    """The seed (deliberately wrong) candidate .so, restored after the test."""
    with open(hd.CAND_SRC) as f:
        orig_src = f.read()
    buggy = orig_src.replace(
        "    for (size_t i = 0; i < len; i++) {\n        hash ^= (uint32_t)data[i];",
        "    if (len == 0xFF) hash = 0x12345678u;\n"
        "    for (size_t i = 0; i < len; i++) {\n        hash ^= (uint32_t)data[i];")
    hd.write_candidate(buggy)
    yield buggy
    hd.write_candidate(orig_src)  # restore whatever was checked in


def test_fuzz_finds_seed_divergence(buggy_candidate):
    """The libFuzzer harness finds the len==255 counterexample."""
    r = hd.run_fuzz(budget_s=10)
    assert r.divergent
    assert r.counterexamples, "expected a parsed counterexample"
    ce = r.counterexamples[0]
    assert len(ce.as_input()) == 255, f"bug fires only at len 255, got {len(ce.as_input())}"
    assert ce.got != ce.want


def test_replay_is_deterministic(buggy_candidate):
    """Replaying a known-divergent input reproduces the same result (NFR-2)."""
    data = b"\x41" * 255
    divs = hd.run_replay([data])
    assert divs, "len=255 input must diverge on the buggy candidate"
    again = hd.run_replay([data])
    assert divs[0].got == again[0].got and divs[0].want == again[0].want
