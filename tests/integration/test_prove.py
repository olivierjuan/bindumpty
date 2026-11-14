"""Integration: FR-11 — the 'proven' state via bounded induction."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from humpty.analyze.prove import prove_fnv1a  # noqa: E402

GOOD = """#include <stdint.h>
#include <stddef.h>
uint32_t fnv1a(const uint8_t *data, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) { h ^= data[i]; h *= 16777619u; }
    return h;
}
"""

WRONG = GOOD.replace("h ^= data[i];", "h ^= data[i] ^ 1;")


def test_correct_candidate_is_proven():
    r = prove_fnv1a(GOOD)
    assert r.proven, f"failures: {r.failures[:3]}"
    assert r.checks >= 65537  # base + exhaustive 2-byte folds
    assert any("induction" in e for e in r.evidence)


def test_wrong_candidate_refuted():
    r = prove_fnv1a(WRONG)
    assert not r.proven
    assert r.failures and "2-byte fold differs" in r.failures[0]


def test_uncompilable_candidate_refuted():
    r = prove_fnv1a("uint32_t fnv1a(int) { return oops; }")
    assert not r.proven
