"""Unit: graveyard Pareto weights are configurable (the M3 open decision)."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from humpty.king.graveyard import _dominates, _score_vector  # noqa: E402


def test_weights_reweight_axes():
    raw_long = "x" * 2000  # simplicity penalty
    base = _score_vector(None, function_id=0, source="short", weights=None)
    reweighted = _score_vector(
        None, function_id=0, source="short",
        weights={"trace_pass_rate": 2.0, "fuzz_divergence_rate": 3.0,
                 "simplicity": 0.1})
    assert set(reweighted) == set(base)
    # doubling the weight doubles the (positive) trace axis
    assert reweighted["trace_pass_rate"] == pytest.approx(
        base["trace_pass_rate"] * 2.0)


def test_fuzz_axis_negated_is_lower_is_better():
    """The fuzz axis stores the negated divergence rate, so higher is always
    better across axes (the Pareto partial order's precondition)."""
    v = _score_vector(None, function_id=0, source="s", weights=None)
    assert v["fuzz_divergence_rate"] <= 0


def test_dominates_partial_order():
    a = {"trace_pass_rate": 1.0, "fuzz_divergence_rate": -2.0, "simplicity": -1.0}
    b = {"trace_pass_rate": 0.5, "fuzz_divergence_rate": -2.0, "simplicity": -1.0}
    assert _dominates(a, b) and not _dominates(b, a)
