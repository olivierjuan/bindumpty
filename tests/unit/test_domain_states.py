"""Tests for humpty.domain — the function lifecycle state machine and confidence.

Covers the whitepaper's 8-state lifecycle (FR-2 fingerprint shortcut, FR-13
demotion, FR-11 proven), the ready-set definition (FR-14), and the confidence
score semantics (FR-13, §9 "proof versus fuzzing").
"""
import pytest

from humpty.domain import (
    Confidence,
    IllegalTransition,
    State,
    can_transition,
    combined_confidence,
    demote,
    fuzz_confidence,
    transition,
    callees_trusted,
)

# --- State machine ---------------------------------------------------------


def test_fingerprint_shortcut_pending_to_trusted():
    # FR-2: a recognized library routine goes straight to Trusted.
    assert can_transition(State.PENDING, State.TRUSTED)
    assert transition(State.PENDING, State.TRUSTED) is State.TRUSTED


def test_cegis_core_loop():
    # Fuzzing -> Divergent -> Repairing -> Fuzzing (the CEGIS core).
    assert transition(State.FUZZING, State.DIVERGENT) is State.DIVERGENT
    assert transition(State.DIVERGENT, State.REPAIRING) is State.REPAIRING
    assert transition(State.REPAIRING, State.FUZZING) is State.FUZZING


def test_clean_fuzzing_goes_to_trusted():
    assert transition(State.FUZZING, State.TRUSTED) is State.TRUSTED


def test_demotion_trusted_to_divergent():
    # FR-13: a parent-revealed regression demotes a trusted callee.
    assert transition(State.TRUSTED, State.DIVERGENT) is State.DIVERGENT


def test_trusted_to_proven():
    # FR-11: proven ranks above trusted.
    assert transition(State.TRUSTED, State.PROVEN) is State.PROVEN


def test_proven_is_absorbing():
    # No outgoing edges from Proven: equivalence is final.
    assert not can_transition(State.PROVEN, State.DIVERGENT)
    for other in State:
        if other is not State.PROVEN:
            assert not can_transition(State.PROVEN, other)


def test_failed_is_retryable():
    # A failed function may be retried (resurrection, FR-18).
    assert can_transition(State.FAILED, State.READY)
    assert not can_transition(State.FAILED, State.TRUSTED)


def test_ready_transitions():
    # Ready -> Fuzzing is the normal path; the fingerprint shortcut to
    # Trusted is allowed (FR-2). Ready must not skip validation to Divergent.
    assert can_transition(State.READY, State.FUZZING)
    assert can_transition(State.READY, State.TRUSTED)
    assert not can_transition(State.READY, State.DIVERGENT)
    assert not can_transition(State.READY, State.PROVEN)


@pytest.mark.parametrize(
    "src,dst",
    [
        (State.PENDING, State.FUZZING),  # must become ready first
        (State.PENDING, State.DIVERGENT),
        (State.REPAIRING, State.TRUSTED),  # must re-fuzz, not skip
        (State.DIVERGENT, State.TRUSTED),
        (State.PROVEN, State.FAILED),
        (State.FAILED, State.FUZZING),
    ],
)
def test_illegal_transitions_raise(src, dst):
    with pytest.raises(IllegalTransition):
        transition(src, dst)


def test_illegal_transition_carries_states():
    try:
        transition(State.PROVEN, State.FAILED)
    except IllegalTransition as e:
        assert e.src is State.PROVEN
        assert e.dst is State.FAILED
    else:
        pytest.fail("expected IllegalTransition")


# --- Ready set (FR-14) -----------------------------------------------------


def test_leaf_is_ready():
    assert callees_trusted([])


def test_ready_when_all_callees_trusted_or_proven():
    assert callees_trusted([State.TRUSTED, State.PROVEN, State.TRUSTED])


def test_not_ready_if_any_callee_untrusted():
    assert not callees_trusted([State.TRUSTED, State.PENDING])
    assert not callees_trusted([State.FAILED])


# --- Confidence ------------------------------------------------------------


def test_proven_short_circuits_to_one():
    c = Confidence(fuzz=0.1, traces=0.5, proven=True)
    assert c.value() == 1.0


def test_confidence_is_weakest_source():
    # fuzz 0.9 but traces only 0.5 -> 0.5 (weakest independent source).
    c = Confidence(fuzz=0.9, traces=0.5)
    assert c.value() == pytest.approx(0.5)


def test_missing_traces_not_penalized():
    # No traces recorded yet: only fuzz counts.
    c = Confidence(fuzz=0.7, traces=None)
    assert c.value() == pytest.approx(0.7)


def test_fuzz_divergence_collapses():
    assert fuzz_confidence(exec_count=10_000, divergences=1, budget=10_000) == 0.0


def test_fuzz_proportional_to_budget():
    assert fuzz_confidence(5_000, 0, 10_000) == pytest.approx(0.5)
    assert fuzz_confidence(10_000, 0, 10_000) == pytest.approx(1.0)


def test_fuzz_zero_budget_is_floor():
    assert fuzz_confidence(10_000, 0, 0) == 0.0


def test_trace_pass_ratio():
    c = combined_confidence(exec_count=100, divergences=0, budget=100,
                            traces_passed=8, traces_total=10)
    assert c.traces == pytest.approx(0.8)


def test_trace_zero_over_zero_is_floor():
    c = combined_confidence(exec_count=10, divergences=0, budget=10)
    assert c.traces is None


def test_demote_clears_proven_and_zeroes_fuzz():
    c = Confidence(fuzz=0.9, traces=0.9, proven=True)
    d = demote(c)
    assert d.fuzz == 0.0
    assert d.proven is False
    assert d.value() == 0.0
    # Trace evidence is preserved (it is still valid ground truth).
    assert d.traces == pytest.approx(0.9)
