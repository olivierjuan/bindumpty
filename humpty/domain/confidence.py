"""humpty.domain.confidence — trust is a score, not a boolean (FR-13).

A function's *confidence* is the probability mass that its reimplementation is
actually equivalent, aggregated over the evidence. Two evidence sources are
scored independently and combined:

1. **Fuzz evidence** — budget spent without divergence. The longer a campaign
   runs (and the more coverage it collects) without finding a counterexample,
   the higher the bound. This is operational "trusted", *not* a proof.
2. **Trace evidence** — pass rate over the recorded ground-truth I/O (FR-3).
   A failing trace is a hard counterexample and is handled by the state
   machine, not by the score.

``Proven`` (FR-11) short-circuits to confidence 1.0: equivalence established is
a proof, not an absence of counterexample.

The score feeds the king's scheduler (FR-14) for tie-breaking and expected
information gain, and it is what "demotes" a callee (FR-13): a parent-revealed
regression sets the callee's confidence toward 0 and moves it to DIVERGENT.
"""
from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "Confidence",
    "fuzz_confidence",
    "combined_confidence",
    "trace_pass_confidence",
    "demote",
]

#: Confidence of a proven function (FR-11). Evidence of equivalence.
PROVEN = 1.0
#: Confidence floor for a freshly ready function with no evidence.
FLOOR = 0.0
#: A divergence is a *hard* counterexample: confidence collapses to zero.
DIVERGED = 0.0


@dataclass(frozen=True, slots=True)
class Confidence:
    """Immutable confidence record for one function.

    ``fuzz``: score in [0,1) from budget-spent-without-divergence.
    ``traces``: fraction of recorded ground-truth inputs passed (None if no
        traces exist yet for the function).
    ``proven``: True once equivalence is established (FR-11).
    """

    fuzz: float = FLOOR
    traces: float | None = None
    proven: bool = False

    def value(self) -> float:
        """The single confidence number in [0, 1] used by the scheduler."""
        if self.proven:
            return PROVEN
        parts: list[float] = [self.fuzz]
        if self.traces is not None:
            parts.append(self.traces)
        # Independent evidence sources: a function is only as confident as its
        # *weakest* source. If one channel has not been exercised (traces is
        # None), do not penalize for it.
        return min(parts)

    def with_fuzz(self, fuzz: float) -> "Confidence":
        return Confidence(fuzz, self.traces, self.proven)

    def with_traces(self, traces: float) -> "Confidence":
        return Confidence(self.fuzz, traces, self.proven)

    def proven_(self) -> "Confidence":
        return Confidence(self.fuzz, self.traces, True)


def fuzz_confidence(exec_count: int, divergences: int, budget: int) -> float:
    """Score a fuzz campaign: budget spent without divergence.

    Returns 0.0 immediately when a divergence was found. Otherwise it grows
    with the *fraction of the budget consumed* — the standard operational
    meaning of "N minutes without divergence" (whitepaper §9). Coverage
    plateau detection is an M1 refinement; the fraction is the v0 baseline.

    - divergences > 0        -> 0.0
    - exec_count >= budget   -> high confidence (budget exhausted, clean)
    - 0 < exec_count < budget -> proportional to exec_count / budget
    """
    if divergences > 0:
        return DIVERGED
    if budget <= 0:
        return FLOOR
    frac = min(1.0, exec_count / budget)
    # Linear in v0; the exact curve is an open decision (see docs/decisions).
    return frac


def trace_pass_confidence(passed: int, total: int) -> float:
    """Fraction of ground-truth traces passed. 0/0 -> 0.0 (no evidence)."""
    if total <= 0:
        return FLOOR
    return passed / total


def combined_confidence(
    *,
    exec_count: int,
    divergences: int,
    budget: int,
    traces_passed: int | None = None,
    traces_total: int | None = None,
    proven: bool = False,
) -> Confidence:
    """Build a :class:`Confidence` from raw campaign + trace numbers."""
    fz = fuzz_confidence(exec_count, divergences, budget)
    tr = (
        trace_pass_confidence(traces_passed or 0, traces_total or 0)
        if traces_total
        else None
    )
    return Confidence(fz, tr, proven)


def demote(current: Confidence) -> Confidence:
    """Collapse a callee's confidence on a parent-revealed regression (FR-13).

    A divergence at a parent that is *attributable* to a child means the child
    was trusted too early: its confidence drops to the divergence floor and its
    proven flag is cleared. The state machine moves it to DIVERGENT in lockstep.
    """
    return Confidence(DIVERGED, current.traces, False)
