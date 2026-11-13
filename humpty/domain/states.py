"""humpty.domain — the function lifecycle: states, transitions, confidence.

The single source of truth for *what state a function is in* and *how much we
trust it*. The whitepaper (§6) fixes an 8-state lifecycle whose core is the
CEGIS loop Fuzzing -> Divergent -> Repairing, plus a fingerprint shortcut
straight to Trusted (FR-2), demotion of a Trusted function on a parent-revealed
regression (FR-13), and a Proven state above Trusted (FR-11).

Design note (ADR candidate): "developing" (the developer worker producing
candidates, FR-4) is *not* a separate state. The developer runs during the
``ready -> fuzzing`` transition: the function is Ready, the developer produces
one or more candidates, and the first of them being fuzzed moves it to Fuzzing.
Keeping 8 states (matching the whitepaper's "8 états") is worth more than a 9th
state for a worker phase that has no distinct *validation* meaning.
"""
from __future__ import annotations

from enum import Enum, unique

__all__ = [
    "State",
    "IllegalTransition",
    "can_transition",
    "transition",
    "is_success",
    "is_absorbing",
    "callees_trusted",
]


@unique
class State(Enum):
    """Lifecycle states of a single function under reconstruction.

    Order here is *not* lifecycle order; see :data:`TRANSITIONS`.
    """

    PENDING = "pending"
    READY = "ready"
    FUZZING = "fuzzing"
    DIVERGENT = "divergent"
    REPAIRING = "repairing"
    TRUSTED = "trusted"
    PROVEN = "proven"
    FAILED = "failed"


#: Legal state transitions. A state absent as a key has no outgoing edges.
TRANSITIONS: dict[State, frozenset[State]] = {
    # Waiting for callees to be trusted, or the fingerprint shortcut (FR-2).
    State.PENDING: frozenset({State.READY, State.TRUSTED}),
    # Developer produces a candidate, then it is fuzzed; or fingerprinted.
    State.READY: frozenset({State.FUZZING, State.TRUSTED}),
    # CEGIS core: budget out with no divergence -> trusted; else divergent.
    State.FUZZING: frozenset({State.TRUSTED, State.DIVERGENT}),
    # Counterexample found: repair, or give up (K exhausted).
    State.DIVERGENT: frozenset({State.REPAIRING, State.FAILED}),
    # Fixer emits a corrected candidate (re-fuzz) or gives up.
    State.REPAIRING: frozenset({State.FUZZING, State.FAILED}),
    # Trusted: demoted on a parent-revealed regression (FR-13) or proven (FR-11).
    State.TRUSTED: frozenset({State.DIVERGENT, State.PROVEN}),
    # Proven: equivalence established; absorbing.
    State.PROVEN: frozenset(),
    # Failed: original retained (NFR-7); may be retried on resurrection (FR-18).
    State.FAILED: frozenset({State.READY}),
}


class IllegalTransition(ValueError):
    """Raised when a state transition is not in :data:`TRANSITIONS`."""

    def __init__(self, src: State, dst: State) -> None:
        super().__init__(f"illegal transition {src.value} -> {dst.value}")
        self.src = src
        self.dst = dst


def can_transition(src: State, dst: State) -> bool:
    """Return True if ``src -> dst`` is a legal lifecycle transition."""
    return dst in TRANSITIONS.get(src, frozenset())


def transition(src: State, dst: State) -> State:
    """Validate and return ``dst``; raise :class:`IllegalTransition` otherwise."""
    if not can_transition(src, dst):
        raise IllegalTransition(src, dst)
    return dst


def is_success(state: State) -> bool:
    """A function counts toward the objective if it is trusted or proven."""
    return state in (State.TRUSTED, State.PROVEN)


def is_absorbing(state: State) -> bool:
    """Proven has no outgoing edges (equivalence is final)."""
    return state is State.PROVEN


def callees_trusted(callee_states: list[State]) -> bool:
    """A function is Ready exactly when every callee is trusted or proven.

    Empty callee list (a leaf) is ready. This is the definition of the ready
    set used by the king (FR-14); it lives in the domain so scheduler and tests
    share one implementation.
    """
    return all(is_success(s) for s in callee_states)
