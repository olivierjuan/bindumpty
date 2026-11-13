"""humpty.domain — the function lifecycle: states, transitions, confidence.

Public API re-exported for convenience.
"""
from humpty.domain.confidence import (
    Confidence,
    combined_confidence,
    demote,
    fuzz_confidence,
    trace_pass_confidence,
)
from humpty.domain.states import (
    State,
    IllegalTransition,
    can_transition,
    is_absorbing,
    is_success,
    transition,
    callees_trusted,
)

__all__ = [
    "State",
    "IllegalTransition",
    "can_transition",
    "transition",
    "is_success",
    "is_absorbing",
    "callees_trusted",
    "Confidence",
    "combined_confidence",
    "fuzz_confidence",
    "trace_pass_confidence",
    "demote",
]
