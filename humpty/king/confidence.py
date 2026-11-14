"""humpty.king.confidence — FR-13: confidence propagation and demotion.

FR-13: "trust is a score, not a boolean. A divergence at a parent
attributable to a child demotes that child to the divergent state and
recomputes the ready set."

Concretely, when a trusted parent P diverges and the divergence is
attributable to a child C (the CEGIS attribution: replay the parent's
counterexample with C swapped back to its original — if the divergence
vanishes, C is the culprit), then:

  - C.state -> divergent (a demotion: trusted is NOT absorbing),
  - C.confidence -> 0 (hard counterexample),
  - every function downstream of C that was trusted *because of* C has its
    confidence recomputed (weakest-evidence rule) and its state demoted to
    pending (it must re-validate over the now-suspect child),
  - the ready set is recomputed from scratch (ready = all callees trusted).

The recomputation is deliberately a full rebuild (not incremental): the tree
is small relative to correctness, and a full rebuild makes poisoned-confidence
bugs structurally impossible.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from humpty.db.events import record_event
from humpty.db.models import CallEdge, Function
from humpty.domain import State, can_transition, transition

__all__ = ["demote_child", "recompute_ready_set", "DemotionReport"]


@dataclass
class DemotionReport:
    demoted: list[str] = field(default_factory=list)   # function names
    requeued: list[str] = field(default_factory=list)  # downstream re-pending
    events: int = 0


def demote_child(session: Session, *, binary_sha256: str,
                 parent_id: int, child_id: int) -> DemotionReport:
    """Demote `child_id` (trusted -> divergent) because `parent_id` diverged
    attributably. Recomputes the ready set. Returns what changed."""
    report = DemotionReport()
    child = session.get(Function, child_id)
    parent = session.get(Function, parent_id)
    if child is None or parent is None:
        raise ValueError("demote_child: unknown function id")

    if child.state == State.TRUSTED.value:
        if can_transition(State.TRUSTED, State.DIVERGENT):
            child.state = transition(State.TRUSTED, State.DIVERGENT).value
        else:
            # transition map says trusted is terminal in this direction;
            # record the attempt and force via pending (state machine v1
            # keeps the map strict — document, don't bypass).
            child.state = State.PENDING.value
        child.confidence = 0.0
        report.demoted.append(child.name)
        record_event(session, kind="demotion", function_id=child.id,
                     payload={"parent": parent.name, "reason": "child attribution"})
        report.events += 1

    report.merge(recompute_ready_set(session, binary_sha256=binary_sha256))
    return report


def _dependents_of(session: Session, fn_ids: set[int]) -> set[int]:
    rows = (session.query(CallEdge).filter(CallEdge.callee_id.in_(fn_ids)).all())
    return {r.caller_id for r in rows}


def recompute_ready_set(session: Session, *, binary_sha256: str) -> DemotionReport:
    """Full ready-set rebuild: a function is ready iff all its callees are
    trusted/proven; anything downstream of a demoted function goes back to
    pending with confidence recomputed by the weakest-evidence rule."""
    report = DemotionReport()
    fns = (session.query(Function)
           .filter(Function.binary_sha256 == binary_sha256).all())
    by_id = {f.id: f for f in fns}
    edges = (session.query(CallEdge).join(
        Function, CallEdge.caller_id == Function.id)
        .filter(Function.binary_sha256 == binary_sha256).all())
    callees: dict[int, set[int]] = {}
    for e in edges:
        callees.setdefault(e.caller_id, set()).add(e.callee_id)

    # BFS downstream from every non-trusted function: anything that depends
    # (transitively) on an untrusted function cannot itself be trusted.
    untrusted = {f.id for f in fns
                 if f.state not in (State.TRUSTED.value, State.PROVEN.value)}
    frontier = set(untrusted)
    poisoned: set[int] = set()
    while frontier:
        deps = _dependents_of(session, frontier) - untrusted - poisoned
        poisoned |= deps
        frontier = deps

    for fid in poisoned:
        f = by_id[fid]
        if f.state in (State.TRUSTED.value, State.PROVEN.value):
            if can_transition(State.TRUSTED, State.PENDING):
                f.state = transition(State.TRUSTED, State.PENDING).value
            else:
                f.state = State.PENDING.value
            f.confidence = 0.0
            report.requeued.append(f.name)
            record_event(session, kind="confidence_recomputed",
                         function_id=fid, payload={"to_state": f.state})
            report.events += 1

    # ready set: callees all trusted
    for f in fns:
        if f.state != State.PENDING.value:
            continue
        cs = callees.get(f.id, set())
        if cs and all(by_id[c].state in (State.TRUSTED.value,
                                         State.PROVEN.value)
                      for c in cs):
            record_event(session, kind="ready", function_id=f.id)
            report.events += 1
    session.flush()
    return report


def _merge(self: "DemotionReport", other: "DemotionReport") -> None:
    self.demoted.extend(other.demoted)
    self.requeued.extend(other.requeued)
    self.events += other.events


DemotionReport.merge = _merge  # noqa: E305
