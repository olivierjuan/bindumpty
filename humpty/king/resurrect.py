"""humpty.king.resurrect — FR-18 extension: crossover + resurrection.

Two mechanisms on top of the graveyard:

1. **Crossover (M4)**: splice two archived candidates — take the failing
   half-structure of one and the passing structure of another. v0 crossover
   for function-level C sources: line-set union, deduplicated, with the
   surviving candidate's includes. Sound because every crossed candidate
   must still pass the replay gate before it is *trusted* — the gate is the
   filter, the crossover is just a smarter proposal.

2. **Resurrection**: a failed function's archived candidates become
   actionable again when the *reason it failed goes away* — a fixed callee,
   a type-registry update (FR-12), or new traces (FR-3). Resurrection
   re-queues the function with the best archived candidate as the fixer's
   starting point, and increments resurrected_count (auditable).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from humpty.db.events import record_event
from humpty.db.models import Candidate, Function, Graveyard
from humpty.king.graveyard import seed_for

__all__ = ["crossover", "resurrect", "ResurrectionReport"]


def crossover(session: Session, *, function_id: int,
              src_a: str, src_b: str) -> str:
    """Line-set crossover of two archived sources (v0: includes from A,
    code lines = union preserving A's order then B's new lines). The replay
    gate filters; this only proposes."""
    def code_lines(src: str) -> list[str]:
        return [l for l in src.splitlines()
                if l.strip() and not l.strip().startswith("#include")]

    def includes(src: str) -> list[str]:
        return [l for l in src.splitlines()
                if l.strip().startswith("#include")]

    a_code, b_code = code_lines(src_a), code_lines(src_b)
    seen = set(a_code)
    merged = list(a_code)
    for l in b_code:
        if l not in seen:
            seen.add(l)
            merged.append(l)
    return "\n".join(includes(src_a) + [""] + merged) + "\n"


@dataclass
class ResurrectionReport:
    function: str
    requeued: bool = False
    seeded_from_candidate: int | None = None
    events: int = 0
    notes: list = field(default_factory=list)


def resurrect(session: Session, *, function_id: int,
              reason: str) -> ResurrectionReport:
    """Re-queue a failed function whose failure reason changed.

    Preconditions: the function is in state `failed` (or divergent), the
    graveyard has at least one archived candidate, and `reason` documents
    what changed (callee fix | type update | new traces). The function goes
    back to pending with its best archived candidate persisted as a dev
    candidate so the next loop iteration starts from it.
    """
    fn = session.get(Function, function_id)
    if fn is None:
        raise ValueError("resurrect: unknown function id")
    report = ResurrectionReport(function=fn.name)

    if fn.state not in ("failed", "divergent"):
        report.notes.append(f"state is {fn.state}; nothing to resurrect")
        return report

    seed = seed_for(session, function_id=function_id)
    if seed is None:
        report.notes.append("no archived candidates to resurrect from")
        return report

    # re-materialize the archived candidate as a live dev candidate
    session.add(Candidate(function_id=function_id,
                          source_code=seed.source_code,
                          created_by="dev", status="pending",
                          parent_candidate_id=seed.id))
    g = (session.query(Graveyard)
         .filter(Graveyard.candidate_id == seed.id).first())
    if g is not None:
        g.resurrected_count += 1

    fn.state = "pending"
    fn.confidence = 0.0
    record_event(session, kind="resurrection", function_id=function_id,
                 payload={"reason": reason,
                          "seeded_candidate": seed.id})
    report.requeued = True
    report.seeded_from_candidate = seed.id
    report.events += 1
    session.flush()
    return report
