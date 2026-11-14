"""humpty.king.graveyard — FR-18: archive of near-miss candidates.

Failed candidates are data, not garbage. The graveyard stores each rejected
candidate with a score vector and a Pareto rank; later repair attempts seed
the fixer with the *best* archived candidate for the function (a starting
point that already passes most cases beats a fresh sample), and M4's
crossover draws multiple archived sources.

Score vector (higher is better on every axis):
    trace_pass_rate   — fraction of recorded traces the candidate passes
    fuzz_divergence_rate — LOWER is better; stored negated so max always wins
    simplicity        — shorter source = simpler (token proxy: -len/1000)

Pareto rank 1 = no other archived candidate dominates it. Retention: keep
every rank-1 candidate plus at most `max_per_function` total (drop the
worst-ranked on overflow — the fixer seeds from the top anyway).
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from humpty.db.events import record_event
from humpty.db.models import Candidate, Counterexample, Function, Graveyard, Trace

__all__ = ["archive_candidate", "seed_for", "pareto_front", "ParetoEntry"]


def _score_vector(session: Session, *, function_id: int, source: str,
                  weights: dict | None = None) -> dict:
    fn = session.get(Function, function_id)
    traces = session.query(Trace).filter(Trace.function_id == function_id).count()
    ces = session.query(Counterexample).filter(
        Counterexample.function_id == function_id).count()
    # v0 scoring from persisted evidence only:
    #   trace_pass_rate: 1.0 when no recorded traces exist yet (nothing failed)
    trace_rate = 1.0 if traces == 0 else max(0.0, 1.0 - ces / max(traces, 1))
    fuzz_rate = -float(ces)  # negated: higher (less negative) = fewer CEs
    simplicity = -len(source) / 1000.0
    raw = {"trace_pass_rate": trace_rate,
           "fuzz_divergence_rate": fuzz_rate,
           "simplicity": simplicity}
    # apply the configured Pareto weights (M3 decision: config knobs
    # graveyard_pareto_weights) so operators can reweight the front.
    w = weights or {"trace_pass_rate": 1.0,
                    "fuzz_divergence_rate": 1.0,
                    "simplicity": 1.0}
    return {k: round(raw[k] * w.get(k, 1.0), 4) for k in raw}


def _dominates(a: dict, b: dict) -> bool:
    """a dominates b iff a is >= on every axis and > on at least one."""
    keys = set(a) | set(b)
    ge = all(a.get(k, float("-inf")) >= b.get(k, float("-inf")) for k in keys)
    gt = any(a.get(k, float("-inf")) > b.get(k, float("-inf")) for k in keys)
    return ge and gt


def pareto_front(entries: list[dict]) -> list[int]:
    """Indices (into `entries`) of the non-dominated candidates."""
    front = []
    for i, a in enumerate(entries):
        dominated = any(_dominates(entries[j], a)
                        for j in range(len(entries)) if j != i)
        if not dominated:
            front.append(i)
    return front


@dataclass
class ParetoEntry:
    candidate_id: int
    score_vector: dict
    pareto_rank: int


def archive_candidate(session: Session, *, candidate_id: int,
                      max_per_function: int = 32,
                      weights: dict | None = None) -> int | None:
    """Archive a rejected candidate into the graveyard. Returns the
    graveyard row id, or None if the candidate is not rejected."""
    cand = session.get(Candidate, candidate_id)
    if cand is None or cand.status != "rejected":
        return None
    scores = _score_vector(session, function_id=cand.function_id,
                           source=cand.source_code, weights=weights)

    # recompute ranks for the function's whole graveyard
    existing = (session.query(Graveyard)
                .filter(Graveyard.function_id == cand.function_id).all())
    all_scores = [g.score_vector for g in existing] + [scores]
    ranks = pareto_front(all_scores)
    front = set(ranks)

    row = Graveyard(function_id=cand.function_id, candidate_id=cand.id,
                    score_vector=scores, pareto_rank=1)
    session.add(row)
    session.flush()

    # rank every row (1 = front, then iteratively strip the front)
    remaining = list(range(len(all_scores)))
    rank = 1
    ids = [g.id for g in existing] + [row.id]
    while remaining:
        front_idx = pareto_front([all_scores[i] for i in remaining])
        this_front = {remaining[i] for i in front_idx}
        for idx in this_front:
            g = session.get(Graveyard, ids[idx])
            g.pareto_rank = rank
        remaining = [i for i in remaining if i not in this_front]
        rank += 1

    # retention: keep the Pareto front, cap total per function
    rows = (session.query(Graveyard)
            .filter(Graveyard.function_id == cand.function_id)
            .order_by(Graveyard.pareto_rank.asc()).all())
    overflow = rows[max_per_function:]
    for g in overflow:
        session.delete(g)

    record_event(session, kind="graveyard_archived",
                 function_id=cand.function_id, candidate_id=cand.id,
                 payload={"scores": scores})
    session.flush()
    return row.id


def seed_for(session: Session, *, function_id: int) -> Candidate | None:
    """The best archived candidate for a function (rank 1, then best score):
    the fixer's starting point (FR-18 'fixer samples from the graveyard')."""
    rows = (session.query(Graveyard)
            .filter(Graveyard.function_id == function_id,
                    Graveyard.pareto_rank == 1)
            .order_by(Graveyard.score_vector["trace_pass_rate"].desc(),
                      Graveyard.archived_at.desc())
            .all())
    if not rows:
        return None
    return session.get(Candidate, rows[0].candidate_id)
