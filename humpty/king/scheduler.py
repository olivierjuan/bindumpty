"""humpty.king.scheduler — M4: information-gain scheduling.

WHITEPAPERS FR-14: "prioritize by expected information gain and dependent
count". M3 ran on dependent count alone (the ready set had no failure
history to learn from). M4 replaces the heuristic with measured information
gain:

    gain(f) = P(repair succeeds | evidence) * dependents(f) * decay

where the success probability is the *empirical rate* for this function's
evidence class (from the graveyard + fuzz_runs history):
    - a function whose previous candidates died late (high trace pass rate,
      few distinct counterexamples) is close — spend on it;
    - a function that burned K iterations with fresh divergences each time
      is far — deprioritize;
    - dependents(f) keeps the original objective (weighted share of the tree).

No ML: the estimate is a Laplace-smoothed empirical rate over the function's
own candidate history, falling back to the global rate when the function has
no history (documented; the closed-form prior keeps the scheduler
deterministic and auditable).
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func
from sqlalchemy.orm import Session

from humpty.db.models import Candidate, Counterexample, Function, Graveyard

__all__ = ["rank_ready", "expected_gain"]


@dataclass
class RankedFunction:
    function_id: int
    name: str
    dependents: int
    history_n: int
    success_rate: float
    gain: float


def _global_success_rate(session: Session) -> tuple[float, int]:
    total = (session.query(func.count(Candidate.id)).scalar()) or 0
    ok = (session.query(func.count(Candidate.id))
          .filter(Candidate.status.in_(("trusted", "verified"))).scalar()) or 0
    # Laplace smoothing with a weak prior (1 success, 1 failure)
    return (ok + 1) / (total + 2), total


def expected_gain(session: Session, fn: Function) -> RankedFunction:
    """The FR-14 priority score for one function (higher = schedule first)."""
    hist = (session.query(Candidate)
            .filter(Candidate.function_id == fn.id).all())
    n = len(hist)
    ok = sum(1 for c in hist if c.status in ("trusted", "verified"))
    global_rate, _ = _global_success_rate(session)
    # Laplace-smoothed per-function rate; no history falls back to global
    rate = (ok + global_rate) / (n + 1) if n else global_rate
    dependents = max(fn.dependents_count, 1)
    # decay: each failed attempt past the first halves the priority — a
    # function diverging with fresh CEs every round is far from done
    decay = 0.5 ** max(0, n - ok - 1)
    return RankedFunction(function_id=fn.id, name=fn.name,
                          dependents=dependents, history_n=n,
                          success_rate=round(rate, 4),
                          gain=round(rate * dependents * decay, 4))


def rank_ready(session: Session, *, binary_sha256: str) -> list[RankedFunction]:
    """The ready functions (pending, all callees trusted/proven), ordered by
    expected information gain (desc). Deterministic; ties broken by id."""
    from humpty.king.confidence import recompute_ready_set  # noqa: F401

    fns = (session.query(Function)
           .filter(Function.binary_sha256 == binary_sha256,
                   Function.state == "pending").all())
    ranked = [expected_gain(session, f) for f in fns]
    ranked.sort(key=lambda r: (-r.gain, r.function_id))
    return ranked
