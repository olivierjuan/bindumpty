"""humpty.king.leaf_loop — the king drives one leaf through the CEGIS loop.

The state machine in ``humpty.domain`` is law (``TRANSITIONS``); this module
wires the proven horses/ CEGIS mechanics (``horses.src.cegis``, M1) to the
database: every state change writes an ``events`` row in the same
transaction, every develop round persists a ``candidates`` row, every
divergence a deduplicated ``counterexamples`` row, every fuzz campaign a
``fuzz_runs`` row.

Per-iteration flow (all inside ``session_scope``-managed transactions):

    pending -> ready
    ready -> fuzzing      (develop produced a candidate; it is being fuzzed)
    fuzzing -> trusted    (budget exhausted clean, confidence scored)
    fuzzing -> divergent  (counterexample found)
    divergent -> repairing
    repairing -> fuzzing  (fixer produced a candidate; re-fuzz)   [K cap]
    divergent -> failed   (K exhausted)

The develop callable is injected exactly like ``cegis_loop``: CI passes
``cegis.stub_develop`` (deterministic, LLM-free); production passes
``cegis.make_pydantic_develop()`` (Pydantic AI). As in ``cegis.cegis_loop``,
the loop itself persists each returned source and rebuilds the candidate .so
(``hd.write_candidate``) before the replay gate — a candidate that still
fails a persisted counterexample is rejected before any fuzz budget is spent
on it (FR-15).
"""
from __future__ import annotations

import hashlib
import sys
import time
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from humpty.db.events import record_event
from humpty.db.models import (
    Candidate,
    Counterexample,
    FuzzRun,
    Function,
)
from humpty.domain import State, can_transition
from humpty.domain.confidence import combined_confidence

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT / "horses" / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "horses" / "src"))
import harness_driver as hd  # noqa: E402
import cegis  # noqa: E402

__all__ = ["LeafLoopError", "run_leaf_loop"]


class LeafLoopError(RuntimeError):
    """An illegal lifecycle transition was attempted (states.py is law)."""


def _move(session: Session, fn: Function, dst: State) -> None:
    """Apply one lifecycle transition, or raise. Event written in-transaction."""
    src = State(fn.state)
    if not can_transition(src, dst):
        raise LeafLoopError(f"{src.value} -> {dst.value}")
    fn.state = dst.value
    record_event(session, kind=f"state:{src.value}:{dst.value}",
                 function_id=fn.id)
    session.flush()


def _persist_counterexample(session: Session, fn: Function, ce) -> bool:
    """Store a divergence as a counterexamples row, deduped by
    (function_id, input_sha256). Returns True when newly inserted."""
    data = ce.as_input()
    sha = hashlib.sha256(data).hexdigest()
    dup = session.scalar(
        select(Counterexample).where(
            Counterexample.function_id == fn.id,
            Counterexample.input_sha256 == sha,
        )
    )
    if dup is not None:
        return False
    expected = ce.want.to_bytes(4, "little")
    observed = ce.got.to_bytes(4, "little")
    session.add(Counterexample(
        function_id=fn.id,
        input_blob=data,
        expected=expected,
        observed=observed,
        kind="return",
        input_sha256=sha,
    ))
    session.flush()
    return True


def run_leaf_loop(session: Session, *, function_id: int, develop,
                  max_iter: int = 5, fuzz_budget_s: int = 15,
                  log=print) -> dict:
    """Drive one leaf function through the full CEGIS lifecycle.

    ``develop(spec, counterexample) -> source`` is the injected developer
    runtime (FR-4); ``max_iter`` is the K cost cap (NFR-6). Returns a result
    dict; the Function row is left in ``trusted`` or ``failed``.
    """
    fn = session.get(Function, function_id)
    if fn is None:
        raise LeafLoopError(f"unknown function id {function_id}")
    spec = {"name": fn.name, "signature": fn.demangled_sig or fn.name,
            "ret_type": "", "notes": ""}
    divergences_seen = 0
    t0 = time.perf_counter()

    if fn.state == State.PENDING.value:
        _move(session, fn, State.READY)
    elif fn.state != State.READY.value:
        raise LeafLoopError(f"leaf loop starts from pending/ready, "
                            f"row is {fn.state}")

    for iteration in range(1, max_iter + 1):
        # FR-15 regression suite: replay every persisted counterexample of
        # this function before spending fuzz budget (reuses hd.run_replay).
        known = [
            ce.input_blob for ce in session.scalars(
                select(Counterexample)
                .where(Counterexample.function_id == function_id)
                .order_by(Counterexample.id)
            )
        ]
        src = develop(spec, cegis._describe(known) if known else None)
        hd.write_candidate(src)

        candidate = Candidate(
            function_id=function_id,
            source_code=src,
            created_by="dev",
            status="pending",
        )
        session.add(candidate)
        session.flush()

        still_bad = hd.run_replay(known) if known else []
        if still_bad:
            candidate.status = "rejected"
            first = still_bad[0]
            _persist_counterexample(session, fn, first)
            _move(session, fn, State.FUZZING)
            _move(session, fn, State.DIVERGENT)
            divergences_seen += 1
            log(f"  iter {iteration}: REJECTED — fails {len(still_bad)} "
                f"persisted counterexample(s)")
            _move(session, fn, State.REPAIRING)
            continue

        candidate.status = "fuzzing"
        _move(session, fn, State.FUZZING)
        result = hd.run_fuzz(budget_s=fuzz_budget_s)
        session.add(FuzzRun(
            candidate_id=candidate.id,
            engine="libfuzzer",
            exec_count=result.execs,
            divergences=len(result.counterexamples),
            duration=result.wall_s,
        ))

        if not result.divergent:
            candidate.status = "trusted"
            _move(session, fn, State.TRUSTED)
            fn.confidence = combined_confidence(
                exec_count=result.execs, divergences=0,
                budget=fuzz_budget_s).value()
            total = time.perf_counter() - t0
            log(f"  iter {iteration}: TRUSTED ({result.execs} execs clean)")
            return {"verified": True, "iterations": iteration,
                    "state": fn.state, "confidence": fn.confidence,
                    "counterexamples": divergences_seen,
                    "wall_s": total}

        # Divergent: persist the counterexample (dedup) and try a repair.
        candidate.status = "diverged"
        first = result.counterexamples[0]
        _persist_counterexample(session, fn, first)
        divergences_seen += 1
        _move(session, fn, State.DIVERGENT)
        log(f"  iter {iteration}: DIVERGENT — {first.describe()}")

        if iteration >= max_iter:
            _move(session, fn, State.FAILED)
            break
        _move(session, fn, State.REPAIRING)

    total = time.perf_counter() - t0
    log(f"  leaf FAILED after {max_iter} iterations "
        f"({divergences_seen} divergence(s))")
    return {"verified": False, "iterations": max_iter,
            "state": fn.state, "confidence": fn.confidence,
            "counterexamples": divergences_seen, "wall_s": total}
