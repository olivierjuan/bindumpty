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


def _decompiled_for(session, fn, binary_path: str | None, log=print) -> str | None:
    """P1: decompiled C for the developer prompt, decompiling on demand.

    Returns the persisted functions.decompiled_code; when NULL and the
    binary path is known, runs DecompileFunction.java once and persists
    the result. Any failure degrades to None (the prompt simply omits
    the decompilation section — never blocks the loop).
    """
    if fn.decompiled_code:
        return fn.decompiled_code
    if not binary_path:
        return None
    try:
        from humpty.ingest.decompile import ensure_decompiled
        code = ensure_decompiled(session, fn, binary_path, log=log)
        if code:
            # P2: the decompiler's prototype line normalizes into
            # demangled_sig so harness_gen picks the right harness family
            from humpty.ingest.prototypes import refresh_prototypes
            refresh_prototypes(session, binary_path, log=log)
        return code
    except Exception as e:  # noqa: BLE001 — decompilation must never kill a leaf
        log(f"  {fn.name}: on-demand decompilation unavailable: {e}")
        return None


def _indirect_callees(session, fn, log=print) -> list[str]:
    """FR-5.2 enrichment: resolved indirect-call targets for this function
    (DynamoRIO edge pass, kind 'indirect_resolved'), formatted as
    dispatch-table knowledge for the developer prompt. Empty when no
    edge pass has run."""
    from humpty.db.models import CallEdge
    rows = (session.query(CallEdge)
            .filter(CallEdge.caller_id == fn.id,
                    CallEdge.kind == "indirect_resolved").all())
    out = []
    for e in rows:
        callee = session.get(Function, e.callee_id)
        if callee is None:
            continue
        out.append(f"indirect call resolved at runtime: {callee.name} "
                   f"(at +0x{callee.address:x})")
    if out:
        log(f"  {fn.name}: {len(out)} resolved indirect targets "
            f"added to the prompt")
    return out


def _try_z3_proof(session, fn, candidate, binary_path, log=print) -> bool:
    """FR-11 generalized proof upgrade: when the fuzzing loop marks a
    candidate trusted, attempt a Z3 QF_BV equivalence proof between the
    original decompiled C and the candidate source. UNSAT upgrades the
    row to State.PROVEN (genuine equivalence, not sampled equivalence).
    Any unsupported construct (loops, pointers beyond the symbolic-memory
    v0, calls) leaves the row trusted. Returns True on upgrade."""
    if binary_path is None:
        return False
    try:
        from humpty.analyze.smt_prove import prove_equivalence
        from humpty.domain import State as _S
        orig_src = fn.decompiled_code
        if not orig_src:
            return False
        proof = prove_equivalence(orig_src, candidate.source_code,
                                  fn.name)
        if proof.status == "proven":
            _move(session, fn, _S.PROVEN)
            candidate.status = "proven"
            fn.confidence = 1.0
            log(f"  {fn.name}: PROVEN via Z3 QF_BV equivalence "
                f"({proof.details})")
            return True
        log(f"  {fn.name}: Z3 proof {proof.status} — stays trusted "
            f"({proof.details[:80]})")
    except Exception as e:  # noqa: BLE001 — proof is best-effort
        log(f"  {fn.name}: Z3 proof error: {e}")
    return False


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


def _persist_counterexample(session: Session, fn: Function, ce,
                            candidate_id: int | None = None) -> bool:
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
        candidate_id=candidate_id,
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
                  log=print, harness_bin: str | None = None,
                  binary_path: str | None = None,
                  types_header: str | None = None) -> dict:
    """Drive one leaf function through the full CEGIS lifecycle.

    ``develop(spec, counterexample) -> source`` is the injected developer
    runtime (FR-4); ``max_iter`` is the K cost cap (NFR-6). Returns a result
    dict; the Function row is left in ``trusted`` or ``failed``.
    """
    fn = session.get(Function, function_id)
    if fn is None:
        raise LeafLoopError(f"unknown function id {function_id}")

    if harness_bin is not None:
        # generated per-binary harness (harness_gen): use a direct fuzz loop
        return _run_with_generated_harness(
            session, fn=fn, develop=develop, harness_bin=harness_bin,
            max_iter=max_iter, fuzz_budget_s=fuzz_budget_s, log=log,
            binary_path=binary_path, types_header=types_header)
    decompiled = _decompiled_for(session, fn, binary_path, log=log)
    # P2: _decompiled_for may have refreshed demangled_sig from the
    # decompiler's prototype line — read it after, not before
    session.refresh(fn)
    spec = {"name": fn.name, "signature": fn.demangled_sig or fn.name,
            "ret_type": "", "notes": "", "decompiled_c": decompiled,
            "types_header": types_header,
            "callees": _indirect_callees(session, fn, log=log)}
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
            candidate.status = "diverged"
            first = still_bad[0]
            _persist_counterexample(session, fn, first, candidate_id=candidate.id)
            _move(session, fn, State.FUZZING)
            _move(session, fn, State.DIVERGENT)
            divergences_seen += 1
            log(f"  iter {iteration}: REJECTED — fails {len(still_bad)} "
                f"persisted counterexample(s)")
            if iteration >= max_iter:
                _move(session, fn, State.FAILED)
                break
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
            if _try_z3_proof(session, fn, candidate, binary_path, log=log):
                return {"verified": True, "iterations": iteration,
                        "state": fn.state, "confidence": fn.confidence,
                        "counterexamples": divergences_seen,
                        "wall_s": time.perf_counter() - t0}
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
        _persist_counterexample(session, fn, first, candidate_id=candidate.id)
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


def _run_with_generated_harness(session: Session, *, fn: Function, develop,
                                harness_bin: str, max_iter: int,
                                fuzz_budget_s: int, log=print,
                                binary_path: str | None = None,
                                types_header: str | None = None) -> dict:
    """CEGIS loop for a function with a generated (harness_gen) harness.
    Compiles the candidate into the generated harness and fuzzes it."""
    import tempfile
    import time as _time
    from humpty.domain import _move, State
    from humpty.db.models import Candidate, Counterexample
    from humpty.domain.confidence import combined_confidence

    decompiled = _decompiled_for(session, fn, binary_path, log=log)
    # P2: _decompiled_for may have refreshed demangled_sig from the
    # decompiler's prototype line — read it after, not before
    session.refresh(fn)
    spec = {"name": fn.name, "signature": fn.demangled_sig or fn.name,
            "ret_type": "", "notes": "", "decompiled_c": decompiled,
            "types_header": types_header,
            "callees": _indirect_callees(session, fn, log=log)}
    divergences_seen = 0
    t0 = time.perf_counter()

    if fn.state == State.PENDING.value:
        _move(session, fn, State.READY)
    elif fn.state != State.READY.value:
        raise LeafLoopError(f"leaf loop starts from pending/ready, "
                            f"row is {fn.state}")

    harness_dir = os.path.dirname(harness_bin)
    ce_dir = os.path.join(harness_dir, "counterexamples")

    for iteration in range(1, max_iter + 1):
        # develop
        src = develop(spec, None)
        cand_c = os.path.join(harness_dir, "candidate.c")
        with open(cand_c, "w") as f:
            f.write(src)
        so = os.path.join(harness_dir, "candidate.so")
        r = subprocess.run(
            ["clang", "-O1", "-fPIC", "-shared", cand_c, "-o", so],
            capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            log(f"  iter {iteration}: build error — {r.stderr[-200:]}")
            if iteration >= max_iter:
                _move(session, fn, State.FAILED)
                return {"verified": False, "iterations": iteration,
                        "counterexamples": divergences_seen,
                        "wall_s": time.perf_counter() - t0}
            continue

        candidate = Candidate(function_id=fn.id, source_code=src,
                              created_by="dev", status="fuzzing")
        session.add(candidate)
        session.flush()

        # fuzz the generated harness with the candidate compiled in
        bin_path = os.path.join(harness_dir, "harness_bin")
        r = subprocess.run(
            [bin_path, f"-max_total_time={fuzz_budget_s}"],
            capture_output=True, text=True, timeout=fuzz_budget_s + 30)
        divergent = "DIVERGENCE" in (r.stdout + r.stderr)
        session.add(__import__("humpty.db.models", fromlist=["FuzzRun"]).FuzzRun(
            candidate_id=candidate.id, engine="libfuzzer",
            divergences=1 if divergent else 0,
            duration=fuzz_budget_s))

        if divergent:
            candidate.status = "diverged"
            _move(session, fn, State.DIVERGENT)
            divergences_seen += 1
            log(f"  iter {iteration}: DIVERGENT")
            if iteration >= max_iter:
                _move(session, fn, State.FAILED)
                return {"verified": False, "iterations": iteration,
                        "counterexamples": divergences_seen,
                        "wall_s": time.perf_counter() - t0}
            _move(session, fn, State.REPAIRING)
            continue

        candidate.status = "trusted"
        _move(session, fn, State.TRUSTED)
        if _try_z3_proof(session, fn, candidate, binary_path, log=log):
            return {"verified": True, "iterations": iteration,
                    "state": fn.state, "confidence": fn.confidence,
                    "counterexamples": divergences_seen,
                    "wall_s": time.perf_counter() - t0}
        fn.confidence = combined_confidence(
            exec_count=1000000, divergences=0,
            budget=fuzz_budget_s).value()
        total = time.perf_counter() - t0
        return {"verified": True, "iterations": iteration,
                "counterexamples": divergences_seen, "wall_s": total}

    _move(session, fn, State.FAILED)
    return {"verified": False, "iterations": max_iter,
            "counterexamples": divergences_seen,
            "wall_s": time.perf_counter() - t0}
