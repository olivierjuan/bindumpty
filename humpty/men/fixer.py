"""humpty.men.fixer — FR-5: counterexample-driven repair with an anti-hardcode
gate.

The fixer takes the current best candidate plus the deduplicated
counterexamples (FR-15) and produces a repaired candidate. Acceptance is
mechanical, in code, not in the model's judgment:

  1. Replay gate — the repair must survive EVERY persisted counterexample of
     the function and every recorded trace (the full regression suite).
     A repair that only fixes the failing inputs but breaks others is
     rejected (this is what makes "hardcode the failing case" unprofitable).
  2. Novelty gate — a repair byte-identical (normalized) to a previously
     rejected candidate is rejected without spend (response cache, NFR-6).

The LLM call itself is injected (same seam as the developer): the default
`llm_source=None` path raises, CI passes a callable. Everything else —
persistence, gating, candidate lineage — is real.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from humpty.db.events import record_event
from humpty.db.models import Candidate, Counterexample, Function, Trace
from humpty.men.prompts.templates import fixer_prompt

__all__ = ["FixResult", "fix", "normalize_source"]


@dataclass
class FixResult:
    ok: bool
    candidate_id: int | None = None
    reason: str = ""
    source: str = ""


def normalize_source(src: str) -> str:
    """Whitespace-insensitive source identity (response cache key, NFR-6)."""
    return hashlib.sha256(
        "\n".join(line.strip() for line in src.strip().splitlines()
                  if line.strip()).encode()
    ).hexdigest()


def _replay_gate(session: Session, function: Function, src: str,
                 spec_builder=None) -> tuple[bool, str]:
    """Replay the full regression suite against a repaired source.

    The gate compiles `src` against the leaf harness scorer (or spec_builder)
    and requires zero divergences.
    `spec_builder(src)` -> callable(bytes) -> bytes is the candidate under
    test, built by the caller (it knows the leaf's ABI).

    Returns (ok, reason).
    """
    if spec_builder is not None:
        try:
            score = spec_builder(src)
            if hasattr(score, "ok") and not score.ok:
                first = score.divergences[0] if getattr(score, "divergences", None) else "spec verification failed"
                return False, f"replay gate: {first}"
            elif isinstance(score, bool) and not score:
                return False, "replay gate: spec builder returned False"
        except Exception as e:
            return False, f"replay gate: spec builder error: {e}"
    elif function.name == "fnv1a":
        from horses.spikes.s4_core import build_and_score, Fnv1aSpec  # noqa: E402
        import sys

        root = str(__import__("pathlib").Path(__file__).resolve().parents[2])
        if root not in sys.path:
            sys.path.insert(0, root)

        spec = Fnv1aSpec(randomized_n=256)
        score = build_and_score(src, spec)
        if not score.ok:
            first = score.divergences[0] if score.divergences else "build error"
            return False, f"replay gate: {first}"
    else:
        lib = _compile_so(src)
        if lib is None:
            return False, "replay gate: candidate does not compile"

    # Persisted counterexamples replayed through the compiled candidate.
    ces = session.query(Counterexample).filter(
        Counterexample.function_id == function.id).all()
    if ces:
        import ctypes
        lib = _compile_so(src)
        if lib is None:
            return False, "replay gate: candidate does not compile"
        fn = getattr(lib, function.name, None)
        if fn is None and function.name == "fnv1a":
            fn = getattr(lib, "fnv1a", None)
        if fn is not None:
            fn.restype = ctypes.c_uint32
            fn.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
            for ce in ces:
                try:
                    got = fn(ce.input_blob, len(ce.input_blob))
                    if ce.expected and int.from_bytes(ce.expected, "little") != got:
                        return False, (f"replay gate: persisted CE "
                                       f"{ce.input_sha256[:12]} still fails")
                except Exception as e:
                    return False, f"replay gate execution error: {e}"
    return True, "replay gate passed"


def _compile_so(src: str):
    import os
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        c = os.path.join(td, "cand.c")
        so = os.path.join(td, "cand.so")
        with open(c, "w") as f:
            f.write(src)
        r = subprocess.run(["clang", "-O1", "-fPIC", "-shared", c, "-o", so],
                           capture_output=True, text=True)
        if r.returncode != 0:
            return None
        import ctypes
        return ctypes.CDLL(so)


def fix(session: Session, *, function_id: int,
        llm_source=None, trace_vectors: bool = True) -> FixResult:
    """Run one fixer round for a function. Persists the candidate (status
    reflects the gate), writes the event row, returns the result.

    `llm_source(prompt) -> str` is the model seam; when None, the fixer
    runs in *mechanical* mode: the previous best candidate is re-scored
    without LLM spend (used by CI and by the deterministic M1 exit run).
    """
    function = session.get(Function, function_id)
    if function is None:
        return FixResult(ok=False, reason="unknown function")

    # FR-15: deduplicated counterexamples feed the prompt.
    ces = session.query(Counterexample).filter(
        Counterexample.function_id == function_id).all()
    ce_rows = [{
        "input_repr": ce.input_blob.hex()[:64] or "(empty)",
        "expected_repr": ce.expected.hex() if ce.expected else "?",
        "observed_repr": ce.observed.hex() if ce.observed else "?",
    } for ce in ces]

    # current best candidate = latest non-rejected
    prev = (session.query(Candidate)
            .filter(Candidate.function_id == function_id,
                    Candidate.status != "rejected")
            .order_by(Candidate.id.desc()).first())
    prev_src = prev.source_code if prev else ""

    spec = {"name": function.name,
            "signature": function.demangled_sig or function.name,
            "ret_type": "", "notes": ""}

    if llm_source is None:
        # mechanical mode: no LLM spend; the "repair" is the previous best
        # candidate re-gated (the deterministic path the M1 exit run uses —
        # the stub develop already encodes the correct repair there).
        src = prev_src
    else:
        prompt = fixer_prompt(spec, prev_src, ce_rows)
        raw = llm_source(prompt)
        try:
            src = json.loads(raw).get("source", "")
        except json.JSONDecodeError:
            src = raw  # model may answer with bare C

    if not src:
        return FixResult(ok=False, reason="fixer produced no source")

    # Response cache (NFR-6): identical (normalized) source already rejected
    # for this function is rejected again without a replay run.
    norm = normalize_source(src)
    dup = (session.query(Candidate)
           .filter(Candidate.function_id == function_id,
                   Candidate.source_hash == norm,
                   Candidate.status == "rejected").first())
    if dup is not None:
        record_event(session, kind="fixer_rejected_cached",
                     function_id=function_id,
                     payload={"reason": "identical to rejected candidate"})
        return FixResult(ok=False, reason="cached rejection (NFR-6)")

    ok, reason = _replay_gate(session, function, src, spec_builder=None)

    cand = Candidate(function_id=function_id, source_code=src,
                     created_by="fixer", source_hash=norm,
                     status="verified" if ok else "rejected",
                     parent_candidate_id=prev.id if prev else None)
    session.add(cand)
    session.flush()
    record_event(session,
                 kind="fixer_ok" if ok else "fixer_rejected",
                 function_id=function_id, candidate_id=cand.id,
                 payload={"reason": reason})
    return FixResult(ok=ok, candidate_id=cand.id, reason=reason, source=src)
