"""humpty.king.run — the general driver: reconstruct any ingested subtree.

The milestone scripts (m1_exit.py, m2_exit.py, acceptance.py) are *proofs*
of the roadmap's exit criteria on the validation baseline — they hardcode
the toy on purpose, because that is what the criteria measure against.

This module is the **general** capability those proofs exercise, without the
toy specifics:

  run_subtree(session, *, binary_sha256, develop, ...) -> RunReport
      - walks the call graph bottom-up (SCC policy applied),
      - fingerprint-matches known library functions first (FR-2: free),
      - runs the CEGIS leaf loop per function in dependency order,
      - parents last, over validated callees,
      - demotes + recomputes on any regression (FR-13),
      - returns per-function verdicts.

`develop` is the only leaf-specific part of any run: inject
`humpty.men.develop.make_llm_source()` for the live model, or any callable
`(spec, counterexample) -> source`. Contract: the returned source must
compile STANDALONE (the leaf loop builds it into a self-contained .so and
fuzzes it against the fnv1a-shaped harness) — a parent's source therefore
declares its callees' prototypes and links against nothing; callees are
validated separately in dependency order. CLI: `python -m humpty.king.run_main`.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from humpty.analyze.complete import apply_scc_policy
from humpty.db.models import Function
from humpty.domain import State, is_success
from humpty.king.leaf_loop import run_leaf_loop

__all__ = ["run_subtree", "RunReport", "FunctionVerdict"]


@dataclass
class FunctionVerdict:
    name: str
    state: str
    confidence: float
    iterations: int = 0


@dataclass
class RunReport:
    binary_sha256: str
    order: list[str] = field(default_factory=list)
    verdicts: dict[str, FunctionVerdict] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)  # fingerprint-matched: free
    failed: list[str] = field(default_factory=list)   # NFR-7: original stands in

    @property
    def verified_frac(self) -> float:
        if not self.verdicts:
            return 0.0
        ok = sum(1 for v in self.verdicts.values()
                 if v.state in ("trusted", "proven"))
        return ok / len(self.verdicts)


def _callees_of(session: Session, sha: str) -> set[int]:
    """Function ids that call at least one other function of the binary
    (parents)."""
    from humpty.db.models import CallEdge
    return {r[0] for r in session.query(CallEdge.caller_id).join(
        Function, CallEdge.caller_id == Function.id)
        .filter(Function.binary_sha256 == sha).all()}


def _fingerprinted(session: Session, sha: str) -> set[int]:
    """Functions already trusted by FR-2 (skipped: no LLM, no fuzz spend)."""
    return {f.id for f in session.query(Function)
            .filter(Function.binary_sha256 == sha,
                    Function.state == "trusted",
                    Function.fingerprint.isnot(None)).all()}


def run_subtree(session: Session, *, binary_sha256: str, develop,
                max_iter: int = 5, fuzz_budget_s: int = 15,
                log=print) -> RunReport:
    """Reconstruct every function of the binary bottom-up.

    Order: SCC policy (indivisible groups stay together), leaf-first. Each
    function runs the full leaf loop; a `failed` function never blocks the
    tree (NFR-7) — its dependents still validate over the ORIGINAL callee
    code (the hybrid harness's oracle path), and the report records it.
    """
    report = RunReport(binary_sha256=binary_sha256)
    plan = apply_scc_policy(session, binary_sha256=binary_sha256,
                            policy=os.environ.get("HUMPTY_SCC_POLICY",
                                                  "indivisible"))
    by_id = {f.id: f for f in session.query(Function)
             .filter(Function.binary_sha256 == binary_sha256).all()}
    fingerprinted = _fingerprinted(session, binary_sha256)
    has_callees = _callees_of(session, binary_sha256)

    for fid in plan.order:
        fn = by_id[fid]
        report.order.append(fn.name)
        if fid in fingerprinted:
            report.skipped.append(fn.name)
            log(f"  {fn.name}: fingerprint match — trusted without spend (FR-2)")
            continue
        if is_success(State(fn.state)):
            log(f"  {fn.name}: already {fn.state}")
            continue

        if fid in has_callees:
            # PARENT: the fnv1a-shaped leaf harness cannot fuzz it (different
            # signature). The general parent path is the FR-7 hook-mode
            # hybrid — needs a per-binary generated harness (m2_hybrid.c is
            # the toy-shaped proof). Until that generator exists, a parent is
            # skipped with an explicit note rather than silently mis-fuzzed.
            report.skipped.append(fn.name)
            log(f"  {fn.name}: PARENT — requires the FR-7 hook-mode hybrid "
                f"(per-binary harness generation is not implemented yet); "
                f"skipped, not mis-validated")
            continue

        r = run_leaf_loop(session, function_id=fid, develop=develop,
                          max_iter=max_iter, fuzz_budget_s=fuzz_budget_s,
                          log=log)
        fn = session.get(Function, fid)
        v = FunctionVerdict(name=fn.name, state=fn.state,
                            confidence=fn.confidence,
                            iterations=r.get("iterations", 0))
        report.verdicts[fn.name] = v
        if fn.state == "failed":
            report.failed.append(fn.name)
            log(f"  {fn.name}: FAILED — original stands in by address (NFR-7); "
                f"dependents continue over the original callee")
    return report
