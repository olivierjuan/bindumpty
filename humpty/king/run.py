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

import json
import os
import tempfile
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from humpty.analyze.complete import apply_scc_policy
from humpty.db.events import record_event
from humpty.db.models import CallEdge, Candidate, Function
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
                binary_path: str | None = None, cg_json_path: str | None = None,
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
            # PARENT: validated through the GENERATED per-binary hook-mode
            # harness (FR-6/FR-7) — candidate parent over ORIGINAL callees
            # vs the original parent oracle.
            if not cg_json_path:
                report.skipped.append(fn.name)
                log(f"  {fn.name}: PARENT — no call-graph file supplied for "
                    f"harness generation; skipped")
                continue
            try:
                v = _validate_parent(session, binary=binary_path,
                                     binary_sha256=binary_sha256,
                                     cg_json=cg_json_path,
                                     function_id=fid, develop=develop,
                                     max_iter=max_iter,
                                     fuzz_budget_s=fuzz_budget_s, log=log)
                report.verdicts[fn.name] = v
                if v.state == "failed":
                    report.failed.append(fn.name)
                continue
            except Exception as e:  # noqa: BLE001
                report.skipped.append(fn.name)
                log(f"  {fn.name}: PARENT validation failed ({e}) — skipped")
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


def _validate_parent(session: Session, *, binary: str, binary_sha256: str,
                     cg_json: str, function_id: int, develop,
                     max_iter: int, fuzz_budget_s: int, log=print) -> FunctionVerdict:
    """Validate a PARENT through the generated per-binary hook-mode harness
    (FR-6/FR-7): candidate parent over ORIGINAL callees vs the original
    parent, fuzzed by libFuzzer. This is the path run_subtree routes
    parents to once the harness generator exists."""
    import json as _json
    import subprocess

    from humpty.db.models import Candidate
    from humpty.king.harness_gen import generate_harness

    fn = session.get(Function, function_id)
    td = tempfile.mkdtemp(prefix="bindumpty-parent-",
                          suffix=f"-{fn.name}")
    cg = os.path.join(td, "cg.json")
    all_fns = session.query(Function).filter(
        Function.binary_sha256 == binary_sha256).all()
    all_edges = session.query(CallEdge).join(
        Function, CallEdge.caller_id == Function.id).filter(
        Function.binary_sha256 == binary_sha256).all()
    doc = {"format": "fuz.call-graph/1",
           "binary": {"sha256": binary_sha256, "arch": "x86-64", "kind": "elf"},
           "functions": [{"name": f.name, "address": f"0x{f.address:x}",
                          "size": f.size, "demangled_sig": f.demangled_sig}
                         for f in all_fns],
           "edges": [{"caller": session.get(Function, e.caller_id).name,
                      "callee": session.get(Function, e.callee_id).name,
                      "kind": e.kind} for e in all_edges],
           "sccs": [], "topological_order": []}
    with open(cg, "w") as f:
        json.dump(doc, f)

    # candidate source: a previously verified candidate, or a fresh develop
    # call (the LLM/deterministic seam) — the parent needs SOME candidate to
    # diff against the original
    # SELF-CONTAINMENT GATE: the candidate source must compile standalone
    # (its callees are the validated leaves it may call). A source that
    # doesn't compile alone would link against arbitrary symbols — silent
    # mis-validation. Register-passed functions (main) fail here honestly.
    verified_candidate = (session.query(Candidate)
                          .filter(Candidate.function_id == function_id,
                                  Candidate.status.in_(("trusted", "verified")))
                          .order_by(Candidate.id.desc()).first())
    if verified_candidate:
        cand_src = verified_candidate.source_code
    else:
        spec = {"name": fn.name, "signature": fn.demangled_sig or fn.name,
                "ret_type": "", "notes": ""}
        cand_src = develop(spec, None)
    probe = os.path.join(td, "cand_alone.c")
    with open(probe, "w") as f:
        f.write(cand_src)
    r = subprocess.run(["clang", "-O1", "-c", probe, "-o",
                        os.path.join(td, "cand_alone.o")],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        record_event(session, kind="parent_candidate_not_selfcontained",
                     function_id=function_id,
                     payload={"error": r.stderr[-300:]})
        log(f"  {fn.name}: candidate source not self-contained — cannot "
            f"validate honestly (this is a develop-seam quality issue)")
        return FunctionVerdict(name=fn.name, state="pending",
                               confidence=0.0, iterations=0)

    h = generate_harness(cg, binary, os.path.join(td, "harness"),
                         root_symbol=fn.name, root_candidate_src=cand_src)
    # build: candidate + harness
    build = os.path.join(td, "build.sh")
    cand_ref = f'"{h.candidate_c}"' if h.candidate_c else ""
    with open(build, "w") as f:
        f.write(f"""#!/usr/bin/env bash
set -euo pipefail
clang -O1 -g -fsanitize=fuzzer,address -D_GNU_SOURCE \\
  "{h.harness_c}" {cand_ref} \\
  -o "{td}/harness_bin"
""")
    os.chmod(build, 0o755)
    r = subprocess.run([build], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        record_event(session, kind="parent_harness_build_failed",
                     function_id=function_id, payload={"err": r.stderr[-300:]})
        log(f"  {fn.name}: parent harness build failed — skipped "
            f"(register-passed functions like main cannot be fuzz-validated "
            f"this way)")
        return FunctionVerdict(name=fn.name, state="pending",
                               confidence=0.0, iterations=0)

    r = subprocess.run([os.path.join(td, "harness_bin"),
                        os.path.join(td, "corpus"), "-max_total_time=0",
                        "-runs=10000"],
                       capture_output=True, text=True, timeout=300)
    out = r.stdout + r.stderr
    state = "trusted" if "DIVERGENCE" not in out else "divergent"
    cand = Candidate(function_id=function_id,
                     source_code=cand_src or "", created_by="dev",
                     status="trusted" if state == "trusted" else "diverged")
    session.add(cand)
    session.flush()
    fn.state = state
    fn.confidence = 1.0 if state == "trusted" else 0.0
    record_event(session, kind="parent_validated" if state == "trusted"
                 else "parent_divergent", function_id=function_id,
                 candidate_id=cand.id)
    return FunctionVerdict(name=fn.name, state=state, confidence=fn.confidence,
                           iterations=1)
