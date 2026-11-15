"""humpty.king.ermite_bridge — GAP 4: bridge to the ermite C++ IPM.

bindumpty validates solver internals function-by-function; the final
gate is that the ermite C++ interior-point stack (IPSolverUser) reaches
the same answer on the same model — the cross-implementation parity
the whitepaper's recomposition contract points at.

Contract: run ermite's solve_mps tool (built from
~/ermite/tools/solve_mps.cpp — CLI11 + IPSolverUser, prints
'objective: <float>') on the same .mps that system_validate ran through
lpex2, and assert objective parity within the same relative epsilon.

The ermite build (Conan + CPLEX + faer + Eigen) is a separate repo
concern; this bridge runs the moment that binary exists and is a hard
skip until then — never a silent pass.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

__all__ = ["ErmiteResult", "run_ermite", "ermite_parity"]

_EPS_OBJECTIVE = 1e-6

_OBJ_RE = re.compile(r"objective:\s*(-?[\d.eE+]+)")
_TIME_RE = re.compile(r"running time:\s*([\d.]+)")


@dataclass
class ErmiteResult:
    model: str
    objective: float | None
    running_time_s: float | None
    exit_code: int
    log_tail: str


def run_ermite(solve_mps: str | Path, model: str,
               solver_name: str = "edf_ldlt", timeout_s: int = 600,
               runs: int = 1) -> ErmiteResult:
    """Run ermite's solve_mps on the model and parse its summary."""
    r = subprocess.run([str(solve_mps), str(model),
                        "-s", solver_name, "-n", str(runs)],
                       capture_output=True, text=True, timeout=timeout_s)
    log = r.stdout + r.stderr
    m = _OBJ_RE.search(log)
    t = _TIME_RE.search(log)
    return ErmiteResult(model=model,
                        objective=float(m.group(1)) if m else None,
                        running_time_s=float(t.group(1)) if t else None,
                        exit_code=r.returncode, log_tail=log[-800:])


def ermite_parity(baseline_objective: float | None, ermite: ErmiteResult,
                  eps: float = _EPS_OBJECTIVE) -> tuple[bool, str]:
    """Cross-implementation objective parity.

    Same relative-epsilon rule as system_validate: the two solvers are
    different codebases; only the objective (not iteration counts) is
    expected to match, and only within 1e-6 relative.
    """
    if baseline_objective is None:
        return False, "no baseline objective"
    if ermite.exit_code != 0:
        return False, f"ermite failed rc={ermite.exit_code}"
    if ermite.objective is None:
        return False, "ermite produced no objective"
    delta = abs(baseline_objective - ermite.objective)
    ok = delta <= eps * max(1.0, abs(baseline_objective))
    return ok, f"|Δ|={delta:.6g} (eps_rel={eps:g})"
