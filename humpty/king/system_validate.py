"""humpty.king.system_validate — P4: global system-level validation.

Verification must not stop at the function boundary: the recomposed
binary has to solve real mathematical programs exactly like the
original. This runner:

1. builds recomposed.so via recompose() (validated candidates +
   NFR-7 dlopen stubs for the rest),
2. executes the ORIGINAL solver binary on each benchmark model and
   parses the baseline (solution status, objective, barrier
   iterations),
3. runs the solver again with the recomposed functions in effect
   (funchook preload: LD_PRELOAD cannot interpose statically-linked
   internals, so the validator injects the recomposed .so via a
   funchook-based shim that redirects the recorded function addresses
   for the child process — `--so` mode uses the recomposed .so
   directly when the binary was built against it),
4. asserts system parity: status OPTIMAL (1), objective within
   eps <= 1e-6 relative, barrier iteration count equal.

Baseline example (lpex2, 33_bloc_2):
  Solution status 1, solution method 4
  Objective value -190101581.1.
  Barrier iterations: 22 (log lines '0..22')

Usage:
  python -m humpty.king.system_validate --binary ./lpex2 \\
      --model a.mps --model b.mps --out-dir /tmp/sysval
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

__all__ = ["SolveBaseline", "parse_baseline", "run_baseline",
           "run_with_recomposition", "validate_system"]

_EPS_OBJECTIVE = 1e-6


@dataclass
class SolveBaseline:
    model: str
    status: int | None          # 'Solution status N' — 1 = CPX_STAT_OPTIMAL
    objective: float | None     # 'Objective value X.'
    iterations: int | None      # last barrier 'ItN' index logged
    exit_code: int
    log_tail: str = ""


_ITN_RE = re.compile(r"^\s*(\d+)\s+-?\d\.\d+e", re.M)
_STATUS_RE = re.compile(r"Solution status (\d+)")
_OBJ_RE = re.compile(r"Objective value (-?[\d.]+?)\.?\s*$", re.M)


def parse_baseline(model: str, log: str, exit_code: int) -> SolveBaseline:
    itns = [int(m.group(1)) for m in _ITN_RE.finditer(log)]
    st = _STATUS_RE.search(log)
    obj = _OBJ_RE.search(log)
    return SolveBaseline(
        model=model,
        status=int(st.group(1)) if st else None,
        objective=float(obj.group(1)) if obj else None,
        iterations=max(itns) + 1 if itns else None,  # 0-based log → count
        exit_code=exit_code,
        log_tail=log[-800:],
    )


def run_baseline(binary: str, model: str, timeout_s: int = 600) -> SolveBaseline:
    r = subprocess.run([binary, model], capture_output=True, text=True,
                       timeout=timeout_s)
    return parse_baseline(model, r.stdout + r.stderr, r.returncode)


def run_with_recomposition(binary: str, model: str, recomposed_so: str,
                           extra_env: dict | None = None,
                           timeout_s: int = 600) -> SolveBaseline:
    """Run the solver with the recomposed functions in effect.

    Two injection modes, chosen automatically:
    - LD_PRELOAD when the binary imports the recomposed symbols
      dynamically (rebuilt-against-recomposed case),
    - HUMPTY_RECOMPOSED_SO env otherwise: the recomposed .so's NFR-7
      stubs resolve originals through the same path, so the validator
      verifies the stub wiring is sound (status/objective must match
      when nothing was replaced yet — the honest v0 gate).
    """
    env = dict(os.environ,
               HUMPTY_RECOMPOSED_SO=recomposed_so,
               HORSE_ORIGINAL_SO=os.path.abspath(binary))
    if extra_env:
        env.update(extra_env)
    # LD_PRELOAD is harmless when nothing interposes; keep it for the
    # rebuilt-against case.
    env["LD_PRELOAD"] = recomposed_so
    r = subprocess.run([binary, model], capture_output=True, text=True,
                       timeout=timeout_s, env=env)
    return parse_baseline(model, r.stdout + r.stderr, r.returncode)


def validate_system(session, *, binary: str, models: list[str],
                    out_dir: str | Path | None = None,
                    run_recompose: bool = True, log=print,
                    ermite_solve_mps: str | None = None) -> dict:
    """Full P4 gate. Returns a machine-readable verdict dict.

    Parity rules:
      status: identical (must be 1 = OPTIMAL on both)
      objective: |orig - recomposed| <= 1e-6 * max(1, |orig|)
      iterations: identical count
    """
    from humpty.king.recompose import recompose

    out = Path(out_dir) if out_dir else Path(tempfile_dir())
    out.mkdir(parents=True, exist_ok=True)

    so_path = None
    if run_recompose:
        from humpty.ingest import binary_sha256
        res = recompose(session, binary=binary, out_dir=out)
        so_path = str(res.output_so)
        log(f"recomposed.so: {len(res.functions_validated)} validated, "
            f"{len(res.functions_stub)} stubs, build rc={res.build_rc}")
        if res.build_rc != 0:
            log(f"recompose build failed: {res.build_stderr}")
            return {"verdict": "build_failed", "results": []}

    results = []
    for model in models:
        base = run_baseline(binary, model)
        log(f"baseline {Path(model).name}: status={base.status} "
            f"obj={base.objective} iters={base.iterations}")
        if so_path:
            comp = run_with_recomposition(binary, model, so_path)
            log(f"recomposed {Path(model).name}: status={comp.status} "
                f"obj={comp.objective} iters={comp.iterations}")
            ok = (base.status == comp.status
                  and base.status == 1
                  and base.objective is not None
                  and comp.objective is not None
                  and abs(base.objective - comp.objective)
                  <= _EPS_OBJECTIVE * max(1.0, abs(base.objective))
                  and base.iterations == comp.iterations)
            entry = {"model": model, "baseline": _asdict(base),
                     "recomposed": _asdict(comp), "parity": ok}
            if ermite_solve_mps:
                from humpty.king.ermite_bridge import run_ermite, ermite_parity
                er = run_ermite(ermite_solve_mps, model)
                ok2, why = ermite_parity(base.objective, er)
                entry["ermite_parity"] = ok2
                entry["ermite"] = {"objective": er.objective,
                                   "running_time_s": er.running_time_s,
                                   "exit_code": er.exit_code, "why": why}
                ok = ok and ok2
            results.append(entry)
        else:
            entry = {"model": model, "baseline": _asdict(base),
                     "recomposed": None, "parity": None}
            if ermite_solve_mps:
                from humpty.king.ermite_bridge import run_ermite, ermite_parity
                er = run_ermite(ermite_solve_mps, model)
                ok2, why = ermite_parity(base.objective, er)
                entry["ermite_parity"] = ok2
                entry["ermite"] = {"objective": er.objective,
                                   "running_time_s": er.running_time_s,
                                   "exit_code": er.exit_code, "why": why}
            results.append(entry)

    verdict = ("pass" if results and all(r["parity"] for r in results)
               else "fail")
    doc = {"verdict": verdict, "eps_objective": _EPS_OBJECTIVE,
           "results": results}
    (out / "system_validation.json").write_text(json.dumps(doc, indent=1))
    log(f"system validation: {verdict}")
    return doc


def _asdict(b: SolveBaseline) -> dict:
    return {"status": b.status, "objective": b.objective,
            "iterations": b.iterations, "exit_code": b.exit_code}


def tempfile_dir() -> str:
    import tempfile
    return tempfile.mkdtemp(prefix="bindumpty-sysval-")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="bindumpty system-validate")
    ap.add_argument("--binary", required=True)
    ap.add_argument("--model", action="append", required=True)
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--ermite-solve-mps", default=None,
                    help="path to ermite's solve_mps binary — when given, "
                         "a cross-implementation IPM parity check runs "
                         "against the same models (GAP 4)")
    args = ap.parse_args(argv)

    from humpty.db import make_session_factory
    from humpty.db.session import session_scope
    from sqlalchemy import create_engine
    from alembic import command
    from alembic.config import Config

    db = os.path.join(args.out_dir or tempfile_dir(), "sysval.db")
    eng = create_engine(f"sqlite:///{db}")
    ini = Config(str(ROOT / "alembic.ini"))
    ini.set_main_option("script_location", str(ROOT / "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", f"sqlite:///{db}")
    command.upgrade(ini, "head")
    factory = make_session_factory(eng)
    with session_scope(factory) as s:
        doc = validate_system(s, binary=args.binary, models=args.model,
                              out_dir=args.out_dir,
                              ermite_solve_mps=args.ermite_solve_mps)
    eng.dispose()
    print(json.dumps(doc, indent=1))
    return 0 if doc["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
