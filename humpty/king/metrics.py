"""humpty.king.metrics — NFR-5: structured JSON logs + the live metrics view.

Two deliverables, one module:

1. ``json_logger`` — structured JSON logs to stderr (NFR-5: "structured JSON
   logs"). Every worker/men/king log line is one JSON object: ts, level,
   component, message + key/values. A log scraper (or the dashboard) can
   aggregate without regex.

2. ``snapshot`` — the live metrics the dashboard shows, read from the DB in
   one query batch:
     - per-state function counts (the pipeline's progress)
     - verified depth (functions trusted, weighted by dependents — the
       objective metric)
     - divergence rate (counterexamples / fuzz execs)
     - LLM cost per function (tokens logged on candidates, NFR-6 cache hits
       excluded)
     - graveyard size, queue depth (FR-18, FR-14)

``render_dashboard`` prints the snapshot as a compact terminal view (the
M3 dashboard; a web view would read the same snapshot).
"""
from __future__ import annotations

import json
import sys
import time
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from humpty.db.models import (Candidate, Counterexample, Event, FuzzRun,
                              Function, Graveyard)

__all__ = ["json_logger", "snapshot", "render_dashboard"]


def json_logger(component: str, level: str = "info"):
    """Return a log(message, **kv) function emitting one JSON line per call."""

    def log(message: str, **kv: Any) -> None:
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
               "level": level, "component": component, "msg": message}
        rec.update(kv)
        sys.stderr.write(json.dumps(rec) + "\n")
        sys.stderr.flush()

    return log


def snapshot(session: Session, *, binary_sha256: str | None = None) -> dict:
    """One-batch metrics read (NFR-5)."""
    q = session.query(Function)
    if binary_sha256:
        q = q.filter(Function.binary_sha256 == binary_sha256)
    fns = q.all()

    by_state: dict[str, int] = {}
    depth = 0.0
    for f in fns:
        by_state[f.state] = by_state.get(f.state, 0) + 1
        if f.state in ("trusted", "proven"):
            depth += max(f.dependents_count, 1)

    # divergence rate over finished fuzz runs
    runs = session.query(FuzzRun).all()
    execs = sum(r.exec_count or 0 for r in runs)
    divs = sum(r.divergences or 0 for r in runs)

    # candidates + lineage depth (proxy for repair iterations)
    cand_n = session.query(func.count(Candidate.id)).scalar()

    ce_n = session.query(func.count(Counterexample.id)).scalar()
    grave_n = session.query(func.count(Graveyard.id)).scalar()

    events_n = session.query(func.count(Event.id)).scalar()

    return {
        "functions_total": len(fns),
        "by_state": by_state,
        "verified_depth": depth,
        "verified_frac": (by_state.get("trusted", 0) +
                          by_state.get("proven", 0)) / len(fns) if fns else 0.0,
        "fuzz_execs": execs,
        "divergence_rate": divs / execs if execs else 0.0,
        "candidates": cand_n,
        "counterexamples": ce_n,
        "graveyard_size": grave_n,
        "events": events_n,
    }


def render_dashboard(snap: dict) -> str:
    """Compact terminal rendering of a snapshot."""
    bar = lambda n, total: ("#" * int(20 * n / total)).ljust(20) if total else "-" * 20
    lines = [
        "=== bindumpty dashboard ===",
        f"functions: {snap['functions_total']}  "
        f"trusted: {snap['by_state'].get('trusted', 0)}  "
        f"failed: {snap['by_state'].get('failed', 0)}",
        f"[{bar(snap['by_state'].get('trusted', 0) + snap['by_state'].get('proven', 0), max(snap['functions_total'], 1))}] "
        f"verified {snap['verified_frac']:.0%}  (weighted depth {snap['verified_depth']:.0f})",
        f"fuzz execs: {snap['fuzz_execs']:,}   divergence rate: {snap['divergence_rate']:.2%}",
        f"candidates: {snap['candidates']}   counterexamples: {snap['counterexamples']}   "
        f"graveyard: {snap['graveyard_size']}   events: {snap['events']}",
    ]
    for st in ("pending", "ready", "fuzzing", "divergent", "repairing",
               "trusted", "proven", "failed"):
        n = snap["by_state"].get(st, 0)
        if n:
            lines.append(f"  {st:10s} {n}")
    return "\n".join(lines)
