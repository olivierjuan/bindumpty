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


def make_dashboard_layout(snap: dict, events: list[dict]) -> Any:
    """Render a full Rich Layout terminal dashboard."""
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=4),
        Layout(name="body", ratio=1),
        Layout(name="events", size=10),
    )

    # Header
    total = max(snap.get("functions_total", 0), 1)
    trusted = snap.get("by_state", {}).get("trusted", 0) + snap.get("by_state", {}).get("proven", 0)
    pct = (trusted / total) * 100
    bar_width = 30
    filled = int(bar_width * (trusted / total))
    bar_str = "█" * filled + "░" * (bar_width - filled)

    header_text = Text()
    header_text.append("bindumpty live monitor  ", style="bold white")
    header_text.append(f"[{bar_str}] ", style="bold green")
    header_text.append(f"{pct:.1f}% ({trusted}/{total})\n", style="bold green")
    header_text.append(f"Fuzz Execs: {snap.get('fuzz_execs', 0):,}  |  "
                       f"Divergence Rate: {snap.get('divergence_rate', 0.0):.2%}  |  "
                       f"Graveyard: {snap.get('graveyard_size', 0)}  |  "
                       f"Events: {snap.get('events', 0):,}", style="dim")
    layout["header"].update(Panel(header_text, border_style="blue", title="Status"))

    # Body: 2 columns (State table + Metrics)
    layout["body"].split_row(
        Layout(name="states", ratio=1),
        Layout(name="details", ratio=1),
    )

    tbl = Table(title="Functions by State", expand=True, border_style="dim")
    tbl.add_column("State", style="bold")
    tbl.add_column("Count", justify="right")
    tbl.add_column("Share", justify="right")

    STATE_STYLES = {
        "trusted": "green", "proven": "bold green", "fuzzing": "magenta",
        "developing": "yellow", "repairing": "yellow", "ready": "cyan",
        "pending": "dim", "failed": "red", "divergent": "bold red"
    }

    for st in ("trusted", "proven", "fuzzing", "developing", "repairing", "ready", "pending", "failed", "divergent"):
        cnt = snap.get("by_state", {}).get(st, 0)
        style = STATE_STYLES.get(st, "white")
        share_str = f"{(cnt / total) * 100:.1f}%" if cnt else "-"
        tbl.add_row(Text(st, style=style), str(cnt), share_str)
    layout["body"]["states"].update(tbl)

    detail_table = Table(title="Pipeline Telemetry", expand=True, border_style="dim")
    detail_table.add_column("Metric", style="bold cyan")
    detail_table.add_column("Value", justify="right")
    detail_table.add_row("Total Functions", str(snap.get("functions_total", 0)))
    detail_table.add_row("Verified Depth (Weight)", f"{snap.get('verified_depth', 0.0):.1f}")
    detail_table.add_row("Candidates Generated", str(snap.get("candidates", 0)))
    detail_table.add_row("Persisted Counterexamples", str(snap.get("counterexamples", 0)))
    detail_table.add_row("Fuzz Executions", f"{snap.get('fuzz_execs', 0):,}")
    detail_table.add_row("Total Lifecycle Events", f"{snap.get('events', 0):,}")
    layout["body"]["details"].update(detail_table)

    # Events table
    ev_table = Table(title="Recent Lifecycle Events (Live Stream)", expand=True, border_style="dim")
    ev_table.add_column("Seq", style="dim", width=6)
    ev_table.add_column("Timestamp", style="dim", width=19)
    ev_table.add_column("Event Kind", style="bold", width=26)
    ev_table.add_column("Fn ID", justify="right", width=6)
    ev_table.add_column("Details", style="dim")

    for e in events:
        kind = e.get("kind", "")
        style = "green" if "trusted" in kind else "yellow" if "fuzz" in kind or "develop" in kind else "red" if "fail" in kind else "white"
        ev_table.add_row(
            str(e.get("seq", "")),
            str(e.get("created_at", ""))[:19],
            Text(kind, style=style),
            str(e.get("function_id") or "-"),
            str(e.get("payload") or "")[:60]
        )
    layout["events"].update(ev_table)

    return layout


def live_monitor(db_path: str, poll_s: float = 1.0) -> None:
    """Run an interactive full-screen Live terminal monitor over a bindumpty database."""
    import sqlite3
    from rich.console import Console
    from rich.live import Live

    console = Console()
    con = sqlite3.connect(db_path, timeout=30.0)
    con.row_factory = sqlite3.Row

    with Live(console=console, refresh_per_second=2, screen=True) as live:
        try:
            while True:
                cur = con.cursor()
                cur.execute("SELECT state, count(*) FROM functions GROUP BY state")
                by_state = {r[0]: r[1] for r in cur.fetchall()}
                total = sum(by_state.values())

                cur.execute("SELECT count(*) FROM fuzz_runs")
                cur.execute("SELECT coalesce(sum(exec_count), 0), coalesce(sum(divergences), 0) FROM fuzz_runs")
                fuzz_row = cur.fetchone()
                execs = fuzz_row[0] if fuzz_row else 0
                divs = fuzz_row[1] if fuzz_row else 0

                cur.execute("SELECT count(*) FROM candidates")
                cands = cur.fetchone()[0]
                cur.execute("SELECT count(*) FROM counterexamples")
                ces = cur.fetchone()[0]
                cur.execute("SELECT count(*) FROM graveyard")
                grave = cur.fetchone()[0]
                cur.execute("SELECT count(*) FROM events")
                ev_count = cur.fetchone()[0]

                snap = {
                    "functions_total": total,
                    "by_state": by_state,
                    "verified_depth": float(by_state.get("trusted", 0) + by_state.get("proven", 0)),
                    "verified_frac": (by_state.get("trusted", 0) + by_state.get("proven", 0)) / total if total else 0.0,
                    "fuzz_execs": execs,
                    "divergence_rate": divs / execs if execs else 0.0,
                    "candidates": cands,
                    "counterexamples": ces,
                    "graveyard_size": grave,
                    "events": ev_count,
                }

                cur.execute("SELECT seq, kind, function_id, ts, payload_json FROM events ORDER BY seq DESC LIMIT 6")
                ev_rows = []
                for r in cur.fetchall():
                    ev_rows.append({
                        "seq": r["seq"],
                        "kind": r["kind"],
                        "function_id": r["function_id"],
                        "created_at": str(r["ts"]),
                        "payload": r["payload_json"]
                    })

                layout = make_dashboard_layout(snap, ev_rows)
                live.update(layout)
                time.sleep(poll_s)
        except KeyboardInterrupt:
            pass
        finally:
            con.close()


def main(argv: list[str] | None = None) -> int:
    import argparse
    import os

    ap = argparse.ArgumentParser(prog="bindumpty monitor")
    ap.add_argument("--db", default="./bindumpty-project/runs/20261115-200441-run/run.db",
                    help="path to bindumpty run.db")
    ap.add_argument("--poll", type=float, default=1.0, help="poll interval in seconds")
    args = ap.parse_args(argv)

    if not os.path.exists(args.db):
        print(f"Database not found at {args.db}", file=sys.stderr)
        return 1

    live_monitor(args.db, poll_s=args.poll)
    return 0


if __name__ == "__main__":
    sys.exit(main())
