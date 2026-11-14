"""humpty.king.todotree — a live TODO tree that tracks pipeline phases.

The operator sees the actual step checklist (same ☐/☑ language as the todo
panel) rendered live: the current phase is ☐ with a spinner, finished
phases flip to ☑, and per-step bars can hang off nodes. Streamed backend
messages go into a bordered box under the tree.

    with TodoTree(console, groups=[...]) as tt:
        tt.start_phase("I", "Ghidra export: ...")     # ☐ live
        tt.finish_phase("I", "Ghidra export: ...")    # flips to ☑
        tt.bar("I", "ingest rows", total=N)           # per-node bar
        tt.message("importing lpex2 (34 MB)")         # streamed box

Groups mirror the todo panel (roman numerals, per-group n/m counters).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (BarColumn, Progress, TaskProgressColumn,
                           TextColumn, TimeElapsedColumn)
from rich.tree import Tree

__all__ = ["TodoTree"]


@dataclass
class PhaseNode:
    group: str
    text: str
    state: str = "pending"   # pending | active | done | skipped | failed
    bar_task: int | None = None


class TodoTree:
    # (substring, phase label) — from a real 34MB import log
    _GHIDRA_PHASES = [
        ("Creating project", "project"),
        ("IMPORTING:", "import"),
        ("REPORT: Processing input files", "processing inputs"),
        ("ANALYZING all memory and code", "auto-analysis"),
        ("Applied data type archive", "datatype archives"),
        ("Packed database cache", "db cache"),
        ("analysis succeeded", "analysis done"),
        ("REPORT: Execute script", "export script"),
        ("REPORT: Export succeeded", "export done"),
    ]

    def __init__(self, console: Console, groups: list[tuple[str, str, list[str]]],
                 messages_height: int = 6):
        """groups: [(id, title, [phase texts])]."""
        self.console = console
        self.groups = groups
        self.nodes: dict[tuple[str, str], PhaseNode] = {}
        for gid, _, phases in groups:
            for ph in phases:
                self.nodes[(gid, ph)] = PhaseNode(group=gid, text=ph)
        self.msgs: list[str] = []
        self.msg_height = messages_height
        self._t0 = time.time()

        self._progress = Progress(
            TextColumn("      {task.description}"),
            BarColumn(bar_width=18), TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console)
        self._bar_ids: dict[tuple[str, str], int] = {}

        self._live: Live | None = None

    # -- tree rendering ------------------------------------------------------

    def _render_tree(self):
        root = Tree("TODO")
        total_done = 0
        total_all = 0
        for gid, title, phases in self.groups:
            nodes = [self.nodes[(gid, p)] for p in phases]
            done = sum(1 for n in nodes if n.state == "done")
            total_done += done
            total_all += len(nodes)
            branch = root.add(f"[bold]{gid}. {title}[/bold] · {done}/{len(nodes)}")
            for n in nodes:
                if n.state == "done":
                    branch.add("[green]☑[/green] " + n.text)
                elif n.state == "active":
                    branch.add("[yellow]☐[/yellow] " + n.text)
                elif n.state == "failed":
                    branch.add("[red]☒[/red] " + n.text)
                else:
                    branch.add("[dim]☐[/dim] " + n.text)
                if n.bar_task is not None:
                    t = self._progress.tasks[n.bar_task]
                    frac = (t.completed / t.total) if t.total else 0
                    filled = int(14 * frac)
                    bar = "█" * filled + "░" * (14 - filled)
                    pct = f"{frac * 100:5.1f}%"
                    branch.add(f"[cyan]{bar}[/cyan] {pct}")
        head = f"TODO · {total_done}/{total_all} · {time.time()-self._t0:.0f}s"
        root.label = head
        return root

    def _render_msgs(self):
        shown = self.msgs[-self.msg_height:]
        body = "\n".join(shown) if shown else "[dim](no messages yet)[/dim]"
        return Panel(body, title="messages", border_style="dim",
                     height=self.msg_height + 2)

    # -- public API ----------------------------------------------------------

    def __enter__(self):
        self._live = Live(self._composite(), console=self.console,
                          refresh_per_second=8)
        self._live.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        # final render: tree + messages stay in scrollback
        self._live.update(Group(self._render_tree(), self._render_msgs()))
        self._live.stop()
        return False

    def _composite(self):
        return Group(self._render_tree(), self._render_msgs())

    def _refresh(self):
        if self._live:
            self._live.update(self._composite())

    def start_phase(self, gid: str, text: str) -> None:
        n = self.nodes.get((gid, text))
        if n:
            n.state = "active"
            if n.bar_task is not None:
                self._progress.reset(n.bar_task)
        self._refresh()

    def finish_phase(self, gid: str, text: str, ok: bool = True) -> None:
        n = self.nodes.get((gid, text))
        if n:
            n.state = "done" if ok else "failed"
        self._refresh()

    def skip_phase(self, gid: str, text: str) -> None:
        n = self.nodes.get((gid, text))
        if n:
            n.state = "skipped"
        self._refresh()

    def bar(self, gid: str, text: str, *, total: int,
            description: str = "") -> None:
        n = self.nodes.get((gid, text))
        if n:
            n.bar_task = self._progress.add_task(
                description or text, total=total)
            self._bar_ids[(gid, text)] = n.bar_task
        self._refresh()

    def advance(self, gid: str, text: str, n: int = 1) -> None:
        tid = self._bar_ids.get((gid, text))
        if tid is not None:
            self._progress.advance(tid, n)
            self._refresh()

    def message(self, text: str) -> None:
        self.msgs.append(text)
        self._refresh()

    def feed_ghidra(self, line: str) -> None:
        """Map an analyzeHeadless stdout line to the matching group-I todo
        node (☐ → ☑) using the real phase substrings from a 34MB import."""
        for pattern, label in self._GHIDRA_PHASES:
            if pattern in line:
                # find the group-I node whose text mentions this phase
                for (gid, text), node in self.nodes.items():
                    if gid == "I" and label.split()[0].lower() in text.lower():
                        self.start_phase(gid, text)
                        self.finish_phase(gid, text)
                        self.message(f"{label} — {line.strip()[:70]}")
                        return
