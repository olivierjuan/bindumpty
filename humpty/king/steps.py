"""humpty.king.steps — per-step progress groups for the operator display.

The operator's rule: the CURRENT pipeline step owns the screen — its
progress bar, its messages, its phase checklist — and closes (with a final
✓ and elapsed time) the moment the next step opens. Implemented over
rich.progress: one Progress context per step, transient for the spinner
lines, persistent for bars, plus a phase checklist fed by backend stdout.

Usage:

    with step("export call graph", backend="ghidra") as st:
        st.phase("headless startup")          # opens a checklist line
        st.phase("auto-analysis")             # marks the previous done
        st.message("importing lpex2 (34 MB)") # plain log line inside the step
        ...
    # on exit: the step closes with ✓ and elapsed

Backend stdout can be streamed: `st.feed(line)` maps INFO lines to phases
(for Ghidra) or increments counters (for objdump/rizin).
"""
from __future__ import annotations

import re
import time
from typing import Any

from rich.console import Console
from rich.progress import (BarColumn, Progress, TaskProgressColumn,
                           TextColumn, TimeElapsedColumn)

__all__ = ["Step", "step"]


class Step:
    """One open pipeline step: a LIVE checkbox list (the current phase shows
    ☐ with a spinner; completed ones ☑), plus bars and messages. On close,
    the checklist commits to the scrollback — each phase on one line."""

    def __init__(self, console: Console, name: str, **meta: Any):
        self.console = console
        self.name = name
        self.meta = meta
        self._t0 = time.time()
        self.phases: list[str] = []          # all declared phases, in order
        self._done_phases: set[str] = set()  # flipped to ☑
        self._current: str | None = None
        self._bars: dict[int, str] = {}      # task id -> bar description
        self._progress = Progress(
            TextColumn("    {task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        )
        self._check_task = self._progress.add_task("☐ …", total=None)
        self._task_id = self._progress.add_task("working", total=None)
        self._lines: list[str] = []
        self._live_started = False

    def __enter__(self) -> "Step":
        self.console.print(f"  [bold blue]{self.name}[/bold blue]")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        elapsed = time.time() - self._t0
        self._progress.stop()
        # commit the final checklist to scrollback: all declared phases,
        # ☑ for completed, ☐ (struck) for never-finished ones
        for p in self.phases:
            if p in self._done_phases and p != self._current:
                self.console.print(f"    [green]☑[/green] {p}")
            elif p == self._current and exc_type is None:
                self.console.print(f"    [green]☑[/green] {p}")
            else:
                self.console.print(f"    [red]☒[/red] {p}")
        mark = "[red]✗[/red]" if exc_type else "[green]✓[/green]"
        self.console.print(f"  {mark} [blue]{self.name}[/blue] "
                           f"({elapsed:.1f}s)")

    def _refresh(self) -> None:
        """Redraw the live checklist line for the current phase."""
        if self._current:
            self._progress.update(self._check_task,
                                  description=f"☐ {self._current} …")

    def phase(self, name: str) -> None:
        """Declare a phase (☐ live). The previous phase flips to ☑."""
        if self._current:
            self._done_phases.add(self._current)
        if name not in self.phases:
            self.phases.append(name)
        self._current = name
        self._refresh()

    def message(self, text: str) -> None:
        self.console.print(f"    [dim]{text}[/dim]")
        self._lines.append(text)

    def bar(self, description: str, total: int | None = None) -> int:
        self._bars[self._task_id] = description
        self._progress.update(self._task_id, description=description,
                              total=total, completed=0)
        return self._task_id

    def advance(self, task_id: int, n: int = 1) -> None:
        self._progress.advance(task_id, n)

    # -- backend stdout feeds ------------------------------------------------

    _GHIDRA_PHASES = [
        ("Headless startup complete", "headless startup"),
        ("Import succeeded", "import"),
        ("INFO  Analyzing", "auto-analysis"),
        ("Analysis succeeded", "auto-analysis complete"),
        ("Execute script", "script export"),
        ("REPORT: Export succeeded", "export"),
    ]

    def feed_ghidra(self, line: str) -> None:
        for pattern, phase in self._GHIDRA_PHASES:
            if pattern in line:
                self.phase(phase)
                return
        if "ERROR" in line:
            self.message(line.strip()[:160])

    def feed_objdump(self, line: str) -> None:
        if re.match(r"^[0-9a-f]+ <", line):
            self.advance(self._task_id, 1)

    def feed_rizin(self, line: str) -> None:
        if line.strip():
            self.advance(self._task_id, 1)


class step:  # noqa: N801 — context manager named lowercase for readability
    """Open a step group on a console."""

    def __init__(self, console: Console, name: str, **meta: Any):
        self._step = Step(console, name, **meta)

    def __enter__(self) -> Step:
        return self._step.__enter__()

    def __exit__(self, exc_type, exc, tb) -> None:
        self._step.__exit__(exc_type, exc, tb)
