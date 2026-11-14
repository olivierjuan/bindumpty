"""humpty.king.bus — FR-17: the event bus consumer side.

Producer side lives in humpty.db.events (record_event: append-only,
write-in-transaction). This module is the consumer:

  - ``EventPoller``: cursor-based poller for SQLite and PostgreSQL alike
    (the correctness path — a lost NOTIFY costs latency, never correctness).
  - ``make_listen_thread``: PostgreSQL LISTEN/NOTIFY wake-up (the latency
    path), running in a daemon thread; every wake simply triggers an
    immediate poll.

Consumers register handlers by event kind (e.g. the ready-set recomputer
listens for ``state:*`` and ``fixer_ok``/``fixer_rejected``). Handlers run
inline in poll order (seq ASC) — the bus guarantees *at-least-once* and
*in-order per cursor*; handlers must be idempotent (they mutate the same
DB the events describe).
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from humpty.db.models import Event

__all__ = ["EventPoller", "make_listen_thread"]

Handler = Callable[[dict[str, Any]], None]


@dataclass
class _Reg:
    kinds: tuple[str, ...] | None  # None = all kinds
    fn: Handler


class EventPoller:
    """Cursor-based, in-order event consumer (FR-17 correctness path)."""

    def __init__(self, url: str, *, cursor_file: str | None = None):
        self._engine = create_engine(url)
        self._S = sessionmaker(bind=self._engine)
        self._handlers: list[_Reg] = []
        self._cursor = 0
        self._cursor_file = cursor_file
        if cursor_file and os.path.exists(cursor_file):
            with open(cursor_file) as f:
                self._cursor = int(f.read().strip() or 0)

    def on(self, kinds: tuple[str, ...] | None, fn: Handler) -> None:
        self._handlers.append(_Reg(kinds=kinds, fn=fn))

    def poll_once(self, limit: int = 500) -> int:
        """Deliver up to `limit` events past the cursor in seq order.
        Returns the number delivered; advances the cursor only after all
        handlers for a batch ran without raising."""
        with self._S() as s:
            rows = (s.query(Event)
                    .filter(Event.seq > self._cursor)
                    .order_by(Event.seq.asc())
                    .limit(limit).all())
            batch = [{"seq": r.seq, "kind": r.kind,
                      "function_id": r.function_id,
                      "candidate_id": r.candidate_id,
                      "payload": r.payload_json or {}} for r in rows]
        for ev in batch:
            for reg in self._handlers:
                if reg.kinds is None or ev["kind"] in reg.kinds:
                    reg.fn(ev)
        if batch:
            self._cursor = batch[-1]["seq"]
            self._save_cursor()
        return len(batch)

    def _save_cursor(self) -> None:
        if self._cursor_file:
            with open(self._cursor_file, "w") as f:
                f.write(str(self._cursor))

    def run_forever(self, *, interval_s: float = 1.0) -> None:
        while True:
            n = self.poll_once()
            if n == 0:
                time.sleep(interval_s)


def make_listen_thread(url: str, poll_fn: Callable[[], Any]):
    """PostgreSQL LISTEN/NOTIFY wake-up thread (FR-17 latency path).

    Listens on humpty.events; every notification triggers `poll_fn()`
    immediately. Falls back to a no-op thread on SQLite (the poller alone
    is correct there). Daemon: the process can exit without joining.
    """
    if not url.startswith(("postgresql", "postgres")):
        t = threading.Thread(target=lambda: None, daemon=True)
        t.start()
        return t

    import psycopg

    def _listen() -> None:
        # a dedicated raw connection: LISTEN is connection-scoped
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("LISTEN humpty.events")
            for _ in conn.notifies(timeout=30):
                try:
                    poll_fn()
                except Exception:
                    pass  # wake-ups are latency-only; the poller recovers

    t = threading.Thread(target=_listen, daemon=True)
    t.start()
    return t

