"""humpty.db.events — the append-only event log (FR-17).

The ``events`` table doubles as the message bus. Two rules make it safe as a
bus, not just a log:

1. **Write-in-transaction.** ``record_event`` is always called on the *active*
   session, inside the same transaction as the state change it describes. If
   the transaction rolls back, the event vanishes with it — the table can never
   describe a state that did not commit.
2. **Notify is best-effort.** After commit, a wake-up (PostgreSQL
   ``LISTEN/NOTIFY``) is delivered. A lost notification costs latency, never
   correctness, because a periodic poll (M3) re-reads the table by the ``seq``
   cursor. On SQLite there is no LISTEN/NOTIFY, so the notifier is a no-op and
   the poller is the only wake path.

``seq`` is a per-database monotonically increasing cursor, allocated as
``max(seq)+1`` inside the transaction. Under contention that is a
serialization point, acceptable for v1 (NATS JetStream is the documented scale
exit, FR-17, and does not change this schema).
"""
from __future__ import annotations

from typing import Any, Callable

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from humpty.db.models import Event

__all__ = ["record_event", "make_notifier", "NotifyFn"]

# A notifier wakes consumers after commit. It receives (channel, payload dict)
# and never raises: a lost wake-up is latency, not correctness (see above).
NotifyFn = Callable[[str, dict[str, Any]], None]

CHANNEL = "humpty.events"


def _next_seq(session: Session) -> int:
    result = session.execute(select(func.coalesce(func.max(Event.seq), 0) + 1))
    return int(result.scalar_one())


def record_event(
    session: Session,
    *,
    kind: str,
    function_id: int | None = None,
    candidate_id: int | None = None,
    worker_id: str | None = None,
    payload: dict[str, Any] | None = None,
) -> Event:
    """Append an event row on the active session (same transaction as caller).

    The caller must commit/rollback; this function only builds and adds the row
    so it participates in the caller's transaction. Do not commit here — the
    state change and this row must commit together.
    """
    ev = Event(
        kind=kind,
        function_id=function_id,
        candidate_id=candidate_id,
        worker_id=worker_id,
        payload_json=payload,
        seq=_next_seq(session),
    )
    session.add(ev)
    session.flush()  # assign ev.id without committing
    return ev


def make_notifier(db_url: str, session_factory) -> NotifyFn:
    """Build a NotifyFn for the database at ``db_url``.

    On PostgreSQL it issues ``SELECT pg_notify`` for the latest event seq —
    best-effort, never raises into the caller. On SQLite (M0-M2) it is a no-op;
    consumers are woken by the poller reading ``events.seq``.
    """
    if not db_url.startswith(("postgresql", "postgres")):
        return lambda channel, payload: None

    def _notify(channel: str, payload: dict[str, Any]) -> None:
        try:
            with session_factory() as s:
                s.execute(
                    text("SELECT pg_notify(:c, :p)"),
                    {"c": channel, "p": str(payload.get("seq", ""))},
                )
                s.commit()
        except Exception:
            # Lost notification is fine: the poller catches up by seq.
            pass

    return _notify
