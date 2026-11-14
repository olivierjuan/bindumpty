"""humpty.king.queue — FR-14: the PostgreSQL SKIP LOCKED job queue.

Productionizes the S5 probe (verified: 121→742 jobs/s over 1→8 workers,
zero dupes/lost on PG16). Jobs are rows in a dedicated table; a worker
claims with `FOR UPDATE SKIP LOCKED` inside a short transaction, does the
work *outside* the lock, then completes or fails the row.

Job kinds mirror the worker roles (WHITEPAPERS §5):
    develop  — one ready function needs N candidates (FR-4)
    fix      — one divergent candidate needs repair (FR-5)
    fuzz     — one candidate needs a fuzz campaign (FR-6)

SQLite (M0-M2) has no concurrent-writer story, so the queue degrades: it
raises unless the URL is postgres — the roadmap explicitly scopes SQLite
out for M3 orchestration.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Column, Integer, String, Text, DateTime, select, text
from sqlalchemy.orm import Session, declarative_base

from humpty.db.models import utcnow

__all__ = ["Job", "Queue", "QueueError"]

QUEUE_BASE = declarative_base()


class Job(QUEUE_BASE):
    """``king_jobs`` — one unit of orchestrator work (FR-14)."""

    __tablename__ = "king_jobs"

    id: Column[int] = Column(Integer, primary_key=True, autoincrement=True)
    kind: Column[str] = Column(String(16), index=True)  # develop|fix|fuzz
    # opaque payload: function_id, candidate_id, budget, ...
    payload_json: Column[dict] = Column(Text)
    # pending | claimed | done | failed
    status: Column[str] = Column(String(16), index=True, default="pending")
    priority: Column[int] = Column(Integer, default=100)  # lower = first
    claimed_by: Column[str] = Column(String(128), nullable=True)
    claimed_at: Column[datetime | None] = Column(DateTime(timezone=True))
    attempts: Column[int] = Column(Integer, default=0)
    max_attempts: Column[int] = Column(Integer, default=3)
    last_error: Column[str | None] = Column(Text)
    created_at: Column[datetime] = Column(DateTime(timezone=True),
                                          default=utcnow)
    finished_at: Column[datetime | None] = Column(DateTime(timezone=True))

    def payload(self) -> dict[str, Any]:
        return json.loads(self.payload_json)


class QueueError(RuntimeError):
    pass


@dataclass
class Claim:
    job_id: int
    kind: str
    payload: dict
    attempt: int


class Queue:
    """SKIP LOCKED job queue on PostgreSQL (FR-14)."""

    def __init__(self, session_factory, *, worker_id: str, url: str):
        self._sf = session_factory
        self._worker = worker_id
        self._url = url
        self._is_pg = url.startswith(("postgresql", "postgres"))

    def ensure_schema(self, engine) -> None:
        QUEUE_BASE.metadata.create_all(engine)

    def push(self, session: Session, *, kind: str, payload: dict,
             priority: int = 100) -> int:
        if kind not in ("develop", "fix", "fuzz"):
            raise QueueError(f"unknown job kind {kind!r}")
        job = Job(kind=kind, payload_json=json.dumps(payload),
                  priority=priority)
        session.add(job)
        session.flush()
        return job.id

    def claim(self, kinds: tuple[str, ...] = ("develop", "fix", "fuzz"),
              ) -> Claim | None:
        """Claim one pending job (FOR UPDATE SKIP LOCKED). Returns None when
        the queue is empty. The claim commits immediately — the worker then
        runs outside the lock."""
        if not self._is_pg:
            raise QueueError(
                "the FR-14 queue requires PostgreSQL (SQLite is out of scope "
                "for M3 orchestration per the roadmap)")
        kind_list = ", ".join(f"'{k}'" for k in kinds)
        sql = text(f"""
            UPDATE king_jobs SET
                status = 'claimed',
                claimed_by = :worker,
                claimed_at = NOW(),
                attempts = attempts + 1
            WHERE id = (
                SELECT id FROM king_jobs
                WHERE status = 'pending'
                  AND attempts < max_attempts
                  AND kind IN ({kind_list})
                ORDER BY priority ASC, id ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            RETURNING id, kind, payload_json, attempts
        """)
        with self._sf() as s:
            row = s.execute(sql, {"worker": self._worker}).first()
            s.commit()
            if row is None:
                return None
            return Claim(job_id=row[0], kind=row[1],
                         payload=json.loads(row[2]), attempt=row[3])

    def complete(self, job_id: int) -> None:
        with self._sf() as s:
            job = s.get(Job, job_id)
            if job is not None:
                job.status = "done"
                job.finished_at = datetime.now(timezone.utc)
                s.commit()

    def fail(self, job_id: int, error: str) -> bool:
        """Mark failed; re-queues (pending) while attempts remain."""
        with self._sf() as s:
            job = s.get(Job, job_id)
            if job is None:
                return False
            job.last_error = error[:2000]
            if job.attempts >= job.max_attempts:
                job.status = "failed"
                job.finished_at = datetime.now(timezone.utc)
            else:
                job.status = "pending"  # retry
            s.commit()
            return job.status == "pending"

    def stats(self) -> dict[str, int]:
        with self._sf() as s:
            rows = s.execute(
                select(Job.status, text("count(*)")).group_by(Job.status)
            ).all()
            return {status: n for status, n in rows}
