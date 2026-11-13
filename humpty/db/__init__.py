"""humpty.db — the database layer: models, sessions, and the event log.

The database is the single source of truth (WHITEPAPERS.md §6, FR-17).
"""
from humpty.db.events import NotifyFn, make_notifier, record_event
from humpty.db.models import (
    Base,
    CallEdge,
    Candidate,
    CandidateOrigin,
    CandidateStatus,
    Counterexample,
    DivergenceKind,
    EdgeKind,
    Event,
    FuzzRun,
    Function,
    Graveyard,
    Trace,
    TypeRow,
)
from humpty.db.session import make_engine, make_session_factory, session_scope

__all__ = [
    "Base",
    "Function",
    "CallEdge",
    "Candidate",
    "Counterexample",
    "Trace",
    "FuzzRun",
    "TypeRow",
    "Event",
    "Graveyard",
    "EdgeKind",
    "CandidateOrigin",
    "DivergenceKind",
    "CandidateStatus",
    "make_engine",
    "make_session_factory",
    "session_scope",
    "record_event",
    "make_notifier",
    "NotifyFn",
]
