"""humpty.db.session — engine and session factories.

SQLite (WAL) through M2; PostgreSQL from M3 (NFR-4). The URL comes from
config; tests use in-memory or temp-file SQLite.

``session_scope`` is the unit of work: a transaction that commits on success
and rolls back on error. Every state change goes through it so that the
``events`` row and the state change land in the *same* transaction (FR-17).
"""
from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker


def make_engine(url: str, *, echo: bool = False) -> Engine:
    """Create an engine for ``url`` with the pipeline's connection hygiene.

    - SQLite: WAL mode, foreign keys enforced, and a timeout so concurrent
      workers (M3) don't deadlock on a busy lock.
    - PostgreSQL: the default pool is fine; SKIP LOCKED is a query feature,
      not a pool feature.
    """
    if url.startswith("sqlite"):
        engine = create_engine(
            url,
            echo=echo,
            future=True,
            connect_args={"timeout": 30, "check_same_thread": False},
        )
    else:
        engine = create_engine(url, echo=echo, future=True, pool_pre_ping=True)

    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record) -> None:  # pragma: no cover - trivial
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()

    return engine


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@contextmanager
def session_scope(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    """A transactional unit of work. Commit on success, rollback on error."""
    session = session_factory()
    try:
        yield session
        session.commit()
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()


def redact_dsn(url: str) -> str:
    """Mask credentials for logging (NFR-5): never print the DSN password."""
    if "@" not in url:
        return url
    scheme, rest = url.split("://", 1)
    userinfo, hostpart = rest.rsplit("@", 1)
    user = userinfo.split(":", 1)[0]
    return f"{scheme}://{user}:***@{hostpart}"
