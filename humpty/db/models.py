"""humpty.db.models — the single source of truth (WHITEPAPERS.md §6).

SQLAlchemy 2.0 declarative models for the relational schema. SQLite (WAL)
through M2, PostgreSQL from M3. The models are dialect-agnostic:

- ``JSON`` columns use a portable JSON type that becomes ``JSONB`` on
  PostgreSQL (better for the graveyard score vectors and retrieval).
- ``LargeBinary`` for all recorded blobs (args, memory, input, expected).
- String-typed enums everywhere so a row's state is readable in raw SQL and a
  schema change to an enum never migrates existing rows.

Column choices per table are annotated with the whitepaper §6 row they come
from. Columns the whitepaper omits but which are load-bearing are marked
``(+aux)`` and justified:

- ``binary_sha256`` (functions): NFR-2 — a run must be replayable from
  ``(seed, binary, candidate, corpus)``; the binary is identified by its
  content hash, and (binary, address) is the natural identity of a function.
- ``created_at`` / ``updated_at``: NFR-5 observability.
- ``events.id`` is the append-only cursor (FR-17); the table has no UPDATE.
"""
from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy import JSON as _JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# Portable JSON: JSONB on PostgreSQL, plain JSON elsewhere (SQLite through M2).
JSON = _JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# --- Enums (stored as their .value strings) --------------------------------


class EdgeKind(str, enum.Enum):
    DIRECT = "direct"
    INDIRECT = "indirect"
    VIRTUAL = "virtual"


class CandidateOrigin(str, enum.Enum):
    DEV = "dev"
    FIXER = "fixer"


class DivergenceKind(str, enum.Enum):
    RETURN = "return"
    MEMORY = "memory"
    UB = "ub"  # undefined behavior observed on the original side


class CandidateStatus(str, enum.Enum):
    PENDING = "pending"
    COMPILING = "compiling"
    TRACES_PASS = "traces_pass"
    FUZZING = "fuzzing"
    DIVERGED = "diverged"
    TRUSTED = "trusted"
    PROVEN = "proven"
    GRAVEYARD = "graveyard"


# --- Tables ----------------------------------------------------------------


class Function(Base):
    """``functions`` — one row per function in the binary (§6)."""

    __tablename__ = "functions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # (+aux) which binary this row belongs to (NFR-2 replay identity).
    binary_sha256: Mapped[str] = mapped_column(String(64), index=True)
    address: Mapped[int] = mapped_column(BigInteger, index=True)
    size: Mapped[int | None] = mapped_column(Integer)
    demangled_sig: Mapped[str | None] = mapped_column(Text)
    has_rtti: Mapped[bool] = mapped_column(Boolean, default=False)
    scc_id: Mapped[int | None] = mapped_column(Integer, index=True)
    # Lifecycle state (humpty.domain.State.value) and its confidence score.
    state: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    confidence: Mapped[float] = mapped_column(default=0.0)
    # Transitive dependent (caller) count, maintained by the king (FR-14).
    dependents_count: Mapped[int] = mapped_column(Integer, default=0)
    # Fingerprint match (FR-2): the real function a match maps to, if any.
    fingerprint: Mapped[str | None] = mapped_column(String(255))
    # (+aux)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    __table_args__ = (
        UniqueConstraint("binary_sha256", "address", name="uq_functions_binary_address"),
        Index("ix_functions_state", "state"),
    )

    # Relationships
    outgoing_edges: Mapped[list["CallEdge"]] = relationship(
        back_populates="caller", foreign_keys="CallEdge.caller_id"
    )
    incoming_edges: Mapped[list["CallEdge"]] = relationship(
        back_populates="callee", foreign_keys="CallEdge.callee_id"
    )
    candidates: Mapped[list["Candidate"]] = relationship(back_populates="function")
    traces: Mapped[list["Trace"]] = relationship(back_populates="function")
    counterexamples: Mapped[list["Counterexample"]] = relationship(back_populates="function")
    graveyard: Mapped[list["Graveyard"]] = relationship(back_populates="function")


class CallEdge(Base):
    """``call_edges`` — edges of the call tree (§6)."""

    __tablename__ = "call_edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    caller_id: Mapped[int] = mapped_column(ForeignKey("functions.id"), index=True)
    callee_id: Mapped[int] = mapped_column(ForeignKey("functions.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16), default="direct")

    caller: Mapped["Function"] = relationship(back_populates="outgoing_edges", foreign_keys=[caller_id])
    callee: Mapped["Function"] = relationship(back_populates="incoming_edges", foreign_keys=[callee_id])

    __table_args__ = (
        UniqueConstraint("caller_id", "callee_id", "kind", name="uq_call_edges"),
    )


class Candidate(Base):
    """``candidates`` — proposed reimplementations (§6)."""

    __tablename__ = "candidates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    function_id: Mapped[int] = mapped_column(ForeignKey("functions.id"), index=True)
    source_code: Mapped[str] = mapped_column(Text)
    llvm_ir: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(16))  # dev | fixer
    # Lineage: which candidate this fix derives from (CEGIS chain).
    parent_candidate_id: Mapped[int | None] = mapped_column(ForeignKey("candidates.id"))
    sampling_seed: Mapped[int | None] = mapped_column(BigInteger)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    # (+aux) normalized source hash for graveyard dedup (FR-18).
    source_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    function: Mapped["Function"] = relationship(back_populates="candidates")
    fuzz_runs: Mapped[list["FuzzRun"]] = relationship(back_populates="candidate")


class Counterexample(Base):
    """``counterexamples`` — divergent inputs (§6)."""

    __tablename__ = "counterexamples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    function_id: Mapped[int] = mapped_column(ForeignKey("functions.id"), index=True)
    candidate_id: Mapped[int | None] = mapped_column(ForeignKey("candidates.id"))
    input_blob: Mapped[bytes] = mapped_column(LargeBinary)
    expected: Mapped[bytes | None] = mapped_column(LargeBinary)
    observed: Mapped[bytes | None] = mapped_column(LargeBinary)
    kind: Mapped[str] = mapped_column(String(16))  # return | memory | ub
    minimized: Mapped[bool] = mapped_column(Boolean, default=False)
    # (+aux) for dedup and NFR-2 deterministic reproducibility.
    input_sha256: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    function: Mapped["Function"] = relationship(back_populates="counterexamples")

    __table_args__ = (
        UniqueConstraint("function_id", "candidate_id", "input_sha256", name="uq_counterex"),
    )


class Trace(Base):
    """``traces`` — recorded I/O (record-replay, FR-3, §6)."""

    __tablename__ = "traces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    function_id: Mapped[int] = mapped_column(ForeignKey("functions.id"), index=True)
    args_blob: Mapped[bytes] = mapped_column(LargeBinary)
    mem_read: Mapped[bytes | None] = mapped_column(LargeBinary)
    ret: Mapped[bytes | None] = mapped_column(LargeBinary)
    mem_written: Mapped[bytes | None] = mapped_column(LargeBinary)
    # (+aux) which input-set / seed produced this trace (NFR-2).
    seed: Mapped[int | None] = mapped_column(BigInteger)
    input_sha256: Mapped[str | None] = mapped_column(String(64), index=True)

    function: Mapped["Function"] = relationship(back_populates="traces")


class FuzzRun(Base):
    """``fuzz_runs`` — fuzzing campaigns (§6)."""

    __tablename__ = "fuzz_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    candidate_id: Mapped[int] = mapped_column(ForeignKey("candidates.id"), index=True)
    engine: Mapped[str] = mapped_column(String(16))  # libfuzzer | afl
    coverage: Mapped[int | None] = mapped_column(Integer)
    exec_count: Mapped[int] = mapped_column(BigInteger, default=0)
    divergences: Mapped[int] = mapped_column(Integer, default=0)
    duration: Mapped[float | None] = mapped_column()  # seconds
    started_at: Mapped[datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column()

    candidate: Mapped["Candidate"] = relationship(back_populates="fuzz_runs")


class TypeRow(Base):
    """``types`` — reconstructed layouts (FR-12, §6).

    Named ``TypeRow`` (not ``Type``) to avoid shadowing the builtin.
    """

    __tablename__ = "types"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    layout_json: Mapped[dict] = mapped_column(JSON)
    owner_worker: Mapped[str | None] = mapped_column(String(128))
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_types_name_version"),
    )


class Event(Base):
    """``events`` — append-only event log and job notifications (FR-17, §6).

    This is the message bus *and* the audit trail. Rows are never updated or
    deleted; a worker writes the row in the same transaction as the state
    change it describes, then a NOTIFY (PostgreSQL) or poll wakes consumers.
    ``payload_json`` carries no payload *of record* — the table is the truth.
    """

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(default=utcnow)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    function_id: Mapped[int | None] = mapped_column(ForeignKey("functions.id"), index=True)
    candidate_id: Mapped[int | None] = mapped_column(ForeignKey("candidates.id"))
    payload_json: Mapped[dict | None] = mapped_column(JSON)
    worker_id: Mapped[str | None] = mapped_column(String(128))
    # (+aux) monotonic cursor for consumers tracking progress across restarts.
    seq: Mapped[int] = mapped_column(BigInteger, unique=True)


class Graveyard(Base):
    """``graveyard`` — archive of near-miss candidates (FR-18, §6)."""

    __tablename__ = "graveyard"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    function_id: Mapped[int] = mapped_column(ForeignKey("functions.id"), index=True)
    candidate_id: Mapped[int] = mapped_column(ForeignKey("candidates.id"), index=True)
    # Score vector: trace pass rate, fuzz divergence rate, simplicity.
    score_vector: Mapped[dict] = mapped_column(JSON)
    pareto_rank: Mapped[int | None] = mapped_column(Integer)
    # pgvector at scale; JSON blob in M0-M2 (retrieval is M4).
    embedding: Mapped[list | None] = mapped_column(JSON)
    archived_at: Mapped[datetime] = mapped_column(default=utcnow)
    resurrected_count: Mapped[int] = mapped_column(Integer, default=0)

    function: Mapped["Function"] = relationship(back_populates="graveyard")

    __table_args__ = (
        UniqueConstraint("candidate_id", name="uq_graveyard_candidate"),
    )
