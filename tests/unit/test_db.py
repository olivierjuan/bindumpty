"""Tests for humpty.db — models, sessions, and the append-only event log.

Exercises:
- the 9-table schema from WHITEPAPERS.md §6 via Alembic (real migration, not
  create_all),
- the FR-17 invariant: an event row commits in the *same* transaction as the
  state change it describes (rollback drops both),
- event ``seq`` monotonicity across commits,
- function identity (binary, address) uniqueness,
- call-edge dedup,
- candidate lineage (parent_candidate_id) and graveyard dedup (FR-18).
"""
import hashlib
import os

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import IntegrityError

from humpty.db import (
    Base,
    CallEdge,
    Candidate,
    Counterexample,
    Event,
    Function,
    Graveyard,
    Trace,
    make_engine,
    make_session_factory,
    record_event,
    session_scope,
)
from humpty.domain import State

EXPECTED_TABLES = {
    "alembic_version",
    "functions",
    "call_edges",
    "candidates",
    "counterexamples",
    "traces",
    "fuzz_runs",
    "types",
    "events",
    "graveyard",
}


@pytest.fixture()
def db_url(tmp_path):
    return f"sqlite:///{tmp_path}/test.db"


@pytest.fixture()
def engine(db_url):
    """Engine with the *migrated* schema (not create_all)."""
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ini = Config(os.path.join(repo_root, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(repo_root, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", db_url)
    eng = create_engine(db_url)
    command.upgrade(ini, "head")
    yield eng
    eng.dispose()


@pytest.fixture()
def factory(engine):
    return make_session_factory(engine)


def test_migration_creates_all_tables(engine):
    insp = inspect(engine)
    assert set(insp.get_table_names()) == EXPECTED_TABLES


def test_function_identity_is_binary_and_address(factory):
    sha = hashlib.sha256(b"toy-case-01").hexdigest()
    with session_scope(factory) as s:
        s.add(Function(binary_sha256=sha, name="fn", address=0x401000, state=State.PENDING.value))
    with pytest.raises(IntegrityError):
        with session_scope(factory) as s:
            s.add(Function(binary_sha256=sha, name="fn", address=0x401000, state=State.PENDING.value))
    # Same address in a *different* binary is fine.
    with session_scope(factory) as s:
        s.add(Function(binary_sha256="0" * 64, name="fn", address=0x401000, state=State.PENDING.value))


def test_call_edge_dedup(factory):
    sha = hashlib.sha256(b"toy").hexdigest()
    with session_scope(factory) as s:
        caller = Function(binary_sha256=sha, name="caller", address=0x1000, state=State.PENDING.value)
        callee = Function(binary_sha256=sha, name="callee", address=0x2000, state=State.PENDING.value)
        s.add_all([caller, callee])
        s.flush()
        s.add(CallEdge(caller_id=caller.id, callee_id=callee.id, kind="direct"))
    with pytest.raises(IntegrityError):
        with session_scope(factory) as s:
            caller_id = s.query(Function).filter_by(address=0x1000).one().id
            callee_id = s.query(Function).filter_by(address=0x2000).one().id
            s.add(CallEdge(caller_id=caller_id, callee_id=callee_id, kind="direct"))


def test_event_commit_is_atomic_with_state_change(factory):
    """FR-17: the event row must die with the state change if the txn fails."""
    sha = hashlib.sha256(b"atomic").hexdigest()
    with session_scope(factory) as s:
        fn = Function(binary_sha256=sha, name="fn", address=0x5000, state=State.PENDING.value)
        s.add(fn)
        s.flush()
        ev = record_event(s, kind="function.created", function_id=fn.id)
        assert ev.id is not None  # flushed, not yet committed
    # Now force a failure in a *new* transaction that touches the same rows
    # and records an event, to prove the event dies with the failed txn.
    with pytest.raises(RuntimeError, match="simulated crash"):
        with session_scope(factory) as s:
            fn = s.query(Function).filter_by(address=0x5000).one()
            fn.state = State.READY.value
            record_event(s, kind="function.ready", function_id=fn.id)
            raise RuntimeError("simulated crash")

    # The first txn committed (fn exists); the second's event did not.
    with session_scope(factory) as s:
        fn = s.query(Function).filter_by(address=0x5000).one()
        assert fn.state == State.PENDING.value  # state change rolled back
        evs = s.query(Event).filter_by(function_id=fn.id).all()
        assert [e.kind for e in evs] == ["function.created"]  # only the first


def test_event_seq_is_monotonic(factory):
    sha = hashlib.sha256(b"seq").hexdigest()
    seqs = []
    for i in range(5):
        with session_scope(factory) as s:
            ev = record_event(s, kind=f"event.{i}", worker_id="test")
            seqs.append(ev.seq)
    assert seqs == sorted(seqs)
    assert len(set(seqs)) == len(seqs)  # no duplicates


def test_state_change_with_event_commits_together(factory):
    sha = hashlib.sha256(b"lifecycle").hexdigest()
    with session_scope(factory) as s:
        fn = Function(binary_sha256=sha, name="fn", address=0x6000, state=State.PENDING.value)
        s.add(fn)
        s.flush()
        fn.state = State.READY.value
        record_event(
            s, kind="function.ready", function_id=fn.id,
            payload={"from": State.PENDING.value, "to": State.READY.value},
        )
    with session_scope(factory) as s:
        fn = s.query(Function).filter_by(address=0x6000).one()
        assert fn.state == State.READY.value
        ev = s.query(Event).filter_by(function_id=fn.id).one()
        assert ev.kind == "function.ready"
        assert ev.payload_json["to"] == "ready"


def test_candidate_lineage_and_source_hash(factory):
    sha = hashlib.sha256(b"lineage").hexdigest()
    with session_scope(factory) as s:
        fn = Function(binary_sha256=sha, name="fn", address=0x7000, state=State.READY.value)
        s.add(fn)
        s.flush()
        dev = Candidate(
            function_id=fn.id, source_code="int f(int x){return x;}",
            created_by="dev", sampling_seed=1,
        )
        s.add(dev)
        s.flush()
        fixer = Candidate(
            function_id=fn.id, source_code="int f(int x){return x+1;}",
            created_by="fixer", parent_candidate_id=dev.id, sampling_seed=2,
        )
        s.add(fixer)
    with session_scope(factory) as s:
        dev = s.query(Candidate).filter_by(created_by="dev").one()
        fixer = s.query(Candidate).filter_by(created_by="fixer").one()
        assert fixer.parent_candidate_id == dev.id
        assert dev.sampling_seed == 1


def test_trace_and_counterexample_blobs_roundtrip(factory):
    sha = hashlib.sha256(b"blobs").hexdigest()
    args = bytes(range(64))
    with session_scope(factory) as s:
        fn = Function(binary_sha256=sha, name="fn", address=0x8000, state=State.PENDING.value)
        s.add(fn)
        s.flush()
        s.add(Trace(function_id=fn.id, args_blob=args, ret=b"\x42"))
        s.add(
            Counterexample(
                function_id=fn.id, input_blob=args, expected=b"\x42",
                observed=b"\x43", kind="return",
                input_sha256=hashlib.sha256(args).hexdigest(),
            )
        )
    with session_scope(factory) as s:
        tr = s.query(Trace).one()
        assert tr.args_blob == args
        assert tr.ret == b"\x42"
        cx = s.query(Counterexample).one()
        assert cx.observed == b"\x43"
        assert cx.kind == "return"


def test_graveyard_dedup_by_candidate(factory):
    """FR-18: a candidate can be archived only once."""
    sha = hashlib.sha256(b"graveyard").hexdigest()
    with session_scope(factory) as s:
        fn = Function(binary_sha256=sha, name="fn", address=0x9000, state=State.DIVERGENT.value)
        s.add(fn)
        s.flush()
        cand = Candidate(function_id=fn.id, source_code="x", created_by="fixer")
        s.add(cand)
        s.flush()
        s.add(Graveyard(
            function_id=fn.id, candidate_id=cand.id,
            score_vector={"trace_pass_rate": 0.9, "fuzz_divergence_rate": 0.1,
                          "simplicity": 0.7},
            pareto_rank=1,
        ))
    with pytest.raises(IntegrityError):
        with session_scope(factory) as s:
            cand = s.query(Candidate).one()
            fn = s.query(Function).one()
            s.add(Graveyard(function_id=fn.id, candidate_id=cand.id,
                            score_vector={"trace_pass_rate": 0.5}))
