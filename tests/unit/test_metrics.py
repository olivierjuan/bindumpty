"""Unit test for humpty.king.metrics."""
import pytest
from humpty.king.metrics import snapshot, render_dashboard, make_dashboard_layout
from humpty.db import make_session_factory
from humpty.db.session import session_scope
from humpty.db.models import Function, FuzzRun, Candidate, Counterexample, Event
from sqlalchemy import create_engine
from alembic import command
from alembic.config import Config
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def test_db(tmp_path):
    db_file = tmp_path / "test.db"
    eng = create_engine(f"sqlite:///{db_file}")
    ini = Config(str(ROOT / "alembic.ini"))
    ini.set_main_option("script_location", str(ROOT / "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", f"sqlite:///{db_file}")
    command.upgrade(ini, "head")
    factory = make_session_factory(eng)

    with session_scope(factory) as s:
        f1 = Function(binary_sha256="0"*64, name="f1", address=0x1000, size=64, state="trusted", confidence=1.0)
        f2 = Function(binary_sha256="0"*64, name="f2", address=0x2000, size=32, state="pending", confidence=0.0)
        s.add_all([f1, f2])
        s.flush()
        ev = Event(seq=1, kind="state:pending:trusted", function_id=f1.id)
        s.add(ev)

    eng.dispose()
    return factory


def test_metrics_snapshot_and_layout(test_db):
    with session_scope(test_db) as s:
        snap = snapshot(s)

    assert snap["functions_total"] == 2
    assert snap["by_state"]["trusted"] == 1
    assert snap["by_state"]["pending"] == 1

    text = render_dashboard(snap)
    assert "bindumpty dashboard" in text
    assert "trusted: 1" in text

    events = [{"seq": 1, "kind": "state:pending:trusted", "function_id": 1, "created_at": "2026-11-15T18:00:00", "payload": "{}"}]
    layout = make_dashboard_layout(snap, events)
    assert layout is not None
