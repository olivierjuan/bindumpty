"""Unit test for humpty.king.dag_server API."""
import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from humpty.king.dag_server import create_app
from humpty.db import make_session_factory
from humpty.db.session import session_scope
from humpty.db.models import Function, CallEdge, Event, Candidate
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
        f1 = Function(binary_sha256="0"*64, name="root_fn", address=0x1000, size=64, state="trusted", confidence=1.0)
        f2 = Function(binary_sha256="0"*64, name="leaf_fn", address=0x2000, size=32, state="pending", confidence=0.0)
        s.add_all([f1, f2])
        s.flush()
        edge = CallEdge(caller_id=f1.id, callee_id=f2.id, kind="direct")
        s.add(edge)
        ev = Event(seq=1, kind="state:pending:trusted", function_id=f1.id)
        s.add(ev)

    eng.dispose()
    return str(db_file)


def test_dag_server_endpoints(test_db):
    app = create_app(test_db)
    client = TestClient(app)

    # 1. HTML index
    res = client.get("/")
    assert res.status_code == 200
    assert "bindumpty — Live Call Graph DAG" in res.text

    # 2. Graph API (unfiltered)
    res = client.get("/api/graph?hide_libs=false")
    assert res.status_code == 200
    data = res.json()
    assert len(data["nodes"]) == 2
    assert len(data["edges"]) == 1
    assert data["stats"]["trusted"] == 1
    assert data["stats"]["pending"] == 1

    # 3. Graph API (rooted subtree)
    res = client.get("/api/graph?root=root_fn&depth=1&hide_libs=false")
    assert res.status_code == 200
    data = res.json()
    assert len(data["nodes"]) == 2
    assert data["nodes"][0]["name"] in ("root_fn", "leaf_fn")

    # 4. Function Detail API
    res = client.get("/api/function/1")
    assert res.status_code == 200
    fn_data = res.json()
    assert fn_data["name"] == "root_fn"
    assert fn_data["state"] == "trusted"

    # 5. Sunburst API
    res = client.get("/api/sunburst?root=root_fn&depth=2&hide_libs=false")
    assert res.status_code == 200
    sb_data = res.json()
    assert sb_data["name"] == "root_fn"
    assert len(sb_data["children"]) == 1
    assert sb_data["children"][0]["name"] == "leaf_fn"

    # 6. Live Events SSE Stream
    with client.stream("GET", "/api/events/live") as stream:
        for chunk in stream.iter_text():
            if chunk:
                assert "state:pending:trusted" in chunk or "ping" in chunk or "data:" in chunk
                break

