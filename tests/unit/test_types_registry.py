"""Unit tests for humpty.types_registry — FR-12, type registry v0.

Exercises the versioning contract on the real ``types`` table via the
Alembic migration (same factory pattern as tests/unit/test_db.py, which
needs no Function rows here: ``types`` has no foreign keys):

- register-new inserts version 1 and stores the binary identity,
- re-registering an identical layout returns the same row unchanged,
- a conflicting layout appends a bumped-version row (history preserved),
- get_layout returns the newest authoritative layout, minus bookkeeping,
- the single-owner rule refuses writes from a different worker (TypeError),
- check_consistency is True for identical/new and False for divergent.
"""
import os

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, select

from humpty.db import TypeRow, make_session_factory, session_scope
from humpty.types_registry import (
    check_consistency,
    get_layout,
    newest_layout_row,
    register_type,
)

SHA = "a" * 64


def _layout(size: int = 24, *fields: dict) -> dict:
    """A v0 layout: {size, fields: [{name, offset, type}]}."""
    return {
        "size": size,
        "fields": list(fields)
        or [{"name": "x", "offset": 0, "type": "int"}, {"name": "y", "offset": 8, "type": "void*"}],
    }


@pytest.fixture()
def factory(tmp_path):
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    db_url = f"sqlite:///{tmp_path}/types.db"
    ini = Config(os.path.join(repo_root, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(repo_root, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", db_url)
    eng = create_engine(db_url)
    command.upgrade(ini, "head")
    yield make_session_factory(eng)
    eng.dispose()


def test_register_new(factory):
    with session_scope(factory) as s:
        row = register_type(s, binary_sha256=SHA, name="struct point", layout_json=_layout(), owner="w1")
        assert row.id is not None
        assert row.name == "struct point"
        assert row.owner_worker == "w1"
        assert row.version == 1
        assert row.layout_json["_binary"] == SHA
        # size/fields round-trip through the JSON column
        assert row.layout_json["size"] == 24
        assert row.layout_json["fields"][0]["name"] == "x"


def test_register_identical_returns_same_row(factory):
    with session_scope(factory) as s:
        first = register_type(s, binary_sha256=SHA, name="point", layout_json=_layout(), owner="w1")
        # same layout, different key insertion order: still identical
        reordered = {"fields": _layout()["fields"], "size": 24}
        again = register_type(s, binary_sha256=SHA, name="point", layout_json=reordered, owner="w1")
        assert again.id == first.id
        assert again.version == 1
        # and the registry holds exactly one row for this name
        assert len(list(s.scalars(select(TypeRow)).all())) == 1


def test_conflicting_layout_bumps_version(factory):
    with session_scope(factory) as s:
        v1 = register_type(s, binary_sha256=SHA, name="point", layout_json=_layout(), owner="w1")
        divergent = _layout(
            32,
            {"name": "x", "offset": 0, "type": "int"},
            {"name": "y", "offset": 8, "type": "void*"},
            {"name": "tag", "offset": 16, "type": "long"},
        )
        v2 = register_type(s, binary_sha256=SHA, name="point", layout_json=divergent, owner="w1")
        assert v2.id != v1.id
        assert v2.version == 2
        # history preserved: both rows remain, newest is authoritative
        rows = list(s.scalars(select(TypeRow).order_by(TypeRow.version)).all())
        assert [r.version for r in rows] == [1, 2]
        assert newest_layout_row(s, binary_sha256=SHA, name="point").id == v2.id
        # versions are per name (schema constraint has no binary column):
        # another binary's first row for this name becomes version 3
        other = register_type(
            s, binary_sha256="b" * 64, name="point", layout_json=_layout(), owner="w2"
        )
        assert other.version == 3


def test_get_layout_newest(factory):
    with session_scope(factory) as s:
        assert get_layout(s, binary_sha256=SHA, name="nope") is None
        register_type(s, binary_sha256=SHA, name="point", layout_json=_layout(), owner="w1")
        divergent = _layout(32, {"name": "z", "offset": 0, "type": "char[32]"})
        register_type(s, binary_sha256=SHA, name="point", layout_json=divergent, owner="w1")
        layout = get_layout(s, binary_sha256=SHA, name="point")
        assert layout == divergent  # newest wins
        assert "_binary" not in layout and "_owner" not in layout  # bookkeeping stripped
        # binary scoping: the other binary still sees only its own rows
        register_type(s, binary_sha256="c" * 64, name="point", layout_json=_layout(), owner="w2")
        assert get_layout(s, binary_sha256="c" * 64, name="point") == _layout()


def test_single_owner_enforcement(factory):
    with session_scope(factory) as s:
        register_type(s, binary_sha256=SHA, name="point", layout_json=_layout(), owner="w1")
        # another worker diverging on an owned type is refused
        with pytest.raises(TypeError, match="owned by"):
            register_type(s, binary_sha256=SHA, name="point", layout_json=_layout(32), owner="w2")
        # the owner itself may keep evolving its type
        v2 = register_type(s, binary_sha256=SHA, name="point", layout_json=_layout(32), owner="w1")
        assert v2.version == 2
        # and the refused write left no row behind
        assert [r.version for r in s.scalars(select(TypeRow).order_by(TypeRow.version)).all()] == [1, 2]


def test_consistency_check(factory):
    with session_scope(factory) as s:
        # unknown type is consistent by definition
        assert check_consistency(s, binary_sha256=SHA, name="point", layout_json=_layout())
        register_type(s, binary_sha256=SHA, name="point", layout_json=_layout(), owner="w1")
        assert check_consistency(s, binary_sha256=SHA, name="point", layout_json=_layout())
        assert not check_consistency(s, binary_sha256=SHA, name="point", layout_json=_layout(32))
        # a different binary's registry is unaffected
        assert check_consistency(s, binary_sha256="d" * 64, name="point", layout_json=_layout(32))
