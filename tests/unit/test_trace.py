"""Tests for humpty.trace — fuz.traces/1 bundle parsing and DB load.

Covers the FR-3 contract: a bundle is ground truth, so parsing is strict (no
silent skips), return values are normalized to byte-exact 4-byte little-endian
(so the harness can compare them in FR-6), and load resolves each record to a
function in the loaded call graph.
"""
import hashlib
import json
import os

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine

from humpty.db import (
    Function,
    Trace,
    make_session_factory,
    session_scope,
)
from humpty.ingest import load_call_graph
from humpty.trace import TraceBundleError, load_bundle, parse_bundle

CASE = os.path.join("toys", "case-01-leaf")

# A representative bundle, embedded so tests don't depend on record.sh having
# run. Byte-call and u32-call records, matching the driver's output.
BUNDLE = """\
{"fn":"fnv1a","arg":"61","arglen":1,"ret":"0xe40c292c"}
{"fn":"fnv1a","arg":"6161","arglen":2,"ret":"0x4c250437"}
{"fn":"digit_sum_u32","arg":"1234","ret":10}
{"fn":"checksum_block","arg":"","arglen":0,"ret":"0xc7b2afd4"}
"""


def _write(tmp_path, text=BUNDLE):
    p = tmp_path / "traces.jsonl"
    p.write_text(text)
    return p


@pytest.fixture()
def factory(tmp_path):
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    db_url = f"sqlite:///{tmp_path}/trace.db"
    ini = Config(os.path.join(repo_root, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(repo_root, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", db_url)
    eng = create_engine(db_url)
    command.upgrade(ini, "head")
    yield make_session_factory(eng)
    eng.dispose()


def test_parse_counts_and_types(tmp_path):
    recs = parse_bundle(_write(tmp_path))
    assert len(recs) == 4
    by = {(r.fn, r.args_blob) for r in recs}
    # fnv1a("a") -> 0xe40c292c, byte-exact little-endian.
    f = next(r for r in recs if r.fn == "fnv1a" and r.args_blob == b"a")
    assert f.ret == (0xE40C292C).to_bytes(4, "little", signed=False)
    # digit_sum_u32(1234) -> 10.
    d = next(r for r in recs if r.fn == "digit_sum_u32")
    assert d.args_blob == (1234).to_bytes(4, "little")
    assert d.ret == (10).to_bytes(4, "little", signed=True)
    assert d.ret_int == 10


def test_parse_rejects_bad_json(tmp_path):
    p = _write(tmp_path, text='{"fn":"fnv1a","arg":"61"')  # missing close
    with pytest.raises(TraceBundleError, match="invalid JSON"):
        parse_bundle(p)


def test_parse_rejects_missing_ret(tmp_path):
    p = _write(tmp_path, text='{"fn":"fnv1a","arg":"61"}')
    with pytest.raises(TraceBundleError, match="ret"):
        parse_bundle(p)


def test_parse_rejects_arglen_mismatch(tmp_path):
    p = _write(tmp_path, text='{"fn":"fnv1a","arg":"6161","arglen":1,"ret":"0x4c250437"}')
    with pytest.raises(TraceBundleError, match="arglen"):
        parse_bundle(p)


def test_parse_rejects_odd_hex(tmp_path):
    p = _write(tmp_path, text='{"fn":"fnv1a","arg":"616","arglen":1,"ret":"0x4c250437"}')
    with pytest.raises(TraceBundleError, match="odd-length"):
        parse_bundle(p)


def test_parse_rejects_unknown_arg(tmp_path):
    p = _write(tmp_path, text='{"fn":"fnv1a","arg":"??","ret":"0x0"}')
    with pytest.raises(TraceBundleError, match="unrecognized arg"):
        parse_bundle(p)


def test_input_sha256_is_over_args(tmp_path):
    p = _write(tmp_path, text='{"fn":"fnv1a","arg":"61","arglen":1,"ret":"0xe40c292c"}')
    recs = parse_bundle(p)
    assert recs[0].args_blob == b"a"
    assert recs[0].input_sha256 == hashlib.sha256(b"a").hexdigest()


def test_load_resolves_and_inserts(factory, tmp_path):
    """A bundle for the case-01 functions loads into ``traces`` rows."""
    from humpty.ingest import binary_sha256, load_call_graph

    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    cg = os.path.join(repo_root, CASE, "ground_truth", "call_graph.json")
    elf = os.path.join(repo_root, CASE, "build", "toy01")
    if not os.path.exists(elf):
        pytest.skip("toy not built (run toys/case-01-leaf/build.sh)")
    sha = binary_sha256(elf)

    with session_scope(factory) as s:
        load_call_graph(s, json_path=cg, binary=elf)
        n = load_bundle(s, bundle=_write(tmp_path), binary_sha256=sha)
    assert n == 4
    with session_scope(factory) as s:
        rows = s.query(Trace).all()
        assert len(rows) == 4
        # fnv1a("a") stored byte-exact.
        fa = next(r for r in rows if r.args_blob == b"a")
        assert fa.ret == (0xE40C292C).to_bytes(4, "little", signed=False)
        # each row's input_sha256 matches its args.
        for r in rows:
            assert r.input_sha256 == hashlib.sha256(r.args_blob).hexdigest()
        # rows are attached to real functions of this binary.
        fn_ids = {r.function_id for r in rows}
        assert len(fn_ids) == 3  # fnv1a, digit_sum_u32, checksum_block


def test_load_rejects_unknown_function(factory, tmp_path):
    from humpty.ingest import binary_sha256
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    elf = os.path.join(repo_root, CASE, "build", "toy01")
    if not os.path.exists(elf):
        pytest.skip("toy not built")
    sha = binary_sha256(elf)
    bad = _write(tmp_path, text='{"fn":"nope","arg":"61","ret":"0x0"}')
    with pytest.raises(TraceBundleError, match="unknown function"):
        with session_scope(factory) as s:
            load_bundle(s, bundle=bad, binary_sha256=sha)
