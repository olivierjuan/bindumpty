"""Integration: FR-2 v0 — library fingerprinting by byte signature.

The corpus is seeded from the toy's own imported PLT stubs (getenv, printf,
...), saved in the documented JSON format, and ``fingerprint_function`` is run
against an ingested Function row. Limitations of v0 (per-binary stubs, exact
bytes) are exercised explicitly: the toy's own ``fnv1a`` — same bytes as the
PLT entry size — must NOT match a stub corpus.
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine

from humpty.db import make_session_factory
from humpty.db.models import Event, Function
from humpty.db.session import session_scope
from humpty.ingest import binary_sha256, load_call_graph
from humpty.analyze.fingerprint import (
    FingerprintError,
    build_corpus_bytes,
    build_corpus_symbols,
    fingerprint_function,
    fingerprint_functions,
    load_corpus,
    save_corpus,
)

CASE = os.path.join("toys", "case-01-leaf")
ELF = os.path.join(CASE, "build", "toy01")


@pytest.fixture()
def factory(tmp_path):
    db = f"sqlite:///{tmp_path}/fp.db"
    ini = Config(os.path.join(ROOT, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(ROOT, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", db)
    eng = create_engine(db)
    command.upgrade(ini, "head")
    yield make_session_factory(eng)
    eng.dispose()


@pytest.fixture()
def toy(factory):
    """Ingest the toy graph; return (elf path, {name: function_id})."""
    elf = os.path.join(ROOT, ELF)
    if not os.path.exists(elf):
        pytest.skip("toy01 not built (run toys/case-01-leaf/build.sh)")
    cg = os.path.join(ROOT, CASE, "ground_truth", "call_graph.json")
    with session_scope(factory) as s:
        load_call_graph(s, json_path=cg, binary=elf)
        ids = {fn.name: fn.id for fn in s.query(Function)}
    return elf, ids


def test_build_corpus_covers_toy_imports(toy, tmp_path):
    """The seeded corpus holds the toy's own imports with real stub bytes."""
    elf, _ = toy
    corpus = build_corpus_symbols([elf])
    for imported in ("getenv", "printf", "fopen", "fclose"):
        assert imported in corpus, f"{imported} missing from corpus"
        assert len(corpus[imported]) == 16  # one PLT stub
    # The corpus JSON round-trips through the documented file format.
    path = os.path.join(tmp_path, "corpus.json")
    save_corpus(corpus, path)
    doc = json.loads(open(path).read())
    assert doc["getenv"] == {"bytes_hex": corpus["getenv"].hex(), "size": 16}


def test_fingerprint_matches_imported_plt_stub(factory, toy, tmp_path):
    """A PLT stub row (size 16) matches its corpus entry: fingerprint set,
    pending -> trusted transition, fingerprint_match event written."""
    elf, ids = toy
    corpus_path = os.path.join(tmp_path, "corpus.json")
    save_corpus(build_corpus_symbols([elf]), corpus_path)

    # Seed a Function row for the getenv PLT stub itself (the ingested graph
    # has no PLT rows; FR-2 matches any row whose bytes are in the corpus).
    import hashlib
    with session_scope(factory) as s:
        row = Function(
            binary_sha256=hashlib.sha256(open(elf, "rb").read()).hexdigest(),
            name="getenv@plt",
            address=0x1030,
            size=16,
            state="pending",
        )
        s.add(row)
        s.flush()
        fid = row.id

    with session_scope(factory) as s:
        matched = fingerprint_function(s, function_id=fid,
                                       corpus_path=corpus_path,
                                       binary_path=elf)
        fn = s.get(Function, fid)
        evs = s.query(Event).filter_by(function_id=fid).all()
    assert matched == "getenv"
    assert fn.fingerprint == "getenv"
    assert fn.state == "trusted"  # pending -> trusted is legal per TRANSITIONS
    kinds = [e.kind for e in evs]
    assert kinds == ["fingerprint_match"]
    payload = evs[0].payload_json
    assert payload["match"] == "getenv" and payload["transitioned"] is True
    assert payload["from_state"] == "pending"


def test_fingerprint_no_match_leaves_function_untouched(factory, toy, tmp_path):
    """The toy's own fnv1a (48 bytes) is not a 16-byte PLT stub: no match,
    no fingerprint, no state change, no event."""
    elf, ids = toy
    corpus_path = os.path.join(tmp_path, "corpus.json")
    save_corpus(build_corpus_symbols([elf]), corpus_path)
    fid = ids["fnv1a"]

    with session_scope(factory) as s:
        matched = fingerprint_function(s, function_id=fid,
                                       corpus_path=corpus_path,
                                       binary_path=elf)
        fn = s.get(Function, fid)
        evs = s.query(Event).filter_by(function_id=fid).all()
    assert matched is None
    assert fn.fingerprint is None
    assert fn.state == "pending"
    assert evs == []


def test_fingerprint_illegal_transition_still_records_match(factory, tmp_path):
    """Documented finding path: pending -> trusted is legal, but a state with
    no transition to trusted (e.g. divergent) keeps its state while the
    fingerprint mapping is still recorded."""
    import hashlib
    with session_scope(factory) as s:
        row = Function(
            binary_sha256=hashlib.sha256(b"x").hexdigest(),
            name="stub",
            address=0x1030,
            size=16,
            state="divergent",  # TRANSITIONS: divergent -> {repairing, failed}
        )
        s.add(row)
        s.flush()
        fid = row.id
    # Corpus with exactly the classic x86-64 getenv stub bytes.
    stub = bytes.fromhex("ff25ca2f00006800000000e9e0ffffff")
    corpus_path = os.path.join(tmp_path, "c.json")
    save_corpus({"getenv": stub}, corpus_path)

    elf = os.path.join(ROOT, ELF)
    if not os.path.exists(elf):
        pytest.skip("toy01 not built (run toys/case-01-leaf/build.sh)")
    with session_scope(factory) as s:
        matched = fingerprint_function(s, function_id=fid,
                                       corpus_path=corpus_path,
                                       binary_path=elf)
        fn = s.get(Function, fid)
        evs = s.query(Event).filter_by(function_id=fid).all()
    assert matched == "getenv"
    assert fn.fingerprint == "getenv"
    assert fn.state == "divergent"  # transition refused, mapping kept
    assert evs[0].payload_json["transitioned"] is False


def test_fingerprint_requires_binary_path(factory):
    """binary_path=None is a caller error, not a silent miss."""
    with session_scope(factory) as s:
        row = Function(binary_sha256="0" * 64, name="x", address=0x1000,
                       size=16, state="pending")
        s.add(row)
        s.flush()
        fid = row.id
        with pytest.raises(FingerprintError, match="binary_path"):
            fingerprint_function(s, function_id=fid,
                                 corpus_path="/nonexistent.json",
                                 binary_path=None)


# --- corpus from the toy's own functions (ground truth) + binary sweep ------


def _require_toy():
    root_elf = os.path.join(ROOT, ELF)
    if not os.path.exists(root_elf):
        pytest.skip("toy01 not built (run toys/case-01-leaf/build.sh)")
    return root_elf


def test_build_corpus_bytes_from_ground_truth(tmp_path):
    """The corpus seeded from the toy's own functions holds real code bytes.

    Addresses and sizes come from the ground-truth call graph (the toy01
    ELF is stripped, so nm -S cannot size it); the JSON round-trips.
    """
    _require_toy()
    elf = os.path.join(ROOT, ELF)
    cg = json.load(open(os.path.join(ROOT, CASE, "ground_truth",
                                     "call_graph.json")))
    layout = {f["name"]: (f["address"], int(f["size"]))
              for f in cg["functions"]}
    names = ["fnv1a", "digit_sum_u32", "checksum_block"]

    corpus = build_corpus_bytes(elf, names, layout=layout)
    assert set(corpus) == set(names)
    assert len(corpus["fnv1a"]) == 48 and len(corpus["checksum_block"]) == 80
    # Bytes equal objdump -d at the ground-truth address (fnv1a @ 0x11d0):
    # push %rbp; mov %rsp,%rbp; mov $0x811c9dc5,%eax (FNV offset basis).
    assert corpus["fnv1a"].startswith(bytes.fromhex("554889e5b8c59d1c81"))

    path = os.path.join(tmp_path, "corpus.json")
    save_corpus(corpus, path)
    assert load_corpus(path) == corpus


def test_fingerprint_functions_sweeps_binary(factory, toy, tmp_path):
    """The binary sweep fingerprints every ingested row matching the corpus.

    The corpus is seeded from the toy's own functions (ground-truth sizes);
    the sweep must match fnv1a (Function.fingerprint == 'fnv1a', pending ->
    trusted) and write the fingerprint_match event, leaving non-corpus rows
    (main) untouched.
    """
    elf, ids = toy
    cg = json.load(open(os.path.join(ROOT, CASE, "ground_truth",
                                     "call_graph.json")))
    layout = {f["name"]: (f["address"], int(f["size"]))
              for f in cg["functions"]}
    names = ["fnv1a", "digit_sum_u32", "checksum_block"]
    corpus_path = os.path.join(tmp_path, "corpus.json")
    save_corpus(build_corpus_bytes(elf, names, layout=layout), corpus_path)
    sha = binary_sha256(elf)

    with session_scope(factory) as s:
        matched = fingerprint_functions(s, binary_sha256=sha,
                                        corpus_path=corpus_path,
                                        binary_path=elf)
        by_id = {r.id: r for r in s.query(Function)}
        evs = s.query(Event).filter_by(kind="fingerprint_match").all()
    assert matched == ["fnv1a", "digit_sum_u32", "checksum_block"]
    rows = {r.name: r for r in by_id.values()}
    for n in matched:
        assert rows[n].fingerprint == n
        assert rows[n].state == "trusted"  # pending -> trusted is legal
    assert rows["main"].fingerprint is None  # not in the corpus
    assert rows["main"].state == "pending"
    assert sorted(by_id[e.function_id].name for e in evs) == sorted(matched)
    fnv_ev = next(e for e in evs
                  if by_id[e.function_id].name == "fnv1a")
    assert fnv_ev.payload_json["match"] == "fnv1a"
    assert fnv_ev.payload_json["transitioned"] is True


def test_fingerprint_functions_ignores_other_binaries(factory, toy, tmp_path):
    """Rows of a different binary_sha256 are never touched by the sweep."""
    elf, _ = toy
    cg = json.load(open(os.path.join(ROOT, CASE, "ground_truth",
                                     "call_graph.json")))
    layout = {f["name"]: (f["address"], int(f["size"]))
              for f in cg["functions"]}
    corpus_path = os.path.join(tmp_path, "corpus.json")
    save_corpus(build_corpus_bytes(elf, list(layout), layout=layout),
                corpus_path)
    with session_scope(factory) as s:
        s.add(Function(binary_sha256="f" * 64, name="fnv1a", address=0x11d0,
                       size=48, state="pending"))
        s.flush()

    with session_scope(factory) as s:
        assert fingerprint_functions(s, binary_sha256="e" * 64,
                                     corpus_path=corpus_path,
                                     binary_path=elf) == []
        assert s.query(Function).filter_by(binary_sha256="f" * 64).one() \
            .fingerprint is None
