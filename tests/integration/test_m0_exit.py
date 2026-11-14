"""Integration: the M0 exit criterion on case-01.

"Call tree extracted and I/O traces recorded for a toy binary" — end to end:
build-free (requires the built toy), ingest the ground-truth call graph into
``functions``/``call_edges``, load the recorded trace bundle into ``traces``,
and verify every trace row matches the original's real I/O.

Marked with the default sandbox-free path (no container needed): it only reads
the toy build artifacts and a SQLite DB.
"""
import hashlib
import json
import os

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine

from humpty.db import (
    CallEdge,
    Function,
    Trace,
    make_session_factory,
    session_scope,
)
from humpty.ingest import binary_sha256, load_call_graph
from humpty.trace import load_bundle
from humpty.domain import State, callees_trusted, is_success

CASE = os.path.join("toys", "case-01-leaf")


def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def factory(tmp_path):
    root = _repo_root()
    db_url = f"sqlite:///{tmp_path}/m0.db"
    ini = Config(os.path.join(root, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(root, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", db_url)
    eng = create_engine(db_url)
    command.upgrade(ini, "head")
    yield make_session_factory(eng)
    eng.dispose()


def _require_artifacts():
    root = _repo_root()
    elf = os.path.join(root, CASE, "build", "toy01")
    cg = os.path.join(root, CASE, "ground_truth", "call_graph.json")
    bundle = os.path.join(root, CASE, "ground_truth", "traces.jsonl")
    for p in (elf, cg, bundle):
        if not os.path.exists(p):
            pytest.skip(f"toy artifact missing: {p} (run build.sh + record.sh)")


def _nm_addresses():
    """Authoritative function addresses from the unstripped build (nm)."""
    import re
    import shutil
    import subprocess

    root = _repo_root()
    sym = os.path.join(root, CASE, "build", "toy01.sym")
    if not os.path.exists(sym) or shutil.which("nm") is None:
        pytest.skip("toy01.sym or nm unavailable (run build.sh)")
    out = subprocess.run(["nm", "-n", sym], capture_output=True, text=True).stdout
    addrs = {}
    for line in out.splitlines():
        m = re.match(r"^([0-9a-f]+)\s+[A-Z]\s+(\S+)$", line)
        if m:
            addrs[m.group(2)] = int(m.group(1), 16)
    return addrs


def test_ground_truth_addresses_match_binary():
    """Guard: ground-truth function addresses must match the built binary.

    A codegen change can shift the ELF layout (observed 2026-11-14: a uniform
    0x20 shift with unchanged sizes). Stale addresses make trace replay and
    FR-7 hooking (module.base + vaddr) hit the wrong bytes, so the recorded
    addresses must stay in lockstep with the unstripped build.
    """
    import json

    root = _repo_root()
    cg = os.path.join(root, CASE, "ground_truth", "call_graph.json")
    if not os.path.exists(cg):
        pytest.skip(f"call graph missing: {cg} (run build.sh)")
    addrs = _nm_addresses()
    g = json.load(open(cg))
    mismatches = []
    for fn in g.get("functions", []):
        want = addrs.get(fn["name"])
        if want is None:
            continue
        got = int(str(fn["address"]), 16)
        if got != want:
            mismatches.append(f"{fn['name']}: gt=0x{got:x} binary=0x{want:x}")
    assert not mismatches, "ground-truth addresses desynced: " + "; ".join(mismatches)


def test_m0_exit_criterion_case_01(factory):
    """The full M0 pipeline: ingest -> ready set -> trace load -> oracle check."""
    _require_artifacts()
    root = _repo_root()
    elf = os.path.join(root, CASE, "build", "toy01")
    cg = os.path.join(root, CASE, "ground_truth", "call_graph.json")
    bundle = os.path.join(root, CASE, "ground_truth", "traces.jsonl")
    sha = binary_sha256(elf)

    with session_scope(factory) as s:
        g = load_call_graph(s, json_path=cg, binary=elf)
        n = load_bundle(s, bundle=bundle, binary_sha256=sha)

    assert n == 24  # the recorded bundle has 24 calls

    with session_scope(factory) as s:
        fns = s.query(Function).all()
        assert len(fns) == 4  # fnv1a, digit_sum_u32, checksum_block, main
        edges = s.query(CallEdge).all()
        assert len(edges) == 3
        # The call-graph JSON's binary sha matches the actual file (NFR-2).
        meta = json.load(open(cg))
        assert meta["binary"]["sha256"] == sha
        # The functions table's sha is the real one (load recomputes it).
        assert all(f.binary_sha256 == sha for f in fns)
        # Topological order: fnv1a and digit_sum_u32 before checksum_block.
        by_id = {f.id: f.name for f in fns}
        order = [by_id[i] for i in g.topological_order]
        assert order.index("fnv1a") < order.index("checksum_block")
        assert order.index("digit_sum_u32") < order.index("checksum_block")
        # Trace rows exist for exactly the three non-main functions.
        traced = {s.get(Function, t.function_id).name for t in s.query(Trace).all()}
        assert traced == {"fnv1a", "digit_sum_u32", "checksum_block"}

    # Oracle check: replay the recorded traces against an independent
    # reference (the known source) — they must all agree.
    root = _repo_root()
    src = os.path.join(root, CASE, "sources", "toy01_impl.h")
    assert os.path.exists(src)
    records = [json.loads(l) for l in open(bundle) if l.strip()]
    fails = []
    for r in records:
        if not _check(r):
            fails.append(r)
    assert not fails, f"traces disagree with reference: {fails[:3]}"

    # Ready set: fnv1a and digit_sum_u32 are leaves (no callees) -> ready.
    assert callees_trusted([])
    # checksum_block is NOT ready until its two callees are trusted.
    assert not callees_trusted([State.PENDING, State.PENDING])
    assert callees_trusted([State.TRUSTED, State.TRUSTED])
    # And the success predicate the objective maximizes.
    assert is_success(State.TRUSTED) and is_success(State.PROVEN)
    assert not is_success(State.FAILED)


# Reference implementation (mirrors sources/toy01_impl.h) for the oracle check.
def _fnv1a(data: bytes) -> int:
    h = 2166136261
    for b in data:
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def _dsum(x: int) -> int:
    s = 0
    while True:
        s += x % 10
        x //= 10
        if x == 0:
            return s


def _csum(data: bytes) -> int:
    half = len(data) // 2
    h1 = _fnv1a(data[:half])
    h2 = _fnv1a(data[half:])
    mix = h1 ^ ((h2 * 2654435761) & 0xFFFFFFFF)
    return mix ^ _dsum(mix)


def _check(r: dict) -> bool:
    fn, arg = r["fn"], r["arg"]
    if fn == "digit_sum_u32":
        return r["ret"] == _dsum(int(arg))
    data = bytes.fromhex(arg)
    expected = (_fnv1a if fn == "fnv1a" else _csum)(data)
    return r["ret"] == f"0x{expected:08x}"
