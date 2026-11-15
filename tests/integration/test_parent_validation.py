"""Integration: D3.1/D3.2 — parent validation via generated per-binary
harness with validated callees compiled in (callee interception)."""
import os
import sys
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "horses", "src"))
sys.path.insert(0, os.path.join(ROOT, "horses", "spikes"))

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine

from humpty.db import make_session_factory
from humpty.db.models import Candidate, Function
from humpty.db.session import session_scope
from humpty.ingest import binary_sha256, load_call_graph
from humpty.king.harness_gen import generate_harness

CASE = os.path.join("toys", "case-01-leaf")

LEAF_SRC = ("#include <stdint.h>\n#include <stddef.h>\n"
            "uint32_t fnv1a(const uint8_t*d,size_t l){uint32_t h=2166136261u;"
            "for(size_t i=0;i<l;i++){h^=d[i];h*=16777619u;}return h;}\n"
            "int digit_sum_u32(uint32_t x){int s=0;do{s+=(int)(x%10u);x/=10u;}"
            "while(x!=0u);return s;}")

PARENT_SRC = ("#include <stdint.h>\n#include <stddef.h>\n"
              "uint32_t checksum_block(const uint8_t*d,size_t l){"
              "size_t h=l/2;uint32_t a=fnv1a(d,h),b=fnv1a(d+h,l-h),"
              "m=a^(b*2654435761u);return m^(uint32_t)digit_sum_u32(m);}")


@pytest.fixture()
def setup(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path}/pv.db")
    ini = Config(os.path.join(ROOT, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(ROOT, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", f"sqlite:///{tmp_path}/pv.db")
    command.upgrade(ini, "head")
    factory = make_session_factory(eng)
    so = os.path.join(ROOT, CASE, "build", "toy01.so")
    if not os.path.exists(so):
        pytest.skip("toy01.so not built")
    sha = binary_sha256(so)
    with session_scope(factory) as s:
        load_call_graph(s, json_path=os.path.join(ROOT, CASE, "ground_truth/call_graph.json"),
                        binary=so)
    yield factory, so, sha, tmp_path
    eng.dispose()


def test_parent_harness_compiles_with_validated_callees(setup):
    """D3.1: the parent harness links the validated callee sources."""
    factory, so, sha, tmp_path = setup
    cg = os.path.join(ROOT, CASE, "ground_truth/call_graph.json")

    res = generate_harness(cg, so, tmp_path / "h", root_symbol="checksum_block",
                           root_candidate_src=PARENT_SRC)

    # compile: harness + candidate (which defines fnv1a, digit_sum, checksum_block)
    cand = tmp_path / "candidate.c"
    cand.write_text(LEAF_SRC + "\n" + PARENT_SRC)
    r = subprocess.run(["clang", "-O1", "-fsyntax-only", "-D_GNU_SOURCE",
                        str(res.harness_c), str(cand)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-300:]


def test_parent_harness_g_orig_naming(setup):
    """The generated harness resolves originals under g_orig_ prefix."""
    factory, so, sha, tmp_path = setup
    cg = os.path.join(ROOT, CASE, "ground_truth/call_graph.json")
    res = generate_harness(cg, so, tmp_path / "h", root_symbol="checksum_block",
                           root_candidate_src=PARENT_SRC)
    src = res.harness_c.read_text()
    assert "g_orig_fnv1a" in src
    assert "g_orig_digit_sum_u32" in src
    assert "resolve_original(0x11d0" in src
    assert "resolve_original(0x1200" in src
