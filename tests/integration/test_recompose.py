"""Integration: recompose — rebuild the call tree into a working .so.

Multi-run sequence: run CEGIS on some functions, recompose, run CEGIS on
more, recompose again — the output picks up all validated sources from
the DB each time.
"""
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "horses", "src"))
sys.path.insert(0, os.path.join(ROOT, "horses", "spikes"))

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

from humpty.db import make_session_factory  # noqa: E402
from humpty.db.models import Candidate, Function  # noqa: E402
from humpty.db.session import session_scope  # noqa: E402
from humpty.ingest import binary_sha256, load_call_graph  # noqa: E402
from humpty.king.recompose import recompose  # noqa: E402

CASE = os.path.join("toys", "case-01-leaf")

SRCS = {
    "fnv1a": "#include <stdint.h>\n#include <stddef.h>\n"
             "uint32_t fnv1a(const uint8_t*d,size_t l){uint32_t h=2166136261u;"
             "for(size_t i=0;i<l;i++){h^=d[i];h*=16777619u;}return h;}",
    "digit_sum_u32": "#include <stdint.h>\n"
                     "int digit_sum_u32(uint32_t x){int s=0;"
                     "do{s+=(int)(x%10u);x/=10u;}while(x!=0u);return s;}",
    "checksum_block": "#include <stdint.h>\n#include <stddef.h>\n"
                      "uint32_t checksum_block(const uint8_t*d,size_t l){"
                      "size_t h=l/2;uint32_t a=fnv1a(d,h),b=fnv1a(d+h,l-h),"
                      "m=a^(b*2654435761u);return m^(uint32_t)digit_sum_u32(m);}",
}


@pytest.fixture()
def env(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path}/rec.db")
    ini = Config(os.path.join(ROOT, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(ROOT, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", f"sqlite:///{tmp_path}/rec.db")
    command.upgrade(ini, "head")
    factory = make_session_factory(eng)
    elf = os.path.join(ROOT, CASE, "build", "toy01")
    if not os.path.exists(elf):
        pytest.skip("toy01 not built")
    sha = binary_sha256(elf)
    with session_scope(factory) as s:
        load_call_graph(s, json_path=os.path.join(ROOT, CASE, "ground_truth/call_graph.json"),
                        binary=elf)
    yield factory, elf, sha, tmp_path
    eng.dispose()


def _validate(session, sha, names):
    for name in names:
        fid = session.query(Function).filter_by(
            binary_sha256=sha, name=name).one().id
        session.add(Candidate(function_id=fid, source_code=SRCS[name],
                              created_by="dev", status="trusted"))


def test_recompose_single_run(env):
    """One run: validate all 3, recompose → .so compiles and exports all 3."""
    factory, elf, sha, td = env
    with session_scope(factory) as s:
        _validate(s, sha, ["fnv1a", "digit_sum_u32", "checksum_block"])
    out = os.path.join(td, "out")
    r = recompose(session=None, binary=elf, out_dir=out) if False else None
    # recompose needs a session for the DB query
    from humpty.db.session import session_scope as _ss
    with _ss(factory) as s:
        r = recompose(s, binary=elf, out_dir=out)
    assert r.build_rc == 0, r.build_stderr
    assert set(r.functions_validated) == {"fnv1a", "digit_sum_u32", "checksum_block"}
    assert os.path.exists(r.output_so)


def test_recompose_multi_run(env):
    """Two run sequences: first validate fnv1a, recompose (1 validated +
    2 stubs), then validate the rest, recompose again (all validated)."""
    factory, elf, sha, td = env

    # ── run 1: validate fnv1a only ──
    with session_scope(factory) as s:
        _validate(s, sha, ["fnv1a"])
    out = os.path.join(td, "out_r1")
    with session_scope(factory) as s:
        r1 = recompose(s, binary=elf, out_dir=out)
    assert r1.build_rc == 0
    assert r1.functions_validated == ["fnv1a"]
    assert "checksum_block" in r1.functions_stub
    assert os.path.exists(r1.output_so)

    # ── run 2: validate the remaining two ──
    with session_scope(factory) as s:
        _validate(s, sha, ["digit_sum_u32", "checksum_block"])
    out2 = os.path.join(td, "out_r2")
    with session_scope(factory) as s:
        r2 = recompose(s, binary=elf, out_dir=out2)
    assert r2.build_rc == 0
    assert set(r2.functions_validated) == {"fnv1a", "digit_sum_u32", "checksum_block"}
    assert r2.functions_stub == ["main"]
    assert os.path.exists(r2.output_so)
    # the output .so exports the validated functions
    nm = subprocess.run(["nm", "-D", str(r2.output_so)],
                        capture_output=True, text=True).stdout
    for sym in ("fnv1a", "digit_sum_u32", "checksum_block"):
        assert sym in nm, f"{sym} not exported from recomposed .so"
