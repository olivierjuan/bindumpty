"""FR-2 Tier 1: symbol-pattern pruning."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from humpty.analyze.library_filter import classify_symbol, prune_libraries


@pytest.mark.parametrize("sym,fam", [
    ("__intel_avx_skx_memcpy", "intel_runtime"),
    ("__libm_sse2_sin", "intel_runtime"),
    ("MKL_Daxpy", "mkl"),
    ("mkl_blas_dgemm", "mkl"),
    ("XML_ParserCreate", "expat"),
    ("sqlite3_exec", "sqlite"),
    ("inflateInit_", "zlib"),
    ("DAXPY", "blas"),
    ("dgemm_", "blas"),
    ("memcpy", "libc"),
    ("memcpy@plt", "libc"),
])
def test_classify_symbols(sym, fam):
    assert classify_symbol(sym) == fam


@pytest.mark.parametrize("sym", ["CPXbaropt", "checksum_block",
                                 "_1f1782bc1340dc3df7b07ab3ddc6d05c", "main"])
def test_classify_app_symbols_untouched(sym):
    assert classify_symbol(sym) is None


def test_prune_libraries_marks_and_skips(tmp_path):
    from sqlalchemy import create_engine
    from alembic import command
    from alembic.config import Config
    from humpty.db import make_session_factory
    from humpty.db.models import Function
    from humpty.ingest import binary_sha256

    db = tmp_path / "lf.db"
    eng = create_engine(f"sqlite:///{db}")
    ini = Config(os.path.join(ROOT, "alembic.ini"))
    ini.set_main_option("script_location",
                        os.path.join(ROOT, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", f"sqlite:///{db}")
    command.upgrade(ini, "head")
    factory = make_session_factory(eng)

    sha = "b" * 64
    from humpty.db.session import session_scope
    with session_scope(factory) as s:
        for i, name in enumerate(["MKL_Daxpy", "sqlite3_exec", "memcpy",
                                  "CPXbaropt", "_1f17deadbeef"]):
            s.add(Function(binary_sha256=sha, name=name, address=0x1000 + i,
                           size=16))
    with session_scope(factory) as s:
        stats = prune_libraries(s, binary_sha256=sha, log=lambda *_: None)
    assert stats["pruned"] == 3
    with session_scope(factory) as s:
        rows = {f.name: (f.state, f.confidence, f.fingerprint)
                for f in s.query(Function).filter_by(binary_sha256=sha)}
    assert rows["MKL_Daxpy"] == ("trusted", 1.0, "vendor::mkl")
    assert rows["memcpy"] == ("trusted", 1.0, "vendor::libc")
    assert rows["CPXbaropt"][0] == "pending"      # untouched
    assert rows["_1f17deadbeef"][0] == "pending"  # untouched


def test_prune_uses_demangled_sig_name(tmp_path):
    from sqlalchemy import create_engine
    from alembic import command
    from alembic.config import Config
    from humpty.db import make_session_factory
    from humpty.db.models import Function
    from humpty.db.session import session_scope

    db = tmp_path / "lf2.db"
    eng = create_engine(f"sqlite:///{db}")
    ini = Config(os.path.join(ROOT, "alembic.ini"))
    ini.set_main_option("script_location",
                        os.path.join(ROOT, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", f"sqlite:///{db}")
    command.upgrade(ini, "head")
    factory = make_session_factory(eng)
    sha = "c" * 64
    with session_scope(factory) as s:
        s.add(Function(binary_sha256=sha, name="FUN_4012a0",
                       demangled_sig="int sqlite3_exec(const char *, char **)",
                       address=0x4012a0, size=32))
    with session_scope(factory) as s:
        stats = prune_libraries(s, binary_sha256=sha, log=lambda *_: None)
    assert stats["pruned"] == 1
    with session_scope(factory) as s:
        fn = s.query(Function).filter_by(binary_sha256=sha).one()
    assert fn.state == "trusted" and fn.fingerprint == "vendor::sqlite"
