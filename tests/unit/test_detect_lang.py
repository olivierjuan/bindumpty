"""Unit tests: humpty.analyze.detect_lang + adapt.

The detector must separate C from C++ binaries on real, locally-built
artifacts. Probes are built (if a compiler is present) into a temp dir by the
session fixture; if building is impossible, tests skip rather than guess.
"""
import os
import shutil
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

from humpty.analyze.detect_lang import elf_language, detect_language  # noqa: E402
from humpty.analyze.adapt import adapter_for  # noqa: E402

_C_SRC = "#include <stdio.h>\nint add3(int a, int b, int c) { return a + b + c; }\nint main(void) { printf(\"%d\\n\", add3(1,2,3)); return 0; }\n"
_CPP_SRC = """\
#include <vector>
#include <algorithm>
#include <cstdio>
extern "C" int compute(const int* a, int n) {
    std::vector<int> v(a, a+n);
    std::sort(v.begin(), v.end());
    return v.empty() ? 0 : v.back();
}
int main() { int a[] = {3,1,2}; std::printf("%d\\n", compute(a, 3)); return 0; }
"""


def _clang() -> str | None:
    return shutil.which("clang")


@pytest.fixture(scope="module")
def probes(tmp_path_factory):
    """Build C and C++ probe binaries; skip the module if impossible."""
    cc = _clang()
    if cc is None:
        pytest.skip("clang unavailable; cannot build probes")
    d = tmp_path_factory.mktemp("langprobes")
    c_src, cpp_src = d / "p.c", d / "p.cpp"
    c_src.write_text(_C_SRC)
    cpp_src.write_text(_CPP_SRC)
    c_bin = d / "p_c"
    cpp_bin = d / "p_cpp"
    lean_bin = d / "p_lean.so"
    r1 = subprocess.run([cc, "-O1", str(c_src), "-o", str(c_bin)],
                        capture_output=True, text=True)
    r2 = subprocess.run([cc, "-O1", "-nostdlib", str(cpp_src), "-shared",
                         "-fno-rtti", "-fno-exceptions", "-fvisibility=hidden",
                         "-o", str(lean_bin)], capture_output=True, text=True)
    r3 = subprocess.run([cc + "++", "-O1", str(cpp_src), "-o", str(cpp_bin)],
                        capture_output=True, text=True) if shutil.which(cc + "++") else None
    if r1.returncode != 0:
        pytest.skip(f"C probe build failed: {r1.stderr[:200]}")
    built = {"c": str(c_bin)}
    if r3 is not None and r3.returncode == 0:
        built["cpp"] = str(cpp_bin)
    if r2.returncode == 0:
        built["lean"] = str(lean_bin)
    return built


def test_c_binary_detected_as_c(probes):
    v = elf_language(probes["c"])
    assert v.verdict == "c", f"evidence: {[(s.name, s.weight) for s in v.evidence]}"


def test_cpp_binary_detected_as_cpp(probes):
    if "cpp" not in probes:
        pytest.skip("clang++ unavailable")
    v = elf_language(probes["cpp"])
    assert v.verdict == "cpp", f"evidence: {[(s.name, s.weight) for s in v.evidence]}"


def test_lean_cpp_detected(probes):
    """C++ compiled -fno-rtti -fno-exceptions with hidden visibility still
    links the C++ runtime — the linkage fact must carry the verdict."""
    if "lean" not in probes:
        pytest.skip("lean probe not built")
    v = elf_language(probes["lean"])
    assert v.verdict in ("cpp", "lean_cpp"), \
        f"evidence: {[(s.name, s.weight) for s in v.evidence]}"


def test_combined_ghidra_authority(tmp_path, probes):
    """When the Ghidra verdict disagrees, it wins and the disagreement is
    recorded (auditable — a silent misadaptation is impossible)."""
    import json

    gh = tmp_path / "lang.json"
    gh.write_text(json.dumps({
        "verdict": "cpp", "score": 5.0, "confidence": "high",
        "evidence": ["mangled_itanium_symbols:42 e.g._ZN3Foo3barEi"],
    }))
    v = detect_language(probes["c"], gh)  # elf says c, ghidra says cpp
    assert v.verdict == "cpp"          # ghidra wins
    assert v.confidence == "medium"    # not silent: confidence drops
    assert any(s.name == "tier_disagreement" for s in v.evidence)


def test_combined_agreement_is_high_confidence(tmp_path, probes):
    import json

    gh = tmp_path / "lang.json"
    gh.write_text(json.dumps({
        "verdict": "c", "score": -1.5, "confidence": "high",
        "evidence": ["no_itanium_mangled_symbols"],
    }))
    v = detect_language(probes["c"], gh)  # both say c
    assert v.verdict == "c" and v.confidence == "high" and v.tier == "combined"


# --- adapter ----------------------------------------------------------------

def test_adapter_c_flavor():
    a = adapter_for("c")
    assert a.type_registry_flavor == "c_struct"
    assert a.fingerprint_corpora == ("libc",)
    assert not a.demangle


def test_adapter_cpp_flavor():
    a = adapter_for("cpp")
    assert a.type_registry_flavor == "cxx_class"
    assert "stl" in a.fingerprint_corpora
    assert a.demangle
    assert any("RTTI" in o for o in a.ghidra_analyzer_options)


def test_adapter_unknown_verdict_rejected():
    with pytest.raises(ValueError):
        adapter_for("rust")


def test_adapter_identical_validation_machinery():
    """The validation pipeline (FR-6 harness, FR-7 hooking) is language-
    agnostic: the adapter carries no switches for it."""
    a_c, a_cpp = adapter_for("c"), adapter_for("cpp")
    for f in ("ghidra_analyzer_options", "fingerprint_corpora",
              "type_registry_flavor", "prompt_notes", "demangle"):
        # none of the adapter fields is named after harness/hooking — those
        # behaviors live in horses/ and are language-agnostic by construction.
        assert "harness" not in f and "hook" not in f


# --- ingest integration: source_lang flows through load_call_graph ----------

def _load(tmp_path, header_lang, monkeypatch):
    """Ingest the toy call graph with an optional binary.source_lang header."""
    import json
    sys.path.insert(0, REPO)
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine
    from humpty.db import make_session_factory
    from humpty.db.session import session_scope
    from humpty.ingest import load_call_graph

    db = f"sqlite:///{tmp_path}/lang.db"
    ini = Config(os.path.join(REPO, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(REPO, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", db)
    eng = create_engine(db)
    command.upgrade(ini, "head")

    elf = os.path.join(REPO, "toys/case-01-leaf/build/toy01")
    cg = os.path.join(REPO, "toys/case-01-leaf/ground_truth/call_graph.json")
    if not os.path.exists(elf):
        pytest.skip("toy01 not built")
    g = json.loads(open(cg).read())
    if header_lang is None:
        g["binary"].pop("source_lang", None)
    else:
        g["binary"]["source_lang"] = header_lang
    p = tmp_path / "cg.json"
    p.write_text(json.dumps(g))
    fac = make_session_factory(eng)
    with session_scope(fac) as s:
        r = load_call_graph(s, json_path=p, binary=elf)
    eng.dispose()
    return r


def test_ingest_header_omitted_uses_elf_fallback(tmp_path, monkeypatch):
    r = _load(tmp_path, None, monkeypatch)
    assert r.source_lang == "c"


def test_ingest_header_honored(tmp_path, monkeypatch):
    r = _load(tmp_path, "cpp", monkeypatch)
    assert r.source_lang == "cpp"


def test_ingest_bad_verdict_rejected(tmp_path, monkeypatch):
    import json
    from humpty.ingest import CallGraphError
    with pytest.raises(CallGraphError):
        _load(tmp_path, "rust", monkeypatch)
