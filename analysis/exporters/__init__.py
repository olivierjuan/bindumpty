"""analysis.exporters — source-language-agnostic call-graph export backends.

Every backend emits the same neutral artifact: ``fuz.call-graph/1`` JSON
(see ``toys/case-01-leaf/ground_truth/call_graph.json``). Downstream (ingest,
CEGIS, harness) consumes only that contract — never analyzer specifics — so
backends are interchangeable and cross-checkable.

Backend contract (``BackendExporter``):
    export(binary_path, out_json, lang_out=None) -> ExportResult

    ExportResult:
        backend        "ghidra" | "objdump" | ...
        source_lang    verdict from this backend ("c" | "cpp" | "lean_cpp")
        functions      list of {name, address, size, ...}
        edges          list of {caller, callee, kind}
        notes          backend-specific caveats (recorded, not swallowed)

Why several backends: two analyzers disagreeing on an edge is a cheap,
pre-LLM signal (the cross-check lives in ``compare_backends``). The Ghidra
backend is the authority for language detection (it sees demanglings and
RTTI recovery); the objdump backend is the fast always-available fallback.

Adding a backend = one module here + a registration in ``BACKENDS``. Nothing
else in the pipeline changes.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["ExportResult", "export_with", "BACKENDS", "compare_backends"]

ROOT = Path(__file__).resolve().parents[2]


@dataclass
class ExportResult:
    backend: str
    source_lang: str  # "c" | "cpp" | "lean_cpp" | "unknown"
    functions: list[dict]
    edges: list[dict]
    notes: list[str] = field(default_factory=list)

    def to_call_graph(self, binary_sha256: str, arch: str = "x86-64") -> dict:
        """Wrap into the fuz.call-graph/1 envelope (ingest-ready)."""
        return {
            "format": "fuz.call-graph/1",
            "binary": {
                "sha256": binary_sha256,
                "arch": arch,
                "kind": "elf",
                "is_pie": None,  # backends that know it set a bool
                "is_stripped": None,
                "source_lang": self.source_lang,
                "backend": self.backend,
            },
            "functions": self.functions,
            "edges": self.edges,
            "backend_notes": self.notes,
        }


def export_with(backend: str, binary: str | Path, out_json: str | Path,
                progress=None) -> ExportResult:
    """Run one backend by name. Unknown backends are a hard error.
    `progress(done, total)` streams per-symbol progress for backends that
    support it (objdump chunked mode); ignored by the rest."""
    if backend not in BACKENDS:
        raise ValueError(f"unknown backend {backend!r} (have: {sorted(BACKENDS)})")
    return BACKENDS[backend](binary, out_json, progress)


def _write_out(res: ExportResult, out_json: str | Path, sha: str) -> ExportResult:
    doc = res.to_call_graph(sha)
    Path(out_json).write_text(json.dumps(doc, indent=1))
    return res


def compare_backends(a: ExportResult, b: ExportResult) -> dict:
    """Edge-level cross-check between two backends (name-normalized).

    Returns the agreement verdict + the disagreement list — a cheap pre-LLM
    signal: two analyzers disagreeing on an edge usually means an indirect
    call one of them resolved differently.
    """
    ea = {(e["caller"], e["callee"]) for e in a.edges}
    eb = {(e["caller"], e["callee"]) for e in b.edges}
    return {
        "backends": [a.backend, b.backend],
        "agree": ea == eb,
        "only_in_" + a.backend: sorted(ea - eb),
        "only_in_" + b.backend: sorted(eb - ea),
        "lang_agree": a.source_lang == b.source_lang,
        "verdicts": [a.source_lang, b.source_lang],
    }


# --- backend implementations -------------------------------------------------


def _objdump_backend(binary: str | Path, out_json: str | Path,
                     progress=None) -> ExportResult:
    """objdump backend: parse call sites from the disassembly, assign each to
    its containing function. Fast, always available, no name recovery on
    stripped binaries (names stay FUN_<vaddr>-style)."""
    from .objdump_export import objdump_call_graph

    res = objdump_call_graph(binary, progress=progress)
    return res  # caller writes it out (sha known there)


def _ghidra_backend(binary: str | Path, out_json: str | Path) -> ExportResult:
    """Ghidra backend: run the headless analyzer + ExportCallGraph.java and
    return its already-contract-shaped output."""
    import hashlib
    import tempfile

    ghidra_root = ROOT / "analysis/ghidra/dist/ghidra_12.2_PUBLIC"
    headless = ghidra_root / "support/analyzeHeadless"
    if not headless.exists():
        raise RuntimeError(f"Ghidra not installed at {ghidra_root}")
    with tempfile.TemporaryDirectory() as td:
        proj = Path(td) / "proj"
        proj.mkdir()
        lang_out = Path(td) / "lang.json"
        cmd = [str(headless), str(proj), "X", "-import", str(binary), "-overwrite",
               "-scriptPath", str(ROOT / "analysis/ghidra/scripts"),
               "-postScript", "ExportCallGraph.java", str(out_json), str(lang_out)]
        subprocess.run(cmd, check=True, capture_output=True, text=True,
                       timeout=600, env={"JAVA_HOME": "/usr/lib/jvm/java-25-openjdk-amd64",
                                         "PATH": "/usr/bin:/bin"})
        doc = json.loads(Path(out_json).read_text())
        lang = json.loads(lang_out.read_text())
    h = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
    res = ExportResult(
        backend="ghidra",
        source_lang=doc["binary"].get("source_lang", "unknown"),
        functions=doc["functions"],
        edges=doc["edges"],
        notes=["headless default analysis; PIE main may be missing (FR-3 completes it)"],
    )
    return _write_out(res, out_json, h)


def _objdump_write(binary: str | Path, out_json: str | Path,
                   progress=None) -> ExportResult:
    import hashlib

    res = _objdump_backend(binary, out_json, progress=progress)
    h = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
    return _write_out(res, out_json, h)


def _rizin_write(binary: str | Path, out_json: str | Path,
                 progress=None) -> ExportResult:
    import hashlib

    from .rizin_export import rizin_call_graph

    res = rizin_call_graph(binary, progress=progress)
    h = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
    return _write_out(res, out_json, h)


BACKENDS = {
    "objdump": _objdump_write,
    "ghidra": _ghidra_backend,
    "rizin": _rizin_write,
}
