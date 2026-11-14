"""rizin backend — export the call graph via the rizin CLI (third backend).

rizin v0.9.1 static x86_64 (pinned; see analysis/rizin/PIN.txt). Same
neutral `fuz.call-graph/1` output as the other backends.

Method: `aaa` analysis, then per-function `axtq` (quiet xrefs to a target):
for each discovered function, the call sites targeting it. Callers are
resolved by containment (the function whose body contains the site). Shares
the known analyzer gap: `main` (register-passed to __libc_start_main) is not
discovered, so its outgoing edge is attributed to (nofunc) and dropped —
FR-3 trace completion supplies it, same as the other backends.

Deliberate limits: no demangling of C++ (the `sym.imp.*` imports are
library calls, not edges the pipeline reimplements — dropped like PLTs).
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from . import ExportResult

ROOT = Path(__file__).resolve().parents[2]
RIZIN = ROOT / "analysis/rizin/dist/bin/rizin"

_XREF_RE = re.compile(r"^(?:\(nofunc\)\s+)?0x([0-9a-f]+)")
_FUNC_RE = re.compile(r"^0x([0-9a-f]+)\s+\d+\s+\d+\s+(?:->\s+\d+\s+)?(\S+)")


def rizin_call_graph(binary: str | Path,
                     name_map: dict[int, str] | None = None,
                     progress=None) -> ExportResult:
    """Export a call graph via rizin. `name_map` (optional) overrides names
    for known functions (same semantics as the objdump backend)."""
    if not RIZIN.exists():
        raise RuntimeError(f"rizin not installed at {RIZIN}")

    def rz(cmds: str) -> str:
        return subprocess.run([str(RIZIN), "-q", "-c", cmds, str(binary)],
                              capture_output=True, text=True,
                              timeout=300).stdout

    flist = rz("aaa; afl")
    functions: list[dict] = []
    func_starts: list[int] = []
    for line in flist.splitlines():
        m = _FUNC_RE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        name = m.group(2)
        if name.startswith("sym.imp."):
            continue  # imports: FR-2 fingerprinting, not reimplementations
        func_starts.append(addr)
        functions.append({"name": name, "address": f"0x{addr:x}", "size": 0})

    # known functions that are never call targets must still be starts
    def _nm(a: int) -> str:
        if name_map and a in name_map:
            return name_map[a]
        return f"fn_{a:x}"

    if name_map:
        func_starts = sorted(set(func_starts) | set(name_map))
    functions = [{"name": _nm(a), "address": f"0x{a:x}", "size": 0}
                 for a in func_starts]

    def fn_name(addr: int) -> str:
        if name_map and addr in name_map:
            return name_map[addr]
        return f"fn_{addr:x}"

    edges: list[dict] = []
    seen: set[tuple[str, str]] = set()
    total = max(len(func_starts), 1)
    for i, a in enumerate(func_starts):
        if progress is not None:
            progress(i, total)
        tgt_name = fn_name(a)
        out = rz(f"aaa; axtq @ 0x{a:x}")
        for line in out.splitlines():
            m = _XREF_RE.match(line)
            if not m:
                continue
            site = int(m.group(1), 16)
            scope = [s for s in func_starts if not name_map or s in name_map] or func_starts
            caller = max((s for s in scope if s <= site), default=None)
            if caller is None:
                continue
            caller_name = fn_name(caller)
            if caller_name == tgt_name or (caller_name, tgt_name) in seen:
                continue  # self-loop / dedupe (site-level calls collapse)
            seen.add((caller_name, tgt_name))
            edges.append({"caller": caller_name, "callee": tgt_name,
                          "kind": "direct"})

    if progress is not None:
        progress(total, total)
    return ExportResult(
        backend="rizin", source_lang="unknown", functions=functions,
        edges=edges,
        notes=[
            "rizin backend: no demangle/RTTI; imports dropped (FR-2 resolves)",
            "register-passed main is undiscovered (FR-3 completes it) — same "
            "known gap as the Ghidra backend",
        ],
    )
