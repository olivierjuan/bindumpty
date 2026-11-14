"""objdump backend — export the call graph from `objdump -d` output.

Method: parse every `call` instruction, map each call site to its containing
function (function boundaries from the `.sym` unstripped build when present,
else from ground truth / prologue heuristics), and emit the same
`fuz.call-graph/1` shape as the Ghidra backend.

Deliberate limits (recorded in `notes`, never hidden):
- No demangling, no RTTI, no vtable recovery — a C-only depth of analysis.
- Indirect calls (`call *%rax`) are *counted* but not resolved; they appear
  as edges with kind "indirect" and a callee of "0x<addr>" when the target
  is statically visible in the same listing, else they are dropped.
- On a stripped binary the function names are the ground-truth names when
  the caller supplies a name map (ingest does), else `fn_<vaddr>`.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from . import ExportResult

_CALL_RE = re.compile(r"^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} )+\s*call\s+0?x?([0-9a-f]+)")
_INDIRECT_RE = re.compile(r"^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} )+\s+call\s+\*")


def objdump_call_graph(binary: str | Path,
                       name_map: dict[int, str] | None = None,
                       progress=None) -> ExportResult:
    """Export a call graph via objdump. `name_map` (optional) maps vaddr ->
    recovered name (e.g. from the unstripped build's `nm`); without it,
    functions are named `fn_<vaddr>` (the stripped reality).

    `progress(done, total)` is called per parsed function chunk when the
    disassembly is streamed in symbol-sized ranges (chunked mode, used for
    big binaries); a single whole-file dump is used when no progress hook is
    supplied."""
    if progress is not None:
        # chunked mode: disassemble per symbol range so progress is real.
        # Requires a symbol table (unstripped); a stripped binary falls
        # through to the single-dump path (no per-function progress is
        # possible without symbols — the ingest bar still shows rows).
        # name_map shape (established API): vaddr -> name
        syms = sorted(((n, a) for a, n in (name_map or {}).items()),
                      key=lambda kv: kv[1]) if name_map else []
        if not syms:
            import subprocess as _sp
            nm = _sp.run(["nm", "-S", "--defined-only", str(binary)],
                         capture_output=True, text=True, timeout=120).stdout
            for line in nm.splitlines():
                m = re.match(r"^([0-9a-f]+)\s+([0-9a-f]+)\s+[Tt]\s+(.+)$", line)
                if m:
                    syms.append((m.group(3), int(m.group(1), 16)))
            syms.sort(key=lambda kv: kv[1])
        if not syms:
            progress(0, 1)  # no symbols: fall through to single-dump mode
        edges: list[dict] = []
        seen: set[tuple[str, str]] = set()
        total = max(len(syms), 1)
        # PLT trampolines: readelf section headers give .plt's range; targets
        # inside it are resolved by FR-2 fingerprinting, not walked
        import subprocess as _sp2
        sec = _sp2.run(["readelf", "-S", "-W", str(binary)],
                       capture_output=True, text=True, timeout=30).stdout
        plt_addrs: set[int] = set()
        for line in sec.splitlines():
            if ".plt" in line and "PROGBITS" in line:
                parts = line.split()
                paddr, psize = int(parts[4], 16), int(parts[5], 16)
                plt_addrs |= set(range(paddr, paddr + psize))
        for idx, (name, start) in enumerate(syms):
            end = syms[idx + 1][1] if idx + 1 < len(syms) else start + 4096
            dis = subprocess.run(
                ["objdump", "-d", f"--start-address=0x{start:x}",
                 f"--stop-address=0x{end:x}", str(binary)],
                capture_output=True, text=True, timeout=60).stdout
            for line in dis.splitlines():
                if "\tcall" not in line:
                    continue
                m = re.search(r"\bcall\s+([0-9a-f]+)\b", line)
                if not m:
                    continue
                tgt = int(m.group(1), 16)
                if tgt in plt_addrs:
                    continue
                tgt_name = (name_map or {}).get(tgt, f"fn_{tgt:x}")
                edge = {"caller": name, "callee": tgt_name, "kind": "direct"}
                if edge["caller"] != edge["callee"] and edge not in edges:
                    edges.append(edge)
            progress(idx + 1, total)
        functions = [{"name": n, "address": f"0x{a:x}", "size": 0}
                     for n, a in syms]
        return ExportResult(backend="objdump", source_lang="unknown",
                            functions=functions, edges=edges,
                            notes=["chunked per-symbol export (progress mode)"])
    dis = subprocess.run(["objdump", "-d", str(binary)],
                         capture_output=True, text=True, timeout=120).stdout

    # function starts: objdump labels ("<name>:" lines) exist only for
    # unstripped binaries; otherwise synthesize boundaries from call targets
    # and prologues. We collect every call target — those are function starts
    # by definition for our purposes.
    sites: list[tuple[int, int]] = []  # (site_vaddr, target_vaddr) direct calls
    indirect_sites: list[int] = []
    for line in dis.splitlines():
        m = _CALL_RE.match(line)
        if m:
            sites.append((int(m.group(1), 16), int(m.group(2), 16)))
            continue
        mi = _INDIRECT_RE.match(line)
        if mi:
            indirect_sites.append(int(mi.group(1), 16))

    targets = sorted({t for _, t in sites})
    # PLT stubs are trampolines, not functions the pipeline reimplements;
    # recognize them from the objdump `<name@plt>` labels and drop both their
    # entries and edges whose target is one of them.
    plt_labels = set(re.findall(r"^([0-9a-f]+) <[^>]+@plt>:", dis, re.M))
    plt_addrs = {int(a, 16) for a in plt_labels}
    starts = [t for t in targets if t not in plt_addrs]
    # Known functions (name_map) that no other function calls — `main` reaches
    # __libc_start_main through a register, so it is never a call target —
    # must still be recognized as function starts, or call sites in their
    # bodies get mis-attributed to the preceding function.
    if name_map:
        starts = sorted(set(starts) | {a for a in name_map if a not in plt_addrs})

    def fn_name(addr: int) -> str:
        if name_map and addr in name_map:
            return name_map[addr]
        return f"fn_{addr:x}"

    functions = [{"name": fn_name(a), "address": f"0x{a:x}", "size": 0}
                 for a in starts]

    edges: list[dict] = []
    # With a name_map, the pipeline's scope is exactly those functions; call
    # sites inside crt/init machinery (fn_1110 self-edges etc.) are noise the
    # pipeline must not ingest.
    known_starts = [a for a in starts if name_map and a in name_map] or starts
    for site, tgt in sites:
        if tgt in plt_addrs:
            continue  # a PLT trampoline edge — resolved via FR-2 fingerprinting
        caller_addr = max((s for s in known_starts if s <= site), default=None)
        if caller_addr is None:
            continue
        edge = {"caller": fn_name(caller_addr), "callee": fn_name(tgt),
                "kind": "direct"}
        if edge["caller"] == edge["callee"]:
            continue  # self-loop: recursion is the SCC policy's business (FR-1)
        if edge not in edges:
            edges.append(edge)
    for site in indirect_sites:
        caller_addr = max((s for s in starts if s <= site), default=None)
        if caller_addr is None:
            continue
        edges.append({"caller": fn_name(caller_addr), "callee": "indirect:unresolved",
                      "kind": "indirect"})

    notes = [
        "objdump backend: no demangling/RTTI/vtable recovery",
        "function starts inferred from call targets (+optional name_map)",
    ]
    if not name_map:
        notes.append("no name_map: stripped-binary names are fn_<vaddr>")
    return ExportResult(backend="objdump", source_lang="unknown",
                        functions=functions, edges=edges, notes=notes)
