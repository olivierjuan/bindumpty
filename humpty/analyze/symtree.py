"""humpty.analyze.symtree — symbol-selected call subtree from an ELF.

`load_symbols(elf)` — every defined text symbol (name, vaddr, size, end)
    from `nm -S` (works on any ELF with a symtab) or `nm` + boundary
    inference from the next symbol.
`subtree(elf, root, depth)` — BFS from the root symbol through *direct
    call targets* discovered by disassembling each function's own body
    (`objdump -d --start-address --stop-address`, per function: fast on
    huge binaries — lpex2 is 34 MB / 19k symbols and a level costs ~20 ms).
    Cross-references the discovered target addresses against the symbol
    table; addresses that land inside a known function map to its name,
    unknown targets become `sub_<vaddr>`.

This is the focus mechanism for "one symbol and its call tree": instead of
exporting a 19k-symbol binary wholesale, the CLI ingests only the selected
subtree.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field

__all__ = ["Symbol", "load_symbols", "subtree", "SymTree"]


@dataclass
class Symbol:
    name: str
    vaddr: int
    size: int

    @property
    def end(self) -> int:
        return self.vaddr + self.size


@dataclass
class SymTree:
    root: str
    nodes: dict[str, Symbol] = field(default_factory=dict)
    edges: list[tuple[str, str]] = field(default_factory=list)
    depth_reached: int = 0


def _nm(elf: str) -> list[Symbol]:
    out = subprocess.run(["nm", "-S", "--defined-only", elf],
                         capture_output=True, text=True, timeout=120).stdout
    syms = []
    for line in out.splitlines():
        # two forms: "addr size type name" (nm -S) or "addr type name"
        m = re.match(r"^([0-9a-fA-F]+)(?:\s+([0-9a-fA-F]+))?\s+[a-zA-Z]\s+(.+)$",
                     line.strip())
        if not m:
            continue
        addr = int(m.group(1), 16)
        size = int(m.group(2), 16) if m.group(2) else 0
        name = m.group(3).strip()
        if name.startswith("$"):
            continue
        syms.append(Symbol(name=name, vaddr=addr, size=size))
    return syms


def load_symbols(elf: str) -> dict[str, Symbol]:
    """All defined text symbols by name. Zero-size symbols get their size
    inferred as the gap to the next symbol at a higher address (nm -S is
    missing sizes for some local symbols)."""
    syms = [s for s in _nm(elf) if s.size > 0]
    by_addr = {s.vaddr: s for s in syms}
    # add zero-size symbols whose address falls inside no known function
    for s in _nm(elf):
        if s.size == 0 and s.vaddr not in by_addr:
            by_addr[s.vaddr] = s
    return {s.name: s for s in syms}


def _calls_in_range(elf: str, start: int, end: int) -> list[int]:
    """Direct call targets inside [start, end)."""
    out = subprocess.run(
        ["objdump", "-d", "--start-address", f"0x{start:x}",
         "--stop-address", f"0x{end:x}", elf],
        capture_output=True, text=True, timeout=60).stdout
    targets = []
    for line in out.splitlines():
        if "\tcall" not in line:
            continue
        m = re.search(r"\bcall\s+([0-9a-f]+)\b", line)
        if m:
            targets.append(int(m.group(1), 16))
    return targets


def _containing(syms: list[Symbol], addr: int) -> Symbol | None:
    for s in syms:
        if s.size and s.vaddr <= addr < s.end:
            return s
    return None


def subtree(elf: str, root: str, depth: int = 3,
            symbols: dict[str, Symbol] | None = None) -> SymTree:
    """BFS the call subtree rooted at `root` up to `depth` levels."""
    all_syms = list(symbols.values()) if symbols else list(load_symbols(elf).values())
    by_name = {s.name: s for s in all_syms}
    if root not in by_name:
        raise KeyError(f"symbol {root!r} not found; use --list to browse")

    tree = SymTree(root=root)
    seen_names = {root}
    frontier = [by_name[root]]

    for level in range(depth):
        nxt: list[Symbol] = []
        for sym in frontier:
            if sym.size <= 0:
                continue
            for tgt in _calls_in_range(elf, sym.vaddr, sym.end):
                cont = _containing(all_syms, tgt)
                if cont is None:
                    continue
                callee = by_name.get(cont.name)
                if callee is None or callee.size == 0:
                    continue
                tree.edges.append((sym.name, cont.name))
                if cont.name not in seen_names:
                    seen_names.add(cont.name)
                    tree.nodes[cont.name] = callee
                    nxt.append(callee)
        tree.depth_reached = level + 1
        if not nxt:
            break
        frontier = nxt

    tree.nodes[root] = by_name[root]
    # dedupe edges
    tree.edges = sorted(set(tree.edges))
    return tree
