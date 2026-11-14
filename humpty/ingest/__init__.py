"""humpty.ingest — ingestion of the call graph into the database (FR-1).

Consumes the JSON that a headless disassembler export produces (see
``toys/case-01-leaf/ground_truth/call_graph.json`` for the reference format,
``fuz.call-graph/1``) and loads it into ``functions`` + ``call_edges``.

The JSON is *analysis output*, not an instruction set: it is validated strictly
against the schema and any field the pipeline does not understand is rejected,
never silently dropped.

Topology (topological order + SCCs) is computed here, not by the disassembler,
so the pipeline owns the graph invariants (FR-1: "Produce a topological order
with strongly connected components (recursion) identified").
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from humpty.db.models import CallEdge, EdgeKind, Function
from humpty.domain import State

__all__ = [
    "CallGraphError",
    "load_call_graph",
    "call_graph_topo_order",
    "strongly_connected_components",
    "binary_sha256",
]

FORMAT = "fuz.call-graph/1"

_EDGE_KINDS = frozenset(k.value for k in EdgeKind)


class CallGraphError(ValueError):
    """The call-graph JSON failed validation."""


def binary_sha256(elf_path: str | Path) -> str:
    """SHA-256 of the binary — its NFR-2 identity."""
    h = hashlib.sha256()
    with open(elf_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _require(obj: dict, key: str, where: str) -> object:
    if key not in obj:
        raise CallGraphError(f"{where}: missing required key {key!r}")
    return obj[key]


@dataclass(frozen=True)
class Graph:
    """Validated, in-memory call graph (names resolved to ids at load)."""

    functions: dict[str, int]  # name -> db id
    edges: list[tuple[int, int, str]]
    topological_order: list[int]  # db ids, callees before callers
    scc_ids: dict[int, int]  # function db id -> scc id (recursion groups)
    # Source-language verdict driving the pipeline adapter ("c" | "cpp" |
    # "lean_cpp"); detected per binary (Ghidra authority, ELF pre-filter
    # fallback) — see humpty.analyze.detect_lang.
    source_lang: str = "c"
    # Which exporter produced this graph ("ghidra" | "objdump" | ...). The
    # king cross-checks two backends' graphs against each other when both
    # exist for one binary — a cheap pre-LLM disagreement signal.
    backend: str = "unknown"


def strongly_connected_components(
    node_ids: list[int], edges: list[tuple[int, int]]
) -> list[list[int]]:
    """Iterative Tarjan SCC. Returns SCCs (lists of node ids); singletons
    included. Deterministic: nodes processed in the given order."""
    index_counter = 0
    index: dict[int, int] = {}
    lowlink: dict[int, int] = {}
    on_stack: set[int] = set()
    stack: list[int] = []
    sccs: list[list[int]] = []

    adj: dict[int, list[int]] = {n: [] for n in node_ids}
    for a, b in edges:
        adj[a].append(b)

    for root in node_ids:
        if root in index:
            continue
        work = [(root, iter(adj[root]))]
        index[root] = lowlink[root] = index_counter
        index_counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, it = work[-1]
            advanced = False
            for nxt in it:
                if nxt not in index:
                    index[nxt] = lowlink[nxt] = index_counter
                    index_counter += 1
                    stack.append(nxt)
                    on_stack.add(nxt)
                    work.append((nxt, iter(adj[nxt])))
                    advanced = True
                    break
                elif nxt in on_stack:
                    lowlink[node] = min(lowlink[node], index[nxt])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                lowlink[parent] = min(lowlink[parent], lowlink[node])
            if lowlink[node] == index[node]:
                comp: list[int] = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp.append(w)
                    if w == node:
                        break
                sccs.append(comp)
    return sccs


def call_graph_topo_order(
    node_ids: list[int],
    edges: list[tuple[int, int]],
    sccs: list[list[int]] | None = None,
) -> list[int]:
    """Kahn topological order (callees before callers) over the *condensation*
    of the call graph: each SCC (a recursion group) is collapsed to one node,
    so mutual recursion does not create a false cycle. Deterministic: ties are
    broken by input order; within an SCC, members are emitted in input order.

    ``sccs`` should be the SCCs from :func:`strongly_connected_components`
    (singletons optional). A cycle that is *not* an SCC is a validation error.
    """
    node_ids = list(node_ids)
    sccs = sccs or []
    comp_of: dict[int, int] = {}
    for sid, comp in enumerate(sccs):
        for n in comp:
            comp_of[n] = sid
    comp_units: dict[int, int] = {}
    node_unit: dict[int, int] = {}
    units: list[list[int]] = []
    for n in node_ids:
        c = comp_of.get(n)
        if c is None:
            node_unit[n] = len(units)
            units.append([n])
        else:
            if c not in comp_units:
                comp_units[c] = len(units)
                units.append([])
            node_unit[n] = comp_units[c]
            units[comp_units[c]].append(n)
    n_units = len(units)
    indeg = [0] * n_units
    adj: list[list[int]] = [[] for _ in range(n_units)]
    for a, b in edges:
        ca, cb = node_unit[a], node_unit[b]
        if ca == cb:
            continue  # intra-SCC (recursive) edge: contracted
        adj[cb].append(ca)  # a calls b => b (callee) precedes a (caller)
        indeg[ca] += 1
    ready = [i for i in range(n_units) if indeg[i] == 0]
    order_units: list[int] = []
    i = 0
    while i < len(ready):
        u = ready[i]
        i += 1
        order_units.append(u)
        for v in adj[u]:
            indeg[v] -= 1
            if indeg[v] == 0:
                ready.append(v)
    if len(order_units) != n_units:
        cyclic_units = [u for u in range(n_units) if u not in order_units]
        raise CallGraphError(
            f"call graph has a cycle not collapsed into an SCC: {cyclic_units}"
        )
    out: list[int] = []
    for u in order_units:
        out.extend(units[u])
    return out


def load_call_graph(session: Session, *, json_path: str | Path, binary: str | Path) -> Graph:
    """Validate and load a call-graph JSON into the given session.

    The caller commits (or rolls back) — loading participates in the caller's
    transaction so a partial ingest never commits.
    """
    data = json.loads(Path(json_path).read_text())
    if data.get("format") != FORMAT:
        raise CallGraphError(
            f"unsupported call-graph format {data.get('format')!r} (want {FORMAT!r})"
        )

    sha = binary_sha256(binary)

    # Source-language verdict (FR-1 aux): prefer the binary header's
    # source_lang (Ghidra's authority, emitted by ExportCallGraph.java);
    # fall back to the ELF pre-filter scan when the header omits it. The
    # pre-filter requires a real ELF64; anything else (a unit-test fake, a
    # non-x86 object) keeps the verdict undetermined rather than failing the
    # load — detection is an enhancement, never a gate.
    from humpty.analyze.detect_lang import elf_language

    header = data.get("binary", {})
    src_lang = header.get("source_lang")
    if src_lang is None:
        try:
            src_lang = elf_language(binary).verdict
        except (ValueError, OSError):
            src_lang = "c"
    elif src_lang not in ("c", "cpp", "lean_cpp"):
        raise CallGraphError(f"binary.source_lang: bad verdict {src_lang!r}")

    # Exporter backend (multi-backend seam, analysis/exporters): recorded so
    # cross-backend runs are attributable, and so the king can schedule a
    # cross-check when two backends produced graphs for one binary.
    backend = header.get("backend", "unknown")
    if not isinstance(backend, str) or not backend.strip():
        raise CallGraphError("binary.backend: must be a non-empty string")

    # --- functions ------------------------------------------------------
    ids: dict[str, int] = {}
    nodes: list[int] = []
    for i, fn in enumerate(data.get("functions", [])):
        name = _require(fn, "name", f"functions[{i}]")
        addr = int(str(_require(fn, "address", f"functions[{i}]")), 0)
        size = int(_require(fn, "size", f"functions[{i}]"))
        sig = fn.get("demangled_sig")
        if sig is not None and not isinstance(sig, str):
            raise CallGraphError(f"functions[{i}].demangled_sig must be str")
        has_rtti = bool(fn.get("has_rtti", False))
        if str(name) in ids:
            raise CallGraphError(f"duplicate function name {name!r}")
        row = Function(
            binary_sha256=sha,
            name=str(name),
            address=addr,
            size=size,
            # For a stripped binary the analyzer's name (FUN_000011b0 or a
            # demangled symbol) is the best identifier available; keep it in
            # demangled_sig so prompts and reports can reference the function.
            demangled_sig=sig if sig is not None else str(name),
            has_rtti=has_rtti,
            state=State.PENDING.value,
        )
        session.add(row)
        session.flush()
        ids[name] = row.id
        nodes.append(row.id)

    # --- edges ----------------------------------------------------------
    edges: list[tuple[int, int, str]] = []
    seen_edges: set[tuple[str, str, str]] = set()
    for i, e in enumerate(data.get("edges", [])):
        caller = _require(e, "caller", f"edges[{i}]")
        callee = _require(e, "callee", f"edges[{i}]")
        kind = str(e.get("kind", "direct"))
        if kind not in _EDGE_KINDS:
            raise CallGraphError(f"edges[{i}]: bad kind {kind!r}")
        if caller not in ids or callee not in ids:
            raise CallGraphError(f"edges[{i}]: unknown endpoint {caller!r}/{callee!r}")
        if caller == callee:
            raise CallGraphError(f"edges[{i}]: self-loop on {caller!r}")
        # duplicate parallel edges (e.g. two call sites to one callee, or an
        # exporter emitting per-site rows) collapse to one — the graph is a
        # set, the call-site count lives in the analysis, not the edge table.
        key = (caller, callee, kind)
        if key in seen_edges:
            continue
        seen_edges.add(key)
        edges.append((ids[caller], ids[callee], kind))
        session.add(
            CallEdge(caller_id=ids[caller], callee_id=ids[callee], kind=kind)
        )

    # --- SCCs (recursion) ----------------------------------------------
    sccs = strongly_connected_components(nodes, [(a, b) for a, b, _ in edges])
    scc_ids: dict[int, int] = {}
    for sid, comp in enumerate(s for s in sccs if len(s) > 1):
        for n in comp:
            scc_ids[n] = sid
            fn = session.get(Function, n)
            assert fn is not None
            fn.scc_id = sid

    # --- topological order (SCC-condensed) -------------------------------
    order = call_graph_topo_order(nodes, [(a, b) for a, b, _ in edges], sccs=sccs)

    session.flush()
    return Graph(functions=ids, edges=edges, topological_order=order,
                 scc_ids=scc_ids, source_lang=src_lang, backend=backend)
