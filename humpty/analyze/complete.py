"""humpty.analyze.complete — FR-1 extension: complete the call graph from
dynamic evidence, and apply the SCC policy decision.

Two gaps in static analysis, both filled here:

1. **Indirect-call completion (FR-1 ext).** A stripped binary's virtual
   calls and function-pointer calls are unresolved edges (kind "indirect")
   or, worse, missing entirely. Record-replay (FR-3) observes the real
   callee at runtime; merging those observations promotes "missing" to a
   real edge and can refine an "indirect" edge to its observed target. The
   merged graph is the one the ready-set computation runs on.

2. **SCC policy (M2 decision).** Recursive clusters (SCCs with >1 node)
   cannot be validated leaf-first. Config `scc_policy` decides:
     - "indivisible" (default): the SCC is one validation unit — validated
       as a whole, trusted/failed together.
     - "unroll": attempt per-function validation inside the SCC in
       call-graph order, allowing a fixed-point pass (documented as v0:
       works for simple self/mutual recursion where each function's
       correctness does not depend on the *trustedness* of the others).

Both are pure graph operations on the DB — no analyzer involvement.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from humpty.db.events import record_event
from humpty.db.models import CallEdge, Function
from humpty.ingest import strongly_connected_components

__all__ = ["complete_from_traces", "apply_scc_policy", "SccPlan"]


@dataclass
class SccPlan:
    """Result of applying the SCC policy: validation order + groupings."""

    order: list[int]  # function db ids in validation order
    indivisible: list[list[int]]  # SCC groups validated as a unit
    policy: str


def complete_from_traces(session: Session, *, binary_sha256: str,
                         observed_calls: list[tuple[int, int]],
                         confidence: float = 1.0) -> int:
    """Merge runtime-observed call edges into the graph.

    `observed_calls`: (caller_vaddr, callee_vaddr) pairs observed by the
    tracer (FR-3). For each pair: if both functions exist and the edge is
    missing, add it (kind "direct" — the trace proves a concrete call); if
    an "indirect" edge exists between them, promote it to "direct" (the
    runtime resolved the indirection).

    Returns the number of edges added or promoted. Writes one event per
    mutation (append-only audit, FR-17).
    """
    by_addr = {}
    for fn in session.query(Function).filter(
            Function.binary_sha256 == binary_sha256).all():
        by_addr[fn.address] = fn

    existing = {}
    for e in session.query(CallEdge).join(
            Function, CallEdge.caller_id == Function.id).filter(
            Function.binary_sha256 == binary_sha256).all():
        existing[(e.caller_id, e.callee_id)] = e

    changed = 0
    for caller_addr, callee_addr in observed_calls:
        caller = by_addr.get(caller_addr)
        callee = by_addr.get(callee_addr)
        if caller is None or callee is None or caller.id == callee.id:
            continue
        edge = existing.get((caller.id, callee.id))
        if edge is None:
            session.add(CallEdge(caller_id=caller.id, callee_id=callee.id,
                                 kind="direct"))
            existing[(caller.id, callee.id)] = CallEdge(
                caller_id=caller.id, callee_id=callee.id, kind="direct")
            changed += 1
            record_event(session, kind="edge_added_from_trace",
                         function_id=caller.id,
                         payload={"callee": callee.name,
                                  "confidence": confidence})
        elif edge.kind == "indirect":
            edge.kind = "direct"  # runtime resolved the indirection
            changed += 1
            record_event(session, kind="edge_promoted_from_trace",
                         function_id=caller.id,
                         payload={"callee": callee.name})
    if changed:
        session.flush()
    return changed


def apply_scc_policy(session: Session, *, binary_sha256: str,
                     policy: str) -> SccPlan:
    """Compute the validation order for one binary under the SCC policy.

    "indivisible": SCC groups (>1 node) are single units; the order is the
    topological order of the condensation with each group contiguous.
    "unroll": every function validated individually, in the same
    topological order (leaf-first), recursions revisited in a second pass.
    """
    from humpty.ingest import call_graph_topo_order

    fns = (session.query(Function)
           .filter(Function.binary_sha256 == binary_sha256)
           .order_by(Function.address).all())
    id_of = {f.id: f for f in fns}
    nodes = [f.id for f in fns]
    edges = [(e.caller_id, e.callee_id)
             for e in session.query(CallEdge).join(
                 Function, CallEdge.caller_id == Function.id).filter(
                 Function.binary_sha256 == binary_sha256).all()]

    sccs = strongly_connected_components(nodes, edges)
    order = call_graph_topo_order(nodes, edges, sccs=sccs)
    multi = [sorted(c) for c in sccs if len(c) > 1]

    if policy == "indivisible":
        # keep the topo order but make each multi-node SCC contiguous
        group_of = {}
        for gid, comp in enumerate(multi):
            for n in comp:
                group_of[n] = gid
        out: list[int] = []
        done_groups: set[int] = set()
        for n in order:
            gid = group_of.get(n)
            if gid is None:
                out.append(n)
            elif gid not in done_groups:
                done_groups.add(gid)
                out.extend(multi[gid])
        return SccPlan(order=out, indivisible=multi, policy=policy)

    if policy == "unroll":
        # leaf-first order for everything; SCC members get a second fixed-
        # point pass after the first full sweep (v0: order-level handling —
        # the loop itself re-fuzzes on each pass).
        scc_members = {n for comp in multi for n in comp}
        return SccPlan(order=order + [n for n in order if n in scc_members],
                       indivisible=[], policy=policy)

    raise ValueError(f"unknown scc_policy {policy!r}")
