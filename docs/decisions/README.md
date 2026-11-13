# docs/decisions — ADRs

Architecture Decision Records. One file per decision: `NNNN-short-title.md`
(e.g. `0001-agent-runtime.md`), appended never rewritten; superseded ADRs keep
their files and get a `Status: superseded by NNNN` header.

## Pending (from WHITEPAPERS.md §9 "Open decisions")

| ADR | Decision | Decide by |
| --- | --- | --- |
| TBD | Operational threshold for "trusted" (duration, coverage, seed count) | M1 |
| TBD | Agent runtime: Pydantic AI vs mini-SWE-agent vs Pi (spike S4) | M0 |
| TBD | Memory-diff granularity: all written memory vs regions under `this` | M2 |
| TBD | SCC (recursion) treatment: indivisible block vs unrolling | M2 |
| TBD | Graveyard retention policy and Pareto score weights | M3 |

Already resolved (recorded in the whitepaper, no ADR needed): v1 target
language is **C**; C++ port in a second phase.

## When to write an ADR

A technology choice frozen after an M0 spike (S1–S5), any change of the default
choices in WHITEPAPERS.md §5, and any schema decision not covered by the §6
tables.
