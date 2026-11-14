# API reference

This section is generated from the source docstrings via
[mkdocstrings](https://mkdocstrings.github.io/). Every page below is
regenerated on each docs build — the rendered pages cannot drift from the
code.

The modules are grouped by the pipeline's own seams:

- `humpty.analyze` — ingestion-adjacent analysis: language detection,
  adapters, trace-completed edges, fingerprinting, equivalence proofs
- `humpty.db` — models, migrations, the append-only event log
- `humpty.domain` — the 8-state machine and confidence rules
- `humpty.ingest` — the `fuz.call-graph/1` loader
- `humpty.king` — the orchestrator: queue, bus, scheduler, workers,
  graveyard, resurrection, metrics, milestone exit scripts
- `humpty.men` — the LLM workers: developer, fixer, response cache,
  cross-oracle
- `humpty.trace` — the trace-bundle loader
- `humpty.types_registry` — versioned type layouts

C-side machinery (the differential harnesses, hooking, memory diff) is
documented in the source: `horses/src/` — `m1_harness.c`, `m2_hybrid.c`,
`m2_memdiff.c`, and the build scripts.
