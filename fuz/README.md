# fuz-llm Python package

Python side of the pipeline: orchestration, workers, glue. C/C++ harness and hooks
live in `harness/`; Ghidra/Frida scripts in `analysis/` and `tracing/`.

## Modules

| Package | Responsibility | Whitepaper | Milestone |
| --- | --- | --- | --- |
| `fuz.domain` | Domain model: function states, confidence, job events | §6 | M0 |
| `fuz.db` | SQLAlchemy models + Alembic migrations (SQLite → PostgreSQL) | §6, FR-17 | M0 |
| `fuz.ingest` | Ghidra headless results → JSON → `functions` / `call_edges` | FR-1 | M0 |
| `fuz.trace` | Record-replay trace ingestion (`traces`) | FR-3 | M0 |
| `fuz.orchestration` | State machine, ready set, scheduler, budgets, job queue | FR-14, FR-13, NFR-4 | M1 loop / M3 parallel |
| `fuz.workers` | Developer and fixer workers (Pydantic AI, typed, stateless) | FR-4, FR-5 | M1 |
| `fuz.llm` | Provider abstraction, response cache keyed by hash(prompt, model, seed), prompts | NFR-6 | M1 |
| `fuz.types_registry` | Versioned type layouts, single owner, consistency check | FR-12 | M1 |
| `fuz.validation` | Harness/fuzz job control, counterexample dedup + minimization | FR-6..9, FR-15, FR-16 | M1/M2 |
| `fuz.graveyard` | Near-miss archive: score vectors, Pareto retention, seeding, resurrection | FR-18 | M3/M4 |
| `fuz.observe` | Structured JSON logs + metrics (NFR-5) | NFR-5 | M1 |

## Layout rules

- Workers are stateless: all coordination goes through the database.
- Every state transition is written to the `events` table in the same transaction
  as the state change (FR-17); LISTEN/NOTIFY only wakes, never carries payload of record.
- LLM prompts live in `fuz/llm/prompts/` as data files, versioned with the code.
