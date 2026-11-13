# humpty — the egg (CLI and orchestrator)

Python side of the pipeline: orchestration, the CEGIS loop, workers, glue.
The C++ differential harness and fuzzer live in `horses/`; Ghidra/Frida
scripts in `analysis/` and `tracing/`.

Naming (Humpty Dumpty): the **egg** is the `egg` CLI/candidate; **the king** is
the orchestrator (`humpty/king/`); the **men** are the LLM workers
(`humpty/men/`); the **horses** are the fuzzer (`horses/`); the **wall** is the
original binary (the reference). When the egg falls (a divergence), the king
dispatches horses and men; if they "cannot put Humpty back again" (K iterations
exhausted), the original stands in its place (NFR-7).

## Entry point

`egg` (console script → `humpty.cli:main`). All subcommands run through it;
workers themselves are stateless and are launched by the orchestrator or as
SLURM jobs.

## Modules

| Package | Responsibility | Whitepaper | Milestone |
| --- | --- | --- | --- |
| `humpty.cli` | `egg` command-line interface | NFR-5 | M0 (skeleton) / M1+ |
| `humpty.domain` | Domain model: function states, confidence, job events | §6 | M0 |
| `humpty.db` | SQLAlchemy models + Alembic migrations (SQLite → PostgreSQL) | §6, FR-17 | M0 |
| `humpty.ingest` | Ghidra headless results → JSON → `functions` / `call_edges` | FR-1 | M0 |
| `humpty.trace` | Record-replay trace ingestion (`traces`) | FR-3 | M0 |
| `humpty.king` | The orchestrator: state machine, ready set, scheduler, budgets, job queue | FR-14, FR-13, NFR-4 | M1 loop / M3 parallel |
| `humpty.men` | The LLM workers: developer and fixer (Pydantic AI, typed, stateless); `prompts/` holds prompt templates as data | FR-4, FR-5 | M1 |
| `humpty.llm` | Provider abstraction, response cache keyed by hash(prompt, model, seed) | NFR-6 | M1 |
| `humpty.types_registry` | Versioned type layouts, single owner, consistency check | FR-12 | M1 |
| `humpty.validation` | Harness/fuzz job control (launches `horses/`), counterexample dedup + minimization | FR-6..9, FR-15, FR-16 | M1/M2 |
| `humpty.graveyard` | Near-miss archive: score vectors, Pareto retention, seeding, resurrection | FR-18 | M3/M4 |
| `humpty.observe` | Structured JSON logs + metrics (NFR-5) | NFR-5 | M1 |

## Layout rules

- Workers are stateless: all coordination goes through the database.
- Every state transition is written to the `events` table in the same transaction
  as the state change (FR-17); LISTEN/NOTIFY only wakes, never carries payload of record.
- LLM prompts live in `humpty/men/prompts/` as data files, versioned with the code.
- Python never executes target binaries or LLM-generated code directly; it
  delegates to the sandbox (see `sandbox/`).
