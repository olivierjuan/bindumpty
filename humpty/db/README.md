# fuz/db — database layer

Models and migrations for the single source of truth. SQLite (WAL) through M2;
PostgreSQL with `SELECT ... FOR UPDATE SKIP LOCKED` + LISTEN/NOTIFY from M3.

## Schema (first migration, M0)

Per WHITEPAPERS.md §6: `functions`, `call_edges`, `candidates`, `counterexamples`,
`traces`, `fuzz_runs`, `types`, `events` (append-only), `graveyard`.

## Rules

- The `events` table is append-only and is written in the same transaction as any
  state change it describes (FR-17).
- Gravedyard rows carry a JSONB score vector + `pareto_rank` + `embedding`
  (pgvector at scale) (FR-18).
- All migrations go through Alembic in `alembic/versions/`; schema changes without a
  migration are not allowed.
