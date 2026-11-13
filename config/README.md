# config/

Runtime configuration (not secrets; secrets are never committed).

Planned files:

- `config.yaml` (M0) — pipeline knobs with the open-decision placeholders:
  - `trusted_threshold:` — duration / coverage / seed count (open, decide by M1)
  - `max_iterations_k:` — LLM cap per function (NFR-6)
  - `candidate_count_n:` — samples per developer job (FR-4)
  - `memory_diff_granularity:` — `all_written` | `regions_under_this` (open, decide by M2)
  - `scc_policy:` — `indivisible` | `unroll` (open, decide by M2)
  - `graveyard:` — retention policy + Pareto score weights (open, decide by M3)
  - `db_url:` — SQLite path (M0-M2) / PostgreSQL DSN (M3)
  - `llm:` — provider, sampling model (local, vLLM) for N candidates, fixer model, cache TTL

Every key must have a default; the pipeline must run with an empty override file.
