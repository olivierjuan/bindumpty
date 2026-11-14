# Reference: configuration

`config/config.yaml` overrides the typed defaults in `humpty.config.Config`.
Every key is optional; the pipeline runs with no config file. Secrets are
never here — the DB DSN comes from `HUMPTY_DB_URL`.

## All knobs

```yaml
# CEGIS budget / LLM cost (NFR-6)
max_iterations_k: 8          # repair rounds before FAILED (NFR-7 fallback)
candidate_count_n: 3         # candidates the developer samples per function
fuzz_budget_exec: 100000     # executions per campaign

# "trusted" threshold (M1)
trusted_min_exec: 50000
trusted_min_coverage: 0.0    # fraction; 0.0 = no coverage floor yet

# memory diff (M2)
memory_diff_granularity: all_written   # or regions_under_this

# SCC / recursion (M2)
scc_policy: indivisible      # or unroll

# source-language adaptation (FR-1 aux)
source_language: auto        # auto | c | cpp

# graveyard (M3, FR-18)
graveyard_pareto_weights:    # higher is better on every axis
  trace_pass_rate: 1.0
  fuzz_divergence_rate: -1.0 # lower is better
  simplicity: 0.5
graveyard_max_per_function: 32

# LLM
llm_sampling_model: local/vllm
llm_fixer_model: api/strong
llm_cache: true              # NFR-6 response cache

# observability (NFR-5)
log_level: info
```

## The DB URL

`HUMPTY_DB_URL` picks the orchestration backend: PostgreSQL (SKIP LOCKED
claims, LISTEN/NOTIFY wakes — the scale path) or SQLite (BEGIN IMMEDIATE
claims, poller wakes — zero-infra fallback, fine up to ~tens of workers).
Validation itself always runs on SQLite. See `humpty/king/queue.py`.

## Where each knob lands

| Knob | Consumer |
|---|---|
| `max_iterations_k` | `humpty.king.leaf_loop` (K cap → `failed`) |
| `fuzz_budget_exec` / `trusted_min_exec` | the trusted transition in the loop |
| `memory_diff_granularity` | FR-9 memdiff (M2) |
| `scc_policy` | `humpty.analyze.complete.apply_scc_policy` |
| `source_language` | `humpty.analyze.adapt` (auto = detect per binary) |
| `graveyard_*` | `humpty.king.graveyard` (weights applied per axis at score time) |
| `llm_cache` | `humpty.men.cache.LLMResponseCache` |

## Open decisions → config edits

The whitepaper's open decisions are explicit knobs on purpose: settling one
is a config edit plus an ADR in `docs/decisions/`, not a code change.
Current decision states live in ROADMAP's decision register.
