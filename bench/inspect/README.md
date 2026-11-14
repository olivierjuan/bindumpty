# bench/inspect

Placeholder for the Inspect AI benchmark (ROADMAP M1: "Inspect AI benchmark
on toy binaries with known sources — prompt/model comparison, reproducible").

**Why empty:** the benchmark compares *live models* on the same scorer, and
the LLM gateway is currently down. The scorer it will drive already exists
and is fully tested — `horses/spikes/s4_core.py` (runtime-agnostic
`build_and_score` + `Fnv1aSpec`) and `horses/spikes/spike_s4.py` (the
Pydantic AI driver with 429 retry/backoff).

**What unblocks it:** a working LLM endpoint (`ANTHROPIC_BASE_URL` /
`ANTHROPIC_AUTH_TOKEN`). Then `spike_s4.py --model <name>` records
iterations-to-verified + token economics per model, and this directory gets
the Inspect AI harness wrapping that scorer across models.
