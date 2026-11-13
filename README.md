# bindumpty

Reconstructs readable, behaviorally equivalent **C** source from a stripped,
non-obfuscated x86-64 C++ binary, one function at a time, bottom-up from the
call-tree leaves.

Three pillars (see [WHITEPAPERS.md](WHITEPAPERS.md) for the full specification):

1. **LLM as program synthesizer** — developer and fixer workers propose and
   repair reimplementations (FR-4, FR-5).
2. **Differential fuzzer as equivalence oracle** — searches for inputs on which
   original and candidate diverge (FR-6..9).
3. **Database-backed orchestrator** — parallelizes the CEGIS loop across
   functions; the DB is the single source of truth and the append-only event
   table doubles as the message bus (FR-14, FR-17).

A function is *trusted* when no divergence is found within budget and all
callees are trusted; *proven* only via equivalence checking (FR-11).

## Where to look

| You want… | Look in |
| --- | --- |
| The requirements | [WHITEPAPERS.md](WHITEPAPERS.md) |
| The build plan (milestones, risks, open decisions) | [ROADMAP.md](ROADMAP.md) |
| Architecture decisions | [docs/decisions/](docs/decisions/) |
| Python pipeline (orchestrator, workers, DB) | [fuz/](fuz/) |
| C/C++ differential harness and hooks | [harness/](harness/) |
| Ghidra scripts and fingerprint corpus | [analysis/](analysis/) |
| Record-replay instrumentation | [tracing/](tracing/) |
| Fuzz engine wiring (libFuzzer / AFL++) | [fuzzing/](fuzzing/) |
| Sandbox and SLURM deployment | [sandbox/](sandbox/) |
| Toy binaries with known sources (validation baseline) | [toys/](toys/) |
| Prompt/model benchmarks | [bench/](bench/) |
| Tests | [tests/](tests/) |
| Pipeline configuration | [config/](config/) |

## Milestones (status)

| M | Objective | Status |
| --- | --- | --- |
| M0 | Infrastructure and ground truth (sandbox, schema, ingestion, record-replay) | not started |
| M1 | CEGIS loop on one leaf | not started |
| M2 | Climbing the tree (hybrid harness, hooking, fingerprinting, memory diff) | not started |
| M3 | Parallelization and orchestration (queue, event bus, scheduler, graveyard) | not started |
| M4 | Strong validation (LLM-vs-LLM, Alive2/Z3, information-gain scheduling) | not started |

## Repository status

Scaffolded 2026-11-13 from WHITEPAPERS.md. Directory structure and manifests
only — no implementation yet. First work items: M0 spikes S1–S5 and the
sandbox + DB schema (see [ROADMAP.md](ROADMAP.md), "Immediate next steps").
