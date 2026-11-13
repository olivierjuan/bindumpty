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
| **The king's court** — `egg` CLI, the king (orchestrator), the men (LLM workers), the DB | [humpty/](humpty/) |
| **The horses** — C/C++ differential harness, hooks, libFuzzer/AFL++ (the fuzzer) | [horses/](horses/) |
| Ghidra scripts and fingerprint corpus | [analysis/](analysis/) |
| Record-replay instrumentation | [tracing/](tracing/) |
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

## Naming

Humpty Dumpty, mapped onto the system:

| Rhyme | System |
| --- | --- |
| Humpty Dumpty (the egg) | a candidate reimplementation; also the `egg` executable |
| the wall | the original binary — the reference the candidate must match |
| the great fall | a divergence found by the fuzzer |
| the King | the orchestrator (`humpty/king/`) |
| all the King's horses | `horses/` — the differential fuzzer |
| all the King's men | `humpty/men/` — the LLM developer/fixer workers |
| "couldn't put Humpty back again" | K iterations exhausted → original stands in (NFR-7) |

## Repository status

Scaffolded 2026-11-13 from WHITEPAPERS.md; court renamed 2026-11-14.
Directory structure, manifests, and M0 core implementation in progress.
First work items: M0 spikes S1–S5 (see [ROADMAP.md](ROADMAP.md),
"Immediate next steps").
