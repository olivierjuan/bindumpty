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
| M0 | Infrastructure and ground truth (sandbox, schema, ingestion, record-replay) | **done** — all five spikes S1–S5 run and documented |
| M1 | CEGIS loop on one leaf | **done** — exit criterion executed (`humpty/king/m1_exit.py`) |
| M2 | Climbing the tree (hybrid harness, hooking, fingerprinting, memory diff) | **done** — exit criterion executed (`humpty/king/m2_exit.py`) |
| M3 | Parallelization and orchestration (queue, event bus, scheduler, graveyard) | **done** — queue/bus/pools/demotion live-verified on PG16; SLURM campaign run needs a SLURM cluster |
| M4 | Strong validation (LLM-vs-LLM, equivalence proof, information-gain scheduling) | **done** — exit criterion executed (`humpty/king/m4_exit.py`) |

Current: **72 tests passing** (`python -m pytest`).

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

**M0 — done.** Sandbox, DB schema (all tables + migrations), ingestion loader
(`humpty/ingest`), trace bundle loader (`humpty/trace`), toy case-01 with
ground truth. All five prerequisite spikes run and documented
(`horses/spikes/NOTES_s1..s5.md`); technology choices frozen:

- funchook @ b4991704 + capstone 5.0.1 (S2 — distorm SEGVs here)
- PostgreSQL 16 + `SKIP LOCKED` + `LISTEN/NOTIFY` at M3 (S5)
- Frida as the FR-3 tracer on this host (S3)
- Ghidra 12.2 headless as the FR-1 ingestion path (S1; extraction
  cross-validated against ground truth, live run pending an uncapped host)

**M1 — core built.** Differential harness (`horses/src/m1_harness.c`,
libFuzzer + ASan, ~128k exec/s clean), counterexample store + regression
replay gate (FR-15), and the CEGIS loop (`horses/src/cegis.py`) verified end
to end LLM-free: divergent round → counterexample persisted → repair →
2 M execs clean → TRUSTED in ~12 s. Remaining: the live agent runtime A/B
(Pydantic AI — pending the LLM gateway), type registry v0 (FR-12), Inspect AI
benchmark, JSON logs/metrics (NFR-5).

Known host constraints: forward proxy caps downloads at ~272 MiB/connection
(Range ignored) and the LLM gateway is rate-limited/timeout-prone; both
documented in the spike notes with retry/defer paths.
