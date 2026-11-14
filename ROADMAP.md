# bindumpty — Roadmap

*Build plan derived from [WHITEPAPERS.md](WHITEPAPERS.md), which is the requirements source of truth (FR/NFR IDs below refer to it). This document plans the build: milestones, work items, exit criteria, risks, open decisions.*

## Objective

Reconstruct readable, behaviorally equivalent **C** source from a stripped, non-obfuscated x86-64 C++ binary, bottom-up from the call-tree leaves. Core loop is CEGIS: LLM synthesizes a candidate, a differential fuzzer searches for a diverging input, the counterexample drives repair.

**Measurable objective.** Maximize the share of the call tree, weighted by dependent count, whose reimplementation is validated, under a CPU (fuzzing) and LLM (token) budget.

**Ground rules**

- Every milestone is validated on non-obfuscated code compiled in-house (true reference known) before any real binary.
- A milestone is closed only when its exit criterion passes **automatically**.
- A failed function never blocks the tree: automatic fallback to the original, called by address (NFR-7).

## Milestones

### M0 — Infrastructure and ground truth

**Goal.** Extract the call tree and record I/O traces for a toy binary. **Status:** **complete** — core built + tested (68 tests green); all five spikes S1–S5 run and documented with frozen, pinned technology choices.

Prerequisite spikes (run before freezing the technology choices of §5) — outcomes in `horses/spikes/NOTES_sN.md`:

- [x] **S1.** Export the call graph of a toy binary through headless PyGhidra. → `analysis/ghidra/ExportCallGraph.java` + `spike_s1.sh` (pinned Ghidra 12.2, `PIN.txt`). **Call-graph extraction validated** via `s1_crosscheck.py`: 3 objdump call edges from the stripped ELF match the source-derived ground truth exactly. Live Ghidra run **blocked by the host proxy cap** (272 MiB/connection, Range ignored) on the 543 MB zip — ready to run on an uncapped host. Also found + fixed a stale-address desync in the toy ground truth (NFR-2); regression test added.
- [x] **S2.** Redirect a function to a reimplementation with funchook, from a libFuzzer harness. → **PASS.** funchook@b4991704 vendored in `horses/third_party/`, **capstone backend** (distorm SEGVs here); hook a function in a loaded module; buggy reimpl → fuzzer finds the counterexample, correct reimpl → 0 divergences (200k runs).
- [x] **S3.** Verify rr and DynamoRIO work on the target machine (performance counters). → Counters OK (paranoid=0, HW CPU_CYCLES/INSTRUCTIONS open per-thread+per-CPU), ptrace_scope=0, **MSR absent, no tracer installed/buildable here** → Frida is the FR-3 tracer now (tracing/record_frida.py); deterministic replay deferred to a host with rr/DynamoRIO+MSR.
- [x] **S4.** Run one toy leaf through Pydantic AI and through mini-SWE-agent, scored with Inspect AI → decides the agent runtime. → CEGIS loop **proven end-to-end** (develop→score→counterexample→fix→verified in 2 iters on `fnv1a`, scorer runtime-agnostic, `horses/spikes/s4_core.py`). Live-LLM leg blocked by gateway 429/timeout (retry/backoff wired); re-run `spike_s4.py --model claude-sonnet-5-5`.
- [x] **S5.** Measure LISTEN/NOTIFY wake-up latency and SKIP LOCKED throughput at target worker count. → **PASS** on PG16: SKIP LOCKED 121→742 jobs/s over 1→8 workers, zero dupes/lost; LISTEN/NOTIFY 500/500 delivered, ~µs observation latency. SQLite→PG at M3 confirmed.

Work items:

- [x] Sandbox: rootless containers, no network, CPU/memory/time limits (NFR-1).
- [x] Database schema: all tables of §6 (`functions`, `call_edges`, `candidates`, `counterexamples`, `traces`, `fuzz_runs`, `types`, `events`, `graveyard`), Alembic migrations, SQLite (WAL) through M2; event table present from day one (FR-17).
- [x] Ingestion: headless Ghidra script → JSON nodes (address, size, demangled sig, RTTI) and edges (direct/indirect/virtual), topological order with SCCs identified (FR-1). → `humpty/ingest` loader + S1 export script.
- [x] Record-replay: tracer (Frida first) records per-function args, memory read, return, memory written on valid inputs; stored in `traces` as oracle + initial corpus (FR-3). → toy oracle (driver) is M0 ground truth; Frida route documented (host limitation; re-exercised M2).
- [x] Pinned dependencies, containerized reproducible build (NFR-8). → funchook, capstone, Ghidra pinned (`PIN.txt`); sandbox image.
- [x] Run determinism: every run reproducible from (seed, binary, candidate, corpus) (NFR-2).

**Exit criterion.** Call tree extracted and I/O traces recorded for a toy binary; spikes S1–S5 have documented outcomes and technology choices are frozen with pinned versions.

### M1 — CEGIS loop on one leaf

**Goal.** One leaf reimplemented and validated end to end, without intervention. **Status:** harness + loop built and verified LLM-free (stub develop closes the seed bug: divergent → counterexample persisted → repair → 2 M execs clean → TRUSTED in ~12 s); real agent runtime pending the LLM gateway.

- [x] Differential harness (C++/clang, libFuzzer + ASan, persistent mode): original and candidate on the same input, return value compared (FR-6 base). → `horses/src/m1_harness.c` + `build_horse.sh` (original linked from `horse_original.c`, candidate is a drop-in `.so`; ~128k exec/s, over the NFR-3 floor).
- [ ] Non-determinism neutralization: pin time, randomness, pointer addresses, iteration order; fork server / explicit reset for global state (FR-16). → `horse_reset_before/after` weak hooks in place; exercised M2 (stateful leaves).
- [ ] Developer worker (Pydantic AI, typed tools): decompiled code + types + traces + callee signatures → N sampled candidates (FR-4). → runtime wired (`cegis.make_pydantic_develop` over `spike_s4.pydantic_develop`); **live A/B pending the gateway**.
- [ ] Fixer worker: candidate + deduplicated counterexamples → corrected version; anti-hardcode guard by replay of the full regression suite (FR-5). → replay gate implemented in `cegis.cegis_loop` (a candidate failing a persisted counterexample is rejected before any fuzz budget is spent); agent-side prompt reuse of `s4_core.develop_prompt(spec, counterexample)`.
- [x] Counterexample management: deduplicate, persist as permanent regression suite (FR-15). → `harness_driver.persist_counterexample`/`load_counterexamples` (`horses/corpus/m1/counterexamples/`), replayed every round.
- [ ] Type registry v0: versioned layouts, single owner per type, consistency checked on write (FR-12).
- [x] CEGIS loop in the orchestrator: fuzz → divergence → repair; cap K iterations per function, response cache (NFR-6). → `horses/src/cegis.py`; K = `max_iter`; cache deferred to the agent runtime layer.
- [ ] Inspect AI benchmark on toy binaries with known sources (prompt/model comparison, reproducible).
- [ ] Structured JSON logs; metrics: coverage, divergent-input rate, LLM cost per function (NFR-5).

**Exit criterion.** One leaf of an in-house non-obfuscated binary is reimplemented and validated end to end (all traces pass + fuzz budget without divergence) with no human intervention.

### M2 — Climbing the tree

**Goal.** A parent and its callees subtree validated on a real stripped binary. **Status:** not started.

- [ ] Hybrid harness: unvalidated callees called in the original by address; validated callees go through their reimplementation (FR-6).
- [ ] Address-based hooking: funchook in-memory hook with trampoline to the original, ASLR-aware (base + offset), ABI/CET-safe (endbr64) (FR-7).
- [ ] Memory-state diff: snapshot written regions before/after the call and compare — required for void/side-effect functions (FR-9).
- [ ] Library fingerprinting: Function ID / BinDiff / Diaphora against a container-built library corpus; matches mapped to the real function and marked trusted without LLM/fuzzing (FR-2).
- [ ] Counterexample minimization (minimize_crash) (FR-15).
- [ ] Tree isolation: failed callee → parent proceeds with the original callee (NFR-7).
- [ ] Feedback distinguishes logic divergence from memory-layout divergence.
- [ ] Throughput check: ≥ 10⁴ executions/s per core on a simple leaf, native hooks not Frida (NFR-3).
- [ ] Resolve open decisions: memory-diff granularity; SCC (recursion) treatment (below).

**Exit criterion.** A parent and its callees subtree validated on a real stripped binary; fingerprinting demonstrably prunes library functions at zero cost.

### M3 — Parallelization and orchestration

**Goal.** Several functions in parallel; confidence propagates upward. **Status:** not started.

- [ ] Migrate to PostgreSQL; job queue with `SELECT ... FOR UPDATE SKIP LOCKED` (NFR-4).
- [ ] Event bus: every state transition written to `events` in the same transaction as the state change; workers wake on LISTEN/NOTIFY with periodic poll covering lost notifications (FR-17).
- [ ] Stateless worker pools (dev / fixer / fuzzer) pulling jobs from the queue.
- [ ] Scheduler: ready set = all callees trusted; prioritize by expected information gain × dependent count, not plain topological order (FR-14).
- [ ] Confidence propagation: trust as a score; a parent-attributable divergence demotes the child to divergent and recomputes the ready set (FR-13).
- [ ] Graveyard: archive near-miss candidates with score vector (trace pass rate, fuzz divergence rate, simplicity), Pareto-front retention, dedup by normalized source hash, eviction of dominated entries; fixer seeds from the archive (FR-18).
- [ ] Dashboard: live tree overview — coverage, divergence rate, LLM cost per function, validated depth, graveyard size and resurrection rate (NFR-5).
- [ ] Durability: loss of any worker or of the orchestrator is a restart that re-reads the database (NFR-9).
- [ ] SLURM deployment of fuzzing campaigns (workers launched as SLURM jobs).
- [ ] Resolve open decision: graveyard retention policy and Pareto score weights.

**Exit criterion.** Several functions processed and validated in parallel; the demotion path (FR-13) is exercised; graveyard-seeded repair measurably outperforms from-scratch repair on the same functions; an SLURM-deployed campaign completes.

### M4 — Strong validation and fine scheduling

**Goal.** Proven leaves, better scheduling, graveyard reuse. **Status:** not started.

- [ ] LLM-versus-LLM oracle: fuzz the N candidates against each other as a cheap pre-filter; diverging inputs become test cases; the original is queried only to arbitrate survivors (FR-10).
- [ ] Validation by translation: lift the original (remill, rev.ng) and the candidate to LLVM IR; equivalence via Alive2-style check or SMT (Z3) on small pure leaves; "proven" state ranks above "trusted" (FR-11).
- [ ] Information-gain scheduling, measured against topological order (FR-14).
- [ ] Graveyard crossover between candidates and resurrection: replay archived candidates against new traces after a child is fixed or a type is updated (FR-18).

**Exit criterion.** At least one leaf proven equivalent (not merely non-refuted); information-gain scheduling measurably better than topological order under the same budgets; at least one previously failed function recovered by a resurrected candidate.

## FR → milestone traceability

| Requirement | Milestone(s) |
| --- | --- |
| FR-1 Ingestion and call graph | M0 |
| FR-2 Library fingerprinting | M2 |
| FR-3 Record-replay | M0 |
| FR-4 Developer worker | M1 |
| FR-5 Fixer worker | M1 |
| FR-6 Differential harness | M1 (base) → M2 (hybrid) |
| FR-7 Address-based hooking | M0 (spike S2) → M2 |
| FR-8 Fuzzing jobs (libFuzzer / AFL++) | M1 |
| FR-9 Memory-state diff | M2 |
| FR-10 LLM-versus-LLM oracle | M4 |
| FR-11 Validation by translation | M4 |
| FR-12 Shared type registry | M1 (v0) |
| FR-13 Confidence propagation | M3 |
| FR-14 Orchestrator / scheduler | M1 (single-function CEGIS loop) → M3 (parallel scheduling) |
| FR-15 Counterexample management | M1 (dedup, regression suite) → M2 (minimization) |
| FR-16 Non-determinism neutralization | M1 |
| FR-17 Event bus | M0 (event table) → M3 (LISTEN/NOTIFY) |
| FR-18 Graveyard | M3 (archive, retention, fixer seeding) → M4 (crossover, resurrection) |

## Open decisions

| Decision | Decide by | Status |
| --- | --- | --- |
| Operational threshold for "trusted" (duration, coverage, seed count) | M1 — first time a function is actually validated | Open |
| v1 target language | — | **Resolved: C** (C++ port in a second phase) |
| Memory-diff granularity (all written memory vs regions under `this`) | M2 | Open |
| SCC treatment (recursion): indivisible block or unrolling | M2 | Open |
| Graveyard retention policy and Pareto score weights | M3 | Open |
| Agent runtime (Pydantic AI vs mini-SWE-agent vs Pi) | M0 — spike S4 | Harness built (`s4_core.py`, runtime-agnostic scorer); CEGIS loop proven; **live A/B run pending gateway** |
| funchook disassembler backend | M0 — spike S2 | **capstone** (distorm 3.5.2b SEGVs in `inst_lookup` on this host) |
| FR-1 ingestion analyzer | M0 — spike S1 | **Ghidra 12.2 headless** (`ExportCallGraph.java`, pinned, Java 21); edge extraction cross-validated on the toy (objdump match). Live run pending uncapped host (proxy caps at 272 MiB/connection) |
| Job-queue engine | M0 — spike S5 | **PostgreSQL 16 + `SKIP LOCKED` + `LISTEN/NOTIFY`** (SQLite only through M2, as planned) |
| FR-3 tracer on this host | M0 — spike S3 | **Frida** (rr/DynamoRIO need MSR, not present; replay deferred) |

## Risk register

From WHITEPAPERS.md §9. "Watch at" = milestone where the risk becomes active and must be evidenced.

| Risk | Mitigation | Watch at |
| --- | --- | --- |
| False divergences (arbitrary bytes reach unreachable states, trigger UB in the original) | Trace-derived corpus; retain only reachable divergences | M1, M2 |
| Fuzzing proves nothing | "trusted" stays operational (budget + coverage plateau); "proven" only via FR-11 | M4 |
| Poisoned confidence (callee validated too early corrupts the tree above) | Confidence as score + demotion (FR-13) | M3 |
| Memory layout (divergences from a bad struct, not logic) | Type registry (FR-12) + state diff (FR-9) | M2 |
| Unbounded LLM cost | Cap K, pre-filter (FR-10), response cache (NFR-6) | M1, M4 |
| Coverage guidance (libFuzzer sees candidate coverage, not original's) | AFL++ on the original (FR-8) | M2 |
| Graveyard growth and bias toward stale local optima | Dedup, Pareto retention, a fraction of repairs always from scratch | M3, M4 |
| Single-database ceiling (queue + event table share one instance) | Move bus to NATS JetStream behind the unchanged event schema (FR-17) | M3+ |

## Global acceptance

- On a toy binary whose sources are known, the system automatically reconstructs an entire subtree with every function validated, and the recomposed binary (functions replaced) passes the original program's test suite.
- Every reported divergence is deterministically reproducible.
- No LLM-generated code executes outside the sandbox.

## Immediate next steps

1. ~~[done]~~ M0 core: sandbox, DB schema, ingestion loader, record-replay (toy oracle + Frida route), pinned deps — built, tested, committed.
2. ~~[done]~~ Spikes S2/S3/S4/S5 run and documented (`horses/spikes/NOTES_sN.md`); tech choices frozen where the data allows (funchook+capstone, PG16 queue, Frida tracer).
3. ~~[done]~~ **S1** validated + ingestion path frozen: call-graph extraction cross-checked against ground truth (`s1_crosscheck.py`), pinned Ghidra 12.2 script ready. On an uncapped host: run `analysis/ghidra/spike_s1.sh <binary> <out.json>`, diff edges vs `ground_truth/call_graph.json`, record the zip sha256 into `PIN.txt` (currently `PENDING`).
4. Re-run the **S4 live A/B** (`spike_s4.py --model claude-sonnet-5-5`) once the gateway clears its rate limit; record iterations-to-verified + token economics.
5. **M1** — wire the differential harness (horses/src) for `fnv1a`: libFuzzer persistent mode, developer + fixer workers over the S4 scorer, Inspect AI benchmark, "trusted" threshold decision.
