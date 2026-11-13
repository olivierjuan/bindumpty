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

**Goal.** Extract the call tree and record I/O traces for a toy binary. **Status:** not started.

Prerequisite spikes (run before freezing the technology choices of §5):

- [ ] **S1.** Export the call graph of a toy binary through headless PyGhidra.
- [ ] **S2.** Redirect a function to a reimplementation with funchook, from a libFuzzer harness.
- [ ] **S3.** Verify rr and DynamoRIO work on the target machine (performance counters).
- [ ] **S4.** Run one toy leaf through Pydantic AI and through mini-SWE-agent, scored with Inspect AI → decides the agent runtime.
- [ ] **S5.** Measure LISTEN/NOTIFY wake-up latency and SKIP LOCKED throughput at target worker count.

Work items:

- [ ] Sandbox: rootless containers, no network, CPU/memory/time limits (NFR-1).
- [ ] Database schema: all tables of §6 (`functions`, `call_edges`, `candidates`, `counterexamples`, `traces`, `fuzz_runs`, `types`, `events`, `graveyard`), Alembic migrations, SQLite (WAL) through M2; event table present from day one (FR-17).
- [ ] Ingestion: headless Ghidra script → JSON nodes (address, size, demangled sig, RTTI) and edges (direct/indirect/virtual), topological order with SCCs identified (FR-1).
- [ ] Record-replay: tracer (Frida first) records per-function args, memory read, return, memory written on valid inputs; stored in `traces` as oracle + initial corpus (FR-3).
- [ ] Pinned dependencies, containerized reproducible build (NFR-8).
- [ ] Run determinism: every run reproducible from (seed, binary, candidate, corpus) (NFR-2).

**Exit criterion.** Call tree extracted and I/O traces recorded for a toy binary; spikes S1–S5 have documented outcomes and technology choices are frozen with pinned versions.

### M1 — CEGIS loop on one leaf

**Goal.** One leaf reimplemented and validated end to end, without intervention. **Status:** not started.

- [ ] Differential harness (C++/clang, libFuzzer + ASan/UBSan, persistent mode): original and candidate on the same input, return value compared (FR-6 base).
- [ ] Non-determinism neutralization: pin time, randomness, pointer addresses, iteration order; fork server / explicit reset for global state (FR-16).
- [ ] Developer worker (Pydantic AI, typed tools): decompiled code + types + traces + callee signatures → N sampled candidates (FR-4).
- [ ] Fixer worker: candidate + deduplicated counterexamples → corrected version; anti-hardcode guard by replay of the full regression suite (FR-5).
- [ ] Counterexample management: deduplicate, persist as permanent regression suite (FR-15).
- [ ] Type registry v0: versioned layouts, single owner per type, consistency checked on write (FR-12).
- [ ] CEGIS loop in the orchestrator: fuzz → divergence → repair; cap K iterations per function, response cache (NFR-6).
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
| Agent runtime (Pydantic AI vs mini-SWE-agent vs Pi) | M0 — spike S4 | Open |

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

1. Run spikes S1–S5.
2. Stand up the sandbox and the full DB schema (first code in this repo).
3. Freeze technology choices and pinned versions from WHITEPAPERS.md §5 once spike results are in.
