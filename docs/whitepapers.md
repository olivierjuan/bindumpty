# bindumpty — Roadmap and Requirements Specification

Nov 13, 2026 · @Olivier

## 1. Abstract and Objectives

bindumpty reconstructs readable, behaviorally equivalent source code from a stripped, non-obfuscated C++ binary, one function at a time, working bottom-up from the leaves of the call tree to its root. It combines a large language model (LLM) as program synthesizer, a differential fuzzer as equivalence oracle, and a database-backed orchestrator that parallelizes the work across many functions.

The core is a counterexample-guided inductive synthesis (CEGIS) loop. The LLM proposes a reimplementation; a differential fuzzer searches for an input on which the original and the candidate diverge; each counterexample is fed back to the LLM for repair. A function is deemed trusted when no divergence is found within a given budget and all of its callees are already trusted.

**Measurable objective.** Maximize the share of the call tree, weighted by dependent count, whose reimplementation is validated, under a CPU budget (fuzzing) and an LLM budget (tokens).

**In scope.** x86-64 ELF, C++, stripped, non-obfuscated, with or without RTTI; deterministic functions, or functions made deterministic; parallel orchestration; validation by differential fuzzing and, for small leaves, equivalence proofs.

**Out of scope (v1).** Obfuscation (control-flow flattening, opaque predicates), other architectures, self-modifying code, anti-debugging, parallelism inside the target function, and end-to-end recompilable projects. The goal is per-function equivalence, not a full build.

## 2. System Architecture

&#91;embedded content: architecture · analyse → base ← orchestrateur → workers\]

The analysis stage (ingestion, fingerprinting, record-replay) populates the database, which is the single source of truth. The orchestrator reads the set of ready functions from it, dispatches jobs to worker pools, and receives candidates, counterexamples and confidence scores in return. Workers are stateless: all coordination goes through the database, whose append-only event table doubles as the message bus (FR-17). Near-miss candidates are not discarded but archived in a graveyard (FR-18), from which later repair attempts draw.

## 3. Functional Requirements

Each requirement is independently verifiable and implementable. The corresponding components are specified in Section 7.

- **FR-1 — Ingestion and call graph.** Extract from a scriptable disassembler (Ghidra or Binary Ninja) the call graph, function addresses, candidate signatures, and vtables/RTTI where present. Produce a topological order with strongly connected components (recursion) identified.
- **FR-2 — Library fingerprinting.** Before any reimplementation, identify known library functions (STL, Boost, zlib, fmt, libc) by signature matching (Function ID, FLIRT, Diaphora, BinDiff). Mark them trusted without LLM or fuzzing, with a mapping to the real function.
- **FR-3 — Record-replay (ground truth).** Execute the original on valid inputs under a tracer (rr, DynamoRIO or Frida) and record, per function, the real I/O: arguments, memory read, return value, memory written. Store it as an oracle and as the initial fuzzing corpus.
- **FR-4 — Developer worker.** For a ready function, give the LLM the decompiled code, reconstructed types, I/O traces and callee signatures, and produce a compilable reimplementation. Generate N candidates by sampling.
- **FR-5 — Fixer worker.** From a candidate and minimized counterexamples, produce a corrected version. Detect and reject hardcoding of counterexamples by regression testing against all retained cases.
- **FR-6 — Differential harness.** Execute original and candidate on the same input and compare both the return value and the written memory state. Unvalidated callees are called in the original by address; validated callees go through their reimplementation (hybrid harness).
- **FR-7 — Address-based substitution (hooking).** Replace a function at its address (base plus offset, ASLR-aware) through in-memory hooking (funchook, subhook, Frida) or static rewriting (e9patch, LIEF), respecting the ABI and CET (endbr64).
- **FR-8 — Fuzzing jobs.** Fuzz the differential harness with libFuzzer by default (in-process, guided by candidate coverage, with sanitizers). Use AFL++ (frida\_mode or qemu\_mode) when coverage feedback from the original binary itself is required. Structure inputs with FuzzedDataProvider or protobuf-mutator, seed the corpus from traces, and report every divergence (input, expected, observed, kind).
- **FR-9 — Memory-state diff.** For functions with no observable output (void, side effects), snapshot the written regions before and after the call and compare them. Without this, such functions would pass falsely.
- **FR-10 — LLM-versus-LLM oracle.** Fuzz the N candidates against each other, not against the original, as an inexpensive pre-filter; any input on which they diverge becomes a test case. Query the costly oracle (the original) only to arbitrate.
- **FR-11 — Validation by translation.** For small leaves, lift original and candidate to LLVM IR and check equivalence (Alive2-style) or by SMT (Z3). Mark a function "proven" only when equivalence is established, not merely "not refuted".
- **FR-12 — Shared type registry.** Centralize and version struct/class layouts, with a single owner per type. Enforce consistency across workers: two divergent reconstructions of one type invalidate everything that depends on it.
- **FR-13 — Confidence propagation.** Trust is a score, not a boolean. A divergence at a parent attributable to a child demotes that child to the divergent state and recomputes the ready set.
- **FR-14 — Orchestrator.** Maintain the state machine, compute the ready set (all callees trusted), prioritize by expected information gain and dependent count, allocate budgets, and never block the tree: a failed function keeps the original, called by address.
- **FR-15 — Counterexample management.** Deduplicate, minimize (minimize\_crash), and keep as a permanent regression suite. A few varied cases suffice for the fixer.
- **FR-16 — Non-determinism neutralization.** Pin time, randomness, pointer addresses and unordered-container iteration order; isolate global state through a fork server or an explicit reset between iterations.
- **FR-17 — Event bus.** Record every state transition and job notification as a row in an append-only event table. Workers are woken by PostgreSQL LISTEN/NOTIFY, which carries no payload of record: the table remains the truth, so a lost notification costs latency, never correctness. A dedicated broker (NATS JetStream) is introduced only if a single database stops scaling.
- **FR-18 — Graveyard of near-misses.** Archive every candidate that is close to correct instead of discarding it, with a score vector (trace pass rate, fuzz divergence rate, simplicity) and a Pareto front per function. Deduplicate and apply a retention policy. The archive serves as: (a) seed for the fixer; (b) material for crossover between candidates, in the spirit of FunSearch and AlphaEvolve; (c) negative examples in prompts; (d) a free oracle, since an archived candidate that disagrees with a new one yields a test case; (e) resurrection, by replaying archived candidates against new traces after a child is fixed or a type is updated; (f) cross-function retrieval of recurring idioms.

## 4. Non-Functional Requirements

- **NFR-1 — Sandboxing.** Compile and execute all LLM-generated code, and the (untrusted) target binary, in isolated containers: timeouts, CPU and memory limits, no network access, no execution on the host.
- **NFR-2 — Reproducibility.** Every run is replayable identically from (seed, binary, candidate, corpus). Every reported divergence must be deterministically reproducible.
- **NFR-3 — Fuzzing throughput.** Persistent mode (libFuzzer or AFL++) and native hooks rather than Frida for high-volume campaigns. Indicative target: at least 10^4 executions per second per core on a simple leaf.
- **NFR-4 — Horizontal scalability.** Stateless workers, job queue in the database, concurrent locking (PostgreSQL SELECT ... FOR UPDATE SKIP LOCKED). Fuzzing campaigns are deployable as SLURM jobs.
- **NFR-5 — Observability.** Log every state transition and expose metrics: coverage reached, divergent-input rate, LLM cost per function, validated depth of the tree, graveyard size and resurrection rate. Provide a live overview of the tree.
- **NFR-6 — LLM cost control.** A cap of K iterations per function, response caching, and the LLM-versus-LLM pre-filter (FR-10) before any call to the costly oracle.
- **NFR-7 — Tree isolation.** A failed function must never block its parents: automatic fallback to the original. The loss is limited to the portability of that branch.
- **NFR-8 — Pipeline portability.** Linux x86-64 target, pinned dependencies, containerized and reproducible build environment.
- **NFR-9 — Durability.** All pipeline state, including the event log and the graveyard, survives the loss of any worker or of the orchestrator. Recovery is a restart that re-reads the database.

## 5. Recommended Technology Choices

Python for orchestration and glue, C/C++ for the harness and hooks, Ghidra for analysis, libFuzzer for fuzzing, and PostgreSQL for coordination, events and the graveyard. LLM agents run as thin, typed, stateless workers inside the orchestrator's own CEGIS loop, not inside a general-purpose coding-agent harness. Every choice has a documented alternative; versions are to be pinned in M0 (NFR-8) and have not been verified here.

| Component | Default choice | Alternative | Rationale |
| --- | --- | --- | --- |
| Orchestrator and workers | Python 3.12, asyncio | — | Ecosystem: PyGhidra, Frida, angr, Z3, LLM clients |
| Agent runtime (developer, fixer) | Pydantic AI: typed tools, structured output, provider-agnostic | smolagents; OpenAI Agents SDK; Claude Agent SDK (Claude-oriented) | A library, not a framework: the loop is the CEGIS loop and belongs to the orchestrator |
| Agent escalation | mini-SWE-agent or Pi (minimal shell agent, four tools, RPC and SDK) for hard functions that need free-form exploration | SWE-agent; OpenHands | Heavier agents only where the typed worker stalls |
| Evaluation harness | Inspect AI (dataset, solver, scorer; sandboxed) to benchmark prompts and models on toy binaries with known sources | Custom scripts | Reproducible model and prompt comparisons (NFR-2) |
| Harness and hooks | C++ compiled with clang (libFuzzer, ASan, UBSan) | — | libFuzzer ships with clang; native code for speed |
| Reimplementations | C in v1, then C++ port | — | Decision taken (see open decisions) |
| Disassembly, decompilation, call graph | Ghidra headless through PyGhidra | Binary Ninja (nicer Python API, paid); ReVa (Ghidra MCP server) to expose Ghidra to agents | Free, scriptable, decompiler and RTTI analysis included |
| Fingerprinting | Ghidra Function ID, BinDiff or Diaphora | FLIRT (IDA) | Avoids a license; library corpus built in a container |
| Tracing (record-replay) | Frida to start, DynamoRIO for large volumes | rr (full replay, needs hardware performance counters) | Frida iterates fast; DynamoRIO is faster |
| Fuzzing | libFuzzer in persistent mode on the harness | AFL++ (frida\_mode or qemu\_mode) to fuzz the original alone | In-process, fast, built-in sanitizers; AFL++ is the route to coverage feedback from a stripped original |
| Hooking | Frida for prototyping, then funchook | subhook; e9patch or LIEF for static rewriting | Funchook is native, without Frida's overhead |
| Equivalence proof | angr and Z3 on small pure leaves | Alive2 on LLVM IR (remill, rev.ng) | Alive2 on lifted code is delicate; try in M4 |
| Database | SQLite (WAL) through M2, then PostgreSQL | — | Zero setup at first, concurrency later |
| Job queue and event bus | Job and event tables with SKIP LOCKED; LISTEN/NOTIFY as wake-up only | NATS JetStream if scaling out | No Celery, Redis or Kafka: one fewer dependency, transactional with the state |
| Distributed executor | None in v1; SLURM jobs launch the workers | Ray as an optional executor on SLURM | Ray's control plane (GCS, per-node raylets over gRPC) is a task and actor scheduler, not a durable queue, and its resources are logical, without isolation |
| Graveyard storage | PostgreSQL table with a JSONB score vector; pgvector for similarity retrieval | Dedicated vector database | Same database and transactions as the rest of the state |
| Database access | SQLAlchemy 2 and Alembic | Direct psycopg | Versioned migrations |
| Isolation | Rootless containers, no network, cgroup limits | Apptainer on SLURM (Docker is often forbidden in HPC); gVisor or Firecracker later | NFR-1 |
| LLM access | Provider abstraction layer, structured JSON output, cache keyed by hash of (prompt, model, seed) | LiteLLM | Swap models without touching workers |
| Models | Local model served by vLLM to sample N candidates; stronger API model for the fixer | A single API model | Sampling costs tokens; fixing needs quality |
| Build and packaging | CMake and clang; uv and pyproject; pinned images | — | NFR-8 |
| Observability | Structured JSON logs; Grafana or Streamlit dashboard | — | NFR-5 |

**Spikes to run in M0 before freezing these choices**

- Export the call graph of a toy binary through headless PyGhidra.
- Redirect a function to a reimplementation with funchook, from a libFuzzer harness.
- Check that rr and DynamoRIO work on the target machine (performance counters).
- Run one leaf of a toy binary through Pydantic AI and through mini-SWE-agent, scored with Inspect AI, to confirm the agent-runtime choice.
- Measure LISTEN/NOTIFY wake-up latency and SKIP LOCKED throughput at the target worker count.

## 6. Data Model and Lifecycle

Relational database: SQLite for bootstrapping, PostgreSQL with `SKIP LOCKED` at scale. The database is the single source of truth; workers are stateless and pull their jobs from the queue. The event table and the graveyard live in the same database, so state, events and archive change in one transaction.

| Table | Role | Key columns |
| --- | --- | --- |
| `functions` | one row per function in the binary | id, address, size, demangled\_sig, has\_rtti, scc\_id, state, confidence, dependents\_count |
| `call_edges` | edges of the call tree | caller\_id, callee\_id, kind (direct / indirect / virtual) |
| `candidates` | proposed reimplementations | id, function\_id, source\_code, llvm\_ir, created\_by (dev / fixer), parent\_candidate\_id, sampling\_seed, status |
| `counterexamples` | divergent inputs | id, function\_id, input\_blob, expected, observed, kind (return / memory / UB), minimized |
| `traces` | recorded I/O (record-replay) | id, function\_id, args\_blob, mem\_read, ret, mem\_written |
| `fuzz_runs` | fuzzing campaigns | id, candidate\_id, engine, coverage, exec\_count, divergences, duration |
| `types` | reconstructed layouts | id, name, layout\_json, owner\_worker, version |
| `events` | append-only event log and job notifications | id, ts, kind, function\_id, candidate\_id, payload\_json, worker\_id |
| `graveyard` | archive of near-miss candidates | id, function\_id, candidate\_id, score\_vector (trace pass rate, fuzz divergence rate, simplicity), pareto\_rank, embedding, archived\_at, resurrected\_count |

Every function follows the state machine below. The central loop is the CEGIS cycle fuzzing, divergence, repair. A candidate that fails but scores well enters the graveyard; a candidate that is superseded or evicted by the retention policy leaves it.

&#91;embedded content: cycle de vie d'une fonction · 8 états, boucle CEGIS\]

The Fuzzing, Divergence, Repair loop is the CEGIS core. The dashed edge shows a regression revealed by a parent demoting an already trusted function (FR-13). A shortcut not drawn: a function recognized as a known library routine (FR-2) goes directly to Trusted.

## 7. Component Specification

- **Ingestion and call graph (FR-1).** A headless Ghidra or Binary Ninja script emits JSON: nodes (address, size, demangled signature when possible, RTTI presence) and edges (direct, indirect, virtual). Virtual calls are resolved through vtables and RecoverClassesFromRTTI. Unresolved indirect calls are completed from dynamic traces (FR-3). Caveat: inlining means the binary's call tree is not the source's call tree.
- **Fingerprinting (FR-2).** Applied first, on the leaves. FLIRT-style signatures and BinDiff or Diaphora comparison against a corpus of libraries compiled with common options. A match maps to the real function (memcpy, std::sort, ...) instead of triggering a reimplementation. This is the system's main free gain: it prunes a large part of the tree at zero cost.
- **Record-replay (FR-3).** A tracer (rr for deterministic replay, DynamoRIO or Frida for instrumentation) captures, per function, arguments, memory read, return value and memory written, over a set of valid inputs. It plays three roles: a cheap oracle (replay before fuzzing), the initial corpus, and concrete examples in the prompt. It limits false divergences caused by unreachable states.
- **Differential harness and hooking (FR-6, FR-7, FR-9).** Loads original and candidate, calls both on the same input, and compares the return value and the written memory regions (snapshots for void functions, FR-9). Unvalidated callees stay in the original, called by address; substitution uses funchook or subhook (in-memory hook, trampoline to call the original) or e9patch or LIEF (static). Feedback distinguishes a logic divergence from a memory-layout divergence.
- **Fuzzing jobs (FR-8, FR-16).** libFuzzer in persistent mode, guided by candidate coverage; AFL++ when coverage of the original itself is needed. Structured inputs through FuzzedDataProvider or protobuf-mutator. Non-determinism is neutralized and global state is reset through a fork server. Every divergence is persisted, then minimized (FR-15).
- **Agent runtime and workers (FR-4, FR-5).** Each job runs one stateless, typed agent (Pydantic AI) with a small tool set: compile, run on traces, read decompiled code, query the type registry, query the graveyard. The developer receives decompiled code, types, traces and callee signatures and produces N candidates. The fixer receives a candidate and deduplicated minimized counterexamples. Anti-hardcode guard: systematic replay of the whole regression suite; a candidate that does not generalize is rejected. A function that stalls past K iterations may escalate to a free-form agent (mini-SWE-agent or Pi) in the sandbox.
- **LLM-versus-LLM oracle (FR-10).** Pre-filter: fuzzing the N candidates against each other eliminates bad ones without touching the instrumented binary, at far lower cost. Inputs on which they diverge are high-quality test cases. The original intervenes only to arbitrate between survivors.
- **Validation by translation (FR-11).** For small pure leaves: lift the original (remill, rev.ng), compile the candidate to LLVM IR, then check equivalence (Alive2) or encode in SMT (Z3). A positive result is a proof, not a mere absence of counterexample; the "proven" state ranks above "trusted by fuzzing".
- **Type registry (FR-12).** A central, versioned `types.h`, one owner per type, shared by all workers. Two concurrent reconstructions of one struct would make everything diverge; consistency is checked on write.
- **Event bus (FR-17).** Every state transition is first written to the `events` table in the same transaction as the state change. Workers block on LISTEN and, on NOTIFY, query the table for work; a periodic poll covers lost notifications. Events are idempotent and replayable, which gives audit, metrics (NFR-5) and crash recovery (NFR-9) from one mechanism.
- **Graveyard (FR-18).** When a candidate fails but scores well, it is archived with a score vector and kept if it lies on the function's Pareto front. The fixer samples from it as seed; crossover combines archived candidates; the developer prompt can include negative examples. When a child is fixed or a type changes, archived candidates of its parents are replayed against the new traces, and a candidate that now passes is resurrected. Retention bounds growth: deduplication by normalized source hash, and eviction of dominated entries.
- **Scheduler and confidence propagation (FR-13, FR-14).** Recomputes the ready set when a callee becomes trusted and prioritizes by expected information gain (reduce uncertainty where the most dependents are unblocked) rather than plain topological order. A parent is first fuzzed with its original callees (to isolate its own errors), then in integration with replaced callees. Confidence flows upward: a bug revealed in a callee demotes it.

## 8. Roadmap by Milestone

Each milestone is validated on non-obfuscated code compiled in-house, where the true reference is known, before any real binary. A milestone is closed only when its exit criterion passes automatically.

| Milestone | Objective | Deliverable | Exit criterion |
| --- | --- | --- | --- |
| M0 | Infrastructure and ground truth | Sandbox, database schema including the event table, ingestion and call graph, record-replay | Call tree extracted and I/O traces recorded for a toy binary |
| M1 | CEGIS loop on one leaf | libFuzzer differential harness, developer and fixer agents (Pydantic AI), Inspect AI benchmark | One leaf reimplemented and validated end to end without intervention |
| M2 | Climbing the tree | Hybrid harness (original callees by address, plus hooking), fingerprinting, memory-state diff | A parent and its callees subtree validated on a real stripped binary |
| M3 | Parallelization and orchestration | Job queue, event bus (LISTEN/NOTIFY), worker pools, scheduler, confidence propagation, graveyard with fixer seeding, dashboard | Several functions processed in parallel; confidence propagates upward; SLURM deployment; repair seeded from the graveyard outperforms repair from scratch on the same functions |
| M4 | Strong validation and fine scheduling | LLM-versus-LLM oracle, validation by translation (Alive2, Z3), information-gain scheduling, graveyard crossover and resurrection | Leaves proven equivalent; scheduling measurably better than topological order; resurrected candidates recover functions that had failed |

Milestones M0 to M2 establish feasibility on one branch; M3 and M4 turn it into a system that scales and exploits scheduling under uncertainty.

## 9. Risks, Open Decisions and Acceptance

**Principal risks**

- **False divergences.** Fuzzing an internal function with arbitrary bytes explores unreachable states and triggers undefined behavior on the original side. Mitigation: trace-derived corpus; retain only reachable divergences.
- **Proof versus fuzzing.** Fuzzing proves nothing; "trusted" remains operational (N minutes without divergence, coverage plateau). Use "proven" only through FR-11.
- **Poisoned confidence.** A callee validated too early corrupts the whole tree above it; hence confidence as a score and demotion (FR-13).
- **Memory layout.** Many divergences will stem from a badly reconstructed struct, not from logic; the type registry (FR-12) and state diff (FR-9) are critical.
- **Unbounded LLM cost.** Without the cap K and the pre-filter, cost explodes; NFR-6 bounds it.
- **Coverage guidance.** libFuzzer alone is guided by candidate coverage, not by coverage of the original. Divergences hidden in original-only paths are found only if the corpus reaches them; AFL++ on the original (FR-8) is the mitigation.
- **Graveyard growth and bias.** An unbounded archive slows retrieval and may steer the fixer toward stale local optima. Mitigation: deduplication, Pareto-front retention, and a fraction of repairs always started from scratch.
- **Single-database ceiling.** The event table and queue share one PostgreSQL instance; if throughput saturates, move the bus to NATS JetStream (FR-17) without changing the event schema.

**Open decisions**

- Exact operational threshold for "trusted" (duration, coverage, number of seeds).
- Resolved: the v1 target language is C, which is simpler to verify; a C++ port follows in a second phase.
- Granularity of the memory diff (all written memory versus regions under `this`).
- Treatment of strongly connected components (recursion): indivisible block or unrolling.
- Graveyard retention policy and the Pareto score weights.

**Global acceptance criteria**

- On a toy binary whose sources are known, the system automatically reconstructs an entire subtree in which every function is validated, and the recomposed binary (functions replaced) passes the original program's test suite.
- Every reported divergence is deterministically reproducible.
- No LLM-generated code executes outside the sandbox.
