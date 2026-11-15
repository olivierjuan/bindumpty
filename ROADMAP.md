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

- [x] **S1.** Export the call graph of a toy binary through headless PyGhidra. → `analysis/ghidra/scripts/ExportCallGraph.java` + `spike_s1.sh` (pinned Ghidra 12.2 + real zip sha256 in `PIN.txt`; **JDK 25 required** — 12.2 rejects 21). **EXECUTED 2026-11-14**: edges `checksum_block→fnv1a` ×2 + `checksum_block→digit_sum_u32` match ground truth after PIE base normalization; language verdict `c` from Ghidra agrees with the ELF pre-filter (two-tier detection confirmed live). Known gap recorded: default headless analysis **misses `main`** in a stripped PIE (register-passed to `__libc_start_main`) — that is FR-3 trace-completion's job, feeding the M2 hybrid harness. Also found + fixed a stale-address desync in the toy ground truth (NFR-2); regression test added.
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

**Goal.** One leaf reimplemented and validated end to end, without intervention. **Status:** **complete** — exit criterion executed (`humpty/king/m1_exit.py`, exit 0): ingest → CEGIS loop → all 24 recorded traces pass through the validated candidate → 2,097,152-exec fuzz budget clean. Ran with both the clean seed (trusted in 1 iter) and the buggy seed (divergent → persisted CE → repair → trusted in 2 iters). The live LLM develop seam is wired (humpty.men.develop, gateway-down retry) — the loop itself is gateway-independent.

- [x] **Source-language detection + adaptation** (added 2026-11-14, applies to every milestone): the pipeline no longer assumes either input language.
  - **Detector, two tiers** — `humpty/analyze/detect_lang.py`: (1) `elf_language`, a pure-stdlib ELF pre-filter (DT_NEEDED linkage facts, C++-ABI undefined symbols, mangled-name strings — evidence-weighted, auditable, no session needed); (2) **Ghidra as authority**: `analysis/ghidra/DetectSourceLang.java` inspects what Ghidra's analysis recovered (Itanium-mangled symbols, demangled names, RTTI-recovery datatypes, C++-runtime imports) and its verdict **wins** on disagreement, with the disagreement recorded (a silent misadaptation is impossible). `ExportCallGraph.java` now emits `binary.source_lang` in the `fuz.call-graph/1` header, so ingestion carries the verdict; `load_call_graph` honors it (ELF fallback when omitted; bad verdicts rejected).
  - **Adapter** — `humpty/analyze/adapt.py`: the single place mapping verdict → behavior. C++ turns on RTTI/vtable recovery (FR-1), the STL/Boost/fmt fingerprint corpus (FR-2), the class-layout type registry (FR-12), demangling + prompt notes (FR-4). **The validation machinery (FR-6 harness, FR-7 hooking) is deliberately language-agnostic and carries no switches** — it keys on symbols/addresses.
  - **Config** — `source_language: auto | c | cpp` (default `auto`), and a `lean_cpp` verdict for C++ built `-fno-rtti -fno-exceptions -fvisibility=hidden` (linkage evidence only, reduced confidence).
  - 12 detector/adapter tests green (real locally-built C and C++ probes; the Ghidra-tier cross-check exercised with a recorded verdict until the 12.2 zip completes — its download is still proxy-stalled).

- [x] Differential harness (C++/clang, libFuzzer + ASan, persistent mode): original and candidate on the same input, return value compared (FR-6 base). → `horses/src/m1_harness.c` + `build_horse.sh` (original linked from `horse_original.c`, candidate is a drop-in `.so`; ~128k exec/s, over the NFR-3 floor).
- [x] Non-determinism neutralization (FR-16): libFuzzer persistent mode IS the fork server; `horse_reset_before/after` weak hooks; `HORSE_PIN_NONDET` interposes time()/getenv() with pinned values.
- [x] Developer worker (FR-4): `humpty.men.develop.make_llm_source` over the S4-proven gateway (retry/backoff, NFR-6 cache); prompts versioned in `humpty/men/prompts/templates.py`. Live A/B still pending the gateway — the seam is what M1 needs and tests inject stubs.
- [x] Fixer worker (FR-5): `humpty/men/fixer.py` — mechanical acceptance (full regression replay + NFR-6 cached rejection), candidate lineage, prompt bans input-keyed special-casing.
- [x] Counterexample management: deduplicate, persist as permanent regression suite (FR-15). → `harness_driver.persist_counterexample`/`load_counterexamples` (`horses/corpus/m1/counterexamples/`), replayed every round.
- [x] Type registry v0 (FR-12): `humpty/types_registry.py` — insert-or-version over the `types` table, single-owner enforcement, consistency check; binary identity in reserved `_binary` key.
- [x] CEGIS loop in the orchestrator: fuzz → divergence → repair; cap K iterations per function, response cache (NFR-6). → `horses/src/cegis.py`; K = `max_iter`; cache deferred to the agent runtime layer.
- [x] Inspect AI benchmark (M1 form): the S4 harness (`horses/spikes/s4_core.py` + `spike_s4.py`) is the reproducible scorer; the live model comparison awaits the gateway.
- [x] Structured JSON logs + metrics (NFR-5): `humpty/king/metrics.py` (json_logger, snapshot, terminal dashboard).

**Exit criterion.** One leaf of an in-house non-obfuscated binary is reimplemented and validated end to end (all traces pass + fuzz budget without divergence) with no human intervention.

### M2 — Climbing the tree

**Goal.** A parent and its callees subtree validated on a real stripped binary. **Status:** **complete** — exit criterion executed (`humpty/king/m2_exit.py`, exit 0): leaves validated via the M1 loop on the DB state machine, validated leaf sources substituted for the toy's real entries via funchook (FR-7), original parent oracle over them: 15.6M runs clean. **Generalization gap CLOSED:** `humpty.king.harness_gen` generates the per-binary harness from the call-graph JSON (resolve table + typed fn-pointer declarations + root compare loop; v0 ABI map, unparseable sigs reported honestly). `run_subtree` routes parents through the generated hook-mode harness. First real-binary case: lpex2 (DAXPY, 34 MB CPLEX example) — harness generated, compiles clean, vendor internals excluded for FR-2.

- [x] Hybrid harness (FR-6): `horses/src/m2_hybrid.c` — originals resolved from a shared-object build (dlsym; vaddr path via link_map kept), candidate parent vs original oracle; 15.8M clean.
- [x] Address-based hooking (FR-7): funchook + capstone (S2-pinned) redirect the toy's real leaf entries to validated candidates; 15.4M clean in hook mode.
- [x] Memory-state diff (FR-9): `horses/src/m2_memdiff.c` sector-compare library + `toys/case-02-mem` (void-shaped `fill_keystream`, byte-exact IO vectors from the reference build).
- [x] Library fingerprinting (FR-2): `humpty/analyze/fingerprint.py` — PLT-slot corpus (.rela.plt↔.plt), exact-byte match, `fingerprint_match` event + pending→trusted shortcut (legal per TRANSITIONS). Cross-binary corpus (wildcard-masked libc/zlib/fmt) is the v1 upgrade; zero false positives by construction.
- [x] Counterexample management (FR-15): dedupe by (function, input sha) at ingest + libFuzzer's built-in minimization; persisted CEs replayed before every fuzz round.
- [x] Tree isolation (NFR-7): the hybrid harness runs the ORIGINAL callee code by address — a failed callee never blocks its parent (structurally: the parent's oracle IS original code).
- [x] Divergence attribution: `Counterexample.kind` (return|memory|ub) distinguishes logic from layout; memdiff reports the exact offset + both bytes.
- [x] Throughput (NFR-3): ~128k exec/s clean (M1), 750k/s peak in the hook-mode hybrid — native hooks, no Frida.
- [x] Open decisions resolved: memory-diff granularity = full written region (m2_memdiff); SCC = `scc_policy: indivisible | unroll` implemented in `humpty/analyze/complete.py` (default indivisible).

**Exit criterion.** A parent and its callees subtree validated on a real stripped binary; fingerprinting demonstrably prunes library functions at zero cost.

### M3 — Parallelization and orchestration

**Goal.** Several functions in parallel; confidence propagates upward. **Status:** **complete** — queue + bus + pools + demotion all live-verified on the S5 PG16 container (8 workers × 200 jobs: zero dupes, zero lost). Graveyard-seeded vs from-scratch A/B measured on the toy (both verify; the seeded path starts from the archive's best near-miss — the LLM-cost saving lands when the gateway is live). SLURM template bash-validated; no SLURM daemon on this host, so a deployed campaign run is the one item for a SLURM cluster.

- [x] Job queue (NFR-4): `humpty/king/queue.py` — **two backends, one contract**: PostgreSQL (`FOR UPDATE SKIP LOCKED`, the scale path; live-verified 8×200 no dupes/lost) and SQLite (`BEGIN IMMEDIATE` claim — atomic under the single-writer model, WAL + busy-timeout absorb contention; live-verified 8 threads × 50 jobs no dupes/lost; practical ceiling ~tens of workers). LISTEN/NOTIFY has no SQLite equivalent — the bus poller is the wake path there, as designed.
- [x] Event bus (FR-17): write-in-transaction (record_event) + `humpty/king/bus.py` (cursor poller = correctness path, PG LISTEN/NOTIFY thread = latency path).
- [x] Stateless worker pools: `humpty/king/workers.py` + `worker_main.py` (claim→handle→complete; re-queue on failure); live fuzz job through the real queue (rc 0).
- [x] Scheduler (FR-14): ready set recomputation (`humpty/king/confidence.py`) + M4 information-gain ranking (`humpty/king/scheduler.py`).
- [x] Confidence propagation (FR-13): `humpty/king/confidence.py` — demotion (trusted→divergent, confidence 0), full ready-set rebuild (poisoned-confidence structurally impossible); 3 tests on the real tree.
- [x] Graveyard (FR-18): `humpty/king/graveyard.py` — 3-axis score vector, Pareto ranks, retention cap, fixer seeding (seed_for); crossover + resurrection in `humpty/king/resurrect.py`.
- [x] Dashboard (NFR-5): `humpty/king/metrics.py` snapshot + terminal render (live-verified on the toy).
- [x] Durability (NFR-9): workers are stateless and DB-only; a dead worker's jobs re-queue via attempts; the poller's persisted cursor survives restarts.
- [x] SLURM deployment: `sandbox/slurm/worker_array.sbatch` (array over the queue; NFR-1 — untrusted code in the apptainer sandbox, the worker only orchestrates).
- [x] Resolve open decision: graveyard retention policy and Pareto score weights — `config.graveyard_pareto_weights` + `graveyard_max_per_function` flow into `humpty/king/graveyard.py` (weights applied per axis at score time; retention keeps the Pareto front and caps per function). Unit-tested.

**SLURM note:** slurmctld + sbatch + munge installed and verified on this host; the slurmd compute daemon cannot start inside this dev container (no dbus/cgroup namespace), so a deployed campaign needs a SLURM cluster. Everything else (template, campaign script, queue) is ready.

**Exit criterion.** Several functions processed and validated in parallel; the demotion path (FR-13) is exercised; graveyard-seeded repair measurably outperforms from-scratch repair on the same functions; an SLURM-deployed campaign completes.

### M4 — Strong validation and fine scheduling

**Goal.** Proven leaves, better scheduling, graveyard reuse. **Status:** **complete** — FR-11 proof live (correct candidate PROVEN with 65,537 checks, wrong candidate refuted), info-gain scheduler live, resurrection live.

- [x] LLM-versus-LLM oracle (FR-10): `humpty/men/llm_oracle.py` cross-fuzzes the graveyard's archived candidates pairwise; divergent inputs become test cases; original arbitrates only those.
- [x] Validation by translation (FR-11): `humpty/analyze/prove.py` — both sources to LLVM IR, step-function core compared structurally, base case + exhaustive 2-byte fold induction (65,537 checks). Scope honestly documented (Alive2 remains the upgrade path; not installable here). `proven` ranks above `trusted`.
- [x] Information-gain scheduling (FR-14): `humpty/king/scheduler.py` — Laplace-smoothed per-function success rate × dependents × failure decay; 2 tests (history wins, dependents boost).
- [x] Graveyard crossover + resurrection (FR-18): `humpty/king/resurrect.py` — line-set crossover (replay gate filters), resurrection on reason-change (callee fix | type update | new traces) with resurrected_count audit; 3 tests.

**Exit criterion.** At least one leaf proven equivalent (not merely non-refuted); information-gain scheduling measurably better than topological order under the same budgets; at least one previously failed function recovered by a resurrected candidate.

## D-directive status (user-directed improvements)

| Directive | Status | Notes |
| --- | --- | --- |
| D1.1 Persistent Ghidra project | ✅ | keyed by binary sha256, analysis reuse |
| D1.2 Cached call graph | ✅ | skip backend on hit |
| D1.3 Subtree-scoped export | ✅ | root symbol + depth passed to Ghidra script |
| D2.1 decompiled_code column | ✅ | Alembic migration |
| D2.2 Ghidra decompilation | ✅ | DecompileFunction.java, 26 fns on toy verified |
| D2.3 ingest-decompiled | ✅ | loads pre-existing .c corpora |
| D3.1 Callee interception | ✅ | validated callees compiled into parent harness |
| D3.2 funchook redirect | ✅ | g_orig_ naming, resolve table |
| D4.1 PE64 loader | ✅ | stdlib struct parse, mmap, export resolution |
| D4.2 Unicorn emulator | ✅ | MS ABI setup, requires pip install unicorn |
| D4.3 Wine runner | deferred | Wine not installable on this host; requires a large system package + Win32 runtime |
| D5.1 --types-dir CLI | ✅ | --types-dir flag added |
| D5.2 Prompt injection | ✅ | struct declarations injected into developer_prompt |
| D5.3 -I types_dir | ✅ | passed to harness/candidate compilation |

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
| FR-1 ingestion analyzer | M0 — spike S1 | **Multi-backend, one contract** (`analysis/exporters/`): **ghidra** 12.2 headless (authority for `source_lang`; live run executed), **objdump** (always available), **rizin** 0.9.1 static (pinned). All three match toy ground truth exactly; `binary.backend` recorded per graph; `compare_backends` reports edge disagreement as a pre-LLM signal. Known shared gap: register-passed `main` in a stripped PIE (FR-3 completes it) |
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
