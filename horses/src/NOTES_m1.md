# M1 — differential harness + CEGIS loop (LLM-free core proven)

**Date:** 2026-11-14 · **Result: FR-6 harness + FR-15 counterexample store + CEGIS loop verified end to end with a stub develop; live agent runtime pending the gateway**

## What was built

- `horses/src/m1_harness.c` — the libFuzzer differential harness. **No hooks**
  (hooks are M2/FR-7): the original `fnv1a` is *linked* from
  `horses/src/horse_original.c` (the ground-truth source, verbatim — the
  oracle is the real original, not a re-typed reference). The candidate is a
  drop-in `.so` (`horses/libfuzzer/horse_candidate.so`) resolved by `dlsym`,
  regenerable by the agent without touching the harness. First divergence
  prints a reproducible counterexample (`len= input= got= want=`) and aborts.
  FR-16 reset hooks (`horse_reset_before/after`) exist as weak symbols for
  future stateful leaves.
- `horses/src/build_horse.sh` — builds both (`-fsanitize=fuzzer,address`;
  note: `-fsanitize=ubsan` alias is not supported by this clang 19 install,
  `fuzzer,address` is).
- `horses/src/harness_driver.py` — Python bridge: `write_candidate` (rebuild
  the `.so`), `run_fuzz` (wall-clock budget; exit-with-divergence is parsed
  into `Counterexample`s), `run_replay` (deterministic replay of specific
  inputs, NFR-2), plus the canonical FR-15 store
  (`horses/corpus/m1/counterexamples/`).
- `horses/src/cegis.py` — the loop: develop → replay-gate against persisted
  counterexamples → fuzz budget → TRUSTED (budget clean) or persist the new
  divergence and feed it back (FR-5's anti-hardcode guard is the replay
  gate: a candidate that still fails a known counterexample is rejected
  before any fuzz budget is spent on it). `develop` is injected —
  `stub_develop` (deterministic, CI-safe) or `make_pydantic_develop` (the
  real runtime over `spike_s4.pydantic_develop`).

## What was proven

1. **The harness finds a real seed bug.** The checked-in candidate is
   deliberately wrong at `len == 255` (wrong FNV offset basis). libFuzzer
   found the counterexample in seconds; ~128k exec/s clean (NFR-3 floor is
   10k/s). The full path: divergent round → counterexample persisted →
   repair → **2,097,152 execs clean → TRUSTED** in ~12 s, all LLM-free.
2. **Deterministic replay (NFR-2).** `run_replay([input])` reproduces the
   exact `got`/`want` pair across runs.
3. **FR-15 dedup.** `persist_counterexample` is idempotent per exact input;
   the store doubles as the permanent regression suite replayed every round.
4. **Loop plumbing is runtime-agnostic.** `stub_develop` proves the loop; the
   Pydantic AI runtime slots in without touching harness or loop.

## Design fact learned (drives M1's remaining work)

**Coverage-guided fuzzing cannot see a branch-free wrongness.** The first
seed bug (`hash ^= 0x00` at `len==255`) is a *no-op on control flow*: 8M+
execs, zero divergence. Fuzzing finds divergences only when the candidate
has a *branch* the original lacks (or vice versa). The M1 consequence: the
CEGIS feedback must not rely on fuzzing alone — **trace replay + curated
test vectors (S4's scorer) catch branch-free wrongness**; fuzzing catches
the rest. The M1 exit run should use both: S4-style scoring first, then the
fuzz budget. (`-use_value_profile=1` and a length dictionary help but do not
change the fundamental picture.)

## Blocked on the gateway

- Live `develop` (Pydantic AI) — the A/B and token economics. Everything
  else is in place; `spike_s4.py --model claude-sonnet-5-5` is the command
  once the gateway answers.
