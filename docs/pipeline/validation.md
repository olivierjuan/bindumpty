# Validation

Three layers, in the order the loop applies them. The rule that shaped them:
**fuzzing alone proves nothing** — a branch-free wrongness survived 8M
executions during development. Each layer catches what the others cannot.

## 1. Trace replay (cheap, always first)

Recorded ground-truth I/O (FR-3) is replayed through the candidate. Any
mismatch rejects the candidate before a single fuzz cycle. The replayed
inputs are also the regression suite: persisted counterexamples (FR-15) are
replayed every round, which is what makes hardcoding unprofitable.

Replay is deterministic (NFR-2): the same input yields the same
`got`/`want` pair across runs.

## 2. Differential fuzzing (the search)

libFuzzer persistent mode drives both implementations on the same input
(`horses/src/m1_harness.c`). First divergence prints a reproducible
counterexample and aborts. Throughput ~128k exec/s clean (NFR-3 floor is
10k/s).

Nondeterminism is neutralized inside the process (FR-16): reset hooks per
call, `HORSE_PIN_NONDET` interposes `time()`/`getenv()` with pinned values,
so stateful leaves see a fixed world.

## 3. Equivalence proof (strongest, per-function shape)

For hash-shaped leaves, `humpty.analyze.prove` verifies equivalence by
bounded induction:

1. **translation** — both sources to LLVM IR (`clang -S -emit-llvm`), the
   step function's arithmetic core compared structurally
2. **base case** — the empty input (exhaustive)
3. **induction step** — all 65,536 2-byte folds from the offset basis,
   exhaustive

`proven` ranks above `trusted` and is absorbing. Honest scope: Alive2/remill
are not installable on the development host; the induction covers the
documented function family, and an SMT/Alive2 backend is the upgrade path.

## What each layer catches

| Wrongness class | Trace replay | Fuzzer | Proof |
|---|---|---|---|
| fails a recorded input | **catches** | likely | catches |
| branch-free wrongness on unseen lengths | **catches** (if in traces) | **misses** | catches (fold induction) |
| wrongness on an unrecorded input shape | misses | **catches** (branch visible) | catches |
| deep semantic divergence beyond the shape | misses | catches | **upgrade path** |
