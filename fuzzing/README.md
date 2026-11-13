# fuzzing/

Fuzzing engine wiring (WHITEPAPERS.md FR-8, FR-16).

- `libfuzzer/` — builds and run scripts for the in-process libFuzzer harness
  (persistent mode, candidate-coverage guided, sanitizers on).
- `afl/` — AFL++ campaigns (frida_mode or qemu_mode) when coverage feedback from
  the original binary itself is required (M2).
- `corpus/` — corpus seeds assembled from traces (FR-3); committed per toy binary,
  large generated corpora stay in the sandbox / run artifacts, not the repo.

Inputs are structured (FuzzedDataProvider or protobuf-mutator); every divergence
(input, expected, observed, kind: return/memory/UB) is reported to Python and
persisted to `counterexamples`, then minimized (FR-15).

Non-determinism neutralization (FR-16) — pinned time, randomness, pointer
addresses, unordered-container iteration order — is implemented in `harness/`
and must be identical across engines.
