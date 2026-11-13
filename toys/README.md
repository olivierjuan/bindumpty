# toys/

Toy binaries compiled in-house with **known sources** — the validation baseline.
Every milestone is validated here before any real stripped binary.

## Required per toy binary

- `sources/` — the true C/C++ source (the reference).
- `test_suite/` — program's own tests; a recomposed binary (functions replaced)
  must pass this suite (global acceptance criterion).
- `build/` — build recipe producing the stripped, non-obfuscated x86-64 ELF.
- `notes.md` — call tree shape, which functions are leaves, which are inlined
  away, determinism notes (globals, time, RNG, containers).

## Planned cases (start M0, grow per milestone)

- `case-01-leaf` (M0/M1): small deterministic pure function — exercises the full
  CEGIS loop end to end.
- `case-02-parent` (M2): a parent with 2–3 validated callees plus one library
  call (exercises hybrid harness, hooking, fingerprinting, memory-state diff).
- `case-03-tree` (M3): a subtree with depth >= 3, one deliberately hard leaf,
  and an SCC (recursion) to settle the open SCC decision.
- `case-04-real` (M2+): a real stripped binary from the target domain; added when
  M2 exit criterion is about to be demonstrated.

## Convention

Toys are built with the same compiler options as the target binaries we expect
to reconstruct, and stripped (`strip --strip-all`). Sources stay readable in the
repo; they are the ground truth for scoring.
