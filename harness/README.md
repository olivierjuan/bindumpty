# harness/

C/C++ side: the differential harness, hooks, and fuzz entry points.
Compiled with clang (libFuzzer, ASan, UBSan) (WHITEPAPERS.md §5).

## Layout

- `src/` — harness implementation (M1+): differential driver, memory-state diff
  (FR-9), fork server / global-state reset (FR-16), C `LLVMFuzzerTestOneInput`.
- `include/` — public headers of the harness for candidate registration.
- `third_party/` — vendored hooks (funchook first; subhook as alternative) and
  their pin versions (NFR-8).

## Responsibilities per whitepaper

- FR-6: call original and candidate on the same input; compare return value and
  written memory state. Unvalidated callees run in the original (hybrid, M2).
- FR-7: address-based substitution via in-memory hook (funchook/subhook, trampoline
  to the original) or static rewrite (e9patch/LIEF); ASLR-aware base+offset;
  ABI and CET (endbr64) respected.
- FR-8: libFuzzer persistent mode is the default engine; AFL++ for original-only
  coverage campaigns (M2).
- NFR-3: native hooks, not Frida, for high-volume campaigns; target >= 10^4
  exec/s/core on a simple leaf.

## Contract with the Python side

Python never runs the harness directly: it builds the candidate C source, compiles
it inside the sandbox, and launches the fuzz binary there. Every divergence the
harness reports (input, expected, observed, kind: return/memory/UB) is written by
Python to `counterexamples` and `events`.
