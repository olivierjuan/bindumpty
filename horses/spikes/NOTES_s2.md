# S2 — funchook redirect from a libFuzzer harness (FR-7)

**Date:** 2026-11-14 · **Result: PASS (mechanism proven; two environmental caveats below)**

## Question
Can we redirect a function at its address to a reimplementation with funchook,
from a libFuzzer harness — i.e. does the core M2 hooking mechanism (FR-6/FR-7)
work, and can a differential fuzzer drive it and find a planted counterexample?

## Answer
Yes. `spike_s2.sh` builds and runs two variants of the same harness:

| variant | reimplementation | outcome |
|---|---|---|
| A (default) | wrong at `a==0xff` | **DIVERGENCE found** by the fuzzer, e.g. `original_add(255,58) reimpl=197 original=313` |
| B (`-DS2_CORRECT`) | identical to original | **200 000 runs, zero divergences** |

Same harness, same installed hook — only the reimplementation differs. That is
the discriminating signal: the comparator is not always-firing, and the
redirect actually executes the reimplementation.

## How it works (funchook semantics, verified against funchook's own suite)
```
g_entry = dlsym(so, "original_add")   # symbol entry point
g_orig  = g_entry
funchook_prepare(h, &g_orig, candidate)  # *g_orig <- TRAMPOLINE (true original)
funchook_install(h, 0)                      # patches g_entry -> candidate
```
After `install`:
- `g_entry(a,b)` runs the **reimplementation** (candidate),
- `g_orig(a,b)` runs the **true original** (via the trampoline).

The harness diffs the two per fuzzer input. The hook is installed from a
`__attribute__((constructor))`, so it is in place before libFuzzer's `main`
and the persistent process (fork server) inherits it.

## Topology chosen
The "original" function lives in `s2_original.so` (a loaded module); the
reimplementation + fuzzer live in the harness. This is the M2 shape: the
stripped binary is *loaded* and its functions are redirected.

## Caveats (for M1/M2 planning — read before choosing the hook stack)
1. **Disassembler backend.** funchook needs a disassembler to build
   trampolines. The vendored default `distorm 3.5.2b` **SEGVs in
   `inst_lookup` on this machine** (reproduced with funchook's own trivial
   hook, distorm build). **capstone 5.0.1 works** — funchook's full official
   suite passes 13/13 with it, including value-returning and prehook tests.
   → **Use the capstone backend** (`-DFUNCHOOK_DISASM=capstone`), already
   wired in `spike_s2.sh` and `horses/third_party/funchook/build-cs/`.
2. **Target location.** Hooking a function in the **main PIE executable**
   crashed capstone's decoder in `reader()` in *this* build (identical bytes
   disassemble fine from a buffer; a minimal main-exe global hook prepared
   cleanly). Hooking a function in a **loaded .so works cleanly**. This is an
   environment/capstone-5.0.1 edge-case, not a funchook logic bug.
   → For M2, keep the **original loaded as a module** (exec or .so loaded via
   dlopen/mmap) and hook through that. If hooking a function inside the
   fuzzer's own address space becomes necessary, isolate it: the M1 harness
   will load the candidate/original in a separate address space.
3. **Sanitizers.** The capstone decoder faults under ASan's redzones in this
   environment, so the spike is built with `-fsanitize=fuzzer` only. The
   hook mechanism itself is sanitizer-free; the **M1 differential harness**
   (horses/src) will carry ASan/UBSan in its *own* build and hook across
   process/address-space boundaries, avoiding the interaction.

## Reproduce
```
horses/spikes/spike_s2.sh
```
prints `A) ... DIVERGENCE` and `B) ... Done 200000 runs` (no DIVERGENCE).

## Artifacts
- `horses/spikes/spike_s2.c` — harness (libFuzzer + funchook + comparator)
- `horses/spikes/s2_original.c` — "original" (loaded module)
- `horses/spikes/spike_s2.sh` — build + both control runs
- `horses/third_party/funchook/` — vendored funchook @ b4991704 (PIN.txt)
