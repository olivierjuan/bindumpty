# tracing/

Record-replay (WHITEPAPERS.md FR-3). Captures, per function, the original's
real I/O on a curated set of *valid* inputs. Stored in `traces` — it is the
cheap oracle (replay before fuzzing), the initial fuzz corpus, and the concrete
examples in LLM prompts. It limits false divergences caused by unreachable
states.

## Output format

`fuz.traces/1`: one JSON object per call, e.g.

    {"fn":"fnv1a","arg":"61","arglen":1,"ret":"0xe40c292c"}
    {"fn":"digit_sum_u32","arg":"1234","ret":10}

## Two routes, one format

- **`record_frida.py` — production route (M2+).** In-place observation of the
  real (source-unavailable) stripped binary: spawn/park it, then a Frida agent
  calls each target at `module.base + vaddr` (ASLR-aware, the same mechanics as
  FR-7 hooking) and reads the return. This is the path the whitepaper names
  (Frida for fast iteration, DynamoRIO for large volume, rr for deterministic
  replay — validated in M0 spike S3).
- **`toys/*/sources/trace_driver.c` — toy oracle (M0).** For a toy whose source
  is known, the cleanest ground truth is to run the original functions in the
  sandbox (NFR-1) on the curated inputs and capture the I/O. Values are
  identical to in-place observation for the same inputs because the functions
  are deterministic (no globals/time/RNG). Each toy's `record.sh` uses this.

## Host note (documented limitation)

On this dev host, calling a function in the *parked main PIE* directly via
Frida `NativeFunction` hit an access violation (observed 2026-11-14, Frida 17.26.3,
clang-19 PIE): module and entry address resolve and are readable, but the
synthetic call faults. The toy oracle (driver route) is unaffected and is the
M0 ground truth; the Frida route is re-exercised at M2, when FR-7 hooking makes
in-place calling mandatory and the target is a real binary loaded normally
(not parked). rr/DynamoRIO availability on this machine is checked by spike S3.

## Subdirectories

- `frida/` — Frida instrumentation scripts (the production route).
- `rr/` — rr deterministic-replay assets (needs hardware performance counters;
  validated by spike S3).
- `record_frida.py` — the Frida tracer (production route).

## Deliverable per run

A trace bundle per (binary, function, input-set) with digests, consumed by
`humpty.trace`. Replaying an existing bundle must reproduce the recorded I/O
exactly (NFR-2).
