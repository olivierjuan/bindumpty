# S3 — deterministic replay viability (rr / DynamoRIO)

**Date:** 2026-11-14 · **Result: counters available, tracers absent, MSR absent**

## Question
Can this host do deterministic record/replay (FR-3's gold standard) via rr or
DynamoRIO, and what are the blocking conditions?

## Probe
`horses/spikes/spike_s3_replay_probe.py` — no tracer install; inspects the
kernel's stance and issues real `perf_event_open(2)` syscalls (the exact call
rr makes) for software and hardware CPU/instruction events.

## Findings (this machine, kernel 5.10.0-46-amd64)
| condition | value | meaning |
|---|---|---|
| `perf_event_paranoid` | **0** | rr wants ≤ 1 — satisfied |
| `ptrace_scope` | **0** | unrestricted — helps DynamoRIO |
| HW `CPU_CYCLES` / `INSTRUCTIONS` open | **OK** (per-thread + per-CPU) | the PMU counters rr/DynamoRIO need are usable |
| SW `cpu-clock` open | **OK** | fallback counter works |
| `/dev/cpu/*/msr` | **ABSENT** | msr module not loaded / no perms — rr's CPU-state snapshot needs it |
| `rr`, `dynamorio` binaries | **not installed** | and **not buildable here** (no `flex`/`bison`/capstone-dev, no root) |

## Verdict
- **Deterministic replay is not runnable on this host as-is.** The performance
  counters and ptrace permission are fine, but (a) the MSR device is absent and
  (b) neither tracer is installed and can't be built here (missing flex/bison
  + capstone dev headers, no root for apt).
- **Frida is the FR-3 tracer to use now** (already implemented:
  `tracing/record_frida.py`). It does not need perf counters or MSR; it captures
  args/memory/ret/writes via injection. It is not *deterministic* replay in the
  rr sense (no instruction-exact rewinding), so the "deterministic replay"
  property of FR-3 is **deferred to a host that has rr/DynamoRIO + MSR**.
- **Escalation** (to make rr viable later): load the `msr` kernel module
  (or grant `/dev/cpu/*/msr`), ensure `perf_event_paranoid<=1`, and install
  rr or DynamoRIO on a build host (needs flex/bison/capstone 5 dev + root).

## Caveat
The `perf_event_open` attr struct is fiddly: the kernel validates `size` at
**offset 4** (32-bit `type` at 0, 32-bit `size` at 4) — a wrong `size` yields
EINVAL. The probe was verified byte-for-byte against a working C struct.

## Reproduce
```
.venv/bin/python horses/spikes/spike_s3_replay_probe.py
```
Exit 0 = at least one tracer's prerequisites present; exit 1 = neither.
