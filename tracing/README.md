# tracing/

Record-replay (WHITEPAPERS.md FR-3). The tracer executes the original on valid
inputs and records, per function: arguments, memory read, return value, memory
written. Stored in `traces` — it is the cheap oracle (replay before fuzzing), the
initial fuzz corpus, and the concrete examples in LLM prompts.

## Subdirectories

- `frida/` — Frida instrumentation scripts (M0 default: fast iteration).
- `rr/` — rr deterministic replay assets (needs hardware performance counters;
  validated by M0 spike S3).
- DynamoRIO is the large-volume alternative; no dedicated directory until chosen.

## Deliverable per run

A trace bundle per (binary, function, input-set) with digests, consumed by
`humpty.trace`. Replaying an existing bundle must reproduce the recorded I/O exactly
(NFR-2).
