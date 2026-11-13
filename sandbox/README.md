# sandbox/

Isolation and deployment (WHITEPAPERS.md NFR-1, NFR-8).

## Rules

- All LLM-generated code and the untrusted target binary execute only here:
  rootless containers, **no network**, cgroup CPU/memory limits, timeouts.
  No execution on the host, ever (global acceptance criterion).
- Pinned base images; the container build must be reproducible (NFR-8).

## Layout

- `Dockerfile` (M0) — sandbox image: clang, libFuzzer, ASan/UBSan, funchook,
  Ghidra headless runtime, Python 3.12.
- `slurm/` (M3, NFR-4) — SLURM submission scripts launching stateless workers;
  Apptainer variants where Docker is forbidden on HPC.

## Contracts

- Every fuzz/candidate run is launched with an explicit
  `(seed, binary, candidate, corpus)` tuple so it is replayable (NFR-2).
- Run artifacts (fuzz coverage, minimized crashes, logs) land in the run
  directory, not in the repository.
