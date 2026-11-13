# bench/

Model and prompt benchmarking (WHITEPAPERS.md §5: Inspect AI).

- `inspect/` — Inspect AI tasks/solvers/scorers on toy binaries with known
  sources. One task per toy case; scorers measure: compile success, trace pass
  rate, fuzz divergence rate, LLM cost (tokens), iterations to first trusted
  candidate.

## Rules

- Runs are reproducible (NFR-2): task + model + prompt + seed recorded in the
  dataset row; results archived as JSON/CSV in `bench/inspect/results/` (not in
  git for large runs).
- Used at M0 (spike S4: Pydantic AI vs mini-SWE-agent on one leaf) and reused at
  each milestone to detect prompt/model regressions.
