# tests/

- `unit/` — fast, no sandbox, no LLM: domain state machine, ready-set / confidence
  propagation, counterexample dedup, graveyard Pareto retention, DB migrations.
- `integration/` — run against a toy binary in the sandbox: ingestion → traces →
  one CEGIS cycle. Slow; marked `@pytest.mark.sandbox` and skipped when the
  sandbox image is unavailable.

## Rules

- No test calls a real LLM provider; LLM responses are cached/mocked (NFR-6
  cache doubles as the test seam).
- Every reported divergence in a test must be deterministically reproducible
  (NFR-2): a test that passes non-deterministically is broken.
- No LLM-generated code executes outside the sandbox (global acceptance).
