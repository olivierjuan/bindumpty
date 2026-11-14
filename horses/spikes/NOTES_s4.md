# S4 — agent runtime bench harness (FR-4, NFR-6)

**Date:** 2026-11-14 · **Result: CEGIS loop PROVEN end-to-end; live-LLM leg blocked by gateway rate limit / timeout (documented, retry wired)**

## Question
Can one leaf (the toy `fnv1a`) go through *develop → differential-score →
counterexample → fix → verified* unattended, and what are the economics
(tokens, iterations, wall)? Which agent runtime (Pydantic AI vs. mini-SWE-agent)
wins is the open M0 decision this spike sets up.

## What was built (the M1 asset, runtime-agnostic)
- `horses/spikes/s4_core.py` — the invariant the M1 developer worker reuses:
  - `LeafSpec` / `DevelopResult` / `ScoreResult` / `LeafResult` data types
  - `develop_prompt(spec, counterexample)` — the M1 developer prompt (signature
    + args layout + ret type + behavior notes + curated test vectors +
    counterexample when repairing)
  - `build_and_score(candidate_src, spec)` — generates one self-contained C
    program (candidate + reference + a `main` that compares them over curated
    **and** randomized cases), compiles with `clang -O1`, runs it.
    `ok == no divergence`. This is the pure-function core of the M1
    differential harness (M1 adds memory diff, FR-9, and hooks the *original*
    binary as the reference instead of source).
- `horses/spikes/spike_s4.py` — the driver. `pydantic_develop` is the
  **swappable runtime** (Pydantic AI wired here; mini-SWE-agent is the
  alternative). Reads `ANTHROPIC_MODEL` / `ANTHROPIC_BASE_URL` /
  `ANTHROPIC_AUTH_TOKEN` from env, and carries 429 retry/backoff (the same
  resilience the M1 fixer worker needs).

## What was proven
1. **Scorer discriminates** (no LLM involved):
   - known-correct `fnv1a` → `ok=True`
   - known-wrong `fnv1a` (prime `+1`) → `ok=False`, divergences reported
   - broken source → `build_error` (the repair feedback path)
   - the C reference matches the Python-minted prompt vectors (byte-exact;
     the scorer emits *real* byte arrays, not hex-string literals).
2. **The CEGIS loop verifies in 2 iterations** (deterministic mock runtime, no
   network): buggy prime → `DIVERGED` on case 1 (`cand=0x6528C6D0
   ref=0xE40C292C`) → counterexample fed back → correct function → `VERIFIED`
   across 262 cases. This is the M1 developer/fixer contract, proven
   end-to-end on the real leaf.

## Blocked (infra, not design)
The **live-LLM leg** could not complete: the configured gateway
(`ANTHROPIC_BASE_URL`, a LiteLLM proxy) served a **429 rate limit** and then
**ReadTimeouts** on all model groups during the run window. The env's model
names (`claude-*-5-3`) are not even the groups the proxy serves
(`claude-*-5-5`); the proxy's `/v1/models` confirms the valid IDs. The driver
is wired to retry/backoff on 429, so a re-run against a live gateway should
complete. **Re-run:** `.venv/bin/python horses/spikes/spike_s4.py --model
claude-sonnet-5-5 --cases 512`.

## Findings for M1 planning
- **The runtime is a thin swappable seam.** Only `develop(spec,
  counterexample) -> {source, tokens}` differs between Pydantic AI and
  mini-SWE-agent; the scorer, prompt, and CEGIS loop are shared. The benchmark
  harness is therefore *not* one agent's tests — it scores both runtimes on
  the same leaf with the same scorer.
- **429 handling must be in the runtime, not the caller** (added; the M1
  fixer inherits it).
- **Economics (to be filled by the live run):** iterations-to-verified,
  in/out tokens, wall, est. cost. The mock run's shape (2 iters) is the floor;
  a real LLM on `fnv1a` should verify in 1–2 iters since the behavior notes
  name the FNV constants.

## Files
- `horses/spikes/s4_core.py` (M1 asset)
- `horses/spikes/spike_s4.py` (driver, Pydantic AI runtime)
- `horses/spikes/out/s4_fnv1a.json` (written when the live run completes)
