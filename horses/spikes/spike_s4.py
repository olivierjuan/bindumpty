#!/usr/bin/env python3
"""S4 spike driver (M0): run the CEGIS leaf pipeline with the Pydantic AI
agent runtime on the toy `fnv1a` leaf, and measure the economics.

This validates the M0 spike S4 question: "one leaf through Pydantic AI, scored
with Inspect AI" — concretized as: does an LLM agent produce a verified
reimplementation of a real leaf, in how many iterations, at what token cost?

Runtime choice (Pydantic AI vs mini-SWE-agent) is the open M0 decision; this
driver wires Pydantic AI. The `develop` function is the swap point — the
scorer (s4_core.build_and_score) is runtime-agnostic and is the M1 asset.

Usage:  .venv/bin/python horses/spikes/spike_s4.py [--model NAME] [--max-iter 3]
Reads ANTHROPIC_MODEL / ANTHROPIC_BASE_URL / ANTHROPIC_AUTH_TOKEN from env.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from s4_core import (  # noqa: E402
    Fnv1aSpec,
    DevelopResult,
    LeafResult,
    build_and_score,
    develop_prompt,
    parse_develop,
)

# public USD per 1M tokens (approx, for the economics table)
MODEL_RATES = {
    "sonnet": (3.0, 15.0),
    "opus": (15.0, 75.0),
    "haiku": (0.25, 1.25),
}


def pydantic_develop(spec, counterexample=None, model=None, max_tokens=4000):
    """The swappable runtime. Returns DevelopResult.

    Reads ANTHROPIC_MODEL (model id), ANTHROPIC_AUTH_TOKEN / ANTHROPIC_API_KEY,
    and ANTHROPIC_BASE_URL from the environment; wires an AnthropicProvider
    explicitly so the custom gateway base_url and auth token are honored.
    """
    from pydantic_ai import Agent
    from pydantic_ai.models.anthropic import AnthropicModel
    from pydantic_ai.providers.anthropic import AnthropicProvider

    model_id = model or os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5")
    api_key = os.environ.get("ANTHROPIC_AUTH_TOKEN") or os.environ.get("ANTHROPIC_API_KEY")
    base_url = os.environ.get("ANTHROPIC_BASE_URL")
    provider = AnthropicProvider(api_key=api_key, base_url=base_url) if base_url else None
    am = AnthropicModel(model_id, provider=provider) if provider else AnthropicModel(model_id)

    system = (
        "You reimplement stripped-binary functions in C. Answer with ONLY "
        '{"source": "..."} — no prose, no markdown fences.'
    )
    agent = Agent(am, system_prompt=system)
    t0 = time.perf_counter()
    # 429 retry/backoff: LLM gateways throttle; the M1 fixer worker needs the
    # same resilience, so the retry loop lives in the runtime, not the caller.
    res = None
    last_err = None
    for attempt in range(6):
        try:
            res = agent.run_sync(develop_prompt(spec, counterexample))
            break
        except Exception as e:  # noqa: BLE001
            last_err = e
            msg = str(e)
            throttled = "429" in msg or "RateLimit" in msg or "rate_limit" in msg
            if not throttled:
                raise
            backoff = min(60.0, 2.0 ** attempt)
            print(f"  [s4] 429 on attempt {attempt + 1}, backing off {backoff:.0f}s",
                  file=sys.stderr)
            time.sleep(backoff)
    if res is None:
        raise RuntimeError(f"LLM still throttled after 6 attempts: {last_err}")
    wall = time.perf_counter() - t0
    src = parse_develop(res.output)
    it = res.usage()
    return DevelopResult(
        source=src,
        input_tokens=getattr(it, "input_tokens", 0) or 0,
        output_tokens=getattr(it, "output_tokens", 0) or 0,
        wall_s=wall,
        error=getattr(res, "error", None),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=None, help="override ANTHROPIC_MODEL")
    ap.add_argument("--max-iter", type=int, default=3)
    ap.add_argument("--cases", type=int, default=512, help="randomized differential cases")
    args = ap.parse_args()

    model = args.model or os.environ.get("ANTHROPIC_MODEL", "anthropic:claude-sonnet-4-5")
    spec = Fnv1aSpec(randomized_n=args.cases)
    print(f"S4: Pydantic AI runtime, model={model}, leaf={spec.name}, "
          f"cases={spec.randomized_n + len(spec.test_vectors)} (incl {len(spec.test_vectors)} curated)")

    t_start = time.perf_counter()
    ce = None
    last_dev, last_score = None, None
    for it in range(1, args.max_iter + 1):
        dev = pydantic_develop(spec, ce, model=model)
        if it > 1:
            # accumulate tokens
            last_dev.input_tokens += dev.input_tokens
            last_dev.output_tokens += dev.output_tokens
            last_dev.wall_s += dev.wall_s
            dev = last_dev
        dev.iterations = it
        score = build_and_score(dev.source, spec)
        last_dev, last_score = dev, score
        status = "VERIFIED" if score.ok else f"DIVERGED x{len(score.divergences)}"
        print(f"  iter {it}: in={dev.input_tokens} out={dev.output_tokens} tokens "
              f"llm={dev.wall_s:5.1f}s build+run={score.wall_s:5.2f}s -> {status}")
        if score.ok:
            break
        # feed the first counterexample back
        if score.divergences:
            c = score.divergences[0]
            ce = f"  cand=0x{c[1]} ref=0x{c[2]} (at {c[0]})"
        elif score.build_error:
            ce = f"  the previous source failed to compile:\n{score.build_error[-500:]}"

    verified = last_score.ok if last_score else False
    total_wall = time.perf_counter() - t_start
    result = LeafResult(
        name=spec.name,
        verified=verified,
        source=last_dev.source if last_dev else "",
        develop=last_dev,
        score=last_score,
        total_wall_s=total_wall,
    )

    # economics
    key = next((k for k in MODEL_RATES if k in model.lower()), "sonnet")
    tin, tout = MODEL_RATES[key]
    cost = (last_dev.input_tokens / 1e6) * tin + (last_dev.output_tokens / 1e6) * tout if last_dev else 0

    print(f"\n{'=' * 64}")
    print(f"LEAF {spec.name}: {'VERIFIED' if verified else 'NOT VERIFIED'} "
          f"in {last_dev.iterations if last_dev else 0} iteration(s)")
    print(f"  tokens: in={last_dev.input_tokens} out={last_dev.output_tokens} "
          f"(est. cost ~${cost:.4f} at {key} rates)")
    print(f"  wall: total={total_wall:6.1f}s  (llm {last_dev.wall_s:5.1f}s + "
          f"build/run {last_score.wall_s if last_score else 0:4.2f}s)")
    if not verified and last_score and last_score.divergences:
        print(f"  remaining divergences: {last_score.divergences[:3]}")
    print(f"{'=' * 64}")

    # also record the winning source for the record
    out = os.path.join(os.path.dirname(__file__), "out")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, f"s4_{spec.name}.json"), "w") as f:
        json.dump({
            "leaf": spec.name, "model": model, "verified": verified,
            "iterations": last_dev.iterations if last_dev else 0,
            "input_tokens": last_dev.input_tokens if last_dev else 0,
            "output_tokens": last_dev.output_tokens if last_dev else 0,
            "total_wall_s": round(total_wall, 2),
            "est_cost_usd": round(cost, 4),
            "source": last_dev.source if last_dev else "",
            "divergences": last_score.divergences[:5] if last_score else [],
        }, f, indent=2)
    print(f"  result -> {out}/s4_{spec.name}.json")

    return 0 if verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
