"""humpty.men.develop — FR-4: the developer worker's LLM seam.

`make_llm_source()` returns a callable `(spec, counterexample) -> str` backed
by the Anthropic-compatible gateway (ANTHROPIC_BASE_URL/AUTH_TOKEN env — the
same gateway the S4 spike wired Pydantic AI to). The gateway is currently
rate-limited/down; the retry/backoff is the S4 pattern (6 attempts, linear
backoff), and failures raise so the queue re-queues the job.

Response cache (NFR-6): every completed call is cached under .llm_cache/
(keyed by prompt+model+seed); a repeated identical prompt costs nothing.
"""
from __future__ import annotations

import json
import os
import time

__all__ = ["make_llm_source"]


def _call_gateway(prompt: str, model: str, base: str, token: str,
                  max_tokens: int = 4000) -> str:
    import urllib.request

    req = urllib.request.Request(
        f"{base}/v1/messages",
        data=json.dumps({"model": model, "max_tokens": max_tokens,
                         "messages": [{"role": "user", "content": prompt}]}).encode(),
        headers={"x-api-key": token, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        obj = json.loads(resp.read())
    return "".join(b.get("text", "") for b in obj.get("content", []))


def make_llm_source(model: str | None = None, cache_dir: str | None = None):
    from humpty.men.cache import LLMResponseCache

    model = model or os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5")
    base = os.environ["ANTHROPIC_BASE_URL"]
    token = os.environ["ANTHROPIC_AUTH_TOKEN"]
    cache = LLMResponseCache(cache_dir)

    def llm_source(spec, counterexample=None, seed: int = 0) -> str:
        from humpty.men.prompts.templates import developer_prompt, fixer_prompt
        if counterexample is None:
            prompt = developer_prompt(spec, [], 3)
        else:
            ces = [counterexample] if isinstance(counterexample, dict) else []
            cand_src = spec.get("candidate_src", "")
            prompt = fixer_prompt(spec, cand_src, ces)
        hit = cache.get(prompt, model, seed)
        if hit is not None:
            return hit
        last = None
        for attempt in range(6):
            try:
                out = _call_gateway(prompt, model, base, token)
                cache.put(prompt, model, seed, out)
                return out
            except Exception as e:  # noqa: BLE001 — retry per S4 pattern
                last = e
                time.sleep(min(2 ** attempt, 30))
        raise RuntimeError(f"gateway unreachable after retries: {last}")

    return llm_source
