"""humpty.men.providers — multi-provider LLM seam (FR-4).

The developer/fixer workers talk to ONE interface; the provider is a config
choice. Backed by litellm (the standard router: one call signature for
Anthropic, Gemini, OpenAI/OpenRouter, Ollama, vLLM, Modal-served endpoints,
...), plus the repo's original direct-Anthropic path (the EDF gateway, which
predates litellm and needs its retry semantics).

Selection — any of:
    --provider claude  --model claude-sonnet-5-5          (direct Anthropic)
    --provider litellm --model gemini/gemini-2.0-flash    (litellm router)
    --provider litellm --model openrouter/openai/gpt-4o   (litellm router)
    --provider litellm --model ollama/llama3              (local, free)
    --provider litellm --model openai/<name> --api-base http://modal.host/v1
    env: HUMPTY_PROVIDER / HUMPTY_MODEL (CLI flags win)

Keys follow each provider's own convention (litellm reads the standard env
vars: ANTHROPIC_API_KEY, GEMINI_API_KEY, OPENROUTER_API_KEY, OPENAI_API_KEY,
...). This module adds: the response cache (NFR-6) in front of every call,
retry with backoff, and a uniform DevelopResult.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass

__all__ = ["ProviderSpec", "make_develop", "PROVIDERS", "ProviderError"]


class ProviderError(RuntimeError):
    pass


@dataclass
class ProviderSpec:
    provider: str          # "claude" | "litellm"
    model: str
    api_base: str | None = None
    api_key_env: str | None = None
    max_tokens: int = 4000
    temperature: float = 0.8
    seed: int = 0


PROVIDERS = {
    # provider id -> (api_key_env, default model, description)
    "claude": ("ANTHROPIC_AUTH_TOKEN", "claude-sonnet-5-5",
               "direct Anthropic Messages API (the EDF gateway path)"),
    "litellm": ("LITELLM_KEY", "gpt-4o-mini",
                "litellm router: gemini/*, openrouter/*, ollama/*, "
                "openai/*, groq/*, together/*, ..."),
    "gemini": ("GEMINI_API_KEY", "gemini-2.0-flash",
               "Google Gemini via litellm"),
    "openrouter": ("OPENROUTER_API_KEY", "openai/gpt-4o",
                   "OpenRouter via litellm (user passes openrouter/<model>)"),
    "codex": ("OPENAI_API_KEY", "openai/codex-mini-latest",
              "OpenAI Codex models via litellm"),
    "modal": ("MODAL_LLM_TOKEN", "openai/",  # user sets --model + --api-base
              "Modal-served OpenAI-compatible endpoint via litellm "
              "(set --api-base to the .modal.run URL)"),
    "ollama": (None, "llama3.1:8b",
               "local Ollama via litellm (free, offline)"),
    "vllm": (None, "openai/<model>",
             "local/self-hosted vLLM via litellm (set --api-base)"),
}


def resolve_provider(provider: str | None, model: str | None,
                     api_base: str | None = None) -> ProviderSpec:
    """Resolve CLI/config inputs into a ProviderSpec. Unknown provider →
    ProviderError listing the valid ones."""
    provider = (provider or os.environ.get("HUMPTY_PROVIDER") or "claude").lower()
    if provider not in PROVIDERS:
        raise ProviderError(
            f"unknown provider {provider!r} (have: {', '.join(sorted(PROVIDERS))})")
    key_env, default_model, _ = PROVIDERS[provider]
    model = (model or os.environ.get("HUMPTY_MODEL") or default_model)
    # litellm models carry a route prefix (ollama/, openai/, gemini/...);
    # never double it when the user already passed one
    if provider in ("litellm", "gemini", "openrouter", "codex", "modal",
                    "ollama", "vllm") and provider != "openrouter":
        route = provider if provider != "gemini" else "gemini"
        if provider == "codex":
            route = "openai"
        if provider == "modal":
            route = "openai"
        if provider == "vllm":
            route = "openai"
        if not model.startswith(route + "/"):
            model = f"{route}/{model}"
    base = api_base or os.environ.get("HUMPTY_API_BASE")
    if provider == "claude" and not base:
        base = os.environ.get("ANTHROPIC_BASE_URL")
    return ProviderSpec(provider=provider, model=model, api_base=base,
                        api_key_env=key_env)


def _chat_litellm(spec: ProviderSpec, prompt: str) -> str:
    import litellm

    kwargs: dict = {"model": spec.model, "max_tokens": spec.max_tokens,
                    "temperature": spec.temperature}
    if spec.api_base:
        kwargs["api_base"] = spec.api_base
    resp = litellm.completion(messages=[{"role": "user", "content": prompt}],
                              **kwargs)
    return resp.choices[0].message.content or ""


def _chat_claude(spec: ProviderSpec, prompt: str) -> str:
    import urllib.request

    base = spec.api_base or "https://api.anthropic.com"
    token = os.environ.get(spec.api_key_env or "ANTHROPIC_AUTH_TOKEN", "")
    req = urllib.request.Request(
        f"{base}/v1/messages",
        data=json.dumps({"model": spec.model, "max_tokens": spec.max_tokens,
                         "messages": [{"role": "user", "content": prompt}]}).encode(),
        headers={"x-api-key": token, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        obj = json.loads(resp.read())
    return "".join(b.get("text", "") for b in obj.get("content", []))


def make_develop(spec: ProviderSpec, cache_dir: str | None = None,
                 retries: int = 6, log=print):
    """The FR-4 develop callable: (leaf_spec, counterexample) -> C source.
    Wraps the provider with retry/backoff and the NFR-6 response cache."""
    from humpty.men.cache import LLMResponseCache
    from humpty.men.prompts.templates import developer_prompt

    cache = LLMResponseCache(cache_dir)

    def develop(leaf_spec, counterexample=None) -> str:
        if isinstance(leaf_spec, dict):
            prompt = developer_prompt(leaf_spec, [], 3)
        else:
            prompt = leaf_spec.prompt_text() if hasattr(leaf_spec, "prompt_text") \
                else developer_prompt({"name": getattr(leaf_spec, "name", "?"),
                                       "signature": getattr(leaf_spec, "signature", ""),
                                       "ret_type": getattr(leaf_spec, "ret_type", ""),
                                       "notes": getattr(leaf_spec, "notes", "")}, [], 3)
        if counterexample:
            prompt += (f"\n\nA previous attempt DIVERGED on:\n{counterexample}\n"
                       "Fix it generally — no input-keyed special cases.")
        hit = cache.get(prompt, spec.model, spec.seed)
        if hit is not None:
            log("cache hit")
            return hit
        chat = _chat_litellm if spec.provider == "litellm" else _chat_claude
        last: Exception | None = None
        for attempt in range(retries):
            try:
                out = chat(spec, prompt)
                cache.put(prompt, spec.model, spec.seed, out)
                return out
            except Exception as e:  # noqa: BLE001 — retry per S4 pattern
                last = e
                time.sleep(min(2 ** attempt, 30))
        raise ProviderError(f"{spec.provider}/{spec.model} unreachable "
                            f"after {retries} retries: {last}")

    return develop
