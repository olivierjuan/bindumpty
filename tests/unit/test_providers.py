"""Unit: humpty.men.providers — provider resolution + litellm e2e path."""
import os
import sys
import unittest.mock as mock

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from humpty.men.providers import (  # noqa: E402
    ProviderError, ProviderSpec, _chat_litellm, make_develop, resolve_provider)


def test_litellm_model_ids_passthrough_untouched():
    """litellm ids already carry their route prefix; the resolver must not
    double it (gemini/x, openrouter/..., groq/...)."""
    for mid in ("gpt-4o-mini", "gemini/gemini-2.0-flash",
                "openrouter/anthropic/claude-sonnet-5-5",
                "groq/llama-3.3-70b"):
        assert resolve_provider("litellm", mid).model == mid


def test_unprefixing_for_routed_providers():
    assert resolve_provider("gemini", "gemini-2.0-flash").model == \
        "gemini/gemini-2.0-flash"
    assert resolve_provider("ollama", "llama3.1:8b").model == \
        "ollama/llama3.1:8b"
    assert resolve_provider("codex", "codex-mini-latest").model == \
        "openai/codex-mini-latest"


def test_unknown_provider_rejected():
    with pytest.raises(ProviderError):
        resolve_provider("skynet", None)


def test_litellm_develop_end_to_end(tmp_path):
    """The full develop seam through litellm.completion (mocked at the HTTP
    boundary — the real code path: cache miss → completion → cache put)."""
    import litellm

    spec = ProviderSpec(provider="litellm", model="gpt-4o-mini")
    fake = '{"source": "uint32_t f(void){return 1;}"}'
    with mock.patch.object(litellm, "completion",
                           return_value=mock.Mock(choices=[mock.Mock(
                               message=mock.Mock(content=fake))])):
        dev = make_develop(spec, cache_dir=str(tmp_path))
        out = dev({"name": "f", "signature": "uint32_t f(void)",
                   "ret_type": "uint32_t", "notes": ""})
        # the JSON envelope is unwrapped to compilable C (the candidate
        # file must never see the raw provider reply)
        assert out == "uint32_t f(void){return 1;}"
        # second identical call = cache hit (completion not called again);
        # the cached value is the ALREADY-EXTRACTED C
        with mock.patch.object(litellm, "completion",
                               side_effect=AssertionError("cache miss!")):
            out2 = dev({"name": "f", "signature": "uint32_t f(void)",
                        "ret_type": "uint32_t", "notes": ""})
            assert out2 == "uint32_t f(void){return 1;}"


def test_provider_table_complete():
    from humpty.men.providers import PROVIDERS
    for name in ("claude", "litellm", "gemini", "openrouter", "codex",
                 "modal", "ollama", "vllm"):
        assert name in PROVIDERS
