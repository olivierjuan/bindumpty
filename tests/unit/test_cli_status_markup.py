"""Regression: _llm_status output must be valid rich markup in every branch
(a malformed tag crashed the whole CLI inside the panel render)."""
import os
import sys

import pytest
from rich.console import Console

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from humpty.king import cli as cli_mod  # noqa: E402
from humpty.men import providers as prov  # noqa: E402


@pytest.mark.parametrize("provider", ["litellm", "gemini", "openrouter",
                                      "codex", "modal", "ollama", "vllm",
                                      "claude"])
def test_llm_status_renders_as_markup(provider, monkeypatch):
    # no keys in env -> the missing-key branch is taken
    for var in ("ANTHROPIC_AUTH_TOKEN", "LITELLM_KEY", "GEMINI_API_KEY",
                "OPENROUTER_API_KEY", "OPENAI_API_KEY", "MODAL_LLM_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    cli_mod._prov_args.clear()
    cli_mod._prov_args.update(provider=provider, model=None, api_base=None)
    status = cli_mod._llm_status()
    console = Console()
    # render_str raises MarkupError on malformed tags — this is the guard
    text = console.render_str(status)
    assert "missing key" in text.plain or "key OK" in text.plain


def test_llm_status_with_key_present(monkeypatch):
    monkeypatch.setenv("LITELLM_KEY", "k")
    cli_mod._prov_args.clear()
    cli_mod._prov_args.update(provider="litellm", model=None, api_base=None)
    status = cli_mod._llm_status()
    console = Console()
    text = console.render_str(status)
    assert "key OK" in text.plain
