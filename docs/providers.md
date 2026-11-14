# LLM providers

The developer/fixer workers talk to one interface; the provider is a
choice. Backed by [litellm](https://docs.litellm.ai/) (one call signature
for every major vendor) plus a direct Anthropic path.

## Providers

| Provider | Flag | Key env | Notes |
|---|---|---|---|
| `claude` | `--provider claude` | `ANTHROPIC_AUTH_TOKEN` | direct Anthropic Messages API (the EDF gateway path) |
| `litellm` | `--provider litellm --model <id>` | varies | the standard router: `groq/*`, `together/*`, `mistral/*`, ... |
| `gemini` | `--provider gemini` | `GEMINI_API_KEY` | Google Gemini |
| `openrouter` | `--provider openrouter --model openrouter/<model>` | `OPENROUTER_API_KEY` | multi-provider catalog |
| `codex` | `--provider codex` | `OPENAI_API_KEY` | OpenAI Codex models |
| `modal` | `--provider modal --model openai/<name> --api-base https://....modal.run/v1` | `MODAL_LLM_TOKEN` | Modal-served OpenAI-compatible endpoint |
| `ollama` | `--provider ollama --model llama3.1:8b` | none | local, free, offline |
| `vllm` | `--provider vllm --model openai/<name> --api-base http://host/v1` | none | self-hosted vLLM |

Defaults come from `HUMPTY_PROVIDER` / `HUMPTY_MODEL` when the flags are
omitted.

## Usage

```bash
# Gemini for the developer seam
.venv/bin/python -m humpty.king.cli lpex2 --symbol main --provider gemini

# local Ollama — no key, no network
.venv/bin/python -m humpty.king.cli lpex2 --symbol main --provider ollama

# switch providers inside the shell
.venv/bin/python -m humpty.king.shell lpex2
  provider gemini
  provider ollama llama3.1:8b
  run
```

Every call goes through the NFR-6 response cache (same prompt + model +
seed = zero cost) and retry/backoff (the gateway's 429/timeouts are a
fact of life; six attempts with exponential backoff before the job
re-queues).

## Honesty rules

- The plan panel shows the **resolved** provider/model and whether the key
  is present — "configured" is never displayed as "working".
- A run without a reachable endpoint **refuses**: the developer seam is the
  synthesizer, and a stripped binary has no source to extract.
- Model quality is measured, not assumed: the M1/M4 scorers report
  iterations-to-verified and token economics per model.
