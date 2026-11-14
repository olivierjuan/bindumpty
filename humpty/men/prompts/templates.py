"""humpty.men.prompts.developer — FR-4/FR-5 prompt templates.

The developer (FR-4) turns a leaf spec + traces into N candidate sources.
The fixer (FR-5) turns candidate + deduplicated counterexamples into a
repaired source. Both are *pure functions of their inputs* (the LLM is
swappable behind them — Pydantic AI, mini-SWE-agent, or the local sampler),
so the prompts live here, versioned, and the workers in humpty.men compose
them.

Anti-hardcode (FR-5): the fixer prompt explicitly forbids input-keyed
special-casing, and the gate in humpty.men.fixer enforces it mechanically by
replaying the full regression suite (all persisted counterexamples + the
trace bundle) on any accepted repair.
"""
from __future__ import annotations

__all__ = ["developer_prompt", "fixer_prompt"]


def developer_prompt(spec: dict, vectors: list[tuple[str, str]], n: int = 3) -> str:
    """FR-4. `spec`: {name, signature, ret_type, notes}. `vectors`:
    (input_repr, expected_repr) from the trace bundle. Returns the prompt
    asking for N distinct candidates as a JSON array of sources."""
    vec = "\n".join(f"  {i} -> {o}" for i, o in vectors) or "  (none recorded)"
    return f"""You are reimplementing one function from a stripped binary.

Function: {spec.get("name")}
Signature: {spec.get("signature")}
Return type: {spec.get("ret_type")}
Behavior notes: {spec.get("notes", "(none)")}

Known input/output pairs (from recorded traces — treat as ground truth):
{vec}

Produce {n} DISTINCT candidate reimplementations in C. Respond with ONLY a
JSON object: {{"candidates": ["<C source>", ...]}}. Each source defines
exactly this function, nothing else. Prefer clear, standard C. Do not read
the original binary's bytes; implement the behavior."""


def fixer_prompt(spec: dict, candidate_src: str,
                 counterexamples: list[dict]) -> str:
    """FR-5. `counterexamples`: [{input_repr, expected_repr, observed_repr}].
    The repair instruction explicitly bans input-keyed special cases; the
    mechanical gate (replay of the full suite) enforces what the prompt asks.
    """
    ces = "\n".join(
        f"  input {c['input_repr']}: expected {c['expected_repr']}, "
        f"candidate returned {c['observed_repr']}"
        for c in counterexamples
    )
    return f"""Your previous reimplementation of one function is WRONG on some
inputs. Function: {spec.get("name")} ({spec.get("signature")}).

Failing cases (deduplicated):
{ces}

The candidate source:
```c
{candidate_src}
```

Rewrite the function so it is correct for ALL inputs, not just the failing
ones. Rules:
- The fix must follow from the function's *specification*, not from the
  failing inputs. Adding branches keyed on the failing input values
  (hardcoding) is forbidden and will be rejected by replay of the full test
  suite.
- Do not reference the original binary or its bytes.
Respond with ONLY a JSON object: {{"source": "<C source>"}}."""
