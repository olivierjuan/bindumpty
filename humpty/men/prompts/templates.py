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


def developer_prompt(spec: dict, vectors: list[tuple[str, str]], n: int = 3,
                     types_header: str | None = None) -> str:
    """FR-4. `spec`: {name, signature, ret_type, notes, decompiled_c, types_header, assembly, callees}.
    `vectors`: (input_repr, expected_repr) from the trace bundle. Returns the prompt
    asking for N distinct candidates as a JSON array of sources."""
    vec = "\n".join(f"  {i} -> {o}" for i, o in vectors) or "  (none recorded)"

    decomp_section = ""
    if spec.get("decompiled_c"):
        decomp_section = f"\nDecompiled C pseudo-code from binary analysis:\n```c\n{spec.get('decompiled_c')}\n```\n"

    types_section = ""
    if spec.get("types_header"):
        types_section = f"\nReconstructed type definitions / struct layouts:\n```c\n{spec.get('types_header')}\n```\n"

    asm_section = ""
    if spec.get("assembly"):
        asm_section = f"\nAssembly listing:\n```asm\n{spec.get('assembly')}\n```\n"

    callees_section = ""
    if spec.get("callees"):
        callees_section = "\nCallee signatures:\n" + "\n".join(f"  {c}" for c in spec.get("callees")) + "\n"

    if spec.get("decompiled_c"):
        return f"""You are lifting and cleaning up decompiled code from a binary function into idiomatic C.

Function: {spec.get("name")}
Signature: {spec.get("signature")}
Return type: {spec.get("ret_type", "")}
Behavior notes: {spec.get("notes", "(none)")}
{decomp_section}{types_section}{callees_section}{asm_section}
Known input/output pairs (from recorded traces — treat as ground truth):
{vec}

Your goal:
1. Lift and clean the decompiled code into readable, idiomatic, standard C while preserving EXACT mathematical and behavioral equivalence.
2. Maintain the signature exactly: {spec.get("signature")}.
3. Replace raw pointer arithmetic and byte-offset casts (e.g. *(int*)(p + 0x18)) with meaningful struct field accesses if types are known.
4. Clean up decompiler artifacts (redundant casts, register names, intermediate compiler temporaries).
5. Ensure the code is self-contained and compilable with clang/gcc.

Produce {n} DISTINCT candidate reimplementations in C. Respond with ONLY a
JSON object: {{"candidates": ["<C source>", ...]}}. Each source defines
exactly this function, nothing else."""

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
    decomp_ctx = ""
    if spec.get("decompiled_c"):
        decomp_ctx = f"\nDecompiled C reference:\n```c\n{spec.get('decompiled_c')}\n```\n"

    return f"""Your previous reimplementation of one function is WRONG on some
inputs. Function: {spec.get("name")} ({spec.get("signature")}).
{decomp_ctx}
Failing cases (deduplicated):
{ces}

The candidate source:
```c
{candidate_src}
```

Rewrite the function so it is correct for ALL inputs, not just the failing
ones. Rules:
- The fix must follow from the function's *specification* and algorithmic logic, not from the
  failing inputs. Adding branches keyed on the failing input values
  (hardcoding) is forbidden and will be rejected by replay of the full test
  suite.
- Do not reference the original binary or its bytes.
Respond with ONLY a JSON object: {{"source": "<C source>"}}."""
