"""humpty.king.stub_develop — LLM-free deterministic develop runtime.

Used by --dev-stub: the 'candidate' is the leaf's own decompiled C
(functions.decompiled_code) — the Ghidra-lifted source. The CEGIS loop
then validates it differentially. This exercises the full pipeline
(prune -> decompile -> harness -> fuzz -> parent validation ->
recompose) without a reachable LLM.
"""
from __future__ import annotations


def make_stub_develop():
    """Returns a develop(spec, counterexample) -> C source callable."""

    from humpty.king.stub_develop import GHIDRA_PRELUDE

    def develop(spec, counterexample=None) -> str:
        src = spec.get("decompiled_c") if isinstance(spec, dict) else None
        if not src:
            raise RuntimeError(
                "stub develop: no decompiled_c in spec — run with the "
                "ghidra backend so decompilation is available")
        # Ghidra's decompiler output uses its own pseudo-types (code,
        # undefined8...); prepend the prelude so the candidate compiles
        return GHIDRA_PRELUDE + src

    return develop


GHIDRA_PRELUDE = """/* Ghidra decompiler type prelude (auto-prepended) */
typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef void code;
typedef struct { unsigned char _[8]; } undefined_ret;
typedef long long longlong;
typedef unsigned char uchar;
"""
