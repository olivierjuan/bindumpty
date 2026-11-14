"""humpty.analyze.adapt — pipeline behavior keyed on the source-language verdict.

A binary built from C++ sources needs different pipeline treatment than one
built from C (see detect_lang). This module is the *single* place that maps a
verdict to concrete behavior, so the adaptation is explicit, testable and
auditable — never sprinkled through the pipeline as `if cxx` checks.

Adaptation map
--------------
| Pipeline point      | C input                    | C++ input                     |
|---------------------|----------------------------|-------------------------------|
| FR-1 Ghidra options | default analyzer           | + RTTI/vtable recovery,       |
|                     |                            |   class recovery, demangler   |
| FR-2 fingerprint    | libc corpus                | + STL/Boost/fmt corpus        |
| FR-12 type registry | C structs/unions only      | + class layouts, inheritance  |
| FR-4 prompt         | C pseudocode               | note mangled names / vtables  |
| FR-6 harness        | (identical — language-agnostic)                            |
| FR-7 hooking        | (identical — symbol/address-based)                         |

The last two rows are the point: the *validation* machinery does not care
about the input language, so the adapter never touches it.
"""
from __future__ import annotations

from dataclasses import dataclass

__all__ = ["Adapter", "adapter_for"]


@dataclass(frozen=True)
class Adapter:
    """Concrete pipeline switches for one source-language verdict."""

    source_lang: str          # "c" | "cpp" | "lean_cpp"
    # FR-1: Ghidra analyzer options to request in the headless session.
    ghidra_analyzer_options: tuple[str, ...] = ()
    # FR-2: fingerprint corpus to load before any reimplementation.
    fingerprint_corpora: tuple[str, ...] = ("libc",)
    # FR-12: type-registry flavor.
    type_registry_flavor: str = "c_struct"
    # FR-4: extra prompt context for the developer worker.
    prompt_notes: tuple[str, ...] = ()
    # Demangling: attempt Itanium demangling of recovered names?
    demangle: bool = False


_C_ADAPTER = Adapter(
    source_lang="c",
    ghidra_analyzer_options=("Decompiler Parameter ID",),
    fingerprint_corpora=("libc",),
    type_registry_flavor="c_struct",
    prompt_notes=(
        "Input built from C sources: all calls are direct (no vtables); "
        "names are plain (no mangling).",
    ),
)

_CPP_ADAPTER = Adapter(
    source_lang="cpp",
    ghidra_analyzer_options=(
        "Decompiler Parameter ID",
        # C++-specific recovery (no-ops on C inputs; see FR-1).
        "RecoverClassesFromRTTI",
        "Reference",  # vtable reference resolution
    ),
    fingerprint_corpora=("libc", "stl", "boost", "fmt"),
    type_registry_flavor="cxx_class",
    prompt_notes=(
        "Input built from C++ sources: recovered names may be Itanium-mangled "
        "(_ZN...); demangle before prompting. Virtual calls dispatch through "
        "vtables — an indirect edge in the call graph is a candidate vtable "
        "slot, not necessarily an LLM target.",
    ),
    demangle=True,
)


def adapter_for(verdict: str) -> Adapter:
    """The Adapter for a detect_lang verdict. Unknown verdicts are a hard
    error — the caller should have validated (load_call_graph does)."""
    if verdict == "c":
        return _C_ADAPTER
    if verdict in ("cpp", "lean_cpp"):
        return _CPP_ADAPTER
    raise ValueError(f"unknown source-language verdict {verdict!r}")
