# analysis/

Static-analysis side (WHITEPAPERS.md §7): headless Ghidra scripts and the library
fingerprinting corpus.

## Subdirectories

- `ghidra/` — headless Ghidra scripts (Python via PyGhidra):
  - `export_call_graph.py` (M0, FR-1): JSON nodes (address, size, demangled sig,
    RTTI presence) + edges (direct/indirect/virtual), topological order, SCCs.
    Virtual calls resolved via vtables / RecoverClassesFromRTTI.
  - decompilation + type extraction export for the developer prompt.
  - Note: inlining means the binary's call tree is not the source's call tree —
    the exporter reports unresolved indirect calls, completed later from dynamic
    traces (FR-3).
- `fingerprint/` (M2, FR-2): Function ID / BinDiff / Diaphora matching against
  `corpus/`. A match maps to the real function and marks it trusted without LLM
  or fuzzing.
- `corpus/` — known libraries compiled in the sandbox with common options
  (STL, Boost, zlib, fmt, libc) for signature matching.
