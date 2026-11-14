# analysis/exporters — call-graph export backends

Every backend emits the same neutral `fuz.call-graph/1` JSON (the ingest
contract; see `humpty/ingest`). Downstream never sees analyzer specifics, so
backends are interchangeable and cross-checkable.

| backend | module | runs via | notes |
| --- | --- | --- | --- |
| `objdump` | `objdump_export.py` | `objdump -d` (always available) | no demangle/RTTI; call targets + optional name_map; PLT edges dropped (FR-2 resolves them) |
| `ghidra` | runs `analysis/ghidra/scripts/ExportCallGraph.java` headless | JDK 25, pinned 12.2 | authority for `source_lang`; default analysis misses register-passed `main` in stripped PIEs (FR-3 completes) |
| `rizin` | (probed — see ROADMAP decision register) | rizin binary | pending availability on this host |

## Contract

```python
from analysis.exporters import export_with, compare_backends
res = export_with("objdump", "bin.elf", "out.json")   # writes fuz.call-graph/1
diff = compare_backends(res_a, res_b)                  # edge disagreement report
```

`binary.backend` in the JSON header records the producer; `load_call_graph`
validates and carries it on the Graph so the king can schedule cross-backend
checks — two analyzers disagreeing on an edge is a cheap pre-LLM signal.
