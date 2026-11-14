# Reference: `fuz.call-graph/1`

The call-graph JSON contract every ingestion backend emits and
`humpty.ingest.load_call_graph` consumes. Reference instance:
`toys/case-01-leaf/ground_truth/call_graph.json`.

## Envelope

```json
{
  "format": "fuz.call-graph/1",
  "binary": {
    "sha256": "<64-hex — the binary's NFR-2 identity>",
    "arch": "x86-64",
    "kind": "elf",
    "is_pie": true,
    "is_stripped": true,
    "source_lang": "c",
    "backend": "ghidra"
  },
  "functions": [ ... ],
  "edges": [ ... ],
  "topological_order": ["fnv1a", "digit_sum_u32", "checksum_block", "main"],
  "sccs": []
}
```

| Field | Required | Notes |
|---|---|---|
| `binary.sha256` | yes | must equal the sha256 of the binary passed to `load_call_graph` |
| `binary.source_lang` | no | `c` / `cpp` / `lean_cpp`; omitted or `unknown` → the ELF pre-filter decides |
| `binary.backend` | no | non-empty string recording the producer; carried on the Graph |
| `functions[].name` | yes | unique per binary |
| `functions[].address` | yes | `"0x..."` — must match the real binary (a regression test enforces it) |
| `functions[].size` | yes | bytes |
| `functions[].demangled_sig` | no | used in prompts and reports |
| `edges[].kind` | no | `direct` (default) / `indirect` / `virtual` |
| `topological_order` | no | recomputed by the loader anyway (SCC-condensed) |

## Rules the loader enforces

- unknown `format`, bad `source_lang` verdict, empty `backend` → `CallGraphError`
- unknown edge endpoints, self-loops, duplicate edges → error / dedup
- function addresses are cross-checked against the binary by a regression
  test (a 0x20 layout shift was a real bug once — see
  `test_ground_truth_addresses_match_binary`)

## Producing it

```python
from analysis.exporters import export_with
export_with("ghidra", "binary", "out.json")   # authority for source_lang
export_with("objdump", "binary", "out.json")  # always available
export_with("rizin", "binary", "out.json")    # pinned static binary
```

See `analysis/exporters/README.md` for backend notes and
`analysis.exporters.compare_backends` for the cross-check.
