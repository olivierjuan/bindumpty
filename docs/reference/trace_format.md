# Reference: `fuz.traces/1`

The trace bundle: recorded ground-truth I/O for one or more functions of a
binary. It is the cheap oracle (replayed before every fuzz round), the
initial fuzz corpus, and the concrete examples in developer prompts.
Loader: `humpty.trace.load_bundle`. Reference:
`toys/case-01-leaf/ground_truth/traces.jsonl`.

## Format

JSON Lines, one object per call:

```json
{"fn":"fnv1a","arg":"61","arglen":1,"ret":"0xe40c292c"}
{"fn":"fnv1a","arg":"6161","arglen":2,"ret":"0x4c250437"}
{"fn":"digit_sum_u32","arg":"1234","ret":10}
```

| Field | Meaning |
|---|---|
| `fn` | function name — resolved against the ingested call graph |
| `arg` | argument bytes, hex-encoded (`""` = empty input) |
| `arglen` | byte length of the argument |
| `ret` | return value: `"0x<8hex>"` for 32-bit returns, or a bare integer |

## Ingest

```python
from humpty.trace import load_bundle
from humpty.ingest import binary_sha256

sha = binary_sha256("toys/case-01-leaf/build/toy01")
n = load_bundle(session, bundle="traces.jsonl", binary_sha256=sha)
```

A record naming a function that is not in the loaded graph is an error —
the bundle must match the binary.

## Why traces come first in the loop

Fuzzing alone proves nothing: during development, a branch-free seed bug
(`hash ^= 0x00` at `len == 255`) survived **8 million** fuzzer executions.
Traces replay catches that class immediately — the replay gate rejects a
candidate that fails any recorded input before any fuzz budget is spent
(FR-15's regression suite).
