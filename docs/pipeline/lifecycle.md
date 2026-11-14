# Function lifecycle

The 8-state machine every reconstructed function walks. Defined in
`humpty.domain.states`; the transition map is law — the orchestrator raises
on any illegal hop.

## States

| State | Meaning |
|---|---|
| `pending` | ingested, callees not yet trusted |
| `ready` | all callees trusted/proven; a candidate can be developed |
| `fuzzing` | a candidate is under differential fuzzing |
| `divergent` | a counterexample was found and persisted |
| `repairing` | the fixer is producing a corrected candidate |
| `trusted` | fuzz budget clean + all callees trusted |
| `proven` | equivalence established (FR-11); ranks above trusted, absorbing |
| `failed` | K iterations exhausted; the original stands in by address (NFR-7) |

## Confidence is a score, not a boolean (FR-13)

`humpty.domain.confidence` combines evidence channels by the
**weakest-evidence rule**: the function is only as confident as its weakest
exercised channel. A proven function short-circuits to 1.0; a divergence
collapses to 0.

A parent-attributable divergence **demotes** the child: `trusted → divergent`,
confidence 0, and the whole ready set is rebuilt (a full rebuild, not
incremental — poisoned-confidence bugs become structurally impossible). See
`humpty.king.confidence`.

## Counterexamples are permanent (FR-15)

Every divergent input is persisted once (dedup by
`(function_id, input_sha256)`) and replayed before any new fuzz round: a
candidate that still fails a known counterexample is rejected before any
budget is spent. That is the mechanical anti-hardcode gate — the fixer
cannot win by patching the failing case.

## The graveyard (FR-18)

Rejected candidates are archived with a 3-axis score vector
(trace pass rate, negated divergence rate, simplicity), ranked on the Pareto
front. The fixer seeds its next attempt from the best rank-1 entry. When the
reason a function failed goes away (callee fixed, type updated, new traces),
the function *resurrects*: re-queued, seeded from its archive.
