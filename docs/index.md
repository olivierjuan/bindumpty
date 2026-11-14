# bindumpty

[![tests](https://github.com/olivierjuan/bindumpty/actions/workflows/tests.yml/badge.svg)](https://github.com/olivierjuan/bindumpty/actions/workflows/tests.yml)
[![milestone exits](https://github.com/olivierjuan/bindumpty/actions/workflows/exits.yml/badge.svg)](https://github.com/olivierjuan/bindumpty/actions/workflows/exits.yml)
[![docs](https://github.com/olivierjuan/bindumpty/actions/workflows/docs.yml/badge.svg)](https://github.com/olivierjuan/bindumpty/actions/workflows/docs.yml)

Reconstruct readable, behaviorally equivalent **C** source from a stripped,
non-obfuscated x86-64 binary, one function at a time, bottom-up from the
call-tree leaves.

Three pillars:

1. **LLM as program synthesizer** — developer and fixer workers propose and
   repair reimplementations (FR-4, FR-5).
2. **Differential fuzzer as equivalence oracle** — searches for inputs on
   which original and candidate diverge (FR-6..9).
3. **Database-backed orchestrator** — parallelizes the CEGIS loop across
   functions; the DB is the single source of truth and the append-only event
   table doubles as the message bus (FR-14, FR-17).

A function is *trusted* when no divergence is found within budget and all
callees are trusted; *proven* only via equivalence checking (FR-11).

## Status

All four milestones implemented and their exit criteria executed:

| Milestone | Exit script | Verdict |
|---|---|---|
| M1 — CEGIS loop on one leaf | `humpty/king/m1_exit.py` | all 24 traces pass, 2M-exec fuzz clean |
| M2 — climbing the tree | `humpty/king/m2_exit.py` | hook-mode hybrid, 15.6M runs clean |
| M3 — orchestration | queue/bus/pools live-verified | 8 workers × 200 jobs, zero dupes/lost |
| M4 — strong validation | `humpty/king/m4_exit.py` | 65,537-check proof + resurrection |
| Global acceptance | `humpty/king/acceptance.py` | recomposed binary passes the original suite 16/16 |

## Quick start

```bash
./toys/case-01-leaf/build.sh
.venv/bin/python humpty/king/m1_exit.py     # watch a leaf get validated
```

See **[Getting started](getting_started.md)** for the full walkthrough.
