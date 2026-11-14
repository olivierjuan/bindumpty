# Operator CLI

The operator console: load an executable or `.so`, select the symbols whose
subtree you want reconstructed, configure the run, and watch it live.

```bash
.venv/bin/python -m humpty.king.cli <binary> --symbol NAME [options]
```

## Options

| Option | Meaning | Default |
|---|---|---|
| `--symbol NAME` | root symbol(s) of the subtree (repeatable) | `main` if present |
| `--depth N` | call-tree depth from each root | 2 |
| `--backend NAME` | call-graph exporter: `ghidra` \| `objdump` \| `rizin` | `objdump` |
| `--horses N` | parallel fuzzer workers | 1 |
| `--men N` | parallel developer/fixer workers | 1 |
| `--fuzz-budget N` | fuzz seconds per campaign | 15 |
| `--max-iter K` | CEGIS repair cap | 5 |
| `--llm` | use the live LLM developer | refuses without a reachable endpoint |
| `--list` | render the plan + tree, then exit | — |
| `--yes` | skip the confirmation prompt | — |
| `--db PATH` | keep the run DB at a known path | temp file |

## What you see

1. A **run-plan panel**: binary, backend, subtree size, worker counts,
   budgets, and the honest LLM status (a 5-second reachability probe —
   configured-but-down is reported as down, not as ready).
2. The **call tree** from each root (rich-rendered, leaf functions green).
3. A confirmation prompt (unless `--yes`).
4. Live progress lines from the CEGIS loop, then a **verdict tree**
   (per-function state, confidence, iterations; skips with reasons).

## Real example — lpex2 (CPLEX LP example, 34 MB, 17,832 symbols)

```bash
.venv/bin/python -m humpty.king.cli lpex2 --symbol main --depth 2 --list
```

renders the plan (`20 functions, 33 edges`) and the tree: `main` calls the
CPX* CPLEX API entry points, each through the binary's PLT thunk. Symbol
selection and the tree took **0.6 s total** — the focused-subtree approach
matters: a whole-binary objdump export of the same file takes 211 s and
still misses `main`.

## How selection works

`humpty.analyze.symtree` reads the symbol table (`nm -S`, 17.8k symbols in
0.2 s), then walks direct call targets by disassembling each function's own
body only (`objdump -d --start/--stop-address`, per function) — a BFS level
costs ~20 ms regardless of binary size. Targets are resolved against the
symbol table; PLT thunks appear as honest nodes (FR-2 fingerprinting
classifies them later).

## What runs, what refuses

- **Leaves** (no callees) run the CEGIS loop: develop → replay gate → fuzz
  → trusted/failed, K-capped.
- **Parents** are routed to the FR-7 hook-mode path. Until the per-binary
  harness generator exists, they are *skipped with an explicit reason* —
  bindumpty never silently validates a parent with the wrong harness.
- **No reachable LLM endpoint → the run refuses.** The developer seam is
  the synthesizer: a stripped binary has no source to extract, and faking a
  reconstruction is worse than refusing. Fix the endpoint, or study the
  tree with `--list` and come back.
