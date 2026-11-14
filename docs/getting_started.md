# bindumpty — Getting Started

Reconstruct readable, behaviorally equivalent **C** source from a stripped
x86-64 binary, one function at a time, bottom-up from the call-tree leaves.
The loop is CEGIS: an LLM proposes a reimplementation, a differential fuzzer
hunts for inputs where original and candidate disagree, and every
counterexample drives the next repair. A function is *trusted* when a fuzz
budget passes clean and all its callees are trusted; *proven* only via
equivalence checking.

This guide gets you from a clean clone to a validated leaf in ~10 minutes.
Everything below was executed on the commit you are reading (see
[milestones](milestones.md) for what each milestone's exit criterion proves).

---

## 0. Prerequisites

- Linux x86-64, `git`, `python3.12+`, `clang` (19+ tested), `make`
- PostgreSQL 16 **for orchestration at scale** (M3+). A SQLite fallback
  ships in the queue (`BEGIN IMMEDIATE` claims — fine up to ~tens of
  workers), so everything below also runs without any server. A PG
  container is the easiest scale path:

```bash
docker run -d --name humpty-pg -p 55433:5432 \
    -e POSTGRES_PASSWORD=humpty -e POSTGRES_DB=humpty postgres:16
```

- Optional: Ghidra 12.2 + JDK 25 for the headless export backend (the
  objdump backend works without it), and a working LLM endpoint for the
  live developer seam (the deterministic path needs no LLM at all).

## 1. Set up

```bash
git clone <this repo> && cd bindumpty
# the repo pins its deps; create the venv from the lockfile
uv venv && uv pip install -r requirements.txt        # or: pip install -e .
.venv/bin/python -m pytest -q                        # 138 tests, ~35s
```

If `138 passed` you are running the same pipeline the milestone exits ran.

## 2. Build the toy (the validation baseline)

```bash
./toys/case-01-leaf/build.sh        # toy01 (stripped) + toy01.sym + toy01.so
./toys/case-02-mem/build.sh         # void-shaped parent for the memory diff
```

The build script also re-syncs `ground_truth/` (sha256 **and** function
addresses) with the binary — this is NFR-2 and the regression test
`test_ground_truth_addresses_match_binary` enforces it.

## 2b. Or use the operator CLI on any binary

```bash
.venv/bin/python -m humpty.king.cli lpex2 --symbol main --depth 2 --list
```

Loads the symbol table (17,832 symbols on a 34 MB CPLEX example in 0.2 s),
renders the run plan + call tree, and reports the honest LLM status. See
[operator CLI](operator_cli.md).

## 3. Watch the pipeline validate a leaf (2 minutes)

```bash
.venv/bin/python humpty/king/m1_exit.py
```

Expected tail:

```
[2/4] CEGIS loop (develop seam: deterministic; LLM is swappable)
    iter 1: DIVERGENT — len=255 got=0xC9223DDA want=0xF3C92129
    iter 2: TRUSTED (2097152 execs clean)
[3/4] full trace replay through the validated candidate
  all recorded traces pass (0 mismatches)
[4/4] fuzz budget without divergence
  2097152 executions clean in 16.4s
M1 EXIT CRITERION MET: leaf validated end to end, unattended
```

What just happened: ingest → the 8-state DB machine (events per transition)
→ the fuzzer found the seed bug at `len==255` → the counterexample was
persisted → the repair passed the full regression replay → trusted.

## 4. The other milestone runs

```bash
.venv/bin/python humpty/king/m2_exit.py      # FR-7 hook mode: the toy's real
                                             # leaf entries substituted; the
                                             # original parent as oracle
.venv/bin/python humpty/king/m4_exit.py      # FR-11 equivalence proof
                                             # (65,537 checks) + info-gain
                                             # scheduler + resurrection
.venv/bin/python humpty/king/acceptance.py   # the §9 verdict: the whole
                                             # subtree reconstructed, and the
                                             # recomposed binary passes the
                                             # original test suite (16/16)
```

Each script is the milestone's exit criterion, executable, exit 0 on
success. They are also the best documentation of how the pieces compose.

## 5. Your own leaf

Point the pipeline at your own binary by producing its `fuz.call-graph/1`
JSON (one of three backends) and a trace bundle:

```python
# 1. export the call graph (pick a backend)
from analysis.exporters import export_with
res = export_with("objdump", "your_binary", "call_graph.json")   # always works
res = export_with("ghidra", "your_binary", "call_graph.json")    # authority for
res = export_with("rizin", "your_binary", "call_graph.json")     # source_lang

# 2. ingest
from humpty.db import make_session_factory
from humpty.ingest import load_call_graph
from humpty.db.session import session_scope
with session_scope(factory) as s:
    g = load_call_graph(s, json_path="call_graph.json", binary="your_binary")
    print(g.source_lang, g.backend, len(g.functions))
```

The JSON contract (nodes with address/size/sig, edges direct/indirect/
virtual, topological order, SCCs) is documented by the reference instance at
`toys/case-01-leaf/ground_truth/call_graph.json`. `binary.source_lang` is
detected automatically (Ghidra verdict wins; ELF pre-filter fallback) and
drives the C/C++ adaptation — see `humpty/analyze/detect_lang.py`.

Then record traces (FR-3) so the loop has ground truth to replay:

```bash
# the toy's record-replay driver (Frida route, host-independent):
.venv/bin/python -m tracing.record_frida --help    # full usage in --help
```

and run the loop exactly like the M1 exit does — `humpty.king.leaf_loop.
run_leaf_loop(session, function_id=..., develop=..., max_iter=K,
fuzz_budget_s=N)`. The `develop` callable is the only piece you may want to
swap: an LLM (`humpty.men.develop.make_llm_source()`), or your own.

## 6. Orchestration (M3): many functions, parallel

```bash
export HUMPTY_DB_URL=postgresql+psycopg://humpty:humpty@127.0.0.1:55433/humpty
python -m humpty.king.worker_main --kind fuzz  --worker-id w1   # fuzz jobs
python -m humpty.king.worker_main --kind fix   --worker-id w2   # repair jobs
```

Workers are stateless: claim from the SKIP LOCKED queue (`FOR UPDATE ...
SKIP LOCKED`, priority-ordered, attempts-bounded retry), work, complete.
Live-verified: 8 workers × 200 jobs → zero dupes, zero lost. Every state
change writes an append-only event; consumers use
`humpty.king.bus.EventPoller` (cursor persists across restarts) with an
optional PG LISTEN/NOTIFY wake-up thread. The live view:

```python
from humpty.king.metrics import snapshot, render_dashboard
with session_scope(factory) as s:
    print(render_dashboard(snapshot(s)))
```

SLURM: `sbatch --array=1-8 sandbox/slurm/worker_array.sbatch fix`
(NFR-1: the untrusted binary runs in the apptainer sandbox; the worker only
orchestrates).

## 7. Strong validation (M4)

```python
# FR-11: prove a leaf equivalent (bounded induction, 65,537 checks) —
from humpty.analyze.prove import prove_fnv1a
r = prove_fnv1a(candidate_source)   # r.proven, r.checks, r.evidence

# FR-10: cross-fuzz archived candidates against each other BEFORE paying for
# the original oracle — every divergent input becomes a test case:
from humpty.men.llm_oracle import cross_fuzz
rep = cross_fuzz(session, function_id=fid, n_inputs=512)

# FR-14: schedule by expected information gain, not plain topo order:
from humpty.king.scheduler import rank_ready
for rf in rank_ready(session, binary_sha256=sha):
    print(rf.name, rf.gain)

# FR-18 ext: a failed function whose failure reason changed resurrects —
from humpty.king.resurrect import resurrect
resurrect(session, function_id=fid, reason="callee fixed")
```

## 8. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `tests skip: toy artifact missing` | binaries are git-ignored | `./toys/case-01-leaf/build.sh` |
| `dlopen failed: cannot dynamically load position-independent executable` | you passed the PIE exe where a `.so` is expected | the M2 harness wants `build/toy01.so` |
| queue behaves oddly at very high worker counts | SQLite fallback's practical ceiling is ~tens of workers | `HUMPTY_DB_URL=postgresql+psycopg://...` (the SKIP LOCKED scale path) |
| `unsupported java version` from Ghidra | 12.2 requires JDK 25 (21 rejected) | `apt install openjdk-25-jdk-headless`, set `JAVA_HOME_OVERRIDE` in `support/launch.properties` |
| script class not found after editing a Ghidra script | poisoned OSGi bundle | wipe `~/.config/ghidra/ghidra_12.2_PUBLIC/osgi/{compiled-bundles,felixcache}` |
| `undefined symbol` loading the candidate `.so` | the last loop wrote a parent-shaped candidate | rebuild: `horses/src/build_horse.sh`, or let the exit scripts rebuild (they do) |
| proxy caps downloads at ~272 MiB | host forward proxy (Range ignored) | assets under that size work (rizin 131 MB OK); Ghidra needs a direct path |

## 9. What works today — and the honest gaps

Working, verified (every claim backed by a passing test or an exit script):
state machine + confidence, DB schema + migrations, ingestion (3 backends +
language detection C/C++ two-tier), trace bundle replay, differential
harness (~128k exec/s), funchook hybrid hooking, memory diff, fingerprinting,
fixer with anti-hardcode gate, response cache, type registry, graveyard
(Pareto + seeding + crossover + resurrection), PG queue, event bus, worker
pools, dashboard, info-gain scheduler, equivalence proof, and all four
milestone exit scripts + global acceptance.

Known gaps (each with its workaround in place):

1. **Live LLM develop** — the gateway times out here; the seam is fully
   wired (`humpty.men.develop`), runs use a deterministic develop, and the
   response cache makes a recovered gateway cheap.
2. **Ghidra in the loop's ingestion** — the export ran (M0/S1); the exit
   scripts consume ground-truth graphs. objdump/rizin backends work
   standalone for real binaries.
3. **SLURM campaign** — template validated, no daemon on this host.
4. **Alive2/remill on real binaries** — not installable here; the induction
   proof covers hash-shaped leaves with documented scope.
5. **Wide parallel campaigns** — the machinery is live-verified, but the
   toy tree has 4 functions; a 50-function run is untested.
