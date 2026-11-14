# Architecture

bindumpty is a pipeline of small, testable stages coordinated by a
database. Nothing coordinates in memory: the DB is the single source of
truth, and the append-only `events` table doubles as the message bus.

## The big picture

```mermaid
flowchart LR
    subgraph Analysis
        ING["Ingestion<br/>(FR-1, 3 backends)"] --> DB[("Database<br/>single source of truth")]
        RR["Record-replay<br/>(FR-3, traces)"] --> DB
        FP["Fingerprinting<br/>(FR-2)"] --> DB
    end
    subgraph Orchestration
        DB --> K["King<br/>(scheduler FR-14)"]
        K --> Q["Job queue<br/>(SKIP LOCKED)"]
        Q --> W1["dev worker<br/>(FR-4)"]
        Q --> W2["fixer worker<br/>(FR-5)"]
        Q --> W3["fuzzer worker<br/>(FR-6)"]
    end
    W1 --> DB
    W2 --> DB
    W3 --> DB
    DB --> EV["Event bus<br/>(FR-17)"]
    EV --> K
```

## The CEGIS loop

The core cycle, per function, driven by the 8-state machine
(`humpty.domain.State`):

```mermaid
stateDiagram-v2
    [*] --> pending : ingested
    pending --> ready : all callees trusted
    pending --> trusted : fingerprint match (FR-2)
    ready --> fuzzing : candidate built (FR-4)
    fuzzing --> divergent : counterexample found
    fuzzing --> trusted : budget clean
    divergent --> repairing : CE persisted (FR-15)
    repairing --> failed : K exhausted (NFR-7)
    repairing --> fuzzing : fix passes replay gate
    trusted --> divergent : parent-attributable regression (FR-13)
    trusted --> proven : equivalence established (FR-11)
```

Key invariant: every transition is written to `events` in the same
transaction as the state change, so a rollback removes the event too — the
bus can never describe a state that did not commit.

## The three validation layers

| Layer | Mechanism | Guarantees | Module |
|---|---|---|---|
| Differential fuzzing | libFuzzer persistent mode, original vs candidate on every input | finds *branch-visible* divergences; ~128k exec/s | `horses/src/m1_harness.c` |
| Trace replay | recorded ground-truth I/O (FR-3) replayed through the candidate | catches branch-free wrongness the fuzzer cannot see | `horses/src/harness_driver.py` |
| Equivalence proof | both sources to LLVM IR; bounded induction over the fold (FR-11) | *proven*, not merely non-refuted | `humpty/analyze/prove.py` |

The M1 lesson that shaped this design: a `hash ^= 0x00` seed bug survived
**8 million** fuzzer executions because it changes no control flow. Fuzzing
alone proves nothing; the three layers together are the oracle
(see `horses/src/NOTES_m1.md`).

## Source-language adaptation

The pipeline detects whether the binary was built from C or C++ (two tiers:
an ELF pre-filter plus Ghidra as the authority) and adapts: RTTI/vtable
recovery, the C++ fingerprint corpus, class-layout registry, demangling.
The *validation* machinery is deliberately language-agnostic — see
`humpty/analyze/detect_lang.py` and `humpty/analyze/adapt.py`.

## Multi-backend ingestion

Three interchangeable backends emit the same `fuz.call-graph/1` contract:
Ghidra headless (the authority for language detection), objdump (always
available), rizin (static binary, pinned). `compare_backends` cross-checks
two graphs against each other — an edge disagreement is a cheap pre-LLM
signal. See `analysis/exporters/`.
