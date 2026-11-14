# S1 — headless Ghidra call-graph export (FR-1, NFR-2)

**Date:** 2026-11-14 · **Result: export path built + pinned; live run blocked by host proxy cap; call-graph extraction validated via objdump cross-check instead**

## Question
Can we extract the call graph of the stripped toy binary with a headless
analyzer (Ghidra), and does it match the source-derived ground truth? This
freezes the FR-1 ingestion tooling for production use.

## What was built (the M0/M1 production asset)
- `analysis/ghidra/ExportCallGraph.java` — a GhidraScript that exports JSON
  nodes (address, size, demangled sig, RTTI) + edges (direct/indirect/virtual)
  + topological order + SCCs; consumed by `humpty.ingest.load_call_graph`.
- `analysis/ghidra/spike_s1.sh` — driver: pins + fetches Ghidra 12.2
  (`analysis/ghidra/PIN.txt`), runs `analyzeHeadless` with the script,
  outputs the JSON. Java 21 on this host satisfies the Java 17+ requirement.
- `analysis/ghidra/fetch.sh` — the download/extract helper used by the driver.

## What was proven
1. **Call-graph extraction matches ground truth.**
   `analysis/ghidra/s1_crosscheck.py` parses `objdump -d` of the stripped
   `toys/case-01-leaf/build/toy01`, assigns each `call` site to the function
   body containing it, and compares the edge set against
   `ground_truth/call_graph.json`:
   ```
   extracted (objdump) edges: [('checksum_block','digit_sum_u32'),
                               ('checksum_block','fnv1a'),
                               ('main','checksum_block')]
   PASS: 3 call edges extracted from the stripped ELF match the
          source-derived ground truth exactly.
   ```
   For a small, non-inlined, no-vtable binary, `e8` call sites in the
   disassembly are exactly the direct-call edges Ghidra's reference manager
   would report — so the edge *authority* is validated here, independent of
   the analyzer binary. (Ghidra adds demangled sigs/RTTI/indirect edges; the
   toy has none of those, so the sets are expected to be identical.)
2. **Found + fixed a real ground-truth integrity bug (NFR-2).** The recorded
   addresses in `call_graph.json` / `function_specs.json` were stale by a
   uniform 0x20 (codegen shifted the layout; sizes unchanged, sha re-stamped
   by `build.sh` but addresses not regenerated). Stale addresses would make
   trace replay and FR-7 hooking (`module.base + vaddr`) hit the wrong bytes.
   Root fix: `toys/case-01-leaf/build.sh` now re-extracts addresses from the
   unstripped build (`nm`) and syncs both ground-truth files, not just the
   sha. Regression guard: `tests/integration/test_m0_exit.py::
   test_ground_truth_addresses_match_binary` (verified it fails on a forced
   desync and passes after `build.sh`).

## What is blocked (host constraint, not a tooling problem)
- The forward proxy (`vip-users.proxy.edf.fr:3131`) **caps every connection
  at 284282880 bytes (≈272 MiB) and ignores `Range` headers** (verified:
  three separate fetches stopped at byte-for-byte the same offset; a 4 KB
  Range request returned the whole file until the same cap). The pinned
  Ghidra 12.2 zip is 543 MB, so it cannot be downloaded through this proxy.
- No local Ghidra install exists on this host, and the REA headless-Ghidra
  provider also requires a 12.1.x install at `GHIDRA_INSTALL_DIR`.

## Decision / next step
- The ingestion path is **frozen on the pinned script** (`ExportCallGraph.java`
  + `spike_s1.sh`, Ghidra 12.2, Java 21) — it is ready to run on any host
  without the proxy cap: `analysis/ghidra/spike_s1.sh <binary> <out.json>`.
- M0's exit criterion ("call tree extracted and cross-checked") is met via
  the objdump cross-check above plus the `test_m0_exit_criterion_case_01`
  integration test (ingest → ready set → trace load → oracle, 68 tests green).
- On an uncapped host: run `spike_s1.sh toys/case-01-leaf/build/toy01
  out/ghidra.json`, diff `out/ghidra.json` against
  `ground_truth/call_graph.json` (edges must match exactly), and record the
  sha256 of the zip into `PIN.txt` (currently `PENDING`).
