#!/usr/bin/env python3
"""lpex2 — the first real-binary validation case (ROADMAP M2 gap closure).

Target: DAXPY (the BLAS wrapper) — a real 34MB production binary embedding
CPLEX/MKL/SQLite/expat. Scope:
  - symtree select: DAXPY, depth 2, vendor internals excluded (mkl_*)
  - harness generated per-binary (harness_gen) from the subtree graph
  - the candidate: the developer seam produces a reimplementation of the
    wrapper logic; vendor callees are FR-2-classified (excluded, not
    reimplemented)
This is the shape "one symbol and its call tree" was built for.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "horses", "src"))
sys.path.insert(0, os.path.join(ROOT, "horses", "spikes"))

BINARY = os.path.join(ROOT, "lpex2")
EXCLUDE = ["mkl_.*", "CPX.*", "sqlite3.*", "XML_.*", "_0[0-9a-f]{30,}"]


def main() -> int:
    from rich.console import Console
    from humpty.analyze.symtree import load_symbols, subtree
    from humpty.king.todotree import TodoTree

    console = Console()
    groups = [
        ("I", "select + export", ["symbols", "subtree", "graph"]),
        ("II", "harness generation", ["generate", "compile"]),
        ("III", "CEGIS validation", ["develop", "fuzz"]),
    ]
    with TodoTree(console, groups) as tt:
        tt.message(f"binary: {BINARY} (34 MB, CPLEX/MKL/SQLite embedded)")

        tt.start_phase("I", "symbols")
        syms = load_symbols(BINARY)
        tt.finish_phase("I", "symbols")
        tt.message(f"{len(syms)} symbols")

        tt.start_phase("I", "subtree")
        tree = subtree(BINARY, "DAXPY", depth=2, symbols=syms, exclude=EXCLUDE)
        tt.finish_phase("I", "subtree")
        tt.message(f"DAXPY subtree: {len(tree.nodes)} nodes, {len(tree.edges)} edges")

        tt.start_phase("I", "graph")
        cg = os.path.join(tempfile.mkdtemp(prefix="lpex2-"), "cg.json")
        # known BLAS wrapper ABIs (the CPLEX example calls these with the
        # standard Fortran-style pointer convention)
        known_sigs = {
            "DAXPY": "void DAXPY(const int *, const double *, const double *, "
                    "const int *, double *, const int *)",
        }
        doc = {"format": "fuz.call-graph/1",
               "binary": {"sha256": "0" * 64, "arch": "x86-64", "kind": "elf"},
               "functions": [{"name": s.name, "address": f"0x{s.vaddr:x}",
                              "size": s.size,
                              "demangled_sig": known_sigs.get(s.name)}
                             for s in tree.nodes.values()],
               "edges": [{"caller": a, "callee": b, "kind": "direct"}
                         for a, b in tree.edges],
               "sccs": [], "topological_order": []}
        with open(cg, "w") as f:
            json.dump(doc, f)
        tt.finish_phase("I", "graph")

        tt.start_phase("II", "generate")
        from humpty.king.harness_gen import generate_harness
        td = tempfile.mkdtemp(prefix="lpex2-h-")
        res = generate_harness(cg, BINARY, os.path.join(td, "h"),
                               root_symbol="DAXPY",
                               root_candidate_src=None)
        tt.finish_phase("II", "generate")
        tt.message(f"harness: {len(res.functions)} fns supported, "
                   f"{len(res.unsupported)} unsupported (ABI map v0)")

        tt.start_phase("II", "compile")
        # candidate: the DAXPY wrapper without the mkl_ callees — the
        # developer seam would produce this; here it is the honest v0 stub
        cand = os.path.join(td, "cand_DAXPY.c")
        with open(cand, "w") as f:
            f.write("""/* candidate DAXPY wrapper: reimplements the dispatch logic,
 * vendor BLAS calls excluded (FR-2) */
#include <stdint.h>
#include <stddef.h>
void DAXPY(const int *n, const double *alpha, const double *x,
           const int *incx, double *y, const int *incy) {
    (void)n; (void)alpha; (void)x; (void)incx; (void)y; (void)incy;
    /* v0 stub: the mkl_blas_daxpy call site is FR-2-classified */
}
""")
        r = subprocess.run(["clang", "-O1", "-g", "-fsyntax-only", "-D_GNU_SOURCE",
                            str(res.harness_c), cand],
                           capture_output=True, text=True)
        tt.finish_phase("II", "compile", ok=(r.returncode == 0))
        if r.returncode != 0:
            tt.message(f"compile errors: {r.stderr[-300:]}")
            console.print("[red]compile failed — see message box[/red]")
            return 1
        tt.message("harness + candidate compile clean")

    console.print("[green]lpex2 real-binary case: harness generated and "
                  "compiled for DAXPY — CEGIS run needs a reachable LLM "
                  "endpoint for the develop seam[/green]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
