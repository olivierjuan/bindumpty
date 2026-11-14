"""humpty.king.cli — the operator console.

    bindumpty <binary> [--symbol NAME ...] [--depth N] [--backend NAME]
                       [--horses N] [--men N] [--fuzz-budget N]
                       [--max-iter K] [--llm] [--list] [--yes]

Load an executable or .so, browse/select symbols, configure the run (LLM
seam, worker counts, export backend, budgets) and run the CEGIS subtree with
a live rich-rendered tree of progress.

The run is the general driver (humpty.king.run.run_subtree): fingerprint
matches first (free), leaves through the CEGIS loop, parents handled per the
FR-7 hook-mode path. All state lives in a per-run SQLite DB (no server
needed for a single run; point HUMPTY_DB_URL at PostgreSQL to share one run
across worker processes).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "horses", "src"))
sys.path.insert(0, os.path.join(ROOT, "horses", "spikes"))

__all__ = ["main"]


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="bindumpty",
        description="Reconstruct selected symbols (and their call trees) "
                    "from a stripped or unstripped binary.")
    ap.add_argument("binary", help="the target ELF executable or .so")
    ap.add_argument("--symbol", action="append", default=[],
                    help="root symbol(s) of the subtree (repeatable)")
    ap.add_argument("--depth", type=int, default=2,
                    help="max call-tree depth from each root (default 2)")
    ap.add_argument("--backend", default="objdump",
                    choices=["objdump", "ghidra", "rizin"],
                    help="call-graph export backend (default objdump)")
    ap.add_argument("--horses", type=int, default=1,
                    help="parallel fuzzer workers (default 1)")
    ap.add_argument("--men", type=int, default=1,
                    help="parallel developer/fixer workers (default 1)")
    ap.add_argument("--fuzz-budget", type=int, default=15,
                    help="fuzz seconds per campaign (default 15)")
    ap.add_argument("--max-iter", type=int, default=5,
                    help="CEGIS repair cap K (default 5)")
    ap.add_argument("--llm", action="store_true",
                    help="use the live LLM developer (needs ANTHROPIC_* env); "
                         "default refuses rather than fake a reconstruction")
    ap.add_argument("--list", action="store_true",
                    help="show the symbol tree and exit (no run)")
    ap.add_argument("--yes", action="store_true",
                    help="skip the confirmation prompt")
    ap.add_argument("--db", help="reuse/keep the run DB at this path "
                                 "(default: a temp file)")
    return ap


def _render_tree(tree, console) -> None:
    from rich.tree import Tree

    children: dict[str, list[str]] = {}
    for a, b in tree.edges:
        children.setdefault(a, []).append(b)

    def add(node: str, rich_node) -> None:
        for ch in children.get(node, []):
            style = "cyan" if ch in children else "green"
            add(ch, rich_node.add(f"[{style}]{ch}[/{style}]"))

    root = tree.root
    rt = Tree(f"[bold yellow]{root}[/bold yellow]")
    add(root, rt)
    console.print(rt)


def _summary_panel(tree, backend: str, args):
    from rich.panel import Panel

    leaf_like = {n for n in tree.nodes
                 if n not in {a for a, _ in tree.edges}}
    lines = [
        f"[b]binary[/b]  {Path(args.binary).name}",
        f"[b]backend[/b] {backend}   [b]depth[/b] {args.depth}",
        f"[b]subtree[/b]  {len(tree.nodes)} functions, {len(tree.edges)} edges "
        f"(root: {tree.root}, depth reached {tree.depth_reached})",
        f"[b]horses[/b]   {args.horses} fuzzer worker(s)   "
        f"[b]men[/b]     {args.men} dev/fixer worker(s)",
        f"[b]budgets[/b]  fuzz {args.fuzz_budget}s/campaign, "
        f"K={args.max_iter}",
        f"[b]llm[/b]     {_llm_status()}",
        f"[b]leaf-like[/b] {len(leaf_like)} (these run the CEGIS loop; "
        f"parents route to the FR-7 hook-mode path)",
    ]
    return Panel("\n".join(lines), title="bindumpty run plan", border_style="blue")


def _llm_ready() -> bool:
    return bool(os.environ.get("ANTHROPIC_AUTH_TOKEN")
                and os.environ.get("ANTHROPIC_BASE_URL"))


def _llm_status() -> str:
    if not _llm_ready():
        return "[red]NOT configured — run will refuse[/red]"
    # cheap reachability probe (the S4 gateway has been timing out; config
    # presence is not endpoint health)
    import urllib.request
    base = os.environ["ANTHROPIC_BASE_URL"]
    try:
        with urllib.request.urlopen(f"{base}/v1/messages", timeout=5) as r:
            return "[green]live[/green]"
    except Exception as e:
        return f"[red]configured but unreachable ({type(e).__name__}) — " \
               f"deterministic develop refused too: no source exists[/red]"


def main(argv: list[str] | None = None) -> int:
    from rich.console import Console

    console = Console()
    args = build_arg_parser().parse_args(argv)

    if not Path(args.binary).exists():
        console.print(f"[red]binary not found: {args.binary}[/red]")
        return 2

    from humpty.analyze.symtree import load_symbols, subtree

    with console.status("[blue]loading symbols..."):
        symbols = load_symbols(args.binary)
    console.print(f"[blue]{len(symbols)} defined symbols loaded[/blue]")

    roots = args.symbol or [n for n, s in symbols.items() if n == "main"] or []
    if not roots:
        console.print("[red]no --symbol given and no `main` found. "
                      "Pass --symbol NAME or an address like fn_<vaddr> "
                      "(use --list to browse).[/red]")
        return 2
    # accept raw hex addresses ("0x1290", "1290") as symbol anchors — on a
    # stripped binary, names are the analyser's, not the binary's
    resolved_roots = []
    for r in roots:
        if r in symbols:
            resolved_roots.append(r)
            continue
        try:
            addr = int(r, 16) if not r.startswith("0x") else int(r, 16)
        except ValueError:
            console.print(f"[red]symbol {r!r} not found "
                          f"(use --list to browse)[/red]")
            return 2
        pseudo = f"fn_{addr:x}"
        if pseudo in symbols or True:
            symbols[pseudo] = __import__(
                "humpty.analyze.symtree", fromlist=["Symbol"]).Symbol(
                name=pseudo, vaddr=addr, size=0)
            resolved_roots.append(pseudo)
    roots = resolved_roots

    trees = {}
    for root in roots:
        try:
            trees[root] = subtree(args.binary, root, depth=args.depth,
                                  symbols=symbols)
        except KeyError as e:
            console.print(f"[red]{e}[/red]")
            return 2

    console.print(_summary_panel(next(iter(trees.values())), args.backend, args))
    for root, tree in trees.items():
        console.print(f"[bold]call tree from [yellow]{root}[/yellow][/bold]")
        _render_tree(tree, console)

    if args.list:
        return 0

    if not _llm_ready() or "unreachable" in _llm_status():
        console.print(
            "[red]The developer seam is the synthesizer — a stripped binary has "
            "no source to extract, so bindumpty refuses to fake a "
            "reconstruction.[/red]\n"
            "[yellow]Fix: set ANTHROPIC_BASE_URL/ANTHROPIC_AUTH_TOKEN to a "
            "reachable endpoint (retry/backoff is built in), or use "
            "--list to study the tree and come back.[/yellow]")
        return 2

    if not args.yes:
        console.print("[yellow]Run with these settings? (Ctrl-C to abort, "
                      "--yes to skip)[/yellow]")
        try:
            input()
        except KeyboardInterrupt:
            console.print("[red]aborted[/red]")
            return 1

    # ---- run ----------------------------------------------------------------
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine

    from humpty.db import make_session_factory
    from humpty.db.session import session_scope
    from humpty.ingest import binary_sha256, load_call_graph
    from humpty.king.run import run_subtree

    db_path = args.db or os.path.join(
        tempfile.mkdtemp(prefix="bindumpty-run-"), "run.db")
    eng = create_engine(f"sqlite:///{db_path}",
                        connect_args={"timeout": 30, "check_same_thread": False})
    ini = Config(os.path.join(ROOT, "alembic.ini"))
    ini.set_main_option("script_location", os.path.join(ROOT, "humpty/db/alembic"))
    ini.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    command.upgrade(ini, "head")
    factory = make_session_factory(eng)
    sha = binary_sha256(args.binary)

    with console.status("[blue]ingesting call graph..."):
        with session_scope(factory) as s:
            load_call_graph(s, json_path=_graph_for(args, trees), binary=args.binary)

    from humpty.men.develop import make_llm_source
    develop = make_llm_source()

    live = console
    with session_scope(factory) as s:
        rep = run_subtree(s, binary_sha256=sha, develop=develop,
                          max_iter=args.max_iter,
                          fuzz_budget_s=args.fuzz_budget,
                          log=lambda m: live.print(f"  [dim]{m}[/dim]"))

    # ---- verdict tree -------------------------------------------------------
    verdict_style = {"trusted": "green", "proven": "bold green",
                     "failed": "red", "divergent": "red"}
    vt = Tree("[bold]run verdict[/bold]")
    for name, v in rep.verdicts.items():
        st = v.state
        style = verdict_style.get(st, "white")
        vt.add(f"{name}: [{style}]{st}[/{style}] conf={v.confidence:.2f} "
               f"iters={v.iterations}")
    for n in rep.skipped:
        vt.add(f"{n}: [blue]skipped[/blue] (see log reason)")
    console.print(vt)
    console.print(f"[b]verified[/b]: {rep.verified_frac:.0%}")
    console.print(f"[dim]run DB: {db_path}[/dim]")
    return 0 if not rep.failed else 1


def _graph_for(args, trees) -> str:
    """Produce a fuz.call-graph/1 file covering the selected subtrees via the
    chosen backend."""
    from analysis.exporters import export_with

    out = os.path.join(tempfile.mkdtemp(prefix="bindumpty-cg-"), "cg.json")
    export_with(args.backend, args.binary, out)
    return out


if __name__ == "__main__":
    sys.exit(main())
