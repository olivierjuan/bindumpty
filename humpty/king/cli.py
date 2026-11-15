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
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "horses", "src"))
sys.path.insert(0, os.path.join(ROOT, "horses", "spikes"))

from analysis.exporters import export_with  # noqa: E402  (needs ROOT on sys.path first)

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
                    help="use the live LLM developer; default refuses rather "
                         "than fake a reconstruction")
    ap.add_argument("--provider", help="claude | litellm | gemini | "
                 "openrouter | codex | modal | ollama | vllm")
    ap.add_argument("--model", help="model id for the provider")
    ap.add_argument("--api-base", help="OpenAI-compatible base URL "
                 "(for modal/vllm/self-hosted endpoints)")
    ap.add_argument("--exclude", action="append", default=[],
                    help="regex: stop call-tree traversal at matching "
                         "symbols (e.g. --exclude 'mkl_.*' --exclude 'CPX.*')")
    ap.add_argument("--types-dir", default=None,
                    help="directory containing reconstructed type headers "
                         "(D5.1 — passed as -I to harness/candidate compilation "
                         "and injected into developer prompts)")
    ap.add_argument("--force-export", action="store_true",
                    help="re-run the export backend even if a cached graph exists")
    ap.add_argument("--cache-dir", default=None,
                    help="cache directory for exported call graphs "
                         "(default: <binary_dir>/.bindumpty_cache)")
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
    return True  # the provider layer handles keys per provider


def _provider_spec(args):
    from humpty.men.providers import ProviderError, resolve_provider
    try:
        return resolve_provider(args.provider, args.model, args.api_base)
    except ProviderError as e:
        raise SystemExit(str(e))


def _llm_status() -> str:
    """Honest status: resolved provider/model + key presence. Reachability
    is only proven by the run itself (a 5s probe proved nothing but cost 5s)."""
    try:
        from humpty.men.providers import resolve_provider
        spec = resolve_provider(_prov_args.get("provider"),
                                _prov_args.get("model"),
                                _prov_args.get("api_base"))
    except Exception as e:
        return f"[red]{e}[/red]"
    key = os.environ.get(spec.api_key_env) if spec.api_key_env else "present"
    key_ok = ("key OK" if key
              else f"[red]missing key {spec.api_key_env}[/red]")
    return f"[green]{spec.provider}/{spec.model}[/green] ({key_ok})"


_prov_args: dict = {}


def main(argv: list[str] | None = None) -> int:
    from rich.console import Console

    from rich.tree import Tree  # verdict rendering

    console = Console()
    args = build_arg_parser().parse_args(argv)
    _prov_args.update(provider=args.provider, model=args.model,
                      api_base=args.api_base)

    if not Path(args.binary).exists():
        console.print(f"[red]binary not found: {args.binary}[/red]")
        return 2

    from humpty.analyze.symtree import load_symbols, subtree

    with console.status("[blue]loading symbols..."):
        symbols = load_symbols(args.binary)
    console.print(f"[blue]{len(symbols)} defined symbols loaded[/blue]")

    # depth is honored as given: BFS terminates at the real call-graph
    # height (seen-set prevents cycles), so a large depth is harmless — it
    # means "walk to the leaves". No clamp.
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
                                  symbols=symbols, exclude=args.exclude)
        except KeyError as e:
            console.print(f"[red]{e}[/red]")
            return 2

    console.print(_summary_panel(next(iter(trees.values())), args.backend, args))
    for root, tree in trees.items():
        console.print(f"[bold]call tree from [yellow]{root}[/yellow][/bold]")
        _render_tree(tree, console)

    if args.list:
        return 0

    try:
        spec = _provider_spec(args)
    except SystemExit as e:
        console.print(f"[red]{e}[/red]")
        return 2
    if args.llm and spec.api_key_env:
        key = os.environ.get(spec.api_key_env)
        if not key:
            console.print(f"[red]provider {spec.provider} needs "
                          f"{spec.api_key_env} in the environment[/red]")
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

    from humpty.king.todotree import TodoTree

    groups = [
        ("I", "export call graph",
         ["backend run", "post-script", "graph written"]),
        ("II", "ingest into DB", ["functions", "edges"]),
        ("III", "CEGIS run", [f"validate {t.root}" for t in trees.values()]),
    ]
    tt = TodoTree(console, groups)

    export_ticks = []

    def _export_progress(done, total):
        # objdump/rizin chunked mode: real per-symbol progress
        export_ticks.append((done, total))

    from humpty.king.steps import step as step_ctx
    with tt:
        tt.start_phase("I", "backend run")
        tt.message(f"exporting call graph via {args.backend} from {Path(args.binary).name}")
        with step_ctx(console, f"export call graph ({args.backend})") as st:
            import subprocess as _sp

            # D1.2: check cache first — if a cached call graph exists for
            # this binary+backend+exclude, skip the backend entirely.
            cg_path = _cache_path_for(args)
            cache_hit = _cache_hit(args) is not None and not args.force_export
            if cache_hit:
                tt.message(f"[cache] reusing exported call graph: {cg_path}")
            if not cache_hit and args.backend != "ghidra":
                # small backends run here; ghidra runs below via the
                # D1.1 persistent-project branch (writes to cg_path too)
                export_with(args.backend, args.binary, cg_path,
                            progress=_export_progress)
            if not cache_hit and args.backend == "ghidra":
                # D1.1: persistent Ghidra project keyed by binary sha256.
                # If the project exists, skip -import (analysis already
                # done, startup drops from ~11 min to ~3 s).
                from humpty.ingest import binary_sha256 as _sha
                bin_sha = _sha(args.binary)
                # Ghidra 12.2 rejects project paths whose elements start
                # with '.', so the persistent store cannot live under
                # ~/.cache — use ~/bindumpty-ghidra/<sha16> instead.
                cache_root = os.path.expanduser(
                    f"~/bindumpty-ghidra/{bin_sha[:16]}")
                os.makedirs(cache_root, exist_ok=True)
                proj_name = "main"
                already_imported = os.path.isdir(
                    os.path.join(cache_root, f"{proj_name}.rep"))
                ghidra = os.path.join(
                    ROOT, "analysis/ghidra/dist/ghidra_12.2_PUBLIC")
                env = dict(os.environ,
                           JAVA_HOME="/usr/lib/jvm/java-25-openjdk-amd64")
                cmd_prefix = [os.path.join(ghidra, "support/analyzeHeadless"),
                              cache_root, proj_name]
                if not already_imported:
                    cmd_prefix += ["-import", args.binary, "-overwrite"]
                else:
                    # Reopening an existing project: attach to the imported
                    # program (named after the binary file) or currentProgram
                    # is null and every script NPEs.
                    cmd_prefix += ["-process", Path(args.binary).name]
                # D1.3: subtree-scoped export — pass root symbol + depth
                # as script args [2] and [3]
                script_args = [cg_path]
                roots = args.symbol or []
                if roots:
                    script_args.append(roots[0])
                    script_args.append(str(args.depth))
                proc = _sp.Popen(
                    cmd_prefix
                    + ["-scriptPath",
                       os.path.join(ROOT, "analysis/ghidra/scripts"),
                       "-postScript", "ExportCallGraph.java"] + script_args,
                    stdout=_sp.PIPE, stderr=_sp.STDOUT, text=True,
                    env=env, cwd=ROOT)
                out_lines: list[str] = []
                for line in proc.stdout:
                    out_lines.append(line)
                    tt.feed_ghidra(line)
                proc.wait()
                if proc.returncode != 0:
                    raise RuntimeError(
                        "ghidra export failed rc="
                        f"{proc.returncode}:\n"
                        + "".join(out_lines[-15:]))
            tt.finish_phase("I", "backend run")
            if export_ticks:
                tt.message(f"backend progress: {export_ticks[-1][0]}/"
                           f"{export_ticks[-1][1]} symbols disassembled")
            tt.finish_phase("I", "post-script")
            tt.finish_phase("I", "graph written")

            tt.finish_phase("II", "functions")
            tt.finish_phase("II", "edges")

        tt.start_phase("II", "functions")
        tt.message(f"ingesting {cg_path} into {db_path}")
        with step_ctx(console, "ingest into DB") as st:
            from rich.progress import (BarColumn, Progress, TaskProgressColumn,
                                       TextColumn, TimeElapsedColumn)
            with Progress(TextColumn("    {task.description}"),
                          BarColumn(), TaskProgressColumn(),
                          TimeElapsedColumn(), console=console,
                          transient=True) as prog:
                tasks = {}

                def on_progress(stage, done, total):
                    key = f"{stage} ({total} rows)"
                    if key not in tasks:
                        tasks[key] = prog.add_task(key, total=total)
                    prog.update(tasks[key], completed=done)

                with session_scope(factory) as s:
                    load_call_graph(s, json_path=cg_path, binary=args.binary,
                                    progress=on_progress)

    from humpty.men.providers import make_develop
    develop = make_develop(spec)

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


def _cache_key(args) -> str:
    """Cache key: binary sha256 + backend + exclude patterns."""
    from humpty.ingest import binary_sha256
    sha = binary_sha256(args.binary)
    excl = ",".join(sorted(args.exclude)) if args.exclude else ""
    return hashlib.sha256(f"{sha}:{args.backend}:{excl}".encode()).hexdigest()[:20]


def _cache_dir_for(args) -> str:
    if args.cache_dir:
        return args.cache_dir
    return os.path.join(os.path.dirname(os.path.abspath(args.binary)),
                        ".bindumpty_cache")


def _cache_path_for(args) -> str:
    """Cache path for this binary+backend+exclude. No I/O beyond mkdir."""
    cache_dir = _cache_dir_for(args)
    os.makedirs(cache_dir, exist_ok=True)
    key = _cache_key(args)
    return os.path.join(cache_dir, f"cg_{key}.json")


def _cache_hit(args) -> str | None:
    """Return the cached graph path when valid for the current binary."""
    cached = _cache_path_for(args)
    if not os.path.exists(cached):
        return None
    try:
        doc = json.load(open(cached))
        from humpty.ingest import binary_sha256
        if doc.get("binary", {}).get("sha256") == binary_sha256(args.binary):
            return cached
    except (json.JSONDecodeError, KeyError):
        pass  # corrupt cache — re-export
    return None


def _graph_for(args, trees, progress=None) -> str:
    """Produce (or reuse a cached) fuz.call-graph/1 file.

    Cache key: binary sha256 + backend + exclude patterns. On a hit, the
    exported graph is reused — no re-analysis of the same binary with the
    same settings. On a miss, the backend runs HERE (small backends:
    objdump/rizin); ghidra is handled by the caller's D1.1 persistent-
    project branch, which writes to this same cache path.
    """
    cached = _cache_hit(args)
    if cached:
        return cached
    out = _cache_path_for(args)
    export_with(args.backend, args.binary, out, progress=progress)
    return out


if __name__ == "__main__":
    sys.exit(main())
