"""humpty.king.shell — the interactive operator shell.

A rich-powered REPL over the loaded binary:

    bindumpty shell <binary>
      symbols [PATTERN]        list symbols (optionally filtered)
      tree NAME [DEPTH]        render the call subtree from a symbol/address
      select NAME ...          set the reconstruction roots (repeatable)
      show                     show current selection + settings
      set horses N | men N | fuzz N | max-iter K | backend NAME | depth N
      llm                      check the LLM endpoint status
      run [--yes]              start the CEGIS subtree run (needs a reachable LLM)
      quit / Ctrl-D            leave

State is per-shell (loaded symbols, selection, settings); each `run` gets a
fresh DB in a temp dir unless --db was given at launch.
"""
from __future__ import annotations

import argparse
import os
import shlex
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "horses", "src"))
sys.path.insert(0, os.path.join(ROOT, "horses", "spikes"))

__all__ = ["Shell", "main"]


class Shell:
    def __init__(self, binary: str, backend: str = "objdump",
                 horses: int = 1, men: int = 1, fuzz_budget: int = 15,
                 max_iter: int = 5, depth: int = 2, db: str | None = None,
                 provider: str | None = None, model: str | None = None,
                 api_base: str | None = None):
        from rich.console import Console

        self.binary = binary
        self.backend = backend
        self.horses = horses
        self.men = men
        self.fuzz_budget = fuzz_budget
        self.max_iter = max_iter
        self.depth = depth
        self.db = db
        self.console = Console()
        self.symbols: dict = {}
        self.roots: list[str] = []
        self.provider = provider
        self.model = model
        self.api_base = api_base

    # -- helpers -------------------------------------------------------------

    def _load(self) -> None:
        from humpty.analyze.symtree import load_symbols

        with self.console.status("[blue]loading symbols..."):
            self.symbols = load_symbols(self.binary)
        self.console.print(f"[blue]{len(self.symbols)} symbols loaded[/blue]")

    def _llm_status(self) -> str:
        try:
            from humpty.men.providers import resolve_provider
            spec = resolve_provider(self.provider, self.model, self.api_base)
        except Exception as e:
            return f"[red]{e}[/red]"
        key = os.environ.get(spec.api_key_env) if spec.api_key_env else "present"
        key_part = f"key {'OK' if key else 'MISSING: ' + spec.api_key_env}"
        return f"[green]{spec.provider}/{spec.model}[/green] ({key_part})"

    def _tree_for(self, name: str, depth: int | None = None):
        from humpty.analyze.symtree import Symbol, subtree

        if name not in self.symbols:
            raise KeyError(name)
        if self.symbols[name].size == 0 and name.startswith("fn_"):
            # ensure the anchor survives subtree()'s by_name lookup
            self.symbols.setdefault(name, Symbol(name=name,
                                                 vaddr=int(name[3:], 16) if name.startswith("fn_") else 0,
                                                 size=0))
        return subtree(self.binary, name, depth=depth or self.depth,
                       symbols=self.symbols)

    def _render_tree(self, name: str, depth: int | None = None) -> None:
        from rich.tree import Tree

        tree = self._tree_for(name, depth)
        children: dict[str, list[str]] = {}
        for a, b in tree.edges:
            children.setdefault(a, []).append(b)

        def add(node: str, rich_node) -> None:
            for ch in children.get(node, []):
                style = "cyan" if ch in children else "green"
                add(ch, rich_node.add(f"[{style}]{ch}[/{style}]"))

        rt = Tree(f"[bold yellow]{name}[/bold yellow]  "
                  f"[dim]({len(tree.nodes)} nodes, {len(tree.edges)} edges, "
                  f"depth {tree.depth_reached})[/dim]")
        add(name, rt)
        self.console.print(rt)

    # -- commands ------------------------------------------------------------

    def cmd_symbols(self, args: list[str]) -> None:
        pattern = args[0] if args else ""
        names = sorted(n for n in self.symbols
                       if pattern.lower() in n.lower())
        if not names:
            self.console.print("[yellow]no match[/yellow]")
            return
        from rich.columns import Columns
        self.console.print(Columns(names[:200], title=f"{len(names)} match(es)"
                                   + (" (first 200)" if len(names) > 200 else "")))

    def cmd_tree(self, args: list[str]) -> None:
        if not args:
            self.console.print("[red]usage: tree NAME|ADDR [DEPTH][/red]")
            return
        name = args[0]
        depth = int(args[1]) if len(args) > 1 else None
        # accept raw hex addresses on stripped binaries: anchor fn_<vaddr>
        if name not in self.symbols:
            try:
                addr = int(name[3:] if name.startswith("fn_") else name, 16)
            except ValueError:
                self.console.print(f"[red]symbol {name!r} not found[/red]")
                return
            from humpty.analyze.symtree import Symbol
            pseudo = f"fn_{addr:x}"
            self.symbols[pseudo] = Symbol(name=pseudo, vaddr=addr, size=0)
            name = pseudo
        try:
            self._render_tree(name, depth)
        except KeyError:
            self.console.print(f"[red]symbol {name!r} not found[/red]")

    def cmd_select(self, args: list[str]) -> None:
        if not args:
            self.console.print("[red]usage: select NAME|ADDR ...[/red]")
            return
        for a in args:
            if a not in self.symbols:
                try:
                    addr = int(a, 16)
                except ValueError:
                    self.console.print(f"[red]{a!r} not found[/red]")
                    return
                from humpty.analyze.symtree import Symbol
                pseudo = f"fn_{addr:x}"
                self.symbols[pseudo] = Symbol(name=pseudo, vaddr=addr, size=0)
                self.symbols[pseudo] = self.symbols[pseudo]
        self.roots = args
        self.console.print(f"[green]roots: {self.roots}[/green]")

    def cmd_show(self, args: list[str]) -> None:
        from rich.panel import Panel
        self.console.print(Panel(
            f"[b]binary[/b]  {self.binary}\n"
            f"[b]backend[/b] {self.backend}  [b]depth[/b] {self.depth}\n"
            f"[b]horses[/b]  {self.horses}   [b]men[/b] {self.men}\n"
            f"[b]budgets[/b] fuzz {self.fuzz_budget}s  K={self.max_iter}\n"
            f"[b]llm[/b]     {self._llm_status()}\n"
            f"[b]roots[/b]   {self.roots or '(none selected)'}",
            title="settings", border_style="blue"))

    def cmd_set(self, args: list[str]) -> None:
        if len(args) != 2:
            self.console.print("[red]usage: set KEY VALUE[/red]\n"
                               "keys: horses men fuzz max-iter backend depth")
            return
        key, val = args
        try:
            if key == "horses":
                self.horses = int(val)
            elif key == "men":
                self.men = int(val)
            elif key == "fuzz":
                self.fuzz_budget = int(val)
            elif key == "max-iter":
                self.max_iter = int(val)
            elif key == "depth":
                self.depth = int(val)
            elif key == "backend":
                if val not in ("objdump", "ghidra", "rizin"):
                    raise ValueError
                self.backend = val
            else:
                self.console.print(f"[red]unknown key {key!r}[/red]")
                return
            self.console.print(f"[green]{key} = {val}[/green]")
        except ValueError:
            self.console.print(f"[red]bad value for {key}: {val!r}[/red]")

    def cmd_llm(self, args: list[str]) -> None:
        self.console.print(self._llm_status())

    def cmd_provider(self, args: list[str]) -> None:
        """provider [NAME] [MODEL] — switch or inspect the LLM provider."""
        if not args:
            self.console.print(self._llm_status())
            return
        self.provider = args[0]
        self.model = args[1] if len(args) > 1 else None
        try:
            from humpty.men.providers import resolve_provider
            spec = resolve_provider(self.provider, self.model, self.api_base)
            self.console.print(f"[green]provider: {spec.provider}/"
                               f"{spec.model}[/green]")
        except Exception as e:
            self.console.print(f"[red]{e}[/red]")

    def cmd_run(self, args: list[str]) -> None:
        if not self.roots:
            self.console.print("[red]no roots selected — use: select NAME[/red]")
            return
        try:
            from humpty.men.providers import resolve_provider, make_develop
            spec = resolve_provider(self.provider, self.model, self.api_base)
            if spec.api_key_env and not os.environ.get(spec.api_key_env):
                self.console.print(f"[red]provider {spec.provider} needs "
                                   f"{spec.api_key_env}[/red]")
                return
            develop = make_develop(spec)
        except Exception as e:
            self.console.print(f"[red]{e}[/red]")
            return

        from alembic import command
        from alembic.config import Config
        from sqlalchemy import create_engine
        from humpty.db import make_session_factory
        from humpty.db.session import session_scope
        from humpty.ingest import binary_sha256, load_call_graph
        from humpty.king.run import run_subtree

        db_path = self.db or os.path.join(
            tempfile.mkdtemp(prefix="bindumpty-run-"), "run.db")
        eng = create_engine(f"sqlite:///{db_path}",
                            connect_args={"timeout": 30,
                                          "check_same_thread": False})
        ini = Config(os.path.join(ROOT, "alembic.ini"))
        ini.set_main_option("script_location",
                            os.path.join(ROOT, "humpty/db/alembic"))
        ini.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
        command.upgrade(ini, "head")
        factory = make_session_factory(eng)

        from humpty.ingest import binary_sha256 as _sha
        sha = _sha(self.binary)
        with session_scope(factory) as s:
            load_call_graph(s, json_path=self._graph_path(), binary=self.binary)

        with session_scope(factory) as s:
            rep = run_subtree(s, binary_sha256=sha, develop=develop,
                              max_iter=self.max_iter,
                              fuzz_budget_s=self.fuzz_budget)
        from rich.tree import Tree
        vt = Tree("[bold]run verdict[/bold]")
        for name, v in rep.verdicts.items():
            st = v.state
            color = {"trusted": "green", "proven": "bold green",
                     "failed": "red"}.get(st, "white")
            vt.add(f"{name}: [{color}]{st}[/{color}] conf={v.confidence:.2f}")
        self.console.print(vt)
        self.console.print(f"[b]verified[/b]: {rep.verified_frac:.0%}  "
                           f"[dim]db: {db_path}[/dim]")

    def _graph_path(self) -> str:
        from analysis.exporters import export_with
        out = os.path.join(tempfile.mkdtemp(prefix="bindumpty-cg-"), "cg.json")
        export_with(self.backend, self.binary, out)
        return out

    def cmd_quit(self, args: list[str]) -> None:
        raise SystemExit(0)

    # -- REPL ----------------------------------------------------------------

    COMMANDS = {
        "symbols": "list symbols (optional substring filter)",
        "tree": "tree NAME [DEPTH] — render a call subtree",
        "select": "select NAME ... — set reconstruction roots",
        "show": "show current settings and selection",
        "set": "set horses/men/fuzz/max-iter/backend/depth",
        "llm": "check the LLM endpoint",
        "provider": "provider [NAME] [MODEL] — switch the LLM provider",
        "run": "start the CEGIS run on the selected roots",
        "help": "this help",
        "quit": "leave the shell",
    }

    def repl(self) -> int:
        from rich.panel import Panel

        if not self.symbols:
            self._load()
        self.console.print(Panel(
            f"[b]binary[/b] {self.binary}\n"
            + "\n".join(f"[b]{k}[/b] — {d}" for k, d in self.COMMANDS.items()),
            title="bindumpty shell — type a command, `help` for the list",
            border_style="blue"))
        while True:
            try:
                line = self.console.input("[bold yellow]bindumpty>[/bold yellow] ")
            except (KeyboardInterrupt, EOFError):
                self.console.print("\n[dim]bye[/dim]")
                return 0
            parts = shlex.split(line.strip())
            if not parts:
                continue
            cmd, args = parts[0].lower(), parts[1:]
            fn = getattr(self, f"cmd_{cmd}", None)
            if cmd in ("quit", "exit"):
                return self.cmd_quit(args)
            if fn is None:
                self.console.print(f"[red]unknown command {cmd!r} — "
                                   f"type `help`[/red]")
                continue
            try:
                fn(args)
            except Exception as e:  # noqa: BLE001 — a REPL must survive
                self.console.print(f"[red]{type(e).__name__}: {e}[/red]")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="bindumpty shell")
    ap.add_argument("binary")
    ap.add_argument("--backend", default="objdump",
                    choices=["objdump", "ghidra", "rizin"])
    ap.add_argument("--horses", type=int, default=1)
    ap.add_argument("--men", type=int, default=1)
    ap.add_argument("--fuzz-budget", type=int, default=15)
    ap.add_argument("--max-iter", type=int, default=5)
    ap.add_argument("--depth", type=int, default=2)
    ap.add_argument("--db")
    ap.add_argument("--provider")
    ap.add_argument("--model")
    ap.add_argument("--api-base")
    args = ap.parse_args(argv)

    if not os.path.exists(args.binary):
        print(f"binary not found: {args.binary}", file=sys.stderr)
        return 2

    shell = Shell(binary=args.binary, backend=args.backend,
                  horses=args.horses, men=args.men,
                  fuzz_budget=args.fuzz_budget, max_iter=args.max_iter,
                  depth=args.depth, db=args.db, provider=args.provider,
                  model=args.model, api_base=args.api_base)
    return shell.repl()


if __name__ == "__main__":
    sys.exit(main())
