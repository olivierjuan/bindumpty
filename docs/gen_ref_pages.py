"""Generate the API reference pages for mkdocstrings.

Follows the mkdocstrings recipes pattern: one page per module under
humpty.*, rendered by reference/api.md's literate-nav.
"""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
PKG = ROOT / "humpty"


def _modules(base: pathlib.Path, prefix: str) -> list[str]:
    out = []
    skip_parts = {"alembic"}
    for p in sorted(base.rglob("*.py")):
        if "__pycache__" in p.parts or "alembic" in p.parts:
            continue
        if p.name in ("__init__.py", "worker_main.py") and "king" in p.parts:
            continue
        if p.name == "__init__.py" and p.parent != base:
            continue
        rel = p.relative_to(base).with_suffix("")
        parts = [x for x in rel.parts if x != "__init__"]
        if not parts:
            parts = ["__init__"]
        out.append(prefix + "." + ".".join(parts))
    return sorted(set(out))


def generate() -> None:
    ref = ROOT / "docs" / "reference" / "api"
    ref.mkdir(parents=True, exist_ok=True)
    modules = _modules(PKG, "humpty")

    for mod in modules:
        (ref / (mod + ".md")).write_text("# " + mod + "\n\n::: " + mod + "\n")

    # literate-nav index (used by reference/api.md)
    nav = "\n".join(f"- [{m.rsplit('.', 1)[-1]}]({m}.md)" for m in modules)
    (ref / "SUMMARY.md").write_text(nav + "\n")
    print(f"generated {len(modules)} API pages")


import sys  # noqa: E402

if __name__ == "__main__":
    generate()
