"""humpty.project — the bindumpty project directory.

One directory holds everything a reconstruction run produces, so a
target's whole lifecycle is inspectable, movable, and cleanable:

    <project>/                       default ./bindumpty-project,
                                     override with HUMPTY_PROJECT_DIR
    ├── cache/
    │   ├── callgraph/               exported fuz.call-graph/1 files
    │   └── llm/                     LLM response cache (responses.json)
    ├── ghidra/<sha16>/              persistent Ghidra projects (D1.1)
    ├── decompiled/<sha16>/<name>.c  decompile file cache (P1)
    ├── runs/<ts>-<label>/           per-run state DBs + artifacts
    ├── src/                         horse_candidate.c (live candidate)
    ├── build/                       harness + candidate .so builds
    └── results/                     verdicts, system_validation.json

Everything resolves through the functions below — no component hardcodes
a dot-directory or a $HOME path anymore. Legacy locations are migrated
on first resolve (one-time move, original removed).
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

__all__ = ["project_dir", "set_project_dir", "cache_dir", "llm_cache_dir",
           "callgraph_cache_dir", "ghidra_dir", "decompiled_dir",
           "runs_dir", "new_run_dir", "src_dir", "build_dir", "results_dir",
           "migrate_legacy"]


def project_dir() -> Path:
    """The project root: $HUMPTY_PROJECT_DIR or ./bindumpty-project."""
    env = os.environ.get("HUMPTY_PROJECT_DIR")
    p = Path(env).expanduser() if env else Path("bindumpty-project")
    return p.resolve()


def set_project_dir(p: str | Path) -> Path:
    """Pin the project root for this process (and persist the env for
    child processes the run spawns)."""
    p = Path(p).expanduser().resolve()
    os.environ["HUMPTY_PROJECT_DIR"] = str(p)
    return p


def _sub(*parts: str) -> Path:
    d = project_dir().joinpath(*parts)
    d.mkdir(parents=True, exist_ok=True)
    return d


def cache_dir() -> Path:
    return _sub("cache")


def callgraph_cache_dir() -> Path:
    return _sub("cache", "callgraph")


def llm_cache_dir() -> Path:
    return _sub("cache", "llm")


def ghidra_dir() -> Path:
    return _sub("ghidra")


def decompiled_dir() -> Path:
    return _sub("decompiled")


def runs_dir() -> Path:
    return _sub("runs")


def new_run_dir(label: str = "run") -> Path:
    """Create and return a fresh run directory (used for the per-run
    state DB and its artifacts)."""
    import time
    d = runs_dir() / f"{time.strftime('%Y%m%d-%H%M%S')}-{label}"
    d.mkdir(parents=True, exist_ok=False)
    return d


def src_dir() -> Path:
    return _sub("src")


def build_dir() -> Path:
    return _sub("build")


def results_dir() -> Path:
    return _sub("results")


# --------------------------------------------------------------------------
# legacy migration — move the pre-project scatter into the project tree
# --------------------------------------------------------------------------

_LEGACY = [
    # (legacy path resolver, destination subdir resolver)
    (lambda: Path(".bindumpty_cache").resolve(), callgraph_cache_dir),
    (lambda: Path(".llm_cache").resolve(), llm_cache_dir),
    (lambda: Path.home() / "bindumpty-ghidra", ghidra_dir),
    (lambda: Path.home() / ".cache" / "bindumpty" / "decompiled",
     decompiled_dir),
]


def migrate_legacy(log=print) -> list[str]:
    """Move legacy stores into the project tree when they exist.

    Idempotent: a legacy path that doesn't exist (or whose destination
    already holds the data) is skipped. Returns what was moved.
    """
    moved = []
    for src_fn, dst_fn in _LEGACY:
        src = src_fn()
        if not src.exists() or not any(src.iterdir()):
            continue
        dst = dst_fn()
        for entry in src.iterdir():
            target = dst / entry.name
            if target.exists():
                continue  # destination wins — never clobber
            shutil.move(str(entry), str(target))
        if not any(src.iterdir()):
            src.rmdir()
            moved.append(str(src))
    if moved:
        log(f"migrated into project {project_dir()}: {', '.join(moved)}")
    return moved
