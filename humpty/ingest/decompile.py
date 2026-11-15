"""humpty.ingest.decompile — on-demand Ghidra decompilation (D2.2 + P1).

Runs DecompileFunction.java inside the persistent Ghidra project
(D1.1, ~/bindumpty-ghidra/<sha16>) and returns {name: C pseudo-code}.
Used by the synthesis loop (P1): when a function reaches `ready` and
its functions.decompiled_code is still NULL, the loop triggers one of
these and persists the result.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_GHIDRA = ROOT / "analysis/ghidra/dist/ghidra_12.2_PUBLIC"
_JAVA_HOME = "/usr/lib/jvm/java-25-openjdk-amd64"


def decompile_on_demand(binary: str, function_name: str | None = None,
                        timeout_s: int = 1200) -> dict[str, str]:
    """Decompile one function (or all when `function_name` is None) of a
    binary through the persistent Ghidra project.

    Returns {name: decompiled_c}. Raises RuntimeError on headless failure.
    Import-on-first-use: the first call for a binary pays the one-time
    ~10 min analysis; later calls reuse the project (~seconds).
    """
    from humpty.ingest import binary_sha256

    sha = binary_sha256(binary)
    cache_root = os.path.expanduser(f"~/bindumpty-ghidra/{sha[:16]}")
    os.makedirs(cache_root, exist_ok=True)
    # 'already imported' = a program .db exists in the repo (see cli.py)
    idata = os.path.join(cache_root, "main.rep", "idata")
    already = any(f.endswith(".db") and not f.startswith("~")
                  for _, _, files in os.walk(idata) for f in files) \
        if os.path.isdir(idata) else False

    cmd = [str(_GHIDRA / "support/analyzeHeadless"), cache_root, "main"]
    if already:
        cmd += ["-process", Path(binary).name]
    else:
        cmd += ["-import", binary, "-overwrite"]
    out = f"/tmp/bindumpty_decompile_{sha[:12]}.json"
    cmd += ["-scriptPath", str(ROOT / "analysis/ghidra/scripts"),
            "-postScript", "DecompileFunction.java", out]
    if function_name:
        cmd.append(function_name)

    env = dict(os.environ, JAVA_HOME=_JAVA_HOME)
    r = subprocess.run(cmd, capture_output=True, text=True,
                       timeout=timeout_s, env=env, cwd=str(ROOT))
    if r.returncode != 0:
        raise RuntimeError(
            f"decompile headless failed rc={r.returncode}:\n"
            + "\n".join((r.stdout + r.stderr).splitlines()[-15:]))
    if not os.path.exists(out):
        raise RuntimeError(f"decompile produced no output at {out}")
    return json.loads(Path(out).read_text())


def _file_cache(binary: str, function_name: str):
    """Persistent decompile cache: run DBs are throwaway
    (/tmp/bindumpty-run-*/run.db), so decompiled bodies are also cached
    on disk keyed by (binary sha, function name). The first run pays
    the 10-min Ghidra import; every later run is a file read."""
    from humpty.ingest import binary_sha256
    sha = binary_sha256(binary)
    d = os.path.expanduser(f"~/.cache/bindumpty/decompiled/{sha[:16]}")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, f"{function_name}.c")


def ensure_decompiled(session, fn, binary: str, log=print) -> str | None:
    """Return fn.decompiled_code, decompiling + persisting on first need.

    Lookup order: session row → file cache → Ghidra on demand. P1
    helper; the caller's transaction owns the commit.
    """
    if fn.decompiled_code:
        return fn.decompiled_code
    cache = _file_cache(binary, fn.name)
    if os.path.exists(cache):
        code = open(cache).read()
        fn.decompiled_code = code
        log(f"  {fn.name}: decompiled_code from file cache ({len(code)} bytes)")
        return code
    try:
        doc = decompile_on_demand(binary, fn.name)
    except (RuntimeError, json.JSONDecodeError) as e:
        log(f"  {fn.name}: on-demand decompilation failed: {e}")
        return None
    code = doc.get(fn.name)
    if not code:
        log(f"  {fn.name}: decompiler returned no code")
        return None
    fn.decompiled_code = code
    with open(cache, "w") as f:
        f.write(code)
    log(f"  {fn.name}: decompiled on demand ({len(code)} bytes, persisted)")
    return code
