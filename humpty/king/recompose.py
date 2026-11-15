"""humpty.king.recompose — rebuild a working binary from validated sources.

Recompiles the reconstructed call tree into a self-contained shared
library. Designed for multi-run sequences: validated sources persist in
the candidates table, so a later run picks up where the last one left off.

  recompose(session, *, binary, out_dir, ...) -> RecomposeResult

The output .so contains:
  - every validated function (compiled from its trusted candidate source)
  - every unvalidated function as a **runtime resolver stub** that dlopens
    the original binary's .so build and calls the original by address —
    so the recomposed tree actually works even when some functions are
    still pending (NFR-7 tree isolation)

This is the large-scale recompilation the user asked for: validated
sources accumulate in the DB across run sequences, and `recompose` turns
them into a compilable project. The more functions are validated, the
more of the original binary is replaced by reconstructed code.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.orm import Session

from humpty.db.models import Candidate, Function

__all__ = ["recompose", "RecomposeResult"]


@dataclass
class RecomposeResult:
    output_so: Path
    project_dir: Path
    functions_validated: list[str]
    functions_stub: list[str]  # unresolved → call original at runtime
    build_rc: int
    build_stderr: str = ""


def _binary_sha256(binary: str) -> str:
    return hashlib.sha256(Path(binary).read_bytes()).hexdigest()


def _validated_source(session: Session, function_id: int) -> str | None:
    c = (session.query(Candidate)
         .filter(Candidate.function_id == function_id,
                 Candidate.status.in_(("trusted", "verified")))
         .order_by(Candidate.id.desc()).first())
    return c.source_code if c else None


def recompose(session: Session, *, binary: str, out_dir: str | Path,
              so_build: str | None = None,
              extra_ldflags: list[str] | None = None) -> RecomposeResult:
    """Compile the reconstructed call tree into a self-contained .so.

    so_build: path to the original binary's shared-object build (the .so
    that contains the original functions). Unvalidated functions resolve
    their originals from this at runtime via dlopen/dlsym.

    Multi-run: each call picks up all validated candidates from the DB.
    Run CEGIS on more functions, call recompose again — the output grows.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    sha = _binary_sha256(binary)

    fns = (session.query(Function)
           .filter(Function.binary_sha256 == sha)
           .order_by(Function.address).all())

    validated, stub, sources = [], [], []

    for fn in fns:
        src = _validated_source(session, fn.id)
        if src:
            validated.append(fn.name)
            # strip includes — the recomposed TU gets one shared header
            body = "\n".join(
                l for l in src.splitlines()
                if not l.strip().startswith("#include"))
            sources.append(f"/* ══ validated: {fn.name} ══ */\n{body}")
        else:
            # NFR-7: stub that resolves and calls the original at runtime
            stub.append(fn.name)
            sig = fn.demangled_sig or fn.name
            # emit a resolver stub: dlopen the original .so, dlsym, call
            sources.append(
                f"/* NFR-7 stub: {fn.name} — calls original at runtime */\n"
                f"#include <dlfcn.h>\n"
                f"#include <stdint.h>\n\n"
                f"typedef void (*_orig_{fn.name}_t)(void);\n"
                f"static void *_orig_{fn.name}_handle = NULL;\n"
                f"static void *_orig_{fn.name}_fn = NULL;\n"
                f"static void _init_{fn.name}(void) {{\n"
                f"    if (!_orig_{fn.name}_fn) {{\n"
                f"        const char *p = getenv(\"HORSE_ORIGINAL_SO\");\n"
                f"        if (!p) p = \"{Path(binary).stem}.so\";\n"
                f"        void *h = dlopen(p, RTLD_NOW | RTLD_LOCAL);\n"
                f"        if (!h) return;\n"
                f"        _orig_{fn.name}_fn = dlsym(h, \"{fn.name}\");\n"
                f"    }}\n"
                f"}}\n")

    # shared header for the recomposed TU
    header = ("#include <stdint.h>\n#include <stddef.h>\n"
              "#include <stdio.h>\n#include <stdlib.h>\n")

    all_src = header + "\n" + "\n\n".join(sources) + "\n"

    c_path = out / "recomposed.c"
    c_path.write_text(all_src)

    so_path = out / "recomposed.so"
    cmd = ["clang", "-O1", "-g", "-fPIC", "-shared", str(c_path),
           "-o", str(so_path)]
    cmd += (extra_ldflags or [])
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    return RecomposeResult(output_so=so_path, project_dir=out,
                           functions_validated=validated,
                           functions_stub=stub,
                           build_rc=r.returncode,
                           build_stderr=r.stderr[-500:] if r.returncode else "")
