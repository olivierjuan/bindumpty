"""humpty.analyze.dynamorio — DynamoRIO record/replay wrapper (RFC v1.0 §8).

Record mode launches the target under `drrun` with the dr_bindumpty
client:

    drrun -c libdr_bindumpty.so --target_offset 0x8aba20 \\
          --record_structs 1 --record_vtables 1 \\
          --out_dir <project>/runs/dr-<ts> -- ./lpex2 model.mps

and ingests the artifacts:
  a) snapshot_*.snap          -> fuz.snapshot/2 byte-level in/out sets
                                 (feeds the differential replay oracle)
  b) structs.json             -> field profiles -> generated struct
                                 headers into --types-dir (P-D5 pipeline)
  c) indirect_edges.json      -> fuz.call-graph-delta/1 -> call_edges table

Requires: DynamoRIO release tree on disk (DYNAMORIO_HOME or
dr_install()) and libdr_bindumpty.so built from analysis/dynamorio/.
"""
from __future__ import annotations

import json
import os
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["DrResult", "dr_home", "client_path", "dr_record",
           "load_snapshots", "load_indirect_edges", "load_structs",
           "ingest_indirect_edges", "structs_to_header"]

SNAP_MAGIC = b"DRSNAP02"


def dr_home() -> Path:
    """DynamoRIO installation root ($DYNAMORIO_HOME or the /tmp layout).

    Handles both layouts: a source build (build/bin64/drrun) and the
    release tarball (bin64/drrun)."""
    def has_drrun(root: Path) -> bool:
        return ((root / "build" / "bin64" / "drrun").exists()
                or (root / "bin64" / "drrun").exists())

    env = os.environ.get("DYNAMORIO_HOME")
    if env and has_drrun(Path(env).expanduser()):
        return Path(env).expanduser()
    for cand in sorted(Path("/tmp").glob("DynamoRIO-Linux-*")):
        if has_drrun(cand):
            return cand
    raise RuntimeError(
        "DynamoRIO not found: set DYNAMORIO_HOME or extract the release "
        "tarball to /tmp/DynamoRIO-Linux-*")


def client_path(edges: bool = False) -> Path:
    """Built client .so. edges=True returns the edge-pass client
    (libdr_edges.so — raw BB event, no drwrap: see dr_edges.cpp)."""
    here = Path(__file__).resolve().parents[2]
    name = "libdr_edges.so" if edges else "libdr_bindumpty.so"
    for cand in (here / "analysis/dynamorio/build" / name,
                 here / "analysis/dynamorio" / name):
        if cand.exists():
            return cand
    raise RuntimeError(
        f"{name} not built: cmake -DDynamoRIO_DIR="
        f"{dr_home()}/cmake -S analysis/dynamorio "
        "-B analysis/dynamorio/build && cmake --build "
        "analysis/dynamorio/build")


@dataclass
class DrResult:
    out_dir: Path
    snapshots: list
    exit_code: int
    duration_s: float
    stderr_tail: str = ""


def dr_record(binary: str, target_offset: int, argv: list[str],
              out_dir: str | Path | None = None,
              record_structs: bool = True, record_vtables: bool = True,
              timeout_s: float = 1800.0) -> DrResult:
    """Record the target under DynamoRIO.

    DR 11.91 constraint (validated by bisection): drwrap's function
    wrapping and clean calls on indirect calls are mutually exclusive —
    combining them hangs the process. When BOTH artifacts are requested
    the target runs TWICE:
      pass 1 (snapshot): libdr_bindumpty.so wraps the target and captures
        fuz.snapshot/2 files;
      pass 2 (edges):    libdr_edges.so (raw BB event, no drwrap) records
        fuz.call-graph-delta/1 indirect edges.
    """
    _home = dr_home()
    drrun = (_home / "build" / "bin64" / "drrun"
             if (_home / "build" / "bin64" / "drrun").exists()
             else _home / "bin64" / "drrun")
    if out_dir is None:
        from humpty.project import new_run_dir
        out_dir = new_run_dir("dr")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    t0 = time.monotonic()
    # pass 1: snapshot tracer (wrap) — only when edges-only mode is off
    snaps: list[str] = []
    exit_code = 0
    stderr_tail = ""
    if not record_vtables or record_structs:
        cmd = [str(drrun), "-c", str(client_path(edges=False)),
               f"--target_offset={target_offset:#x}",
               f"--record_structs={'1' if record_structs else '0'}",
               f"--record_vtables=0",
               f"--out_dir={out_dir}",
               "--", binary, *argv]
        r1 = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=timeout_s)
        exit_code = r1.returncode
        stderr_tail = (r1.stderr or "")[-800:]
        snaps = sorted(str(p) for p in out_dir.glob("snapshot_*.snap"))

    # pass 2: indirect-edge pass (separate client, no drwrap)
    if record_vtables:
        cmd = [str(drrun), "-c", str(client_path(edges=True)),
               f"--out_dir={out_dir}",
               "--", binary, *argv]
        r2 = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=timeout_s)
        exit_code = r2.returncode
        stderr_tail = (r2.stderr or "")[-800:]

    dur = time.monotonic() - t0
    return DrResult(out_dir=out_dir, snapshots=snaps,
                    exit_code=exit_code, duration_s=dur,
                    stderr_tail=stderr_tail)


def load_snapshots(paths: list[str]) -> list[dict]:
    """Parse fuz.snapshot/2 files (RFC §6.1) into dicts."""
    out = []
    for p in paths:
        data = Path(p).read_bytes()
        if data[:8] != SNAP_MAGIC:
            raise ValueError(f"{p}: bad snapshot magic")
        off = 8
        (target_vaddr, tid, inv, initial_rax, return_rax) = \
            struct.unpack_from("<QIIQQ", data, off)
        off += 8 + 4 + 4 + 8 + 8
        regs = struct.unpack_from("<8Q", data, off)
        off += 64
        n_read = struct.unpack_from("<I", data, off)[0]
        off += 4
        reads = {}
        for _ in range(n_read):
            (start,) = struct.unpack_from("<Q", data, off)
            (ln,) = struct.unpack_from("<I", data, off + 8)
            off += 12
            reads[f"{start:x}"] = data[off:off + ln]
            off += ln
        n_write = struct.unpack_from("<I", data, off)[0]
        off += 4
        writes = {}
        for _ in range(n_write):
            (start,) = struct.unpack_from("<Q", data, off)
            (ln,) = struct.unpack_from("<I", data, off + 8)
            off += 12
            pre = data[off:off + ln]
            off += ln
            (n2,) = struct.unpack_from("<I", data, off)
            off += 4
            post = data[off:off + n2]
            off += n2
            writes[f"{start:x}"] = {"pre": pre, "post": post, "len": ln}
        out.append({
            "file": p, "target_vaddr": target_vaddr, "thread": tid,
            "invocation": inv, "initial_rax": initial_rax,
            "return_rax": return_rax,
            "regs": [f"{r:#x}" for r in regs],
            "reads": reads, "writes": writes,
        })
    return out


def load_indirect_edges(path: str | Path) -> list[dict]:
    """Parse fuz.call-graph-delta/1 (RFC §6.3)."""
    doc = json.loads(Path(path).read_text())
    if doc.get("format") != "fuz.call-graph-delta/1":
        raise ValueError(f"{path}: unexpected format {doc.get('format')!r}")
    return doc.get("edges", [])


def load_structs(path: str | Path) -> list[dict]:
    return json.loads(Path(path).read_text())


def structs_to_header(structs: list[dict], out_path: str | Path) -> Path:
    """Emit a C header from struct profiles (RFC §8 step 3b) for the
    --types-dir pipeline: LLM-visible struct definitions with concrete
    offsets and inferred types."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = ["/* GENERATED by humpty.analyze.dynamorio — dynamic struct",
             " * layout profiles (do not edit by hand). */"]
    for st in structs:
        name = st.get("struct_name", "STRUCT")
        lines.append(f"typedef struct {{  /* total_size={st.get('total_size')} */")
        for fld in st.get("fields", []):
            t = fld.get("inferred_type", "uint8_t")
            off = fld.get("offset", "0x0")
            hint = fld.get("semantic_hint", "")
            comment = f"  /* {hint} */" if hint else ""
            if t.endswith("*"):
                lines.append(f"    {t} field_{off};{comment}")
            else:
                lines.append(f"    {t} field_{off};{comment}")
        lines.append(f"}} {name};")
    out.write_text("\n".join(lines) + "\n")
    return out


def ingest_indirect_edges(session, *, binary_sha256: str,
                          edges: list[dict], log=print) -> int:
    """RFC §8 step 3a: enrich the call_edges table with dynamically
    resolved indirect edges (kind 'indirect_resolved'). Edge endpoints
    that have no Function row yet are created as fn_<offset> stubs.
    Caller commits. Returns the number of edges written."""
    from humpty.db.models import CallEdge, Function

    created = 0
    by_offset: dict[int, int] = {}

    def fn_for_offset(off: int) -> Function | None:
        if off in by_offset:
            return by_offset[off]
        row = (session.query(Function)
               .filter(Function.binary_sha256 == binary_sha256,
                       Function.address == off).one_or_none())
        if row is None:
            row = Function(binary_sha256=binary_sha256, name=f"fn_{off:x}",
                           address=off, size=0)
            session.add(row)
            session.flush()
        by_offset[off] = row
        return row

    for e in edges:
        caller_off = int(e.get("caller_offset", "0"), 0)
        callee_off = int(e.get("callee_offset", "0"), 0)
        caller = fn_for_offset(caller_off)
        callee = fn_for_offset(callee_off)
        if caller is None or callee is None:
            continue
        dup = (session.query(CallEdge)
               .filter(CallEdge.caller_id == caller.id,
                       CallEdge.callee_id == callee.id,
                       CallEdge.kind == "indirect_resolved")
               .one_or_none())
        if dup is None:
            session.add(CallEdge(caller_id=caller.id, callee_id=callee.id,
                                 kind="indirect_resolved"))
            created += 1
    if created:
        log(f"DR: added {created} indirect_resolved edges")
    return created


def snapshots_to_replay_pages(snap: dict) -> tuple[dict, dict]:
    """Convert a parsed DRSNAP02 snapshot into (in_pages, out_pages) for
    snapshot_replay's driver: the read set (arg-pointed pages, pre-image)
    plus the write set (pre + final bytes). Keys are hex addresses."""
    in_pages: dict[str, bytes] = {}
    out_pages: dict[str, bytes] = {}
    for addr, data in snap.get("reads", {}).items():
        in_pages[addr] = data
    for addr, w in snap.get("writes", {}).items():
        # the driver maps out pages and diffs post vs recorded: the page
        # must start with the PRE-image and end matching the POST image —
        # for v0 the pre-image is the replay seed and the diff target is
        # the recorded final bytes
        in_pages.setdefault(addr, w["pre"])
        out_pages[addr] = w["post"]
    return in_pages, out_pages
