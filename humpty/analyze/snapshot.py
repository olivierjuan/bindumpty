"""humpty.analyze.snapshot — P3a: Frida memory-snapshot capture (FR-3/FR-9).

Captures what a *real* call to a target function sees and produces, so
the CEGIS oracle can diff memory state instead of only scalar returns:

- attach to the running solver process (e.g. lpex2 solving an .mps),
- Interceptor at the target function entry: dump the argument registers
  (System V AMD64: rdi rsi rdx rcx r8 r9) plus every writable page they
  transitively reference within N hops (heap structs, arrays),
- Interceptor at return: dump the same set + rax,
- write snapshot_in.bin / snapshot_out.bin (framing below) for the
  harness replay driver (P3b).

Snapshot file format (fuz.snapshot/1), little-endian:
  magic "FUSNAP01" | u32 n_regs | regs... (name\0 + u64 value)
  u32 n_pages | each page: u64 start_addr, u32 size, bytes[size]

The dump is the ORACLE's ground truth — the replay driver seeds a
scratch buffer with the IN pages, runs the function, and asserts the
OUT page deltas match. Divergences become CEGIS counterexamples with
concrete expected/observed memory.
"""
from __future__ import annotations

import os
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["SnapshotCapture", "capture_snapshot", "load_snapshot"]

_SNAP_MAGIC = b"FUSNAP01"
_ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

_FRIDA_HOOK_JS = r"""
// P3a: snapshot hook — args + reachable pages at entry, pages + rax at
// return. Config via RPC: which function offset to hook, how many pages.
const TARGET_OFFSET = %(offset)d;   // module-relative function offset
const MAX_PAGES = %(max_pages)d;
const PAGE = 4096;

const mod = Process.getModuleByName("%(module)s");
const target = mod.base.add(TARGET_OFFSET);

function pageStartOf(v) {
    // frida 17: NativePointer.and was removed; mask the low 12 bits via
    // the hex string (last 3 hex digits = 4096-granularity offset)
    const hex = v.toString().replace(/^0x/, "");
    return ptr("0x" + hex.slice(0, Math.max(hex.length - 3, 0)) + "000");
}

function sendPages(ctx, phase) {
    // pages directly referenced by the argument registers (1 hop; deep
    // walks of pointer graphs happen in the replay driver, not here).
    // Binary travels in send()'s `data` channel, addr in the JSON.
    let sent = 0;
    for (const name of ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]) {
        const v = ctx[name];
        if (v === undefined || v === null || v.isNull()) continue;
        try {
            const start = pageStartOf(v);
            const bytes = start.readByteArray(PAGE);
            send({ type: "page", phase: phase, addr: start.toString() },
                 bytes);
            if (++sent >= MAX_PAGES) break;
        } catch (e) { /* unreadable — skip */ }
    }
}

function dumpRegs(ctx) {
    return {
        rdi: ctx.rdi.toString(), rsi: ctx.rsi.toString(),
        rdx: ctx.rdx.toString(), rcx: ctx.rcx.toString(),
        r8: ctx.r8.toString(), r9: ctx.r9.toString(),
        rax: ctx.rax.toString(),
        rsp: ctx.rsp.toString(),
    };
}

let inBlob = null;

Interceptor.attach(target, {
    onEnter: function (args) {
        this.regs = dumpRegs(this.context);
        sendPages(this.context, "in");
        // regs-only snapshot now; pages arrive as separate 'page' messages
        send({ type: "snapshot", regs: this.regs });
    },
    onLeave: function (retval) {
        sendPages(this.context, "out");
        send({ type: "snapshot", regs: dumpRegs(this.context),
               phase: "out" });
    }
});
"""


@dataclass
class SnapshotCapture:
    target_function: str
    target_offset: int
    in_regs: dict = field(default_factory=dict)
    in_pages: dict = field(default_factory=dict)   # addr(hex str) -> bytes
    out_regs: dict = field(default_factory=dict)
    out_pages: dict = field(default_factory=dict)

    def serialize_in(self) -> bytes:
        return _serialize(self.in_regs, self.in_pages)

    def serialize_out(self) -> bytes:
        return _serialize(self.out_regs, self.out_pages)


def _serialize(regs: dict, pages: dict) -> bytes:
    out = bytearray(_SNAP_MAGIC)
    out += struct.pack("<I", len(regs))
    for name, val in regs.items():
        out += name.encode() + b"\x00" + struct.pack("<Q", int(val, 16) & (2**64 - 1))
    out += struct.pack("<I", len(pages))
    for addr, data in pages.items():
        # pages arrive base64-encoded from the hook (send() nulls binary)
        if isinstance(data, str):
            import base64
            b = base64.b64decode(data)
        else:
            b = bytes(data or b"")
        out += struct.pack("<Q", int(addr, 16)) + struct.pack("<I", len(b)) + b
    return bytes(out)


def load_snapshot(path: str | Path) -> tuple[dict, dict]:
    """Read a snapshot file -> (regs, pages)."""
    data = Path(path).read_bytes()
    assert data[:8] == _SNAP_MAGIC, "bad snapshot magic"
    off = 8
    (nregs,) = struct.unpack_from("<I", data, off)
    off += 4
    regs = {}
    for _ in range(nregs):
        end = data.index(b"\x00", off)
        name = data[off:end].decode()
        (val,) = struct.unpack_from("<Q", data, end + 1)
        regs[name] = val
        off = end + 9
    (npages,) = struct.unpack_from("<I", data, off)
    off += 4
    pages = {}
    for _ in range(npages):
        (addr,) = struct.unpack_from("<Q", data, off)
        (size,) = struct.unpack_from("<I", data, off + 8)
        pages[f"{addr:x}"] = data[off + 12: off + 12 + size]
        off += 12 + size
    return regs, pages


def capture_snapshot(binary: str, function_name: str, function_offset: int,
                     runner_cmd: list[str], timeout_s: int = 600,
                     max_pages: int = 32, out_dir: str | None = None,
                     disable_aslr: bool = True) -> SnapshotCapture:
    """Run `runner_cmd` under Frida, snapshot `function_name` (at
    `function_offset` in its module) on entry+return during the run.

    `runner_cmd` is the argv that starts the real workload (e.g.
    ['./lpex2', 'model.mps']) — the snapshot is only meaningful when the
    function runs in an authentic solve. disable_aslr uses frida's
    spawn-time personality (NOT a setarch wrapper: frida does not
    instrument exec chains, only the spawned image).
    """
    import frida

    module = Path(binary).name
    js = _FRIDA_HOOK_JS % {"offset": function_offset, "module": module,
                           "max_pages": max_pages}

    cap = SnapshotCapture(target_function=function_name,
                          target_offset=function_offset)
    got = {"in_regs": None, "out_regs": None}

    def on_message(message, data):
        if message.get("type") != "send":
            return
        payload = message.get("payload", {})
        kind = payload.get("type") if isinstance(payload, dict) else None
        if kind == "page":
            # binary page in `data`; addr in the JSON
            if data is not None:
                store = (cap.in_pages if payload.get("phase") == "in"
                         else cap.out_pages)
                addr = payload["addr"]
                if addr not in store:  # first writer wins (before-state)
                    store[addr] = bytes(data)
        elif kind == "snapshot":
            if payload.get("phase") == "out":
                got["out_regs"] = payload.get("regs", {})
            else:
                got["in_regs"] = payload.get("regs", {})

    # spawn under frida so the hook is installed before any code runs
    argv = list(runner_cmd)
    if disable_aslr:
        pid = frida.spawn(argv, aslr="disable")
    else:
        pid = frida.spawn(argv)
    session = frida.attach(pid)
    script = session.create_script(js)
    script.on("message", on_message)
    script.load()
    frida.resume(pid)
    deadline = time.monotonic() + timeout_s
    try:
        while got["in_regs"] is None and time.monotonic() < deadline:
            time.sleep(0.2)
    finally:
        try:
            session.detach()
        except Exception:
            pass
        try:
            frida.kill(pid)
        except Exception:
            pass

    if got["in_regs"] is None:
        raise RuntimeError(f"no snapshot captured for {function_name} "
                           f"within {timeout_s}s")
    cap.in_regs = got["in_regs"]
    cap.out_regs = got["out_regs"] or {}

    if out_dir:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "snapshot_in.bin").write_bytes(cap.serialize_in())
        (out / "snapshot_out.bin").write_bytes(cap.serialize_out())
    return cap
