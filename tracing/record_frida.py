#!/usr/bin/env python3
"""record_frida.py — M0 record-replay via Frida (FR-3, production path).

Traces the *running* original (the stripped ELF, parked under FUZ_HOLD=1) and
calls each target function directly through a Frida agent, capturing the real
I/O: arguments, return value. (Memory read/written regions are added with FR-9
in M2 when the first non-pure function enters the set.)

The agent uses NativeFunction with explicit x86-64 SysV argument mapping,
resolving each function at module.base + vaddr — the same base+offset
mechanics FR-7 hooking relies on (ASLR-safe).

Usage:
  record_frida.py --elf <stripped-elf> --specs <function_specs.json> [--frida-server <path>]

Output: JSON lines on stdout, one per (function, input):
  {"fn":..., "vaddr":..., "base":..., "arg":..., "ret":...}
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time

import frida

AGENT_TEMPLATE = r"""
'use strict';
// Frida >= 16: Process.findModuleByPath was removed; match by module name
// (the main executable's module name is its basename).
const mod = Process.getModuleByName(__MODULE_NAME__) ||
            (Process.mainModule.name === __MODULE_NAME__ ? Process.mainModule : null);
if (mod === null) { throw new Error('module not found: ' + __MODULE_NAME__); }
const base = mod.base;
const results = [];

function hexToBytes(hex) {
    const a = [];
    for (let i = 0; i + 1 < hex.length; i += 2) {
        a.push(parseInt(hex.substr(i, 2), 16));
    }
    return a;
}
function callBytes(vaddr, dataHex) {
    const arr = hexToBytes(dataHex);
    const buf = Memory.alloc(arr.length || 1);
    if (arr.length > 0) buf.writeByteArray(arr);
    const f = new NativeFunction(base.add(vaddr), 'uint32', ['pointer', 'uint64']);
    return f(buf, arr.length);
}
function callU32(vaddr, x) {
    const f = new NativeFunction(base.add(vaddr), 'int32', ['uint32']);
    return f(x);
}

send({ base: base.toString() });
const queue = __CALLS__;
for (const c of queue) {
    if (c.kind === 'bytes') {
        const ret = callBytes(c.vaddr, c.arg);
        results.push({ fn: c.fn, vaddr: c.vaddr, kind: 'bytes',
                       arg: c.arg, ret: '0x' + (ret >>> 0).toString(16).padStart(8, '0') });
    } else {
        const ret = callU32(c.vaddr, c.x);
        results.push({ fn: c.fn, vaddr: c.vaddr, kind: 'u32',
                       arg: String(c.x), ret: String(ret) });
    }
}
send({ results: results });
"""


def build_calls(specs: dict) -> list[dict]:
    calls = []
    for fn in specs["functions"]:
        vaddr = int(fn["address"], 16)
        if "data" in fn["inputs"]:
            for h in fn["inputs"]["data"]:
                calls.append({"fn": fn["name"], "vaddr": vaddr,
                              "kind": "bytes", "arg": h})
        if "x" in fn["inputs"]:
            for x in fn["inputs"]["x"]:
                calls.append({"fn": fn["name"], "vaddr": vaddr,
                              "kind": "u32", "x": x})
    return calls


def start_frida_server(path: str) -> subprocess.Popen:
    proc = subprocess.Popen(
        [path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    # Wait until the server accepts connections (device becomes visible).
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            if any(d.type == "local" for d in frida.enumerate_devices()):
                return proc
        except Exception:
            pass
        time.sleep(0.2)
    proc.kill()
    raise RuntimeError("frida-server did not come up")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", required=True)
    ap.add_argument("--specs", required=True)
    ap.add_argument("--frida-server", default=os.environ.get("FRIDA_SERVER", "frida-server"))
    args = ap.parse_args()

    specs = json.load(open(args.specs))
    calls = build_calls(specs)

    elf_real = os.path.realpath(args.elf)
    server = start_frida_server(args.frida_server)
    session = None
    try:
        pid = frida.spawn([elf_real], env={"FUZ_HOLD": "1", "PATH": "/usr/bin:/bin"})
        session = frida.attach(pid)
        frida.resume(pid)

        agent_code = (
            AGENT_TEMPLATE.replace("__MODULE_NAME__", json.dumps(os.path.basename(elf_real)))
            .replace("__CALLS__", json.dumps(calls))
        )
        base_holder: dict = {}
        results: list = []

        def on_message(message, _data):
            if message.get("type") == "send":
                payload = message["payload"]
                if "base" in payload:
                    base_holder["base"] = payload["base"]
                elif "results" in payload:
                    results.extend(payload["results"])
            elif message.get("type") == "error":
                raise RuntimeError(f"agent error: {message.get('description')}")

        script = session.create_script(agent_code)
        script.on("message", on_message)
        script.load()

        # The script runs synchronously on the main thread of the parked
        # process; poll for completion (bounded).
        deadline = time.time() + 60
        while time.time() < deadline and len(results) < len(calls):
            time.sleep(0.05)
        if len(results) < len(calls):
            print(f"warning: got {len(results)}/{len(calls)} results", file=sys.stderr)

        for r in results:
            r["base"] = base_holder.get("base", "")
            print(json.dumps(r))
        return 0
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
        server.kill()
        try:
            server.wait(timeout=5)
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
