"""humpty.trace — record-replay trace bundles (FR-3).

A *trace bundle* is the recorded I/O of a function (or a set of functions) on
a curated set of valid inputs, produced by a recorder:

- toy oracle: ``toys/*/record.sh`` -> ``trace_driver.c`` (M0), or
- production: ``tracing/record_frida.py`` (M2+).

Both emit the same ``fuz.traces/1`` format (JSON lines), so this module is the
single reader that turns a bundle into ``traces`` rows. The bundle is:

  1. the **cheap oracle** — replay a candidate against it before spending a
     fuzz budget (a trace failure is a hard counterexample),
  2. the **initial fuzz corpus** — the recorded inputs seed the fuzzer,
  3. the **concrete examples** in the developer prompt (FR-4).

Design: the bundle is *function-scoped* (every record names its function),
so one bundle may cover several functions of a binary. It carries no return
value for the *caller's* benefit beyond what is recorded; it is pure ground
truth, validated at load time.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from humpty.db.models import Function, Trace

__all__ = ["TraceBundleError", "TraceRecord", "parse_bundle", "load_bundle"]

FORMAT = "fuz.traces/1"


class TraceBundleError(ValueError):
    """The trace bundle failed validation."""


@dataclass(frozen=True)
class TraceRecord:
    """One recorded call.

    ``fn``: function name as emitted by the recorder (matches the call-graph
        name / ``demangled_sig`` used at load time).
    ``args_blob``: the raw argument bytes (hex-decoded) for a ``bytes`` call,
        or the u32 big-endian for a ``u32`` call.
    ``ret``: the recorded return value bytes (the return register, truncated
        to the natural width) — stored as the oracle. For a ``u32``/``i32``
        function this is the 4-byte little-endian of the integer; the parser
        keeps the canonical form.
    ``ret_int``: the decoded integer return (None when the recorder emitted a
        hex string it does not decode to a small int — kept for fidelity).
    """

    fn: str
    args_blob: bytes
    ret: bytes
    ret_int: int | None

    @property
    def input_sha256(self) -> str:
        return hashlib.sha256(self.args_blob).hexdigest()


def _ret_bytes(value: object) -> tuple[bytes, int | None]:
    """Normalize a recorded return value to (bytes, int|None).

    The driver emits ``"0x<8hex>"`` for 32-bit returns and a bare integer for
    the i32 digit-sum. Both are normalized to the 4-byte little-endian form so
    the oracle is byte-exact and comparable in the harness (FR-6).
    """
    if isinstance(value, int):
        return value.to_bytes(4, "little", signed=True), value
    if isinstance(value, str):
        v = int(value, 16) if value.lower().startswith("0x") else int(value, 0)
        if v >= (1 << 31):
            v -= 1 << 32  # interpret a 32-bit unsigned as signed for storage
        return v.to_bytes(4, "little", signed=True), v
    raise TraceBundleError(f"unsupported ret value type: {type(value)!r}")


def parse_bundle(path: str | Path) -> list[TraceRecord]:
    """Parse a ``fuz.traces/1`` JSON-lines bundle into records.

    Each line is one of:
      {"fn":..., "arg":"<hex>", "arglen":N, "ret":"0x<8hex>"}   (bytes call)
      {"fn":..., "arg":"<int>",  "ret":<int>}                   (u32 call)
    Lines that do not match are rejected (the bundle is ground truth — no
    silent skips).
    """
    records: list[TraceRecord] = []
    text = Path(path).read_text()
    for i, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            raise TraceBundleError(f"line {i}: invalid JSON: {e}") from e
        fn = obj.get("fn")
        if not isinstance(fn, str):
            raise TraceBundleError(f"line {i}: missing/invalid 'fn'")
        arg = obj.get("arg")
        if arg is None:
            raise TraceBundleError(f"line {i}: missing 'arg'")
        ret = obj.get("ret")
        if ret is None:
            raise TraceBundleError(f"line {i}: missing 'ret'")

        # The discriminator is `arglen`: the driver emits it for byte-calls
        # (hex args) and omits it for u32-calls (decimal args). "1234" is
        # valid hex *and* decimal, so the field presence is what disambiguates.
        if "arglen" in obj:
            if not isinstance(arg, str):
                raise TraceBundleError(f"line {i}: bytes call needs a string arg")
            if len(arg) % 2 != 0:
                raise TraceBundleError(f"line {i}: odd-length hex arg {arg!r}")
            args_blob = bytes.fromhex(arg)
            if int(obj["arglen"]) != len(args_blob):
                raise TraceBundleError(
                    f"line {i}: arglen {obj['arglen']} != decoded {len(args_blob)}"
                )
        elif isinstance(arg, str) and arg.lstrip("-").isdigit():
            x = int(arg)
            if not 0 <= x <= 0xFFFFFFFF:
                raise TraceBundleError(f"line {i}: u32 arg out of range: {x}")
            args_blob = x.to_bytes(4, "little")
        else:
            raise TraceBundleError(f"line {i}: unrecognized arg {arg!r}")

        ret_bytes, ret_int = _ret_bytes(ret)
        records.append(TraceRecord(fn=fn, args_blob=args_blob, ret=ret_bytes, ret_int=ret_int))
    return records


def load_bundle(session: Session, *, bundle: str | Path, binary_sha256: str) -> int:
    """Load a bundle into ``traces``. Returns the number of records inserted.

    The function for each record is resolved by its name against the loaded
    call graph (``demangled_sig``). The caller commits — loading joins the
    caller's transaction. A record naming a function not present in this
    binary's graph is an error (the bundle must match the binary).
    """
    records = parse_bundle(bundle)
    inserted = 0
    for rec in records:
        fn = session.query(Function).filter(
            Function.binary_sha256 == binary_sha256,
            Function.name == rec.fn,
        ).one_or_none()
        if fn is None:
            raise TraceBundleError(
                f"trace for unknown function {rec.fn!r} (binary {binary_sha256[:12]}…)"
            )
        session.add(
            Trace(
                function_id=fn.id,
                args_blob=rec.args_blob,
                ret=rec.ret,
                input_sha256=rec.input_sha256,
            )
        )
        inserted += 1
    session.flush()
    return inserted
