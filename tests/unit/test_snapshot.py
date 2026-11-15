"""P3: snapshot serialization round-trip (unit)."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from humpty.analyze.snapshot import _serialize, load_snapshot


def test_roundtrip_regs_and_pages(tmp_path):
    regs = {"rdi": "0x7fff0000abcd", "rsi": "0x40", "rax": "0xf4a29bc5"}
    pages = {"7fff0000a000": bytes(range(256)) * 16,   # 4096 bytes
             "7fff0000b000": b"\x00" * 4096}
    blob = _serialize(regs, pages)
    p = tmp_path / "snap.bin"
    p.write_bytes(blob)
    r2, p2 = load_snapshot(p)
    assert r2["rdi"] == 0x7FFF0000ABCD
    assert r2["rax"] == 0xF4A29BC5
    assert set(p2) == {"7fff0000a000", "7fff0000b000"}
    assert p2["7fff0000a000"] == bytes(range(256)) * 16
    assert p2["7fff0000b000"] == b"\x00" * 4096


def test_bad_magic_rejected(tmp_path):
    p = tmp_path / "bad.bin"
    p.write_bytes(b"NOTMAGIC" + b"\x00" * 16)
    try:
        load_snapshot(p)
        assert False, "expected assertion for bad magic"
    except AssertionError as e:
        assert "magic" in str(e)
