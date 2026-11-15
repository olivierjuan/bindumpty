"""P3 integration: Frida capture -> snapshot replay oracle on a real
pointer-arg function (fnv1a(const uint8_t*, size_t)). Skipped when
frida or the toy build is unavailable; capture disables ASLR at spawn
time (frida aslr=disable) so the recorded addresses stay valid."""
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from humpty.analyze.snapshot import capture_snapshot, load_snapshot
from humpty.analyze.snapshot_replay import build_replay_driver, run_replay

SO = os.path.join(ROOT, "toys/case-01-leaf/build/toy01.so")

pytestmark = [
    pytest.mark.skipif(not os.path.exists(SO), reason="toy01.so not built"),
]


def _driver(tmp_path):
    """Compile a driver that calls fnv1a from the toy .so."""
    c = tmp_path / "driver.c"
    c.write_text(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n"
        "#include <stddef.h>\n"
        "uint32_t fnv1a(const uint8_t *d, size_t l);\n"
        "int main(void) {\n"
        "    uint8_t buf[64];\n"
        "    for (int i = 0; i < 64; i++) buf[i] = (uint8_t)(i * 7);\n"
        "    printf(\"%u\\n\", fnv1a(buf, 64));\n"
        "    return 0;\n"
        "}\n")
    exe = tmp_path / "driver"
    r = subprocess.run(["clang", "-O0", "-g", "-o", str(exe), str(c),
                        "-Wl,--no-as-needed", SO,
                        f"-Wl,-rpath,{os.path.dirname(SO)}"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return exe


def test_capture_then_replay_matches(tmp_path):
    exe = _driver(tmp_path)
    # ASLR disabled at spawn: recorded addresses survive into replay
    cap = capture_snapshot(SO, "fnv1a", 0x1120, [str(exe)],
                           timeout_s=60, max_pages=8, out_dir=tmp_path)
    # fnv1a over buf[i] = i*7, i in 0..63 — verified against the driver
    assert int(cap.out_regs.get("rax"), 16) == 2071816645
    regs, pages = load_snapshot(tmp_path / "snapshot_in.bin")
    assert "rdi" in regs and pages

    driver = build_replay_driver(tmp_path, 0x1120, out_dir=tmp_path,
                                 module=SO, symbol="fnv1a")
    v = run_replay(driver, shift=0)
    assert v.exit_code == 0, v.stderr_tail
    assert v.divergences == 0
    assert v.rax == 2071816645
