"""Integration: M1 CEGIS loop closes the seed bug end to end (LLM-free).

The stub develop runtime knows the fix, so the loop must:
  1. find a divergence (round 1),
  2. persist a counterexample (FR-15),
  3. repair and come back clean (TRUSTED) in a later round.

Skipped when the harness binary is not built.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for p in (os.path.join(ROOT, "horses", "src"), os.path.join(ROOT, "horses", "spikes")):
    sys.path.insert(0, p)

import cegis  # noqa: E402
import harness_driver as hd  # noqa: E402
from s4_core import Fnv1aSpec  # noqa: E402

pytestmark = pytest.mark.skipif(
    not os.path.exists(hd.HARNESS),
    reason="harness not built (run horses/src/build_horse.sh)")


@pytest.fixture()
def buggy_candidate_and_clean_ce():
    """Seed candidate with the len==255 bug; empty counterexample store."""
    orig_src = '#include <stdint.h>\n#include <stddef.h>\n\nuint32_t fnv1a(const uint8_t *data, size_t len) {\n    uint32_t hash = 2166136261u;\n    for (size_t i = 0; i < len; i++) {\n        hash ^= (uint32_t)data[i];\n        hash *= 16777619u;\n    }\n    return hash;\n}\n\nint digit_sum_u32(uint32_t x) {\n    int s = 0;\n    do { s += (int)(x % 10u); x /= 10u; } while (x != 0u);\n    return s;\n}\n\nuint32_t checksum_block(const uint8_t *data, size_t len) {\n    size_t half = len / 2;\n    uint32_t h1 = fnv1a(data, half);\n    uint32_t h2 = fnv1a(data + half, len - half);\n    uint32_t mix = h1 ^ (h2 * 2654435761u);\n    return mix ^ (uint32_t)digit_sum_u32(mix);\n}\n'
    buggy = orig_src.replace(
        "    for (size_t i = 0; i < len; i++) {\n        hash ^= (uint32_t)data[i];",
        "    if (len == 0xFF) hash = 0x12345678u;\n"
        "    for (size_t i = 0; i < len; i++) {\n        hash ^= (uint32_t)data[i];")
    hd.write_candidate(buggy)
    # clean the counterexample store
    if os.path.isdir(cegis.CE_DIR):
        for f in os.listdir(cegis.CE_DIR):
            os.remove(os.path.join(cegis.CE_DIR, f))
    yield buggy
    hd.write_candidate(orig_src)


def test_cegis_loop_closes_seed_bug(buggy_candidate_and_clean_ce):
    spec = Fnv1aSpec(randomized_n=0)
    res = cegis.cegis_loop(spec, cegis.stub_develop, max_iter=5,
                           fuzz_budget_s=10, log=lambda *_: None)
    assert res.verified, f"expected TRUSTED, got {res.history}"
    assert res.iterations >= 2, "expected a divergent round before repair"
    outcomes = [h["outcome"] for h in res.history]
    assert outcomes[0] == "divergent" and outcomes[-1] == "trusted"
    # FR-15: the divergent input was persisted
    ces = cegis.load_counterexamples()
    assert len(ces) == 1 and len(ces[0]) == 255
