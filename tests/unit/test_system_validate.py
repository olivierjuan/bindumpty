"""P4: baseline parsing + parity rules (unit level; the solver-shaped
end-to-end runs against ./lpex2 outside the test suite)."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from humpty.king.system_validate import parse_baseline

LOG = """Selected objective sense:  MINIMIZE
 Itn      Primal Obj        Dual Obj  Prim Inf Upper Inf  Dual Inf          
   0   2.2722169e+11  -2.4054111e+11  2.13e+08  2.47e+08  3.22e+07
  22  -1.9010158e+08  -1.9010158e+08  6.19e-05  3.01e-10  3.19e-10
Barrier time = 0.13 sec. (45.53 ticks)
Solution status 1, solution method 4
Objective value -190101581.1.
"""


def test_parse_baseline_full():
    b = parse_baseline("m.mps", LOG, 0)
    assert b.status == 1
    assert b.objective == -190101581.1
    assert b.iterations == 23  # final Itn index 22, 0-based
    assert b.exit_code == 0


def test_parse_baseline_garbage():
    b = parse_baseline("m.mps", "nothing useful", 1)
    assert b.status is None and b.objective is None and b.iterations is None


def test_parity_logic_matches():
    a = parse_baseline("m.mps", LOG, 0)
    b = parse_baseline("m.mps", LOG.replace("Objective value -190101581.1.",
                                            "Objective value -190101581.1000001."), 0)
    eps = 1e-6
    assert abs(a.objective - b.objective) <= eps * max(1.0, abs(a.objective))
    c = parse_baseline("m.mps", LOG.replace("Objective value -190101581.1.",
                                            "Objective value -190102181.1."), 0)
    assert not abs(a.objective - c.objective) <= eps * max(1.0, abs(a.objective))
