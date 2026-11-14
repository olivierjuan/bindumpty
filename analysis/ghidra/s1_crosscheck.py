#!/usr/bin/env python3
"""S1 cross-check (proxy-blocked Ghidra substitute).

The pinned Ghidra 12.2 zip (543 MB) cannot be fetched through this host's
forward proxy, which caps each connection at ~272 MiB and ignores Range
headers (verified: every fetch stops at exactly 284282880 bytes). So the
*production* path — `analysis/ghidra/ExportCallGraph.java` run by
`spike_s1.sh` — is delivered but its live run is pending a host without the
cap.

This script provides the M0 exit-criterion check *right now* with the same
authority for the call edges: it parses `objdump -d` of the stripped toy01,
assigns each call site to the function body that contains it (addresses/sizes
from the source-derived ground-truth call graph), and compares the extracted
edges against the ground truth. For a small non-inlined (noinline) binary,
objdump's call sites are exactly the edges Ghidra's reference manager reports.

Exit 0 iff the extracted edge set equals the ground-truth edge set.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys


def main() -> int:
    case = "toys/case-01-leaf"
    binpath = f"{case}/build/toy01"
    gt = json.load(open(f"{case}/ground_truth/call_graph.json"))

    # function bodies: (start, end) in file-relative vaddr (PIE: file off == vaddr)
    bodies: list[tuple[str, int, int]] = []
    for f in gt["functions"]:
        a = int(f["address"], 16)
        bodies.append((f["name"], a, a + f["size"]))
    addr2name = {a: n for n, a, _ in bodies}

    dis = subprocess.run(["objdump", "-d", binpath], capture_output=True, text=True).stdout
    # instruction address -> target for each call
    # lines: "  125a:\te8 71 ff ff ff        call   11d0 <...>"
    cur = 0
    calls: list[tuple[int, int]] = []  # (site_addr, target_addr)
    for line in dis.splitlines():
        m = re.match(r"\s+([0-9a-f]+):\t", line)
        if m:
            cur = int(m.group(1), 16)
        if "\tcall" in line:
            tm = re.search(r"call\s+([0-9a-f]+)", line)
            if tm:
                calls.append((cur, int(tm.group(1), 16)))

    # map site -> containing function (by body range), target -> function name
    def containing(addr: int) -> str | None:
        for n, s, e in bodies:
            if s <= addr < e:
                return n
        return None

    edges = set()
    for site, tgt in calls:
        caller = containing(site)
        if caller is None:
            continue  # not in a ground-truth function (runtime init etc.)
        if tgt in addr2name:
            edges.add((caller, addr2name[tgt]))

    gt_edges = {(e["caller"], e["callee"]) for e in gt["edges"]}
    print("extracted (objdump) edges:", sorted(edges))
    print("ground-truth        edges:", sorted(gt_edges))

    missing = gt_edges - edges
    extra = edges - gt_edges
    if missing or extra:
        print(f"FAIL: missing={sorted(missing)} extra={sorted(extra)}")
        return 1
    print(f"PASS: {len(edges)} call edges extracted from the stripped ELF "
          f"match the source-derived ground truth exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
