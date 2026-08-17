#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze the boundary parity corpus: threshold behavior at every cut edge, including the 2^53 zone.

For each threshold t in a wide range flow (10^2 up to 10^12) the corpus probes t-1, t, t+1; around
the f64 integer exactness edge it probes 2^53-1, 2^53, 2^53+2 (2^53+1 is not representable) and
10^15. Expected symbols are computed by the reference quantizer at generation time and FROZEN;
the Python and Rust test twins replay them, so a symbol drift on either side of any boundary in
either implementation turns a test red. Regenerating this file is a spec change and must be
reviewed as one.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent.parent))

import quantizer as q  # noqa: E402

FLOW = """---
name: boundary_guard
start: classify
---
## classify
-> tiny: when mag < 100
-> small: when mag < 5000
-> mid: when mag < 1000000
-> large: when mag < 1000000000
-> huge: when mag < 1000000000000
-> extreme: else
## tiny
## small
## mid
## large
## huge
## extreme
"""

THRESHOLDS = [100, 5000, 1_000_000, 1_000_000_000, 1_000_000_000_000]
EDGE = 2**53


def main() -> int:
    from prismpath.parser import parse
    parts = q.build_partitions(parse(FLOW))
    p = parts["mag"]
    probes = []
    values = []
    for t in THRESHOLDS:
        values += [t - 1, t, t + 1]
    values += [EDGE - 1, EDGE, EDGE + 2, 10**15]
    for v in values:
        probes.append({"value": v, "symbol": p.symbol(v)})
    out = {
        "comment": "FROZEN. Boundary parity: expected quantizer symbol at every threshold edge "
                   "and the 2^53 f64 exactness edge. Both implementation twins replay this file.",
        "flow": FLOW,
        "field": "mag",
        "cells": p.n,
        "probes": probes,
    }
    path = HERE / "conformance" / "boundary.json"
    path.write_text(json.dumps(out, indent=1) + "\n")
    print(f"wrote {path}: {len(probes)} probes over {p.n} cells")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
