# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze the spiral tessellation + a decisions-preserved probe set for the conformance test.

Emits `conformance/spiral.json`: the integer cell->index/band/route map for a fixed flow (a mapping bug
in the layout flips a frozen entry -> test RED) plus boundary-probing readings tagged with the route the
flow makes on them (the decisions-preserved proof re-routes each three ways and must agree).

Only the integer mapping is frozen  -  the build-time xy coordinates are float geometry (visualization) and
are deliberately excluded so the corpus is platform-stable.

    python gen_spiral_corpus.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))   # repo root

from prismpath.telemetry import spiral   # noqa: E402
from prismpath.telemetry import wire      # noqa: E402
from prismpath.kernel.parser import parse            # noqa: E402

FLOW = """---
name: attitude
start: watch
---
## watch
-> critical: when vibration >= 80
-> alarm: when pitch >= 45 or roll >= 45
-> caution: when pitch >= 20 or roll >= 20 or vibration >= 40
-> nominal: else
## critical
## alarm
## caution
## nominal
"""
NODE = "watch"


def _probes(graph, layout):
    """Boundary-probing readings: each threshold and +/-1 around it, across the three fields."""
    thresholds = {"pitch": [20, 45], "roll": [20, 45], "vibration": [40, 80]}
    base = {"pitch": 0, "roll": 0, "vibration": 0}
    seen = set()
    probes = []
    for field, cuts in thresholds.items():
        for cut in cuts:
            for value in (cut - 1, cut, cut + 1):
                reading = dict(base)
                reading[field] = max(0, value)
                key = tuple(sorted(reading.items()))
                if key in seen:
                    continue
                seen.add(key)
                probes.append({"reading": reading, "route": wire.route_node(graph, NODE, reading)})
    return probes


def main() -> int:
    graph = parse(FLOW)
    layout = spiral.SpiralLayout(graph, NODE)
    corpus = {
        "flow": FLOW,
        "node": NODE,
        "fields": layout.fields,
        "radices": layout.radices,
        "size": layout.size,
        "bands": [{"route": route, "base": layout.band_base[band], "width": layout.band_width[band]}
                  for band, route in enumerate(layout.routes)],
        "cells": [{"cell": list(layout.cell_of[spiral_index]), "n": spiral_index,
                   "band": layout.band_index[layout.route_of(spiral_index)],
                   "route": layout.route_of(spiral_index)}
                  for spiral_index in range(layout.size)],
        "probes": _probes(graph, layout),
    }
    out = Path(__file__).resolve().parent / "conformance" / "spiral.json"
    out.write_text(json.dumps(corpus, indent=1) + "\n")
    print(f"wrote {out}  ({layout.size} cells, {len(layout.routes)} bands, {len(corpus['probes'])} probes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
