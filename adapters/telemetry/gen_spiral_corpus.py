"""Freeze the spiral tessellation + a decisions-preserved probe set for the conformance test.

Emits `conformance/spiral.json`: the integer cell->index/band/route map for a fixed flow (a mapping bug
in the layout flips a frozen entry -> test RED) plus boundary-probing readings tagged with the route the
flow makes on them (the decisions-preserved proof re-routes each three ways and must agree).

Only the integer mapping is frozen — the build-time xy coordinates are float geometry (visualization) and
are deliberately excluded so the corpus is platform-stable.

    python gen_spiral_corpus.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))   # repo root

import spiral as sp   # noqa: E402
import wire as w      # noqa: E402
from prismpath.parser import parse            # noqa: E402

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
        for c in cuts:
            for v in (c - 1, c, c + 1):
                r = dict(base)
                r[field] = max(0, v)
                key = tuple(sorted(r.items()))
                if key in seen:
                    continue
                seen.add(key)
                probes.append({"reading": r, "route": w.route_node(graph, NODE, r)})
    return probes


def main() -> int:
    graph = parse(FLOW)
    L = sp.SpiralLayout(graph, NODE)
    corpus = {
        "flow": FLOW,
        "node": NODE,
        "fields": L.fields,
        "radices": L.radices,
        "size": L.size,
        "bands": [{"route": r, "base": L.band_base[i], "width": L.band_width[i]}
                  for i, r in enumerate(L.routes)],
        "cells": [{"cell": list(L.cell_of[n]), "n": n,
                   "band": L.band_index[L.route_of(n)], "route": L.route_of(n)}
                  for n in range(L.size)],
        "probes": _probes(graph, L),
    }
    out = Path(__file__).resolve().parent / "conformance" / "spiral.json"
    out.write_text(json.dumps(corpus, indent=1) + "\n")
    print(f"wrote {out}  ({L.size} cells, {len(L.routes)} bands, {len(corpus['probes'])} probes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
