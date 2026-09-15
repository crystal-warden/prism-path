# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze the fusion_triage spiral tessellation + a decisions-preserved probe set.

Mirrors prismpath/telemetry/gen_spiral_corpus.py, with two deliberate differences: the flow is
read from flows/fusion_triage.md (not an inline string) and its sha256 is embedded so the frozen
corpus detects flow drift. Only the integer mapping is frozen  -  build-time xy floats are
excluded so the corpus stays platform-stable.

    python -m adapters.fusion.gen_fusion_spiral
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from prismpath.kernel.parser import parse
from prismpath.telemetry import spiral
from prismpath.telemetry import wire

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent

FLOW_PATH = HERE / "flows" / "fusion_triage.md"
NODE = "correlate"

# Boundary probes: +/-1 around every numeric cut, categorical values incl. unknowns that must
# land in the OTHER cell. Base is the quiet posture; joint corners come from the routing matrix.
_DEV_VALUES = [0, 149, 150, 151, 499, 500, 501, 2499, 2500, 2501]
_LEVEL_VALUES = [0, 6, 7, 8, 11, 12, 13]
_SOC_VALUES = ["contain", "watch", "ignore", "none"]           # last two -> OTHER
_STAB_VALUES = ["shaken", "moving", "still", "On Table"]       # last two -> OTHER

_BASE = {"stability": "still", "dev_mg": 0, "rule_level": 0, "soc_action": "ignore"}

_CORNERS = [
    {"stability": "shaken", "dev_mg": 3000, "rule_level": 13, "soc_action": "contain"},
    {"stability": "shaken", "dev_mg": 0, "rule_level": 3, "soc_action": "contain"},
    {"stability": "still", "dev_mg": 3000, "rule_level": 3, "soc_action": "contain"},
    {"stability": "still", "dev_mg": 200, "rule_level": 12, "soc_action": "watch"},
    {"stability": "still", "dev_mg": 0, "rule_level": 12, "soc_action": "contain"},
    {"stability": "still", "dev_mg": 149, "rule_level": 12, "soc_action": "contain"},
    {"stability": "shaken", "dev_mg": 2600, "rule_level": 5, "soc_action": "ignore"},
    {"stability": "still", "dev_mg": 2500, "rule_level": 3, "soc_action": "ignore"},
    {"stability": "moving", "dev_mg": 600, "rule_level": 8, "soc_action": "watch"},
    {"stability": "still", "dev_mg": 600, "rule_level": 3, "soc_action": "watch"},
    {"stability": "still", "dev_mg": 0, "rule_level": 8, "soc_action": "ignore"},
    {"stability": "moving", "dev_mg": 100, "rule_level": 3, "soc_action": "ignore"},
    {"stability": "still", "dev_mg": 400, "rule_level": 3, "soc_action": "ignore"},
    {"stability": "still", "dev_mg": 0, "rule_level": 0, "soc_action": "ignore"},
]


def _probes(graph) -> list:
    seen, probes = set(), []

    def add(reading):
        key = tuple(sorted((field, str(value)) for field, value in reading.items()))
        if key in seen:
            return
        seen.add(key)
        probes.append({"reading": reading, "route": wire.route_node(graph, NODE, reading)})

    for field, values in (("dev_mg", _DEV_VALUES), ("rule_level", _LEVEL_VALUES),
                          ("soc_action", _SOC_VALUES), ("stability", _STAB_VALUES)):
        for value in values:
            add({**_BASE, field: value})
    for corner in _CORNERS:
        add(dict(corner))
    return probes


def main() -> int:
    flow_text = FLOW_PATH.read_text()
    graph = parse(flow_text)
    layout = spiral.SpiralLayout(graph, NODE)
    corpus = {
        "version": 1,
        "note": "Frozen integer tessellation of fusion_triage@correlate. xy floats deliberately "
                "excluded (build-time geometry, regenerable). A mapping change flips a frozen "
                "entry -> test RED. flow_sha256 pins the flow this corpus was built from.",
        "flow": flow_text,
        "flow_sha256": hashlib.sha256(flow_text.encode()).hexdigest(),
        "node": NODE,
        "fields": layout.fields,
        "radices": layout.radices,
        "size": layout.size,
        "bands": [{"route": target, "base": layout.band_base[band_index], "width": layout.band_width[band_index]}
                  for band_index, target in enumerate(layout.routes)],
        "cells": [{"cell": list(layout.cell_of[cell_index]), "n": cell_index,
                   "band": layout.band_index[layout.route_of(cell_index)], "route": layout.route_of(cell_index)}
                  for cell_index in range(layout.size)],
        "probes": _probes(graph),
    }
    out = HERE / "conformance" / "spiral_fusion.json"
    out.write_text(json.dumps(corpus, indent=1) + "\n")
    print(f"wrote {out}  ({layout.size} cells, {len(layout.routes)} bands, {len(corpus['probes'])} probes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
