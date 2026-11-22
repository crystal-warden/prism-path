# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze the grouped spiral profile's band tier (PROTOCOL.md 2.6.1) for the cross language test.

Emits `conformance/grouped_band.json`: for two policies that are too large to list (and one small flow, so
the layout the grouped profile defers to is pinned too), each decision node's band list and a seeded set of
readings (uniform cells and boundary values) with the band the policy routes each to and the Fibonacci bits
of its code. The Rust crate finds the band by evaluating the policy and must write the same bits.

    python gen_grouped_corpus.py        (then copy the file to prismpath-telemetry-rs/tests/fixtures/)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))   # repo root

from prismpath.kernel import core_render                       # noqa: E402
from prismpath.kernel.parser import parse                       # noqa: E402
from prismpath.telemetry import quantizer, spiral_groups as sg  # noqa: E402
from prismpath.telemetry import zeckendorf as zeck              # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent
POLICIES = ["integrations/governed_population/policy/admission.core.json",
            "prismpath/agent/policy/agent_review.core.json"]
SMALL = """---
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
READINGS = 40


def _case(name: str, flow: str, seed: int) -> dict:
    graph = parse(flow)
    parts = quantizer.build_partitions(graph)
    nodes = [node for node in sg.wire.decision_nodes(graph) if sg.spiral._node_fields(graph, node, parts)]
    pops = sg.populations(parts, seed, READINGS)
    readings = pops["uniform"][:READINGS // 2] + pops["boundary"][:READINGS // 2]
    return {"name": name, "flow": flow, "nodes": nodes,
            "joint_cells": {node: sg.joint_cells(graph, node, parts) for node in nodes},
            "routes": {node: ["" if route is None else route for route in sg.route_order(graph, node)]
                       for node in nodes},
            "readings": [{"reading": reading,
                          "bands": {node: sg.route_order(graph, node).index(sg.wire.route_node(graph, node, reading))
                                    for node in nodes},
                          "bits": "".join(zeck.encode(sg.route_order(graph, node).index(
                              sg.wire.route_node(graph, node, reading)) + 1) for node in nodes)}
                         for reading in readings]}


def main() -> int:
    cases = []
    for number, path in enumerate(POLICIES):
        raw = (ROOT / path).read_text(encoding="utf-8")
        flow = core_render.render(json.loads(raw)) if path.endswith(".core.json") else raw
        cases.append(_case(path.rsplit("/", 1)[1], flow, 20261121 + number))
    cases.append(_case("attitude", SMALL, 20261121 + len(POLICIES)))
    out = Path(__file__).resolve().parent / "conformance" / "grouped_band.json"
    out.write_text(json.dumps({"version": 1, "cases": cases}, indent=1) + "\n")
    print(f"wrote {out}  ({len(cases)} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
