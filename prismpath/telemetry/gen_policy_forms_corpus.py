#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze the policy forms corpus: which condition forms the codec carries, and which it refuses.

Run as `python -m prismpath.telemetry.gen_policy_forms_corpus`. Every carried case is a Level M
condition the October 2026 reading boundary audit found the Python or the Rust quantizer handling
wrongly, a chained range, a negative threshold, a constant on the left, a boolean constant on a
numeric field, and each probe records the route the engine takes on the raw reading. The routes come
from the engine, not from either quantizer, so the Python and Rust twins are both held to the
reference decision rather than to each other. Every refused case is a form the codec cannot carry
faithfully, and both twins must refuse the whole flow rather than partition it. Regenerating this file
is a spec change and must be reviewed as one.

Absence is deliberately left out of the carried cases. A comparison with None is refused here until
the canonical reading gives absence an explicit cell, and that decision is not this corpus's to make.
"""
import json
from pathlib import Path

from prismpath.kernel import engine
from prismpath.kernel.parser import parse

HERE = Path(__file__).resolve().parent

FLOW_TEMPLATE = ("---\nname: policy_forms\nstart: s\n---\n## s\n-> hit: when {condition}\n-> miss: else\n"
                 "## hit\nH\n## miss\nM\n")

CARRIED = [
    ("x", "0 < x < 5", [-1, 0, 1, 4, 5, 6]),
    ("x", "x < -3", [-5, -4, -3, -2, 0]),
    ("x", "-3 > x", [-5, -4, -3, -2, 0]),
    ("x", "x in [-2, 4]", [-3, -2, -1, 0, 4, 5]),
    ("x", "x not in [-2, 4]", [-3, -2, -1, 0, 4, 5]),
    ("x", "-10 <= x <= -5 or x == 7", [-11, -10, -7, -5, -4, 6, 7, 8]),
    ("x", "not (0 <= x < 3)", [-1, 0, 2, 3, 4]),
    ("x", "x == True or x > 5", [0, 1, 2, 5, 6]),
    ("x", "x in [True, 5]", [0, 1, 2, 5, 6]),
    ("x", "True == x", [False, True]),
    ("kind", 'kind == "a" or kind in ["b", "c"]', ["a", "b", "c", "d"]),
    ("kind", '"a" != kind', ["a", "z"]),
]

REFUSED = [
    "x == y",
    'kind < "m"',
    '"m" > kind',
    "x in y",
    'kind in "abc"',
    "x < 2.5",
    "x in [1, 2.5]",
    'x == 3 or x == "a"',
    'x == True or x == "a"',
    "x == None",
    "x != None and x > 3",
]


def main() -> int:
    carried = []
    for field, condition, values in CARRIED:
        graph = parse(FLOW_TEMPLATE.format(condition=condition))
        readings = [{"value": value,
                     "route": engine.first_deterministic(graph.nodes["s"].edges, {field: value})[0]}
                    for value in values]
        carried.append({"field": field, "condition": condition, "readings": readings})
    out = {
        "comment": "FROZEN. Policy forms: Level M conditions the codec must carry with the engine's own "
                   "route on every probe, and forms it must refuse as a whole flow. Both implementation "
                   "twins replay this file.",
        "flow_template": FLOW_TEMPLATE,
        "node": "s",
        "carried": carried,
        "refused": [{"condition": condition} for condition in REFUSED],
    }
    path = HERE / "conformance" / "policy_forms.json"
    path.write_text(json.dumps(out, indent=1) + "\n")
    probes = sum(len(case["readings"]) for case in carried)
    print(f"wrote {path}: {len(carried)} carried forms with {probes} probes, {len(REFUSED)} refused forms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
