#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Generate the frozen decisions-preserved corpus: a set of flows + boundary-probing reading grids, each
reading tagged with the full-precision route at every decision node. `test_decisions_preserved.py` replays
it two ways  -  the engine must still produce the frozen routes (drift guard), and the wire round-trip
(quantize -> Fibonacci -> decode -> reconstruct) must reproduce them exactly (the differentiated proof).

Usage: gen_decisions_corpus.py   # writes conformance/decisions.json
"""
import itertools
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO))

from prismpath.telemetry import quantizer          # noqa: E402
from prismpath.telemetry import wire              # noqa: E402
from prismpath.kernel.parser import parse, parse_file  # noqa: E402

_INCIDENT = REPO / "prismpath" / "gallery" / "incident_severity" / "incident_severity.md"

CAT = """---
name: cat
start: classify
---
## classify
-> urgent: when kind == 'urgent'
-> batch: when kind in ('nightly', 'weekly')
-> blocked: when status != 'ok'
-> normal: else
## urgent
## batch
## blocked
## normal
"""

NUMEQ = """---
name: numeq
start: classify
---
## classify
-> exact: when x == 5
-> high: when x >= 10
-> low: else
## exact
## high
## low
"""

PIPELINE = """---
name: pipeline
start: intake
---
## intake
-> reject: when size > 1000
-> triage: else
## triage
-> urgent: when priority >= 8
-> batch: when kind in ('nightly', 'weekly')
-> normal: else
## reject
## urgent
## batch
## normal
"""

# Regression flows (September 2026): the atom forms whose constants the first quantizer did not use as
# cut points. Found while stating I1 in Lean (formal/FQ); each violated decision preservation.
NUMIN = """---
name: numin
start: classify
---
## classify
-> listed: when x in (3, 5)
-> excluded: when x not in (7, 9)
-> rest: else
## listed
## excluded
## rest
"""

TRUTHYNUM = """---
name: truthynum
start: classify
---
## classify
-> high: when x >= 5
-> nonzero: when x
-> zero: else
## high
## nonzero
## zero
"""

STRTRUTHY = """---
name: strtruthy
start: classify
---
## classify
-> root: when name == 'root'
-> named: when name
-> anonymous: else
## root
## named
## anonymous
"""

MAX_READINGS = 250            # per-flow cap; strided deterministically if the grid is larger


def _field_values(partition):
    if partition.kind == "numeric":
        vals = set()
        for cell in partition.cells:
            vals.add(cell["rep"])
            if cell["lo"] is not None:
                vals.add(cell["lo"]); vals.add(cell["lo"] - 1)
            if cell["hi"] is not None:
                vals.add(cell["hi"]); vals.add(cell["hi"] + 1)
        return sorted(vals)[:12]
    if partition.kind == "boolean":
        return [False, True]
    # categorical
    return [cell["const"] for cell in partition.cells
            if cell["const"] != quantizer.OTHER_CELL] + ["__unlisted__"]


def _grid(parts):
    order = sorted(parts.keys())
    axes = [_field_values(parts[field]) for field in order]
    combos = list(itertools.product(*axes))
    if len(combos) > MAX_READINGS:
        stride = len(combos) // MAX_READINGS + 1
        combos = combos[::stride]
    return [dict(zip(order, combo)) for combo in combos]


def _case(name, graph):
    parts = quantizer.build_partitions(graph)
    nodes = wire.decision_nodes(graph)
    entries = []
    for reading in _grid(parts):
        routes = {node: wire.route_node(graph, node, reading) for node in nodes}
        entries.append({"reading": reading, "routes": routes})
    return {"name": name, "flow": None, "decision_nodes": nodes, "readings": entries}


def main():
    flows = {
        "incident_severity": (parse_file(str(_INCIDENT)), _INCIDENT.read_text()),
        "cat": (parse(CAT), CAT),
        "numeq": (parse(NUMEQ), NUMEQ),
        "pipeline": (parse(PIPELINE), PIPELINE),
        "numin": (parse(NUMIN), NUMIN),
        "truthynum": (parse(TRUTHYNUM), TRUTHYNUM),
        "strtruthy": (parse(STRTRUTHY), STRTRUTHY),
    }
    cases = []
    for name, (graph, text) in flows.items():
        case = _case(name, graph)
        case["flow"] = text
        cases.append(case)
    doc = {
        "version": 2,
        "note": "Decisions-preserved corpus (v2 adds numin, truthynum, strtruthy: the cut point regression flows). Each reading is tagged with the full-precision route at every "
                "decision node; the engine must reproduce it (drift) and the quantize->Fibonacci->decode-> "
                "reconstruct wire round-trip must too (decision preservation).",
        "cases": cases,
    }
    out = HERE / "conformance" / "decisions.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(doc, indent=1) + "\n")
    total = sum(len(case["readings"]) for case in cases)
    print(f"wrote {out}  ({len(cases)} flows, {total} readings)")
    for case in cases:
        print(f"  {case['name']:20} nodes={case['decision_nodes']}  readings={len(case['readings'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
