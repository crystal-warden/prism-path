#!/usr/bin/env python3
"""Generate the frozen decisions-preserved corpus: a set of flows + boundary-probing reading grids, each
reading tagged with the full-precision route at every decision node. `test_decisions_preserved.py` replays
it two ways — the engine must still produce the frozen routes (drift guard), and the wire round-trip
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

import quantizer as q          # noqa: E402
import wire as w              # noqa: E402
from prismpath.parser import parse, parse_file  # noqa: E402

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

MAX_READINGS = 250            # per-flow cap; strided deterministically if the grid is larger


def _field_values(p):
    if p.kind == "numeric":
        vals = set()
        for c in p.cells:
            vals.add(c["rep"])
            if c["lo"] is not None:
                vals.add(c["lo"]); vals.add(c["lo"] - 1)
            if c["hi"] is not None:
                vals.add(c["hi"]); vals.add(c["hi"] + 1)
        return sorted(vals)[:12]
    if p.kind == "boolean":
        return [False, True]
    # categorical
    return [c["const"] for c in p.cells if c["const"] != q._OTHER] + ["__unlisted__"]


def _grid(parts):
    order = sorted(parts.keys())
    axes = [_field_values(parts[f]) for f in order]
    combos = list(itertools.product(*axes))
    if len(combos) > MAX_READINGS:
        stride = len(combos) // MAX_READINGS + 1
        combos = combos[::stride]
    return [dict(zip(order, c)) for c in combos]


def _case(name, graph):
    parts = q.build_partitions(graph)
    nodes = w.decision_nodes(graph)
    entries = []
    for reading in _grid(parts):
        routes = {n: w.route_node(graph, n, reading) for n in nodes}
        entries.append({"reading": reading, "routes": routes})
    return {"name": name, "flow": None, "decision_nodes": nodes, "readings": entries}


def main():
    flows = {
        "incident_severity": (parse_file(str(_INCIDENT)), _INCIDENT.read_text()),
        "cat": (parse(CAT), CAT),
        "numeq": (parse(NUMEQ), NUMEQ),
        "pipeline": (parse(PIPELINE), PIPELINE),
    }
    cases = []
    for name, (graph, text) in flows.items():
        c = _case(name, graph)
        c["flow"] = text
        cases.append(c)
    doc = {
        "version": 1,
        "note": "Decisions-preserved corpus. Each reading is tagged with the full-precision route at every "
                "decision node; the engine must reproduce it (drift) and the quantize->Fibonacci->decode-> "
                "reconstruct wire round-trip must too (decision preservation).",
        "cases": cases,
    }
    out = HERE / "conformance" / "decisions.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(doc, indent=1) + "\n")
    total = sum(len(c["readings"]) for c in cases)
    print(f"wrote {out}  ({len(cases)} flows, {total} readings)")
    for c in cases:
        print(f"  {c['name']:20} nodes={c['decision_nodes']}  readings={len(c['readings'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
