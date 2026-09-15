# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Human-readable inspect path  -  the answer to "opaque wire, no tcpdump".

Point it at a captured telemetry bitstream + the flow `.md` and it decodes each reading back to its
symbols, the reconstructed representative values, and  -  the useful part  -  the **routing decision** the
policy makes on it. The `.md` IS the decoder: it defines both the field partition (how bits become
symbols) and the routing (how symbols become a decision), so no bespoke, drifting tooling is needed.

Kept as a standalone adapter tool (no core change); a `prismpath decode` CLI alias would be a one-line
wiring in `prismpath/cli.py` if desired.

  python prismpath/telemetry/decode.py --flow <flow.md> --bits <stream-of-0s-and-1s | ->  [--json]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List

try:
    import prismpath  # noqa: F401  installed or already on the path: leave sys.path alone
except ImportError:  # run as a loose script from a clone: make the repo root importable
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from prismpath.telemetry import quantizer   # noqa: E402
from prismpath.telemetry import wire        # noqa: E402
from prismpath.telemetry import zeckendorf as zeck  # noqa: E402
from prismpath.kernel.parser import parse  # noqa: E402


def _show(value):
    return "<other>" if value == quantizer.OTHER_CELL else value


def encode_readings(parts, readings: List[dict]) -> str:
    """The multi-reading wire: each reading's fields in canonical order, concatenated (zero header)."""
    return "".join(wire.encode_reading(parts, reading) for reading in readings)


def inspect(graph, bits: str) -> Dict:
    """Decode a bitstream against a flow -> per-reading symbols, reconstructed values, and routes."""
    parts = quantizer.build_partitions(graph)
    fields = sorted(parts.keys())
    nodes = wire.decision_nodes(graph)
    nf = len(fields)
    wire_ints = zeck.decode_stream(bits)
    n_complete = len(wire_ints) // nf if nf else 0
    rows = []
    for reading_index in range(n_complete):
        syms = {fields[field_index]: wire_ints[reading_index * nf + field_index] - 1
                for field_index in range(nf)}
        reading = quantizer.reconstruct(parts, syms)
        routes = {node: wire.route_node(graph, node, reading) for node in nodes}
        rows.append({"symbols": syms,
                     "reading": {field: _show(value) for field, value in reading.items()},
                     "routes": routes})
    trailing = len(wire_ints) - n_complete * nf          # leftover ints = a partial final frame
    dist = Counter(tuple(sorted(row["routes"].items())) for row in rows)
    return {"fields": fields, "decision_nodes": nodes, "n_readings": len(rows),
            "trailing_ints": trailing, "readings": rows,
            "route_distribution": {" ".join(f"{node}={target}" for node, target in route_pairs): count
                                   for route_pairs, count in dist.items()}}


def _render(rep: Dict) -> str:
    out = [f"fields: {rep['fields']}   decision nodes: {rep['decision_nodes']}",
           f"decoded {rep['n_readings']} reading(s)"
           + (f"  (+{rep['trailing_ints']} trailing int(s) = partial final frame)"
              if rep["trailing_ints"] else ""), ""]
    for reading_index, reading in enumerate(rep["readings"]):
        route = ", ".join(f"{node}->{target}" for node, target in reading["routes"].items())
        out.append(f"#{reading_index:4d}  {reading['reading']}   =>  {route}")
    out += ["", "route distribution:"]
    for route_label, count in sorted(rep["route_distribution"].items(), key=lambda kv: -kv[1]):
        out.append(f"  {count:6d}  {route_label}")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Decode a PrismPath telemetry bitstream against its flow.")
    ap.add_argument("--flow", required=True, help="the flow .md (the decoder)")
    ap.add_argument("--bits", required=True, help="file of 0/1 chars, or - for stdin")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    bits = sys.stdin.read() if args.bits == "-" else Path(args.bits).read_text()
    bits = "".join(ch for ch in bits if ch in "01")
    graph = parse(Path(args.flow).read_text())
    rep = inspect(graph, bits)
    print(json.dumps(rep, indent=1) if args.json else _render(rep))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
