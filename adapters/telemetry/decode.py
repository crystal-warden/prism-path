# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Human-readable inspect path — the answer to "opaque wire, no tcpdump".

Point it at a captured telemetry bitstream + the flow `.md` and it decodes each reading back to its
symbols, the reconstructed representative values, and — the useful part — the **routing decision** the
policy makes on it. The `.md` IS the decoder: it defines both the field partition (how bits become
symbols) and the routing (how symbols become a decision), so no bespoke, drifting tooling is needed.

Kept as a standalone adapter tool (no core change); a `prismpath decode` CLI alias would be a one-line
wiring in `prismpath/cli.py` if desired.

  python adapters/telemetry/decode.py --flow <flow.md> --bits <stream-of-0s-and-1s | ->  [--json]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))   # repo root, for prismpath

import quantizer as q   # noqa: E402
import wire as w        # noqa: E402
import zeckendorf as z  # noqa: E402
from prismpath.parser import parse  # noqa: E402


def _show(v):
    return "<other>" if v == q._OTHER else v


def encode_readings(parts, readings: List[dict]) -> str:
    """The multi-reading wire: each reading's fields in canonical order, concatenated (zero header)."""
    return "".join(w.encode_reading(parts, r) for r in readings)


def inspect(graph, bits: str) -> Dict:
    """Decode a bitstream against a flow -> per-reading symbols, reconstructed values, and routes."""
    parts = q.build_partitions(graph)
    fields = sorted(parts.keys())
    nodes = w.decision_nodes(graph)
    nf = len(fields)
    wire_ints = z.decode_stream(bits)
    n_complete = len(wire_ints) // nf if nf else 0
    rows = []
    for i in range(n_complete):
        syms = {fields[j]: wire_ints[i * nf + j] - 1 for j in range(nf)}
        reading = q.reconstruct(parts, syms)
        routes = {n: w.route_node(graph, n, reading) for n in nodes}
        rows.append({"symbols": syms,
                     "reading": {f: _show(v) for f, v in reading.items()},
                     "routes": routes})
    trailing = len(wire_ints) - n_complete * nf          # leftover ints = a partial final frame
    dist = Counter(tuple(sorted(r["routes"].items())) for r in rows)
    return {"fields": fields, "decision_nodes": nodes, "n_readings": len(rows),
            "trailing_ints": trailing, "readings": rows,
            "route_distribution": {" ".join(f"{n}={t}" for n, t in k): c for k, c in dist.items()}}


def _render(rep: Dict) -> str:
    out = [f"fields: {rep['fields']}   decision nodes: {rep['decision_nodes']}",
           f"decoded {rep['n_readings']} reading(s)"
           + (f"  (+{rep['trailing_ints']} trailing int(s) = partial final frame)"
              if rep["trailing_ints"] else ""), ""]
    for i, r in enumerate(rep["readings"]):
        route = ", ".join(f"{n}->{t}" for n, t in r["routes"].items())
        out.append(f"#{i:4d}  {r['reading']}   =>  {route}")
    out += ["", "route distribution:"]
    for k, c in sorted(rep["route_distribution"].items(), key=lambda kv: -kv[1]):
        out.append(f"  {c:6d}  {k}")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Decode a PrismPath telemetry bitstream against its flow.")
    ap.add_argument("--flow", required=True, help="the flow .md (the decoder)")
    ap.add_argument("--bits", required=True, help="file of 0/1 chars, or - for stdin")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    bits = sys.stdin.read() if a.bits == "-" else Path(a.bits).read_text()
    bits = "".join(ch for ch in bits if ch in "01")
    graph = parse(Path(a.flow).read_text())
    rep = inspect(graph, bits)
    print(json.dumps(rep, indent=1) if a.json else _render(rep))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
