#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""canary_verify: prove the Facet leg of a canary routes exactly like the pipeline you trust.

During a canary, one Vector source fans out to your existing JSON sink (the raw capture) and to a
Facet sink whose wire an aggregator decodes back to events (the decoded capture). This verifier
replays every raw event through the reference implementation (the same one the codec is
parity-tested against), computes the route the policy takes on it, and compares against the route
the decoded leg actually carried. It checks three things: the two captures carry the same number of
events, every position routes identically, and the per route distributions agree. Any daylight
between the legs is listed with the offending events.

Usage:
  canary_verify.py FLOW.md --raw raw.ndjson --decoded decoded.ndjson --route-node NODE
                   [--route-field facet_route] [--map FIELD=PATH ...] [--json OUT.json]

Exit status: 0 = perfect parity, 1 = any mismatch, count drift, or unreadable input.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_TELEMETRY = Path(__file__).resolve().parent.parent.parent / "adapters" / "telemetry"
sys.path.insert(0, str(_TELEMETRY))
sys.path.insert(0, str(_TELEMETRY.parent.parent))

import preflight  # noqa: E402  (extract_reading + _codec_view: the codec's exact view of an event)
import quantizer as q  # noqa: E402
import wire as w  # noqa: E402
from prismpath.parser import parse_file  # noqa: E402


def _read_ndjson(path: str) -> Tuple[List[dict], int]:
    events, bad = [], 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            if isinstance(ev, dict):
                events.append(ev)
            else:
                bad += 1
    return events, bad


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="canary-verify",
        description="Diff the routes of a canary's raw JSON leg against its decoded Facet leg.")
    ap.add_argument("flow", help="the policy flow BOTH legs run (pin policy_sha256 so it stays that way)")
    ap.add_argument("--raw", required=True, help="NDJSON capture from the existing JSON sink")
    ap.add_argument("--decoded", required=True, help="NDJSON re-emitted by the Facet decoding aggregator")
    ap.add_argument("--route-node", required=True,
                    help="decision node the aggregator routes from (its decoding.route_node)")
    ap.add_argument("--route-field", default="facet_route",
                    help="field carrying the decoded route (default: facet_route, the codec default)")
    ap.add_argument("--map", action="append", default=[], metavar="FIELD=PATH",
                    help="flow field -> raw event path, matching the encoder's field_paths")
    ap.add_argument("--json", dest="json_out", default=None, metavar="OUT.json",
                    help="also write the full comparison as JSON")
    args = ap.parse_args()

    field_paths: Dict[str, str] = {}
    for m in args.map:
        f, _, p = m.partition("=")
        field_paths[f] = p

    graph = parse_file(args.flow)
    parts = q.build_partitions(graph)
    if args.route_node not in w.decision_nodes(graph):
        ap.error(f"--route-node {args.route_node!r} is not a decision node of the flow")
    order = sorted(parts.keys())

    raw, raw_bad = _read_ndjson(args.raw)
    decoded, dec_bad = _read_ndjson(args.decoded)

    expected: List[Optional[str]] = []
    unencodable = 0
    for ev in raw:
        reading, missing = preflight.extract_reading(ev, order, field_paths)
        if missing:
            unencodable += 1
            expected.append(None)          # the encoder dropped it; no decoded twin should exist
            continue
        try:
            seen, _trunc = preflight._codec_view(parts, reading)
            w.encode_reading(parts, seen)
        except (TypeError, ValueError, KeyError):
            unencodable += 1
            expected.append(None)
            continue
        expected.append(w.route_node(graph, args.route_node, seen) or "(no match)")

    exp_routes = [r for r in expected if r is not None]
    got_routes = [str(ev.get(args.route_field, "(absent)")) for ev in decoded]

    mismatches: List[dict] = []
    for i, (e, g) in enumerate(zip(exp_routes, got_routes)):
        if e != g and len(mismatches) < 10:
            mismatches.append({"position": i, "expected": e, "decoded": g})
    count_drift = len(exp_routes) - len(got_routes)
    exp_dist, got_dist = Counter(exp_routes), Counter(got_routes)
    ok = not mismatches and count_drift == 0 and exp_dist == got_dist \
        and len(exp_routes) > 0 and raw_bad == 0 and dec_bad == 0

    md = [f"# canary-verify: {Path(args.flow).name} at `{args.route_node}`", "",
          f"- raw leg: {len(raw)} events" + (f" ({raw_bad} unparseable lines)" if raw_bad else "")
          + (f", {unencodable} not encodable (no decoded twin expected)" if unencodable else ""),
          f"- decoded leg: {len(decoded)} events" + (f" ({dec_bad} unparseable lines)" if dec_bad else ""), ""]
    if count_drift:
        md.append(f"**COUNT DRIFT**: {len(exp_routes)} encodable raw events vs {len(got_routes)} "
                  f"decoded ({count_drift:+d}). Positional comparison below covers the overlap; "
                  f"look for drops or a reconnect between the legs.")
        md.append("")
    md += ["| route | raw leg | decoded leg |", "|---|---|---|"]
    for route in sorted(set(exp_dist) | set(got_dist)):
        flag = "" if exp_dist[route] == got_dist[route] else "  <-- differs"
        md.append(f"| `{route}` | {exp_dist[route]} | {got_dist[route]}{flag} |")
    md.append("")
    if mismatches:
        md.append(f"**{len(mismatches)}{'+' if len(mismatches) == 10 else ''} POSITIONAL "
                  f"MISMATCHES** (first shown; usual causes: flow version skew between the legs, "
                  f"an unpinned policy edited on one side, or field_paths that differ from the "
                  f"encoder's):")
        for m in mismatches:
            md.append(f"- event {m['position']}: raw leg routes `{m['expected']}`, "
                      f"decoded leg carried `{m['decoded']}`")
        md.append("")
    md.append("**PARITY.** Every decoded route matches the raw leg; the Facet wire is carrying "
              "your decisions faithfully." if ok else
              "**NO PARITY.** Do not cut over; resolve the findings above and rerun.")
    print("\n".join(md))

    if args.json_out:
        Path(args.json_out).write_text(json.dumps({
            "flow": args.flow, "route_node": args.route_node,
            "raw_events": len(raw), "decoded_events": len(decoded),
            "unencodable_raw": unencodable, "count_drift": count_drift,
            "raw_distribution": dict(exp_dist), "decoded_distribution": dict(got_dist),
            "mismatches": mismatches, "parity": ok}, indent=1) + "\n")
        print(f"\nwrote {args.json_out}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
