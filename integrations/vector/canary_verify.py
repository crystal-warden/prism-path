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

Route parity alone cannot see a lost event replaced by a duplicate that takes the same route. When
both legs carry an event identity, `--id-field` turns on the strict mode: the identities of the
encodable raw events and of the decoded events must be the same sequence, with no duplicate, no
missing and no reordered identity. Captures without an identity field keep the route only mode.

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

# Imported as a module (python -m integrations.vector.canary_verify) the repository root is already
# on sys.path. Run as a plain script against an uninstalled checkout it is not, and that is how the
# verifier is invoked in the field, so the root goes on the path for that case.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from prismpath.kernel.parser import parse_file  # noqa: E402
from prismpath.telemetry import preflight  # noqa: E402  (extract_reading + the codec's exact view of an event)
from prismpath.telemetry import quantizer  # noqa: E402
from prismpath.telemetry import wire  # noqa: E402


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


def _lookup(event: dict, dotted_path: str):
    """The value at a dotted path in a raw event, None when any segment is absent."""
    value: Any = event
    for segment in dotted_path.split("."):
        if not isinstance(value, dict) or segment not in value:
            return None
        value = value[segment]
    return value


def _compare_identities(raw_ids: List[Any], decoded_ids: List[Any]) -> dict:
    """The strict comparison: the decoded identities must be the raw identities in order, each once.

    A lost event that a duplicate stands in for keeps the route counts intact and fails here, because
    the lost identity is missing and the duplicate's identity appears twice. An event without an
    identity on either leg is counted, never guessed."""
    unidentified = sum(1 for identifier in raw_ids + decoded_ids if identifier is None)
    raw_counts, decoded_counts = Counter(raw_ids), Counter(decoded_ids)
    missing = [identifier for identifier in raw_ids if decoded_counts[identifier] == 0]
    duplicated = sorted({identifier for identifier, count in decoded_counts.items() if count > 1 and identifier is not None}, key=str)
    extra = [identifier for identifier in decoded_ids if raw_counts[identifier] == 0]
    reordered = sum(1 for raw_id, decoded_id in zip(raw_ids, decoded_ids) if raw_id != decoded_id)
    ok = not missing and not duplicated and not extra and unidentified == 0 and reordered == 0 and len(raw_ids) == len(decoded_ids)
    return {"ok": ok, "missing": [str(identifier) for identifier in missing],
            "duplicated": [str(identifier) for identifier in duplicated],
            "extra": [str(identifier) for identifier in extra],
            "unidentified": unidentified, "reordered": reordered}


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
    ap.add_argument("--id-field", default=None, metavar="RAW_PATH",
                    help="strict mode: the raw event path carrying a per event identity (dotted path allowed); "
                         "the decoded leg must carry the same identity in sequence")
    ap.add_argument("--decoded-id-field", default=None, metavar="NAME",
                    help="the decoded event field carrying the identity (default: the last segment of --id-field)")
    ap.add_argument("--json", dest="json_out", default=None, metavar="OUT.json",
                    help="also write the full comparison as JSON")
    args = ap.parse_args()

    field_paths: Dict[str, str] = {}
    for m in args.map:
        field, _, raw_path = m.partition("=")
        field_paths[field] = raw_path

    graph = parse_file(args.flow)
    parts = quantizer.build_partitions(graph)
    if args.route_node not in wire.decision_nodes(graph):
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
            wire.encode_reading(parts, seen)
        except (TypeError, ValueError, KeyError):
            unencodable += 1
            expected.append(None)
            continue
        expected.append(wire.route_node(graph, args.route_node, seen) or "(no match)")

    exp_routes = [route for route in expected if route is not None]
    got_routes = [str(ev.get(args.route_field, "(absent)")) for ev in decoded]

    identity = None
    if args.id_field:
        decoded_id_field = args.decoded_id_field or args.id_field.split(".")[-1]
        raw_ids = [_lookup(ev, args.id_field) for ev, route in zip(raw, expected) if route is not None]
        decoded_ids = [ev.get(decoded_id_field) for ev in decoded]
        identity = _compare_identities(raw_ids, decoded_ids)

    mismatches: List[dict] = []
    for position, (expected_route, decoded_route) in enumerate(zip(exp_routes, got_routes)):
        if expected_route != decoded_route and len(mismatches) < 10:
            mismatches.append({"position": position, "expected": expected_route, "decoded": decoded_route})
    count_drift = len(exp_routes) - len(got_routes)
    exp_dist, got_dist = Counter(exp_routes), Counter(got_routes)
    ok = not mismatches and count_drift == 0 and exp_dist == got_dist \
        and len(exp_routes) > 0 and raw_bad == 0 and dec_bad == 0 \
        and (identity is None or identity["ok"])

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
        for mismatch in mismatches:
            md.append(f"- event {mismatch['position']}: raw leg routes `{mismatch['expected']}`, "
                      f"decoded leg carried `{mismatch['decoded']}`")
        md.append("")
    if identity is not None:
        md.append(f"**IDENTITY** (strict mode on `{args.id_field}`): "
                  + ("every decoded event is the raw event at the same position, none lost, none duplicated."
                     if identity["ok"] else
                     f"{len(identity['missing'])} lost, {len(identity['duplicated'])} duplicated, "
                     f"{identity['unidentified']} without identity, {identity['reordered']} out of sequence."))
        for identifier in identity["missing"][:10]:
            md.append(f"- raw event `{identifier}` has no decoded twin")
        for identifier in identity["duplicated"][:10]:
            md.append(f"- decoded identity `{identifier}` appears more than once")
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
            "mismatches": mismatches, "identity": identity, "parity": ok}, indent=1) + "\n")
        print(f"\nwrote {args.json_out}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
