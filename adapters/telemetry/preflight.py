#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""prismpath-preflight: will YOUR events survive the Facet codec? One command, one report.

Point it at a policy flow and a sample of your real events (NDJSON, one JSON object per line) and it
answers the adoption questions before you touch a Vector config: which fields the flow makes
decision-relevant (the codebook), how many of your events encode cleanly and exactly why the rest do
not, what the wire will cost per event next to your raw JSON, and how your traffic distributes over
the flow's routes. It also replays every encodable event through the full round trip
(quantize, Fibonacci-code, decode, reconstruct) and verifies the representative routes identically
to the original at every decision node, so "decision preserving" is checked on your data, not ours.

This is the same reference implementation the Vector codec is parity-tested against, with the same
semantics: `field_paths` mapping (--map), `on_missing` error|skip, one byte-aligned reading per
frame, and integer truncation on numeric fields (a value 21.7 compares as 21; the report counts how
often that bites your sample).

Usage:
  preflight.py FLOW.md SAMPLE.ndjson [--map FIELD=PATH ...] [--on-missing error|skip]
               [--route-node NODE] [--limit N] [--json OUT.json]

Exit status: 0 = ready (everything encodable, routes preserved), 1 = findings need attention.
"""
from __future__ import annotations

import argparse
import itertools
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent.parent))              # repo root, for prismpath

import packed  # noqa: E402
import quantizer as q  # noqa: E402
import wire as w  # noqa: E402
from prismpath.parser import parse_file  # noqa: E402


# ----------------------------------------------------------------- event -> reading
def _walk_path(obj: Any, path: str) -> Tuple[bool, Any]:
    """Dot-path lookup into a parsed JSON object: (found, value). Mirrors the codec's
    `parse_path_and_get_value`; a JSON null counts as missing, exactly as the codec treats it."""
    cur = obj
    for part in path.lstrip(".").split("."):
        if not isinstance(cur, dict) or part not in cur:
            return False, None
        cur = cur[part]
    if cur is None:
        return False, None
    return True, cur


def extract_reading(event: dict, fields: List[str], field_paths: Dict[str, str]
                    ) -> Tuple[Dict[str, Any], List[str]]:
    """(reading, missing_fields) for one event, honoring --map exactly as the codec honors
    `field_paths`."""
    reading: Dict[str, Any] = {}
    missing: List[str] = []
    for f in fields:
        found, value = _walk_path(event, field_paths.get(f, f))
        if found:
            reading[f] = value
        else:
            missing.append(f)
    return reading, missing


def _codec_view(parts: Dict[str, q.FieldPartition], reading: Dict[str, Any]
                ) -> Tuple[Dict[str, Any], List[str]]:
    """The reading as the codec compares it (numeric fields truncate to int); also returns which
    fields lost a fractional part, since that truncation can flip a threshold."""
    seen: Dict[str, Any] = {}
    truncated: List[str] = []
    for f, v in reading.items():
        p = parts[f]
        if p.kind == "numeric":
            iv = int(v)
            if isinstance(v, float) and iv != v:
                truncated.append(f)
            seen[f] = iv
        else:
            seen[f] = v
    return seen, truncated


# ----------------------------------------------------------------- report pieces
def _cells_desc(p: q.FieldPartition) -> str:
    if p.kind == "numeric":
        spans = []
        for c in p.cells:
            lo = "-inf" if c["lo"] is None else str(c["lo"])
            hi = "+inf" if c["hi"] is None else str(c["hi"])
            spans.append(f"[{lo}..{hi}]")
        return " ".join(spans)
    if p.kind == "boolean":
        return "[false] [true]"
    consts = [repr(c["const"]) for c in p.cells if "const" in c and c["const"] != q._OTHER]
    return " ".join(f"[{c}]" for c in consts) + " [other]"


def _pct(part: int, whole: int) -> str:
    return f"{100.0 * part / whole:.1f}%" if whole else "n/a"


# ----------------------------------------------------------------- privacy (measured, not asserted)
def _reconstruction_bound(p: q.FieldPartition) -> dict:
    """How precisely a raw reading is recoverable from the cell the wire carries. Privacy by
    information loss: the wider the cells, the less an observer (even one holding the policy) can
    recover. This measures it per field instead of asserting it."""
    if p.kind == "boolean":
        return {"kind": "boolean", "leak": "exact",
                "note": "exact (1 bit): a boolean has no hidden information, the cell IS the value"}
    if p.kind == "categorical":
        enumerated = sum(1 for c in p.cells if c.get("const", q._OTHER) != q._OTHER)
        return {"kind": "categorical", "leak": "mixed", "exact_values": enumerated,
                "note": f"{enumerated} enumerated values exact; every other value collapses to the "
                        f"'other' cell (an unbounded set, unrecoverable)"}
    widths, unbounded, singletons = [], 0, 0
    for c in p.cells:
        lo, hi = c["lo"], c["hi"]
        if lo is None or hi is None:
            unbounded += 1
        else:
            w = hi - lo + 1
            widths.append(w)
            if w == 1:
                singletons += 1
    max_w = max(widths) if widths else None
    leak = "coarse" if unbounded == p.n else "exact" if singletons == p.n else "bounded"
    if max_w is None:
        note = "only a >=/< threshold is learned (all cells unbounded); the value is not recoverable"
    else:
        parts_note = [f"recoverable to +/- {max_w} at worst (widest bounded cell)"]
        if singletons:
            parts_note.append(f"{singletons} cell(s) exact (leak the value)")
        if unbounded:
            parts_note.append(f"{unbounded} unbounded cell(s) (only a threshold learned)")
        note = "; ".join(parts_note)
    return {"kind": "numeric", "leak": leak, "max_bounded_width": max_w,
            "unbounded_cells": unbounded, "singleton_cells": singletons, "note": note}


def _aggregation_privacy(graph, parts, order, branch_nodes, cap: int = 200_000) -> dict:
    """How many joint input cell-tuples produce each route at each decision node. A verdict
    produced by many input tuples hides which inputs made it (high privacy); one produced by a
    single tuple pins the inputs (a leak). Information-theoretic: holds even against a policy
    holder, because a many-to-one fusion genuinely destroys which-input information."""
    total = 1
    for f in order:
        total *= parts[f].n
    if total > cap:
        return {"joint_cells": total, "enumerated": False}
    per_node: Dict[str, Counter] = {n: Counter() for n in branch_nodes}
    for combo in itertools.product(*[range(parts[f].n) for f in order]):
        reading = {f: parts[f].representative(combo[i]) for i, f in enumerate(order)}
        for n in branch_nodes:
            per_node[n][w.route_node(graph, n, reading) or "(no match)"] += 1
    return {"joint_cells": total, "enumerated": True,
            "per_node": {n: dict(c) for n, c in per_node.items()}}


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="prismpath-preflight",
        description="Report how a sample of real events fares under the Facet codec for a given flow.")
    ap.add_argument("flow", help="policy flow (.md) the codebook derives from")
    ap.add_argument("sample", help="sample events, NDJSON (one JSON object per line); '-' for stdin")
    ap.add_argument("--map", action="append", default=[], metavar="FIELD=PATH",
                    help="map a flow field to a dot path in the event (repeatable); "
                         "same as the codec's field_paths")
    ap.add_argument("--on-missing", choices=("error", "skip"), default="error",
                    help="codec behavior for events missing a decision field (default: error)")
    ap.add_argument("--route-node", default=None,
                    help="report the route distribution from this node only (default: every "
                         "decision node)")
    ap.add_argument("--limit", type=int, default=None, metavar="N",
                    help="scan at most N events")
    ap.add_argument("--privacy", action="store_true",
                    help="add a privacy audit: per-field reconstruction bound and, for fusion "
                         "policies, how many joint input cells produce each verdict")
    ap.add_argument("--json", dest="json_out", default=None, metavar="OUT.json",
                    help="also write the full report as JSON")
    args = ap.parse_args()

    field_paths: Dict[str, str] = {}
    for m in args.map:
        if "=" not in m:
            ap.error(f"--map wants FIELD=PATH, got {m!r}")
        f, _, p = m.partition("=")
        field_paths[f] = p

    graph = parse_file(args.flow)
    parts = q.build_partitions(graph)
    if not parts:
        print(f"NOT READY: policy {args.flow!r} yields no decision-relevant fields "
              f"(no `field OP const` conditions on deterministic edges).")
        return 1
    order = sorted(parts.keys())

    nodes = w.decision_nodes(graph)
    if args.route_node is not None:
        if args.route_node not in nodes:
            ap.error(f"--route-node {args.route_node!r} is not a decision node "
                     f"(decision nodes: {', '.join(nodes)})")
        nodes = [args.route_node]

    # ------------------------------------------------------------- scan the sample
    lines = sys.stdin if args.sample == "-" else open(args.sample, encoding="utf-8")
    n_lines = n_events = n_encoded = 0
    bad_json = 0
    missing_counts: Counter = Counter()          # field -> events missing it
    missing_events = 0
    out_of_partition: Counter = Counter()        # field -> events whose value fell outside
    oop_examples: Dict[str, Any] = {}
    truncated_counts: Counter = Counter()        # field -> events where int() dropped a fraction
    field_seen: Counter = Counter()              # field -> events where it was present
    raw_bytes = 0
    wire_bits = 0
    framed_bytes = 0
    route_dist: Dict[str, Counter] = {n: Counter() for n in nodes}
    mismatches: List[dict] = []
    non_decision_keys: Counter = Counter()

    try:
        for line in lines:
            line = line.strip()
            if not line:
                continue
            n_lines += 1
            if args.limit is not None and n_lines > args.limit:
                n_lines -= 1
                break
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                bad_json += 1
                continue
            if not isinstance(event, dict):
                bad_json += 1
                continue
            n_events += 1
            raw_bytes += len(line.encode("utf-8"))
            for k in event:
                if k not in parts and field_paths.get(k, k) not in parts:
                    non_decision_keys[k] += 1

            reading, missing = extract_reading(event, order, field_paths)
            field_seen.update(reading.keys())
            if missing:
                missing_events += 1
                missing_counts.update(missing)
                continue

            try:
                seen, truncated = _codec_view(parts, reading)
            except (TypeError, ValueError):
                for f in order:
                    if parts[f].kind == "numeric":
                        try:
                            int(reading[f])
                        except (TypeError, ValueError):
                            out_of_partition[f] += 1
                            oop_examples.setdefault(f, reading[f])
                continue
            truncated_counts.update(truncated)

            try:
                bits = w.encode_reading(parts, seen)
            except ValueError:
                for f in order:
                    try:
                        parts[f].symbol(seen[f])
                    except ValueError:
                        out_of_partition[f] += 1
                        oop_examples.setdefault(f, reading[f])
                continue
            n_encoded += 1
            wire_bits += len(bits)
            framed_bytes += len(packed.pack(bits, 8))    # the Vector wire: one byte-aligned reading per frame

            rep = w.decode_reading(parts, bits)
            for node in nodes:
                orig_t = w.route_node(graph, node, seen)
                rep_t = w.route_node(graph, node, rep)
                route_dist[node][orig_t or "(no match)"] += 1
                if orig_t != rep_t and len(mismatches) < 10:
                    mismatches.append({"node": node, "reading": reading,
                                       "original": orig_t, "representative": rep_t})
    finally:
        if lines is not sys.stdin:
            lines.close()

    unseen = [f for f in order if field_seen[f] == 0]
    codec_errors = missing_events if args.on_missing == "error" else 0
    ready = (n_encoded > 0 and not mismatches and not unseen
             and codec_errors == 0 and sum(out_of_partition.values()) == 0)

    # ------------------------------------------------------------- report
    md: List[str] = []
    md += [f"# prismpath-preflight: {Path(args.flow).name} x {n_events} events", ""]

    md += ["## Codebook (derived from the flow, nothing learned)", "",
           "| field | kind | cells | decision cells |", "|---|---|---|---|"]
    for f in order:
        p = parts[f]
        md.append(f"| `{f}` | {p.kind} | {p.n} | {_cells_desc(p)} |")
    cell_product = 1
    for f in order:
        cell_product *= parts[f].n
    md += ["", f"Wire order is sorted field names (zero header). {len(order)} fields, "
           f"{cell_product} joint cells: every event collapses to one of {cell_product} "
           f"decision-distinct messages.", ""]

    md += ["## Sample scan", "",
           f"- events read: {n_events}" + (f" (of {n_lines} lines; {bad_json} not a JSON object)"
                                           if bad_json else ""),
           f"- encoded cleanly: {n_encoded} ({_pct(n_encoded, n_events)})"]
    if missing_events:
        detail = ", ".join(f"`{f}` x{c}" for f, c in missing_counts.most_common())
        verb = ("error (event dropped, error surfaced)" if args.on_missing == "error"
                else "skip (event silently dropped)")
        md.append(f"- missing decision fields: {missing_events} events -> on_missing={verb}: {detail}")
    if out_of_partition:
        for f, c in out_of_partition.most_common():
            md.append(f"- out of partition on `{f}`: {c} events "
                      f"(example value: {oop_examples[f]!r}) -> encoding error")
    if truncated_counts:
        detail = ", ".join(f"`{f}` x{c}" for f, c in truncated_counts.most_common())
        md.append(f"- float truncation: numeric fields compare on int(value); affected: {detail} "
                  f"(a 21.7 routes as 21; make thresholds integer-aware or scale the field)")
    if unseen:
        md.append(f"- NEVER SEEN in the sample: {', '.join(f'`{f}`' for f in unseen)} "
                  f"(is the field name right? try --map FIELD=your.json.path)")
    md.append("")

    if n_encoded:
        md += ["## Wire cost (projected)", "",
               "| | bytes/event |", "|---|---|",
               f"| raw NDJSON (your sample) | {raw_bytes / n_events:.3f} |",
               f"| Facet, framed (one reading per frame, as the Vector codec sends) "
               f"| {framed_bytes / n_encoded:.3f} |",
               f"| Facet, continuous stream (no per event alignment) "
               f"| {wire_bits / 8 / n_encoded:.3f} |", "",
               f"Projected shrink: **{raw_bytes / n_events / (framed_bytes / n_encoded):.1f}x** "
               f"framed, {raw_bytes / n_events / (wire_bits / 8 / n_encoded):.1f}x continuous. "
               f"Framing (length_delimited) and transport headers are extra on both sides of the "
               f"comparison.", ""]

        md += ["## Decision preservation (round trip on your events)", ""]
        if mismatches:
            md.append(f"**{len(mismatches)}+ MISMATCHES** (original vs reconstructed route "
                      f"differs) - this should never happen; please report it with the flow + "
                      f"offending readings below:")
            for m in mismatches:
                md.append(f"- node `{m['node']}`: {m['original']} vs {m['representative']} "
                          f"on {json.dumps(m['reading'])}")
        else:
            checks = n_encoded * len(nodes)
            md.append(f"{checks} route checks ({n_encoded} events x {len(nodes)} decision "
                      f"nodes): reconstructed representative routes **identically** to the "
                      f"original every time.")
        md.append("")

        branch_nodes = [n for n in nodes
                        if len({t for t, _c in graph.nodes[n].edges}) > 1] or nodes
        md += ["## Route distribution"
               + (" (pass-through nodes omitted)" if len(branch_nodes) < len(nodes) else ""), ""]
        for node in branch_nodes:
            md += [f"from `{node}`:", ""]
            for target, c in route_dist[node].most_common():
                md.append(f"- `{target}`: {c} ({_pct(c, n_encoded)})")
            md.append("")
        only_route = [n for n in branch_nodes
                      if len(route_dist[n]) == 1 and "(no match)" not in route_dist[n]]
        if only_route and n_encoded >= 20:
            md.append(f"Note: {', '.join(f'`{n}`' for n in only_route)} routed every sample event "
                      f"the same way. Fine if the sample is quiet; if it should discriminate, "
                      f"check the thresholds against the sample's value range.")
            md.append("")

    if non_decision_keys:
        top = ", ".join(f"`{k}`" for k, _ in non_decision_keys.most_common(12))
        md += ["## Not transmitted", "",
               f"Event keys with no decision role in this flow (they cost 0 bytes on the wire and "
               f"are not reconstructable from it): {top}"
               + (" ..." if len(non_decision_keys) > 12 else ""), ""]

    recon = agg = None
    if args.privacy:
        recon = {f: _reconstruction_bound(parts[f]) for f in order}
        branch = [n for n in nodes if len({t for t, _c in graph.nodes[n].edges}) > 1]
        agg = _aggregation_privacy(graph, parts, order, branch) if branch else None
        md += ["## Privacy audit", "",
               "**Scope: this bounds what a single decision reveals about field _values_. It does "
               "not measure what the decision _stream_ reveals over time.** Timing, activity level, "
               "and state transition patterns are a behavioral signal that survives coarse cells, so "
               "read the numbers below as a value reconstruction bound, not a claim that the stream "
               "is private.", "",
               "### Reconstruction bound (measured, not asserted)", "",
               "How precisely a raw reading is recoverable from what the wire carries. Information "
               "loss: coarse cells hide, singleton cells leak.", "",
               "| field | recoverable to |", "|---|---|"]
        for f in order:
            md.append(f"| `{f}` | {recon[f]['note']} |")
        md.append("")
        if agg and agg["enumerated"]:
            md += ["### Aggregation (how much a verdict hides its inputs)", "",
                   f"Across {agg['joint_cells']} joint input cells, how many produce each verdict. "
                   "A verdict produced by many input cells hides which inputs made it (information "
                   "theoretic, holds even against a policy holder); one produced by a single cell "
                   "pins the inputs.", ""]
            for n, per in agg["per_node"].items():
                if len(per) <= 1:
                    continue
                md.append(f"from `{n}`:")
                worst = min(per.values())
                for route, cnt in sorted(per.items(), key=lambda kv: -kv[1]):
                    md.append(f"- `{route}`: consistent with {cnt} of {agg['joint_cells']} input "
                              f"cells{'  <-- most revealing' if cnt == worst else ''}")
                md.append("")
        elif agg and not agg["enumerated"]:
            md += ["### Aggregation", "",
                   f"Joint input space is {agg['joint_cells']} cells, too large to enumerate here "
                   "(a coarse policy would be small; a large space means fine cells, which leak "
                   "more, not less).", ""]

    md += ["## Verdict", ""]
    if ready:
        skipped = (f" ({missing_events} skipped by on_missing=skip)"
                   if args.on_missing == "skip" and missing_events else "")
        md.append(f"**READY.** {n_encoded} of {n_events} events encode{skipped}, "
                  f"every route is preserved. "
                  f"Vector config: `encoding.codec = \"facet\"` + `encoding.policy = "
                  f"\"{args.flow}\"` on the sink; `decoding.codec = \"facet\"` + "
                  f"`framing.method = \"length_delimited\"` on the source.")
    else:
        md.append("**NOT READY** until the findings above are addressed "
                  "(missing or never-seen fields usually mean a --map is needed; out of "
                  "partition values mean the flow's thresholds do not cover the field's range).")
    print("\n".join(md))

    if args.json_out:
        report = {
            "flow": args.flow, "sample": args.sample,
            "field_paths": field_paths, "on_missing": args.on_missing,
            "codebook": {f: {"kind": parts[f].kind, "cells": parts[f].n,
                             "desc": _cells_desc(parts[f])} for f in order},
            "joint_cells": cell_product,
            "events": n_events, "bad_json": bad_json, "encoded": n_encoded,
            "missing_events": missing_events, "missing_by_field": dict(missing_counts),
            "out_of_partition": dict(out_of_partition),
            "float_truncated_by_field": dict(truncated_counts),
            "fields_never_seen": unseen,
            "raw_bytes_per_event": raw_bytes / n_events if n_events else None,
            "framed_bytes_per_event": framed_bytes / n_encoded if n_encoded else None,
            "stream_bytes_per_event": wire_bits / 8 / n_encoded if n_encoded else None,
            "route_distribution": {n: dict(c) for n, c in route_dist.items()},
            "route_mismatches": mismatches,
            "non_decision_keys": dict(non_decision_keys),
            "ready": ready,
        }
        if args.privacy:
            report["privacy_scope"] = ("per-decision field-value recoverability only; does NOT "
                                       "measure stream/behavioral leakage (timing, activity level, "
                                       "state-transition patterns)")
            report["privacy_reconstruction"] = recon
            report["privacy_aggregation"] = agg
        Path(args.json_out).write_text(json.dumps(report, indent=1) + "\n")
        print(f"\nwrote {args.json_out}")

    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
