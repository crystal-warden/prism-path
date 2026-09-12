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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
try:
    import prismpath  # noqa: F401  installed or already on the path: leave sys.path alone
except ImportError:  # run as a loose script from a clone: make the repo root importable
    sys.path.insert(0, str(HERE.parent.parent))

from prismpath.telemetry import packed  # noqa: E402
from prismpath.telemetry import quantizer  # noqa: E402
from prismpath.telemetry import wire  # noqa: E402
from prismpath.kernel.parser import parse_file  # noqa: E402


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
    for field in fields:
        found, value = _walk_path(event, field_paths.get(field, field))
        if found:
            reading[field] = value
        else:
            missing.append(field)
    return reading, missing


def _codec_view(parts: Dict[str, quantizer.FieldPartition], reading: Dict[str, Any]
                ) -> Tuple[Dict[str, Any], List[str]]:
    """The reading as the codec compares it (numeric fields truncate to int); also returns which
    fields lost a fractional part, since that truncation can flip a threshold."""
    seen: Dict[str, Any] = {}
    truncated: List[str] = []
    for field, value in reading.items():
        partition = parts[field]
        if partition.kind == "numeric":
            int_val = int(value)
            if isinstance(value, float) and int_val != value:
                truncated.append(field)
            seen[field] = int_val
        else:
            seen[field] = value
    return seen, truncated


# ----------------------------------------------------------------- report pieces
def _cells_desc(partition: quantizer.FieldPartition) -> str:
    if partition.kind == "numeric":
        spans = []
        for cell in partition.cells:
            lo_val = "-inf" if cell["lo"] is None else str(cell["lo"])
            hi_val = "+inf" if cell["hi"] is None else str(cell["hi"])
            spans.append(f"[{lo_val}..{hi_val}]")
        return " ".join(spans)
    if partition.kind == "boolean":
        return "[false] [true]"
    consts = [repr(cell["const"]) for cell in partition.cells if "const" in cell and cell["const"] != quantizer._OTHER]
    return " ".join(f"[{const_val}]" for const_val in consts) + " [other]"


def _pct(part: int, whole: int) -> str:
    return f"{100.0 * part / whole:.1f}%" if whole else "n/a"


# ----------------------------------------------------------------- privacy (measured, not asserted)
def _reconstruction_bound(partition: quantizer.FieldPartition) -> dict:
    """How precisely a raw reading is recoverable from the cell the wire carries. Privacy by
    information loss: the wider the cells, the less an observer (even one holding the policy) can
    recover. This measures it per field instead of asserting it."""
    if partition.kind == "boolean":
        return {"kind": "boolean", "leak": "exact",
                "note": "exact (1 bit): a boolean has no hidden information, the cell IS the value"}
    if partition.kind == "categorical":
        enumerated = sum(1 for cell in partition.cells if cell.get("const", quantizer._OTHER) != quantizer._OTHER)
        return {"kind": "categorical", "leak": "mixed", "exact_values": enumerated,
                "note": f"{enumerated} enumerated values exact; every other value collapses to the "
                        f"'other' cell (an unbounded set, unrecoverable)"}
    widths, unbounded, singletons = [], 0, 0
    for cell in partition.cells:
        lo_val, hi_val = cell["lo"], cell["hi"]
        if lo_val is None or hi_val is None:
            unbounded += 1
        else:
            width = hi_val - lo_val + 1
            widths.append(width)
            if width == 1:
                singletons += 1
    max_w = max(widths) if widths else None
    leak = "coarse" if unbounded == partition.n else "exact" if singletons == partition.n else "bounded"
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


def _aggregation_privacy(graph: Any, parts: Dict[str, quantizer.FieldPartition],
                         order: List[str], branch_nodes: List[str], cap: int = 200_000) -> dict:
    """How many joint input cell-tuples produce each route at each decision node. A verdict
    produced by many input tuples hides which inputs made it (high privacy); one produced by a
    single tuple pins the inputs (a leak). Information-theoretic: holds even against a policy
    holder, because a many-to-one fusion genuinely destroys which-input information."""
    total = 1
    for field in order:
        total *= parts[field].n
    if total > cap:
        return {"joint_cells": total, "enumerated": False}
    per_node: Dict[str, Counter] = {node: Counter() for node in branch_nodes}
    for combo in itertools.product(*[range(parts[field].n) for field in order]):
        reading = {field: parts[field].representative(combo[idx]) for idx, field in enumerate(order)}
        for node in branch_nodes:
            per_node[node][wire.route_node(graph, node, reading) or "(no match)"] += 1
    return {"joint_cells": total, "enumerated": True,
            "per_node": {node: dict(counter) for node, counter in per_node.items()}}


@dataclass
class ScanResult:
    """Encapsulates telemetry preflight sample scan results for report rendering."""

    flow: str
    sample: str
    parts: Dict[str, quantizer.FieldPartition]
    order: List[str]
    graph: Any
    nodes: List[str]
    field_paths: Dict[str, str]
    on_missing: str
    privacy: bool
    n_lines: int
    n_events: int
    bad_json: int
    n_encoded: int
    missing_events: int
    missing_counts: Counter
    out_of_partition: Counter
    oop_examples: Dict[str, Any]
    truncated_counts: Counter
    field_seen: Counter
    raw_bytes: int
    wire_bits: int
    framed_bytes: int
    route_dist: Dict[str, Counter]
    mismatches: List[dict]
    non_decision_keys: Counter
    unseen: List[str]
    codec_errors: int
    ready: bool
    recon: Optional[Dict[str, dict]] = None
    agg: Optional[dict] = None


def scan_sample(
    parts: Dict[str, quantizer.FieldPartition],
    lines: Iterable[str],
    graph: Any,
    nodes: List[str],
    field_paths: Dict[str, str],
    on_missing: str = "error",
    limit: Optional[int] = None,
    privacy: bool = False,
    flow: str = "",
    sample: str = "",
) -> ScanResult:
    """Scans sample event lines against flow partitions and returns structured counters."""
    n_lines = 0
    n_events = 0
    n_encoded = 0
    bad_json = 0
    missing_counts: Counter = Counter()
    missing_events = 0
    out_of_partition: Counter = Counter()
    oop_examples: Dict[str, Any] = {}
    truncated_counts: Counter = Counter()
    field_seen: Counter = Counter()
    raw_bytes = 0
    wire_bits = 0
    framed_bytes = 0
    route_dist: Dict[str, Counter] = {node: Counter() for node in nodes}
    mismatches: List[dict] = []
    non_decision_keys: Counter = Counter()

    order = sorted(parts.keys())

    for line in lines:
        line_str = line.strip()
        if not line_str:
            continue
        n_lines += 1
        if limit is not None and n_lines > limit:
            n_lines -= 1
            break
        try:
            event = json.loads(line_str)
        except json.JSONDecodeError:
            bad_json += 1
            continue
        if not isinstance(event, dict):
            bad_json += 1
            continue
        n_events += 1
        raw_bytes += len(line_str.encode("utf-8"))
        for key in event:
            if key not in parts and field_paths.get(key, key) not in parts:
                non_decision_keys[key] += 1

        reading, missing = extract_reading(event, order, field_paths)
        field_seen.update(reading.keys())
        if missing:
            missing_events += 1
            missing_counts.update(missing)
            continue

        try:
            seen, truncated = _codec_view(parts, reading)
        except (TypeError, ValueError):
            for field in order:
                if parts[field].kind == "numeric":
                    try:
                        int(reading[field])
                    except (TypeError, ValueError):
                        out_of_partition[field] += 1
                        oop_examples.setdefault(field, reading[field])
            continue
        truncated_counts.update(truncated)

        try:
            bits = wire.encode_reading(parts, seen)
        except ValueError:
            for field in order:
                try:
                    parts[field].symbol(seen[field])
                except ValueError:
                    out_of_partition[field] += 1
                    oop_examples.setdefault(field, reading[field])
            continue
        n_encoded += 1
        wire_bits += len(bits)
        framed_bytes += len(packed.pack(bits, 8))

        rep = wire.decode_reading(parts, bits)
        for node in nodes:
            orig_target = wire.route_node(graph, node, seen)
            rep_target = wire.route_node(graph, node, rep)
            route_dist[node][orig_target or "(no match)"] += 1
            if orig_target != rep_target and len(mismatches) < 10:
                mismatches.append({"node": node, "reading": reading,
                                   "original": orig_target, "representative": rep_target})

    unseen = [field for field in order if field_seen[field] == 0]
    codec_errors = missing_events if on_missing == "error" else 0
    ready = (n_encoded > 0 and not mismatches and not unseen
             and codec_errors == 0 and sum(out_of_partition.values()) == 0)

    recon = None
    agg = None
    if privacy:
        recon = {field: _reconstruction_bound(parts[field]) for field in order}
        branch_nodes = [node for node in nodes
                        if len({target for target, _condition in graph.nodes[node].edges}) > 1]
        agg = _aggregation_privacy(graph, parts, order, branch_nodes) if branch_nodes else None

    return ScanResult(
        flow=flow,
        sample=sample,
        parts=parts,
        order=order,
        graph=graph,
        nodes=nodes,
        field_paths=field_paths,
        on_missing=on_missing,
        privacy=privacy,
        n_lines=n_lines,
        n_events=n_events,
        bad_json=bad_json,
        n_encoded=n_encoded,
        missing_events=missing_events,
        missing_counts=missing_counts,
        out_of_partition=out_of_partition,
        oop_examples=oop_examples,
        truncated_counts=truncated_counts,
        field_seen=field_seen,
        raw_bytes=raw_bytes,
        wire_bits=wire_bits,
        framed_bytes=framed_bytes,
        route_dist=route_dist,
        mismatches=mismatches,
        non_decision_keys=non_decision_keys,
        unseen=unseen,
        codec_errors=codec_errors,
        ready=ready,
        recon=recon,
        agg=agg,
    )


def render_markdown(result: ScanResult) -> str:
    """Renders the Markdown report section text from scan results."""
    md: List[str] = []
    md += [f"# prismpath-preflight: {Path(result.flow).name} x {result.n_events} events", ""]

    md += ["## Codebook (derived from the flow, nothing learned)", "",
           "| field | kind | cells | decision cells |", "|---|---|---|---|"]
    for field in result.order:
        partition = result.parts[field]
        md.append(f"| `{field}` | {partition.kind} | {partition.n} | {_cells_desc(partition)} |")
    cell_product = 1
    for field in result.order:
        cell_product *= result.parts[field].n
    md += ["", f"Wire order is sorted field names (zero header). {len(result.order)} fields, "
           f"{cell_product} joint cells: every event collapses to one of {cell_product} "
           f"decision-distinct messages.", ""]

    md += ["## Sample scan", "",
           f"- events read: {result.n_events}" + (f" (of {result.n_lines} lines; {result.bad_json} not a JSON object)"
                                                   if result.bad_json else ""),
           f"- encoded cleanly: {result.n_encoded} ({_pct(result.n_encoded, result.n_events)})"]
    if result.missing_events:
        detail = ", ".join(f"`{field}` x{count}" for field, count in result.missing_counts.most_common())
        verb = ("error (event dropped, error surfaced)" if result.on_missing == "error"
                else "skip (event silently dropped)")
        md.append(f"- missing decision fields: {result.missing_events} events -> on_missing={verb}: {detail}")
    if result.out_of_partition:
        for field, count in result.out_of_partition.most_common():
            md.append(f"- out of partition on `{field}`: {count} events "
                      f"(example value: {result.oop_examples[field]!r}) -> encoding error")
    if result.truncated_counts:
        detail = ", ".join(f"`{field}` x{count}" for field, count in result.truncated_counts.most_common())
        md.append(f"- float truncation: numeric fields compare on int(value); affected: {detail} "
                  f"(a 21.7 routes as 21; make thresholds integer-aware or scale the field)")
    if result.unseen:
        md.append(f"- NEVER SEEN in the sample: {', '.join(f'`{field}`' for field in result.unseen)} "
                  f"(is the field name right? try --map FIELD=your.json.path)")
    md.append("")

    if result.n_encoded:
        md += ["## Wire cost (projected)", "",
               "| | bytes/event |", "|---|---|",
               f"| raw NDJSON (your sample) | {result.raw_bytes / result.n_events:.3f} |",
               f"| Facet, framed (one reading per frame, as the Vector codec sends) "
               f"| {result.framed_bytes / result.n_encoded:.3f} |",
               f"| Facet, continuous stream (no per event alignment) "
               f"| {result.wire_bits / 8 / result.n_encoded:.3f} |", "",
               f"Projected shrink: **{result.raw_bytes / result.n_events / (result.framed_bytes / result.n_encoded):.1f}x** "
               f"framed, {result.raw_bytes / result.n_events / (result.wire_bits / 8 / result.n_encoded):.1f}x continuous. "
               f"Framing (length_delimited) and transport headers are extra on both sides of the "
               f"comparison.", ""]

        md += ["## Decision preservation (round trip on your events)", ""]
        if result.mismatches:
            md.append(f"**{len(result.mismatches)}+ MISMATCHES** (original vs reconstructed route "
                      f"differs) - this should never happen; please report it with the flow + "
                      f"offending readings below:")
            for mismatch in result.mismatches:
                md.append(f"- node `{mismatch['node']}`: {mismatch['original']} vs {mismatch['representative']} "
                          f"on {json.dumps(mismatch['reading'])}")
        else:
            checks = result.n_encoded * len(result.nodes)
            md.append(f"{checks} route checks ({result.n_encoded} events x {len(result.nodes)} decision "
                      f"nodes): reconstructed representative routes **identically** to the "
                      f"original every time.")
        md.append("")

        branch_nodes = [node for node in result.nodes
                        if len({target for target, _condition in result.graph.nodes[node].edges}) > 1] or result.nodes
        md += ["## Route distribution"
               + (" (pass-through nodes omitted)" if len(branch_nodes) < len(result.nodes) else ""), ""]
        for node in branch_nodes:
            md += [f"from `{node}`:", ""]
            for target, count in result.route_dist[node].most_common():
                md.append(f"- `{target}`: {count} ({_pct(count, result.n_encoded)})")
            md.append("")
        only_route = [node for node in branch_nodes
                      if len(result.route_dist[node]) == 1 and "(no match)" not in result.route_dist[node]]
        if only_route and result.n_encoded >= 20:
            md.append(f"Note: {', '.join(f'`{node}`' for node in only_route)} routed every sample event "
                      f"the same way. Fine if the sample is quiet; if it should discriminate, "
                      f"check the thresholds against the sample's value range.")
            md.append("")

    if result.non_decision_keys:
        top = ", ".join(f"`{key}`" for key, _ in result.non_decision_keys.most_common(12))
        md += ["## Not transmitted", "",
               f"Event keys with no decision role in this flow (they cost 0 bytes on the wire and "
               f"are not reconstructable from it): {top}"
               + (" ..." if len(result.non_decision_keys) > 12 else ""), ""]

    if result.privacy:
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
        for field in result.order:
            md.append(f"| `{field}` | {result.recon[field]['note']} |")
        md.append("")
        if result.agg and result.agg["enumerated"]:
            md += ["### Aggregation (how much a verdict hides its inputs)", "",
                   f"Across {result.agg['joint_cells']} joint input cells, how many produce each verdict. "
                   "A verdict produced by many input cells hides which inputs made it (information "
                   "theoretic, holds even against a policy holder); one produced by a single cell "
                   "pins the inputs.", ""]
            for node, per in result.agg["per_node"].items():
                if len(per) <= 1:
                    continue
                md.append(f"from `{node}`:")
                worst = min(per.values())
                for route, count in sorted(per.items(), key=lambda kv: -kv[1]):
                    md.append(f"- `{route}`: consistent with {count} of {result.agg['joint_cells']} input "
                              f"cells{'  <-- most revealing' if count == worst else ''}")
                md.append("")
        elif result.agg and not result.agg["enumerated"]:
            md += ["### Aggregation", "",
                   f"Joint input space is {result.agg['joint_cells']} cells, too large to enumerate here "
                   "(a coarse policy would be small; a large space means fine cells, which leak "
                   "more, not less).", ""]

    md += ["## Verdict", ""]
    if result.ready:
        skipped = (f" ({result.missing_events} skipped by on_missing=skip)"
                   if result.on_missing == "skip" and result.missing_events else "")
        md.append(f"**READY.** {result.n_encoded} of {result.n_events} events encode{skipped}, "
                  f"every route is preserved. "
                  f"Vector config: `encoding.codec = \"facet\"` + `encoding.policy = "
                  f"\"{result.flow}\"` on the sink; `decoding.codec = \"facet\"` + "
                  f"`framing.method = \"length_delimited\"` on the source.")
    else:
        md.append("**NOT READY** until the findings above are addressed "
                  "(missing or never-seen fields usually mean a --map is needed; out of "
                  "partition values mean the flow's thresholds do not cover the field's range).")
    return "\n".join(md)


def render_json(result: ScanResult) -> Dict[str, Any]:
    """Renders the JSON report structure dictionary from scan results."""
    cell_product = 1
    for field in result.order:
        cell_product *= result.parts[field].n

    report = {
        "flow": result.flow,
        "sample": result.sample,
        "field_paths": result.field_paths,
        "on_missing": result.on_missing,
        "codebook": {field: {"kind": result.parts[field].kind, "cells": result.parts[field].n,
                             "desc": _cells_desc(result.parts[field])} for field in result.order},
        "joint_cells": cell_product,
        "events": result.n_events,
        "bad_json": result.bad_json,
        "encoded": result.n_encoded,
        "missing_events": result.missing_events,
        "missing_by_field": dict(result.missing_counts),
        "out_of_partition": dict(result.out_of_partition),
        "float_truncated_by_field": dict(result.truncated_counts),
        "fields_never_seen": result.unseen,
        "raw_bytes_per_event": result.raw_bytes / result.n_events if result.n_events else None,
        "framed_bytes_per_event": result.framed_bytes / result.n_encoded if result.n_encoded else None,
        "stream_bytes_per_event": result.wire_bits / 8 / result.n_encoded if result.n_encoded else None,
        "route_distribution": {node: dict(counter) for node, counter in result.route_dist.items()},
        "route_mismatches": result.mismatches,
        "non_decision_keys": dict(result.non_decision_keys),
        "ready": result.ready,
    }
    if result.privacy:
        report["privacy_scope"] = ("per-decision field-value recoverability only; does NOT "
                                   "measure stream/behavioral leakage (timing, activity level, "
                                   "state-transition patterns)")
        report["privacy_reconstruction"] = result.recon
        report["privacy_aggregation"] = result.agg
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="prismpath-preflight",
        description="Report how a sample of real events fares under the Facet codec for a given flow.")
    parser.add_argument("flow", help="policy flow (.md) the codebook derives from")
    parser.add_argument("sample", help="sample events, NDJSON (one JSON object per line); '-' for stdin")
    parser.add_argument("--map", action="append", default=[], metavar="FIELD=PATH",
                        help="map a flow field to a dot path in the event (repeatable); "
                             "same as the codec's field_paths")
    parser.add_argument("--on-missing", choices=("error", "skip"), default="error",
                        help="codec behavior for events missing a decision field (default: error)")
    parser.add_argument("--route-node", default=None,
                        help="report the route distribution from this node only (default: every "
                             "decision node)")
    parser.add_argument("--limit", type=int, default=None, metavar="N",
                        help="scan at most N events")
    parser.add_argument("--privacy", action="store_true",
                        help="add a privacy audit: per-field reconstruction bound and, for fusion "
                             "policies, how many joint input cells produce each verdict")
    parser.add_argument("--json", dest="json_out", default=None, metavar="OUT.json",
                        help="also write the full report as JSON")
    args = parser.parse_args()

    field_paths: Dict[str, str] = {}
    for mapping in args.map:
        if "=" not in mapping:
            parser.error(f"--map wants FIELD=PATH, got {mapping!r}")
        field, _, path = mapping.partition("=")
        field_paths[field] = path

    graph = parse_file(args.flow)
    parts = quantizer.build_partitions(graph)
    if not parts:
        print(f"NOT READY: policy {args.flow!r} yields no decision-relevant fields "
              f"(no `field OP const` conditions on deterministic edges).")
        return 1

    nodes = wire.decision_nodes(graph)
    if args.route_node is not None:
        if args.route_node not in nodes:
            parser.error(f"--route-node {args.route_node!r} is not a decision node "
                         f"(decision nodes: {', '.join(nodes)})")
        nodes = [args.route_node]

    lines = sys.stdin if args.sample == "-" else open(args.sample, encoding="utf-8")
    try:
        result = scan_sample(
            parts=parts,
            lines=lines,
            graph=graph,
            nodes=nodes,
            field_paths=field_paths,
            on_missing=args.on_missing,
            limit=args.limit,
            privacy=args.privacy,
            flow=args.flow,
            sample=args.sample,
        )
    finally:
        if lines is not sys.stdin:
            lines.close()

    print(render_markdown(result))

    if args.json_out:
        report_dict = render_json(result)
        Path(args.json_out).write_text(json.dumps(report_dict, indent=1) + "\n")
        print(f"\nwrote {args.json_out}")

    return 0 if result.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
