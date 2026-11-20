# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""What does Facet cost per decision across every policy the repository ships?

    PYTHONPATH=. python tools/facet_across_policies.py results/facet_across_policies_2026-11-20.json

Enumerates every tracked policy (Level M flow .md files and agent core images), builds each one's
codebook with quantizer.build_partitions, and costs it two ways.

Computed. Under PROTOCOL.md 2.2 a field's symbol s is sent as the Fibonacci (Zeckendorf) code of s + 1,
whose length is zeck_len(s + 1). So bits per decision = the sum over fields of zeck_len(symbol + 1).
That depends on which cells a population lands in. The computed figure assumes every cell of every field
is equally likely, so a field's expected bits is the mean of zeck_len(s + 1) over its cells. The O2 band
stream sends one code per decision node, zeck_len(band + 1), with a band weighted by its share of that
node's joint cells (SpiralLayout.band_width).

Measured. Real readings are encoded with wire.encode_reading, the bit length is checked against the
sum of code lengths, each stream is decoded and every decision node's route is compared with the engine's
route on the raw reading. Two populations: cells uniform, and a boundary mix (values at and next to every
cut, every named constant, a near miss string). Where the joint grid is small the whole grid is encoded
once, so the measured mean equals the computed mean exactly.

The integrity apparatus is counted by bandwidth._stream_stats, the same function that produced 1.516.
"""
import glob
import hashlib
import itertools
import json
import math
import random
import subprocess
import sys

sys.setrecursionlimit(100000)
from adapters.fusion.bench import bandwidth
from prismpath.kernel import core_render
from prismpath.kernel.parser import parse
from prismpath.telemetry import decode, quantizer, spiral, wire
from prismpath.telemetry import zeckendorf as zeck

N_EPOCH = 4096
N_PAPER = 64484
EXHAUSTIVE_LIMIT = 150_000
SPIRAL_LIMIT = 300_000
OTLP_FAITHFUL = 101.372
OTLP_ZSTD = 7.162
FUSION_PAPER = 1.516

_zl = {}


def zlen(n):
    v = _zl.get(n)
    if v is None:
        v = _zl[n] = len(zeck.encode(n))
    return v


def classify(path):
    if path.startswith(("prismpath/tests/fixtures/broken/",)):
        return "excluded-broken-fixture"
    if path.startswith("prismpath/tests/fixtures/agent_old_starters/"):
        return "excluded-retired-agent-image"
    if path.startswith(("docs/", "tools/", "SPEC.md", "GETTING_STARTED.md")) or path.endswith("/GETTING_STARTED.md"):
        return "docs-illustration"
    if path.startswith("decisions.json:"):
        return "conformance-corpus"
    if path.startswith("prismpath/tests/"):
        return "test-fixture"
    return "shipped"


def enumerate_policies(root="."):
    files = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout.split("\n")
    out = []
    for path in files:
        if path.endswith(".core.json"):
            text = open(path, encoding="utf-8").read()
            out.append({"path": path, "kind": "core-image", "raw": text,
                        "render": lambda t=text: core_render.render(json.loads(t))})
        elif path.endswith(".md") and not path.endswith((".tests.md", "README.md")):
            text = open(path, encoding="utf-8").read()
            head = text.split("\n---", 1)[0] if text.startswith("---") else ""
            if "\nstart:" in head:
                out.append({"path": path, "kind": "flow", "raw": text, "render": lambda t=text: t})
    for case in json.load(open("prismpath/telemetry/conformance/decisions.json"))["cases"]:
        out.append({"path": f"decisions.json:{case['name']}", "kind": "corpus-case",
                    "raw": case["flow"], "render": lambda t=case["flow"]: t})
    return out


def reachable(part):
    """(symbol, a raw value in that cell the encoder accepts) for every cell some admissible value falls in.
    An inferred field admits any integer or string, so every cell. A defined integer field admits only its
    declared range, so a cell wholly outside the range is never sent, and the value used is clamped into it."""
    d = part.definition
    out = []
    for s, c in enumerate(part.cells):
        if d is not None and part.kind == "numeric" and not c.get("absent"):
            lo = d.minimum if c["lo"] is None else max(c["lo"], d.minimum)
            hi = d.maximum if c["hi"] is None else min(c["hi"], d.maximum)
            if lo > hi:
                continue
            out.append((s, lo))
        else:
            out.append((s, c["rep"]))
    return out


def field_bits(part):
    reach = reachable(part)
    lens = [zlen(s + 1) for s, _ in reach]
    return {"cells": part.n, "reachable_cells": len(reach), "kind": part.kind, "mean_bits": sum(lens) / len(lens),
            "min_bits": min(lens), "max_bits": max(lens),
            "fixed_width_bits": math.ceil(math.log2(part.n)) if part.n > 1 else 0,
            "absent_cell": part.absent_symbol is not None}


def boundary_values(part):
    """Raw values at and next to every cut, for the boundary mix."""
    if part.kind == "boolean":
        vals = [False, True]
    elif part.kind == "categorical":
        consts = [c["const"] for c in part.cells if c.get("const") != quantizer.OTHER_CELL]
        vals = consts + [c + "~" for c in consts[:3]] + ["ünlisted"]
    else:
        vals = set()
        for c in part.cells:
            if c.get("absent"):
                continue
            for v in (c["lo"], c["hi"]):
                if v is not None:
                    vals.update((v - 1, v, v + 1))
        vals = sorted(vals) or [0]
    if part.definition is not None and part.definition.absent_allowed:
        vals = list(vals) + [None]
    return list(vals)


def route_map(graph, nodes, reading):
    return tuple(wire.route_node(graph, n, reading) for n in nodes)


def encode_checked(graph, parts, nodes, order, readings):
    """Encode, then check length, decode and routes. Returns (bit strings, refusals)."""
    bits_list, refused = [], 0
    for r in readings:
        try:
            syms = quantizer.checked_quantize(parts, r)
        except quantizer.InputRefused:
            refused += 1
            continue
        bits = wire.encode_reading(parts, r)
        assert len(bits) == sum(zlen(syms[f] + 1) for f in order), "bit length != sum of code lengths"
        back = wire.decode_reading(parts, bits)
        assert route_map(graph, nodes, back) == route_map(graph, nodes, r), "decision lost in round trip"
        assert {f: parts[f].symbol(back[f]) for f in order} == syms, "cells lost in round trip"
        bits_list.append(bits)
    return bits_list, refused


def stream(bits_list, n):
    reps = (bits_list * (n // len(bits_list) + 1))[:n]
    s = bandwidth._stream_stats(reps, n)
    return {"n": n, "payload_bits": s["payload_bits"], "payload_bits_per_decision": s["payload_bits"] / n,
            "pad_bits": s["pad_bits"], "epochs": s["epochs"], "wire_bytes": s["wire_bytes"],
            "merkle_chain_bytes": s["merkle_epoch_bytes"], "ack_bytes": s["ack_bytes"],
            "bytes_per_decision": s["bytes_per_alert"],
            "bytes_per_decision_with_ack": round((s["wire_bytes_total"] + s["ack_bytes"]) / n, 3)}


def computed_total(bits_mean, n):
    """Computed bytes per decision from a mean payload, with per-epoch byte padding, no population."""
    full, rest = divmod(n, N_EPOCH)
    wire_bytes = full * math.ceil(N_EPOCH * bits_mean / 8) + (math.ceil(rest * bits_mean / 8) if rest else 0)
    epochs = full + (1 if rest else 0)
    return {"n": n, "bytes_per_decision": round((wire_bytes + 64 * epochs) / n, 3),
            "bytes_per_decision_with_ack": round((wire_bytes + 96 * epochs) / n, 3),
            "epoch_overhead_share": round(64 * epochs / (wire_bytes + 64 * epochs), 4)}


def o2_stats(graph, nodes, parts, rng):
    """The band-ID stream. One band code per decision node; exact expectation over each node's joint cells."""
    per_node, total = [], 0.0
    for node in nodes:
        try:
            fields = spiral._node_fields(graph, node, parts)
            if not fields:
                continue
            grid = math.prod(parts[f].n for f in fields)
            if grid > SPIRAL_LIMIT:
                per_node.append({"node": node, "grid": grid, "skipped": "joint grid over limit"})
                return {"applies": False, "reason": f"node {node!r} joint grid {grid:,} cells exceeds {SPIRAL_LIMIT:,}", "nodes": per_node}
            lay = spiral.SpiralLayout(graph, node)
        except Exception as e:  # noqa: BLE001
            return {"applies": False, "reason": f"{type(e).__name__}: {str(e)[:100]}", "nodes": per_node}
        mean = sum(w * zlen(b + 1) for b, w in enumerate(lay.band_width)) / lay.size
        per_node.append({"node": node, "fields": fields, "joint_cells": lay.size, "bands": len(lay.routes),
                         "mean_bits": mean})
        total += mean
    if not per_node:
        return {"applies": False, "reason": "no node routes on a decision field", "nodes": []}
    big = max(per_node, key=lambda x: x["joint_cells"])
    return {"applies": True, "nodes": per_node, "mean_bits": total, "mean_bits_largest_node": big["mean_bits"],
            "largest_node": big["node"],
            "note": "mean_bits sums one band code per decision node; mean_bits_largest_node is the node with the most joint cells (the fusion paper's O2 is its correlate node)"}


def _accepted(parts, r):
    try:
        quantizer.checked_quantize(parts, r)
        yield True
    except quantizer.InputRefused:
        yield False


def measure(entry, graph, rng):
    parts = quantizer.build_partitions(graph)
    if not parts:
        return None, "no decision-relevant field: nothing for the codec to carry"
    nodes = wire.decision_nodes(graph)
    order = wire._order(parts)
    fb = {f: field_bits(parts[f]) for f in order}
    mean = sum(x["mean_bits"] for x in fb.values())
    grid = math.prod(x["cells"] for x in fb.values())
    rgrid = math.prod(x["reachable_cells"] for x in fb.values())
    reach = {f: reachable(parts[f]) for f in order}
    res = {"fields": len(order), "grid_cells": grid, "reachable_grid_cells": rgrid, "decision_nodes": nodes,
           "per_field": [{"field": f, **fb[f]} for f in order],
           "payload_bits_computed": {"expected_uniform_cells": mean,
                                     "min": sum(x["min_bits"] for x in fb.values()),
                                     "max": sum(x["max_bits"] for x in fb.values()),
                                     "fixed_width_reference": sum(x["fixed_width_bits"] for x in fb.values())},
           "computed_total": {str(n): computed_total(mean, n) for n in (N_EPOCH, N_PAPER)}}
    # --- measured, cells uniform
    exhaustive = rgrid <= EXHAUSTIVE_LIMIT
    if exhaustive:
        pop = [{f: v for f, v in zip(order, combo)}
               for combo in itertools.product(*[[v for _, v in reach[f]] for f in order])]
        bits_u, refused_u = encode_checked(graph, parts, nodes, order, pop)
        exact_mean = sum(map(len, bits_u)) / len(bits_u)
        assert abs(exact_mean - mean) < 1e-9, (entry["path"], exact_mean, mean)
        rng.shuffle(bits_u)
        res["uniform_population"] = {"method": "every joint cell once", "readings": len(bits_u),
                                     "mean_bits": exact_mean, "equals_computed": True, "refused": refused_u}
    else:
        pop = [{f: rng.choice(reach[f])[1] for f in order} for _ in range(N_PAPER)]
        bits_u, refused_u = encode_checked(graph, parts, nodes, order, pop)
        m = sum(map(len, bits_u)) / len(bits_u)
        res["uniform_population"] = {"method": f"{N_PAPER} readings, each field's cell uniform", "readings": len(bits_u),
                                     "mean_bits": m, "equals_computed": False,
                                     "gap_to_computed": m - mean, "refused": refused_u}
    res["measured_uniform"] = {str(n): stream(bits_u, n) for n in (N_EPOCH, N_PAPER)}
    # --- measured, boundary mix
    bv = {f: boundary_values(parts[f]) for f in order}
    pop = [{f: rng.choice(bv[f]) for f in order} for _ in range(N_PAPER)]
    bits_b, refused_b = encode_checked(graph, parts, nodes, order, pop)
    if bits_b:
        res["boundary_population"] = {"readings": len(bits_b), "refused": refused_b,
                                      "mean_bits": sum(map(len, bits_b)) / len(bits_b),
                                      "decode_checked": True}
        res["measured_boundary"] = {str(n): stream(bits_b, n) for n in (N_EPOCH, N_PAPER)}
    else:
        res["boundary_population"] = {"readings": 0, "refused": refused_b, "note": "every boundary reading refused"}
    # --- O2
    o2 = o2_stats(graph, nodes, parts, rng)
    if o2["applies"]:
        o2["computed_total"] = {str(n): computed_total(o2["mean_bits"], n) for n in (N_EPOCH, N_PAPER)}
        lays = {n["node"]: spiral.SpiralLayout(graph, n["node"]) for n in o2["nodes"]}
        sample = [r for r in pop[:N_EPOCH] if all(_accepted(parts, r))][:N_EPOCH]
        bits_o, ok = [], True
        for r in sample:
            code = "".join(lay.encode_decision(r) for lay in lays.values())
            bits_o.append(code)
            for node, lay in lays.items():
                ok &= lay.decode_decision(lay.encode_decision(r)) == wire.route_node(graph, node, r)
        if bits_o:
            o2["measured_boundary_n4096"] = stream(bits_o, N_EPOCH)
            o2["roundtrip_route_checked"] = {"readings": len(sample), "all_nodes_agree": bool(ok)}
    res["o2"] = o2
    return res, None


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else None
    rng = random.Random(20261120)
    entries = enumerate_policies()
    seen, results, excluded, unencodable = {}, [], [], []
    for e in entries:
        sha = hashlib.sha256(e["raw"].encode("utf-8")).hexdigest()
        cat = classify(e["path"])
        base = {"name": e["path"].rsplit("/", 1)[-1].replace(".core.json", "").replace(".md", "") if ":" not in e["path"] else e["path"],
                "path": e["path"], "sha256": sha, "kind": e["kind"], "category": cat}
        if cat.startswith("excluded"):
            excluded.append({**base, "why": "deliberately malformed test input" if "broken" in cat else "retired historical image kept for migration tests"})
            continue
        if sha in seen:
            seen[sha]["also_at"].append(e["path"])
            continue
        try:
            graph = parse(e["render"]())
            res, why = measure(e, graph, rng)
        except Exception as error:  # noqa: BLE001
            res, why = None, f"{type(error).__name__}: {str(error)[:200]}"
        if res is None:
            unencodable.append({**base, "why": why})
            continue
        rec = {**base, "also_at": [], **res}
        seen[sha] = rec
        results.append(rec)
        print(f"{cat[:9]:9} {e['path'][-60:]:60} f={rec['fields']:2} grid={rec['grid_cells']:>12,} "
              f"bits={rec['payload_bits_computed']['expected_uniform_cells']:6.2f} "
              f"B/dec@64484={rec['measured_uniform']['64484']['bytes_per_decision']}", flush=True)
    fusion = bandwidth_fusion()
    data = {"generated": "2026-11-20", "n_epoch": N_EPOCH, "n_paper": N_PAPER, "otlp_faithful_B": OTLP_FAITHFUL,
            "otlp_zstd_batched_B": OTLP_ZSTD, "fusion_paper_B": FUSION_PAPER, "fusion_fixture_run": fusion,
            "encodable": results, "unencodable": unencodable, "excluded": excluded}
    if out_path:
        json.dump(data, open(out_path, "w"), indent=1)
    print(f"\n{len(results)} unique encodable, {len(unencodable)} not encodable, {len(excluded)} excluded")


def bandwidth_fusion():
    """The fusion policy through bandwidth.py's own path on its synthetic fixture, for the reference row."""
    from pathlib import Path
    graph = parse(bandwidth.FLOW_PATH.read_text())
    parts = quantizer.build_partitions(graph)
    hits = list(bandwidth.hits_from_ndjson(Path("adapters/fusion/fixtures/alerts_synth.ndjson")))
    hits = [h for h in hits if h["_source"].get("level", 0) >= 7]
    col = bandwidth.collect(iter(hits), lambda h: h["_source"])
    o1 = bandwidth.decision_stream_stats(parts, col["readings"])
    layout = spiral.SpiralLayout(graph, bandwidth.NODE)
    o2 = bandwidth.band_stream_stats(layout, col["readings"])
    return {"source": "adapters/fusion/fixtures/alerts_synth.ndjson (synthetic fixture, mechanics only)",
            "n": len(col["readings"]), "o1": o1, "o2": o2}


if __name__ == "__main__":
    main()
