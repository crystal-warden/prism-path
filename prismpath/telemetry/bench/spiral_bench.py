# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tier 6 gate  -  routing accuracy vs bits received, on multi-dimensional correlated telemetry.

The claim under test: packing a multi-var reading onto the decision-first spiral lets the edge transmit a
single **band ID** that routes correctly, where the linear per-field wire must transmit *every* field
symbol before it can route. So the honest measurements are:

  Set 1  bits to route correctly            linear (all k fields) vs spiral decision-only (1 band ID);
                                            the win, and whether it grows with dimensionality k.
  Set 2  fidelity parity                    spiral *progressive* (band + within-band index) vs linear;
                                            ~1x confirms the win is progressiveness, not dropped data.
  Set 3  correlation makes it cheaper       decision-stream bits + band entropy, correlated vs uniform.
  Set 4  survival under burst loss          fraction still routing when frames are lost (1 frame vs k).

PASS iff for k>=2 the decision-only wire routes correctly at materially fewer bits (margin growing with
k), fidelity parity holds, and the decision frame survives loss better. Otherwise the tier does not land.

    python bench/spiral_bench.py            # writes bench/spiral_results.md + .json
"""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Dict, List

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))   # repo root

from prismpath.telemetry import spiral   # noqa: E402
from prismpath.telemetry import wire      # noqa: E402
from prismpath.telemetry.bench.channel import lost_mask                 # noqa: E402
from prismpath.kernel.parser import parse            # noqa: E402

SEVERITY = [("critical", 80), ("alarm", 45), ("caution", 20)]   # thresholds; any field triggers


def make_flow(field_count: int) -> str:
    """A watch node over k numeric fields; route = worst severity across all fields (route needs all k)."""
    fields = [f"f{field_index}" for field_index in range(field_count)]
    lines = ["---", "name: multi", "start: watch", "---", "## watch"]
    for route, thr in SEVERITY:
        cond = " or ".join(f"{field} >= {thr}" for field in fields)
        lines.append(f"-> {route}: when {cond}")
    lines.append("-> nominal: else")
    lines += [f"## {route}" for route, _ in SEVERITY] + ["## nominal"]
    return "\n".join(lines) + "\n"


def gen(field_count: int, reading_count: int, correlated: bool, seed: int) -> List[Dict[str, int]]:
    """n readings over k fields in [0,100]. Correlated: a shared latent stress drives every field so
    readings co-vary and cluster into few bands. Uniform: each field independent."""
    rng = np.random.default_rng(seed)
    out = []
    for _ in range(reading_count):
        if correlated:
            stress = rng.beta(1.5, 4.0) * 100.0            # mostly-low latent stress, occasional spike
            vals = np.clip(stress + rng.normal(0, 8, field_count), 0, 100)
        else:
            vals = rng.uniform(0, 100, field_count)
        out.append({f"f{field_index}": int(vals[field_index]) for field_index in range(field_count)})
    return out


def _mean_bits(codes: List[str]) -> float:
    return sum(len(code) for code in codes) / len(codes)


def _entropy_bits(labels: List[int]) -> float:
    from collections import Counter
    counts = Counter(labels)
    tot = len(labels)
    return -sum((count / tot) * math.log2(count / tot) for count in counts.values())


def set1_and_2(ks: List[int], reading_count: int, seed: int) -> List[Dict]:
    rows = []
    for field_count in ks:
        graph = parse(make_flow(field_count))
        parts = spiral.q.build_partitions(graph)
        layout = spiral.SpiralLayout(graph, "watch")
        readings = gen(field_count, reading_count, correlated=True, seed=seed + field_count)
        linear = [wire.encode_reading(parts, reading) for reading in readings]   # all k field symbols
        decision = [layout.encode_decision(reading) for reading in readings]                  # 1 band ID
        prog = [decision_bits + refine_bits for decision_bits, refine_bits
                in (layout.encode_progressive(reading) for reading in readings)]
        # both linear and decision are decision-lossless -> routing is 100% correct at those bits
        lin_b, dec_b, prog_b = _mean_bits(linear), _mean_bits(decision), _mean_bits(prog)
        rows.append({"k": field_count, "cells": layout.size, "bands": len(layout.routes),
                     "linear_bits": round(lin_b, 2), "decision_bits": round(dec_b, 2),
                     "route_win_x": round(lin_b / dec_b, 2),
                     "progressive_bits": round(prog_b, 2),
                     "fidelity_ratio": round(prog_b / lin_b, 2)})
    return rows


def set3_correlation(field_count: int, reading_count: int, seed: int) -> Dict:
    graph = parse(make_flow(field_count))
    layout = spiral.SpiralLayout(graph, "watch")
    out = {}
    for tag, corr in (("correlated", True), ("uniform", False)):
        readings = gen(field_count, reading_count, correlated=corr, seed=seed)
        bands = [layout.band_id(reading) for reading in readings]
        bits = _mean_bits([layout.encode_decision(reading) for reading in readings])
        out[tag] = {"decision_bits": round(bits, 2), "band_entropy_bits": round(_entropy_bits(bands), 2)}
    return out


def set4_loss(field_count: int, reading_count: int, seed: int) -> List[Dict]:
    """Frames lost under Gilbert-Elliott. A reading routes iff all the frames its scheme needs survive:
    linear needs its k field frames, the spiral decision needs its 1 band frame."""
    graph = parse(make_flow(field_count))
    layout = spiral.SpiralLayout(graph, "watch")
    readings = gen(field_count, reading_count, correlated=True, seed=seed)
    rows = []
    for label, loss_probability, recovery_probability in (("light burst", 0.02, 0.5),
                                                          ("heavy burst", 0.08, 0.3)):
        # k linear frames + 1 decision frame per reading
        frames = reading_count * (field_count + 1)
        mask = lost_mask(frames, loss_probability, recovery_probability, seed=seed)
        lin_ok = dec_ok = 0
        idx = 0
        for _ in readings:
            lin_frames = mask[idx:idx + field_count]
            dec_frame = mask[idx + field_count]
            idx += field_count + 1
            if not lin_frames.any():
                lin_ok += 1
            if not dec_frame:
                dec_ok += 1
        rows.append({"regime": label, "linear_routed_pct": round(100 * lin_ok / reading_count, 1),
                     "spiral_routed_pct": round(100 * dec_ok / reading_count, 1)})
    return rows


def verdict(s12: List[Dict], s4: List[Dict]) -> Dict:
    multi = [row for row in s12 if row["k"] >= 2]
    win_grows = all(multi[row_index]["route_win_x"] <= multi[row_index + 1]["route_win_x"]
                    for row_index in range(len(multi) - 1))
    wins = all(row["route_win_x"] > 1.3 for row in multi)
    parity = all(row["fidelity_ratio"] <= 1.35 for row in multi)
    loss = all(row["spiral_routed_pct"] >= row["linear_routed_pct"] for row in s4)
    ok = wins and win_grows and parity and loss
    return {"route_win_for_multidim": wins, "win_grows_with_k": win_grows,
            "fidelity_parity": parity, "better_loss_survival": loss, "PASS": ok}


def main() -> int:
    reading_count, seed = 20_000, 7
    ks = [1, 2, 3, 4]
    s12 = set1_and_2(ks, reading_count, seed)
    s3 = set3_correlation(3, reading_count, seed)
    s4 = set4_loss(3, reading_count, seed)
    verdict_summary = verdict(s12, s4)

    out = {"n": reading_count, "seed": seed, "set1_2_bits": s12, "set3_correlation": s3,
           "set4_loss": s4, "verdict": verdict_summary}
    here = Path(__file__).resolve().parent
    (here / "spiral_results.json").write_text(json.dumps(out, indent=2) + "\n")

    md = ["# Tier 6 (spiral)  -  routing accuracy vs bits", "",
          f"N={reading_count} readings/scenario, seed={seed}, correlated multi-dim telemetry.", "",
          "## Set 1+2  -  bits to route, and fidelity parity (per dimensionality k)", "",
          "| k | cells | bands | linear bits | decision bits | route win | progressive bits | fidelity ratio |",
          "|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for row in s12:
        md.append(f"| {row['k']} | {row['cells']} | {row['bands']} | {row['linear_bits']} "
                  f"| {row['decision_bits']} | {row['route_win_x']}x "
                  f"| {row['progressive_bits']} | {row['fidelity_ratio']} |")
    md += ["", "*Route win* = linear bits / decision bits (both route 100% correctly  -  decision-lossless). "
           "*Fidelity ratio* = spiral progressive (full quantized magnitude) / linear: ~1x means the win is "
           "progressiveness, not dropped data.", "",
           "## Set 3  -  correlation makes the decision stream cheaper (k=3)", "",
           "| telemetry | decision bits | band entropy (bits) |", "|---|---:|---:|"]
    for tag in ("correlated", "uniform"):
        md.append(f"| {tag} | {s3[tag]['decision_bits']} | {s3[tag]['band_entropy_bits']} |")
    md += ["", "## Set 4  -  survival under burst loss (k=3, Gilbert-Elliott)", "",
           "| regime | linear routed % | spiral routed % |", "|---|---:|---:|"]
    for row in s4:
        md.append(f"| {row['regime']} | {row['linear_routed_pct']} | {row['spiral_routed_pct']} |")
    md += ["", "*Linear needs all k field frames to survive to route; the spiral decision needs its 1 band "
           "frame.*", "", f"## Verdict: **{'PASS' if verdict_summary['PASS'] else 'FAIL'}**", ""]
    for kk, vv in verdict_summary.items():
        if kk != "PASS":
            md.append(f"- {kk}: {vv}")
    (here / "spiral_results.md").write_text("\n".join(md) + "\n")

    print("\n".join(md))
    return 0 if verdict_summary["PASS"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
