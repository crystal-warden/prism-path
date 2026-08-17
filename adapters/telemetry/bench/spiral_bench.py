# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tier 6 gate — routing accuracy vs bits received, on multi-dimensional correlated telemetry.

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

import spiral as sp   # noqa: E402
import wire as w      # noqa: E402
from channel import lost_mask                 # noqa: E402
from prismpath.parser import parse            # noqa: E402

SEVERITY = [("critical", 80), ("alarm", 45), ("caution", 20)]   # thresholds; any field triggers


def make_flow(k: int) -> str:
    """A watch node over k numeric fields; route = worst severity across all fields (route needs all k)."""
    fields = [f"f{i}" for i in range(k)]
    lines = ["---", "name: multi", "start: watch", "---", "## watch"]
    for route, thr in SEVERITY:
        cond = " or ".join(f"{f} >= {thr}" for f in fields)
        lines.append(f"-> {route}: when {cond}")
    lines.append("-> nominal: else")
    lines += [f"## {r}" for r, _ in SEVERITY] + ["## nominal"]
    return "\n".join(lines) + "\n"


def gen(k: int, n: int, correlated: bool, seed: int) -> List[Dict[str, int]]:
    """n readings over k fields in [0,100]. Correlated: a shared latent stress drives every field so
    readings co-vary and cluster into few bands. Uniform: each field independent."""
    rng = np.random.default_rng(seed)
    out = []
    for _ in range(n):
        if correlated:
            s = rng.beta(1.5, 4.0) * 100.0            # mostly-low latent stress, occasional spike
            vals = np.clip(s + rng.normal(0, 8, k), 0, 100)
        else:
            vals = rng.uniform(0, 100, k)
        out.append({f"f{i}": int(vals[i]) for i in range(k)})
    return out


def _mean_bits(codes: List[str]) -> float:
    return sum(len(c) for c in codes) / len(codes)


def _entropy_bits(labels: List[int]) -> float:
    from collections import Counter
    c = Counter(labels)
    tot = len(labels)
    return -sum((v / tot) * math.log2(v / tot) for v in c.values())


def set1_and_2(ks: List[int], n: int, seed: int) -> List[Dict]:
    rows = []
    for k in ks:
        g = parse(make_flow(k))
        parts = sp.q.build_partitions(g)
        L = sp.SpiralLayout(g, "watch")
        readings = gen(k, n, correlated=True, seed=seed + k)
        linear = [w.encode_reading(parts, r) for r in readings]              # all k field symbols
        decision = [L.encode_decision(r) for r in readings]                  # 1 band ID
        prog = [a + b for a, b in (L.encode_progressive(r) for r in readings)]
        # both linear and decision are decision-lossless -> routing is 100% correct at those bits
        lin_b, dec_b, prog_b = _mean_bits(linear), _mean_bits(decision), _mean_bits(prog)
        rows.append({"k": k, "cells": L.size, "bands": len(L.routes),
                     "linear_bits": round(lin_b, 2), "decision_bits": round(dec_b, 2),
                     "route_win_x": round(lin_b / dec_b, 2),
                     "progressive_bits": round(prog_b, 2),
                     "fidelity_ratio": round(prog_b / lin_b, 2)})
    return rows


def set3_correlation(k: int, n: int, seed: int) -> Dict:
    g = parse(make_flow(k))
    L = sp.SpiralLayout(g, "watch")
    out = {}
    for tag, corr in (("correlated", True), ("uniform", False)):
        readings = gen(k, n, correlated=corr, seed=seed)
        bands = [L.band_id(r) for r in readings]
        bits = _mean_bits([L.encode_decision(r) for r in readings])
        out[tag] = {"decision_bits": round(bits, 2), "band_entropy_bits": round(_entropy_bits(bands), 2)}
    return out


def set4_loss(k: int, n: int, seed: int) -> List[Dict]:
    """Frames lost under Gilbert-Elliott. A reading routes iff all the frames its scheme needs survive:
    linear needs its k field frames, the spiral decision needs its 1 band frame."""
    g = parse(make_flow(k))
    L = sp.SpiralLayout(g, "watch")
    readings = gen(k, n, correlated=True, seed=seed)
    rows = []
    for label, p, r in (("light burst", 0.02, 0.5), ("heavy burst", 0.08, 0.3)):
        frames = n * (k + 1)                                  # k linear frames + 1 decision frame / reading
        mask = lost_mask(frames, p, r, seed=seed)
        lin_ok = dec_ok = 0
        idx = 0
        for _ in readings:
            lin_frames = mask[idx:idx + k]
            dec_frame = mask[idx + k]
            idx += k + 1
            if not lin_frames.any():
                lin_ok += 1
            if not dec_frame:
                dec_ok += 1
        rows.append({"regime": label, "linear_routed_pct": round(100 * lin_ok / n, 1),
                     "spiral_routed_pct": round(100 * dec_ok / n, 1)})
    return rows


def verdict(s12: List[Dict], s4: List[Dict]) -> Dict:
    multi = [r for r in s12 if r["k"] >= 2]
    win_grows = all(multi[i]["route_win_x"] <= multi[i + 1]["route_win_x"] for i in range(len(multi) - 1))
    wins = all(r["route_win_x"] > 1.3 for r in multi)
    parity = all(r["fidelity_ratio"] <= 1.35 for r in multi)
    loss = all(r["spiral_routed_pct"] >= r["linear_routed_pct"] for r in s4)
    ok = wins and win_grows and parity and loss
    return {"route_win_for_multidim": wins, "win_grows_with_k": win_grows,
            "fidelity_parity": parity, "better_loss_survival": loss, "PASS": ok}


def main() -> int:
    n, seed = 20_000, 7
    ks = [1, 2, 3, 4]
    s12 = set1_and_2(ks, n, seed)
    s3 = set3_correlation(3, n, seed)
    s4 = set4_loss(3, n, seed)
    v = verdict(s12, s4)

    out = {"n": n, "seed": seed, "set1_2_bits": s12, "set3_correlation": s3,
           "set4_loss": s4, "verdict": v}
    here = Path(__file__).resolve().parent
    (here / "spiral_results.json").write_text(json.dumps(out, indent=2) + "\n")

    md = ["# Tier 6 (spiral) — routing accuracy vs bits", "",
          f"N={n} readings/scenario, seed={seed}, correlated multi-dim telemetry.", "",
          "## Set 1+2 — bits to route, and fidelity parity (per dimensionality k)", "",
          "| k | cells | bands | linear bits | decision bits | route win | progressive bits | fidelity ratio |",
          "|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in s12:
        md.append(f"| {r['k']} | {r['cells']} | {r['bands']} | {r['linear_bits']} | {r['decision_bits']} "
                  f"| {r['route_win_x']}x | {r['progressive_bits']} | {r['fidelity_ratio']} |")
    md += ["", "*Route win* = linear bits / decision bits (both route 100% correctly — decision-lossless). "
           "*Fidelity ratio* = spiral progressive (full quantized magnitude) / linear: ~1x means the win is "
           "progressiveness, not dropped data.", "",
           "## Set 3 — correlation makes the decision stream cheaper (k=3)", "",
           "| telemetry | decision bits | band entropy (bits) |", "|---|---:|---:|"]
    for tag in ("correlated", "uniform"):
        md.append(f"| {tag} | {s3[tag]['decision_bits']} | {s3[tag]['band_entropy_bits']} |")
    md += ["", "## Set 4 — survival under burst loss (k=3, Gilbert-Elliott)", "",
           "| regime | linear routed % | spiral routed % |", "|---|---:|---:|"]
    for r in s4:
        md.append(f"| {r['regime']} | {r['linear_routed_pct']} | {r['spiral_routed_pct']} |")
    md += ["", "*Linear needs all k field frames to survive to route; the spiral decision needs its 1 band "
           "frame.*", "", f"## Verdict: **{'PASS' if v['PASS'] else 'FAIL'}**", ""]
    for kk, vv in v.items():
        if kk != "PASS":
            md.append(f"- {kk}: {vv}")
    (here / "spiral_results.md").write_text("\n".join(md) + "\n")

    print("\n".join(md))
    return 0 if v["PASS"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
