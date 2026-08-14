"""Band-population census for the fusion_triage tessellation.

Weights every ring of the spiral with REAL data: the cyber axis from an alert-level backlog
(a level histogram — under the decidable projection the cyber marginal IS the level histogram,
so one aggregation replaces a 64k document pull), the physical axis from the recorded sensor
sessions in prismpath-hw/evidence/.

Two pairings, both labeled, neither time-coincident:

- assume_still  — every alert fused with the baseline posture {still, 0}. The cyber axis is
  fully observed; the physical axis is a stated baseline. The fusion bands stay empty and that
  emptiness is the finding: without coincident capture there is no honest joint.
- independence_expected — cyber marginal x IMU marginal, normalized to the cyber N. Marginals
  measured, joint modeled. Expected counts under independence, explicitly not observations.

Committed artifacts are aggregates only: no alert content, agent names, hostnames, or IPs
(tests/test_census.py enforces this against the committed file).

    python adapters/fusion/census.py --from-fixture [path]

The cyber axis is fed here from an NDJSON level backlog. Any decision source that yields a
`rule.level` histogram is a valid connector; the archived SIEM connector was the v1 example.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
for p in (str(REPO / "adapters" / "telemetry"), str(REPO), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import quantizer as q  # noqa: E402
import spiral as sp    # noqa: E402
from prismpath.parser import parse  # noqa: E402

import projection as pj  # noqa: E402

FLOW_PATH = HERE / "flows" / "fusion_triage.md"
NODE = "correlate"
HW_EVIDENCE = REPO / "prismpath-hw" / "evidence"
POSTURE_SESSIONS = [
    "mac_bridge_session1.ndjson",
    "mac_bridge_sessions2-5.ndjson",
    "fabric_session1.ndjson",
]

PROJECTION_RULE = ("soc_action = 'contain' if rule_level >= 12 else 'watch' if rule_level >= 7 "
                   "else 'ignore' (the triage flow's own containment edge and triage floor; "
                   "decidable, NOT an adjudicator verdict)")

CAVEATS = [
    "The pairings are NOT time-coincident: cyber and physical streams were recorded in "
    "different windows. assume_still asserts nothing about the joint; independence_expected "
    "models it under an explicit independence assumption (marginals measured, joint modeled).",
    "The cyber verdict is the decidable projection of rule_level, not an adjudicator verdict; "
    "under this projection soc_action is a deterministic function of rule_level, so the census "
    "cannot separate those two facets. The adjudicator path is exercised separately.",
    "A live coincident capture (sensor and alerts in the same window) is the only artifact that "
    "can honestly populate the coincident bands; it is a planned follow-on.",
]


# --------------------------------------------------------------- cyber marginal

def cyber_marginal_ndjson(path: Path) -> Tuple[Dict[int, int], dict]:
    hist: Counter = Counter()
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            hist[int(json.loads(line)["level"])] += 1
    return dict(hist), {"index_pattern": f"fixture:{path.name}", "span": None}


# ---------------------------------------------------------------- IMU marginal

def imu_marginal(parts, paths: Iterable[Path], include_derived: bool = False) -> dict:
    """Counter over (stability, dev_mg symbol) from the real recorded sessions."""
    dev_part = parts["dev_mg"]
    counts: Counter = Counter()
    rows = used = derived_excluded = 0
    sessions = []
    for path in paths:
        if not path.exists():
            continue
        sessions.append(path.name)
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            rows += 1
            out = pj.normalize_imu(json.loads(line))
            if out is None:
                continue
            if out["derived"] and not include_derived:
                derived_excluded += 1
                continue
            counts[(out["stability"], dev_part.symbol(out["dev_mg"]))] += 1
            used += 1
    return {
        "sessions": sessions,
        "rows_seen": rows,
        "rows_used": used,
        "derived_excluded": derived_excluded,
        "include_derived": include_derived,
        # JSON-friendly: "stability|dev_symbol" -> count
        "counts": {f"{s}|{d}": c for (s, d), c in sorted(counts.items())},
    }


# -------------------------------------------------------------------- pairings

def _band_add(layout, reading: dict, weight: float, bands: Counter, cells: list) -> None:
    n = layout.index(reading)
    cells[n] += weight
    bands[layout.routes[layout.band_id(reading)]] += weight


def band_census(layout, parts, pairing: str, cyber_hist: Dict[int, int], imu: dict) -> dict:
    dev_rep = {int(k.split("|")[1]): parts["dev_mg"].cells[int(k.split("|")[1])]["rep"]
               for k in imu["counts"]}
    bands: Counter = Counter()
    cells = [0.0] * layout.size
    n_cyber = sum(cyber_hist.values())

    if pairing == "assume_still":
        label = ("every alert fused with the baseline posture {still, dev_mg=0}; cyber axis "
                 "fully observed, physical axis a stated baseline")
        for level, count in cyber_hist.items():
            reading = pj.fused_reading(level, pj.soc_action_from_level(level), pj.ASSUME_STILL)
            _band_add(layout, reading, count, bands, cells)
    elif pairing == "independence_expected":
        label = ("cyber marginal x IMU marginal normalized to cyber N; marginals measured, "
                 "joint modeled under an explicit independence assumption; NOT time-coincident")
        n_imu = sum(imu["counts"].values()) or 1
        for level, c_count in cyber_hist.items():
            action = pj.soc_action_from_level(level)
            for key, i_count in imu["counts"].items():
                stability, dsym = key.split("|")
                reading = pj.fused_reading(level, action,
                                           {"stability": stability, "dev_mg": dev_rep[int(dsym)]})
                _band_add(layout, reading, c_count * i_count / n_imu, bands, cells)
    else:
        raise ValueError(f"unknown pairing {pairing!r}")

    rounded = {r: int(round(v)) for r, v in bands.items()}
    residual = n_cyber - sum(rounded.values())
    return {
        "pairing": pairing,
        "label": label,
        "n": n_cyber,
        "bands": {r: rounded.get(r, 0) for r in layout.routes},
        "cells": [int(round(v)) for v in cells],
        "rounding_residual": residual,
    }


# ------------------------------------------------------------------------ main

def build_artifact(cyber_hist: Dict[int, int], query_meta: dict, min_level: int,
                   include_derived: bool = False) -> dict:
    flow_text = FLOW_PATH.read_text()
    graph = parse(flow_text)
    layout = sp.SpiralLayout(graph, NODE)
    parts = q.build_partitions(graph)

    filtered = {lvl: c for lvl, c in cyber_hist.items() if lvl >= min_level}
    imu = imu_marginal(parts, [HW_EVIDENCE / s for s in POSTURE_SESSIONS],
                       include_derived=include_derived)

    totals = {"all_levels": sum(cyber_hist.values()),
              "at_or_above_min_level": sum(filtered.values()),
              "at_or_above_12": sum(c for lvl, c in cyber_hist.items() if lvl >= 12)}

    return {
        "generated": _dt.date.today().isoformat(),
        "adapter": "fusion",
        "flow_sha256": hashlib.sha256(flow_text.encode()).hexdigest(),
        "node": NODE,
        "query": {**query_meta, "min_level": min_level, "totals": totals},
        "projection_rule": PROJECTION_RULE,
        "cyber_marginal": {str(k): v for k, v in sorted(filtered.items())},
        "cyber_marginal_all_levels": {str(k): v for k, v in sorted(cyber_hist.items())},
        "imu_marginal": imu,
        "pairings": {
            p: band_census(layout, parts, p, filtered, imu)
            for p in ("assume_still", "independence_expected")
        },
        "caveats": CAVEATS,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--from-fixture", nargs="?", const=str(HERE / "fixtures" / "alerts_synth.ndjson"),
                    default=str(HERE / "fixtures" / "alerts_synth.ndjson"),
                    help="replay a flat NDJSON of {level: int} rows (the alert-level backlog connector)")
    ap.add_argument("--min-level", type=int, default=7)
    ap.add_argument("--include-derived", action="store_true",
                    help="include session rows whose dev_mg is derived (instantaneous, not peak-hold)")
    ap.add_argument("--out", default=None, help="output path (default evidence/census_YYYY-MM.json)")
    args = ap.parse_args(argv)

    cyber_hist, meta = cyber_marginal_ndjson(Path(args.from_fixture))

    artifact = build_artifact(cyber_hist, meta, args.min_level,
                              include_derived=args.include_derived)
    out = Path(args.out) if args.out else \
        HERE / "evidence" / f"census_{_dt.date.today():%Y-%m}.json"
    out.write_text(json.dumps(artifact, indent=1) + "\n")

    a = artifact["pairings"]["assume_still"]["bands"]
    print(f"wrote {out}")
    print(f"  cyber N={artifact['pairings']['assume_still']['n']:,}  "
          f"imu rows used={artifact['imu_marginal']['rows_used']:,}")
    print(f"  assume_still bands: {json.dumps(a)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
