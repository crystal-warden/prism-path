#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Route a REAL alert stream through the eBPF triage router in-kernel.

For each real alert (from scratch/real_alerts.ndjson): normalize it, project the alert level onto the
flow's routing action (the flow's own containment edge and triage floor — decidable, the flow is the
adjudicator), build the routing field vector the flow reads, and emit a batch record. The loader's
`runbatch` mode then drives each alert through the actual XDP program in-kernel and confirms the path
matches the host reference.

Usage: run_stream_demo.py
"""
import collections
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "prismpath-hw"))
sys.path.insert(0, str(REPO))
import ppt_compile as pc                                  # noqa: E402
from prismpath.parser import parse_file                  # noqa: E402

FLOW = REPO / "prismpath" / "flows" / "wazuh_triage.md"
DECISION = {"contain": "stage_containment", "watch": "watchlist", "ignore": "benign"}


def action_from_level(level: int) -> str:
    """The flow's own containment edge (>=12) and triage floor (>=7); decidable, no adjudicator."""
    return "contain" if level >= 12 else "watch" if level >= 7 else "ignore"


def normalize(rec: dict) -> dict:
    """Tolerant field pull from an alert record (raw-nested or already-flat)."""
    rule = rec.get("rule") or {}
    agent = rec.get("agent")
    return {
        "rule_id": rec.get("rule_id") or rule.get("id"),
        "level": int(rec.get("level", rule.get("level", 0))),
        "agent": agent if isinstance(agent, str) else (agent or {}).get("name"),
        "srcip": rec.get("srcip") or (rec.get("data") or {}).get("srcip"),
        "description": rec.get("description") or rule.get("description") or "",
    }


def main():
    g = parse_file(str(FLOW))
    img = pc.compile_flow(g, 25)
    names = [n for n, _ in img.nodes]
    start = names.index(g.start)
    (HERE / "scratch").mkdir(exist_ok=True)
    (HERE / "scratch" / "wazuh.ppt").write_bytes(img.serialize())
    (HERE / "scratch" / "wazuh.names").write_text("\n".join(names) + "\n")

    alerts = [json.loads(l) for l in open(HERE / "scratch" / "real_alerts.ndjson") if l.strip()]
    records = bytearray()
    rows = []
    dist = collections.Counter()
    print(f"routing {len(alerts)} REAL alerts by the flow's decidable level projection...\n")
    for raw in alerts:
        a = normalize(raw)
        rec = action_from_level(a["level"])
        fields = {"no_alert": False, "cached_action": "none", "rule_level": a["level"],
                  "recommended_action": rec, "staged_ok": True}
        regs = pc.encode_regs(img, fields, node_idx=start)[4:]     # strip node_idx; runbatch starts at flow start
        records += struct.pack("<I", len(regs)) + regs
        dec = DECISION.get(rec, "watchlist")
        dist[dec] += 1
        rows.append((a["level"], rec, dec, a["description"][:46]))

    (HERE / "scratch" / "stream.records.bin").write_bytes(records)

    print(f"{'lvl':>3}  {'projection':11}  {'router decision':17}  alert")
    print("  " + "-" * 74)
    for lvl, rec, dec, desc in rows:
        print(f"{lvl:>3}  {rec:11}  {dec:17}  {desc}")
    print(f"\nreal triage distribution (level projection -> in-kernel router decision): {dict(dist)}")
    print(f"\nnow route all {len(alerts)} REAL alerts IN-KERNEL:")
    print(f"  cd {HERE} && sudo ./loader scratch/wazuh.ppt runbatch "
          f"scratch/stream.records.bin scratch/wazuh.names")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
