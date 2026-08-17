#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Route ONE real high-severity incident (the level-10 SSH brute-force alert) through the eBPF triage
router in-kernel. The routing action is the flow's own decidable projection of the alert level (the
flow is the adjudicator, a proof not a judgment), and the loader `run` mode then drives it hop-by-hop
through the XDP program, checking the in-kernel path matches the host reference.
"""
import json
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
        "full_log": rec.get("full_log", ""),
    }


def main():
    raw = json.loads(open(HERE / "scratch" / "incident.ndjson").read().strip())
    a = normalize(raw)
    print(f"INCIDENT: rule {a['rule_id']} level {a['level']} — {a['description']}")
    print(f"  agent={a['agent']}  srcip={a['srcip']}  log={a['full_log'][:90]}")

    g = parse_file(str(FLOW))
    img = pc.compile_flow(g, 25)
    names = [n for n, _ in img.nodes]
    start = names.index(g.start)
    (HERE / "scratch" / "wazuh.ppt").write_bytes(img.serialize())
    (HERE / "scratch" / "wazuh.names").write_text("\n".join(names) + "\n")

    rec = action_from_level(a["level"])
    print(f"\ndecidable projection: rule_level {a['level']} -> action={rec}")

    fields = {"no_alert": False, "cached_action": "none", "rule_level": a["level"],
              "recommended_action": rec, "staged_ok": True}
    (HERE / "scratch" / "incident.regs.bin").write_bytes(pc.encode_regs(img, fields, node_idx=start))

    # reference path via interp, hop by hop (no root)
    path, cur = [start], start
    for _ in range(64):
        if not img.nodes[cur][1]:
            break
        import subprocess
        (HERE / "scratch" / "_hop.bin").write_bytes(pc.encode_regs(img, fields, node_idx=cur))
        out = subprocess.run([str(HERE / "interp"), "eval", str(HERE / "scratch" / "wazuh.ppt"),
                              str(HERE / "scratch" / "_hop.bin")], capture_output=True, text=True).stdout.strip()
        if not out.startswith("match"):
            break
        cur = int(out.split()[2]); path.append(cur)

    print(f"\nrouter decision: {DECISION.get(rec, 'watchlist')}")
    print(f"reference path : " + " -> ".join(names[i] for i in path))
    print(f"\nnow route this real incident IN-KERNEL:")
    print(f"  cd {HERE} && sudo ./loader scratch/wazuh.ppt run scratch/incident.regs.bin scratch/wazuh.names")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
