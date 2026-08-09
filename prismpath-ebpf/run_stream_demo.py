#!/usr/bin/env python3
"""Route a REAL Wazuh alert stream through the eBPF triage router in-kernel.

For each real alert (from scratch/real_alerts.ndjson): normalize it, get a REAL triage verdict from the
live LLM (the SoC adapter's own classify_verdict — no synthetic field values), build the routing field
vector the flow reads, and emit a batch record. The loader's `runbatch` mode then drives each alert
through the actual XDP program in-kernel and confirms the path matches the host reference.

No corpus side effects: we call classify_verdict (the pure LLM verdict), NOT classify (which learns).

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
sys.path.insert(0, str(REPO / "adapters" / "soc"))
import ppt_compile as pc                                  # noqa: E402
from prismpath.parser import parse_file                  # noqa: E402
import wazuh_triage_agent as agent                        # noqa: E402
from siem import normalize_wazuh_hit                      # noqa: E402

FLOW = REPO / "adapters" / "soc" / "flows" / "wazuh_triage.md"
DECISION = {"contain": "stage_containment", "watch": "watchlist", "ignore": "benign"}


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
    print(f"classifying {len(alerts)} REAL alerts with the live LLM (SoC adapter classify_verdict)...\n")
    for raw in alerts:
        a = normalize_wazuh_hit(raw)
        brief = f"rule {a['rule_id']} on agent {a['agent']}; srcip {a['srcip'] or 'n/a'}"
        try:
            verdict = agent.classify_verdict(a, brief)
            rec = verdict.get("recommended_action") or "watch"
        except Exception as e:
            rec = "watch"
            print(f"  [classify failed: {type(e).__name__}] -> default watch")
        fields = {"no_alert": False, "cached_action": "none", "rule_level": a["level"],
                  "recommended_action": rec, "staged_ok": True}
        regs = pc.encode_regs(img, fields, node_idx=start)[4:]     # strip node_idx; runbatch starts at flow start
        records += struct.pack("<I", len(regs)) + regs
        dec = DECISION.get(rec, "watchlist")
        dist[dec] += 1
        rows.append((a["level"], rec, dec, a["description"][:46]))

    (HERE / "scratch" / "stream.records.bin").write_bytes(records)

    print(f"{'lvl':>3}  {'LLM verdict':11}  {'router decision':17}  alert")
    print("  " + "-" * 74)
    for lvl, rec, dec, desc in rows:
        print(f"{lvl:>3}  {rec:11}  {dec:17}  {desc}")
    print(f"\nreal triage distribution (live LLM verdict -> in-kernel router decision): {dict(dist)}")
    print(f"\nnow route all {len(alerts)} REAL alerts IN-KERNEL:")
    print(f"  cd {HERE} && sudo ./loader scratch/wazuh.ppt runbatch "
          f"scratch/stream.records.bin scratch/wazuh.names")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
