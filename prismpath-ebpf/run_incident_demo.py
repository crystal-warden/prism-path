#!/usr/bin/env python3
"""Route ONE real high-severity incident (the level-10 SSH brute-force alert) through the eBPF triage
router in-kernel. Classify it with the live LLM (real verdict), build the routing register file, and
print the reference path. The loader `run` mode then drives it hop-by-hop through the XDP program.
"""
import json
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
    raw = json.loads(open(HERE / "scratch" / "incident.ndjson").read().strip())
    a = normalize_wazuh_hit(raw)
    print(f"INCIDENT: rule {a['rule_id']} level {a['level']} — {a['description']}")
    print(f"  agent={a['agent']}  srcip={a['srcip']}  log={a['full_log'][:90]}")

    g = parse_file(str(FLOW))
    img = pc.compile_flow(g, 25)
    names = [n for n, _ in img.nodes]
    start = names.index(g.start)
    (HERE / "scratch" / "wazuh.ppt").write_bytes(img.serialize())
    (HERE / "scratch" / "wazuh.names").write_text("\n".join(names) + "\n")

    brief = f"rule {a['rule_id']} on agent {a['agent']}; srcip {a['srcip'] or 'n/a'}; {a['description']}"
    verdict = agent.classify_verdict(a, brief)
    rec = verdict.get("recommended_action") or "watch"
    print(f"\nLIVE LLM verdict: {verdict.get('threat_class','?')} / active={verdict.get('is_active_threat')}"
          f" / conf={verdict.get('confidence')} / action={rec}")
    print(f"  rationale: {verdict.get('rationale','')[:200]}")

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
