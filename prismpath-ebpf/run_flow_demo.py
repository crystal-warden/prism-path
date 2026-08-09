#!/usr/bin/env python3
"""Prepare a REAL PrismPath flow to run through the eBPF target in-kernel.

Compiles adapters/soc/flows/wazuh_triage.md (a 12-node, fully Level M SOC alert-triage flow) to a PPT
table, sets a concrete alert scenario, writes the register file + a node-name sidecar, and computes the
reference routing path with interp.c (no root). The loader's `run` mode then drives the flow hop-by-hop
through the actual XDP program in-kernel and checks it takes the same path.

Usage: run_flow_demo.py
"""
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "prismpath-hw"))
sys.path.insert(0, str(REPO))
import ppt_compile as pc                                  # noqa: E402
from prismpath.parser import parse_file                  # noqa: E402

INTERP = HERE / "interp"
FLOW = REPO / "adapters" / "soc" / "flows" / "wazuh_triage.md"

# A concrete alert: a high-severity hit, not in the prefilter cache, that gets contained and staged OK.
SCENARIO = {
    "no_alert": False,            # observe -> enrich (an alert is present)
    "cached_action": "none",      # prefilter miss -> falls through to classify
    "rule_level": 13,             # classify: rule_level >= 12 -> stage_containment
    "recommended_action": "contain",
    "staged_ok": True,            # verify_staged -> report
}


def main():
    g = parse_file(str(FLOW))
    img = pc.compile_flow(g, 25)
    names = [name for name, _ in img.nodes]
    start = names.index(g.start)

    (HERE / "scratch").mkdir(exist_ok=True)
    (HERE / "scratch" / "wazuh.ppt").write_bytes(img.serialize())
    (HERE / "scratch" / "wazuh.names").write_text("\n".join(names) + "\n")
    (HERE / "scratch" / "wazuh.regs.bin").write_bytes(pc.encode_regs(img, SCENARIO, node_idx=start))

    # reference path via interp.c, hop by hop (no root)
    path = [start]
    cur = start
    for _ in range(img_max := 64):
        if not img.nodes[cur][1]:                         # terminal (no edges)
            break
        regs = pc.encode_regs(img, SCENARIO, node_idx=cur)
        (HERE / "scratch" / "_hop.bin").write_bytes(regs)
        out = subprocess.run([str(INTERP), "eval", str(HERE / "scratch" / "wazuh.ppt"),
                              str(HERE / "scratch" / "_hop.bin")],
                             capture_output=True, text=True).stdout.strip()
        if not out.startswith("match"):
            break
        cur = int(out.split()[2])
        path.append(cur)

    print(f"flow      : {FLOW.name}  ({len(names)} nodes, Level M)")
    print(f"scenario  : {SCENARIO}")
    print(f"fields    : {list(img.fields)}")
    print(f"\nreference path (interp.c, no root):")
    print("  " + " -> ".join(names[i] for i in path))
    print(f"\nnow run it IN-KERNEL:")
    print(f"  cd {HERE} && sudo ./loader scratch/wazuh.ppt run scratch/wazuh.regs.bin scratch/wazuh.names")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
