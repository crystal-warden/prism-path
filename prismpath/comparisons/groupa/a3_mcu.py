# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A3 MCU leg: replay the a3 corpus on a serial PPT board (the RP2350 or ESP32 certification firmware,
unchanged; the wire contract is prismpath-hw/rp2350/certify_rp2350.py's `Board`: I ident, L load a
table, V evaluate a register payload, reply M edge target or N).

For each of the two compiled images the board loads the table once and evaluates every complete
scenario reading; the target it returns is recorded beside the host Python, C, and kernel targets.
Writes results/prismpath/evidence/A3/mcu_<ident>.json and .log.

Usage: python -m prismpath.comparisons.groupa.a3_mcu --port /dev/ttyACM0
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from prismpath.comparisons.groupa.common import evidence_dir, policy_by_id
from prismpath.comparisons.harness import HERE, gen_dir_for, scenario_steps
from prismpath.parser import parse

REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "prismpath-hw"))
sys.path.insert(0, str(REPO / "prismpath-hw" / "rp2350"))
import ppt_compile as pc  # noqa: E402
from certify_rp2350 import Board  # noqa: E402

POLICIES = ["network_admission", "sensor_interlock"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", required=True)
    a = ap.parse_args(argv)
    ev = evidence_dir("prismpath", "A3")
    vectors = json.loads((ev / "a3_vectors.json").read_text())["vectors"]
    board = Board(a.port)
    ident = board.ident()
    tag = ident.replace("/", "_").replace(" ", "_")
    rows, mismatches, lat = [], 0, []
    for pid in POLICIES:
        graph = parse((gen_dir_for("prismpath", pid) / f"{pid}.md").read_text())
        img = pc.compile_flow(graph)
        blob = img.serialize()
        assert blob == (ev / f"{pid}.ppt").read_bytes(), "image differs from the corpus image"
        board.load(blob)
        policy = policy_by_id(pid)
        for sid, kind, inp, exp in scenario_steps(policy):
            if kind == "undeclared_missing":
                continue
            ctx = {k: v for k, v in inp.items() if v is not None}
            regs = pc.encode_regs(img, ctx, node_idx=0)
            t0 = time.perf_counter()
            got = board.eval(regs)
            lat.append(round((time.perf_counter() - t0) * 1e6, 1))
            target = got[1] if got is not None else -1
            ref = next(v for v in vectors if v["policy"] == pid and v["scenario"] == sid)
            ok = target == ref["python_target"] == ref["c_target"]
            mismatches += 0 if ok else 1
            rows.append({"policy": pid, "scenario": sid, "board_target": target, "board_edge": got[0] if got else None,
                         "python_target": ref["python_target"], "c_target": ref["c_target"], "agree": ok})
    out = {"ident": ident, "port": a.port, "vectors": len(rows), "mismatches": mismatches,
           "usb_cdc_round_trip_us": {"min": min(lat), "median": sorted(lat)[len(lat) // 2], "max": max(lat)}, "rows": rows}
    (ev / f"mcu_{tag}.json").write_text(json.dumps(out, indent=1) + "\n")
    (ev / f"mcu_{tag}.log").write_text(f"{ident}: {len(rows) - mismatches}/{len(rows)} vectors agree with host Python and the C reference\n")
    print(f"{ident}: {len(rows) - mismatches}/{len(rows)} agree, USB-CDC round trip median {out['usb_cdc_round_trip_us']['median']} us")
    return 0 if mismatches == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
