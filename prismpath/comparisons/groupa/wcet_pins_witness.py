# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A7 pins witness driver, run on the host the LA2016 is plugged into (gx10). While the board's single
process sweeps a policy image's vectors on the tapped datapath overlay, take repeated free run
captures on Pmod JB (CH0 clk, CH1 busy, CH2 done, CH3 start; 200 MSa/s, 1.4 V threshold, passed to sigrok as the range literal 1.4-1.4) and measure
every evaluation's busy window against the image's signed wcet_cycles, exactly as ledger #122/#123
did (prismpath-hw/wcet-pins on the bench workspace). Writes the verdict record to
results/prismpath/evidence/A7/pins_<policy>.json.

Usage: python -m prismpath.comparisons.groupa.wcet_pins_witness --policy network_admission --bound 35 --iters 12
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from prismpath.comparisons.groupa.common import evidence_dir

# CONFIGURE: the wcet-pins workspace on the host the LA2016 is plugged into (the default is the
# bench box this witness was recorded on; PRISMPATH_WCET_PINS moves it without editing the driver).
BENCH = Path(os.environ.get("PRISMPATH_WCET_PINS", "/home/cwadmin/cwprojects/prismpath-hw/wcet-pins"))
sys.path.insert(0, str(BENCH))
from la_wcet_check import CHMAP, DEV, SIGROK, _env, load_srzip, measure  # noqa: E402

CHANS = "CH0=clk,CH1=busy,CH2=done,CH3=start"


def cap(path: str, sample_count: int, rate: str, threshold: str) -> None:
    subprocess.run([SIGROK, "-d", DEV, "--config", f"samplerate={rate}:voltage_threshold={threshold}",
                    "--channels", CHANS, "--samples", str(sample_count), "-o", path], env=_env(), check=True, capture_output=True, timeout=120)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", required=True)
    ap.add_argument("--bound", type=int, required=True)
    ap.add_argument("--iters", type=int, default=12)
    ap.add_argument("--samples", type=int, default=400000)
    ap.add_argument("--rate", default="200m")
    ap.add_argument("--threshold", default="1.4-1.4")  # kingst-la2016 takes a range literal; 1.4 V = 3V3 CMOS
    args = ap.parse_args(argv)
    ev = evidence_dir("prismpath", "A7")
    hist = collections.Counter(); gmax = 0; total = 0; disagree = 0; width_max = 0
    tmp = tempfile.mktemp(suffix=".sr")
    for capture_index in range(args.iters):
        cap(tmp, args.samples, args.rate, args.threshold)
        samples, rate = load_srzip(tmp)
        evals = measure(samples, CHMAP, 50_000_000, rate)
        for evaluation in evals:
            hist[evaluation["edge_cycles"]] += 1
            gmax = max(gmax, evaluation["edge_cycles"])
            width_max = max(width_max, evaluation.get("width_cycles", evaluation["edge_cycles"]))
            total += 1
            disagree += 0 if evaluation["agree"] else 1
        print(f"  [{capture_index+1:2d}/{args.iters}] evals={len(evals):4d} running max={gmax}", flush=True)
    if os.path.exists(tmp):
        os.remove(tmp)
    ok = total > 0 and gmax <= args.bound
    rec = {"policy": args.policy, "signed_wcet_cycles": args.bound, "evaluations_measured": total, "global_max_edge_cycles": gmax,
           "global_max_width_cycles": width_max, "method_disagreements": disagree, "cycle_histogram": {str(cycles): count for cycles, count in sorted(hist.items())},
           "samplerate": args.rate, "threshold_v": args.threshold, "samples_per_capture": args.samples, "captures": args.iters,
           "verdict": "PASS" if ok else "FAIL", "instrument": "Kingst LA2016 on gx10 USB, sigrok-cli /usr/local/bin with kingst-la2016 driver"}
    (ev / f"pins_{args.policy}.json").write_text(json.dumps(rec, indent=2) + "\n")
    print(f"WCET-ON-PINS {args.policy}: max {gmax} cycles vs signed {args.bound}: {'PASS' if ok else 'FAIL'} ({total} evaluations)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
