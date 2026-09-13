# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# Runs ON THE BOARD (Arty Z7-20, PYNQ) as root with the PYNQ env sourced. ONE PL configuration per
# power cycle (see memory fpga-board-access): load the tapped datapath overlay once, then do all the
# work against it in this one process: (1) the A3 fabric leg, every corpus vector on both compiled
# images through the certified PS path (auto_mode 0); (2) a continuous evaluation sweep per image for
# the LA2016 on Pmod JB to witness busy windows (A7). Output is appended line by line to a file so a
# dropped SSH loses nothing. No hardcoded MMIO probe before the overlay load.
#
# usage: python3 a3_fabric_run.py a3_fabric_bundle.json out.log [sweep_seconds]
import json, sys, time
sys.path.insert(0, "/home/xilinx")
from ppt_pynq import PptOverlay, PptImage

bundle = json.load(open(sys.argv[1]))
out = open(sys.argv[2], "a", buffering=1)
sweep_s = float(sys.argv[3]) if len(sys.argv) > 3 else 90.0
R_CAUSE = 0x34

def log(message):
    out.write(message + "\n"); out.flush()

log("BOOT " + time.strftime("%Y-%m-%dT%H:%M:%S"))
ol = PptOverlay("/home/xilinx/ppt_datapath.bit")           # the one configuration
log("LOADED ppt_datapath.bit magic ok")

imgs = {}
for pid, spec in bundle["images"].items():
    open(f"/tmp/{pid}.ppt", "wb").write(bytes.fromhex(spec["ppt_hex"]))
    json.dump(spec["json"], open(f"/tmp/{pid}.json", "w"))
    imgs[pid] = PptImage(f"/tmp/{pid}.ppt", f"/tmp/{pid}.json")

# (1) A3 fabric leg
rows = []
for pid, img in imgs.items():
    ol.load_image(img)
    for vector in bundle["vectors"]:
        if vector["cid"] != pid:
            continue
        ol.write_fields(img, vector["ctx"])
        t0 = time.perf_counter_ns()
        res = ol.evaluate(img.start)
        dt = (time.perf_counter_ns() - t0) / 1000
        cause = ol.io.read(R_CAUSE) & 0xFF
        target = res[1] if res is not None else -1
        rows.append({"policy": pid, "scenario": vector["scenario"], "fabric_target": target, "fabric_edge": res[0] if res else None,
                     "cause": cause, "python_target": vector["python_target"], "agree": target == vector["python_target"], "round_trip_us": round(dt, 1)})
        log("A3ROW " + json.dumps(rows[-1]))
agree = sum(1 for row in rows if row["agree"])
log(f"A3DONE {agree}/{len(rows)} fabric targets equal the host Python targets")

# (2) sweeps for the pins witness
for pid, img in imgs.items():
    ol.load_image(img)
    vecs = [vector for vector in bundle["vectors"] if vector["cid"] == pid]
    log(f"SWEEP START {pid} wcet_cycles={bundle['images'][pid]['wcet_cycles']}")
    t_end = time.time() + sweep_s
    evaluation_count = 0
    while time.time() < t_end:
        for vector in vecs:
            ol.write_fields(img, vector["ctx"])
            ol.evaluate(img.start)
            evaluation_count += 1
    log(f"SWEEP END {pid} evaluations={evaluation_count}")
log("ALLDONE")
