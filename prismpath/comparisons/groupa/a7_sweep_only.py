# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# Runs ON THE BOARD after a3_fabric_run.py has finished (ALLDONE). Register traffic only against the
# already resident tapped datapath overlay: attach without reconfiguration, then sweep one policy's
# corpus vectors for N seconds so the LA2016 can witness busy windows. Exactly one process may drive
# the fabric at a time.
import json, sys, time
sys.path.insert(0, "/home/xilinx")
from pynq import Overlay, MMIO
import ppt_pynq as P
pid, secs = sys.argv[1], float(sys.argv[2])
bundle = json.load(open("/home/xilinx/a3_fabric_bundle.json"))
ol = Overlay("/home/xilinx/ppt_datapath.bit", download=False)
ip = next(k for k in ol.ip_dict if "ppt" in k.lower())
io = MMIO(ol.ip_dict[ip]["phys_addr"], 0x100)
assert io.read(P.R_MAGIC) == P.MAGIC
po = P.PptOverlay.__new__(P.PptOverlay); po.io = io
spec = bundle["images"][pid]
open(f"/tmp/{pid}.ppt", "wb").write(bytes.fromhex(spec["ppt_hex"])); json.dump(spec["json"], open(f"/tmp/{pid}.json", "w"))
img = P.PptImage(f"/tmp/{pid}.ppt", f"/tmp/{pid}.json")
po.load_image(img)
vecs = [v for v in bundle["vectors"] if v["cid"] == pid]
print(f"SWEEP START {pid} wcet_cycles={spec['wcet_cycles']} secs={secs}", flush=True)
t_end = time.time() + secs; n = 0
while time.time() < t_end:
    for v in vecs:
        po.write_fields(img, v["ctx"]); po.evaluate(img.start); n += 1
print(f"SWEEP END {pid} evaluations={n}", flush=True)
