# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# Runs ON THE BOARD as root with the PYNQ env sourced. Attaches to the RESIDENT finale overlay (loaded
# by the boot demo service) WITHOUT reconfiguring the PL, using the current design's own hwh for the
# address (memory fpga-board-access: never a hardcoded probe, one configuration per power cycle):
# auto mode off (PS path, the certified evaluate path of #117/#123), then the A3 fabric leg: every
# corpus vector on both compiled images, targets and cause byte recorded. Appends lines to a file.
#   usage: python3 a3_fabric_attach.py a3_fabric_bundle.json out.log
import json, sys, time
sys.path.insert(0, "/home/xilinx")
from pynq import Overlay, MMIO
import ppt_pynq as P

bundle = json.load(open(sys.argv[1])); out = open(sys.argv[2], "a", buffering=1)
def log(s): out.write(s + "\n"); out.flush()
R_AUTO_CTRL, R_CAUSE = 0x28, 0x34

log("BOOT " + time.strftime("%Y-%m-%dT%H:%M:%S") + " attach-only, no PL download")
ol = Overlay("/home/xilinx/ppt_finale.bit", download=False)      # parse the resident design's hwh only
ip = next(k for k in ol.ip_dict if "ppt" in k.lower())
base = ol.ip_dict[ip]["phys_addr"]
io = MMIO(base, 0x100)
log(f"ATTACHED ip={ip} base={base:#x}")
io.write(R_AUTO_CTRL, 0)                                         # auto off: FSM and LED mux back to PS mode
time.sleep(0.05)
magic = io.read(P.R_MAGIC)
log(f"MAGIC {magic:#x} {'ok' if magic == P.MAGIC else 'MISMATCH'}")
assert magic == P.MAGIC
po = P.PptOverlay.__new__(P.PptOverlay); po.io = io                # the driver's methods over the attached MMIO

rows = []
for pid, spec in bundle["images"].items():
    open(f"/tmp/{pid}.ppt", "wb").write(bytes.fromhex(spec["ppt_hex"])); json.dump(spec["json"], open(f"/tmp/{pid}.json", "w"))
    img = P.PptImage(f"/tmp/{pid}.ppt", f"/tmp/{pid}.json")
    po.load_image(img)
    for v in bundle["vectors"]:
        if v["cid"] != pid: continue
        po.write_fields(img, v["ctx"])
        t0 = time.perf_counter_ns(); res = po.evaluate(img.start); dt = (time.perf_counter_ns() - t0) / 1000
        cause = io.read(R_CAUSE) & 0xFF
        target = res[1] if res is not None else -1
        rows.append({"policy": pid, "scenario": v["scenario"], "fabric_target": target, "fabric_edge": res[0] if res else None,
                     "cause": cause, "python_target": v["python_target"], "agree": target == v["python_target"], "round_trip_us": round(dt, 1)})
        log("A3ROW " + json.dumps(rows[-1]))
log(f"A3DONE {sum(1 for r in rows if r['agree'])}/{len(rows)} fabric targets equal the host Python targets (resident ppt_finale overlay, PS path)")
log("ALLDONE")
