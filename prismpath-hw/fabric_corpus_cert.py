# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
import json, sys, time
sys.path.insert(0, "/home/xilinx/ppt")
from ppt_pynq import PptOverlay, PptImage
from collections import defaultdict
bundle = json.load(open(sys.argv[1]))
ol = PptOverlay("/home/xilinx/ppt/ppt_overlay.bit")
byc = defaultdict(list)
for i, v in enumerate(bundle["vectors"]):
    byc[v["cid"]].append((i, v["ctx"]))
results = {}; lat = []
for cid, spec in bundle["images"].items():
    open("/tmp/fc.ppt", "wb").write(bytes.fromhex(spec["ppt_hex"]))
    json.dump(spec["json"], open("/tmp/fc.json", "w"))
    img = PptImage("/tmp/fc.ppt", "/tmp/fc.json")
    ol.load_image(img)
    for i, ctx in byc[cid]:
        ol.write_fields(img, ctx)
        t0 = time.perf_counter_ns()
        res = ol.evaluate(img.start)
        lat.append((time.perf_counter_ns() - t0) / 1000)
        results[str(i)] = res is not None
lat.sort()
print("FCERT " + json.dumps({"results": results, "n": len(lat),
      "lat_min": round(lat[0],1), "lat_med": round(lat[len(lat)//2],1), "lat_max": round(lat[-1],1)}))
