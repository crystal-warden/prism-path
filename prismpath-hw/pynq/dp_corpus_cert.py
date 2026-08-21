# dp_corpus_cert.py — #108's fabric corpus certification, pointed at the DATAPATH overlay in
# PS mode (auto_mode=0, the reset default): the certified AXI path must be intact on the new
# bitstream. Paths adjusted for /home/xilinx flat layout.
import json, sys, time
sys.path.insert(0, "/home/xilinx")
from ppt_pynq import PptOverlay, PptImage
from collections import defaultdict
bundle = json.load(open(sys.argv[1]))
ol = PptOverlay("/home/xilinx/ppt_datapath.bit")
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
