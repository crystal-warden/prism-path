#!/usr/bin/env bash
# wcet_rewitness.sh — WCET-on-pins for hyst_band (the last gate before the commits + row #123).
#
# The finale bitstream has no tap pins, so this runs on the TAPPED ppt_datapath overlay (Pmod JB
# tap, LA2016 @ 200MSa/s — the same rig as the demo_input/demo_binary witnesses). The witness
# measures the per-evaluate busy window; the bound is a property of the signed table (worst node =
# mid, 3 edges, signed wcet=11), independent of WHO supplies the start node — so arming the
# stateless tapped overlay from start=mid exercises exactly the worst path every evaluate.
#
# Operator preconditions: LA2016 on Pmod JB (JB1=clk JB2=busy JB3=done JB4=start JB5=GND), pot
# wired to A0/3V3/GND. Run from gx10; SWEEP THE POT while the capture loop runs.
set -euo pipefail
JUMP="${PPT_JUMP:-adminlocal@192.168.4.2}"
BOARD="${PPT_BOARD:-xilinx@10.10.10.2}"
HERE="$(cd "$(dirname "$0")" && pwd)"
HW="$HERE/.."

echo "== 1/3 land hyst_band on the board =="
scp -J "$JUMP" "$HW/demo/flows/hyst_band.ppt" "$HW/demo/flows/hyst_band.json" "$BOARD:/tmp/"

echo "== 2/3 stop the demo service; load TAPPED ppt_datapath + hyst_band, arm start=mid =="
ssh -J "$JUMP" "$BOARD" "sudo bash -s" <<'REMOTE'
systemctl stop prismpath-finale.service 2>/dev/null
mv /tmp/hyst_band.ppt /tmp/hyst_band.json /home/xilinx/ 2>/dev/null || true
source /etc/profile.d/pynq_venv.sh; source /etc/profile.d/xrt_setup.sh 2>/dev/null; source /etc/profile.d/boardname.sh 2>/dev/null
cd /home/xilinx
python3 - <<'PY'
import json, sys, time
sys.path.insert(0, "/home/xilinx")
from ppt_pynq import PptImage, PptOverlay
img = PptImage("/home/xilinx/hyst_band.ppt", "/home/xilinx/hyst_band.json")
ol = PptOverlay("/home/xilinx/ppt_datapath.bit")     # the TAPPED overlay (wcet_tap on JB)
ol.load_image(img)
nodes = sorted(json.load(open("/home/xilinx/hyst_band.json"))["nodes"], key=lambda n: n["i"])
for ni, n in enumerate(nodes):
    ol.io.write(0x00, (7 << 16) | ni)
    ol.io.write(0x04, int(n.get("color", 0)) & 0xFFFFFFFF)
pot_fidx = json.load(open("/home/xilinx/hyst_band.json"))["fields"]["pot"]
ol.io.write(0x28, (pot_fidx << 16) | (1 << 8) | 1)   # arm from start=mid: worst 3-edge node
time.sleep(0.05)
print("tapped overlay armed from mid; POT_NOW =", ol.io.read(0x2C) & 0xFFF)
PY
REMOTE

echo "== 3/3 capture + verdict (SWEEP THE POT for the whole run, ~2 min) =="
export LD_LIBRARY_PATH=/usr/local/lib
cd "$HW/wcet-pins"
python3 sweep_wcet.py --bound 11 --iters 20 --samples 40000 --rate 200m
echo ""
echo "on PASS: copy the printed .sr/verdict artifacts into $HERE/evidence/ + extend SHA256SUMS;"
echo "then the commits and row #123 finalize. Restore the demo:"
echo "  ssh -J $JUMP $BOARD 'sudo systemctl start prismpath-finale.service'"
