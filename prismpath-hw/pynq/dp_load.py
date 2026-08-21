#!/usr/bin/env python3
"""dp_load.py — the ENTIRE software footprint of the demo, then it exits.

    sudo python3 dp_load.py <pack.ppt> <debug.json> <authority.pub>

1. Verifies the signed pack ON the board (ed25519 over the canonical manifest + image sha256 +
   header counts + wcet recompute) — an unauthorized or tampered policy refuses to load.
2. Loads the table into fabric BRAM and the per-node colors (from the SIGNED image's color
   section) into the fabric color LUT.
3. Arms AUTO_CTRL (start node + pot field index + auto_mode=1) and EXITS.

After exit, no policy logic exists in software: the fabric reads the pot over XADC-DRP,
evaluates the signed policy, and drives the RGB LEDs from the signed colors. Kill every
process; the knob still answers."""
import json
import struct
import sys

sys.path.insert(0, "/home/xilinx")
import policy_pack
from ppt_pynq import PptImage, PptOverlay

R_LOAD_SEL_ADDR, R_LOAD_DATA, R_AUTO_CTRL = 0x00, 0x04, 0x28

ppt_path, json_path, pub_path = sys.argv[1], sys.argv[2], sys.argv[3]
BIT = sys.argv[4] if len(sys.argv) > 4 else "/home/xilinx/ppt_datapath.bit"

ok, reasons, man = policy_pack.verify_pack(ppt_path, [pub_path])
if not ok:
    print(f"REFUSED: {reasons}")
    sys.exit(1)
print(f"verified: {man['envelope_id']} v{man['version']} key={man['key_id'][:8]} "
      f"wcet={man.get('wcet_cycles','-')}cyc sha={man['image_sha256'][:8]}")

data = open(ppt_path, "rb").read()
h = policy_pack.read_ppt_header(data)
colors = [0] * h["nodes"]
if h["flags"] & policy_pack.FLAG_COLORS:
    off = len(data) - 2 * h["nodes"]
    colors = list(struct.unpack_from(f"<{h['nodes']}H", data, off))

img = PptImage(ppt_path, json_path)

# QUIESCE BEFORE REPROGRAM: if a previous datapath design is live in auto mode (FSM + DRP engine
# running), reprogramming the PL under it can leave a dangling handshake that wedges the ARM on the
# next PL access. Disarm + soft-reset the old design first; harmless if the PL is fresh or absent.
try:
    # only touch 0x40000000 if the PL is actually configured — an AXI access to an
    # unprogrammed PL (fresh boot) wedges the ARM just as hard as the hazard we're avoiding.
    state = open("/sys/class/fpga_manager/fpga0/state").read().strip()
    if state == "operating":
        from pynq import MMIO
        old = MMIO(0x40000000, 0x10000)
        if old.read(0x24) == 0x50505431:                  # a ppt design is present
            old.write(R_AUTO_CTRL, 0)                     # auto off: FSM + LED mux back to PS mode
            old.write(0x20, 1)                            # soft reset the core
            import time; time.sleep(0.05)
            print("quiesced previous design (auto disarmed, core reset)")
    else:
        print(f"PL state '{state}' — no design to quiesce")
except Exception as e:
    print(f"quiesce skipped ({type(e).__name__}) — proceeding")

ol = PptOverlay(BIT)                                       # asserts PPT1 magic
ol.load_image(img)
for ni, c in enumerate(colors):                            # signed colors -> fabric LUT (sel=7)
    ol.io.write(R_LOAD_SEL_ADDR, (7 << 16) | ni)
    ol.io.write(R_LOAD_DATA, c)

pot_fidx = img.fields["pot"]
ol.io.write(R_AUTO_CTRL, (pot_fidx << 16) | (img.start << 8) | 1)
names = img.node_names
print(f"loaded: start='{names[img.start]}' colors=" +
      " ".join(f"{names[i]}=0x{c:02x}" for i, c in enumerate(colors) if c))
print("AUTO_MODE ARMED — fabric owns the loop. Exiting; software is done.")
