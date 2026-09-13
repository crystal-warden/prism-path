#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# arm_uart_auto.py - board-side: load the PL-native UART overlay, load the demo policy + its per-node
# colors into the fabric, and ARM auto mode. After this the fabric closes the whole loop in the PL:
# a byte on Pmod JA1 (from the ESP-NOW bridge) -> uart_rx -> field -> Level M interpreter -> per-node
# color -> RGB LED. The PS only arms it and reads POT_NOW back to show the live field; it makes no
# decision. Loads ppt_datapath_uart.bit ONLY - the certified checkpoint ppt_datapath.bit is a
# separate file and is never touched, so reverting is just loading that bit instead.
#
#   sudo bash -c 'source /etc/profile.d/pynq_venv.sh; source /etc/profile.d/xrt_setup.sh; \
#                 source /etc/profile.d/boardname.sh; python3 arm_uart_auto.py'
import sys, time, json
sys.path.insert(0, "/home/xilinx")
from pynq import MMIO
from ppt_pynq import PptImage, PptOverlay

BIT  = sys.argv[1] if len(sys.argv) > 1 else "/home/xilinx/ppt_datapath_zeck.bit"
PPT  = "/home/xilinx/demo_input.ppt"
JSON = "/home/xilinx/demo_input.json"
# Same arm path for either UART overlay (ppt_datapath_uart = MCU-decoded byte,
# ppt_datapath_zeck = fabric-decoded frame): identical ppt_axi map, policy, colors, auto mode.
# Pass the .bit as arg 1; defaults to the native fabric-decode overlay.

R_LOAD_SEL_ADDR = 0x00
R_LOAD_DATA     = 0x04
R_SOFT_RST      = 0x20
R_MAGIC         = 0x24
R_AUTO_CTRL     = 0x28
R_POT_NOW       = 0x2C
MAGIC           = 0x50505431

# --- quiesce a live auto design before reprogramming (avoid ARM wedge; led_from_band pattern) ---
try:
    state = open("/sys/class/fpga_manager/fpga0/state").read().strip()
    if state == "operating":
        mmio = MMIO(0x40000000, 0x10000)
        if mmio.read(R_MAGIC) == MAGIC:
            mmio.write(R_AUTO_CTRL, 0); mmio.write(R_SOFT_RST, 1); time.sleep(0.05)
            print("[arm] quiesced prior auto design", file=sys.stderr)
except Exception as error:
    print(f"[arm] quiesce skipped ({type(error).__name__})", file=sys.stderr)

img = PptImage(PPT, JSON)
overlay = PptOverlay(BIT)
overlay.load_image(img)                                       # routing program (sels 0..6)

# --- per-node colors (sel=7) from the JSON's compiled colors: the signed table's own colors ---
nodes  = sorted(json.load(open(JSON))["nodes"], key=lambda node: node["i"])
colors = [node.get("color", 0) for node in nodes]
for node_index, color in enumerate(colors):
    overlay.io.write(R_LOAD_SEL_ADDR, (7 << 16) | node_index)
    overlay.io.write(R_LOAD_DATA, color & 0xFFFFFFFF)
print("[arm] colors loaded: " + ", ".join(
    f"{nodes[index]['name']}=0x{colors[index]:02x}" for index in range(len(nodes))))

# --- arm auto: auto_mode=1, start_node=0, pot_field_idx=0 ---
overlay.io.write(R_AUTO_CTRL, 0x00000001)
assert overlay.io.read(R_MAGIC) == MAGIC, "overlay not alive after arm"
print("[arm] AUTO ARMED - the fabric now decides on UART bytes (Pmod JA1). Watch LD4/LD5.")
print("[arm]   field cuts: >=1631 high(RED)  >=665 mid(BLUE)  else low(GREEN)")

# --- live readback: POT_NOW reflects the ACTUAL field (UART byte<<4, or the pot until a byte lands) ---
def label(field_value):
    return "high/RED" if field_value >= 1631 else "mid/BLUE" if field_value >= 665 else "low/GREEN"
print("[arm] reading POT_NOW (Ctrl-C to leave it armed)...")
last = None
try:
    while True:
        field_value = overlay.io.read(R_POT_NOW) & 0xFFFF
        if field_value != last:
            print(f"[arm] field={field_value:5d} -> fabric lights {label(field_value)}")
            last = field_value
        time.sleep(0.1)
except KeyboardInterrupt:
    print("\n[arm] left armed. UART -> fabric -> LED loop is live.")
