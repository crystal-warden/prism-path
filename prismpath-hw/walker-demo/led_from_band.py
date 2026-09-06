# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# led_from_band.py - the FPGA end of the walker->mesh->FPGA hop. Reads walker motion BAND values
# (0..4) on stdin (one per line, relayed by gx10 off a fixed mesh node), maps each to a pot-field
# value, evaluates it through the datapath overlay's Level M interpreter IN THE FABRIC (PS-mode
# evaluate over AXI), and lights the RGB LED from the decision. The fabric decides; the PS only
# couriers the band in and the color out. Quiesces any armed auto design first so the Overlay load
# cannot wedge the ARM (dp_load.py pattern).
#
#   sudo bash -c 'source /etc/profile.d/pynq_venv.sh; source /etc/profile.d/xrt_setup.sh; \
#                 source /etc/profile.d/boardname.sh; python3 led_from_band.py'
import sys, time
sys.path.insert(0, "/home/xilinx")
from pynq import MMIO
from ppt_pynq import PptImage, PptOverlay

R_AUTO_CTRL = 0x28

# --- quiesce a live auto design before reprogramming (avoid ARM wedge) ---
try:
    state = open("/sys/class/fpga_manager/fpga0/state").read().strip()
    if state == "operating":
        m = MMIO(0x40000000, 0x10000)
        if m.read(0x24) == 0x50505431:
            m.write(R_AUTO_CTRL, 0); m.write(0x20, 1); time.sleep(0.05)
            print("[led] quiesced prior auto design", file=sys.stderr)
except Exception as e:
    print(f"[led] quiesce skipped ({type(e).__name__})", file=sys.stderr)

img = PptImage("/home/xilinx/demo_input.ppt", "/home/xilinx/demo_input.json")
ol = PptOverlay("/home/xilinx/ppt_datapath.bit")     # PS mode (auto off): led_o = ps_led = gpio_out
ol.load_image(img)
gpio = ol.ol.gpio_out                                 # raw Overlay's 6b axi_gpio -> ps_led -> LD4/LD5

# demo_input decision node -> RGB color (matches the signed colors: high=red, mid=blue, low=green)
NODE_COLOR = {1: 0x01, 2: 0x04, 3: 0x02}              # 1=high(R) 2=mid(B) 3=low(G); LD4 r/g/b=0x01/0x02/0x04
BAND_POT   = [200, 500, 1000, 1800, 2600]             # band 0..4 -> pot-field value (still..vigorous)

def set_led(color):
    try:
        gpio.channel1.write(color, 0x3F)
    except Exception:
        try:    gpio.write(color, 0x3F)
        except Exception as e:  print(f"[led] LED write failed: {e}", file=sys.stderr)

print("READY", flush=True)
for line in sys.stdin:
    line = line.strip()
    if not line.lstrip("-").isdigit():
        continue
    band = max(0, min(4, int(line)))
    pot = BAND_POT[band]
    ol.write_fields(img, {"pot": pot})
    res = ol.evaluate(img.start)                       # the fabric interpreter decides
    target = res[1] if res else -1
    color = NODE_COLOR.get(target, 0)
    set_led(color)
    names = img.node_names
    print(f"band={band} pot={pot} -> node={target}({names[target] if 0<=target<len(names) else '?'}) "
          f"led=0x{color:02x}", flush=True)
