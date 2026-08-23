#!/usr/bin/env python3
"""led_listen.py - the FPGA render endpoint of the decision-delta pipeline.

The dev station emits raw control EVENTS; the signed posture_selector on the Protectli DECIDES
(the certified eBPF resident FSM) and forwards only the DELTAS (posture changes) here over UDP,
each carrying the upstream receipt's seq + signed t_ns. This listener does no deciding: it lights
LD4/LD5 for the received posture and appends a render line to a trail file. Holds never arrive
(send-on-delta), so the LED's hold-time IS the time-delta made physical.

Run ON the Arty Z7-20 under PYNQ, as root with the venv sourced:
  sudo bash -c 'source /etc/profile.d/pynq_venv.sh; source /etc/profile.d/xrt_setup.sh; \
                source /etc/profile.d/boardname.sh; cd /home/xilinx; \
                nohup python3 led_listen.py 90 /home/xilinx/led_render.log > /home/xilinx/led_listen.out 2>&1 &'

WEDGE SAFETY: this does NOT probe a hardcoded AXI address before loading (that hangs the Zynq bus
if a different design is resident). PRECONDITION: the PL is clean - power-cycle the board first, or
have a non-auto design resident. On a fresh boot the Overlay load is safe with no probing.
"""
import sys, time, socket
sys.path.insert(0, "/home/xilinx")
from ppt_pynq import PptImage, PptOverlay
from pynq import MMIO

BIT = "/home/xilinx/ppt_pathb.bit"
# demo_input just puts the pathb overlay into its proven PS-driven LED state (as live_stepped.py
# does); we ignore the interpreter and drive the LEDs directly from the posture on the wire.
PPT = "/home/xilinx/demo_input.ppt"
JSN = "/home/xilinx/demo_input.json"
LED_BASE = 0x41210000                       # axi_gpio -> LD4/LD5 (from live_stepped.py / poke_pathb.py)

# posture index (from posture_selector node order) -> 6-bit LD4|LD5 color, both LEDs
#   LD4 r/g/b = 0x01/0x02/0x04 ; LD5 r/g/b = 0x08/0x10/0x20
NAME  = {0: "normal",   1: "elevated", 2: "lockdown"}
COLOR = {0: 0x12,       1: 0x1b,       2: 0x09}        # green / amber / red (both LEDs)

def main():
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 90
    trail = sys.argv[2] if len(sys.argv) > 2 else "/home/xilinx/led_render.log"
    port  = int(sys.argv[3]) if len(sys.argv) > 3 else 9410

    img = PptImage(PPT, JSN)
    ol = PptOverlay(BIT)                      # direct load; PL must be clean (see WEDGE SAFETY)
    ol.load_image(img)
    leds = MMIO(LED_BASE, 0x10000)
    leds.write(0x04, 0x00)                    # TRI -> outputs
    leds.write(0x00, COLOR[0])               # park green (normal), matching the resident start posture

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx.bind(("0.0.0.0", port))
    rx.settimeout(0.5)

    f = open(trail, "a", buffering=1)
    hdr = f"# led_listen trail  port={port}  overlay={BIT}  started_local={time.time():.6f}"
    print(hdr, flush=True); f.write(hdr + "\n")
    f.write("# recv_local_s\tposture\tidx\tled\tup_seq\tup_t_ns\n")

    rendered = 0
    t_end = time.time() + duration
    last = 0
    while time.time() < t_end:
        try:
            data, _ = rx.recvfrom(64)
        except socket.timeout:
            continue
        parts = data.decode(errors="ignore").split()
        if not parts or not parts[0].lstrip("-").isdigit():
            continue
        idx = int(parts[0])
        up_seq = parts[1] if len(parts) > 1 else "-"
        up_t_ns = parts[2] if len(parts) > 2 else "-"
        color = COLOR.get(idx)
        if color is None:
            continue
        leds.write(0x00, color)              # RENDER the posture the selector decided
        recv = time.time()
        last = idx
        rendered += 1
        line = f"{recv:.6f}\t{NAME.get(idx,'?')}\t{idx}\t0x{color:02x}\t{up_seq}\t{up_t_ns}"
        print("  DELTA -> " + line, flush=True)
        f.write(line + "\n")

    leds.write(0x00, COLOR[0])               # park green on exit
    tail = f"# done: {rendered} deltas rendered; parked green. last={NAME.get(last,'?')}"
    print(tail, flush=True); f.write(tail + "\n"); f.close()

if __name__ == "__main__":
    main()
