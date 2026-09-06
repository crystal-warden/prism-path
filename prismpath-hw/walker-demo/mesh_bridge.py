# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# mesh_bridge.py - gx10 side of the walker -> mesh -> FPGA hop. Reads a FIXED mesh node's serial,
# pulls the WALKER's band out of its "R 2 c1 t<tick> v<band>" receive lines (role 2 = walker,
# class 1 = band tier), and prints the band to stdout on change - to be piped into the board's
# led_from_band.py over SSH. The walker is heard over the air; nothing is wired to the FPGA.
import serial, sys, re, time
PORT = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB2"
s = serial.Serial(PORT, 115200, timeout=0.3)
s.setDTR(False); s.setRTS(True); time.sleep(0.15); s.setRTS(False)   # reset the node into run mode
time.sleep(0.1); s.reset_input_buffer()
pat = re.compile(rb"R 2 c1 t\d+ v(\d+)")
last = None
sys.stderr.write(f"[bridge] reading {PORT} for the walker's band (role 2)...\n"); sys.stderr.flush()
while True:
    line = s.readline()
    if not line:
        continue
    m = pat.search(line)
    if m:
        band = int(m.group(1))
        if band != last:
            print(band, flush=True)                        # -> board daemon stdin
            sys.stderr.write(f"[bridge] walker band -> {band}\n"); sys.stderr.flush()
            last = band
