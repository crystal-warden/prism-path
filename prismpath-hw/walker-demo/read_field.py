#!/usr/bin/env python3
# read_field.py - read the native overlay's POT_NOW register (the ACTUAL field the fabric decides on:
# the fabric-decoded band value once the walker's frames arrive over JA1, else the XADC pot). Pure
# MMIO read, no overlay reload, so it does not disturb the armed auto loop.
import time
from pynq import MMIO

m = MMIO(0x40000000, 0x100)
mg = m.read(0x24)
print(f"MAGIC={mg:#010x} ({'PPT1 datapath overlay' if mg == 0x50505431 else 'UNEXPECTED'})")

R_POT_NOW = 0x2C
BANDVAL = {200: 0, 500: 1, 1000: 2, 1800: 3, 2600: 4}   # the band->field LUT in ppt_datapath_zeck


def label(f):
    return "high/RED" if f >= 1631 else "mid/BLUE" if f >= 665 else "low/GREEN"


seen = set()
last = None
t0 = time.time()
while time.time() - t0 < 12:
    f = m.read(R_POT_NOW) & 0xFFFF
    seen.add(f)
    if f != last:
        tag = f"band {BANDVAL[f]}" if f in BANDVAL else "(pot-like -> no frame decoded)"
        print(f"field={f:5d} -> {label(f):9s} {tag}")
        last = f
    time.sleep(0.1)

bandvals = sorted(v for v in seen if v in BANDVAL)
if bandvals:
    print(f"RESULT: fabric is decoding walker frames. band-fields seen: {bandvals}")
else:
    print(f"RESULT: no band decoded -- field stayed pot-like ({sorted(seen)[:6]}...). "
          f"Check the D4->JA1 wire / shared GND / walker powered.")
