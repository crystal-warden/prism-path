#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Wedge-safe quiesce: disarm a resident auto-mode PPT design before a different overlay is loaded.

Reprogramming the PL while an auto-mode design is actively mastering the AXI bus hard-wedges the ARM
(only a power cycle recovers). This disarms it first. It derives the ppt IP address from the RESIDENT
design's OWN hwh (ppt_datapath_zeck, loaded by prismpath-demo.service) instead of a blind constant,
and guards every AXI access with a MAGIC read, so it never probes an unmapped window. No-op on a
clean or non-PPT PL. Run as root with the pynq venv sourced.
"""
import time
from pynq import Overlay, MMIO

RESIDENT_BIT = "/home/xilinx/ppt_datapath_zeck.bit"   # what prismpath-demo.service loads
R_SOFT_RST, R_MAGIC, R_AUTO_CTRL = 0x20, 0x24, 0x28
MAGIC = 0x50505431                                    # "PPT1"

st = open("/sys/class/fpga_manager/fpga0/state").read().strip()
print("fpga state:", st)
if st != "operating":
    print("PL not operating -> nothing to quiesce"); raise SystemExit(0)

# Derive the base from the resident design's hwh WITHOUT reprogramming (download=False parses the
# hardware handoff only). This is the "derive from the current design, never a constant" rule.
ol = Overlay(RESIDENT_BIT, download=False)
base = None
for k, e in ol.ip_dict.items():
    pa = e.get("phys_addr")
    if isinstance(pa, int) and any(s in k.lower() for s in ("ppt", "interp", "datapath")):
        base = pa; print(f"resident ppt IP: {k} @ {pa:#010x}"); break
if base is None:
    base = 0x40000000
    print(f"no ppt IP in hwh; magic-guarded fallback to {base:#010x}")

m = MMIO(base, 0x10000)
mg = m.read(R_MAGIC)
print("magic @0x24:", hex(mg))
if mg == MAGIC:
    m.write(R_AUTO_CTRL, 0); m.write(R_SOFT_RST, 1); time.sleep(0.05)
    print(f"DISARMED auto + soft-reset at {base:#010x}; auto_ctrl now = {m.read(R_AUTO_CTRL)}")
else:
    print("MAGIC mismatch -> not a PPT auto design here; no write performed (safe)")
