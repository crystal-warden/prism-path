#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# measure_zeck_codec.py — board-side: MEASURE the native Zeckendorf codec on the physical Zynq fabric,
# closing C2's "FPGA shift-register codec unbuilt" caveat. Loads ppt_zeck.bit and:
#   (1) runs the in-fabric self-test sweep n=1..MAX  -> decode(encode(n))==n, counted in the PL;
#   (2) PEEKs each value of the same seed-42 corpus the MCU bench used, and checks the fabric's
#       encoded wire bits == the reference AND the in-fabric decode == n.
# The codec runs entirely in the PL; the PS only starts runs and reads tallies. N/N here is the
# measurement (not a model) that the ledger's C2 row was waiting on.
#
#   sudo bash -c 'source /etc/profile.d/pynq_venv.sh; source /etc/profile.d/xrt_setup.sh; \
#                 source /etc/profile.d/boardname.sh; python3 measure_zeck_codec.py [bit] [MAX]'
import sys
import random
from pynq import Overlay, MMIO

BIT = sys.argv[1] if len(sys.argv) > 1 else "/home/xilinx/ppt_zeck.bit"
MAX = int(sys.argv[2]) if len(sys.argv) > 2 else 1000

R_MAGIC = 0x00; R_CTRL = 0x04; R_STATUS = 0x08; R_PEEK_IN = 0x0C; R_SELFTEST_MAX = 0x10
R_PEEK_BITS = 0x14; R_PEEK_LEN = 0x18; R_PEEK_DEC = 0x1C
R_PASS = 0x20; R_TOTAL = 0x24; R_FIRST_FAIL = 0x28
MAGIC = 0x5A434B31

# --- inline Zeckendorf reference (matches zeck.h / prismpath.telemetry.zeckendorf; no board deps) ---
FIB = [1, 2]
while FIB[-1] < 2 ** 53:
    FIB.append(FIB[-1] + FIB[-2])


def zeck_bits(n):
    """The wire bit-string for n: F2..Fk value bits ascending, then the self-framing terminator 1."""
    k = 0
    while k + 1 < len(FIB) and FIB[k + 1] <= n:
        k += 1
    code = ['0'] * (k + 1)
    rem = n
    for i in range(k, -1, -1):
        if FIB[i] <= rem:
            code[i] = '1'
            rem -= FIB[i]
    return ''.join(code) + '1'


# --- quiesce any armed auto design before reprogramming (avoid ARM wedge; led_from_band pattern) ---
try:
    state = open("/sys/class/fpga_manager/fpga0/state").read().strip()
    if state == "operating":
        m = MMIO(0x40000000, 0x10000)
        if m.read(0x24) == 0x50505431:          # a live PPT1 datapath overlay
            m.write(0x28, 0); m.write(0x20, 1)   # auto_ctrl=0, soft_rst
        del m
except Exception as e:
    print(f"[zeck] quiesce skipped ({type(e).__name__})", file=sys.stderr)

ol = Overlay(BIT)
ipname = next(k for k in ol.ip_dict if "ppt" in k.lower())
base = ol.ip_dict[ipname]["phys_addr"]
io = MMIO(base, 0x100)
got = io.read(R_MAGIC)
assert got == MAGIC, f"overlay MAGIC {got:#x} != ZCK1 (0x5A434B31)"
print(f"[zeck] overlay up @ {base:#x}, MAGIC=ZCK1")


def peek(n):
    io.write(R_PEEK_IN, n)
    io.write(R_CTRL, 0x1)                        # peek_go pulse
    for _ in range(100000):
        if io.read(R_STATUS) & 0b0010:           # peek_done
            break
    else:
        raise TimeoutError(f"peek({n}) never completed")
    bits = io.read(R_PEEK_BITS)
    ln = io.read(R_PEEK_LEN) & 0x7F
    dec = io.read(R_PEEK_DEC)
    wire = "".join(str((bits >> (ln - 1 - j)) & 1) for j in range(ln))
    return wire, dec


# --- (1) in-fabric self-test sweep ---
io.write(R_SELFTEST_MAX, MAX)
io.write(R_CTRL, 0x2)                             # selftest_go pulse
for _ in range(2000000):
    if io.read(R_STATUS) & 0b0100:               # selftest_done
        break
else:
    raise TimeoutError("selftest never completed")
pc = io.read(R_PASS); tot = io.read(R_TOTAL); ff = io.read(R_FIRST_FAIL)
err = (io.read(R_STATUS) >> 3) & 1
print(f"[zeck] SELF-TEST on silicon: {pc}/{tot} round-trips decode(encode(n))==n  first_fail={ff} err={err}")

# --- (2) per-value wire-exactness vs the reference, same seed-42 corpus as the MCU bench ---
random.seed(42)
vals = set()
for lo, hi in ((1, 6), (1, 1001)):
    for _ in range(64):
        for _ in range(4):
            vals.add(random.randint(lo, hi))
vals = sorted(vals)
wire_ok = dec_ok = 0
first_bad = None
for n in vals:
    wire, dec = peek(n)
    if wire == zeck_bits(n):
        wire_ok += 1
    elif first_bad is None:
        first_bad = (n, "wire", wire, zeck_bits(n))
    if dec == n:
        dec_ok += 1
    elif first_bad is None:
        first_bad = (n, "dec", dec, n)
print(f"[zeck] PEEK on silicon: wire {wire_ok}/{len(vals)} bit-exact vs reference; "
      f"decode {dec_ok}/{len(vals)} == n")
if first_bad:
    print(f"[zeck] first mismatch: {first_bad}")

ok = (pc == tot == MAX and ff == 0 and err == 0 and wire_ok == len(vals) == dec_ok)
print("[zeck] === C2 MEASURED ON SILICON: PASS ===" if ok else "[zeck] === MEASUREMENT FAILED ===")
sys.exit(0 if ok else 1)
