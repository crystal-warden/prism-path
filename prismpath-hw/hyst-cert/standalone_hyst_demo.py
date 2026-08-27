#!/usr/bin/env python3
# standalone_hyst_demo.py - DEMO boot: the stateful finale from nothing but power. v2: the OLED is
# rendered IN-PROCESS (import oled_live_v2), so exactly ONE process touches the PL — no concurrent
# MMIO pollers (mitigation for the bench wedge pattern seen with two pollers running).
# Sequence: wait out jupyter's base.bit (same discipline as standalone_finale), claim the PL with
# ppt_finale.bit, SELF-CHECK the fabric on signed demo_input (the proven acquire path), then load
# the signed hyst_band tables, arm the STATEFUL word (resident band + fail-safe, the signed mode),
# init the OLED resident readout, and settle into one flight-recorder + render loop on CUR_NODE.
# Self-heals by reacquiring if MAGIC ever reads wrong. Buttons stay live: the fabric ROM roster
# (BTN0 exact / BTN1 steady / BTN3 finale) works under this arm; a BTN swap re-arms from the
# SIGNED pack replay.
import json
import os
import sys
import time

sys.path.insert(0, "/home/xilinx")
import standalone_finale as sf              # wait_for_pl_settled / quiesce / acquire (proven path)
from cert_hyst_board import load_policy     # MMIO-level PS load of a signed .ppt
import oled_live_v2 as ol2                  # in-process OLED render (oled_init / oled_tick)

LOG = "/home/xilinx/hyst_demo_log.ndjson"
ARM_STATEFUL = 0x02000003                   # safe=2<<24 | fidx=0<<16 | start=0<<8 | stateful | en
R_MAGIC, R_AUTO, R_POT, R_CUR = 0x24, 0x28, 0x2C, 0x30
NAMES = {0: "low/GREEN", 1: "mid/BLUE", 2: "high/RED"}


def rec(log, obj):
    log.write(json.dumps(obj) + "\n"); log.flush(); os.fsync(log.fileno())


def arm_hyst(ol, log):
    dbg = json.load(open("/home/xilinx/hyst_band.json"))
    ol.io.write(R_AUTO, 0)
    load_policy(ol.io, "/home/xilinx/hyst_band.ppt", dbg)
    ol.io.write(R_AUTO, ARM_STATEFUL)
    time.sleep(0.05)
    cn = ol.io.read(R_CUR)
    if not ((cn >> 16) & 1):
        raise RuntimeError("stateful arm readback bad")
    rec(log, {"event": "hyst_armed", "wall": time.time(), "arm": hex(ARM_STATEFUL)})


def main():
    sf.wait_for_pl_settled()
    log = open(LOG, "a")
    ol = sf.acquire(log, "demo_armed")      # bit + demo_input self-check + stateless arm (proven)
    if ol is None:
        return
    arm_hyst(ol, log)
    ol2.oled_init()
    rec(log, {"event": "oled_inproc", "wall": time.time()})
    t0 = time.time(); last = None; oled_key = None
    while True:
        try:
            if ol.io.read(R_MAGIC) != sf.MAGIC:
                rec(log, {"event": "clobbered", "t": round(time.time() - t0, 3)})
                ol = sf.acquire(log, "reclaim")
                if ol is None:
                    return
                arm_hyst(ol, log); ol2.oled_init(); last = None; oled_key = None
            cn = ol.io.read(R_CUR)
            band = cn & 0xFFFF if ((cn >> 16) & 1) else None
            pot = ol.io.read(R_POT) & 0xFFF
            if band is not None and band != last:
                rec(log, {"t": round(time.time() - t0, 3), "pot": pot,
                          "band": NAMES.get(band, band)})
                last = band
            oled_key = ol2.oled_tick(oled_key)
            time.sleep(0.05)
        except Exception as e:
            rec(log, {"event": "error", "error": str(e)}); time.sleep(2)


if __name__ == "__main__":
    main()
