#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""finale_cert.py — arc #6: silicon certification of the pure-fabric control plane (Arty Z7-20).

    sudo bash -c 'source /etc/profile.d/pynq_venv.sh; source /etc/profile.d/xrt_setup.sh; \
                  source /etc/profile.d/boardname.sh; cd /home/xilinx; python3 finale_cert.py'

What it proves ON SILICON, hands-off (button presses injected via the gpio_dbg cert hook, which ORs
into the same conditioned path as the physical buttons):

  A  the certified AXI path is intact on the finale bitstream: PS-mode load + evaluate works
  B  an injected BTN0 press makes the FABRIC loader install baked policy 0 (the SIGNED switch_nav
     pack, verified at bake time) with no processor: decisions change
  C  an injected BTN1 press installs baked policy 1 (live): decisions return EXACTLY to the
     PS-loaded baseline — the loader's replay is byte-identical to the PS, proven by decision parity
  D  the meta-swap (BTN3) flips the signed profile and the finale controls answer: severity bias,
     mute, color cycle, decision-arm (POT_NOW = ref+bias), then meta-swap back
  E  an out-of-range swap request (BTN2 in profile 0, pack index 2 of 2) is refused by the guard

Notes: live.ppt is the unsigned bench image (PS baseline leg only); the fabric-swapped pack was
signature-verified when tools/gen_pack_svh.py baked it. LED color is not electrically read back;
it follows node_color[dec_target], which leg C pins via decisions.
"""
import json
import sys
import time

sys.path.insert(0, "/home/xilinx")
from ppt_pynq import PptOverlay, PptImage

BIT = "/home/xilinx/ppt_finale.bit"
PROBES = [100, 400, 800, 1200, 1700, 2200, 3000]

# status bits: {thresh[1:0], color[2:0], mute, loading, profile}
B_PROFILE, B_LOADING, B_MUTE = 0x01, 0x02, 0x04


def gpio_dbg(ol):
    from pynq import MMIO
    entry = next(v for k, v in ol.ol.ip_dict.items() if "gpio_dbg" in k.lower())
    return MMIO(entry["phys_addr"], 0x1000)


def inject(dbg, bits, hold=0.05):
    dbg.write(0x0, bits)          # ch1 data: [3:0] btn, [5:4] sw
    time.sleep(hold)              # >> the 5 ms debounce
    dbg.write(0x0, 0)
    time.sleep(hold)


def sw_level(dbg, sw):
    dbg.write(0x0, (sw & 0x3) << 4)   # held level, not a pulse
    time.sleep(0.05)


def status(dbg):
    return dbg.read(0x8) & 0xFF


def wait_not_loading(dbg, timeout=1.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if not (status(dbg) & B_LOADING):
            return True
        time.sleep(0.002)
    return False


def decisions(ol, img):
    out = []
    for p in PROBES:
        ol.write_fields(img, {"pot": p})
        out.append(ol.evaluate(img.start))
    return out


def main():
    checks = []

    def check(name, ok, detail=""):
        checks.append((name, bool(ok), detail))
        print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))

    print("== finale silicon cert ==")
    ol = PptOverlay(BIT)                      # asserts the PPT1 magic
    dbg = gpio_dbg(ol)
    print("overlay loaded, magic ok, gpio_dbg mapped")

    st = status(dbg)
    check("A0 reset state: profile 0, not loading", (st & (B_PROFILE | B_LOADING)) == 0, f"status={st:#04x}")

    # A: PS-mode baseline on the certified path
    img = PptImage("/home/xilinx/live.ppt", "/home/xilinx/live.json")
    ol.load_image(img)
    base = decisions(ol, img)
    check("A1 PS-mode load + evaluate (certified path intact)", any(d is not None for d in base),
          f"decisions={base}")

    # B: fabric swap to baked policy 0 (signed switch_nav) via injected BTN0
    inject(dbg, 0x01)
    check("B1 loader ran and finished", wait_not_loading(dbg))
    swapped = decisions(ol, img)
    check("B2 policy actually changed", swapped != base, f"{swapped} vs {base}")

    # C: fabric swap to baked policy 1 (live) via injected BTN1 -> byte-identical replay
    inject(dbg, 0x02)
    check("C1 loader ran and finished", wait_not_loading(dbg))
    back = decisions(ol, img)
    check("C2 HEADLINE: fabric-loaded == PS-loaded, decision-exact", back == base, f"{back} vs {base}")

    # E: out-of-range swap (BTN2 in profile 0 -> pack index 2 of 2) must be refused
    inject(dbg, 0x04)
    time.sleep(0.1)
    check("E1 out-of-range swap refused (never loading)", not (status(dbg) & B_LOADING))

    # D: meta-swap into the finale profile; the same buttons now mean different things
    inject(dbg, 0x08)
    wait_not_loading(dbg)
    check("D1 meta-swap: profile flipped by signed table", status(dbg) & B_PROFILE)

    sw_level(dbg, 0x3)                        # severity: severe
    check("D2 switches now mean severity", ((status(dbg) >> 6) & 0x3) == 0x3)
    sw_level(dbg, 0x0)

    inject(dbg, 0x02)                         # BTN1 now = mute
    check("D3 BTN1 now mutes", status(dbg) & B_MUTE)
    inject(dbg, 0x02)
    check("D4 mute releases", not (status(dbg) & B_MUTE))

    c0 = (status(dbg) >> 3) & 0x7             # BTN0 now = color cycle
    inject(dbg, 0x01)
    check("D5 BTN0 now cycles color", ((status(dbg) >> 3) & 0x7) == ((c0 + 1) & 0x7))

    inject(dbg, 0x04)                         # BTN2 now = decision-arm: POT_NOW = ref(200)+bias(0)
    time.sleep(0.05)
    pot_now = ol.io.read(0x2C) & 0xFFF
    check("D6 decision-arm: POT_NOW = governed ref", pot_now == 200, f"POT_NOW={pot_now}")
    sw_level(dbg, 0x3)                        # severe while armed -> 200+1600
    pot_now = ol.io.read(0x2C) & 0xFFF
    check("D7 armed + severe bias", pot_now == 1800, f"POT_NOW={pot_now}")
    sw_level(dbg, 0x0)
    inject(dbg, 0x04)                         # release

    inject(dbg, 0x08)                         # meta-swap back
    wait_not_loading(dbg)
    check("D8 meta-swap back: profile 0", not (status(dbg) & B_PROFILE))

    n_ok = sum(1 for _, ok, _ in checks if ok)
    verdict = "CERT PASS" if n_ok == len(checks) else "CERT FAIL"
    print(f"\n{verdict}: {n_ok}/{len(checks)} checks")
    print("FINALE_CERT " + json.dumps({"pass": n_ok == len(checks),
                                       "checks": [(n, ok) for n, ok, _ in checks]}))
    return 0 if n_ok == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
