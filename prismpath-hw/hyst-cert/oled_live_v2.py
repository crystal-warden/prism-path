#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""oled_live_v2.py — the OLED decision readout, resident-band aware.

v2 reads the band from CUR_NODE (0x30) when the fabric is armed stateful, so the glass shows the
SAME resident authority as the LED — never a display-side re-derivation. Fallbacks keep it honest
on any bitstream: CUR_NODE present but stateful=0 -> EXACT mode (stateless thresholds, the
demo_input view); CUR_NODE absent (old bitstream reads 0xDEADBEEF) -> LEGACY (v1 behavior).

Deploy to /home/xilinx/ after the stateful finale overlay lands. Run detached like v1.
"""
from pynq import MMIO
import time
from PIL import Image, ImageDraw

ADDR = 0x3C
IIC = MMIO(0x41600000, 0x10000)
PPT = MMIO(0x40000000, 0x10000)
R_MAGIC, R_POT_NOW, R_CUR_NODE = 0x24, 0x2C, 0x30
MAGIC = 0x50505431
SOFTR, CR, SR, TXF, ISR = 0x40, 0x100, 0x104, 0x108, 0x20

# hyst_band: node index -> (band word, color word); the signed deadband edges for the bar ticks
NODES = {0: ("LOW", "GREEN"), 1: ("MID", "BLUE"), 2: ("HIGH", "RED")}
DEADBAND_TICKS = (649, 681, 1615, 1647)
EXACT_TICKS = (665, 1631)


def reset_core():
    IIC.write(SOFTR, 0x0A); time.sleep(0.001)
    IIC.write(ISR, 0xFF); IIC.write(CR, 0x01); time.sleep(0.0005)


def i2c_write(payload, timeout=0.5):
    reset_core(); IIC.write(TXF, 0x100 | (ADDR << 1))
    n = len(payload); i = 0; t0 = time.time()
    while i < n:
        if (IIC.read(SR) & 0x10) == 0:
            IIC.write(TXF, (0x200 if i == n - 1 else 0) | (payload[i] & 0xFF)); i += 1
        elif time.time() - t0 > timeout:
            return False
    t0 = time.time()
    while (IIC.read(SR) & 0x04) and time.time() - t0 < timeout:
        pass
    return True


def cmd(l): return i2c_write([0x00] + list(l))
def data(l): return i2c_write([0x40] + list(l))


INIT = [0xAE, 0xDC, 0x00, 0x81, 0x2F, 0x20, 0xA0, 0xC0, 0xA8, 0x7F, 0xD3, 0x00,
        0xD5, 0xF0, 0xD9, 0x22, 0xDB, 0x35, 0xB0, 0xA4, 0xA6, 0xAF]


def push(img):
    px = img.load()
    for page in range(16):
        cmd([0xB0 | page, 0x00, 0x10])
        row = []
        for col in range(128):
            b = 0
            for bit in range(8):
                if px[col, page * 8 + bit]:
                    b |= (1 << bit)
            row.append(b)
        data(row)


def stateless_decide(f):
    if f >= 1631: return "HIGH", "RED"
    if f >= 665: return "MID", "BLUE"
    return "LOW", "GREEN"


def big(word, scale):
    t = Image.new('1', (len(word) * 6 + 2, 9), 0)
    ImageDraw.Draw(t).text((1, 0), word, fill=1)
    return t.resize((t.width * scale, t.height * scale))


def render(pot, band, color, mode):
    img = Image.new('1', (128, 128), 0); d = ImageDraw.Draw(img)
    d.text((30, 2), "PrismPath", fill=1); d.line([0, 13, 127, 13], fill=1)
    w = big(band, 3); img.paste(w, (max(2, (128 - w.width) // 2), 20))
    d.text((max(2, (128 - len(color) * 6) // 2), 52), color, fill=1)
    x0, x1, y0, y1 = 4, 123, 72, 84
    d.rectangle([x0, y0, x1, y1], outline=1)
    ticks = DEADBAND_TICKS if mode == "RESIDENT" else EXACT_TICKS
    for thr in ticks:
        tx = x0 + int((x1 - x0) * thr / 4095); d.line([tx, y0 - 3, tx, y1 + 3], fill=1)
    mx = x0 + int((x1 - x0) * min(pot, 4095) / 4095)
    d.rectangle([mx - 1, y0, mx + 1, y1], fill=1)
    d.text((14, 90), "pot %4d / 4095" % pot, fill=1)
    d.line([0, 106, 127, 106], fill=1)
    # EXACT/LEGACY label stays generic: after a BTN2 nav swap the loaded table is not demo_input,
    # and the OLED must never claim a policy it cannot verify from the fabric registers
    label = {"RESIDENT": "hyst_band RESIDENT", "EXACT": "signed policy EXACT",
             "LEGACY": "signed policy"}[mode]
    d.text((max(2, (128 - len(label) * 6) // 2), 110), label, fill=1)
    return img


def read_band():
    """(pot, band, color, mode) from the fabric — the resident node when stateful."""
    pot = PPT.read(R_POT_NOW) & 0xFFF
    cn = PPT.read(R_CUR_NODE)
    if cn == 0xDEADBEEF:                                # old bitstream: no CUR_NODE register
        b, c = stateless_decide(pot)
        return pot, b, c, "LEGACY"
    if (cn >> 16) & 1:                                  # armed stateful: the resident band IS the truth
        band, color = NODES.get(cn & 0xFFFF, ("?%d" % (cn & 0xFFFF), "?"))
        return pot, band, color, "RESIDENT"
    b, c = stateless_decide(pot)
    return pot, b, c, "EXACT"


def oled_init():
    """Bring up the panel. Call once (or again after a reclaim)."""
    reset_core(); cmd(INIT)


def oled_tick(prev):
    """One poll+render cycle; returns the new change-key. Import path for the demo service so ONE
    process owns every PL access — no concurrent MMIO pollers (wedge mitigation)."""
    pot, band, color, mode = read_band()
    key = (mode, band, pot // 16)
    if key != prev:
        push(render(pot, band, color, mode))
    return key


def main():
    oled_init()
    prev = None
    while True:
        try:
            if PPT.read(R_MAGIC) != MAGIC:
                time.sleep(0.2); continue
            prev = oled_tick(prev)
            time.sleep(0.04)
        except Exception as e:
            open("/home/xilinx/oled_live.log", "a").write("ERR %s\n" % e); time.sleep(0.5)


if __name__ == "__main__":
    main()
