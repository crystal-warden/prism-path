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
    byte_count = len(payload); byte_index = 0; start_time = time.time()
    while byte_index < byte_count:
        if (IIC.read(SR) & 0x10) == 0:
            IIC.write(TXF, (0x200 if byte_index == byte_count - 1 else 0) | (payload[byte_index] & 0xFF)); byte_index += 1
        elif time.time() - start_time > timeout:
            return False
    start_time = time.time()
    while (IIC.read(SR) & 0x04) and time.time() - start_time < timeout:
        pass
    return True


def cmd(command_bytes): return i2c_write([0x00] + list(command_bytes))
def data(data_bytes): return i2c_write([0x40] + list(data_bytes))


INIT = [0xAE, 0xDC, 0x00, 0x81, 0x2F, 0x20, 0xA0, 0xC0, 0xA8, 0x7F, 0xD3, 0x00,
        0xD5, 0xF0, 0xD9, 0x22, 0xDB, 0x35, 0xB0, 0xA4, 0xA6, 0xAF]


def push(img):
    pixels = img.load()
    for page in range(16):
        cmd([0xB0 | page, 0x00, 0x10])
        row = []
        for col in range(128):
            byte_value = 0
            for bit in range(8):
                if pixels[col, page * 8 + bit]:
                    byte_value |= (1 << bit)
            row.append(byte_value)
        data(row)


def stateless_decide(pot):
    if pot >= 1631: return "HIGH", "RED"
    if pot >= 665: return "MID", "BLUE"
    return "LOW", "GREEN"


def big(word, scale):
    text_image = Image.new('1', (len(word) * 6 + 2, 9), 0)
    ImageDraw.Draw(text_image).text((1, 0), word, fill=1)
    return text_image.resize((text_image.width * scale, text_image.height * scale))


def render(pot, band, color, mode):
    img = Image.new('1', (128, 128), 0); draw = ImageDraw.Draw(img)
    draw.text((30, 2), "PrismPath", fill=1); draw.line([0, 13, 127, 13], fill=1)
    band_image = big(band, 3); img.paste(band_image, (max(2, (128 - band_image.width) // 2), 20))
    draw.text((max(2, (128 - len(color) * 6) // 2), 52), color, fill=1)
    left, right, top, bottom = 4, 123, 72, 84
    draw.rectangle([left, top, right, bottom], outline=1)
    ticks = DEADBAND_TICKS if mode == "RESIDENT" else EXACT_TICKS
    for thr in ticks:
        tick_x = left + int((right - left) * thr / 4095); draw.line([tick_x, top - 3, tick_x, bottom + 3], fill=1)
    marker_x = left + int((right - left) * min(pot, 4095) / 4095)
    draw.rectangle([marker_x - 1, top, marker_x + 1, bottom], fill=1)
    draw.text((14, 90), "pot %4d / 4095" % pot, fill=1)
    draw.line([0, 106, 127, 106], fill=1)
    # EXACT/LEGACY label stays generic: after a BTN2 nav swap the loaded table is not demo_input,
    # and the OLED must never claim a policy it cannot verify from the fabric registers
    label = {"RESIDENT": "hyst_band RESIDENT", "EXACT": "signed policy EXACT",
             "LEGACY": "signed policy"}[mode]
    draw.text((max(2, (128 - len(label) * 6) // 2), 110), label, fill=1)
    return img


def read_band():
    """(pot, band, color, mode) from the fabric — the resident node when stateful."""
    pot = PPT.read(R_POT_NOW) & 0xFFF
    current_node = PPT.read(R_CUR_NODE)
    if current_node == 0xDEADBEEF:                                # old bitstream: no CUR_NODE register
        band, color = stateless_decide(pot)
        return pot, band, color, "LEGACY"
    if (current_node >> 16) & 1:                                  # armed stateful: the resident band IS the truth
        band, color = NODES.get(current_node & 0xFFFF, ("?%d" % (current_node & 0xFFFF), "?"))
        return pot, band, color, "RESIDENT"
    band, color = stateless_decide(pot)
    return pot, band, color, "EXACT"


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
        except Exception as error:
            open("/home/xilinx/oled_live.log", "a").write("ERR %s\n" % error); time.sleep(0.5)


if __name__ == "__main__":
    main()
