#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Host referee for the spiral-node firmware: reset the board, capture its output, and diff every
line against the DERIVED materialization (SpiralLayout from the same flow) + the Python Zeckendorf
reference. PASS means baked-on-device and derived-on-host describe the same layout and produce
bit-identical frames — the two-materializations contract, judged on silicon.

    python3 referee_spiral_node.py /dev/ttyUSB2
"""
import os
import sys

import serial

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "adapters", "telemetry"))
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import packed                             # noqa: E402
import spiral as sp                       # noqa: E402
import zeckendorf as z                    # noqa: E402
from prismpath.parser import parse        # noqa: E402
from gen_spiral_node_data import FLOW, NODE, probes   # noqa: E402


def expected():
    g = parse(FLOW)
    L = sp.SpiralLayout(g, NODE)
    grids = [probes(L.parts[f]) for f in L.fields]
    readings = []
    def rec(i, cur):
        if i == len(grids):
            readings.append(tuple(cur)); return
        for v in grids[i]:
            rec(i + 1, cur + [v])
    rec(0, [])
    seed = 0x5EED
    for _ in range(16):
        row = []
        for _f in L.fields:
            seed ^= (seed << 13) & 0xFFFFFFFF
            seed ^= seed >> 17
            seed ^= (seed << 5) & 0xFFFFFFFF
            row.append(seed % 1024)
        readings.append(tuple(row))

    out = []
    for r in readings:
        reading = dict(zip(L.fields, r))
        cell = L.cell(reading)
        n = L.n_of[cell]
        band = next(i for i, (b, w) in enumerate(zip(L.band_base, L.band_width))
                    if b <= n < b + w)
        route = L.routes[band] or "?"
        fb = packed.pack(z.encode_stream([band + 1]), 8).hex()
        fn = packed.pack(z.encode_stream([n + 1]), 8).hex()
        out.append((band, n, route, fb, fn))
    return out


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB2"
    exp = expected()
    s = serial.Serial(port, 115200, timeout=25)
    # esp32 auto-reset dance: EN low via RTS with IO0 high via DTR released
    s.dtr = False; s.rts = True
    import time; time.sleep(0.1)
    s.rts = False
    s.reset_input_buffer()

    got = {}
    header = None
    deadline = time.time() + 60
    while time.time() < deadline:
        line = s.readline().decode(errors="replace").strip()
        if line.startswith("SSC OK"):
            header = line
        elif line.startswith("SSC PARSE FAIL"):
            print(line); sys.exit(1)
        elif line.startswith("V "):
            parts = line.split()
            i = int(parts[1])
            kv = dict(p.split("=", 1) for p in parts[2:])
            got[i] = (int(kv["band"]), int(kv["n"]), kv["route"], kv["fb"], kv["fn"])
        elif line.startswith("DONE"):
            break
    s.close()

    print(header or "(no header seen)")
    mism = 0
    for i, e in enumerate(exp):
        g = got.get(i)
        if g != e:
            mism += 1
            if mism <= 5:
                print(f"  MISMATCH v{i}: device={g} derived={e}")
    print(f"vectors expected={len(exp)} received={len(got)} mismatches={mism}")
    print("REFEREE:", "PASS — baked(device) == derived(host), frames bit-identical"
          if mism == 0 and len(got) == len(exp) else "FAIL")
    sys.exit(0 if mism == 0 and len(got) == len(exp) else 1)


if __name__ == "__main__":
    main()
