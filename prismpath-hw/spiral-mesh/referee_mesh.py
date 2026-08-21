#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Three-port referee for the spiral-mesh binding. Captures every node's serial for a window and
judges four claims:

  1. WIRE INTEGRITY  — every received frame's hex equals the sender's transmitted hex for that
     (role, class, tick): Facet frames crossed real RF bit-exactly.
  2. DERIVED == BAKED == AIR — every band symbol on the air equals the host re-deriving the
     quantization from the signed flow (synthesis is deterministic, so every tick is checkable).
  3. LOSS SEMANTICS  — per-link delivery counted; a lost frame may cost freshness, never a wrong
     symbol (no received symbol ever disagrees with the sender's computation).
  4. COHERENCE BEACON — posture gossip: fraction of observed ticks where all nodes report the
     same joint cell n (transient skew at band edges is expected and reported, not hidden).

    python3 referee_mesh.py 30            # seconds to observe
"""
import os
import sys
import threading
import time

import serial

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "adapters", "telemetry"))
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import spiral as sp                              # noqa: E402
from prismpath.parser import parse               # noqa: E402
from gen_spiral_mesh_data import FLOW, NODE, ROLES, synth   # noqa: E402

PORTS = ["/dev/ttyUSB2", "/dev/ttyUSB3", "/dev/ttyUSB4"]


def capture(port, out, secs):
    s = serial.Serial(port, 115200, timeout=2)
    s.dtr = False; s.rts = True
    time.sleep(0.1)
    s.rts = False
    s.reset_input_buffer()
    end = time.time() + secs
    while time.time() < end:
        line = s.readline().decode(errors="replace").strip()
        if line:
            out.append(line)
    s.close()


def main():
    secs = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    logs = [[] for _ in PORTS]
    threads = [threading.Thread(target=capture, args=(p, logs[i], secs))
               for i, p in enumerate(PORTS)]
    for t in threads: t.start()
    for t in threads: t.join()

    g = parse(FLOW)
    L = sp.SpiralLayout(g, NODE)
    fidx = {f: i for i, f in enumerate(L.fields)}

    tx = {}                    # (role, cls, tick) -> (value, hex)
    rx = []                    # (observer, srcrole, cls, tick, value, hex)
    postures = {}              # tick -> {role: n}
    boots = []
    for role, log in enumerate(logs):
        for line in log:
            p = line.split()
            try:
                if line.startswith("BOOT"):
                    boots.append(f"node{role}: {line}")
                elif line.startswith("T "):
                    tick, cls = int(p[1]), int(p[2][1:])
                    tx[(role, cls, tick)] = (int(p[3][1:]), p[4])
                elif line.startswith("R "):
                    rx.append((role, int(p[1]), int(p[2][1:]), int(p[3][1:]),
                               int(p[4][1:]), p[5]))
                elif line.startswith("P "):
                    tick = int(p[1])
                    n = int(p[2].split("=")[1])
                    postures.setdefault(tick, {})[role] = n
            except (ValueError, IndexError):
                pass

    for b in boots:
        print(b)

    # 1+3: wire integrity + loss + no-wrong-symbol
    bad_hex = wrong_sym = 0
    matched = 0
    for obs, src, cls, tick, val, hx in rx:
        want = tx.get((src, cls, tick))
        if want is None:
            continue                              # sender line lost on SERIAL, not RF — skip
        if want[1] != hx:
            bad_hex += 1
        elif want[0] != val:
            wrong_sym += 1
        else:
            matched += 1

    # 2: derived == air for every band symbol transmitted
    derive_bad = 0
    checked = 0
    for (role, cls, tick), (val, _hx) in tx.items():
        if cls != 1:
            continue
        field = ROLES[role][1]
        want = L.parts[field].symbol(synth(role, tick))
        checked += 1
        if want != val:
            derive_bad += 1

    # 4: posture coherence over ticks where all three reported
    full = {t: v for t, v in postures.items() if len(v) == len(PORTS)}
    agree = sum(1 for v in full.values() if len(set(v.values())) == 1)

    # loss accounting: band frames sent per role vs received per observer pair
    sent1 = {r: sum(1 for (rr, c, _t) in tx if rr == r and c == 1) for r in range(len(PORTS))}
    got1 = {r: sum(1 for (_o, s, c, *_x) in rx if s == r and c == 1) for r in range(len(PORTS))}

    print(f"tx_frames={len(tx)}  rx_frames={len(rx)}  rx_matched_bitexact={matched} "
          f"bad_hex={bad_hex} wrong_symbol={wrong_sym}")
    print(f"derived==air band symbols: {checked - derive_bad}/{checked}")
    print(f"band frames sent per role: {sent1}  received (2 observers each): {got1}")
    print(f"posture coherence: {agree}/{len(full)} fully-reported ticks agree "
          f"({100.0 * agree / len(full):.1f}%)" if full else "posture: no full ticks observed")
    ok = (bad_hex == 0 and wrong_sym == 0 and derive_bad == 0
          and matched > 0 and full and agree > 0)
    print("REFEREE:", "PASS — Facet frames crossed RF bit-exactly; air == derived; "
                      "coherence beacon live" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
