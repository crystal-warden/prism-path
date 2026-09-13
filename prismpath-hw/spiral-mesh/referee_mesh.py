#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Three-port referee for the spiral-mesh binding. Captures every node's serial for a window and
judges four claims:

  1. WIRE INTEGRITY   -  every received frame's hex equals the sender's transmitted hex for that
     (role, class, tick): Facet frames crossed real RF bit-exactly.
  2. DERIVED == BAKED == AIR  -  every band symbol on the air equals the host re-deriving the
     quantization from the signed flow (synthesis is deterministic, so every tick is checkable).
  3. LOSS SEMANTICS   -  per-link delivery counted; a lost frame may cost freshness, never a wrong
     symbol (no received symbol ever disagrees with the sender's computation).
  4. COHERENCE BEACON  -  posture gossip: fraction of observed ticks where all nodes report the
     same joint cell n (transient skew at band edges is expected and reported, not hidden).

    python3 referee_mesh.py 30            # seconds to observe
"""
import os
import sys
import threading
import time

import serial

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", ".."))

from prismpath.telemetry import spiral                              # noqa: E402
from prismpath.kernel.parser import parse               # noqa: E402
from gen_spiral_mesh_data import FLOW, NODE, ROLES, synth   # noqa: E402

PORTS = ["/dev/ttyUSB2", "/dev/ttyUSB3", "/dev/ttyUSB4"]


def capture(port, out, secs):
    serial_port = serial.Serial(port, 115200, timeout=2)
    serial_port.dtr = False; serial_port.rts = True
    time.sleep(0.1)
    serial_port.rts = False
    serial_port.reset_input_buffer()
    end = time.time() + secs
    while time.time() < end:
        line = serial_port.readline().decode(errors="replace").strip()
        if line:
            out.append(line)
    serial_port.close()


def main():
    secs = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    logs = [[] for _ in PORTS]
    threads = [threading.Thread(target=capture, args=(port, logs[index], secs))
               for index, port in enumerate(PORTS)]
    for thread in threads: thread.start()
    for thread in threads: thread.join()

    flow = parse(FLOW)
    layout = spiral.SpiralLayout(flow, NODE)
    fidx = {field: index for index, field in enumerate(layout.fields)}

    tx = {}                    # (role, cls, tick) -> (value, hex)
    rx = []                    # (observer, srcrole, cls, tick, value, hex)
    postures = {}              # tick -> {role: n}
    boots = []
    for role, log in enumerate(logs):
        for line in log:
            parts = line.split()
            try:
                if line.startswith("BOOT"):
                    boots.append(f"node{role}: {line}")
                elif line.startswith("T "):
                    tick, cls = int(parts[1]), int(parts[2][1:])
                    tx[(role, cls, tick)] = (int(parts[3][1:]), parts[4])
                elif line.startswith("R "):
                    rx.append((role, int(parts[1]), int(parts[2][1:]), int(parts[3][1:]),
                               int(parts[4][1:]), parts[5]))
                elif line.startswith("P "):
                    tick = int(parts[1])
                    posture_index = int(parts[2].split("=")[1])
                    postures.setdefault(tick, {})[role] = posture_index
            except (ValueError, IndexError):
                pass

    for boot_line in boots:
        print(boot_line)

    # 1+3: wire integrity + loss + no-wrong-symbol
    bad_hex = wrong_sym = 0
    matched = 0
    for obs, src, cls, tick, val, hx in rx:
        want = tx.get((src, cls, tick))
        if want is None:
            continue                              # sender line lost on SERIAL, not RF  -  skip
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
        want = layout.parts[field].symbol(synth(role, tick))
        checked += 1
        if want != val:
            derive_bad += 1

    # 4: posture coherence over ticks where all three reported
    full = {tick: by_role for tick, by_role in postures.items() if len(by_role) == len(PORTS)}
    agree = sum(1 for by_role in full.values() if len(set(by_role.values())) == 1)

    # loss accounting: band frames sent per role vs received per observer pair
    sent1 = {role: sum(1 for (tx_role, cls, _tick) in tx if tx_role == role and cls == 1) for role in range(len(PORTS))}
    got1 = {role: sum(1 for (_observer, src_role, cls, *_rest) in rx if src_role == role and cls == 1) for role in range(len(PORTS))}

    print(f"tx_frames={len(tx)}  rx_frames={len(rx)}  rx_matched_bitexact={matched} "
          f"bad_hex={bad_hex} wrong_symbol={wrong_sym}")
    print(f"derived==air band symbols: {checked - derive_bad}/{checked}")
    print(f"band frames sent per role: {sent1}  received (2 observers each): {got1}")
    print(f"posture coherence: {agree}/{len(full)} fully-reported ticks agree "
          f"({100.0 * agree / len(full):.1f}%)" if full else "posture: no full ticks observed")
    ok = (bad_hex == 0 and wrong_sym == 0 and derive_bad == 0
          and matched > 0 and full and agree > 0)
    print("REFEREE:", "PASS  -  Facet frames crossed RF bit-exactly; air == derived; "
                      "coherence beacon live" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
