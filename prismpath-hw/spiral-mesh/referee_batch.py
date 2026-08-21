#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Airtime/batching analyzer for the mesh binding — MEASURED sizes, computed airtime with the
constants stated. Captures all three nodes for a window and reports, per node and total: frames
sent (X lines), measured payload bytes per frame, triples carried, delivery, decode integrity —
then computes per-frame airtime at the ESP-NOW default PHY and totals the A/B story.

Airtime model (constants in the open, so the 'computed' half is auditable):
  802.11b 1 Mbps long preamble: 192 us PLCP; ESP-NOW action frame overhead = 24 B MAC header
  + 15 B action/vendor header + 4 B FCS = 43 B; airtime(payload) = 192 us + 8 * (43 + payload) us.
The payload BYTES are measured off the wire logs; only the multiplication is computed.

    python3 referee_batch.py 60
"""
import sys
import threading
import time

import serial

PORTS = ["/dev/ttyUSB2", "/dev/ttyUSB3", "/dev/ttyUSB4"]
PLCP_US = 192.0
OVERHEAD_B = 43


def airtime_us(payload_b):
    return PLCP_US + 8.0 * (OVERHEAD_B + payload_b)


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
    secs = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    logs = [[] for _ in PORTS]
    ts = [threading.Thread(target=capture, args=(p, logs[i], secs)) for i, p in enumerate(PORTS)]
    for t in ts: t.start()
    for t in ts: t.join()

    total_frames = total_bytes = total_triples = 0
    rbad = 0
    rx_triples = 0
    per_node = []
    for role, log in enumerate(logs):
        frames = tbytes = triples = 0
        sizes = []
        for line in log:
            p = line.split()
            try:
                if line.startswith("X "):
                    n = int(p[2].split("=")[1])
                    frames += 1; tbytes += n; sizes.append(n)
                elif line.startswith("T "):
                    triples += 1
                elif line.startswith("R "):
                    rx_triples += 1
                elif line.startswith("RBAD"):
                    rbad += 1
            except (ValueError, IndexError):
                pass
        per_node.append((frames, tbytes, triples, sizes))
        total_frames += frames; total_bytes += tbytes; total_triples += triples

    print(f"window={secs}s  nodes={len(PORTS)}")
    for role, (frames, tbytes, triples, sizes) in enumerate(per_node):
        if frames:
            print(f"  node{role}: frames={frames} triples={triples} "
                  f"payload B/frame min/avg/max={min(sizes)}/{tbytes/frames:.1f}/{max(sizes)} "
                  f"triples/frame={triples/frames:.2f}")
    if total_frames:
        at = sum(airtime_us(b) for _f, tb, _t, ss in per_node for b in ss)
        print(f"TOTAL: frames={total_frames} payload_bytes={total_bytes} triples={total_triples}")
        print(f"AIRTIME (measured sizes, stated constants): {at / 1e3:.1f} ms total, "
              f"{at / total_frames:.0f} us/frame, {at / max(total_triples, 1):.0f} us/decision-triple")
        print(f"  fixed overhead share: {100.0 * (total_frames * (PLCP_US + 8 * OVERHEAD_B)) / at:.1f}%")
    print(f"rx_triples={rx_triples} rbad={rbad}")


if __name__ == "__main__":
    main()
