#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""drive_scenario.py - the dev-station end of the decision-delta pipeline.

Sends raw control EVENTS over UDP to the Protectli forwarder (which runs the signed selector and
decides). This node knows nothing about postures - it only emits events. Event codes match the
posture_selector transition policy:
    1 = escalate     2 = de-escalate     0 = hold (out-of-range -> self-loop, no posture change)

The default scenario is the 9-event walk (6 deltas, 3 holds) from the original bring-up:
    escalate, hold, escalate, hold, hold, de-escalate, de-escalate, escalate, escalate
Use --slow for a longer walk where each hold sits visibly (the LED holds; the wire stays quiet).

  python3 drive_scenario.py [--host 192.168.4.2] [--port 9500] [--gap 2.0] [--slow] [EVENTS...]
"""
import argparse, socket, time

DEFAULT = [1, 0, 1, 0, 0, 2, 2, 1, 1]
SLOW    = [1, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 2, 0, 0, 0]   # long holds -> visible suppression

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.4.2")
    ap.add_argument("--port", type=int, default=9500)
    ap.add_argument("--gap", type=float, default=2.0)
    ap.add_argument("--slow", action="store_true")
    ap.add_argument("events", nargs="*", type=int)
    a = ap.parse_args()

    seq = a.events if a.events else (SLOW if a.slow else DEFAULT)
    NM = {0: "hold", 1: "escalate", 2: "de-escalate"}
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"driving {len(seq)} events -> {a.host}:{a.port}  gap={a.gap}s", flush=True)
    for i, ev in enumerate(seq):
        tx.sendto(str(ev).encode(), (a.host, a.port))
        print(f"  [{i+1:2d}/{len(seq)}] ev={ev} ({NM.get(ev,'?')})", flush=True)
        time.sleep(a.gap)
    print("scenario sent.", flush=True)

if __name__ == "__main__":
    main()
