# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Watch the 3-node ESP-NOW decision-fusion mesh, and optionally coordinate a fusion-rule swap.

Opens all three nodes, resets them into the app, and streams their fused-posture lines with a host
timestamp. Each node senses one channel (two VL53L0X rangefinders + an arming potentiometer),
broadcasts its band over ESP-NOW, hears the other two, and runs the SAME baked Level M table to reach
one fused posture. All three print the SAME posture and change it together as the sensors move.
CRITICAL requires BOTH rangefinders close AND the knob armed, a region no single node reaches alone.

With --swap-at, one node is poked with 'R' at that time and coordinates a two-phase commit that swaps
the fusion RULE across the fleet (policy A arms at knob band >= 2, policy B at >= 3). Hold the sensors
in an A-CRITICAL state (both ToF near, knob at band 2) and the whole fleet re-fuses to WARN on the
swap, without a sensor moving.

    python orchestrate_fusion.py [--secs 20] [--swap-at 8] [/dev/ttyUSB0 /dev/ttyUSB1 /dev/ttyUSB2]
"""
import sys, time, select, re
import serial

argv = sys.argv[1:]
SECS = 20.0
SWAP_AT = None
if "--secs" in argv:
    flag_index = argv.index("--secs"); SECS = float(argv[flag_index + 1]); del argv[flag_index:flag_index + 2]
if "--swap-at" in argv:
    flag_index = argv.index("--swap-at"); SWAP_AT = float(argv[flag_index + 1]); del argv[flag_index:flag_index + 2]
PORTS = argv or ["/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyUSB2"]
LAB = {port: f"USB{port[-1]}" for port in PORTS}
POST = re.compile(r'->\s*(\w+)\s*$')
POL = re.compile(r'\bpol=(\w+)')
FLIP = re.compile(r'FLIP (\S+) -> fusion policy (\w+) epoch=(\d+)')


def reset_into_app(serial_port):
    serial_port.dtr = False; serial_port.rts = True; time.sleep(0.1); serial_port.rts = False


def main():
    sers = {}
    for port in PORTS:
        serial_port = serial.Serial(port, 115200, timeout=0); reset_into_app(serial_port); sers[port] = serial_port
    note = f", swap at {SWAP_AT:.0f}s" if SWAP_AT is not None else ""
    print(f"opened {', '.join(PORTS)} — booting Wi-Fi/ESP-NOW ({SECS:.0f}s window{note})...")
    time.sleep(2.0)
    for serial_port in sers.values():
        serial_port.reset_input_buffer()
    start_time = time.time(); bufs = {port: b"" for port in PORTS}
    last = {port: None for port in PORTS}; pol = {port: None for port in PORTS}; flips = {}
    swapped = SWAP_AT is None
    end = time.time() + SECS
    while time.time() < end:
        if not swapped and time.time() - start_time >= SWAP_AT:
            swapped = True
            print(f"\n>>> poking {LAB[PORTS[0]]} with 'R' (coordinate the fusion-rule swap) <<<\n")
            sers[PORTS[0]].write(b"R")
        readable, _, _ = select.select([sers[port] for port in PORTS], [], [], 0.1)
        for serial_port in readable:
            port = next(candidate for candidate in PORTS if sers[candidate] is serial_port)
            bufs[port] += serial_port.read(4096)
            while b"\n" in bufs[port]:
                line, bufs[port] = bufs[port].split(b"\n", 1)
                txt = line.decode(errors="replace").strip()
                if not txt:
                    continue
                elapsed = time.time() - start_time
                print(f"  [{elapsed:6.2f}s] {LAB[port]}| {txt}")
                posture_match = POST.search(txt)
                if posture_match:
                    last[port] = posture_match.group(1)
                mp = POL.search(txt)
                if mp:
                    pol[port] = mp.group(1)
                mf = FLIP.search(txt)
                if mf:
                    flips[LAB[port]] = (elapsed, mf.group(2), int(mf.group(3)))
    print("\n=== latest state per node ===")
    for port in PORTS:
        print(f"  {LAB[port]} ({port}): fusion-{pol[port]} -> {last[port]}")
    vals = [posture for posture in last.values() if posture]
    if len(vals) == len(PORTS) and len(set(vals)) == 1:
        print(f"  POSTURE AGREEMENT: all {len(PORTS)} nodes fused to {vals[0]}")
    pols = [policy for policy in pol.values() if policy]
    if len(pols) == len(PORTS) and len(set(pols)) == 1:
        print(f"  POLICY AGREEMENT: all {len(PORTS)} nodes on fusion policy {pols[0]}")
    if flips:
        tmin = min(flip[0] for flip in flips.values()); tmax = max(flip[0] for flip in flips.values())
        for lbl in sorted(flips):
            elapsed, pl, ep = flips[lbl]
            print(f"  {lbl}: flipped to fusion policy {pl} epoch {ep} @ {elapsed:.3f}s")
        print(f"  flip spread across nodes: {(tmax - tmin) * 1000:.1f} ms ({len(flips)}/{len(PORTS)})")
    for serial_port in sers.values():
        serial_port.close()


if __name__ == "__main__":
    raise SystemExit(main())
