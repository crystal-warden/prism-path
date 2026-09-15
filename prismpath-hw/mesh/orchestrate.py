# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Watch the 3-node ESP-NOW mesh and trigger a coordinated policy swap.

Opens all three nodes, prints their status with a host timestamp, then pokes ONE node with 'R' — it
becomes coordinator and runs the two-phase commit. You should see PREPARE -> ACKs -> COMMIT, then all
three flip verdict (ALLOW->DENY) within a few ms of each other, all landing on the same epoch.

    python orchestrate.py [/dev/ttyUSB0 /dev/ttyUSB2 /dev/ttyUSB3]
"""
import sys, time, select, re
import serial

PORTS = sys.argv[1:] or ["/dev/ttyUSB0", "/dev/ttyUSB2", "/dev/ttyUSB3"]
LABELS = {port: chr(ord('A') + index) for index, port in enumerate(PORTS)}


def reset_into_app(serial_port):
    serial_port.dtr = False; serial_port.rts = True; time.sleep(0.1); serial_port.rts = False


def main():
    sers = {}
    for port in PORTS:
        serial_port = serial.Serial(port, 115200, timeout=0)
        reset_into_app(serial_port)
        sers[port] = serial_port
    print(f"opened {', '.join(f'{LABELS[port]}={port}' for port in PORTS)} — booting ESP-NOW...")
    time.sleep(2.0)                                # let all 3 reboot, bring up Wi-Fi + ESP-NOW
    for serial_port in sers.values():              # drop ROM boot log + any pre-run backlog
        serial_port.reset_input_buffer()
    start_time = time.time()
    bufs = {port: b"" for port in PORTS}
    flips = {}          # label -> (host_t, epoch)

    def pump(deadline):
        while time.time() < deadline:
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
                    print(f"  [{elapsed:6.2f}s] {LABELS[port]}| {txt}")
                    match = re.search(r'FLIP node=\w+ -> policy (\w+) verdict=(\w+) epoch=(\d+)', txt)
                    if match:
                        flips[LABELS[port]] = (elapsed, match.group(1), match.group(2), int(match.group(3)))

    pump(start_time + 2.5)                                 # clean baseline: all on policy A / ALLOW
    print(f"\n>>> poking node {LABELS[PORTS[0]]} with 'R' (become coordinator, roll the fleet) <<<\n")
    sers[PORTS[0]].write(b"R")
    pump(start_time + 8)                                    # capture PREPARE/ACK/COMMIT, the flip, settled DENY

    print("\n=== coordinated flip summary ===")
    if flips:
        t_min = min(flip[0] for flip in flips.values()); t_max = max(flip[0] for flip in flips.values())
        for lbl in sorted(flips):
            elapsed, pol, verd, ep = flips[lbl]
            print(f"  node {lbl}: -> policy {pol} verdict {verd} epoch {ep}  @ {elapsed:.3f}s")
        print(f"  spread across nodes: {(t_max - t_min) * 1000:.1f} ms  ({len(flips)}/{len(PORTS)} flipped)")
    else:
        print("  no FLIP observed — check that all 3 nodes are up and on the same channel")
    for serial_port in sers.values():
        serial_port.close()


if __name__ == "__main__":
    raise SystemExit(main())
