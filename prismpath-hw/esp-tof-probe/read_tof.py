# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Read the tof-probe output from all three ESP32s at once.

    python read_tof.py [/dev/ttyUSB0 /dev/ttyUSB2 /dev/ttyUSB3]

Resets each board into its app, then streams the probe's scan result + live distance for ~8s so you
can wave a hand at each sensor and watch its band change.
"""
import sys, time, select
import serial

PORTS = sys.argv[1:] or ["/dev/ttyUSB0", "/dev/ttyUSB2", "/dev/ttyUSB3"]
LABELS = {port: chr(ord('A') + index) for index, port in enumerate(PORTS)}
RUN_S = 8


def main():
    sers = {}
    for port in PORTS:
        serial_port = serial.Serial(port, 115200, timeout=0)
        serial_port.dtr = False; serial_port.rts = True; time.sleep(0.1); serial_port.rts = False   # reset into app
        sers[port] = serial_port
    print(f"opened {', '.join(f'{LABELS[port]}={port}' for port in PORTS)} — booting probe (capturing boot)...")
    start_time = time.time()   # read from the start so we catch the scan + RESULT lines (ROM noise is filtered)
    bufs = {port: b"" for port in PORTS}
    seen_ok = {LABELS[port]: False for port in PORTS}
    while time.time() - start_time < RUN_S:
        readable, _, _ = select.select([sers[port] for port in PORTS], [], [], 0.1)
        for serial_port in readable:
            port = next(candidate for candidate in PORTS if sers[candidate] is serial_port)
            bufs[port] += serial_port.read(4096)
            while b"\n" in bufs[port]:
                line, bufs[port] = bufs[port].split(b"\n", 1)
                txt = line.decode(errors="replace").strip()
                if "[tof-probe]" not in txt:
                    continue
                msg = txt.split("[tof-probe]", 1)[1].strip()
                print(f"  {LABELS[port]}| {msg}")
                if "RESULT: OK" in msg:
                    seen_ok[LABELS[port]] = True

    print("\n=== per-node result ===")
    for lbl in sorted(seen_ok):
        print(f"  node {lbl}: {'OK — sensor initialized' if seen_ok[lbl] else 'no OK seen (see lines above)'}")
    for serial_port in sers.values():
        serial_port.close()


if __name__ == "__main__":
    raise SystemExit(main())
