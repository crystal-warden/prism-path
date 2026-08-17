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
LABELS = {p: chr(ord('A') + i) for i, p in enumerate(PORTS)}
RUN_S = 8


def main():
    sers = {}
    for p in PORTS:
        s = serial.Serial(p, 115200, timeout=0)
        s.dtr = False; s.rts = True; time.sleep(0.1); s.rts = False   # reset into app
        sers[p] = s
    print(f"opened {', '.join(f'{LABELS[p]}={p}' for p in PORTS)} — booting probe (capturing boot)...")
    t0 = time.time()   # read from the start so we catch the scan + RESULT lines (ROM noise is filtered)
    bufs = {p: b"" for p in PORTS}
    seen_ok = {LABELS[p]: False for p in PORTS}
    while time.time() - t0 < RUN_S:
        r, _, _ = select.select([sers[p] for p in PORTS], [], [], 0.1)
        for s in r:
            p = next(pp for pp in PORTS if sers[pp] is s)
            bufs[p] += s.read(4096)
            while b"\n" in bufs[p]:
                line, bufs[p] = bufs[p].split(b"\n", 1)
                txt = line.decode(errors="replace").strip()
                if "[tof-probe]" not in txt:
                    continue
                msg = txt.split("[tof-probe]", 1)[1].strip()
                print(f"  {LABELS[p]}| {msg}")
                if "RESULT: OK" in msg:
                    seen_ok[LABELS[p]] = True

    print("\n=== per-node result ===")
    for lbl in sorted(seen_ok):
        print(f"  node {lbl}: {'OK — sensor initialized' if seen_ok[lbl] else 'no OK seen (see lines above)'}")
    for s in sers.values():
        s.close()


if __name__ == "__main__":
    raise SystemExit(main())
