"""Watch the 3-node ESP-NOW mesh and trigger a coordinated policy swap.

Opens all three nodes, prints their status with a host timestamp, then pokes ONE node with 'R' — it
becomes coordinator and runs the two-phase commit. You should see PREPARE -> ACKs -> COMMIT, then all
three flip verdict (ALLOW->DENY) within a few ms of each other, all landing on the same epoch.

    python orchestrate.py [/dev/ttyUSB0 /dev/ttyUSB2 /dev/ttyUSB3]
"""
import sys, time, select, re
import serial

PORTS = sys.argv[1:] or ["/dev/ttyUSB0", "/dev/ttyUSB2", "/dev/ttyUSB3"]
LABELS = {p: chr(ord('A') + i) for i, p in enumerate(PORTS)}


def reset_into_app(s):
    s.dtr = False; s.rts = True; time.sleep(0.1); s.rts = False


def main():
    sers = {}
    for p in PORTS:
        s = serial.Serial(p, 115200, timeout=0)
        reset_into_app(s)
        sers[p] = s
    print(f"opened {', '.join(f'{LABELS[p]}={p}' for p in PORTS)} — booting ESP-NOW...")
    time.sleep(2.0)                                # let all 3 reboot, bring up Wi-Fi + ESP-NOW
    for s in sers.values():                        # drop ROM boot log + any pre-run backlog
        s.reset_input_buffer()
    t0 = time.time()
    bufs = {p: b"" for p in PORTS}
    flips = {}          # label -> (host_t, epoch)

    def pump(deadline):
        while time.time() < deadline:
            r, _, _ = select.select([sers[p] for p in PORTS], [], [], 0.1)
            for s in r:
                p = next(pp for pp in PORTS if sers[pp] is s)
                bufs[p] += s.read(4096)
                while b"\n" in bufs[p]:
                    line, bufs[p] = bufs[p].split(b"\n", 1)
                    txt = line.decode(errors="replace").strip()
                    if not txt:
                        continue
                    ht = time.time() - t0
                    print(f"  [{ht:6.2f}s] {LABELS[p]}| {txt}")
                    m = re.search(r'FLIP node=\w+ -> policy (\w+) verdict=(\w+) epoch=(\d+)', txt)
                    if m:
                        flips[LABELS[p]] = (ht, m.group(1), m.group(2), int(m.group(3)))

    pump(t0 + 2.5)                                 # clean baseline: all on policy A / ALLOW
    print(f"\n>>> poking node {LABELS[PORTS[0]]} with 'R' (become coordinator, roll the fleet) <<<\n")
    sers[PORTS[0]].write(b"R")
    pump(t0 + 8)                                    # capture PREPARE/ACK/COMMIT, the flip, settled DENY

    print("\n=== coordinated flip summary ===")
    if flips:
        t_min = min(v[0] for v in flips.values()); t_max = max(v[0] for v in flips.values())
        for lbl in sorted(flips):
            ht, pol, verd, ep = flips[lbl]
            print(f"  node {lbl}: -> policy {pol} verdict {verd} epoch {ep}  @ {ht:.3f}s")
        print(f"  spread across nodes: {(t_max - t_min) * 1000:.1f} ms  ({len(flips)}/{len(PORTS)} flipped)")
    else:
        print("  no FLIP observed — check that all 3 nodes are up and on the same channel")
    for s in sers.values():
        s.close()


if __name__ == "__main__":
    raise SystemExit(main())
