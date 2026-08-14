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
    i = argv.index("--secs"); SECS = float(argv[i + 1]); del argv[i:i + 2]
if "--swap-at" in argv:
    i = argv.index("--swap-at"); SWAP_AT = float(argv[i + 1]); del argv[i:i + 2]
PORTS = argv or ["/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyUSB2"]
LAB = {p: f"USB{p[-1]}" for p in PORTS}
POST = re.compile(r'->\s*(\w+)\s*$')
POL = re.compile(r'\bpol=(\w+)')
FLIP = re.compile(r'FLIP (\S+) -> fusion policy (\w+) epoch=(\d+)')


def reset_into_app(s):
    s.dtr = False; s.rts = True; time.sleep(0.1); s.rts = False


def main():
    sers = {}
    for p in PORTS:
        s = serial.Serial(p, 115200, timeout=0); reset_into_app(s); sers[p] = s
    note = f", swap at {SWAP_AT:.0f}s" if SWAP_AT is not None else ""
    print(f"opened {', '.join(PORTS)} — booting Wi-Fi/ESP-NOW ({SECS:.0f}s window{note})...")
    time.sleep(2.0)
    for s in sers.values():
        s.reset_input_buffer()
    t0 = time.time(); bufs = {p: b"" for p in PORTS}
    last = {p: None for p in PORTS}; pol = {p: None for p in PORTS}; flips = {}
    swapped = SWAP_AT is None
    end = time.time() + SECS
    while time.time() < end:
        if not swapped and time.time() - t0 >= SWAP_AT:
            swapped = True
            print(f"\n>>> poking {LAB[PORTS[0]]} with 'R' (coordinate the fusion-rule swap) <<<\n")
            sers[PORTS[0]].write(b"R")
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
                print(f"  [{ht:6.2f}s] {LAB[p]}| {txt}")
                m = POST.search(txt)
                if m:
                    last[p] = m.group(1)
                mp = POL.search(txt)
                if mp:
                    pol[p] = mp.group(1)
                mf = FLIP.search(txt)
                if mf:
                    flips[LAB[p]] = (ht, mf.group(2), int(mf.group(3)))
    print("\n=== latest state per node ===")
    for p in PORTS:
        print(f"  {LAB[p]} ({p}): fusion-{pol[p]} -> {last[p]}")
    vals = [v for v in last.values() if v]
    if len(vals) == len(PORTS) and len(set(vals)) == 1:
        print(f"  POSTURE AGREEMENT: all {len(PORTS)} nodes fused to {vals[0]}")
    pols = [v for v in pol.values() if v]
    if len(pols) == len(PORTS) and len(set(pols)) == 1:
        print(f"  POLICY AGREEMENT: all {len(PORTS)} nodes on fusion policy {pols[0]}")
    if flips:
        tmin = min(v[0] for v in flips.values()); tmax = max(v[0] for v in flips.values())
        for lbl in sorted(flips):
            ht, pl, ep = flips[lbl]
            print(f"  {lbl}: flipped to fusion policy {pl} epoch {ep} @ {ht:.3f}s")
        print(f"  flip spread across nodes: {(tmax - tmin) * 1000:.1f} ms ({len(flips)}/{len(PORTS)})")
    for s in sers.values():
        s.close()


if __name__ == "__main__":
    raise SystemExit(main())
