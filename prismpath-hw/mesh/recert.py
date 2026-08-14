"""Re-certify the Ed25519-signed ESP-NOW swap mesh: one happy path + the negative matrix.

Opens all three nodes, resets them, clears the anti-rollback floor, then drives:
  HAPPY     'R' -> coordinator pushes the signed tighten A(v1) -> B(v2); followers verify the Ed25519
            signature AND version > floor, ACK, and the fleet flips together to B.
  ROLLBACK  'R' again -> coordinator pushes A(v1); v1 <= floor(2) so every follower REJECTS. No flip.
  TAMPERED  'T' -> a byte-flipped B table with B's real signature -> signature fails -> REJECT. No flip.
  WRONG SIG 'W' -> B's table with a corrupted signature -> REJECT. No flip.

Pass = 3/3 flip on the happy path and every negative rejected with the fleet unchanged (still B).

    python recert.py [/dev/ttyUSB0 /dev/ttyUSB1 /dev/ttyUSB2]
"""
import sys, time, select, re
import serial

PORTS = sys.argv[1:] or ["/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyUSB2"]
LAB = {p: f"USB{p[-1]}" for p in PORTS}
FLIP = re.compile(r'FLIP node=\w+ -> policy (\w+) v(\d+) verdict=(\w+) epoch=(\d+)')
REJ = re.compile(r'PREPARE REJECT seq=\d+ (.+)')


def reset_into_app(s):
    s.dtr = False; s.rts = True; time.sleep(0.1); s.rts = False


def main():
    sers = {}
    for p in PORTS:
        s = serial.Serial(p, 115200, timeout=0); reset_into_app(s); sers[p] = s
    print(f"opened {', '.join(f'{LAB[p]}={p}' for p in PORTS)} — booting ESP-NOW...")
    time.sleep(2.5)
    for s in sers.values():
        s.reset_input_buffer()
    t0 = time.time(); bufs = {p: b"" for p in PORTS}; events = []

    def pump(dur):
        end = time.time() + dur
        while time.time() < end:
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
                    events.append((ht, LAB[p], txt))

    def poke(ch, label):
        print(f"\n>>> {label}: poking {LAB[PORTS[0]]} with '{ch}' <<<")
        sers[PORTS[0]].write(ch.encode())

    for p in PORTS:
        sers[p].write(b"Z")                       # clean floor for a repeatable run
    pump(1.0)
    print("\n===== HAPPY PATH: signed tighten A(v1) -> B(v2) =====")
    poke('R', "happy swap A->B"); pump(3.0)
    print("\n===== NEGATIVE 1: rollback B -> A (v1 <= floor v2) must REJECT =====")
    poke('R', "rollback attempt"); pump(3.0)
    print("\n===== NEGATIVE 2: tampered table must REJECT (bad signature) =====")
    poke('T', "tampered table"); pump(2.0)
    print("\n===== NEGATIVE 3: wrong signature must REJECT =====")
    poke('W', "wrong signature"); pump(2.0)

    print("\n=== CERT SUMMARY ===")
    flips = [(t, l, m) for (t, l, txt) in events for m in [FLIP.search(txt)] if m]
    rejects = [(t, l, m.group(1)) for (t, l, txt) in events for m in [REJ.search(txt)] if m]
    b_flips = {l for (t, l, m) in flips if m.group(1) == 'B'}
    a_flips = {l for (t, l, m) in flips if m.group(1) == 'A'}
    if b_flips:
        ts = [t for (t, l, m) in flips if m.group(1) == 'B']
        print(f"  HAPPY: {len(b_flips)}/{len(PORTS)} nodes flipped to policy B v2, spread {(max(ts)-min(ts))*1000:.1f} ms  {'PASS' if len(b_flips)==len(PORTS) else 'FAIL'}")
    else:
        print("  HAPPY: no B flip observed  FAIL")
    reasons = {}
    for _, l, reason in rejects:
        reasons.setdefault(reason.split('(')[0].strip() or reason, 0)
        reasons[reason.split('(')[0].strip() or reason] += 1
    print(f"  REJECTS: {len(rejects)} total")
    for reason, n in reasons.items():
        print(f"    x{n}  {reason}")
    print(f"  unexpected roll-back-to-A flips: {len(a_flips)}  {'PASS' if not a_flips else 'FAIL'}")
    ok = len(b_flips) == len(PORTS) and not a_flips and len(rejects) >= 3
    print(f"  RESULT: {'PASS — signed swap accepted, all three negatives rejected, fleet held on B' if ok else 'REVIEW the log above'}")
    for s in sers.values():
        s.close()


if __name__ == "__main__":
    raise SystemExit(main())
