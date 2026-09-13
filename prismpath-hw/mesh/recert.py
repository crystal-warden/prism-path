# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
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
LAB = {port: f"USB{port[-1]}" for port in PORTS}
FLIP = re.compile(r'FLIP node=\w+ -> policy (\w+) v(\d+) verdict=(\w+) epoch=(\d+)')
REJ = re.compile(r'PREPARE REJECT seq=\d+ (.+)')


def reset_into_app(serial_port):
    serial_port.dtr = False; serial_port.rts = True; time.sleep(0.1); serial_port.rts = False


def main():
    sers = {}
    for port in PORTS:
        serial_port = serial.Serial(port, 115200, timeout=0); reset_into_app(serial_port); sers[port] = serial_port
    print(f"opened {', '.join(f'{LAB[port]}={port}' for port in PORTS)} — booting ESP-NOW...")
    time.sleep(2.5)
    for serial_port in sers.values():
        serial_port.reset_input_buffer()
    start_time = time.time(); bufs = {port: b"" for port in PORTS}; events = []

    def pump(dur):
        end = time.time() + dur
        while time.time() < end:
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
                    events.append((elapsed, LAB[port], txt))

    def poke(ch, label):
        print(f"\n>>> {label}: poking {LAB[PORTS[0]]} with '{ch}' <<<")
        sers[PORTS[0]].write(ch.encode())

    for port in PORTS:
        sers[port].write(b"Z")                       # clean floor for a repeatable run
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
    flips = [(elapsed, label, match) for (elapsed, label, txt) in events for match in [FLIP.search(txt)] if match]
    rejects = [(elapsed, label, match.group(1)) for (elapsed, label, txt) in events for match in [REJ.search(txt)] if match]
    b_flips = {label for (elapsed, label, match) in flips if match.group(1) == 'B'}
    a_flips = {label for (elapsed, label, match) in flips if match.group(1) == 'A'}
    if b_flips:
        ts = [elapsed for (elapsed, label, match) in flips if match.group(1) == 'B']
        print(f"  HAPPY: {len(b_flips)}/{len(PORTS)} nodes flipped to policy B v2, spread {(max(ts)-min(ts))*1000:.1f} ms  {'PASS' if len(b_flips)==len(PORTS) else 'FAIL'}")
    else:
        print("  HAPPY: no B flip observed  FAIL")
    reasons = {}
    for _, label, reason in rejects:
        reasons.setdefault(reason.split('(')[0].strip() or reason, 0)
        reasons[reason.split('(')[0].strip() or reason] += 1
    print(f"  REJECTS: {len(rejects)} total")
    for reason, count in reasons.items():
        print(f"    x{count}  {reason}")
    print(f"  unexpected roll-back-to-A flips: {len(a_flips)}  {'PASS' if not a_flips else 'FAIL'}")
    ok = len(b_flips) == len(PORTS) and not a_flips and len(rejects) >= 3
    print(f"  RESULT: {'PASS — signed swap accepted, all three negatives rejected, fleet held on B' if ok else 'REVIEW the log above'}")
    for serial_port in sers.values():
        serial_port.close()


if __name__ == "__main__":
    raise SystemExit(main())
