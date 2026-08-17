# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Certify the ESP32-C6's PPT interpreter against the frozen predicate corpus, over UART (CP2102).

Identical contract to certify_uno.py (#92) / certify_rp2350.py (#97): the EXACT
run_vectors.cert_predicates certification with the subprocess replaced by the wire — each in-subset
predicate compiled by the UNTOUCHED compiler, streamed ('L'), the registers from the UNTOUCHED
encode_regs streamed ('V'), the board's verdict checked against the frozen expectation; exclusions by
the same machine-readable reasons.

    python certify_esp32.py --port /dev/ttyUSB2
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
HW = HERE.parent
REPO = HW.parent
sys.path.insert(0, str(HW))
sys.path.insert(0, str(REPO))

import serial  # noqa: E402
import ppt_compile as pc  # noqa: E402

CONF = REPO / "prismpath" / "portable" / "conformance"


class Board:
    def __init__(self, port: str, baud: int = 115200):
        self.s = serial.Serial(port, baud, timeout=5)
        # ESP32 dev boards auto-reset on the CP2102 DTR/RTS lines, and merely opening the port can
        # bounce the chip into download mode. Force a clean reset INTO THE APP (IO0 high) via the
        # standard RTS=EN / DTR=IO0 circuit, then wait for boot and drain the ROM boot-log bytes.
        self.s.dtr = False            # IO0 high -> run (not download)
        self.s.rts = True             # EN low  -> assert reset
        time.sleep(0.1)
        self.s.rts = False            # EN high -> release; boots the app
        time.sleep(1.5)               # boot + app start
        self.s.reset_input_buffer()   # drain ROM / 2nd-stage boot bytes

    def _expect(self, n: int) -> bytes:
        b = self.s.read(n)
        if len(b) != n:
            raise RuntimeError(f"serial timeout (wanted {n}, got {len(b)})")
        return b

    def ident(self) -> str:
        self.s.write(b"I")
        tag = self._expect(1)
        if tag != b"i":
            raise RuntimeError(f"bad ident reply {tag!r}")
        n = self._expect(1)[0]
        return self._expect(n).decode()

    def load(self, image: bytes) -> None:
        self.s.write(b"L" + struct.pack("<H", len(image)) + image)
        tag = self._expect(1)
        if tag == b"E":
            raise RuntimeError(f"load rejected: code {self._expect(1)[0]}")
        if tag != b"l":
            raise RuntimeError(f"bad load reply {tag!r}")

    def eval(self, regs_payload: bytes):
        self.s.write(b"V" + struct.pack("<H", len(regs_payload)) + regs_payload)
        tag = self._expect(1)
        if tag == b"N":
            return None
        if tag == b"M":
            edge = self._expect(1)[0]
            (target,) = struct.unpack("<H", self._expect(2))
            return edge, target
        if tag == b"E":
            raise RuntimeError(f"eval error: code {self._expect(1)[0]}")
        raise RuntimeError(f"bad eval reply {tag!r}")


def cert_predicates(board: Board):
    cases = json.loads((CONF / "predicates.json").read_text())["cases"]
    excluded: Counter = Counter()
    passed = failed = 0
    failures = []
    img_cache: dict = {}
    lat_us = []
    loaded_cond = None

    for i, case in enumerate(cases):
        cond, ctx, expect = case["cond"], case["ctx"], case["expect"]
        try:
            if cond not in img_cache:
                img = pc.compile_predicate(cond)
                img_cache[cond] = (img, img.serialize())
            img, blob = img_cache[cond]
            regs = pc.encode_regs(img, ctx, node_idx=0)
        except pc.SubsetError as e:
            excluded[e.reason] += 1
            continue
        if loaded_cond != cond:
            board.load(blob)
            loaded_cond = cond
        t0 = time.perf_counter()
        got = board.eval(regs) is not None
        lat_us.append((time.perf_counter() - t0) * 1e6)
        if expect == "ERROR":
            raise RuntimeError(f"ERROR case survived the subset filter: {cond!r}")
        if got == expect:
            passed += 1
        else:
            failed += 1
            failures.append((i, cond, ctx, expect, got))
    return passed, failed, excluded, failures, lat_us


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", default="/dev/ttyUSB2")
    ap.add_argument("--out", default=str(HERE / "cert_esp32.json"))
    args = ap.parse_args(argv)

    board = Board(args.port)
    ident = board.ident()
    print(f"board: {ident}")

    pp, pf, pex, pfail, lat = cert_predicates(board)
    total = pp + pf + sum(pex.values())
    print("── predicate vectors ─────────────────────────────")
    print(f"  total {total}   in-subset {pp + pf}   pass {pp}   FAIL {pf}   "
          f"excluded {sum(pex.values())}")
    for r, n in sorted(pex.items(), key=lambda kv: -kv[1]):
        print(f"    excluded {n:4d}  {r}")
    for i, cond, ctx, want, got in pfail[:20]:
        print(f"    ✗ case {i}: {cond!r}  ctx={ctx}  want={want} got={got}")
    if lat:
        lat.sort()
        print(f"  eval round-trip us over UART: min {lat[0]:.0f}  "
              f"median {lat[len(lat)//2]:.0f}  max {lat[-1]:.0f}")

    ok = pf == 0
    print("\n" + (f"✅ CONFORMANT on the declared subset ({ident})" if ok else "✗ NOT CONFORMANT"))
    Path(args.out).write_text(json.dumps({
        "board": ident, "port": args.port,
        "total": total, "in_subset": pp + pf, "pass": pp, "fail": pf,
        "excluded": dict(pex),
        "latency_us": {"min": round(lat[0]), "median": round(lat[len(lat) // 2]),
                       "max": round(lat[-1])} if lat else None,
        "failures": pfail[:20],
    }, indent=1) + "\n")
    print(f"wrote {args.out}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
