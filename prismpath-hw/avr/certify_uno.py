"""Certify the Uno's PPT interpreter against the frozen predicate corpus, over serial.

The EXACT contract of run_vectors.cert_predicates (the C target's certification), with the
subprocess call replaced by the wire: for every in-subset vector the table is compiled by the
UNTOUCHED compiler, streamed to the board ('L'), the registers encoded by the UNTOUCHED
encode_regs are streamed ('V' — the same bytes interp.c's eval mode reads), and the board's
verdict must equal the frozen expectation. Exclusions use the same machine-readable reasons.

    python certify_uno.py --port /dev/ttyACM1        # full declared subset
    python certify_uno.py --port /dev/ttyACM1 --demo # + the incident_severity live table

Latency per decision is measured wall-clock around the 'V' round-trip (serial dominated; the
point is the decision happens ON THE 8-bit MCU, not how fast 38400 baud is).
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


class Uno:
    def __init__(self, port: str, baud: int = 38400):
        self.s = serial.Serial(port, baud, timeout=5)
        time.sleep(2.5)                         # DTR reset + bootloader window
        self.s.reset_input_buffer()

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
        """-> (edge, target) on match, None on no-match. Raises on protocol/board error."""
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


def cert_predicates(uno: Uno):
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
        if loaded_cond != cond:                 # table-per-condition, like the C cert
            uno.load(blob)
            loaded_cond = cond
        t0 = time.perf_counter()
        got = uno.eval(regs) is not None
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
    ap.add_argument("--port", default="/dev/ttyACM1")
    ap.add_argument("--out", default=str(HERE / "cert_uno.json"))
    args = ap.parse_args(argv)

    uno = Uno(args.port)
    ident = uno.ident()
    print(f"board: {ident}")

    pp, pf, pex, pfail, lat = cert_predicates(uno)
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
        print(f"  eval round-trip us over serial: min {lat[0]:.0f}  "
              f"median {lat[len(lat)//2]:.0f}  max {lat[-1]:.0f}")

    ok = pf == 0
    print("\n" + ("✅ Uno CONFORMANT on the declared subset" if ok else "✗ NOT CONFORMANT"))
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
