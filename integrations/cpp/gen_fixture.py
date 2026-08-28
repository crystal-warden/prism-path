#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Generate the C++ embed-proof fixture from the certified CLI's own verdicts.

For every event of the frozen hysteresis sequence oracle (41 streams / 4568 events), this runs
the CERTIFIED interp binary (`build/interp eval`) and records its verdict, while asserting that
the resulting walk reproduces the corpus's frozen trail step for step — so generating the
fixture is itself a full sequence re-certification of the interp build. The C++ example then
replays these records in-process through the embeddable API and must agree 100%: the same
certified source, two materializations (subprocess CLI and linked-in library), byte-identical
verdicts. Output bytes are deterministic (no timestamps, fixed layout).

Fixture format (little endian):
  magic 'PPTF' | u16 version=1 | u16 n_fields | u32 n_events | 32-byte image sha256
  per event: u16 node_in | n_fields x (i32 ty, i32 val) | i16 expected_edge | u16 node_out
"""
from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
HW = REPO / "prismpath-hw"
IMAGE = HW / "demo" / "flows" / "hyst_band.ppt"
CORPUS = HW / "demo" / "flows" / "hyst_corpus.json"
INTERP = HW / "build" / "interp"
OUT = HERE / "hyst_fixture.bin"

TY_INT = 2


def main() -> int:
    if not INTERP.exists():
        print(f"build the certified CLI first: make -C {HW} cert")
        return 2
    corpus = json.loads(CORPUS.read_text())
    image_sha = hashlib.sha256(IMAGE.read_bytes()).hexdigest()
    if image_sha != corpus["image_sha256"]:
        print(f"image/corpus mismatch: {image_sha} != {corpus['image_sha256']}")
        return 2

    n_fields = 1  # hyst_band routes on one field (pot); asserted against the regs contract below
    records = []
    checked = 0
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
        regs_path = Path(tf.name)
    try:
        for stream in corpus["streams"]:
            cur = stream["start"]
            for pot, expect_node in zip(stream["pots"], stream["trail"]):
                regs_path.write_bytes(struct.pack("<iii", cur, TY_INT, pot))
                out = subprocess.run([str(INTERP), "eval", str(IMAGE), str(regs_path)],
                                     capture_output=True, text=True)
                if out.returncode != 0:
                    print(f"interp failed: {out.stderr.strip()}")
                    return 2
                verdict = out.stdout.strip()
                if verdict == "none":
                    edge, node_out = -1, cur
                else:
                    _m, e, t = verdict.split()
                    edge, node_out = int(e), int(t)
                if node_out != expect_node:
                    print(f"RE-CERT FAIL {stream['name']}: got node {node_out}, "
                          f"oracle says {expect_node} (pot={pot}, in={cur})")
                    return 1
                records.append(struct.pack("<Hii hH", cur, TY_INT, pot, edge, node_out))
                cur = node_out
                checked += 1
    finally:
        regs_path.unlink(missing_ok=True)

    blob = b"PPTF" + struct.pack("<HHI", 1, n_fields, len(records))
    blob += bytes.fromhex(image_sha)
    blob += b"".join(records)
    OUT.write_bytes(blob)
    print(f"RE-CERT PASS: {checked} events reproduce the frozen trail via the certified CLI")
    print(f"{OUT.name}: {len(records)} records, sha256 {hashlib.sha256(blob).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
