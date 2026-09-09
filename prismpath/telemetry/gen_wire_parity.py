#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze the Python reference's wire bits for every reading of the decisions corpus, so the Rust
crate's `test_xwire_parity` can hold Rust byte identical to Python (the cross implementation
property). Run after `gen_decisions_corpus.py`.

Usage: gen_wire_parity.py   # writes prismpath-telemetry-rs/tests/fixtures/wire_parity.json
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO))

from prismpath.telemetry import quantizer as q          # noqa: E402
from prismpath.telemetry import wire as w              # noqa: E402
from prismpath.parser import parse  # noqa: E402


def main():
    corpus = json.loads((HERE / "conformance" / "decisions.json").read_text())
    out = {}
    for case in corpus["cases"]:
        parts = q.build_partitions(parse(case["flow"]))
        out[case["name"]] = [w.encode_reading(parts, e["reading"]) for e in case["readings"]]
    dest = REPO / "prismpath-telemetry-rs" / "tests" / "fixtures" / "wire_parity.json"
    dest.write_text(json.dumps(out, indent=1) + "\n")
    print(f"wrote {dest}  ({len(out)} flows, {sum(len(v) for v in out.values())} readings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
