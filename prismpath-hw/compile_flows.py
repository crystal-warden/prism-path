#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""compile_flows.py — table-compile every repo flow (the day-1 `compile --target table` sweep).

For each flow in the repo: attempt a PPT image of its deterministic tier. Reports compilable
flows with their table statistics (the future BRAM budget), and the exclusion reason for the
rest. Images + JSON debug views land in build/flows/.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import ppt_compile as pc
from prismpath.parser import parse_file

HERE = Path(__file__).resolve().parent
OUT = HERE / "build" / "flows"
REPO = Path(pc._REPO)
# the repo's real flows (mirrors the `verify --level-m` sweep): authored flows, the gallery,
# the compliance adapter, the PR demo — not test fixtures, not doc snippets
FLOW_DIRS = [
    REPO / "prismpath" / "flows",
    REPO / "prismpath" / "gallery",
    REPO / "adapters" / "compliance" / "flows",
    REPO / "prismpath" / "examples" / "pr_demo",
]


def _flow_files():
    seen = []
    for d in FLOW_DIRS:
        seen.extend(sorted(d.rglob("*.md")))
    return [p for p in seen
            if not p.name.endswith(".tests.md") and p.name != "README.md"]


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    ok, bad = [], []
    for md in _flow_files():
        label = f"{md.parent.name}/{md.stem}" if md.parent.name != "flows" else md.stem
        graph = parse_file(str(md))
        try:
            img = pc.compile_flow(graph)
        except pc.SubsetError as e:
            bad.append((label, e.reason))
            continue
        blob = img.serialize()
        assert blob == pc.compile_flow(parse_file(str(md))).serialize(), \
            f"non-deterministic compile: {md.stem}"
        (OUT / f"{label.replace(chr(47), "_")}.ppt").write_bytes(blob)
        (OUT / f"{label.replace(chr(47), "_")}.json").write_text(json.dumps(img.debug(), indent=1) + "\n")
        n_edges = sum(len(e) for _, e in img.nodes)
        ok.append((label, len(blob), len(img.fields), len(img.atoms),
                   len(img.nodes), n_edges, len(img.skipped_tiers)))

    print(f"── table-compilable: {len(ok)}/{len(ok) + len(bad)} flows ──────────────")
    print(f"  {'flow':28s} {'bytes':>5s} {'flds':>4s} {'atoms':>5s} "
          f"{'nodes':>5s} {'edges':>5s} {'host':>4s}")
    for name, nb, nf, na, nn, ne, nh in ok:
        print(f"  {name:28s} {nb:5d} {nf:4d} {na:5d} {nn:5d} {ne:5d} {nh:4d}")
    print("── not table-compilable ─────────────────────────")
    for name, reason in bad:
        print(f"  {name:28s} {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
