#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Compile the hot-swap migration fixtures used by migrate_selector.c.

Three signed tables: policy A (posture_selector) and a REINDEXED policy B (posture_selector_v2 — same
posture NAMES, different node indices), stamped with safe_node + the migration mode + a per-node
name-hash section (FLAG_NODE_NAMES). B is emitted twice: once by-name and once reset-to, so the harness
can exercise both strategies. The name-hash is FNV-1a-32 of the node name, matched byte-for-byte by the
loader's migrate_node().

    gen_migrate_fixtures.py            # writes migrate_A.ppt, migrate_Bname.ppt, migrate_Breset.ppt
"""
import os
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "prismpath-hw"))
sys.path.insert(0, str(HERE.parent))
os.environ.setdefault("PRISMPATH_REPO", str(HERE.parent))
import ppt_compile as pc                              # noqa: E402
from prismpath.parser import parse_file               # noqa: E402

FLAG_MIGRATE_BY_NAME = 0x02
FLAG_NODE_NAMES = 0x04


def fnv32(s: str) -> int:
    h = 0x811c9dc5
    for b in s.encode():
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def build(md: str, migration: str, out: str):
    g = parse_file(str(HERE / md))
    img = pc.compile_flow(g)
    names = [n for n, _ in img.nodes]
    tbl = bytearray(img.serialize())
    safe = g.meta.get("safe")
    if safe is not None:
        tbl[27] = names.index(safe) & 0xFF                 # signed fail-safe node (flags-word high byte)
    if migration == "by-name":
        tbl[26] |= FLAG_MIGRATE_BY_NAME
    tbl[26] |= FLAG_NODE_NAMES                              # append the signed per-node name-hash section
    for nm in names:
        tbl += struct.pack("<I", fnv32(nm))
    (HERE / out).write_bytes(bytes(tbl))
    print(f"{out}: nodes={names} safe={safe}({names.index(safe) if safe else '-'}) "
          f"migration={migration} len={len(tbl)}")


def main():
    build("posture_selector.md",    "by-name",  "migrate_A.ppt")       # v1: normal=0 elevated=1 lockdown=2
    build("posture_selector_v2.md", "by-name",  "migrate_Bname.ppt")   # v2: normal=0 lockdown=1 elevated=2
    build("posture_selector_v2.md", "reset-to", "migrate_Breset.ppt")


if __name__ == "__main__":
    main()
