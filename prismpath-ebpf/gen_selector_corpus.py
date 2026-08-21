#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze a conformance corpus for the STATEFUL selector (posture_selector). Unlike the stateless
predicate corpus (independent table-per-vector records), this is a set of event STREAMS: each stream
starts the resident FSM at the policy's start node and applies a sequence of control events; the
reference is the posture (node index) the resident interpreter reaches after each event. The kernel
cert (cert_selector) replays each stream through ppt_select via BPF_PROG_TEST_RUN and must reproduce
the whole trail. The reference is the Python interpreter, cross-checked step-by-step against the C
target (interp.c), exactly the two-referee discipline the predicate corpus uses.

Binary format (LE):  <u32 tbl_len><tbl bytes><u32 n_streams>{ <u32 n_events>{<s32 ev><s32 posture>} }

    gen_selector_corpus.py <policy.ppt> <out.bin>
"""
import json
import os
import random
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "prismpath-hw"))
sys.path.insert(0, str(HERE.parent))
os.environ.setdefault("PRISMPATH_REPO", str(HERE.parent))
import ppt_compile as pc                              # noqa: E402
from prismpath.parser import parse_file               # noqa: E402
from prismpath.engine import first_deterministic       # noqa: E402

INTERP = HERE / "interp"


def build_streams():
    """Thorough coverage: boundary walks, every (posture,event) transition, holds, and random."""
    streams = []
    streams.append([1, 1, 1, 1])                       # escalate, clamps at the ceiling
    streams.append([2, 2, 2, 2])                       # de-escalate from the floor, stays
    streams.append([1, 1, 2, 2])                       # full up then full down
    streams.append([1, 1, 1, 2, 1, 2, 1])              # oscillate at the ceiling
    streams.append([2, 1, 2, 1, 2])                    # oscillate at the floor
    streams.append([1, 0, 1, 3, 2, 99, 2, 0])          # holds: 0/3/99 are not up/down -> stay
    # every (start posture, event) transition, explicitly (prime to the posture, then the event)
    prime = {0: [], 1: [1], 2: [1, 1]}
    for p in (0, 1, 2):
        for e in (0, 1, 2, 3):
            streams.append(prime[p] + [e])
    # deterministic random streams over events {0,1,2,3}
    rnd = random.Random(7)
    for _ in range(30):
        streams.append([rnd.choice([0, 1, 2, 3]) for _ in range(rnd.randint(5, 20))])
    streams.append([rnd.choice([0, 1, 2, 3]) for _ in range(200)])   # a long stress stream
    return streams


def main():
    ppt_path, out_path = sys.argv[1], sys.argv[2]
    g = parse_file(str(HERE / "posture_selector.md"))
    img = pc.compile_flow(g)
    names = [n for n, _ in img.nodes]
    tbl = bytearray(img.serialize())
    # Signed fail-safe: the policy declares `safe: <node>` in its frontmatter; stamp that node index
    # into the HIGH byte of the flags word (offset 26, so byte 27 in LE) so the fail-safe posture rides
    # inside the image — and thus the manifest signature — instead of an unsigned convention. Left 0
    # when undeclared, in which case the reader falls back to the last (most-restrictive) node.
    safe_name = g.meta.get("safe")
    if safe_name is not None:
        tbl[27] = names.index(safe_name) & 0xFF
        # A resident selector (declares `safe:`) must also declare a signed hot-swap migration
        # strategy — the stateful-migration lint. Enforce it at build, and stamp the mode into the
        # flags low byte: `by-name` sets bit 1 (FLAG_MIGRATE_BY_NAME), `reset-to` leaves it clear
        # (reset to the fail-safe on swap). Both ride the image, hence the manifest signature.
        mig = (g.meta.get("migration") or "").strip().split("=", 1)[0].strip().lower()
        if mig not in ("by-name", "reset-to"):
            raise SystemExit("posture_selector declares `safe:` but no valid `migration:` — refusing "
                             "to build (analysis code stateful-migration-undeclared)")
        if mig == "by-name":
            tbl[26] |= 0x02          # FLAG_MIGRATE_BY_NAME
    tbl = bytes(tbl)
    Path(ppt_path).write_bytes(tbl)

    def py_next(cur, ev):
        t, _ = first_deterministic(g.nodes[names[cur]].edges, {"ev": ev})
        return names.index(t) if t else cur

    def c_next(cur, ev, tmp=HERE / ".sel_tmp"):
        tmp.mkdir(exist_ok=True)
        (tmp / "c.ppt").write_bytes(tbl)
        (tmp / "c.bin").write_bytes(pc.encode_regs(img, {"ev": ev}, node_idx=cur))
        out = subprocess.run([str(INTERP), "eval", str(tmp / "c.ppt"), str(tmp / "c.bin")],
                             capture_output=True, text=True).stdout.strip()
        return int(out.split()[2]) if out.startswith("match") else cur

    streams = build_streams()
    rec = struct.pack("<I", len(tbl)) + tbl + struct.pack("<I", len(streams))
    total_events = 0
    ref_json = []
    c_disagree = 0
    for events in streams:
        cur = img.start
        trail = []
        for ev in events:
            nxt = py_next(cur, ev)
            if c_next(cur, ev) != nxt:                 # the two referees must agree at every step
                c_disagree += 1
            cur = nxt
            trail.append(cur)
        rec += struct.pack("<I", len(events))
        for ev, post in zip(events, trail):
            rec += struct.pack("<ii", ev, post)
        total_events += len(events)
        ref_json.append({"events": events, "postures": [names[p] for p in trail]})

    Path(out_path).write_bytes(rec)
    Path(out_path).with_suffix(".json").write_text(json.dumps(
        {"policy": "posture_selector", "nodes": names, "streams": ref_json}, indent=1))
    print(f"SELECTOR CORPUS: {len(streams)} streams, {total_events} events; "
          f"C-target reference agrees with Python at every step: {c_disagree == 0} "
          f"({c_disagree} disagreements)")


if __name__ == "__main__":
    main()
