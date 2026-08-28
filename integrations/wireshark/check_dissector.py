#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Conformance harness: run tshark with facet.lua over the committed pcap corpus and compare
every frame's dissection against facet_corpus.expected.json (which is computed by the reference
codec + the strict decode mirror, independent of the Lua).

Pass criteria per frame:
  malformed frames    form and malformed flag must match
  well formed frames  form, count, wire integers, pad bits, and malformed flag must match

Exit codes: 0 all frames match, 1 mismatch, 2 tshark not available.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    if shutil.which("tshark") is None:
        print("SKIP: tshark not found on PATH (install wireshark-common to run this harness)")
        return 2
    expected = json.loads((HERE / "facet_corpus.expected.json").read_text())

    cmd = ["tshark", "-r", str(HERE / "facet_corpus.pcap"),
           "-X", f"lua_script:{HERE / 'facet.lua'}",
           "-T", "fields", "-E", "separator=|", "-E", "occurrence=f",
           "-e", "frame.number", "-e", "facet.form", "-e", "facet.count",
           "-e", "facet.wireints", "-e", "facet.padbits", "-e", "facet.malformed"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stderr.strip())
        print("FAIL: tshark exited nonzero")
        return 1

    got = {}
    for line in proc.stdout.strip().splitlines():
        parts = line.split("|")
        if len(parts) == 6 and parts[0]:
            got[int(parts[0])] = {"form": parts[1], "count": parts[2],
                                  "wireints": parts[3], "padbits": parts[4],
                                  "malformed": parts[5]}

    fails = 0
    for e in expected:
        g = got.get(e["frame"])
        if e["form"] == "none":
            if g is not None and g["form"]:
                print(f"FAIL #{e['frame']} {e['name']}: expected no facet output, got {g}")
                fails += 1
            continue
        if g is None:
            print(f"FAIL #{e['frame']} {e['name']}: no dissection output")
            fails += 1
            continue
        problems = []
        if g["form"] != e["form"]:
            problems.append(f"form {g['form']!r} != {e['form']!r}")
        if g["malformed"] != str(e["malformed"]):
            problems.append(f"malformed {g['malformed']!r} != {e['malformed']!r}")
        if not e["malformed"]:
            if g["count"] != str(e["count"]):
                problems.append(f"count {g['count']!r} != {e['count']!r}")
            if g["wireints"] != e["wireints"]:
                problems.append(f"wireints {g['wireints']!r} != {e['wireints']!r}")
            if "padbits" in e and g["padbits"] != str(e["padbits"]):
                problems.append(f"padbits {g['padbits']!r} != {e['padbits']!r}")
        if problems:
            print(f"FAIL #{e['frame']} {e['name']}: " + "; ".join(problems))
            fails += 1

    total = len(expected)
    print(f"{total - fails}/{total} frames match the reference decode")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
