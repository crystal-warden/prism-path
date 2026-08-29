#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Conformance harness: run tshark with facet.lua over the committed pcap corpus.

Checks:
  1. Parity: Lua cause lookup table matches prismpath/causes.py.
  2. Pass 1: dissect corpus frames with facet.interpret_receipts false and compare against facet_corpus.expected.json.
  3. Pass 2: dissect corpus frames with facet.interpret_receipts true and verify cause fields on receipt frames.

Exit codes: 0 all checks pass, 1 failure, 2 tshark not available.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def check_parity() -> bool:
    """Verify Lua cause code table in facet.lua matches prismpath/causes.py exactly."""
    sys.path.insert(0, str(REPO))
    from prismpath import causes

    py_map = {0: "clean"}
    py_map.update({code: name for code, name, _k, _d in causes._REGISTRY})

    lua_text = (HERE / "facet.lua").read_text()
    lua_map = {}
    for match in re.finditer(r'\[\s*(\d+)\s*\]\s*=\s*["\']([^"\']+)["\']', lua_text):
        code = int(match.group(1))
        name = match.group(2)
        lua_map[code] = name

    if py_map != lua_map:
        print("FAIL: cause table parity mismatch between causes.py and facet.lua")
        missing = set(py_map.keys()) - set(lua_map.keys())
        extra = set(lua_map.keys()) - set(py_map.keys())
        mismatch = {k: (py_map[k], lua_map[k]) for k in py_map.keys() & lua_map.keys() if py_map[k] != lua_map[k]}
        if missing:
            print(f"  Missing in Lua: {sorted(missing)}")
        if extra:
            print(f"  Extra in Lua: {sorted(extra)}")
        if mismatch:
            print(f"  Mismatched names: {mismatch}")
        return False

    print("PARITY OK: Lua cause table matches prismpath/causes.py")
    return True


def main() -> int:
    if not check_parity():
        return 1

    if shutil.which("tshark") is None:
        print("SKIP: tshark not found on PATH (install wireshark-common to run this harness)")
        return 2
    expected = json.loads((HERE / "facet_corpus.expected.json").read_text())

    # Pass 1: interpret_receipts FALSE (default)
    cmd1 = ["tshark", "-r", str(HERE / "facet_corpus.pcap"),
            "-X", f"lua_script:{HERE / 'facet.lua'}",
            "-T", "fields", "-E", "separator=|", "-E", "occurrence=f",
            "-e", "frame.number", "-e", "facet.form", "-e", "facet.count",
            "-e", "facet.wireints", "-e", "facet.padbits", "-e", "facet.malformed"]
    proc1 = subprocess.run(cmd1, capture_output=True, text=True)
    if proc1.returncode != 0:
        print(proc1.stderr.strip())
        print("FAIL: tshark pass 1 exited nonzero")
        return 1

    got = {}
    for line in proc1.stdout.strip().splitlines():
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
    print(f"Pass 1 OK: {total - fails}/{total} frames match reference decode with interpret_receipts=false")
    if fails > 0:
        return 1

    # Pass 2: interpret_receipts TRUE
    cmd2 = ["tshark", "-r", str(HERE / "facet_corpus.pcap"),
            "-X", f"lua_script:{HERE / 'facet.lua'}",
            "-o", "facet.interpret_receipts:true",
            "-T", "fields", "-E", "separator=|", "-E", "occurrence=f",
            "-e", "frame.number", "-e", "facet.cause", "-e", "facet.cause_name"]
    proc2 = subprocess.run(cmd2, capture_output=True, text=True)
    if proc2.returncode != 0:
        print(proc2.stderr.strip())
        print("FAIL: tshark pass 2 exited nonzero")
        return 1

    got2 = {}
    for line in proc2.stdout.strip().splitlines():
        parts = line.split("|")
        if len(parts) == 3 and parts[0]:
            got2[int(parts[0])] = (parts[1], parts[2])

    expected_receipts = {
        19: ("0", "clean"),
        20: ("36", "route:stuck"),
    }

    receipt_fails = 0
    for frame_num, (exp_cause, exp_cname) in expected_receipts.items():
        g = got2.get(frame_num, ("", ""))
        if g != (exp_cause, exp_cname):
            print(f"FAIL #{frame_num} receipt interpretation: got cause={g[0]!r}, cause_name={g[1]!r}; expected cause={exp_cause!r}, cause_name={exp_cname!r}")
            receipt_fails += 1

    for frame_num in range(1, len(expected) + 1):
        if frame_num not in expected_receipts:
            g = got2.get(frame_num, ("", ""))
            if g[0] or g[1]:
                print(f"FAIL #{frame_num} non-receipt frame reported cause: got cause={g[0]!r}, cause_name={g[1]!r}")
                receipt_fails += 1

    if receipt_fails > 0:
        return 1

    print(f"Pass 2 OK: receipt interpretation verified on {len(expected_receipts)} receipt frames with interpret_receipts=true")
    return 0


if __name__ == "__main__":
    sys.exit(main())

