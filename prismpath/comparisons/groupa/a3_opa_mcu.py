# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A3 combination test (Phase 5): OPA compiled to WebAssembly, executed on an MCU class target.

PREREGISTRATION.md section 5, A3: "WITH-WORK: a comparator reaches a second substrate class through a
documented compiler or runtime (for example OPA to WebAssembly) with the decisions identical", and
section 9 counts practical combinations against the DISTINCT verdict. This driver replays the 23 A3
corpus readings through the RP2350 firmware in groupa/opa_wasm_mcu/ (the modules opa build -t wasm
produced for network_admission and sensor_interlock, run by the wasm3 interpreter) and compares each
board decision, outcome and rule, with the corpus expectation. It writes the evidence log and the 23
result files for the combination column opa+glue, graded WITH-WORK when every decision is identical
and the glue stays under the section 4 budget, NOT otherwise.

Usage: python -m prismpath.comparisons.groupa.a3_opa_mcu --port /dev/ttyACM0 [--hours 2.0]
"""
from __future__ import annotations

import argparse
import json
import struct
import subprocess
import sys
import time
from pathlib import Path

import serial

from prismpath.comparisons.groupa.common import evidence_dir, policy_by_id, write_result
from prismpath.comparisons.harness import HERE, scenario_steps

POLICIES = ["network_admission", "sensor_interlock"]
GLUE_DIR = HERE / "groupa" / "opa_wasm_mcu"
GLUE_FILES = ["opa_wasm_eval.c", "opa_wasm_eval.h", "pico/opa_pico.c", "pico/CMakeLists.txt"]


def loc(paths) -> int:
    n = 0
    for p in paths:
        for line in (GLUE_DIR / p).read_text().splitlines():
            s = line.strip()
            if s and not s.startswith(("#", "//", "/*", "*")):
                n += 1
    return n


def wasm3_commit() -> str:
    src = HERE / ".toolchain" / "src" / "wasm3"
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=src, capture_output=True, text=True).stdout.strip()
    except Exception:
        return "unknown"


class Board:
    def __init__(self, port: str):
        self.s = serial.Serial(port, 115200, timeout=15)
        time.sleep(1.0)
        self.s.reset_input_buffer()

    def frame(self):
        t = self.s.read(1)
        if len(t) != 1:
            raise RuntimeError("serial timeout")
        n = struct.unpack("<H", self.s.read(2))[0]
        return t, self.s.read(n)

    def ident(self) -> str:
        self.s.write(b"I"); t = self.s.read(1); n = self.s.read(1)
        assert t == b"i"
        return self.s.read(n[0]).decode()

    def stats(self) -> dict:
        self.s.write(b"S"); t, b = self.frame(); assert t == b"s"; return json.loads(b)

    def load(self, idx: int) -> str:
        self.s.write(b"L" + bytes([idx])); t, b = self.frame()
        if t != b"l":
            raise RuntimeError(f"load failed: {b!r}")
        return b.decode()

    def eval(self, inp: dict):
        b = json.dumps(inp, separators=(",", ":")).encode()
        t0 = time.perf_counter()
        self.s.write(b"V" + struct.pack("<H", len(b)) + b)
        t, r = self.frame()
        dt = (time.perf_counter() - t0) * 1e6
        return t, r, dt


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", default="/dev/ttyACM0")
    ap.add_argument("--hours", type=float, default=2.0, help="hours spent building the glue, recorded in the result files")
    a = ap.parse_args(argv)
    board = Board(a.port)
    ident = board.ident()
    isa = ident.split()[1]
    print("board:", ident)
    ev = evidence_dir("opa+glue", "A3")
    rows = []
    for idx, pid in enumerate(POLICIES):
        policy = policy_by_id(pid)
        board.load(idx)
        first = True
        for sid, kind, inp, exp in scenario_steps(policy):
            if kind == "undeclared_missing" or any(v is None for v in inp.values()):
                continue  # A3 uses the complete readings, the same 23 as the PrismPath legs
            t, r, dt = board.eval({k: v for k, v in inp.items() if v is not None})
            if t == b"M":
                res = json.loads(r)[0]["result"]
                obs, rule = res.get("outcome"), res.get("rule")
            else:
                obs, rule = "error", None
            agree = (obs == exp["outcome"] and rule == exp.get("rule"))
            rows.append({"policy": pid, "scenario": sid, "board_outcome": obs, "board_rule": rule, "expected_outcome": exp["outcome"],
                         "expected_rule": exp.get("rule"), "agree": agree, "round_trip_us": round(dt, 1), "first_eval_after_load": first,
                         "raw": r.decode(errors="replace")})
            first = False
            print(f"  {pid:18s} {sid:34s} board={obs}/{rule} expected={exp['outcome']}/{exp.get('rule')} {'ok' if agree else 'MISMATCH'} {dt:.0f} us")
    stats = board.stats()
    n_ok = sum(1 for r in rows if r["agree"])
    glue_loc = loc(GLUE_FILES)
    record = {"ident": ident, "isa": isa, "wasm3_commit": wasm3_commit(), "stats_after": stats, "rows": rows, "agree": n_ok, "total": len(rows),
              "glue_loc": glue_loc, "glue_files": GLUE_FILES, "hours": a.hours}
    (ev / f"opa_wasm3_{isa}.json").write_text(json.dumps(record, indent=1) + "\n")
    print(f"OPA wasm on {isa}: {n_ok}/{len(rows)} identical; heap high water {stats['heap_high_water']} B, linear memory {stats['linear_memory_bytes']} B; glue {glue_loc} lines")
    # result files: grade from the run and the budget
    within = glue_loc <= 300 and a.hours <= 8
    all_ok = n_ok == len(rows)
    grade = "WITH-WORK" if (all_ok and within) else "NOT"
    glue = {"description": ("OPA's own compiler (opa build -t wasm) plus the wasm3 WebAssembly interpreter (third party, MIT) built into "
                            "RP2350 firmware with a host layer that supplies the module's six imports, drives the documented opa_eval ABI, "
                            "and carries JSON in and out over USB-CDC; both compiled modules live in flash, one runtime open at a time"),
            "components": [f"wasm3 {record['wasm3_commit']} (interpreter, not counted as glue lines)", "opa_wasm_eval.c/.h (ABI glue)",
                           "pico/opa_pico.c (firmware and protocol)", "pico/CMakeLists.txt"],
            "loc": glue_loc, "hours": a.hours}
    # every ISA leg recorded so far (opa_wasm3_<isa>.json) rides along in the result files
    legs = {}
    for f in sorted(ev.glob("opa_wasm3_*.json")):
        rec = json.loads(f.read_text())
        legs[rec["isa"]] = {"agree": rec["agree"], "total": rec["total"], "heap_high_water_bytes": rec["stats_after"]["heap_high_water"]}
    by_key = {(r["policy"], r["scenario"]): r for r in rows}
    for pid in POLICIES:
        for sid, kind, inp, exp in scenario_steps(policy_by_id(pid)):
            if (pid, sid) not in by_key:
                continue
            r = by_key[(pid, sid)]
            write_result(system="opa+glue", dimension="A3", policy=pid, scenario=sid, expected=exp["outcome"],
                         observed=r["board_outcome"], grade=grade, idiomatic=True, evidence_path=ev, glue=glue,
                         measurements={"round_trip_us": r["round_trip_us"], "heap_high_water_bytes": stats["heap_high_water"],
                                       "linear_memory_bytes": stats["linear_memory_bytes"], "isa": isa, "legs": legs},
                         notes=(f"OPA's WebAssembly module for this policy decided {r['board_outcome']}/{r['board_rule']} on the RP2350 "
                                f"({isa}) under wasm3, expected {exp['outcome']}/{exp.get('rule')}: {'identical' if r['agree'] else 'DIFFERENT'}. "
                                f"Board evidence {ev.relative_to(HERE.parent.parent)}/opa_wasm3_{isa}.json. The comparator reaches the MCU "
                                f"class through its documented compiler and a third party interpreter; the glue is {glue_loc} lines and about "
                                f"{a.hours} h, {'within' if within else 'OVER'} the section 4 budget, no trust anchor added. Memory on the board: "
                                f"{stats['heap_high_water']} B heap high water of 520 KB SRAM, {stats['linear_memory_bytes']} B linear memory, "
                                f"{r['round_trip_us']:.0f} us USB round trip{' (first evaluation after load, lazy compile)' if r['first_eval_after_load'] else ''}. "
                                f"ISA legs on record: {legs}. For scale, PrismPath's table image for the same policy is 224 B or 160 B "
                                "under a 1.7 KB interpreter class."))
    print(f"opa+glue A3 rows written, grade {grade}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
