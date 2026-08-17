#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The REAL pass/fail gate for the RTL testbench.

cocotb + Makefile.sim returns exit 0 even when a cocotb test FAILS (the simulator finishes cleanly;
the failure is recorded in results.xml, not in the make exit code). So a bare `make -C tb` is NOT a
gate — it "passes" on a broken RTL. This parses the JUnit results.xml the sim just wrote and exits
nonzero on any failure/error, or if an expected test did not run at all (a stale/half-run result).

Use `make -C tb gate` (which runs the sim then this) as the gate, never bare `make`.
"""
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

EXPECTED = {"conformance", "sensor_log_replay"}

r = Path(__file__).resolve().parent / "results.xml"
if not r.exists():
    sys.exit("RTL gate FAIL: results.xml missing — the sim did not run")

cases = ET.parse(r).getroot().findall(".//testcase")
names = {c.get("name") for c in cases}
failing = sum(len(c.findall("failure")) + len(c.findall("error")) for c in cases)
missing = EXPECTED - names

if failing or missing or not cases:
    print(f"RTL gate FAIL: {failing} failing/errored, "
          f"missing={sorted(missing) or 'none'}, ran={sorted(names)}")
    sys.exit(1)

print(f"RTL gate PASS: {len(cases)} tests, 0 failing ({sorted(names)})")
