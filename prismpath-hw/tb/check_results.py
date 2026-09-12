#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The REAL pass/fail gate for the RTL testbench.

cocotb + Makefile.sim returns exit 0 even when a cocotb test FAILS (the simulator finishes cleanly;
the failure is recorded in results.xml, not in the make exit code). So a bare `make -C tb` is NOT a
gate — it "passes" on a broken RTL. This parses the JUnit results.xml the sim just wrote and exits
nonzero on any failure/error, or if an expected test did not run at all (a stale/half-run result).

Use `make -C tb gate` (which runs the sim then this) as the gate, never bare `make`.

Called with no arguments it checks this directory's results.xml against the interpreter suite, which
is what `make -C tb gate` does. The unit testbenches under rtl-tb/ and codec-bench/rtl-tb/ reach the
same check through rtl-tb/gate.mk, which names the results file and the expected tests of the single
testbench it is gating, so one checker decides pass or fail for every cocotb suite in the tree.
"""
import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# The defaults are the interpreter suite in this directory, so that the historical invocation
# `python3 check_results.py` keeps meaning exactly what it meant before the other testbenches
# started calling in with arguments of their own.
INTERPRETER_RESULTS = Path(__file__).resolve().parent / "results.xml"
INTERPRETER_SUITE = ["conformance", "sensor_log_replay"]


def parse_args():
    parser = argparse.ArgumentParser(description="Fail the build on any cocotb failure.")
    parser.add_argument("--results",
                        default=str(INTERPRETER_RESULTS),
                        help="the JUnit results file the simulation just wrote")
    parser.add_argument("--expect",
                        nargs="+",
                        default=INTERPRETER_SUITE,
                        metavar="TEST",
                        help="cocotb test names that must be present; a missing one fails the gate")
    return parser.parse_args()


def main():
    args = parse_args()
    results_path = Path(args.results)
    if not results_path.exists():
        sys.exit("RTL gate FAIL: results.xml missing — the sim did not run")

    cases = ET.parse(results_path).getroot().findall(".//testcase")
    names = {case.get("name") for case in cases}
    failing = sum(len(case.findall("failure")) + len(case.findall("error")) for case in cases)
    missing = set(args.expect) - names

    if failing or missing or not cases:
        print(f"RTL gate FAIL: {failing} failing/errored, "
              f"missing={sorted(missing) or 'none'}, ran={sorted(names)}")
        sys.exit(1)

    print(f"RTL gate PASS: {len(cases)} tests, 0 failing ({sorted(names)})")


if __name__ == "__main__":
    main()
