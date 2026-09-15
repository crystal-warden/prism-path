# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Regenerate the capability matrix corpus from the Python model checker reference implementation.

Ensures the JavaScript capability report and Python capability report remain in bit for bit parity
without silent specification drift.
"""
import json
import sys
from pathlib import Path

from prismpath.kernel import model_check as model_check_module
from prismpath.kernel.parser import parse as parse_flow_document

CONFORMANCE_DIRECTORY = Path(__file__).resolve().parent / "conformance"
TARGET_CORPUS_FILE = CONFORMANCE_DIRECTORY / "capability.json"


def generate() -> dict:
    """Recompute the capability report for every case in the committed capability corpus."""
    disk_bytes = TARGET_CORPUS_FILE.read_bytes()
    document_data = json.loads(disk_bytes.decode("utf-8"))
    cases_list = document_data["cases"]
    updated_cases = []
    for case_item in cases_list:
        flow_graph = parse_flow_document(case_item["flow"])
        capability_report_data = model_check_module.capability_report(flow_graph)
        updated_cases.append({
            "key": case_item["key"],
            "flow": case_item["flow"],
            "expected": capability_report_data,
        })
    return {
        "note": document_data["note"],
        "version": document_data["version"],
        "cases": updated_cases,
    }


def main() -> int:
    """Regenerate capability.json and verify exact byte for byte reproduction."""
    document_structure = generate()
    generated_text = json.dumps(document_structure, indent=2)
    generated_bytes = generated_text.encode("utf-8")
    existing_bytes = TARGET_CORPUS_FILE.read_bytes()
    if generated_bytes != existing_bytes:
        print("GATE FAIL: capability.json regeneration differed from committed file")
        return 1
    print(f"wrote {TARGET_CORPUS_FILE} ({len(document_structure['cases'])} cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
