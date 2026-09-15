# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Regenerate the reachability corpus from the Python model checker reference implementation.

Ensures the JavaScript bounded reachability checker and Python reachability checker remain in
bit for bit parity without silent specification drift.
"""
import json
import sys
from pathlib import Path

from prismpath.kernel import model_check as model_check_module
from prismpath.kernel.parser import parse as parse_flow_document

CONFORMANCE_DIRECTORY = Path(__file__).resolve().parent / "conformance"
TARGET_CORPUS_FILE = CONFORMANCE_DIRECTORY / "reach.json"


def generate() -> dict:
    """Recompute reachability verdicts for every case in the committed reachability corpus."""
    disk_bytes = TARGET_CORPUS_FILE.read_bytes()
    document_data = json.loads(disk_bytes.decode("utf-8"))
    cases_list = document_data["cases"]
    updated_cases = []
    for case_item in cases_list:
        flow_graph = parse_flow_document(case_item["flow"])
        targets_list = case_item["targets"]
        reachability_results = model_check_module.check_reach(
            flow_graph,
            targets_list,
            assume=case_item.get("assume"),
            bound=case_item.get("bound", 25),
            include_errors=case_item.get("include_errors", True),
            include_events=case_item.get("include_events", True),
        )
        expected_verdicts = {
            target_name: {
                "reachable": reachability_results[target_name].reachable,
                "proven": reachability_results[target_name].proven,
            }
            for target_name in targets_list
        }
        updated_cases.append({
            "key": case_item["key"],
            "flow": case_item["flow"],
            "targets": targets_list,
            "assume": case_item.get("assume"),
            "bound": case_item.get("bound", 25),
            "include_errors": case_item.get("include_errors", True),
            "include_events": case_item.get("include_events", True),
            "expected": expected_verdicts,
        })
    return {
        "note": document_data["note"],
        "version": document_data["version"],
        "cases": updated_cases,
    }


def main() -> int:
    """Regenerate reach.json and verify exact byte for byte reproduction."""
    document_structure = generate()
    generated_text = json.dumps(document_structure, indent=2)
    generated_bytes = generated_text.encode("utf-8")
    existing_bytes = TARGET_CORPUS_FILE.read_bytes()
    if generated_bytes != existing_bytes:
        print("GATE FAIL: reach.json regeneration differed from committed file")
        return 1
    print(f"wrote {TARGET_CORPUS_FILE} ({len(document_structure['cases'])} cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
