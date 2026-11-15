# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The release policy over synthetic acceptance reports: a full leg with every required gate passing
is eligible, one failed gate refuses, a missing required row is missing evidence and not a refusal,
a single language leg refuses, the policy compiles to a table image, and the receipt binds the
decision to the revision, the artifacts, the policy identity and the reports."""
import json
from pathlib import Path

from tools import release_eligibility

ALL_PASS = ["export tracked tree", "build wheel and sdist", "reproducible wheel and sdist", "package boundary (wheel and sdist)",
            "python full: skip budget", "inventory and boundary: repository", "compatibility", "provenance check",
            "end to end: Python chain from the wheel, Rust chain from the candidates, seams compared"]


def _report(out: Path, leg: str, statuses: dict, extra_rows=()):
    lines = ["# Acceptance report", "", f"commit abc123, leg {leg}, 2026-09-20T00:00Z", "", "| Gate | Status | Detail |", "|---|---|---|"]
    for gate, status in statuses.items():
        lines.append(f"| {gate} | {status} | log |")
    lines += list(extra_rows)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text("\n".join(lines) + "\n")
    (out / "skips.log").write_text("skips: 0\n")
    (out / "dist").mkdir(exist_ok=True)
    (out / "dist" / "prismpath-0.0.0-py3-none-any.whl").write_bytes(b"wheel")


def test_full_leg_all_pass_is_eligible(tmp_path):
    _report(tmp_path, "full", {gate: "pass" for gate in ALL_PASS})
    assert release_eligibility.main(["--out", str(tmp_path), "--revision", "abc123"]) == 0
    receipt = json.loads((tmp_path / "release_receipt.json").read_text())
    assert receipt["decision"] == "eligible" and receipt["path"] == ["assess", "eligible"]
    assert receipt["source_revision"] == "abc123"
    assert receipt["artifacts"]["prismpath-0.0.0-py3-none-any.whl"]
    assert len(receipt["policy"]["image_sha256"]) == 64 and receipt["policy"]["image_bytes"] > 0
    assert receipt["reports"]["report.md"] and receipt["reports"]["skips.log"]
    assert (tmp_path / "release_receipts.log").exists()


def test_one_failed_gate_refuses(tmp_path):
    statuses = {gate: "pass" for gate in ALL_PASS}
    statuses["compatibility"] = "FAIL"
    _report(tmp_path, "full", statuses)
    assert release_eligibility.main(["--out", str(tmp_path), "--revision", "abc123"]) == 1
    receipt = json.loads((tmp_path / "release_receipt.json").read_text())
    assert receipt["decision"] == "refused" and receipt["facts"]["compatibility_ok"] is False


def test_a_gate_that_never_ran_is_missing_evidence_not_a_refusal(tmp_path):
    statuses = {gate: "pass" for gate in ALL_PASS if gate != "provenance check"}
    _report(tmp_path, "full", statuses)
    assert release_eligibility.main(["--out", str(tmp_path), "--revision", "abc123"]) == 1
    receipt = json.loads((tmp_path / "release_receipt.json").read_text())
    assert receipt["decision"] == "missing_evidence" and receipt["facts"]["evidence_complete"] is False


def test_a_missing_gate_row_from_the_script_refuses(tmp_path):
    statuses = {gate: "pass" for gate in ALL_PASS}
    _report(tmp_path, "full", statuses, extra_rows=["| missing gate: rust: workspace tests | FAIL | never ran |"])
    assert release_eligibility.main(["--out", str(tmp_path), "--revision", "abc123"]) == 1
    receipt = json.loads((tmp_path / "release_receipt.json").read_text())
    assert receipt["decision"] == "refused" and receipt["facts"]["gates_missing"] == 1


def test_single_language_leg_is_not_eligible(tmp_path):
    _report(tmp_path, "python", {gate: "pass" for gate in ALL_PASS})
    assert release_eligibility.main(["--out", str(tmp_path), "--revision", "abc123"]) == 1
    assert json.loads((tmp_path / "release_receipt.json").read_text())["decision"] == "refused"


def test_no_report_is_an_error_not_a_decision(tmp_path):
    assert release_eligibility.main(["--out", str(tmp_path), "--revision", "abc123"]) == 2
    assert not (tmp_path / "release_receipt.json").exists()


def test_policy_is_level_m():
    identity = release_eligibility.policy_identity()
    assert identity["image_bytes"] > 0
