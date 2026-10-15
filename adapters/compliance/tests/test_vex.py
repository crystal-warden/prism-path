# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""CycloneDX VEX from reachability verdicts: the OpenVEX vocabulary maps onto CycloneDX's, the
document validates against the cached 1.6 schema, and a not affected verdict without a justification
is refused rather than written."""
import pytest

pytest.importorskip("jsonschema")

from adapters.compliance import emit  # noqa: E402
from adapters.compliance.tests.sample import FIXED_NOW  # noqa: E402

COMPONENT = {"name": "shopapp", "version": "1.4.0", "purl": "pkg:pypi/shopapp@1.4.0"}
VERDICTS = [
    {"id": "CVE-2024-0001", "state": "affected", "detail": "reachable: routes.upload -> yaml.load",
     "source_name": "NVD", "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"},
    {"id": "CVE-2024-0002", "state": "not_affected", "justification": "vulnerable_code_not_in_execute_path",
     "detail": "no call, value, unresolved call, dynamic access or dependency leads to it",
     "properties": {"calls_to_vulnerable": 0, "unresolved_calls_matching": 0}},
    {"id": "CVE-2024-0003", "state": "not_affected", "justification": "component_not_present", "detail": "never imported"},
    {"id": "GHSA-aaaa-bbbb-cccc", "state": "under_investigation", "detail": "yaml.load taken as a value at app.py:3"},
]


def test_verdicts_become_a_valid_cyclonedx_vex_document():
    doc = emit.emit_vex(VERDICTS, COMPONENT, now=FIXED_NOW)
    assert emit.validate(doc, "cyclonedx") == (True, [])
    analyses = {entry["id"]: entry["analysis"] for entry in doc["vulnerabilities"]}
    assert analyses["CVE-2024-0001"]["state"] == "exploitable"
    assert analyses["CVE-2024-0002"] == {"state": "not_affected", "justification": "code_not_reachable",
                                         "detail": VERDICTS[1]["detail"]}
    assert analyses["CVE-2024-0003"]["justification"] == "code_not_present"
    assert analyses["GHSA-aaaa-bbbb-cccc"]["state"] == "in_triage"
    assert all(entry["affects"] == [{"ref": "product:shopapp"}] for entry in doc["vulnerabilities"])


def test_the_same_verdicts_give_the_same_document():
    first = emit.emit_vex(VERDICTS, COMPONENT, now=FIXED_NOW)
    second = emit.emit_vex(VERDICTS, COMPONENT, now=FIXED_NOW)
    assert first == second


def test_not_affected_without_a_justification_is_refused():
    with pytest.raises(ValueError, match="needs a justification"):
        emit.emit_vex([{"id": "CVE-2024-0009", "state": "not_affected", "detail": "trust me"}], COMPONENT)


def test_an_unknown_state_is_refused():
    with pytest.raises(ValueError, match="unknown VEX state"):
        emit.emit_vex([{"id": "CVE-2024-0009", "state": "probably_fine", "detail": ""}], COMPONENT)
