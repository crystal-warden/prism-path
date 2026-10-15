# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The policy delivery assessment: the SSDF and Cyber Resilience Act catalogs, the checks the assessor
runs again on a real deployment, the narrow mapping from checks to requirements, and the reports the
existing emitter writes for each standard."""
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("jsonschema")

from adapters.compliance import assess_policy_delivery as delivery  # noqa: E402
from adapters.compliance import compliance_adapter as ca  # noqa: E402
from adapters.compliance import emit  # noqa: E402
from adapters.compliance.tests.sample import record, FIXED_NOW  # noqa: E402
from prismpath.hotswap import policy_pack  # noqa: E402
from prismpath.hotswap.policy_host import PolicyHost  # noqa: E402
from prismpath.kernel.parser import parse  # noqa: E402
from prismpath.tests._repo import repo_file

sys.path.insert(0, str(repo_file("prismpath-hw")))    # the compiler lives beside the hardware targets
import ppt_compile  # noqa: E402

FLOW = """---
name: delivery_fixture
start: start
field.temp: int min=0 max=200
---
## start
-> hot: when temp >= 100
-> cold: else

## hot
-> end

## cold
-> end

## end
"""

EXPECTED = {"nist_ssdf": {"PS.2": "met", "PS.3": "partially-met", "PW.4": "partially-met"},
            "eu_cra_annex_i": {"I.2.f": "partially-met", "I.2.l": "partially-met",
                               "II.1": "partially-met", "II.7": "partially-met"}}


def _tree_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(Path(root).rglob("*")) if path.is_file()}


@pytest.fixture()
def deployed(tmp_path):
    """A deployed directory laid out as the Zarf integrations leave it, with the host's swap done."""
    keys = policy_pack.keygen(str(tmp_path / "keys"))
    deployed_dir = tmp_path / "deployed"
    deployed_dir.mkdir()
    image_path = deployed_dir / delivery.PACK_NAME
    image_path.write_bytes(ppt_compile.compile_flow(parse(FLOW)).serialize())
    policy_pack.build_pack(str(image_path), {}, version=1, envelope_id="env1",
                           priv_path=keys["private"], pub_path=keys["public"], flow_text=FLOW)
    envelope = policy_pack.build_envelope("env1", policy_pack.field_dictionary_of(FLOW), None,
                                          keys["private"], keys["public"], str(deployed_dir))
    shutil.copyfile(keys["public"], deployed_dir / "authority.pub")
    host = PolicyHost(str(deployed_dir / delivery.STATE_DIR_NAME), [keys["public"]], envelope)
    assert host.swap(str(image_path))["ok"]
    sbom = emit.pack_sbom(str(image_path), [keys["public"]], name="delivery-fixture")
    assert sbom["ok"], sbom
    (deployed_dir / delivery.SBOM_NAME).write_text(json.dumps(sbom["sbom"], indent=1, sort_keys=True) + "\n")
    return deployed_dir


def _write_activation(deployed_dir, **overrides):
    image = hashlib.sha256((deployed_dir / delivery.PACK_NAME).read_bytes()).hexdigest()
    receipt = {"activated": True, "reason": "fixture", "attested_active": image, "loaded_sha256": image,
               "host_reference_path": "start -> hot -> end", "in_kernel_path": "start -> hot -> end",
               "at": FIXED_NOW, **overrides}
    (deployed_dir / delivery.ACTIVATION_NAME).write_text(json.dumps(receipt))


def _assessed(summary):
    return {standard: result["assessed"] for standard, result in summary["standards"].items()}


# ---------------- the catalogs ----------------
def test_the_ssdf_catalog_carries_every_practice_and_task_of_version_1_1():
    catalog = json.load(open(delivery.CATALOGS["nist_ssdf"], encoding="utf-8"))
    controls = catalog["controls"]
    assert len(controls) == 19 and catalog["_meta"]["controls"] == 19
    assert sum(len(control["objectives"]) for control in controls.values()) == 42
    assert set(catalog["families"]) == {"PO", "PS", "PW", "RV"}
    assert controls["PS.3"]["objectives"][1]["text"] == (
        "Collect, safeguard, maintain, and share provenance data for all components of each software release "
        "(e.g., in a software bill of materials [SBOM]).")
    for control in controls.values():                # no page furniture leaked out of the PDF text layer
        for text in [control["control"]] + [objective["text"] for objective in control["objectives"]]:
            assert "SSDF VERSION" not in text and "NIST SP 800-218" not in text and " Tasks" not in text


def test_the_cra_catalog_carries_annex_i_parts_i_and_ii():
    catalog = json.load(open(delivery.CATALOGS["eu_cra_annex_i"], encoding="utf-8"))
    controls = catalog["controls"]
    assert len(controls) == 22
    assert [control_id for control_id in controls if control_id.startswith("I.2.")] == ["I.2." + letter for letter in "abcdefghijklm"]
    assert [control_id for control_id in controls if control_id.startswith("II.")] == ["II.%d" % number for number in range(1, 9)]
    assert controls["II.1"]["control"].startswith("Manufacturers of products with digital elements shall: identify")
    assert "11 December 2027" in catalog["_meta"]["applicability"]


def test_both_catalogs_are_selectable_standards():
    listed = ca.list_standards()
    assert listed["nist_ssdf"]["controls"] == 19 and listed["eu_cra_annex_i"]["controls"] == 22
    ca.use_standard("eu_cra_annex_i")
    assert ca.get_control("II.7")["title"] == "Secure distribution of updates"


# ---------------- the assessment of a good deployment ----------------
def test_a_good_deployment_meets_only_what_its_evidence_reaches(deployed, tmp_path):
    before = _tree_hashes(deployed)
    summary = delivery.assess_deployment(str(deployed), out_dir=str(tmp_path / "reports"), now=FIXED_NOW)
    assert {name: check["ok"] for name, check in summary["checks"].items()} == {
        "pack_verifies": True, "tampered_copy_refused": True, "host_attests_pack": True, "replay_refused": True,
        "audit_trail_intact": True, "sbom_bound": True, "activation_consistent": None}
    assert _assessed(summary) == EXPECTED
    for standard, result in summary["standards"].items():
        catalog = json.load(open(delivery.CATALOGS[standard], encoding="utf-8"))
        assert sorted(result["not_assessed"] + list(result["assessed"])) == sorted(catalog["controls"])
        for name, emission in result["emitted"].items():
            assert emission["valid"] is True, (standard, name, emission["errors"])
    assert _tree_hashes(deployed) == before          # the assessor never writes the deployment


def test_the_reports_name_the_standard_and_attest_nothing_they_did_not_assess(deployed):
    summary = delivery.assess_deployment(str(deployed), now=FIXED_NOW)
    result = summary["standards"]["eu_cra_annex_i"]
    records, not_assessed = result["records"], result["not_assessed_detail"]
    bom = emit.emit_cyclonedx(records, now=FIXED_NOW, standard="eu_cra_annex_i", not_assessed=not_assessed)
    assert bom["definitions"]["standards"][0]["name"].startswith("Regulation (EU) 2024/2847")
    mapped = {item["requirement"] for item in bom["declarations"]["attestations"][0]["map"]}
    assert mapped == {"req-I.2.f", "req-I.2.l", "req-II.1", "req-II.7"}
    assert len(bom["definitions"]["standards"][0]["requirements"]) == 22
    results = emit.emit_oscal_ar(records, now=FIXED_NOW, standard="eu_cra_annex_i",
                                 not_assessed=not_assessed)["assessment-results"]["results"][0]
    reviewed = results["reviewed-controls"]["control-selections"][0]["include-controls"]
    assert [item["control-id"] for item in reviewed] == ["control-I.2.f", "control-I.2.l", "control-II.1", "control-II.7"]
    assert "I.2.a No known exploitable vulnerabilities" in results["remarks"]


def test_a_partial_objective_names_what_it_does_not_reach(deployed):
    records = delivery.assess_deployment(str(deployed), now=FIXED_NOW)["standards"]["eu_cra_annex_i"]["records"]
    sbom_record = next(item for item in records if item["control_id"] == "II.1")
    assert sbom_record["unmet_objective_ids"] == ["II.1[a]"]
    assert "not reached: identifying and documenting vulnerabilities" in sbom_record["gap_summary"]
    assert sbom_record["manifest"]["gate_id"] == delivery.ASSESSOR_ID


def test_a_consistent_activation_receipt_supports_and_does_not_change_the_statuses(deployed):
    _write_activation(deployed)
    summary = delivery.assess_deployment(str(deployed), now=FIXED_NOW)
    assert summary["checks"]["activation_consistent"]["ok"] is True
    assert _assessed(summary) == EXPECTED


# ---------------- each check bites ----------------
def test_an_activation_receipt_that_disagrees_fails_the_requirements_resting_on_it(deployed):
    _write_activation(deployed, in_kernel_path="start -> cold -> end")
    assessed = _assessed(delivery.assess_deployment(str(deployed), now=FIXED_NOW))
    assert assessed["nist_ssdf"]["PW.4"] == "not-met"
    assert assessed["eu_cra_annex_i"]["I.2.f"] == "not-met" and assessed["eu_cra_annex_i"]["II.7"] == "not-met"
    assert assessed["eu_cra_annex_i"]["II.1"] == "partially-met"      # the SBOM does not rest on activation


def test_an_sbom_for_another_image_fails_only_the_sbom_requirements(deployed):
    sbom_path = deployed / delivery.SBOM_NAME
    sbom = json.loads(sbom_path.read_text())
    sbom["metadata"]["component"]["hashes"][0]["content"] = "0" * 64
    sbom_path.write_text(json.dumps(sbom))
    assessed = _assessed(delivery.assess_deployment(str(deployed), now=FIXED_NOW))
    assert assessed["nist_ssdf"] == {"PS.2": "met", "PS.3": "not-met", "PW.4": "partially-met"}
    assert assessed["eu_cra_annex_i"]["II.1"] == "not-met" and assessed["eu_cra_annex_i"]["II.7"] == "partially-met"


def test_a_tampered_delivered_image_fails_every_assessed_requirement(deployed):
    image_path = deployed / delivery.PACK_NAME
    image = bytearray(image_path.read_bytes())
    image[len(image) // 2] ^= 0xFF
    image_path.write_bytes(bytes(image))
    summary = delivery.assess_deployment(str(deployed), now=FIXED_NOW)
    assert summary["checks"]["pack_verifies"]["ok"] is False
    for assessed in _assessed(summary).values():
        assert set(assessed.values()) == {"not-met"}


def test_a_host_whose_stored_image_was_replaced_does_not_attest_the_pack(deployed):
    (deployed / delivery.STATE_DIR_NAME / "active.ppt").write_bytes(b"not the verified image")
    summary = delivery.assess_deployment(str(deployed), now=FIXED_NOW)
    assert summary["checks"]["host_attests_pack"]["ok"] is False
    assert _assessed(summary)["eu_cra_annex_i"]["I.2.f"] == "not-met"


def test_an_unreadable_audit_log_fails_the_recording_requirement(deployed):
    with open(deployed / delivery.STATE_DIR_NAME / "swaps.log", "a") as log_file:
        log_file.write("{not json\n")
    summary = delivery.assess_deployment(str(deployed), now=FIXED_NOW)
    assert summary["checks"]["audit_trail_intact"]["ok"] is False
    assert _assessed(summary)["eu_cra_annex_i"]["I.2.l"] == "not-met"


# ---------------- the emitter's standard parameter ----------------
def test_the_default_standard_is_still_nist_800_171_rev_2():
    bom = emit.emit_cyclonedx([record("3.1.1")], now=FIXED_NOW)
    assert bom["definitions"]["standards"][0]["bom-ref"] == "std-nist-800-171-r2"
    results = emit.emit_oscal_ar([record("3.1.1")], now=FIXED_NOW)["assessment-results"]["results"][0]
    assert results["reviewed-controls"] == {"control-selections": [{"include-all": {}}]} and "remarks" not in results


def test_an_unknown_standard_is_refused():
    with pytest.raises(KeyError):
        emit.emit_cyclonedx([record("3.1.1")], now=FIXED_NOW, standard="iso_27001")
