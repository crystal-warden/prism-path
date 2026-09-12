# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The SSP generator renders the master 800-171 document: system sections from the org profile, and the
control-implementation section from the live assessment (status per verdict, responsible role, governing
policy). Blank profile + no verdicts = the reusable template; a filled profile + real verdicts = the
organization's SSP, consistent with the actual posture."""
from adapters.compliance import compliance_adapter as ca
from adapters.compliance import ssp_generator as ssp


def test_template_ssp_is_blank_and_complete():
    ssp_result = ssp.generate_ssp()
    md = ssp_result["markdown"]
    assert ssp_result["controls"] == 110
    for heading in ("System Identification", "System Environment", "Control Implementation", "Related Documents"):
        assert heading in md
    assert md.count("\n| 3.") >= 100          # one control-implementation row per requirement
    assert "[TODO:" in md                      # unfilled fields are visible TODOs
    assert "Crystal Warden" not in md          # the template is organization-agnostic


def test_instance_ssp_fills_profile_and_maps_status():
    ca.use_standard("nist_800171_r2")
    allc = ca._catalog()["controls"]
    verdicts = {control_id: ("met" if control_id == "3.13.16" else "insufficient") for control_id in allc}   # FileVault met, rest open
    ssp_result = ssp.generate_ssp({"org_name": "Crystal Warden Supply Chain Labs LLC",
                                   "system_name": "Crystal Warden CUI enclave (company Mac)",
                                   "sprs_score": "-119"}, verdicts)
    md = ssp_result["markdown"]
    assert "Crystal Warden Supply Chain Labs LLC" in md and "-119" in md
    assert "Implemented" in md and "Planned (POA&M)" in md        # status mapped from the verdicts
    assert ssp_result["status_tally"].get("met") == 1
