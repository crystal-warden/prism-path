# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The SSP generator renders the master 800-171 document: system sections from the org profile, and the
control-implementation section from the live assessment (status per verdict, responsible role, governing
policy). Blank profile + no verdicts = the reusable template; a filled profile + real verdicts = the
organization's SSP, consistent with the actual posture."""
import compliance_adapter as ca
import ssp_generator as ssp


def test_template_ssp_is_blank_and_complete():
    m = ssp.generate_ssp()
    md = m["markdown"]
    assert m["controls"] == 110
    for s in ("System Identification", "System Environment", "Control Implementation", "Related Documents"):
        assert s in md
    assert md.count("\n| 3.") >= 100          # one control-implementation row per requirement
    assert "[TODO:" in md                      # unfilled fields are visible TODOs
    assert "Crystal Warden" not in md          # the template is organization-agnostic


def test_instance_ssp_fills_profile_and_maps_status():
    ca.use_standard("nist_800171_r2")
    allc = ca._catalog()["controls"]
    verdicts = {c: ("met" if c == "3.13.16" else "insufficient") for c in allc}   # FileVault met, rest open
    m = ssp.generate_ssp({"org_name": "Crystal Warden Supply Chain Labs LLC",
                          "system_name": "Crystal Warden CUI enclave (company Mac)",
                          "sprs_score": "-119"}, verdicts)
    md = m["markdown"]
    assert "Crystal Warden Supply Chain Labs LLC" in md and "-119" in md
    assert "Implemented" in md and "Planned (POA&M)" in md        # status mapped from the verdicts
    assert m["status_tally"].get("met") == 1
