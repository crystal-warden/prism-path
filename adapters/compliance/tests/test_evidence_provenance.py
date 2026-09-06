# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Evidence provenance: every deterministic verdict discloses HOW its facts were evidenced
(tool-scanned vs documentation-attested) - the cause-code layer ported from the fabric receipt
(supporting-evidence #129/#130)."""
import compliance_adapter as ca
import deterministic_checks as dc


def _control(cid):
    ca.use_standard("nist_800171_r2")
    return ca.get_control(cid)


def test_scanned_vs_attested_classification():
    ca.use_standard("nist_800171_r2")
    # a tool-verifiable config fact
    assert dc.evidence_class("3.5.3[a]") == "scanned"       # MFA config
    assert dc.evidence_class("3.13.1[c]") == "scanned"      # boundary monitoring (Zeek running)
    # a documentation-backed attestation
    assert dc.evidence_class("3.13.2[a]") == "attested"     # security architecture employed
    assert dc.evidence_class("3.9.2[a]") == "attested"      # personnel action process (documented)
    # no registered check -> no class
    assert dc.evidence_class("3.2.1[a]") is None            # training: not machine-checkable


def test_determination_receipt_carries_evidence_rollup():
    # an all-scanned control
    res = dc.adjudicate_deterministic(_control("3.5.3"), {"facts": {
        "privileged_accounts_identified": True, "mfa_local_privileged": True,
        "mfa_network_privileged": True, "mfa_network_nonprivileged": True}})
    assert res["evidence"]["class"] == "scanned"
    assert set(res["evidence"]["by_class"]) == {"scanned"}

    # an all-attested control
    res = dc.adjudicate_deterministic(_control("3.13.2"), {"facts": {"security_architecture_employed": True}})
    assert res["evidence"]["class"] == "attested"

    # a mixed control: 3.4.6[a] essential_capabilities_defined (attested) + [b] least_functionality_enforced (scanned)
    res = dc.adjudicate_deterministic(_control("3.4.6"), {"facts": {
        "essential_capabilities_defined": True, "least_functionality_enforced": True}})
    assert res["evidence"]["class"] == "mixed"
    assert set(res["evidence"]["by_class"]) == {"scanned", "attested"}


def test_check_objectives_typed_exposes_per_objective_evidence():
    typed = dc.check_objectives_typed(_control("3.4.6"), {
        "essential_capabilities_defined": True, "least_functionality_enforced": True})
    assert typed["3.4.6[a]"] == {"met": True, "evidence": "attested"}
    assert typed["3.4.6[b]"] == {"met": True, "evidence": "scanned"}
