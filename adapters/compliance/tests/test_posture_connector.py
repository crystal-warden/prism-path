# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Layer 3: a scanned machine posture grades every control it can fully decide, deterministically,
and defers (never assumes) the rest."""
import json
import compliance_adapter as ca
import deterministic_checks as dc
import posture_connector as pc

CHECKABLE = {
    "3.1.8", "3.1.10", "3.1.11",
    "3.5.3", "3.5.4", "3.5.5", "3.5.6", "3.5.7", "3.5.8", "3.5.9", "3.5.10", "3.5.11",
    "3.13.6", "3.13.7", "3.13.9", "3.13.11", "3.13.16",
    "3.14.4", "3.14.5"
}


def _std():
    ca.use_standard("nist_800171_r2")


def test_machine_checkable_controls_registered():
    _std()
    assert set(pc.machine_checkable_controls()) == CHECKABLE


def test_required_facts_match_the_check_registry():
    _std()
    req = pc.required_facts()
    assert set(req) == CHECKABLE
    assert req["3.5.3"] == sorted(["privileged_accounts_identified", "mfa_local_privileged",
                                   "mfa_network_privileged", "mfa_network_nonprivileged"])
    # every listed fact key is a real check key
    for keys in req.values():
        for k in keys:
            assert k in dc.FACT_KEYS.values()


def test_full_posture_assesses_all_checkable_none_deferred():
    _std()
    posture = pc.load_sample("example_host")
    res = pc.assess(posture)
    assert res["assessed"] == len(CHECKABLE)
    assert res["deferred"] == []
    # the one intentional gap: MFA for network access to non-privileged accounts is off
    assert res["tally"] == {"met": len(CHECKABLE) - 1, "partially-met": 1, "not-met": 0}
    by_id = {r["control_id"]: r for r in res["results"]}
    assert by_id["3.5.3"]["status"] == "partially-met"
    assert by_id["3.5.3"]["unmet_objective_ids"] == ["3.5.3[d]"]
    assert all(r["method"] == "deterministic" for r in res["results"])
    assert res["boundary"] == "warden-node-01 CUI enclave host"
    assert res["provenance"]["source"] == "example-scan"


def test_partial_posture_defers_what_it_cannot_decide():
    _std()
    # only the FIPS and lockout facts present -> only 3.13.11 and 3.1.8 fully decidable
    posture = {"boundary": "partial", "facts": {
        "fips_validated_cryptography": True,
        "account_lockout_threshold": 5, "account_lockout_enforced": True}}
    res = pc.assess(posture)
    assert {r["control_id"] for r in res["results"]} == {"3.13.11", "3.1.8"}
    assert set(res["deferred"]) == CHECKABLE - {"3.13.11", "3.1.8"}
    assert res["tally"]["met"] == 2


def test_empty_posture_defers_everything():
    _std()
    res = pc.assess({"boundary": "empty", "facts": {}})
    assert res["assessed"] == 0
    assert set(res["deferred"]) == CHECKABLE


def test_assess_writes_records(tmp_path):
    _std()
    posture = pc.load_sample("example_host")
    res = pc.assess(posture, out_dir=str(tmp_path))
    written = list(tmp_path.glob("*.json"))
    assert len(written) == res["assessed"]
    # the partially-met control produces a POA&M record
    poams = list(tmp_path.glob("poam_3.5.3.json"))
    assert len(poams) == 1
    rec = json.loads(poams[0].read_text())
    assert rec["status"] == "partially-met"
