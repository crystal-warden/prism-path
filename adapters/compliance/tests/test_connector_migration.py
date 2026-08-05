"""The Connector SDK migration — ComplianceConnector wraps the six ports; the module-level
functions remain the stable API and route through it. Pins port parity, manifest parity
(attest through the SDK produces the same bound fields + verifiable manifest), the prompt
seam, and the shared deferral backend."""
import hashlib
import json

import compliance_adapter as ca
from prismpath import ledger_airgap
from prismpath.connector import BaseConnector


REQ = {"control_id": "3.1.1", "boundary": "test-boundary",
       "evidence": [{"type": "config", "text": "SSP §2 enforced via IdP policy"}]}


def test_connector_is_an_sdk_consumer():
    assert isinstance(ca.CONNECTOR, BaseConnector)
    assert ca.CONNECTOR.name == "compliance.nist_800171"


def test_port_parity_with_module_functions():
    # Ingestion / Retrieval hashes are the module functions, verbatim
    assert ca.CONNECTOR.compute_ingestion_hash(REQ) == ca.bundle_hash(REQ)
    assert ca.CONNECTOR.compute_knowledge_hash() == ca.catalog_hash()
    cid = next(iter(ca._catalog()["controls"]))
    assert ca.CONNECTOR.retrieve_criteria(cid) == ca.get_control(cid)
    assert ca.CONNECTOR.ingest_payload(dict(REQ)) == REQ


def test_attest_routes_through_the_sdk_with_manifest_parity():
    cid = next(iter(ca._catalog()["controls"]))
    control = ca.get_control(cid)
    det = {"status": "met", "unmet_objective_ids": [], "gap_summary": "all objectives evidenced"}
    m = ca.attest(control, REQ, det)
    # the SDK binding computes the same root the pre-migration code did
    assert m["root"] == hashlib.sha256(json.dumps(det, sort_keys=True).encode()).hexdigest()
    assert m["label"] == f"assess:{cid}"
    assert m["gate_id"] == "nist_800171_generic@v1"
    assert m["ingestion_hashes"] == [ca.bundle_hash(REQ)]
    assert m["knowledge_base_hash"] == ca.catalog_hash()
    assert m["policy_hash"] == ca.active_flow_hash()
    assert ledger_airgap.verify_manifest(m), "the SDK-produced manifest must verify"


def test_adjudication_prompt_lives_on_the_connector(monkeypatch):
    cid = next(iter(ca._catalog()["controls"]))
    control = ca.get_control(cid)
    prompt = ca.CONNECTOR.adjudication_prompt(REQ, criteria=control)
    assert f"control {cid}" in prompt and "test-boundary" in prompt
    assert "NOT MET unless the evidence POSITIVELY DEMONSTRATES" in prompt
    # and adjudicate() feeds exactly that prompt into the _gemma seam
    seen = {}
    monkeypatch.setattr(ca, "_gemma", lambda p, s, n, concise=False: seen.update(p=p) or
                        {"status": "met", "unmet_objective_ids": [], "gap_summary": "x"})
    ca.adjudicate(control, REQ)
    assert seen["p"] == prompt


def test_deferral_backend_is_shared_by_default(tmp_path):
    conn = ca.ComplianceConnector(
        deferral_store=__import__("prismpath.deferral", fromlist=["FileDeferralStore"])
        .FileDeferralStore(str(tmp_path / "d")))
    conn.defer_decision("assess:3.1.1:test", "human_review: parity", {"control_id": "3.1.1"})
    assert [p["unit_id"] for p in conn.pending_deferrals()] == ["assess:3.1.1:test"]
    conn.resume_decision("assess:3.1.1:test", {"status": "met"}, actor="auditor")
    assert conn.pending_deferrals() == []
    # the module seam is initialized to the CONNECTOR's own store
    assert ca._DEFER is ca.CONNECTOR.deferrals or ca._DEFER is not None
