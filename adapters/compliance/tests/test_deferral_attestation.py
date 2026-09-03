"""Adversarial tests for the core primitives that carry the whole value proposition:
the Flow-Ledger attestation (tamper-evidence, provable override chain) and the Deferral store.
If these pass, 'attestable' is a claim the bytes actually support."""
import hashlib
import pytest
from prismpath import ledger_airgap, deferral


def mk(root="a" * 64, **kw):
    d = dict(root_hex=root, label="assess:x", policy_hash="sha256:pol", gate_id="gate@v0",
             ingestion_hashes=["sha256:in"], knowledge_base_hash="sha256:kb")
    d.update(kw)
    return ledger_airgap.provenance_manifest(**d)


# ================= provenance manifest =================
def test_manifest_is_deterministic():
    assert mk()["manifest_hash"] == mk()["manifest_hash"]


def test_manifest_verifies():
    assert ledger_airgap.verify_manifest(mk())


@pytest.mark.parametrize("field,newval", [
    ("root", "b" * 64), ("policy_hash", "sha256:evil"), ("gate_id", "other@v9"),
    ("knowledge_base_hash", "sha256:swapped"), ("label", "assess:tampered"),
])
def test_tamper_any_bound_field_detected(field, newval):
    m = mk()
    m[field] = newval
    assert not ledger_airgap.verify_manifest(m)


def test_tamper_ingestion_hash_detected():
    m = mk()
    m["ingestion_hashes"] = ["sha256:different"]
    assert not ledger_airgap.verify_manifest(m)


def test_distinct_inputs_distinct_hash():
    assert mk(root="a" * 64)["manifest_hash"] != mk(root="c" * 64)["manifest_hash"]


# ================= override chain =================
def test_override_supersedes_prior():
    prior = mk()
    ov = ledger_airgap.override_manifest(prior, overrider_id="auditor:jsmith",
                                         rationale="compensating control", new_root_hex="d" * 64)
    assert ov["supersedes"] == prior["manifest_hash"]


def test_override_preserves_prior_root_and_actor():
    prior = mk(root="e" * 64)
    ov = ledger_airgap.override_manifest(prior, overrider_id="auditor:jsmith",
                                         rationale="why", new_root_hex="d" * 64)
    assert ov["prior_root"] == prior["root"]
    assert ov["overrider_id"] == "auditor:jsmith" and ov["rationale"] == "why"


def test_override_new_root_differs_from_prior():
    prior = mk()
    ov = ledger_airgap.override_manifest(prior, overrider_id="a", rationale="r", new_root_hex="f" * 64)
    assert ov["root"] == "f" * 64 and ov["root"] != prior["root"]


def test_override_verifies():
    ov = ledger_airgap.override_manifest(mk(), overrider_id="a", rationale="r", new_root_hex="f" * 64)
    assert ledger_airgap.verify_manifest(ov)


def test_cannot_repoint_supersedes_without_detection():
    """Adversary tries to silently re-point the override at a different prior decision."""
    ov = ledger_airgap.override_manifest(mk(), overrider_id="a", rationale="r", new_root_hex="f" * 64)
    ov["supersedes"] = hashlib.sha256(b"forged-prior").hexdigest()
    assert not ledger_airgap.verify_manifest(ov)


def test_cannot_rewrite_rationale_without_detection():
    ov = ledger_airgap.override_manifest(mk(), overrider_id="a", rationale="original reason",
                                         new_root_hex="f" * 64)
    ov["rationale"] = "a different reason"
    assert not ledger_airgap.verify_manifest(ov)


def test_override_of_override_chains():
    prior = mk()
    ov1 = ledger_airgap.override_manifest(prior, overrider_id="a", rationale="r1", new_root_hex="1" * 64)
    ov2 = ledger_airgap.override_manifest(ov1, overrider_id="b", rationale="r2", new_root_hex="2" * 64)
    assert ov2["supersedes"] == ov1["manifest_hash"] and ov2["prior_root"] == ov1["root"]


# ================= deferral store =================
def store(tmp_path):
    return deferral.FileDeferralStore(str(tmp_path / "d"))


def test_defer_then_in_pending(tmp_path):
    s = store(tmp_path)
    s.defer("u1", reason="r", state={"k": "v"})
    assert "u1" in [p["unit_id"] for p in s.pending()]


def test_get_unknown_returns_none(tmp_path):
    assert store(tmp_path).get("nope") is None


def test_resume_records_actor_and_resolution(tmp_path):
    s = store(tmp_path)
    s.defer("u1", reason="r", state={})
    rec = s.resume("u1", resolution={"status": "met"}, actor="auditor:jsmith")
    assert rec["actor"] == "auditor:jsmith" and rec["resolution"]["status"] == "met"


def test_resume_unknown_raises(tmp_path):
    with pytest.raises(KeyError):
        store(tmp_path).resume("ghost", resolution={}, actor="a")


def test_double_resume_raises(tmp_path):
    s = store(tmp_path)
    s.defer("u1", reason="r", state={})
    s.resume("u1", resolution={}, actor="a")
    with pytest.raises(ValueError):
        s.resume("u1", resolution={}, actor="b")


def test_prior_output_preserved(tmp_path):
    s = store(tmp_path)
    s.defer("u1", reason="r", state={}, prior_output={"determination": {"status": "not-met"}})
    s.resume("u1", resolution={}, actor="a")
    assert s.get("u1")["prior_output"]["determination"]["status"] == "not-met"


def test_resume_removes_from_pending(tmp_path):
    s = store(tmp_path)
    s.defer("u1", reason="r", state={})
    s.resume("u1", resolution={}, actor="a")
    assert "u1" not in [p["unit_id"] for p in s.pending()]


def test_persistence_across_store_instances(tmp_path):
    s1 = store(tmp_path)
    s1.defer("u1", reason="r", state={"k": "v"})
    s2 = deferral.FileDeferralStore(str(tmp_path / "d"))         # fresh instance, same dir
    assert s2.get("u1")["state"]["k"] == "v"                     # durable on disk
