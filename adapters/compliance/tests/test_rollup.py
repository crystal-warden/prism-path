"""Rollup Sink: SPRS scoring math + honesty rails, scope binding, and the tamper property —
the system rollup is bound to the EXACT per-control attestations, so swapping one changes the root."""
import copy
import pytest
import rollup
from prismpath import ledger_airgap
from sample import record

CATALOG_HASH = "sha256:catalogtest"
SCOPE = {"system_name": "Sys", "boundary": "enclave", "assets_sampled": ["a"],
         "sampling_method": "all", "assessor": "auto", "assessment_date": "2026-07-22"}


def _scope():
    return rollup.build_scope(SCOPE)


# ---------------- SPRS scoring ----------------
def test_deductions_sum_weights_of_non_met():
    recs = [record("3.1.1", "C", "met"), record("3.1.5", "C", "not-met"), record("3.1.12", "C", "partially-met")]
    s = rollup.sprs_partial(recs)
    assert s["deducted_points"] == 3 + 5                         # 3.1.5=3, 3.1.12=5 (partial counts)


def test_partial_scored_as_not_met():
    s = rollup.sprs_partial([record("3.1.12", "C", "partially-met")])
    assert s["deducted_points"] == 5                            # full weight deducted, no partial credit


def test_all_met_zero_deduction():
    s = rollup.sprs_partial([record("3.1.1", "C", "met"), record("3.1.5", "C", "met")])
    assert s["deducted_points"] == 0
    assert s["ceiling_if_unassessed_all_met"] == s["base"]


def test_unknown_control_counts_zero_with_note():
    s = rollup.sprs_partial([record("3.9.9", "C", "not-met")])   # not in the weights table
    d = s["deductions"][0]
    assert d["counted"] == 0 and d["note"] and "VERIFY" in d["note"]


def test_ceiling_and_subset_math():
    recs = [record("3.1.1", "C", "met"), record("3.1.5", "C", "not-met"), record("3.1.12", "C", "partially-met")]
    s = rollup.sprs_partial(recs)
    assert s["ceiling_if_unassessed_all_met"] == s["base"] - s["deducted_points"]
    assert s["assessed_subset_max_points"] == 5 + 3 + 5          # weights of 3.1.1,3.1.5,3.1.12
    assert s["assessed_subset_earned_points"] == s["assessed_subset_max_points"] - s["deducted_points"]


def test_caveat_present_and_honest():
    s = rollup.sprs_partial([record("3.1.1", "C", "met")])
    assert "PARTIAL" in s["caveat"] and "not a submittable" in s["caveat"].lower()
    assert "provisional" in s["weights_verification"].lower()


# ---------------- scope hashing ----------------
def test_scope_hash_stable_and_sensitive():
    a = rollup.scope_hash(_scope())
    assert a == rollup.scope_hash(_scope())
    changed = _scope(); changed["boundary"] = "other"
    assert rollup.scope_hash(changed) != a


# ---------------- rollup attestation binding ----------------
def test_rollup_binds_all_control_manifests():
    recs = [record("3.1.1", "C", "met"), record("3.1.5", "C", "not-met")]
    s = rollup.sprs_partial(recs)
    manifest, _ = rollup.system_attestation(recs, s, _scope(), CATALOG_HASH)
    bound = set(manifest["ingestion_hashes"])
    assert bound == {r["manifest"]["manifest_hash"] for r in recs}


def test_rollup_manifest_verifies_and_tamper_detected():
    recs = [record("3.1.5", "C", "not-met")]
    s = rollup.sprs_partial(recs)
    manifest, _ = rollup.system_attestation(recs, s, _scope(), CATALOG_HASH)
    assert ledger_airgap.verify_manifest(manifest)
    manifest["root"] = "0" * 64
    assert not ledger_airgap.verify_manifest(manifest)


def test_root_changes_when_a_control_manifest_is_swapped():
    recs = [record("3.1.1", "C", "met"), record("3.1.5", "C", "not-met")]
    s = rollup.sprs_partial(recs)
    m1, _ = rollup.system_attestation(recs, s, _scope(), CATALOG_HASH)
    tampered = copy.deepcopy(recs)
    tampered[0]["manifest"] = record("3.1.1", "C", "met")["manifest"]  # different root -> different manifest
    tampered[0]["manifest"] = rollup.ledger_airgap.provenance_manifest(
        root_hex="f" * 64, label="assess:3.1.1", policy_hash="sha256:flow", gate_id="gate@v0",
        ingestion_hashes=["sha256:evil"], knowledge_base_hash="sha256:kb")
    m2, _ = rollup.system_attestation(tampered, s, _scope(), CATALOG_HASH)
    assert m1["root"] != m2["root"]                             # rollup is bound to the exact control attestations


def test_scope_change_changes_kb_binding():
    recs = [record("3.1.5", "C", "not-met")]
    s = rollup.sprs_partial(recs)
    m1, _ = rollup.system_attestation(recs, s, _scope(), CATALOG_HASH)
    other = _scope(); other["boundary"] = "different"
    m2, _ = rollup.system_attestation(recs, s, other, CATALOG_HASH)
    assert m1["knowledge_base_hash"] != m2["knowledge_base_hash"]


# ---------------- summary writer ----------------
def test_write_summary(tmp_path):
    recs = [record("3.1.5", "C", "not-met")]
    s = rollup.sprs_partial(recs)
    manifest, summary = rollup.system_attestation(recs, s, _scope(), CATALOG_HASH)
    path = rollup.write_summary(s, _scope(), manifest, summary, str(tmp_path))
    import json
    doc = json.load(open(path))
    assert doc["rollup_attestation"]["manifest_hash"] == manifest["manifest_hash"]
    assert doc["rollup_attestation"]["bound_control_manifests"] == manifest["ingestion_hashes"]
