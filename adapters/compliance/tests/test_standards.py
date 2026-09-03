"""Dual-catalog coverage: the engine is catalog-agnostic and the assessor selects the standard.
Rev 2 (CMMC's current basis, SPRS-scored) and Rev 3 (NIST's current official, not SPRS-scored)."""
import pytest
import compliance_adapter as ca
from sample import record


def test_list_standards_shows_both_revisions():
    st = ca.list_standards()
    assert st["nist_800171_r2"]["controls"] == 110 and st["nist_800171_r2"]["families"] == 14
    assert st["nist_800171_r3"]["controls"] == 130 and st["nist_800171_r3"]["families"] == 17


def test_use_unknown_standard_raises():
    with pytest.raises(KeyError):
        ca.use_standard("iso_27001")


def test_r2_full_breadth_and_weights():
    ca.use_standard("nist_800171_r2")
    cat = ca._catalog()["controls"]
    assert len(cat) == 110
    assert all("dod_am_weight" in c for c in cat.values())      # every control DoD-weighted
    assert len(ca.catalog_weights()) == 110
    fams = {c["family"] for c in cat.values()}
    assert len(fams) == 14


def test_r3_full_breadth_no_sprs_has_odps():
    ca.use_standard("nist_800171_r3")
    cat = ca._catalog()["controls"]
    assert len(cat) == 130
    assert ca.catalog_weights() == {}                           # Rev 3 is not SPRS-scored
    assert any(c.get("odps") for c in cat.values())             # Rev 3 carries ODPs
    fams = {c["family"] for c in cat.values()}
    assert len(fams) == 17


def test_control_resolves_per_standard():
    ca.use_standard("nist_800171_r2")
    assert ca.get_control("3.1.5")["title"] == "Employ the principle of least privilege"
    ca.use_standard("nist_800171_r3")
    assert ca.get_control("3.1.1")["title"] == "Account Management"   # Rev 3 renumbered/restructured


def test_catalog_hash_differs_by_standard():
    ca.use_standard("nist_800171_r2"); h2 = ca.catalog_hash()
    ca.use_standard("nist_800171_r3"); h3 = ca.catalog_hash()
    assert h2 != h3


def test_r3_rollup_marks_sprs_not_applicable(tmp_path):
    ca.use_standard("nist_800171_r3")
    recs = [record("3.1.1", "Account Management", "not-met", ["3.1.1[b.01]"]),
            record("3.1.2", "Access Enforcement", "met")]
    out = ca.rollup_report(recs, {"boundary": "enclave"}, out_dir=str(tmp_path), fmt="oscal")
    assert out["sprs"].get("applicable") is False
    assert "Rev 2" in out["sprs"]["reason"]
    for name, r in out["emitted"].items():
        assert r["valid"], (name, r)


def test_r2_rollup_scores_sprs(tmp_path):
    ca.use_standard("nist_800171_r2")
    recs = [record("3.1.1", "C", "not-met", ["3.1.1[a]"]),   # weight 5
            record("3.1.5", "C", "met")]                     # weight 3, met -> no deduction
    out = ca.rollup_report(recs, {"boundary": "enclave"}, out_dir=str(tmp_path), fmt="oscal")
    assert out["sprs"]["deducted_points"] == 5
