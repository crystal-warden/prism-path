# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""CMMC 2.0 levels are deterministic views over the 800-171 engine: L1 is met/not-met over the 17 FAR
practices, L2 is the SPRS-scored 110 with POA&M eligibility, L3 declares its 800-172 dependency rather
than guessing. Insufficient is always scored as not-met (fail closed), never assumed met."""
import compliance_adapter as ca
import cmmc


def _fixed(status_by_id=None, default="met"):
    """A full_determination stand-in that returns a chosen status per control id (default otherwise)."""
    status_by_id = status_by_id or {}
    def f(control, req, completions=None, as_of=None, use_llm=False):
        cid = req.get("control_id") or control.get("id")
        return {"status": status_by_id.get(cid, default), "coverage": {}, "objectives_total": 1,
                "undetermined_objective_ids": [], "unmet_objective_ids": []}
    return f


def setup_function(_):
    ca.use_standard("nist_800171_r2")


def test_level_membership_is_real():
    allc = ca._catalog()["controls"]
    l1 = cmmc.level_controls(1)
    assert len(l1) == 17 and all(c in allc for c in l1)     # every L1 practice exists in the catalog
    assert len(cmmc.level_controls(2)) == 110               # L2 is the full Rev 2 set
    assert cmmc.level_controls(3) is None                   # L3 needs 800-172


def test_all_met_is_clean_at_both_levels(monkeypatch):
    monkeypatch.setattr(cmmc._un, "full_determination", _fixed(default="met"))
    l1 = cmmc.assess_level(1, {"facts": {}})
    l2 = cmmc.assess_level(2, {"facts": {}})
    assert l1["status"] == "met" and l1["practices_met"] == 17 and l1["failing_practices"] == []
    assert l2["status"] == "met" and l2["sprs_score"] == 110 and l2["requirements_met"] == 110
    assert l2["poam"]["eligible"] is True


def test_insufficient_scores_as_not_met(monkeypatch):
    monkeypatch.setattr(cmmc._un, "full_determination", _fixed(default="insufficient"))
    l1 = cmmc.assess_level(1, {"facts": {}})
    l2 = cmmc.assess_level(2, {"facts": {}})
    assert l1["status"] == "not-met" and len(l1["failing_practices"]) == 17
    assert l2["status"] == "not-met"
    assert l2["sprs_score"] < 110                            # deductions applied, not an optimistic ceiling
    assert l2["poam"]["eligible"] is False


def test_open_high_value_control_blocks_poam(monkeypatch):
    # everything met except one requirement worth more than 1 point -> no conditional status
    weights = ca.catalog_weights()
    high = next(c for c, w in weights.items() if w and w > 1)
    monkeypatch.setattr(cmmc._un, "full_determination", _fixed({high: "not-met"}, default="met"))
    l2 = cmmc.assess_level(2, {"facts": {}})
    assert l2["status"] != "met"
    assert high in l2["poam"]["blocking_high_value_controls"]
    assert l2["poam"]["eligible"] is False


def test_only_one_point_open_can_be_conditional(monkeypatch):
    # a single 1-point requirement open, score still >= 88 -> POA&M-eligible conditional status
    weights = ca.catalog_weights()
    one = next(c for c, w in weights.items() if w == 1)
    monkeypatch.setattr(cmmc._un, "full_determination", _fixed({one: "not-met"}, default="met"))
    l2 = cmmc.assess_level(2, {"facts": {}})
    assert l2["poam"]["blocking_high_value_controls"] == []
    assert l2["sprs_score"] >= cmmc.POAM_MIN_SCORE
    assert l2["status"] == "conditional" and l2["poam"]["eligible"] is True


def test_level3_declares_its_dependency():
    l3 = cmmc.assess_level(3, {"facts": {}})
    assert l3["assessable"] is False and l3["depends_on"] == "nist_800172"


def test_assess_combines_levels_and_renders(monkeypatch):
    monkeypatch.setattr(cmmc._un, "full_determination", _fixed(default="met"))
    rep = cmmc.assess({"facts": {}, "boundary": "enclave"})
    assert [lv["level"] for lv in rep["levels"]] == [1, 2, 3]
    txt = cmmc.render_text(rep)
    assert "CMMC 2.0 assessment" in txt and "L1" in txt and "L2" in txt
