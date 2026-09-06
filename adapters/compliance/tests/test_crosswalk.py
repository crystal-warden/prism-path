# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The crosswalk engine propagates one framework's verdicts to another from authoritative mapping data,
fail closed: a target is met only when every mapped source is met, a single not-met makes it not-met, and
a missing verdict makes it insufficient. Partial crosswalks report only what they map, so coverage is
visible instead of silently assumed complete."""
import pytest
import crosswalk as cw


def test_combine_is_fail_closed():
    assert cw._combine(["met", "met"]) == "met"
    assert cw._combine(["met", "not-met"]) == "not-met"
    assert cw._combine(["met", "insufficient"]) == "insufficient"
    assert cw._combine(["met", None]) == "insufficient"        # a missing source verdict is unproven
    assert cw._combine([]) == "insufficient"


def test_crosswalks_present_and_load():
    names = cw.list_crosswalks()
    assert {"nist_800171_r2__cmmc", "nist_800171_r2__nist_800_53_r5"} <= set(names)
    x = cw.load_crosswalk("nist_800171_r2__cmmc")
    assert x["a"] == "nist_800171_r2" and x["b"] == "cmmc" and x["edges"]


def test_cmmc_crosswalk_complete_and_translates_ids():
    x = cw.load_crosswalk("nist_800171_r2__cmmc")
    cov = cw.coverage(x)
    assert cov["complete"] is True and cov["a_controls_mapped"] == 110
    rep = cw.propagate(x, "nist_800171_r2", {"3.1.1": "met", "3.1.3": "not-met"})
    assert rep["target_framework"] == "cmmc"
    assert rep["controls"]["AC.L1-3.1.1"]["verdict"] == "met"    # 3.1.1 is an L1 practice
    assert rep["controls"]["AC.L2-3.1.3"]["verdict"] == "not-met"  # 3.1.3 is L2


def test_800_53_is_the_authoritative_nist_table_and_fail_closed():
    x = cw.load_crosswalk("nist_800171_r2__nist_800_53_r5")
    assert cw.coverage(x)["complete"] is True                   # the NIST CPRT authoritative mapping
    empty = cw.propagate(x, "nist_800171_r2", {})
    multi = next(t for t, v in empty["controls"].items() if len(v["from"]) >= 2)   # a target with 2+ sources
    srcs = empty["controls"][multi]["from"]
    all_met = cw.propagate(x, "nist_800171_r2", {s: "met" for s in srcs})
    assert all_met["controls"][multi]["verdict"] == "met"
    one_bad = cw.propagate(x, "nist_800171_r2", dict({s: "met" for s in srcs}, **{srcs[0]: "not-met"}))
    assert one_bad["controls"][multi]["verdict"] == "not-met"
    assert empty["controls"][multi]["verdict"] == "insufficient"   # missing evidence fails closed


def test_reverse_direction_and_unknown_framework_raises():
    x = cw.load_crosswalk("nist_800171_r2__nist_800_53_r5")
    single = next(e for e in x["edges"] if len(e["b"]) == 1)     # an a -> single-b edge
    rev = cw.propagate(x, "nist_800_53_r5", {single["b"][0]: "met"})
    assert rev["target_framework"] == "nist_800171_r2"
    assert rev["controls"][single["a"]]["verdict"] == "met"
    with pytest.raises(ValueError):
        cw.propagate(x, "iso_27001", {"a.5.1": "met"})


def test_ai_governance_crosswalk_maps_to_ai_rmf():
    import compliance_adapter as ca
    ca.use_standard("ai_governance")
    aig = set(ca._catalog()["controls"])
    ca.use_standard("nist_800171_r2")
    x = cw.load_crosswalk("ai_governance__nist_ai_rmf")
    assert x["a"] == "ai_governance" and x["b"] == "nist_ai_rmf"
    assert all(e["a"] in aig for e in x["edges"])              # every source is a real AI-GOV control
    rep = cw.propagate(x, "ai_governance", {"MP-1": "met"})
    assert rep["target_framework"] == "nist_ai_rmf"
    assert rep["controls"]["GOVERN 1.6"]["verdict"] == "met"   # MP-1 (AI inventory) -> AI RMF GOVERN 1.6


def test_every_source_id_in_the_800171_crosswalks_is_a_real_control():
    import compliance_adapter as ca
    ca.use_standard("nist_800171_r2")
    allc = set(ca._catalog()["controls"])
    for name in ("nist_800171_r2__cmmc", "nist_800171_r2__nist_800_53_r5"):
        x = cw.load_crosswalk(name)
        bad = [e["a"] for e in x["edges"] if e["a"] not in allc]
        assert bad == [], "%s references non-existent controls: %s" % (name, bad)
