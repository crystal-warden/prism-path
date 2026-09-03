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


def test_800_53_subset_is_partial_and_propagates_fail_closed():
    x = cw.load_crosswalk("nist_800171_r2__nist_800_53_r5")
    assert cw.coverage(x)["complete"] is False                  # honestly a subset, not the full mapping
    # ac-3 is fed by both 3.1.1 and 3.1.2 -> met only when both are met
    both_met = cw.propagate(x, "nist_800171_r2", {"3.1.1": "met", "3.1.2": "met"})
    assert both_met["controls"]["ac-3"]["verdict"] == "met"
    assert set(both_met["controls"]["ac-3"]["from"]) == {"3.1.1", "3.1.2"}
    one_bad = cw.propagate(x, "nist_800171_r2", {"3.1.1": "not-met", "3.1.2": "met"})
    assert one_bad["controls"]["ac-3"]["verdict"] == "not-met"
    none = cw.propagate(x, "nist_800171_r2", {})
    assert none["controls"]["ac-3"]["verdict"] == "insufficient"


def test_reverse_direction_and_unknown_framework_raises():
    x = cw.load_crosswalk("nist_800171_r2__nist_800_53_r5")
    rev = cw.propagate(x, "nist_800_53_r5", {"sc-13": "met"})
    assert rev["target_framework"] == "nist_800171_r2"
    assert rev["controls"]["3.13.11"]["verdict"] == "met"
    with pytest.raises(ValueError):
        cw.propagate(x, "iso_27001", {"a.5.1": "met"})


def test_every_source_id_in_the_800171_crosswalks_is_a_real_control():
    import compliance_adapter as ca
    ca.use_standard("nist_800171_r2")
    allc = set(ca._catalog()["controls"])
    for name in ("nist_800171_r2__cmmc", "nist_800171_r2__nist_800_53_r5"):
        x = cw.load_crosswalk(name)
        bad = [e["a"] for e in x["edges"] if e["a"] not in allc]
        assert bad == [], "%s references non-existent controls: %s" % (name, bad)
