# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""SOC 2 is registered as its own standard (the Common Criteria) and, more usefully, is reachable from
an 800-171 assessment through a curated crosswalk: a SOC 2 criterion is reported met only when every
mapped 800-171 control is met (fail closed). The crosswalk is a labeled subset, and every id on both
sides is real."""
import compliance_adapter as ca
import crosswalk as cw
import multi_framework as mf


def test_soc2_is_a_registered_standard():
    assert "soc2_tsc" in ca.list_standards()
    ca.use_standard("soc2_tsc")
    cat = ca._catalog()
    assert cat["_meta"]["controls"] == 33 and len(cat["families"]) == 9
    assert "CC6.1" in cat["controls"] and cat["controls"]["CC6.1"]["family"] == "CC6"
    ca.use_standard("nist_800171_r2")


def test_soc2_crosswalk_ids_are_all_real():
    ca.use_standard("nist_800171_r2")
    src = set(ca._catalog()["controls"])
    ca.use_standard("soc2_tsc")
    tgt = set(ca._catalog()["controls"])
    ca.use_standard("nist_800171_r2")
    x = cw.load_crosswalk("nist_800171_r2__soc2_tsc")
    assert cw.coverage(x)["complete"] is False
    bad_src = [e["a"] for e in x["edges"] if e["a"] not in src]
    bad_tgt = [b for e in x["edges"] for b in e["b"] if b not in tgt]
    assert bad_src == [] and bad_tgt == []


def test_soc2_criterion_is_fail_closed_over_its_800171_sources():
    x = cw.load_crosswalk("nist_800171_r2__soc2_tsc")
    # CC6.1 is fed by 3.1.1, 3.5.1, 3.5.3 -> met only when all three are met
    met = cw.propagate(x, "nist_800171_r2", {"3.1.1": "met", "3.5.1": "met", "3.5.3": "met"})
    assert met["controls"]["CC6.1"]["verdict"] == "met"
    one_bad = cw.propagate(x, "nist_800171_r2", {"3.1.1": "met", "3.5.1": "not-met", "3.5.3": "met"})
    assert one_bad["controls"]["CC6.1"]["verdict"] == "not-met"


def test_multi_framework_now_reaches_soc2():
    r = mf.demo()
    reached = {f["framework"] for f in r["frameworks_reached"]}
    assert "soc2_tsc" in reached
