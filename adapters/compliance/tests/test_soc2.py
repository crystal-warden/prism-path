# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""SOC 2 is registered as its own standard (the Common Criteria) and, more usefully, is reachable from
an 800-171 assessment through a curated crosswalk: a SOC 2 criterion is reported met only when every
mapped 800-171 control is met (fail closed). The crosswalk is a labeled subset, and every id on both
sides is real."""
from adapters.compliance import compliance_adapter as ca
from adapters.compliance import crosswalk as cw
from adapters.compliance import multi_framework as mf


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
    crosswalk = cw.load_crosswalk("nist_800171_r2__soc2_tsc")
    assert cw.coverage(crosswalk)["complete"] is False
    bad_src = [edge["a"] for edge in crosswalk["edges"] if edge["a"] not in src]
    bad_tgt = [target_control for edge in crosswalk["edges"] for target_control in edge["b"] if target_control not in tgt]
    assert bad_src == [] and bad_tgt == []


def test_soc2_criterion_is_fail_closed_over_its_800171_sources():
    crosswalk = cw.load_crosswalk("nist_800171_r2__soc2_tsc")
    empty = cw.propagate(crosswalk, "nist_800171_r2", {})
    # a criterion with 2+ sources
    multi = next(target_control for target_control, propagated in empty["controls"].items()
                 if len(propagated["from"]) >= 2)
    srcs = empty["controls"][multi]["from"]
    all_met = cw.propagate(crosswalk, "nist_800171_r2", {source_control: "met" for source_control in srcs})
    assert all_met["controls"][multi]["verdict"] == "met"
    one_bad = cw.propagate(crosswalk, "nist_800171_r2", dict({source_control: "met" for source_control in srcs}, **{srcs[0]: "not-met"}))
    assert one_bad["controls"][multi]["verdict"] == "not-met"


def test_multi_framework_now_reaches_soc2():
    posture = mf.demo()
    reached = {framework["framework"] for framework in posture["frameworks_reached"]}
    assert "soc2_tsc" in reached
