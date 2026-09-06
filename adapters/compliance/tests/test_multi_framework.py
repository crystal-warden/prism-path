# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""One assessment, many frameworks: assess_environment runs the 800-171 determination once and reports
the same verdicts as an 800-171 tally, the CMMC level statuses, and every crosswalked framework. A
framework appears only if a stated-authority mapping reaches it, and partial mappings are labeled."""
import multi_framework as mf


def test_reports_every_reachable_framework_from_one_assessment():
    r = mf.demo()
    assert r["assessed_standard"] == "nist_800171_r2"
    assert r["nist_800171"]["n_controls"] == 110
    assert sum(r["nist_800171"]["tally"].values()) == 110
    # SPRS and FAIR are real rollups of the same verdicts
    assert isinstance(r["sprs"]["score_if_all_assessed"], int)
    assert r["fair"]["aggregate_ale"]["likely"] > 0
    # all three CMMC levels reported; L1 and L2 have a concrete status
    levels = {c["level"]: c for c in r["cmmc"]}
    assert set(levels) == {1, 2, 3}
    assert levels[1]["status"] in ("met", "not-met")
    assert levels[2]["status"] in ("met", "conditional", "not-met")
    # the crosswalked frameworks are reached, each labeled complete/partial
    reached = {f["framework"]: f for f in r["frameworks_reached"]}
    assert "cmmc" in reached and reached["cmmc"]["complete"] is True
    assert "nist_800_53_r5" in reached and reached["nist_800_53_r5"]["complete"] is True   # NIST CPRT table
    assert reached["nist_800_53_r5"]["authority"]                       # provenance carried through


def test_render_text_runs():
    txt = mf.render_text(mf.demo())
    assert "Multi-framework posture" in txt and "CMMC L1" in txt and "nist_800_53_r5" in txt
