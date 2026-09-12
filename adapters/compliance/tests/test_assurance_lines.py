# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Integrated assurance across the three lines of defense: one signed determination per control serves the
first, second, and third lines and the governing body, instead of each line re-testing. The third line
verifies the signed receipt rather than re-testing, so independence is preserved without duplication."""
from adapters.compliance import compliance_adapter as ca
from adapters.compliance import assurance_lines as al


def test_summary_quantifies_the_deduplication():
    summary = al.assurance_summary(110, 110)
    assert summary["traditional_line_assessments"] == 330 and summary["integrated_assessments"] == 110
    assert summary["assessments_deduplicated"] == 220 and summary["reduction"] == "67%"


def test_one_determination_serves_all_four_lines():
    ca.use_standard("nist_800171_r2")
    assurance = al.assurance_for_control("3.1.1", "met", signed=True)
    lines = {ln["line"]: ln for ln in assurance["lines"]}
    assert set(lines) == {"first_line", "second_line", "third_line", "governing_body"}
    assert lines["first_line"]["owner"]                                  # first line has the named owner
    assert "verifies the signed" in lines["third_line"]["responsibility"]   # audit checks the receipt, no re-test


def test_without_a_signed_receipt_the_third_line_must_retest():
    ca.use_standard("nist_800171_r2")
    assurance = al.assurance_for_control("3.1.1", "met", signed=False)
    assert "re-test" in assurance["lines"][2]["responsibility"]


def test_demo_and_render():
    txt = al.render_text(al.demo())
    assert "Three-lines-of-defense" in txt and "First Line" in txt
    ca.use_standard("nist_800171_r2")
