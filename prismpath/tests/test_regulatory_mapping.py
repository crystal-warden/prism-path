# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The regulatory mapping referee (docs/standards/crosswalks/).

The crosswalks map the evidence PrismPath produces onto provisions and controls. Every evidence id and
every target id must be in a pinned list, every edge must say what it does not satisfy, and every edge
that maps must say why. When the research repository's compliance adapter is present, the edges that
reuse its AI governance controls must repeat everything its AI RMF crosswalk reaches from them."""
import json
from pathlib import Path

from prismpath.tests._repo import repo_file

REPO = Path(__file__).resolve().parents[2]
STANDARDS = repo_file("docs", "standards")
TARGETS = {"eu_ai_act": "eu_ai_act", "nist_ai_rmf": "nist_ai_rmf", "nist_ai_600_1": "nist_ai_600_1", "nist_800_53_r5": "nist_800_53_r5"}


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


EVIDENCE = _load(STANDARDS / "taxonomies" / "evidence_items.json")


def _crosswalk(target):
    return _load(STANDARDS / "crosswalks" / ("prismpath_evidence__%s.json" % target))


def test_each_crosswalk_uses_the_adapter_shape_and_pinned_ids():
    for target, pinned_name in TARGETS.items():
        crosswalk = _crosswalk(target)
        pinned = _load(STANDARDS / "taxonomies" / (pinned_name + ".json"))
        assert crosswalk["id"] == "prismpath_evidence__" + target
        assert crosswalk["a"] == "prismpath_evidence" and crosswalk["b"] == target
        assert crosswalk["complete"] is False and crosswalk["authority"].strip()
        assert crosswalk["edges"]
        seen = set()
        for edge in crosswalk["edges"]:
            assert edge["a"] in EVIDENCE["ids"], (target, edge["a"])
            assert edge["a"] not in seen, (target, edge["a"])
            seen.add(edge["a"])
            assert edge["does_not_satisfy"].strip(), (target, edge["a"])
            for control in edge["b"]:
                assert control in pinned["ids"], (target, edge["a"], control)
            if edge["b"]:
                assert edge["rationale"].strip() and "none" not in edge, (target, edge["a"])
            else:
                assert edge["none"].strip() and "rationale" not in edge, (target, edge["a"])


def test_the_two_full_crosswalks_place_every_evidence_item():
    assert {edge["a"] for edge in _crosswalk("eu_ai_act")["edges"]} == set(EVIDENCE["ids"])
    assert {edge["a"] for edge in _crosswalk("nist_800_53_r5")["edges"]} == set(EVIDENCE["ids"])


def test_eu_dates_are_the_omnibus_dates():
    crosswalk = _crosswalk("eu_ai_act")
    assert crosswalk["application"]["annex_iii_systems"] == "2027-12-02"
    assert crosswalk["application"]["annex_i_systems"] == "2028-08-02"
    pinned = _load(STANDARDS / "taxonomies" / "eu_ai_act.json")
    assert pinned["application"]["annex_iii_high_risk_chapter_iii_sections_1_to_3"] == "2027-12-02"
    assert pinned["application"]["annex_i_high_risk_chapter_iii_sections_1_to_3"] == "2028-08-02"


def test_the_ai_rmf_crosswalk_repeats_what_the_adapter_reaches():
    adapter = REPO / "adapters" / "compliance" / "crosswalks" / "ai_governance__nist_ai_rmf.json"
    if not adapter.exists():
        return          # the product repository does not carry the adapter
    reach = {}
    for edge in _load(adapter)["edges"]:
        reach[edge["a"]] = set(edge["b"])
    for edge in _crosswalk("nist_ai_rmf")["edges"]:
        for control in edge.get("via_ai_governance", []):
            assert control in reach, control
            assert reach[control] <= set(edge["b"]), (edge["a"], control, sorted(reach[control] - set(edge["b"])))
