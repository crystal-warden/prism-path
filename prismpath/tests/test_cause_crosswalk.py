# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The cause crosswalk referee (docs/standards/cause-crosswalk.json).

Every cause in the registry must have a crosswalk entry, and every id an entry names must be in the
pinned list for that taxonomy version (docs/standards/taxonomies/). So a cause appended to
prismpath/kernel/causes.py fails this test until someone maps it, or writes down why it has no
mapping. Each of the three taxonomies is either mapped with a rationale or marked none with a reason.
Nothing here reaches the network: moving to a newer taxonomy version means replacing the pinned file
and reviewing the entries, in one commit."""
import json
from pathlib import Path

import pytest

from prismpath.kernel import causes

REPO = Path(__file__).resolve().parents[2]
STANDARDS = REPO / "docs" / "standards"
TAXONOMIES = ("owasp_asi", "mitre_atlas", "cwe")
KINDS = ("security-control", "routing", "internal")


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


CROSSWALK = _load(STANDARDS / "cause-crosswalk.json")
ENTRIES = CROSSWALK["entries"]
PINNED = {key: _load(REPO / meta["pinned"]) for key, meta in CROSSWALK["_meta"]["taxonomies"].items()}


def test_every_registered_cause_has_an_entry():
    unmapped = sorted(code for code in causes.CODES if str(code) not in ENTRIES)
    assert not unmapped, (
        "causes %s are registered in prismpath/kernel/causes.py but have no entry in "
        "docs/standards/cause-crosswalk.json; map each to OWASP ASI, MITRE ATLAS and CWE ids, or write a "
        "none with its reason" % [(code, causes.name(code)) for code in unmapped])


def test_no_entry_for_an_unregistered_cause():
    stale = sorted(code for code in ENTRIES if int(code) not in causes.CODES)
    assert not stale, "crosswalk entries %s name no registered cause" % stale


def test_entry_name_and_class_match_the_registry():
    for code, entry in ENTRIES.items():
        registered_name, registered_class, _description = causes.CODES[int(code)]
        assert entry["name"] == registered_name, code
        assert entry["class"] == registered_class, code
        assert entry["kind"] in KINDS, code


def test_taxonomies_are_pinned_at_the_stated_version():
    assert set(CROSSWALK["_meta"]["taxonomies"]) == set(TAXONOMIES)
    for key, meta in CROSSWALK["_meta"]["taxonomies"].items():
        pinned = PINNED[key]
        assert pinned["version"] == meta["version"], key
        assert pinned["released"] == meta["released"], key
        assert pinned["source"] and pinned["checked"], key
        assert pinned["ids"], key


def test_every_referenced_id_is_in_the_pinned_list():
    for code, entry in ENTRIES.items():
        for key in TAXONOMIES:
            for taxonomy_id in entry[key]["ids"]:
                assert taxonomy_id in PINNED[key]["ids"], "cause %s names %s, not in %s %s" % (
                    code, taxonomy_id, key, PINNED[key]["version"])


def test_each_taxonomy_is_mapped_with_a_rationale_or_none_with_a_reason():
    for code, entry in ENTRIES.items():
        for key in TAXONOMIES:
            mapping = entry[key]
            assert set(mapping) in ({"ids", "rationale"}, {"ids", "none"}), (code, key)
            ids = mapping["ids"]
            assert len(ids) == len(set(ids)), (code, key)
            if ids:
                assert "none" not in mapping and mapping["rationale"].strip(), (code, key)
            else:
                assert "rationale" not in mapping and mapping["none"].strip(), (code, key)


def test_the_pinned_lists_are_not_hollow():
    assert len(PINNED["owasp_asi"]["ids"]) == 10 and sorted(PINNED["owasp_asi"]["ids"]) == ["ASI%02d" % n for n in range(1, 11)]
    assert all(taxonomy_id.startswith("AML.T") for taxonomy_id in PINNED["mitre_atlas"]["ids"])
    assert all(taxonomy_id.startswith("CWE-") for taxonomy_id in PINNED["cwe"]["ids"])
    assert "AML.T0053" in PINNED["mitre_atlas"]["ids"] and "CWE-22" in PINNED["cwe"]["ids"]


def test_an_unmapped_new_cause_would_fail():
    """The point of the referee, shown on a synthetic append: a registry row with no entry is reported."""
    extended = dict(causes.CODES)
    extended[999] = ("future:cause", "routing", "a cause appended without a mapping")
    unmapped = sorted(code for code in extended if str(code) not in ENTRIES)
    assert unmapped == [999]
