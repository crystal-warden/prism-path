# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tests for OSCAL catalog import and export interop."""
import json
import os
import pytest
from oscal_catalog import export_oscal, import_oscal


def test_oscal_roundtrip_nist_800171_r2():
    cat_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "catalog")
    r2_path = os.path.join(cat_dir, "nist_800171_r2.json")
    with open(r2_path, "r", encoding="utf-8") as f:
        r2 = json.load(f)

    oscal_dict = export_oscal(r2)
    imported = import_oscal(oscal_dict)

    # Assert every control id is preserved
    assert set(r2["controls"].keys()) == set(imported["controls"].keys())

    # Assert every control statement is preserved
    for cid, original_ctl in r2["controls"].items():
        imported_ctl = imported["controls"][cid]
        assert original_ctl["control"] == imported_ctl["control"], f"Statement mismatch for control {cid}"

    # Assert complete set of objective ids and texts are preserved
    for cid, original_ctl in r2["controls"].items():
        imported_ctl = imported["controls"][cid]
        original_objs = [(o["id"], o["text"]) for o in original_ctl["objectives"]]
        imported_objs = [(o["id"], o["text"]) for o in imported_ctl["objectives"]]
        assert original_objs == imported_objs, f"Objectives mismatch for control {cid}"


def test_import_oscal_handwritten_snippet():
    snippet = {
        "catalog": {
            "groups": [
                {
                    "id": "AC",
                    "title": "Access Control",
                    "controls": [
                        {
                            "id": "3.1.1",
                            "title": "Limit system access",
                            "parts": [
                                {
                                    "name": "statement",
                                    "prose": "Limit system access to authorized users."
                                },
                                {
                                    "name": "assessment-objective",
                                    "id": "3.1.1[a]",
                                    "prose": "authorized users are identified."
                                },
                                {
                                    "name": "assessment-objective",
                                    "id": "3.1.1[b]",
                                    "prose": "processes acting on behalf of authorized users are identified."
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    }

    result = import_oscal(snippet)

    assert "families" in result
    assert result["families"].get("AC") == "Access Control"

    assert "controls" in result
    assert "3.1.1" in result["controls"]

    ctl = result["controls"]["3.1.1"]
    assert ctl["family"] == "AC"
    assert ctl["family_name"] == "Access Control"
    assert ctl["title"] == "Limit system access"
    assert ctl["control"] == "Limit system access to authorized users."

    objectives = ctl["objectives"]
    assert len(objectives) == 2
    assert objectives[0]["id"] == "3.1.1[a]"
    assert objectives[0]["text"] == "authorized users are identified."
    assert objectives[1]["id"] == "3.1.1[b]"
    assert objectives[1]["text"] == "processes acting on behalf of authorized users are identified."
