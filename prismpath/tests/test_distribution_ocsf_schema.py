# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The OCSF export (prismpath/distribution/export.py) against the OCSF 1.10.0 schema. The fixture
fixtures/ocsf/ocsf-1.10.0-subset.json holds the classes 5019 and 2004 and every object they reach, compiled from
the OCSF schema release 1.10 with each class's and object's `extends` and `$include` applied, and for each attribute
its requirement, type, array flag and enum values. Every exported event has each required attribute, no attribute
the class or object lacks, values of the attribute's type and enum, and a class, category, type and activity
that agree."""
import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from prismpath.distribution import export
from prismpath.tests.test_distribution_export import _committed, _lapse

SCHEMA = json.loads((Path(__file__).parent / "fixtures" / "ocsf" / "ocsf-1.10.0-subset.json").read_text())
TYPES = {"integer_t": int, "long_t": int, "string_t": str, "boolean_t": bool, "float_t": (int, float)}


def _problems(value, attributes, where):
    problems = [f"{where}: required {key} missing" for key, row in attributes.items()
                if row["r"] == "required" and key not in value]
    for key, item in value.items():
        row = attributes.get(key)
        if row is None:
            problems.append(f"{where}: {key} is not an attribute here")
            continue
        if row.get("a") and not isinstance(item, list):
            problems.append(f"{where}.{key}: not an array")
            continue
        for one in (item if row.get("a") else [item]):
            if "o" in row:
                if not isinstance(one, dict):
                    problems.append(f"{where}.{key}: not an object")
                elif row["o"] != "object":
                    problems += _problems(one, SCHEMA["objects"][row["o"]], f"{where}.{key}")
            elif row.get("t") in TYPES and (not isinstance(one, TYPES[row["t"]]) or
                                           (row["t"] != "boolean_t" and isinstance(one, bool))):
                problems.append(f"{where}.{key}: {one!r} is not {row['t']}")
            if "e" in row and str(one) not in row["e"]:
                problems.append(f"{where}.{key}: {one!r} not in its enum")
    return problems


def _check(event):
    spec = SCHEMA["classes"][str(event["class_uid"])]
    problems = _problems(event, spec["attributes"], spec["name"])
    if event["category_uid"] != spec["category_uid"] or event["class_name"] != spec["caption"]:
        problems.append("class name or category does not match the class")
    if event["type_uid"] != event["class_uid"] * 100 + event["activity_id"]:
        problems.append("type_uid is not class_uid * 100 + activity_id")
    if event["activity_id"] != 99 and event["activity_name"] != spec["activities"][str(event["activity_id"])]:
        problems.append("activity_name is not the activity's caption")
    return problems


def test_the_fixture_is_ocsf_1_10_0():
    assert SCHEMA["ocsf_version"] == export.OCSF_VERSION == "1.10.0"


def test_each_exported_commit_lapse_and_finding_is_valid_ocsf_1_10_0(tmp_path):
    fleet = _committed(tmp_path)
    _lapse(fleet)
    events = export.ocsf_events(fleet.controller)
    assert {event["class_uid"] for event in events} == {5019, 2004}
    assert [problem for event in events for problem in _check(event)] == []


def test_the_check_refuses_a_missing_required_attribute_an_unknown_one_and_a_value_outside_its_enum(tmp_path):
    fleet = _committed(tmp_path)
    _lapse(fleet)
    events = export.ocsf_events(fleet.controller)
    state = next(event for event in events if event["class_uid"] == 5019)
    finding = next(event for event in events if event["class_uid"] == 2004)
    assert _check({k: v for k, v in state.items() if k != "device"})
    assert _check({**state, "unknown": 1})
    assert _check({**finding, "severity_id": 9})
    assert _check({**finding, "finding_info": {k: v for k, v in finding["finding_info"].items() if k != "uid"}})
    assert _check({**finding, "raw_data_hash": {**finding["raw_data_hash"], "algorithm_id": "3"}})
