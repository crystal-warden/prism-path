# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Field definitions (SPEC section 4.5), held to the frozen vectors in portable/conformance/.

The vectors are regenerated here and must match the committed file exactly, so a change to the reference
shows up as a diff to review rather than drifting silently. Then every case is replayed: the shared
conversion, parse time lowering, the policy rules, the canonical boundary, and the engine's routes on
canonical readings. The Rust twin replays the same file.
"""
import json
from decimal import Decimal
from fractions import Fraction
from pathlib import Path

import pytest

from prismpath.kernel import engine, field_definitions as fd
from prismpath.kernel.parser import parse
from prismpath.portable import gen_field_definitions

CORPUS = json.loads((Path(gen_field_definitions.__file__).parent / "conformance" / "field_definitions.json")
                    .read_text())
ACCEPTED = [policy for policy in CORPUS["policies"] if policy["accepted"]]
REFUSED = [policy for policy in CORPUS["policies"] if not policy["accepted"]]


def test_no_silent_drift_from_the_reference():
    assert gen_field_definitions.build() == CORPUS


@pytest.mark.parametrize("case", CORPUS["conversion"], ids=lambda case: f"{case['definition']}|{case['raw']!r}")
def test_the_shared_conversion(case):
    definition = fd.parse_definition("value", case["definition"])
    if "refused" in case:
        with pytest.raises(fd.CanonicalRefusal) as refusal:
            fd.canonical_value(definition, case["raw"])
        assert refusal.value.reason == case["refused"]
    else:
        assert fd.canonical_value(definition, case["raw"]) == case["canonical"]


@pytest.mark.parametrize("policy", ACCEPTED, ids=lambda policy: policy["name"])
def test_an_accepted_policy_lowers_and_routes_as_frozen(policy):
    graph = parse(policy["flow"])
    assert [cond for _target, cond in graph.nodes["s"].edges] == policy["lowered"]
    for probe in policy["probes"]:
        assert engine.first_deterministic(graph.nodes["s"].edges, probe["reading"])[0] == probe["route"]


@pytest.mark.parametrize("policy", REFUSED, ids=lambda policy: policy["name"])
def test_a_refused_policy_never_parses(policy):
    with pytest.raises(ValueError):
        parse(policy["flow"])


def test_exact_inputs_agree_with_their_decimal_text():
    definition = fd.parse_definition("value", "fixed scale=100 rounding=floor")
    assert fd.canonical_value(definition, Decimal("0.29")) == 29
    assert fd.canonical_value(definition, Fraction(29, 100)) == 29
    assert fd.canonical_value(definition, json.loads("0.29", parse_float=Decimal)) == 29
    assert int(0.29 * 100) == 28            # the trap the exact path exists to avoid


def test_a_flow_without_definitions_is_untouched():
    flow = "---\nname: t\nstart: s\n---\n## s\n-> hit: when x >= 0.85\n-> miss: else\n## hit\n## miss\n"
    graph = parse(flow)
    assert graph.fields == {}
    assert graph.nodes["s"].edges[0][1] == "when x >= 0.85"


def test_two_spellings_of_one_definition_bind_the_same_text():
    one = fd.parse_definition("r", "fixed rounding=floor scale=10000 unit=ratio max=10000 min=0")
    two = fd.parse_definition("r", "fixed scale=10000 unit=ratio rounding=floor min=0 max=10000 absent=refused")
    assert one.canonical_text() == two.canonical_text()


def test_every_refusal_carries_a_registered_cause():
    """A refused flow names a registered refusal (spec-verified-core.md section 5) for its first problem
    and for every problem, as the frozen corpus records it; no refusal of the core is uncoded."""
    from prismpath.kernel import causes
    corpus = json.loads((Path(__file__).resolve().parents[1] / "portable" / "conformance" /
                         "field_definitions.json").read_text())
    refused = [policy for policy in corpus["policies"] if not policy["accepted"]]
    assert refused
    for policy in refused:
        with pytest.raises(fd.FieldDefinitionError) as raised:
            parse(policy["flow"])
        error = raised.value
        assert error.code is not None and causes.name(error.code) == error.cause == policy["cause"], policy["name"]
        assert [problem.cause for problem in error.problems] == policy["causes"], policy["name"]
        assert all(problem.code is not None for problem in error.problems), policy["name"]
    for text in ("float", "", "int min=5 max=4", "fixed scale=100", "int min=x", "bool min=0"):
        with pytest.raises(fd.FieldDefinitionError) as raised:
            fd.parse_definition("x", text)
        assert raised.value.cause == "policy:definition" and raised.value.code == causes.code("policy:definition")


def test_the_system_boundary_and_the_policy_check():
    """D4 (spec-verified-core.md section 6.1): the system boundary checks every defined field, the policy
    check only the fields the rules read; a reading the system boundary accepts passes the policy check."""
    flow = ("---\nname: t\nstart: s\nfield.x: int min=0 max=10\nfield.unused: bool\n"
            "field.r: fixed scale=100 rounding=floor\n---\n## s\n-> hit: when x >= 5 and r >= 0.5\n-> miss: else\n"
            "## hit\n## miss\n")
    graph = parse(flow)
    assert fd.routed_fields(graph) == ["r", "x"]
    assert fd.system_boundary(graph, {"x": 5, "r": 50}) == ("unused", "missing")
    assert fd.policy_check(graph, {"x": 5, "r": 50}) is None
    assert fd.system_boundary(graph, {"x": 11, "r": 50, "unused": True}) == ("x", "out_of_range")
    assert fd.policy_check(graph, {"x": 11, "r": 50}) == ("x", "out_of_range")
    assert fd.policy_check(graph, {"x": 1}) == ("r", "missing")
    for reading in ({}, {"x": 1, "r": 2, "unused": False}, {"x": "1", "unused": 1}, {"r": True, "x": 3}):
        if fd.system_boundary(graph, reading) is None:
            assert fd.policy_check(graph, reading) is None
        if fd.policy_check(graph, reading) is not None:
            assert fd.system_boundary(graph, reading) is not None
