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
