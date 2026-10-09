# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze the field definition vectors (SPEC section 4.5) as language neutral data.

    python -m prismpath.portable.gen_field_definitions

Writes `portable/conformance/field_definitions.json`, generated from the Python reference, in three
parts that every implementation replays:

  * `conversion`: a definition and a raw JSON value, and the canonical value `canonical_value`
    returns or the reason it refuses. This pins the one shared conversion, including the exact decimal
    cases a binary double gets wrong.
  * `policies`: flows that define their fields. An accepted flow records the conditions after parse
    time lowering and, for a set of readings, the route the engine takes and the reason any reading
    that is not canonical is refused at the boundary. A refused flow records only that it is refused.
  * `version`: bumped when an existing case changes meaning.

Every expected value comes from the reference implementation, never from either twin, so the Rust
replay is held to the reference rather than to the Python code it was ported from. Regenerating this
file is a spec change and must be reviewed as one.
"""
from __future__ import annotations

import json
from pathlib import Path

from prismpath.kernel import engine, field_definitions
from prismpath.kernel.parser import parse

OUT = Path(__file__).parent / "conformance" / "field_definitions.json"
VERSION = 1

DEFINITIONS = {
    "ratio_floor": "fixed scale=10000 unit=ratio rounding=floor min=0 max=10000",
    "drift_floor": "fixed scale=100 unit=celsius rounding=floor min=-5000 max=5000",
    "seconds_ceiling": "fixed scale=1000 unit=seconds rounding=ceiling min=0 max=600000",
    "price_exact": "fixed scale=100 unit=usd rounding=exact min=-100000 max=100000",
    "count_int": "int min=-5 max=5 absent=allowed",
    "flag_bool": "bool",
    "label_category": "category absent=allowed",
}

CONVERSION = [
    ("ratio_floor", ["0.892", "0.85", "0.8499", "0.84999", "1", "1.0", "0", "+0.5", ".5", "5.", "8.5e-1",
                     "1e-4", "0.00001", "-0.00001", "1.00001", "0.85000000000000000000000000",
                     "1_000", "0x10", " 0.5", "0.5 ", "NaN", "inf", "", "1e31", "1e-31",
                     "1234567890123456789012345678", "12345678901234567890123456789",
                     0.5, 1, 1.0, 0, True, None, [1], {"value": 1}]),
    ("drift_floor", ["0.29", "-0.291", "-0.29", "-50", "-50.001", "50", "50.01", 0.29, -3, -3.0]),
    ("seconds_ceiling", ["0.0001", "1.5", "1.5001", "0", "600", "600.0001", "-0.0001", 2]),
    ("price_exact", ["19.99", "19.999", "-0.01", "0.005", "1000", "1000.01", "1e2", "1.5e1", 19.99, 20]),
    ("count_int", ["3", "-5", "6", "3.0", "3.5", "1e1", "2e0", 3, 3.0, 3.5, -0.0, True, None, "x"]),
    ("flag_bool", [True, False, 1, 0, "true", None]),
    ("label_category", ["a", "", 3, None, True]),
]

FLOW_TEMPLATE = "---\nname: {name}\nstart: s\n{definitions}---\n## s\n{edges}\n## hit\n## low\n## gone\n## miss\n"


def _flow(name: str, definitions: dict, edges: list) -> str:
    lines = "".join(f"field.{field}: {text}\n" for field, text in definitions.items())
    return FLOW_TEMPLATE.format(name=name, definitions=lines,
                                edges="\n".join(f"-> {target}: {cond}" for target, cond in edges))


ACCEPTED = [
    ("floor_ratio_with_absent_label",
     {"error_rate": DEFINITIONS["ratio_floor"], "label": DEFINITIONS["label_category"]},
     [("hit", "when error_rate >= 0.85"), ("gone", "when label == None"),
      ("low", "when error_rate < 0.25 and label == \"a\""), ("miss", "else")],
     [{"error_rate": 8500, "label": "b"}, {"error_rate": 8499, "label": "a"}, {"error_rate": 2499, "label": "a"},
      {"error_rate": 2500, "label": "a"}, {"error_rate": 100}, {"error_rate": 100, "label": None},
      {"error_rate": 0, "label": ""}, {"error_rate": 10000, "label": "z"}],
     [{"error_rate": "8500", "label": "a"}, {"error_rate": 8500.5, "label": "a"}, {"error_rate": True, "label": "a"},
      {"label": "a"}, {"error_rate": 10001, "label": "a"}, {"error_rate": -1, "label": "a"},
      {"error_rate": 100, "label": 3}]),
    ("floor_orientation_and_negation",
     {"drift": DEFINITIONS["drift_floor"]},
     [("hit", "when 0.5 <= drift"), ("low", "when not (drift >= -1.25)"), ("miss", "else")],
     [{"drift": 50}, {"drift": 49}, {"drift": -125}, {"drift": -126}, {"drift": 5000}, {"drift": -5000}],
     [{"drift": 0.5}, {"drift": None}]),
    ("ceiling_seconds",
     {"latency": DEFINITIONS["seconds_ceiling"]},
     [("hit", "when latency > 1.5"), ("low", "when latency <= 0.25"), ("miss", "else")],
     [{"latency": 1501}, {"latency": 1500}, {"latency": 250}, {"latency": 251}, {"latency": 0}],
     [{"latency": "1.5"}]),
    ("exact_price_every_operator",
     {"price": DEFINITIONS["price_exact"]},
     [("hit", "when price == 19.99"), ("low", "when price in [0, 5.5, -0.01]"),
      ("gone", "when -1 < price < 1 and price != 0.5"), ("miss", "when price")],
     [{"price": 1999}, {"price": 0}, {"price": 550}, {"price": -1}, {"price": 50}, {"price": 99},
      {"price": -99}, {"price": 100}, {"price": 1998}],
     [{"price": 19.99}]),
    ("int_and_bool_with_absent_count",
     {"count": DEFINITIONS["count_int"], "armed": DEFINITIONS["flag_bool"]},
     [("gone", "when count == None"), ("hit", "when count >= 3 and armed"), ("low", "when not armed"),
      ("miss", "else")],
     [{"armed": True}, {"count": None, "armed": False}, {"count": 3, "armed": True}, {"count": 2, "armed": True},
      {"count": 5, "armed": False}, {"count": -5, "armed": True}],
     [{"count": 3, "armed": 1}, {"count": 3}, {"count": 6, "armed": True}, {"count": "3", "armed": True}]),
]

REFUSED = [
    ("floor_with_greater", {"r": DEFINITIONS["ratio_floor"]}, ["when r > 0.85"]),
    ("floor_with_less_equal", {"r": DEFINITIONS["ratio_floor"]}, ["when r <= 0.85"]),
    ("floor_with_equality", {"r": DEFINITIONS["ratio_floor"]}, ["when r == 0.85"]),
    ("floor_with_membership", {"r": DEFINITIONS["ratio_floor"]}, ["when r in [0.5]"]),
    ("floor_with_truthiness", {"r": DEFINITIONS["ratio_floor"]}, ["when r"]),
    ("ceiling_with_greater_equal", {"t": DEFINITIONS["seconds_ceiling"]}, ["when t >= 1.5"]),
    ("off_grid_threshold", {"r": DEFINITIONS["ratio_floor"]}, ["when r >= 0.85001"]),
    ("threshold_out_of_range", {"r": DEFINITIONS["ratio_floor"]}, ["when r >= 1.5"]),
    ("int_constant_out_of_range", {"c": "int min=0 max=10"}, ["when c >= 11"]),
    ("decimal_on_int_field", {"c": "int"}, ["when c >= 2.5"]),
    ("undefined_field_read", {"r": DEFINITIONS["ratio_floor"]}, ["when r >= 0.5 and other > 3"]),
    ("none_on_field_refusing_absence", {"c": "int"}, ["when c == None"]),
    ("absence_allowed_but_never_tested", {"c": "int absent=allowed"}, ["when c > 3"]),
    ("none_inside_a_list", {"c": "int absent=allowed"}, ["when c in [1, None]", "when c == None"]),
    ("none_ordered", {"c": "int absent=allowed"}, ["when c < None", "when c == None"]),
    ("bool_field_against_number", {"b": "bool"}, ["when b == 1"]),
    ("int_field_against_bool", {"c": "int"}, ["when c == True"]),
    ("int_field_against_string", {"c": "int"}, ["when c == \"3\""]),
    ("category_field_ordered", {"k": "category"}, ["when k < \"m\""]),
    ("category_field_against_number", {"k": "category"}, ["when k == 3"]),
    ("field_against_field", {"a": "int", "b": "int"}, ["when a == b"]),
    ("unknown_kind", {"x": "float"}, ["when x > 1"]),
    ("fixed_without_rounding", {"x": "fixed scale=100"}, ["when x >= 1"]),
    ("fixed_with_zero_scale", {"x": "fixed scale=0 rounding=floor"}, ["when x >= 1"]),
    ("option_the_kind_does_not_take", {"x": "int scale=100"}, ["when x > 1"]),
    ("option_given_twice", {"x": "int min=0 min=1"}, ["when x > 1"]),
    ("empty_range", {"x": "int min=5 max=4"}, ["when x > 1"]),
    ("range_wider_than_exact", {"x": "int max=9007199254740992"}, ["when x > 1"]),
    ("absent_neither_word", {"x": "int absent=maybe"}, ["when x > 1"]),
    ("engine_counter_defined", {"visits": "int"}, ["when visits > 1"]),
]


def _route(graph, reading):
    return engine.first_deterministic(graph.nodes["s"].edges, reading)[0]


def _boundary_refusal(graph, reading):
    """The first field, in sorted order, whose value the canonical boundary refuses, with the reason."""
    for field in sorted(graph.fields):
        reason, _value = field_definitions.accept_canonical(graph.fields[field], reading.get(field))
        if reason is not None:
            return {"field": field, "reason": reason}
    return None


def build() -> dict:
    conversion = []
    for definition_name, raws in CONVERSION:
        definition = field_definitions.parse_definition("value", DEFINITIONS[definition_name])
        for raw in raws:
            try:
                expected = {"canonical": field_definitions.canonical_value(definition, raw)}
            except field_definitions.CanonicalRefusal as refusal:
                expected = {"refused": refusal.reason}
            conversion.append({"definition": DEFINITIONS[definition_name], "raw": raw, **expected})

    policies = []
    for name, definitions, edges, readings, refused_readings in ACCEPTED:
        flow = _flow(name, definitions, edges)
        graph = parse(flow)
        lowered = [cond for _target, cond in graph.nodes["s"].edges]
        probes = [{"reading": reading, "route": _route(graph, reading)} for reading in readings]
        refusals = []
        for reading in refused_readings:
            refusal = _boundary_refusal(graph, reading)
            assert refusal is not None, (name, reading)
            refusals.append({"reading": reading, **refusal})
        policies.append({"name": name, "flow": flow, "accepted": True, "lowered": lowered,
                         "probes": probes, "refused_readings": refusals})
    for name, definitions, conditions in REFUSED:
        flow = _flow(name, definitions, [("hit", cond) for cond in conditions] + [("miss", "else")])
        try:
            parse(flow)
        except ValueError:
            policies.append({"name": name, "flow": flow, "accepted": False})
            continue
        raise AssertionError(f"{name} was meant to be refused and parsed")
    return {
        "comment": "FROZEN. Field definitions (SPEC section 4.5): the shared conversion, parse time "
                   "lowering, the policy rules and the canonical boundary. Generated from the Python "
                   "reference by prismpath.portable.gen_field_definitions.",
        "version": VERSION,
        "conversion": conversion,
        "policies": policies,
    }


def main() -> int:
    corpus = build()
    OUT.write_text(json.dumps(corpus, indent=1, sort_keys=False) + "\n")
    accepted = sum(policy["accepted"] for policy in corpus["policies"])
    print(f"wrote {OUT}: {len(corpus['conversion'])} conversions, {accepted} accepted policies, "
          f"{len(corpus['policies']) - accepted} refused policies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
