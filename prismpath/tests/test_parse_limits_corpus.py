# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The parse limits corpus (conformance/parse_limits.json) is what portable/gen_parse_limits_fixtures.py writes
from prismpath.kernel.parser now, and the committed vectors hold a document exactly at each cap and one over it, for the size, the nodes and the edges, and the default caps
as well. The crate replays every case (prismpath-rs/tests/test_parse_limits.rs)."""
import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PORTABLE = REPO / "prismpath" / "portable"


def _generator():
    spec = importlib.util.spec_from_file_location("gen_parse_limits_fixtures", PORTABLE / "gen_parse_limits_fixtures.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _committed() -> dict:
    return json.loads((PORTABLE / "conformance" / "parse_limits.json").read_text(encoding="utf-8"))


def test_the_corpus_is_what_the_generator_writes_now():
    text = json.dumps(_generator().generate(), indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    committed = (PORTABLE / "conformance" / "parse_limits.json").read_text(encoding="utf-8")
    assert committed == text, "parse_limits.json is stale; run python -m prismpath.portable.gen_parse_limits_fixtures"


def test_each_cap_has_a_case_at_it_and_a_case_over_it():
    doc = _committed()
    for prefix, cap in (("size", "PRISMPATH_MAX_FLOW_BYTES"), ("nodes", "PRISMPATH_MAX_NODES"), ("edges", "PRISMPATH_MAX_EDGES")):
        outcomes = [case["expect"] for case in doc["cases"] if case["name"].startswith(prefix + "-")]
        assert any(outcome.get("ok") for outcome in outcomes), prefix
        assert any(cap in outcome.get("error", "") for outcome in outcomes), prefix
    by_name = {case["name"]: case["expect"] for case in doc["defaults"]}
    assert by_name["default-nodes-at-the-cap"]["ok"] and "MAX_NODES" in by_name["default-nodes-one-over"]["error"]
    assert by_name["default-edges-at-the-cap"]["ok"] and "MAX_EDGES" in by_name["default-edges-one-over"]["error"]
    assert by_name["default-characters-at-the-cap"]["ok"] and "MAX_FLOW_BYTES" in by_name["default-characters-one-over"]["error"]
    assert {case["limits"]["max_nodes"] for case in doc["defaults"]} == {5000}


def test_the_refusals_are_parse_errors_with_the_reference_messages():
    for case in _committed()["cases"]:
        if "error" in case["expect"]:
            assert case["expect"]["error_class"] == "ParseError", case["name"]
            assert case["expect"]["error"].startswith("flow document exceeds PRISMPATH_MAX_"), case["name"]


def test_names_are_unique():
    doc = _committed()
    for key in ("cases", "defaults"):
        names = [case["name"] for case in doc[key]]
        assert len(names) == len(set(names)), key
