# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The rules-source refusal corpus (conformance/rules_source.json) is what
portable/gen_rules_source_fixtures.py writes from prismpath.kernel.parser now, the Rust crate carries a
byte identical copy, and every case replays cleanly against the Python reference parser."""
import importlib.util
import json
from pathlib import Path

import pytest

from prismpath.kernel import parser

REPO = Path(__file__).resolve().parents[2]
PORTABLE = REPO / "prismpath" / "portable"


def _generator():
    spec = importlib.util.spec_from_file_location("gen_rules_source_fixtures", PORTABLE / "gen_rules_source_fixtures.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _committed() -> dict:
    return json.loads((PORTABLE / "conformance" / "rules_source.json").read_text(encoding="utf-8"))


def test_the_corpus_is_what_the_generator_writes_now():
    text = json.dumps(_generator().generate(), indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    committed = (PORTABLE / "conformance" / "rules_source.json").read_text(encoding="utf-8")
    assert committed == text, "rules_source.json is stale; run python -m prismpath.portable.gen_rules_source_fixtures"


@pytest.mark.cross_language
def test_the_corpus_is_copied_into_the_crate():
    committed = (PORTABLE / "conformance" / "rules_source.json").read_text(encoding="utf-8")
    assert (REPO / "prismpath-rs" / "tests" / "fixtures" / "rules_source.json").read_text(encoding="utf-8") == committed


def test_every_case_replays_against_the_reference_parser(tmp_path):
    doc = _committed()
    for index, case in enumerate(doc["cases"]):
        filename = case["filename"]
        flow = case["flow"]
        expect = case["expect"]
        if "error" in expect:
            with pytest.raises(parser.RulesSourceError) as exc_info:
                if filename is None:
                    parser.parse(flow)
                else:
                    target = tmp_path / f"case_{index}" / filename
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(flow, encoding="utf-8")
                    parser.parse_file(str(target))
            assert isinstance(exc_info.value, parser.ParseError)
            assert str(exc_info.value) == expect["error"], case["name"]
            assert type(exc_info.value).__name__ == expect["error_class"], case["name"]
            assert "prismpath policy compile" in str(exc_info.value), case["name"]
        else:
            if filename is None:
                graph = parser.parse(flow)
            else:
                target = tmp_path / f"case_{index}" / filename
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(flow, encoding="utf-8")
                graph = parser.parse_file(str(target))
            got_nodes = [[name, [[t, c] for t, c in node.edges]] for name, node in graph.nodes.items()]
            assert graph.start == expect["start"], case["name"]
            assert got_nodes == expect["nodes"], case["name"]


def test_corpus_covers_refusals_and_near_misses():
    doc = _committed()
    by_name = {case["name"]: case for case in doc["cases"]}
    assert len(by_name) == len(doc["cases"]), "case names must be unique"
    assert "error" in by_name["refuse-rule-with-frontmatter"]["expect"]
    assert "error" in by_name["escalate-rule-bulleted-and-indented"]["expect"]
    assert "error" in by_name["rules-md-filename-with-allow-only"]["expect"]
    assert by_name["rendered-refuse-code-edge"]["expect"]["ok"] is True
    assert by_name["normal-when-edge"]["expect"]["ok"] is True
    assert by_name["prose-mentioning-refuse"]["expect"]["ok"] is True
