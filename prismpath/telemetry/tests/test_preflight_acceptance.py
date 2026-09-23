# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Preflight reports acceptance's refusals field by field and withholds READY on them,
and a clean sample that the contract accepts is READY with an empty refusal map, so a passing
preflight predicts exactly what the checked encoder will do."""
import json

from prismpath.telemetry import preflight

FLOW = "---\nname: t\nstart: a\n---\n## a\n-> hot: when temp >= 90 and armed\n-> warm: when temp >= 50\n-> cold: else\n## hot\n## warm\n## cold\n"


def _scan(lines):
    from prismpath.kernel.parser import parse
    from prismpath.telemetry import quantizer, wire
    graph = parse(FLOW)
    parts = quantizer.build_partitions(graph)
    result = preflight.scan_sample(parts, lines, graph, wire.decision_nodes(graph), {}, flow="flow.md", sample="sample.ndjson")
    return preflight.render_json(result)


def test_refusals_are_reported_and_block_ready():
    report = _scan(['{"temp": 95, "armed": true}', '{"temp": "hot", "armed": true}', '{"temp": 2.5, "armed": "yes"}'])
    assert report["refused_by_field"] == {"armed": {"wrong_type": 1}, "temp": {"unparseable_string": 1, "fractional": 1}}
    assert report["out_of_partition"] == {"temp": 1}
    assert report["ready"] is False


def test_clean_sample_has_no_refusals_and_is_ready():
    report = _scan(['{"temp": 95, "armed": true}', '{"temp": 10, "armed": false}', '{"temp": "60", "armed": 1}'])
    assert report["refused_by_field"] == {}
    assert report["ready"] is True
