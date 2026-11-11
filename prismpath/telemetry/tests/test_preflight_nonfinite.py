# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A telemetry line that holds a NaN or Infinity token, a number beyond the double range, or a lone
surrogate is not an event: canonical JSON has no form for it, so preflight counts it as not JSON
rather than reading a number from it. The Rust tool's test of the same name pins the same counts."""
import json
import sys

from prismpath.telemetry import preflight

FLOW = """---
name: preflight_guard
start: classify
---
## classify
-> critical: when temp >= 90 and armed
-> warn: when temp >= 50
-> ok: else
## critical
## warn
## ok
"""

LINES = [
    '{"temp": 95, "armed": true}', '{"temp": NaN, "armed": true}', '{"temp": Infinity, "armed": true}',
    '{"temp": -Infinity, "armed": true}', '{"temp": 1e400, "armed": true}', '{"temp": -1e400, "armed": false}',
    '{"temp": 60, "armed": true, "note": "\\ud800"}', '{"temp": 60, "armed": false}',
]


def test_non_finite_overflowing_and_lone_surrogate_lines_are_not_events(tmp_path, monkeypatch):
    flow, sample, out = tmp_path / "flow.md", tmp_path / "sample.ndjson", tmp_path / "report.json"
    flow.write_text(FLOW)
    sample.write_text("\n".join(LINES) + "\n")
    monkeypatch.setattr(sys, "argv", ["preflight", str(flow), str(sample), "--json", str(out)])
    assert preflight.main() == 0
    report = json.loads(out.read_text())
    assert report["bad_json"] == 6
    assert report["encoded"] == 2
