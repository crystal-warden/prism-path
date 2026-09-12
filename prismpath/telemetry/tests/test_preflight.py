# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""prismpath-preflight is the adoption gate: it must tell an integrator the truth about their sample:
every clean event encodes and routes identically after the round trip, every unencodable event is
attributed to its exact cause, and the exit code is honest (0 only when nothing needs attention)."""
import json
import subprocess
import sys
from pathlib import Path

_ADAPTER = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ADAPTER))
from prismpath.telemetry import preflight  # noqa: E402

_FLOW = """---
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


def _run(flow_path, sample_path, *extra):
    return subprocess.run(
        [sys.executable, str(_ADAPTER / "preflight.py"), str(flow_path), str(sample_path),
         *extra],
        capture_output=True, text=True)


def _setup(tmp_path, events):
    flow = tmp_path / "flow.md"
    flow.write_text(_FLOW)
    sample = tmp_path / "sample.ndjson"
    sample.write_text("".join(json.dumps(event) + "\n" for event in events))
    return flow, sample


def test_clean_sample_is_ready(tmp_path):
    flow, sample = _setup(tmp_path, [
        {"temp": 95, "armed": True}, {"temp": 60, "armed": False},
        {"temp": 10, "armed": True}, {"temp": 89, "armed": True}])
    out = tmp_path / "report.json"
    result = _run(flow, sample, "--json", str(out))
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(out.read_text())
    assert report["ready"] and report["encoded"] == 4 and report["route_mismatches"] == []
    assert report["codebook"]["temp"]["cells"] == 3      # (-inf..49] [50..89] [90..+inf)
    assert report["codebook"]["armed"]["kind"] == "boolean"
    # one byte-aligned reading per frame, exactly as the Vector codec sends it
    assert report["framed_bytes_per_event"] == 1.0       # 2 fields, <=8 bits


def test_missing_field_error_vs_skip(tmp_path):
    flow, sample = _setup(tmp_path, [
        {"temp": 95, "armed": True}, {"temp": 60}])   # second event lacks `armed`
    assert _run(flow, sample).returncode == 1         # on_missing=error (the codec default)
    out = tmp_path / "report.json"
    result = _run(flow, sample, "--on-missing", "skip", "--json", str(out))
    assert result.returncode == 0                          # skip is declared codec behavior
    report = json.loads(out.read_text())
    assert report["encoded"] == 1 and report["missing_by_field"] == {"armed": 1}


def test_map_reaches_nested_fields(tmp_path):
    flow, sample = _setup(tmp_path, [
        {"sensor": {"temp": 95}, "armed": True}, {"sensor": {"temp": 20}, "armed": False}])
    assert _run(flow, sample).returncode == 1         # temp never seen without the map
    out = tmp_path / "report.json"
    result = _run(flow, sample, "--map", "temp=sensor.temp", "--json", str(out))
    assert result.returncode == 0
    report = json.loads(out.read_text())
    assert report["encoded"] == 2 and report["fields_never_seen"] == []
    assert report["route_distribution"]["classify"] == {"critical": 1, "ok": 1}


def test_unconvertible_numeric_is_reported_not_crashed(tmp_path):
    flow, sample = _setup(tmp_path, [
        {"temp": "not-a-number", "armed": True}, {"temp": 50, "armed": False}])
    out = tmp_path / "report.json"
    result = _run(flow, sample, "--json", str(out))
    assert result.returncode == 1
    report = json.loads(out.read_text())
    assert report["out_of_partition"] == {"temp": 1} and report["encoded"] == 1


def test_float_truncation_counted_and_null_is_missing(tmp_path):
    flow, sample = _setup(tmp_path, [
        {"temp": 49.9, "armed": True},                # truncates to 49 -> ok, counted
        {"temp": None, "armed": True}])               # JSON null = missing, as in the codec
    out = tmp_path / "report.json"
    result = _run(flow, sample, "--on-missing", "skip", "--json", str(out))
    assert result.returncode == 0
    report = json.loads(out.read_text())
    assert report["float_truncated_by_field"] == {"temp": 1}
    assert report["missing_by_field"] == {"temp": 1}
    assert report["route_distribution"]["classify"] == {"ok": 1}


def test_walk_path_mirrors_codec_lookup():
    event = {"a": {"b": {"c": 7}}, "n": None}
    assert preflight._walk_path(event, "a.b.c") == (True, 7)
    assert preflight._walk_path(event, ".a.b.c") == (True, 7)
    assert preflight._walk_path(event, "a.b.missing") == (False, None)
    assert preflight._walk_path(event, "n") == (False, None)


def test_no_decision_fields_flow_fails_loud(tmp_path):
    flow = tmp_path / "flow.md"
    flow.write_text("---\nname: f\nstart: a\n---\n## a\n-> b: always\n## b\n")
    sample = tmp_path / "sample.ndjson"
    sample.write_text('{"x": 1}\n')
    result = _run(flow, sample)
    assert result.returncode == 1 and "no decision-relevant fields" in result.stdout


def test_privacy_reconstruction_bound(tmp_path):
    flow, sample = _setup(tmp_path, [{"temp": 95, "armed": True}, {"temp": 10, "armed": False}])
    out = tmp_path / "r.json"
    result = _run(flow, sample, "--privacy", "--json", str(out))
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(out.read_text())
    reconstruction = report["privacy_reconstruction"]
    assert reconstruction["armed"]["leak"] == "exact"                 # a boolean leaks its 1 bit
    assert reconstruction["temp"]["kind"] == "numeric"
    assert reconstruction["temp"]["unbounded_cells"] == 2             # (-inf..49] and [90..+inf)
    assert "recoverable" in reconstruction["temp"]["note"] or "threshold" in reconstruction["temp"]["note"]


def test_privacy_aggregation_counts_sum_to_joint(tmp_path):
    flow, sample = _setup(tmp_path, [{"temp": 95, "armed": True}])
    out = tmp_path / "r.json"
    result = _run(flow, sample, "--privacy", "--json", str(out))
    report = json.loads(out.read_text())
    aggregation = report["privacy_aggregation"]
    assert aggregation["enumerated"] and aggregation["joint_cells"] == 6     # temp(3) x armed(2)
    per_node = aggregation["per_node"]["classify"]
    assert sum(per_node.values()) == 6                            # every joint cell routes somewhere
    # critical needs temp>=90 AND armed: exactly one input cell (the leak); warn/ok hide more
    assert per_node["critical"] == 1


def test_privacy_absent_by_default(tmp_path):
    flow, sample = _setup(tmp_path, [{"temp": 95, "armed": True}])
    out = tmp_path / "r.json"
    _run(flow, sample, "--json", str(out))
    report = json.loads(out.read_text())
    assert "privacy_reconstruction" not in report and "privacy_aggregation" not in report


def test_scan_render_byte_identity(tmp_path):
    flow, sample = _setup(tmp_path, [
        {"temp": 95, "armed": True},
        {"temp": 60, "armed": False},
        {"temp": 10, "armed": True},
    ])
    output_json_path = tmp_path / "cli_out.json"
    process_result = _run(flow, sample, "--json", str(output_json_path))
    assert process_result.returncode == 0

    cli_stdout = process_result.stdout
    cli_json_text = output_json_path.read_text()

    graph = preflight.parse_file(str(flow))
    parts = preflight.quantizer.build_partitions(graph)
    nodes = preflight.wire.decision_nodes(graph)
    with open(sample, encoding="utf-8") as sample_file:
        scan_result = preflight.scan_sample(
            parts=parts,
            lines=sample_file,
            graph=graph,
            nodes=nodes,
            field_paths={},
            on_missing="error",
            limit=None,
            privacy=False,
            flow=str(flow),
            sample=str(sample),
        )

    markdown_text = preflight.render_markdown(scan_result)
    rendered_json_dict = preflight.render_json(scan_result)
    expected_json_text = json.dumps(rendered_json_dict, indent=1) + "\n"
    expected_full_stdout = markdown_text + f"\n\nwrote {output_json_path}\n"

    assert cli_stdout == expected_full_stdout
    assert cli_json_text == expected_json_text
