# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""prismpath-preflight is the adoption gate: it must tell an integrator the truth about their sample —
every clean event encodes and routes identically after the round trip, every unencodable event is
attributed to its exact cause, and the exit code is honest (0 only when nothing needs attention)."""
import json
import subprocess
import sys
from pathlib import Path

_ADAPTER = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ADAPTER))
import preflight  # noqa: E402

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
    sample.write_text("".join(json.dumps(e) + "\n" for e in events))
    return flow, sample


def test_clean_sample_is_ready(tmp_path):
    flow, sample = _setup(tmp_path, [
        {"temp": 95, "armed": True}, {"temp": 60, "armed": False},
        {"temp": 10, "armed": True}, {"temp": 89, "armed": True}])
    out = tmp_path / "report.json"
    r = _run(flow, sample, "--json", str(out))
    assert r.returncode == 0, r.stdout + r.stderr
    rep = json.loads(out.read_text())
    assert rep["ready"] and rep["encoded"] == 4 and rep["route_mismatches"] == []
    assert rep["codebook"]["temp"]["cells"] == 3      # (-inf..49] [50..89] [90..+inf)
    assert rep["codebook"]["armed"]["kind"] == "boolean"
    # one byte-aligned reading per frame, exactly as the Vector codec sends it
    assert rep["framed_bytes_per_event"] == 1.0       # 2 fields, <=8 bits


def test_missing_field_error_vs_skip(tmp_path):
    flow, sample = _setup(tmp_path, [
        {"temp": 95, "armed": True}, {"temp": 60}])   # second event lacks `armed`
    assert _run(flow, sample).returncode == 1         # on_missing=error (the codec default)
    out = tmp_path / "report.json"
    r = _run(flow, sample, "--on-missing", "skip", "--json", str(out))
    assert r.returncode == 0                          # skip is declared codec behavior
    rep = json.loads(out.read_text())
    assert rep["encoded"] == 1 and rep["missing_by_field"] == {"armed": 1}


def test_map_reaches_nested_fields(tmp_path):
    flow, sample = _setup(tmp_path, [
        {"sensor": {"temp": 95}, "armed": True}, {"sensor": {"temp": 20}, "armed": False}])
    assert _run(flow, sample).returncode == 1         # temp never seen without the map
    out = tmp_path / "report.json"
    r = _run(flow, sample, "--map", "temp=sensor.temp", "--json", str(out))
    assert r.returncode == 0
    rep = json.loads(out.read_text())
    assert rep["encoded"] == 2 and rep["fields_never_seen"] == []
    assert rep["route_distribution"]["classify"] == {"critical": 1, "ok": 1}


def test_unconvertible_numeric_is_reported_not_crashed(tmp_path):
    flow, sample = _setup(tmp_path, [
        {"temp": "not-a-number", "armed": True}, {"temp": 50, "armed": False}])
    out = tmp_path / "report.json"
    r = _run(flow, sample, "--json", str(out))
    assert r.returncode == 1
    rep = json.loads(out.read_text())
    assert rep["out_of_partition"] == {"temp": 1} and rep["encoded"] == 1


def test_float_truncation_counted_and_null_is_missing(tmp_path):
    flow, sample = _setup(tmp_path, [
        {"temp": 49.9, "armed": True},                # truncates to 49 -> ok, counted
        {"temp": None, "armed": True}])               # JSON null = missing, as in the codec
    out = tmp_path / "report.json"
    r = _run(flow, sample, "--on-missing", "skip", "--json", str(out))
    assert r.returncode == 0
    rep = json.loads(out.read_text())
    assert rep["float_truncated_by_field"] == {"temp": 1}
    assert rep["missing_by_field"] == {"temp": 1}
    assert rep["route_distribution"]["classify"] == {"ok": 1}


def test_walk_path_mirrors_codec_lookup():
    ev = {"a": {"b": {"c": 7}}, "n": None}
    assert preflight._walk_path(ev, "a.b.c") == (True, 7)
    assert preflight._walk_path(ev, ".a.b.c") == (True, 7)
    assert preflight._walk_path(ev, "a.b.missing") == (False, None)
    assert preflight._walk_path(ev, "n") == (False, None)


def test_no_decision_fields_flow_fails_loud(tmp_path):
    flow = tmp_path / "flow.md"
    flow.write_text("---\nname: f\nstart: a\n---\n## a\n-> b: always\n## b\n")
    sample = tmp_path / "sample.ndjson"
    sample.write_text('{"x": 1}\n')
    r = _run(flow, sample)
    assert r.returncode == 1 and "no decision-relevant fields" in r.stdout


def test_privacy_reconstruction_bound(tmp_path):
    flow, sample = _setup(tmp_path, [{"temp": 95, "armed": True}, {"temp": 10, "armed": False}])
    out = tmp_path / "r.json"
    r = _run(flow, sample, "--privacy", "--json", str(out))
    assert r.returncode == 0, r.stdout + r.stderr
    rep = json.loads(out.read_text())
    recon = rep["privacy_reconstruction"]
    assert recon["armed"]["leak"] == "exact"                 # a boolean leaks its 1 bit
    assert recon["temp"]["kind"] == "numeric"
    assert recon["temp"]["unbounded_cells"] == 2             # (-inf..49] and [90..+inf)
    assert "recoverable" in recon["temp"]["note"] or "threshold" in recon["temp"]["note"]


def test_privacy_aggregation_counts_sum_to_joint(tmp_path):
    flow, sample = _setup(tmp_path, [{"temp": 95, "armed": True}])
    out = tmp_path / "r.json"
    r = _run(flow, sample, "--privacy", "--json", str(out))
    rep = json.loads(out.read_text())
    agg = rep["privacy_aggregation"]
    assert agg["enumerated"] and agg["joint_cells"] == 6     # temp(3) x armed(2)
    per = agg["per_node"]["classify"]
    assert sum(per.values()) == 6                            # every joint cell routes somewhere
    # critical needs temp>=90 AND armed: exactly one input cell (the leak); warn/ok hide more
    assert per["critical"] == 1


def test_privacy_absent_by_default(tmp_path):
    flow, sample = _setup(tmp_path, [{"temp": 95, "armed": True}])
    out = tmp_path / "r.json"
    _run(flow, sample, "--json", str(out))
    rep = json.loads(out.read_text())
    assert "privacy_reconstruction" not in rep and "privacy_aggregation" not in rep
