# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""canary_verify is the cutover gate: exit 0 only on perfect route parity between a canary's raw
JSON leg and its decoded Facet leg, with any daylight named by position and route. It must also
keep positions synchronized when the encoder legitimately dropped events (on_missing)."""
import json
import pytest
import subprocess
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent.parent.parent
_VERIFY = _REPO / "integrations" / "vector" / "canary_verify.py"
if not _VERIFY.exists():                      # the integration script is only in a repo checkout, not the wheel
    pytest.skip(f"{_VERIFY} is only in a repo checkout", allow_module_level=True)

_FLOW = """---
name: canary_guard
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

_RAW = [{"temp": 95, "armed": True},   # critical
        {"temp": 60, "armed": False},  # warn
        {"temp": 10, "armed": True}]   # ok
_ROUTES = ["critical", "warn", "ok"]


def _run(tmp_path, raw, decoded, *extra):
    flow = tmp_path / "flow.md"
    flow.write_text(_FLOW)
    rawf = tmp_path / "raw.ndjson"
    rawf.write_text("".join(json.dumps(event) + "\n" for event in raw))
    decf = tmp_path / "decoded.ndjson"
    decf.write_text("".join(json.dumps(event) + "\n" for event in decoded))
    return subprocess.run(
        [sys.executable, str(_VERIFY), str(flow), "--raw", str(rawf), "--decoded", str(decf),
         "--route-node", "classify", *extra],
        capture_output=True, text=True)


def test_parity_exits_zero(tmp_path):
    decoded = [{"facet_route": route} for route in _ROUTES]
    result = _run(tmp_path, _RAW, decoded)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "**PARITY.**" in result.stdout


def test_route_mismatch_named_by_position(tmp_path):
    decoded = [{"facet_route": route} for route in ["critical", "ok", "ok"]]   # position 1 skewed
    result = _run(tmp_path, _RAW, decoded)
    assert result.returncode == 1
    assert "event 1" in result.stdout and "`warn`" in result.stdout and "NO PARITY" in result.stdout


def test_count_drift_flagged(tmp_path):
    decoded = [{"facet_route": route} for route in _ROUTES[:2]]                # one decoded event lost
    result = _run(tmp_path, _RAW, decoded)
    assert result.returncode == 1 and "COUNT DRIFT" in result.stdout


def test_encoder_dropped_events_keep_positions_synced(tmp_path):
    raw = [_RAW[0], {"temp": 60}, _RAW[2]]            # middle event lacks `armed`: encoder dropped it
    decoded = [{"facet_route": "critical"}, {"facet_route": "ok"}]
    result = _run(tmp_path, raw, decoded)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 not encodable" in result.stdout and "**PARITY.**" in result.stdout


def test_map_applies_to_raw_leg(tmp_path):
    raw = [{"sensor": {"temp": 95}, "armed": True}, {"sensor": {"temp": 10}, "armed": False}]
    decoded = [{"facet_route": "critical"}, {"facet_route": "ok"}]
    result = _run(tmp_path, raw, decoded, "--map", "temp=sensor.temp")
    assert result.returncode == 0, result.stdout + result.stderr

def test_a_duplicate_standing_in_for_a_lost_event_passes_route_parity_but_fails_strict_mode(tmp_path):
    """Three raw events with identities; the decoded leg lost the second and carries the first twice.
    Every position still routes as the raw leg does, so route parity passes; the identities do not."""
    raw = [{"id": "a", "temp": 95, "armed": True}, {"id": "b", "temp": 96, "armed": True}, {"id": "c", "temp": 10, "armed": True}]
    decoded = [{"id": "a", "facet_route": "critical"}, {"id": "a", "facet_route": "critical"}, {"id": "c", "facet_route": "ok"}]
    route_only = _run(tmp_path, raw, decoded)
    assert route_only.returncode == 0 and "**PARITY.**" in route_only.stdout
    strict = _run(tmp_path, raw, decoded, "--id-field", "id", "--json", str(tmp_path / "out.json"))
    assert strict.returncode == 1, strict.stdout + strict.stderr
    assert "NO PARITY" in strict.stdout and "`b` has no decoded twin" in strict.stdout and "`a` appears more than once" in strict.stdout
    assert "1 lost, 1 duplicated, 0 without identity" in strict.stdout
    identity = json.loads((tmp_path / "out.json").read_text())["identity"]
    assert identity == {"ok": False, "missing": ["b"], "duplicated": ["a"], "extra": [], "unidentified": 0, "reordered": 1}


def test_strict_mode_passes_when_identities_match_in_sequence(tmp_path):
    raw = [{"meta": {"id": 1}, "temp": 95, "armed": True}, {"meta": {"id": 2}, "temp": 10, "armed": False}]
    decoded = [{"id": 1, "facet_route": "critical"}, {"id": 2, "facet_route": "ok"}]
    result = _run(tmp_path, raw, decoded, "--id-field", "meta.id")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "**IDENTITY**" in result.stdout and "none lost, none duplicated" in result.stdout


def test_strict_mode_refuses_an_event_without_identity(tmp_path):
    raw = [{"id": "a", "temp": 95, "armed": True}, {"temp": 10, "armed": False}]
    decoded = [{"id": "a", "facet_route": "critical"}, {"facet_route": "ok"}]
    result = _run(tmp_path, raw, decoded, "--id-field", "id")
    assert result.returncode == 1 and "2 without identity" in result.stdout
