"""canary_verify is the cutover gate: exit 0 only on perfect route parity between a canary's raw
JSON leg and its decoded Facet leg, with any daylight named by position and route. It must also
keep positions synchronized when the encoder legitimately dropped events (on_missing)."""
import json
import subprocess
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent.parent.parent
_VERIFY = _REPO / "integrations" / "vector" / "canary_verify.py"

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
    rawf.write_text("".join(json.dumps(e) + "\n" for e in raw))
    decf = tmp_path / "decoded.ndjson"
    decf.write_text("".join(json.dumps(e) + "\n" for e in decoded))
    return subprocess.run(
        [sys.executable, str(_VERIFY), str(flow), "--raw", str(rawf), "--decoded", str(decf),
         "--route-node", "classify", *extra],
        capture_output=True, text=True)


def test_parity_exits_zero(tmp_path):
    decoded = [{"facet_route": r} for r in _ROUTES]
    r = _run(tmp_path, _RAW, decoded)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "**PARITY.**" in r.stdout


def test_route_mismatch_named_by_position(tmp_path):
    decoded = [{"facet_route": r} for r in ["critical", "ok", "ok"]]   # position 1 skewed
    r = _run(tmp_path, _RAW, decoded)
    assert r.returncode == 1
    assert "event 1" in r.stdout and "`warn`" in r.stdout and "NO PARITY" in r.stdout


def test_count_drift_flagged(tmp_path):
    decoded = [{"facet_route": r} for r in _ROUTES[:2]]                # one decoded event lost
    r = _run(tmp_path, _RAW, decoded)
    assert r.returncode == 1 and "COUNT DRIFT" in r.stdout


def test_encoder_dropped_events_keep_positions_synced(tmp_path):
    raw = [_RAW[0], {"temp": 60}, _RAW[2]]            # middle event lacks `armed`: encoder dropped it
    decoded = [{"facet_route": "critical"}, {"facet_route": "ok"}]
    r = _run(tmp_path, raw, decoded)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "1 not encodable" in r.stdout and "**PARITY.**" in r.stdout


def test_map_applies_to_raw_leg(tmp_path):
    raw = [{"sensor": {"temp": 95}, "armed": True}, {"sensor": {"temp": 10}, "armed": False}]
    decoded = [{"facet_route": "critical"}, {"facet_route": "ok"}]
    r = _run(tmp_path, raw, decoded, "--map", "temp=sensor.temp")
    assert r.returncode == 0, r.stdout + r.stderr
