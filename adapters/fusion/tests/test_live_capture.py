"""live_capture.py — offline tests for the join, the multimodal summary, and the privacy
regression against the committed coincident artifacts. The live sensor/SIEM paths are opt-in
(`-m live`) and exercised by hand on the rig; everything here runs without hardware."""
import json
import re
from pathlib import Path

import pytest

import live_capture as lc

ADAPTER = Path(__file__).resolve().parent.parent


def _post(stab, dev, ts):
    return {"stability": stab, "dev_mg": dev, "ts": ts, "derived": False}


# ------------------------------------------------------------------- the join

def test_join_matches_worst_posture_and_routes():
    postures = [_post("still", 0, t) for t in range(90, 210)]
    postures += [_post("shaken", 6000, 100.0), _post("shaken", 6000, 100.5)]
    # watch@quiet -> cyber_watch ; contain@shake -> coincident_critical ; watch@shake -> physical_escalation
    alerts = [(200.0, 8), (100.1, 12), (100.2, 8)]
    c = lc.join_and_census(postures, alerts, window=3.0)
    assert c["alerts_matched_to_posture"] == 3
    assert c["bands"]["cyber_watch"] == 1
    assert c["bands"]["coincident_critical"] == 1
    assert c["bands"]["physical_escalation"] == 1
    assert sum(c["bands"].values()) == 3


def test_unmatched_alert_is_counted_not_dropped():
    postures = [_post("still", 0, 100.0)]
    alerts = [(100.0, 5), (500.0, 5)]  # second is far outside the ±window
    c = lc.join_and_census(postures, alerts, window=3.0)
    assert c["alerts_matched_to_posture"] == 1
    assert c["alerts_unmatched"] == 1


# ------------------------------------------------------------- multimodal summary

def test_multimodal_summary_shape_and_bandwidth():
    rows = [{"stability": "still", "dev_mg": 0, "accel_mg": [0, 0, 9806],
             "orientation": {"roll": 1.0, "pitch": -2.0, "yaw": 10.0, "tilt_deg": 1.2},
             "chip_stability": "On Table", "ts": 100.0 + i * 0.1} for i in range(20)]
    rows += [{"stability": "shaken", "dev_mg": 6000, "accel_mg": [3000, 0, 9000],
              "orientation": {"roll": 40.0, "pitch": -30.0, "yaw": 120.0, "tilt_deg": 50.0},
              "chip_stability": "Motion", "ts": 102.0 + i * 0.1} for i in range(10)]
    m = lc.multimodal_summary(rows)
    assert m["n_rich_readings"] == 30
    assert m["orientation_deg"]["tilt_deg"] == {"min": 1.2, "max": 50.0}
    assert m["chip_stability_verdicts"] == {"On Table": 20, "Motion": 10}
    # still->On Table and shaken->Motion both agree on the still/not-still binary
    assert m["derived_vs_chip_still_agreement"] == 1.0
    bw = m["bandwidth"]
    assert bw["standard_multimodal_json_bytes_per_reading"] > bw["physical_decision_bits_per_reading"]
    assert bw["ratio_json_over_decision"] > 1


def test_no_rich_rows_yields_no_multimodal():
    assert lc.multimodal_summary([{"stability": "still", "dev_mg": 0, "ts": 1.0}]) is None


# ------------------------------------------------------------- privacy regression

FORBIDDEN = {"agent", "agents", "srcip", "src_ip", "description", "full_log", "hostname", "id"}
SUBS = ["gx10", "warden-node", "opnsense", "vm101"]
IP = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def _walk(o, p="$"):
    if isinstance(o, dict):
        for k, v in o.items():
            assert k.lower() not in FORBIDDEN, f"forbidden key {k!r} at {p}"
            _walk(v, f"{p}.{k}")
    elif isinstance(o, list):
        for i, v in enumerate(o):
            _walk(v, f"{p}[{i}]")
    elif isinstance(o, str):
        low = o.lower()
        for s in SUBS:
            assert s not in low, f"forbidden substring {s!r} at {p}"
        assert not IP.search(o), f"IP-like value at {p}"


def test_committed_coincident_artifacts_are_aggregate_only():
    committed = sorted((ADAPTER / "evidence").glob("coincident_*.json"))
    if not committed:
        pytest.skip("no committed coincident artifact yet")
    for path in committed:
        _walk(json.loads(path.read_text()))
