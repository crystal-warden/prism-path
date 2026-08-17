# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""projection.py — the decidable cyber projection, the verdict clamp, IMU normalization,
and an end-to-end pass over the REAL recorded sensor sessions (read-only, in-repo)."""
import json
import math
from pathlib import Path

import pytest

import projection as pj

REPO = Path(__file__).resolve().parents[3]
HW_EVIDENCE = REPO / "prismpath-hw" / "evidence"

# The sessions that carry physical posture (the two small fabric logs are pure routing records).
POSTURE_SESSIONS = [
    "mac_bridge_session1.ndjson",
    "mac_bridge_sessions2-5.ndjson",
    "fabric_session1.ndjson",
]
NO_POSTURE_SESSIONS = ["fabric_recert_float_chained.ndjson", "fabric_hotswap_midstream.ndjson"]


# ------------------------------------------------------------- cyber projection

@pytest.mark.parametrize("level,expected", [
    (0, "ignore"), (3, "ignore"), (6, "ignore"),
    (7, "watch"), (11, "watch"),
    (12, "contain"), (15, "contain"),
])
def test_projection_matrix(level, expected):
    assert pj.soc_action_from_level(level) == expected


def test_projection_is_monotone_in_severity():
    rank = {"ignore": 0, "watch": 1, "contain": 2}
    prev = -1
    for level in range(0, 20):
        cur = rank[pj.soc_action_from_level(level)]
        assert cur >= prev
        prev = cur


@pytest.mark.parametrize("verdict,expected", [
    ({"recommended_action": "contain"}, "contain"),
    ({"recommended_action": "watch"}, "watch"),
    ({"recommended_action": "ignore"}, "ignore"),
    ({"recommended_action": "nuke_it"}, "watch"),   # out-of-vocabulary clamps up, never down
    ({"recommended_action": None}, "watch"),
    ({}, "watch"),
    (None, "watch"),
])
def test_verdict_clamp_is_escalation_default(verdict, expected):
    assert pj.soc_action_from_verdict(verdict) == expected


# ------------------------------------------------------------ IMU normalization

def test_session1_label_drift_maps_to_still():
    row = {"stability": "On Table", "accel_mg": [66, -363, 9691], "ts": 1.0}
    out = pj.normalize_imu(row)
    assert out["stability"] == "still"
    assert out["derived"] is True
    expected = abs(int(round(math.sqrt(66**2 + 363**2 + 9691**2))) - 9806)
    assert out["dev_mg"] == expected


def test_canonical_row_passes_through_native_dev_mg():
    row = {"stability": "shaken", "dev_mg": 3100, "accel_mg": [0, 0, 9806], "ts": 2.0}
    out = pj.normalize_imu(row)
    assert out == {"stability": "shaken", "dev_mg": 3100, "ts": 2.0, "derived": False}


def test_unknown_label_passes_through_lowercased_for_the_other_cell():
    out = pj.normalize_imu({"stability": "In Motion", "dev_mg": 10})
    assert out["stability"] == "in motion"   # not silently coerced; lands in OTHER


def test_row_without_posture_is_none():
    assert pj.normalize_imu({"decision": "watch", "us": 128.4, "error_rate": 0}) is None


# ------------------------------------------------------------- fused contract

def test_fused_reading_contract():
    imu = {"stability": "still", "dev_mg": 0, "derived": False}
    r = pj.fused_reading(8, "watch", imu)
    assert r == {"stability": "still", "dev_mg": 0, "rule_level": 8, "soc_action": "watch"}


def test_fused_reading_refuses_missing_dev_mg():
    with pytest.raises(ValueError):
        pj.fused_reading(8, "watch", {"stability": "still", "dev_mg": None})


# ----------------------------------------- the real sessions, end to end (read-only)

@pytest.mark.parametrize("fname", POSTURE_SESSIONS)
def test_real_session_normalizes_fully(fname):
    path = HW_EVIDENCE / fname
    if not path.exists():
        pytest.skip(f"{fname} not present in this checkout")
    n = dropped = uncanonical = missing_dev = 0
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        out = pj.normalize_imu(json.loads(line))
        n += 1
        if out is None:
            dropped += 1
            continue
        if out["stability"] not in pj.CANONICAL_STABILITY:
            uncanonical += 1
        if out["dev_mg"] is None:
            missing_dev += 1
    assert n > 0
    assert dropped == 0, "posture sessions must not drop rows"
    assert uncanonical == 0, "every real label must canonicalize (drift map incomplete)"
    assert missing_dev == 0, "every posture row must yield dev_mg (native or derived)"


@pytest.mark.parametrize("fname", NO_POSTURE_SESSIONS)
def test_pure_routing_logs_are_excluded(fname):
    path = HW_EVIDENCE / fname
    if not path.exists():
        pytest.skip(f"{fname} not present in this checkout")
    rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    assert all(pj.normalize_imu(r) is None for r in rows)
