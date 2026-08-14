"""Field projections for the fusion_triage flow — both cyber paths and the IMU normalization.

Two cyber paths feed the SAME field contract:

- `soc_action_from_level` — the DECIDABLE projection, used by the month-scale census where
  calling an adjudicator per alert is neither viable nor needed. Its constants are not invented
  here: 12 is the triage flow's own containment edge (`rule_level >= 12` -> stage_containment),
  7 is that flow's triage floor, and the fallback mirrors the escalation-default. Artifacts fed
  by this path must say so.
- `soc_action_from_verdict` — the adjudicator path, for any decision source that emits a
  `recommended_action`: only that field is consumed, and anything missing or out-of-vocabulary
  clamps to "watch" (escalation-default, never silent-benign).

The IMU side normalizes the sensor bridge's NDJSON rows (`prismpath-hw/bridge/field_bridge.py`)
across the observed schema drift: session1 predates the `dev_mg` field and uses the raw
stability-classifier label "On Table"; later sessions emit canonical labels and native dev_mg.
"""
from __future__ import annotations

import math
from typing import Any, Dict, Optional

SOC_ACTIONS = ("contain", "watch", "ignore")

# One standard gravity in the bridge's milli-units (it names the field dev_mg; the unit is
# milli-m/s^2, ~9806 == 1 g — the bridge's own naming, kept for schema compatibility).
_GRAVITY_MG = 9806

# Observed label drift only — session1's raw classifier label. Canonical labels pass through;
# anything unknown passes through lowercased and lands in the flow's OTHER cell (honest, visible).
_LABEL_MAP = {"on table": "still"}

CANONICAL_STABILITY = ("still", "moving", "shaken")

# The census baseline posture: the device's overwhelmingly typical state per the recorded
# sessions. Asserts nothing about the joint distribution — see census.py's pairing labels.
ASSUME_STILL = {"stability": "still", "dev_mg": 0}


def soc_action_from_level(level: int) -> str:
    """Decidable projection of a SIEM rule level onto the flow's soc_action vocabulary."""
    if level >= 12:
        return "contain"
    if level >= 7:
        return "watch"
    return "ignore"


def soc_action_from_verdict(verdict: Dict[str, Any]) -> str:
    """Real-adjudicator path; escalation-default clamp on anything unexpected."""
    rec = (verdict or {}).get("recommended_action") or "watch"
    return rec if rec in SOC_ACTIONS else "watch"


def normalize_imu(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Bridge NDJSON row -> canonical {stability, dev_mg, ts, derived} — or None when the row
    carries no physical posture at all (some fabric logs are pure routing records)."""
    stability = row.get("stability")
    accel = row.get("accel_mg")
    if stability is None and accel is None:
        return None

    label = str(stability).strip().lower() if stability is not None else "still"
    label = _LABEL_MAP.get(label, label)

    dev = row.get("dev_mg")
    derived = False
    if dev is None and isinstance(accel, (list, tuple)) and len(accel) == 3:
        # session1 support: instantaneous |magnitude - g|. NOT the bridge's peak-hold dev_mg —
        # flagged so callers can exclude derived rows (census default excludes them).
        ax, ay, az = accel
        dev = abs(int(round(math.sqrt(ax * ax + ay * ay + az * az))) - _GRAVITY_MG)
        derived = True

    return {
        "stability": label,
        "dev_mg": int(dev) if dev is not None else None,
        "ts": row.get("ts"),
        "derived": derived,
    }


def fused_reading(alert_level: int, soc_action: str, imu: Dict[str, Any]) -> Dict[str, Any]:
    """The one reading shape every path emits — exactly the flow's four decision fields."""
    if imu.get("dev_mg") is None:
        raise ValueError("imu posture has no dev_mg (derived excluded or missing) — cannot fuse")
    return {
        "stability": imu["stability"],
        "dev_mg": int(imu["dev_mg"]),
        "rule_level": int(alert_level),
        "soc_action": soc_action,
    }
