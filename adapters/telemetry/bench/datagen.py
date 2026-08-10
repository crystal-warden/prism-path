"""Seeded, reproducible telemetry generators. Realistic in the way that matters for delta-differencing:
consecutive samples are correlated (bounded random walks), not i.i.d. noise. The four regimes span the
value dynamic range — the axis Fibonacci coding is sensitive to.

  quiet     small range, small steps                     (Fibonacci's happy path)
  moderate  mid range                                     (typical)
  wide      large values, large-but-bounded steps         (stresses raw magnitude)
  spiky     small baseline + ~1% huge anomalies           (the honest Fibonacci-tax case)
"""
from __future__ import annotations

from typing import List

import numpy as np


def _walk(rng, n: int, lo: int, hi: int, step: int) -> List[int]:
    steps = rng.integers(-step, step + 1, size=n)
    xs = np.clip(np.cumsum(steps) + (lo + hi) // 2, lo, hi)
    return xs.astype(np.int64).tolist()


def channel(regime: str, n: int, seed: int = 0) -> List[int]:
    """A single integer telemetry channel of length n for the codec bake-off."""
    rng = np.random.default_rng(seed)
    if regime == "quiet":
        return _walk(rng, n, 0, 100, 5)
    if regime == "moderate":
        return _walk(rng, n, 0, 10_000, 200)
    if regime == "wide":
        return _walk(rng, n, 0, 1_000_000, 50_000)
    if regime == "spiky":
        xs = np.array(_walk(rng, n, 0, 100, 5), dtype=np.int64)
        k = max(1, n // 100)                       # ~1% anomaly spikes
        idx = rng.choice(n, size=k, replace=False)
        xs[idx] = rng.integers(50_000, 1_000_000, size=k)
        return xs.tolist()
    raise ValueError(f"unknown regime {regime!r}")


REGIMES = ("quiet", "moderate", "wide", "spiky")


# --------------------------------------------------------------- flow-reading streams (decision path)
def incident_readings(regime: str, n: int, seed: int = 0):
    """Readings for the incident_severity flow: error_rate from a regime channel (clamped to 0..100,
    the field's real domain), plus occasional data_at_risk / user_facing flags."""
    rng = np.random.default_rng(seed + 1)
    er = [min(100, max(0, v % 101)) for v in channel(regime, n, seed)]
    dar = rng.random(n) < 0.03
    uf = rng.random(n) < 0.30
    return [{"data_at_risk": bool(dar[i]), "user_facing": bool(uf[i]), "error_rate": er[i]}
            for i in range(n)]


WIDE_FIELD_FLOW = """---
name: sensor_guard
start: classify
---
## classify
-> critical: when temp >= 90000
-> warn: when temp >= 50000
-> ok: else
## critical
## warn
## ok
"""


def wide_field_readings(regime: str, n: int, seed: int = 0):
    """Readings for a flow that routes a WIDE-range field (temp, 0..1e6) on just two thresholds — the
    case where raw telemetry cost scales with magnitude but the decision telemetry does not."""
    return [{"temp": v} for v in channel("wide" if regime == "wide" else regime, n, seed)]
