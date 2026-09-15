# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
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


def _walk(rng, sample_count: int, lo: int, hi: int, step: int) -> List[int]:
    steps = rng.integers(-step, step + 1, size=sample_count)
    xs = np.clip(np.cumsum(steps) + (lo + hi) // 2, lo, hi)
    return xs.astype(np.int64).tolist()


def channel(regime: str, sample_count: int, seed: int = 0) -> List[int]:
    """A single integer telemetry channel of length n for the codec bake-off."""
    rng = np.random.default_rng(seed)
    if regime == "quiet":
        return _walk(rng, sample_count, 0, 100, 5)
    if regime == "moderate":
        return _walk(rng, sample_count, 0, 10_000, 200)
    if regime == "wide":
        return _walk(rng, sample_count, 0, 1_000_000, 50_000)
    if regime == "spiky":
        xs = np.array(_walk(rng, sample_count, 0, 100, 5), dtype=np.int64)
        spike_count = max(1, sample_count // 100)                       # ~1% anomaly spikes
        idx = rng.choice(sample_count, size=spike_count, replace=False)
        xs[idx] = rng.integers(50_000, 1_000_000, size=spike_count)
        return xs.tolist()
    raise ValueError(f"unknown regime {regime!r}")


REGIMES = ("quiet", "moderate", "wide", "spiky")


# --------------------------------------------------------------- flow-reading streams (decision path)
def incident_readings(regime: str, sample_count: int, seed: int = 0):
    """Readings for the incident_severity flow: error_rate from a regime channel (clamped to 0..100,
    the field's real domain), plus occasional data_at_risk / user_facing flags."""
    rng = np.random.default_rng(seed + 1)
    er = [min(100, max(0, value % 101)) for value in channel(regime, sample_count, seed)]
    dar = rng.random(sample_count) < 0.03
    uf = rng.random(sample_count) < 0.30
    return [{"data_at_risk": bool(dar[sample_index]), "user_facing": bool(uf[sample_index]),
             "error_rate": er[sample_index]}
            for sample_index in range(sample_count)]


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


def wide_field_readings(regime: str, sample_count: int, seed: int = 0):
    """Readings for a flow that routes a WIDE-range field (temp, 0..1e6) on just two thresholds — the
    case where raw telemetry cost scales with magnitude but the decision telemetry does not."""
    return [{"temp": value} for value in channel("wide" if regime == "wide" else regime, sample_count, seed)]
