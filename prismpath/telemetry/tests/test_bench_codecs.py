# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The benchmark measures nothing trustworthy unless its codecs are correct. Pin the round-trips."""
import sys
from pathlib import Path

import pytest

_BENCH = Path(__file__).resolve().parent.parent / "bench"
sys.path.insert(0, str(_BENCH))
sys.path.insert(0, str(_BENCH.parent))       # adapter dir, for zeckendorf
from prismpath.telemetry.bench import benchcodecs as codecs   # noqa: E402
from prismpath.telemetry.bench import datagen  # noqa: E402


@pytest.mark.parametrize("regime", datagen.REGIMES)
def test_lossless_round_trips(regime):
    xs = datagen.channel(regime, 2000, seed=7)
    assert codecs.roundtrip_uvarint(xs) == xs                    # channel values are >= 0
    assert codecs.roundtrip_fib(xs) == xs
    assert codecs.roundtrip_delta_zigzag_fib(xs) == xs
    assert codecs.roundtrip_delta_zigzag_uvarint(xs) == xs


def test_transforms_invert():
    xs = [5, 5, 7, 3, 100, 100, 0, 42]
    assert codecs.undelta(codecs.delta(xs)) == xs
    for value in (-50, -1, 0, 1, 2, 999):
        assert codecs.unzigzag(codecs.zigzag(value)) == value


def test_fib_beats_fixed_on_small_deltas():
    xs = datagen.channel("quiet", 5000, seed=1)
    assert codecs.bits_delta_zigzag_fib(xs) < codecs.bits_fixed32(xs)


def test_all_codec_sizes_positive():
    xs = datagen.channel("moderate", 1000)
    for name, fn in codecs.CODECS.items():
        bits = fn(xs)
        assert bits is None or bits > 0, name
