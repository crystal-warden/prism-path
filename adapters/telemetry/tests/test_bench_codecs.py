"""The benchmark measures nothing trustworthy unless its codecs are correct. Pin the round-trips."""
import sys
from pathlib import Path

import pytest

_BENCH = Path(__file__).resolve().parent.parent / "bench"
sys.path.insert(0, str(_BENCH))
sys.path.insert(0, str(_BENCH.parent))       # adapter dir, for zeckendorf
import benchcodecs as C   # noqa: E402
import datagen as D  # noqa: E402


@pytest.mark.parametrize("regime", D.REGIMES)
def test_lossless_round_trips(regime):
    xs = D.channel(regime, 2000, seed=7)
    assert C.roundtrip_uvarint(xs) == xs                    # channel values are >= 0
    assert C.roundtrip_fib(xs) == xs
    assert C.roundtrip_delta_zigzag_fib(xs) == xs
    assert C.roundtrip_delta_zigzag_uvarint(xs) == xs


def test_transforms_invert():
    xs = [5, 5, 7, 3, 100, 100, 0, 42]
    assert C.undelta(C.delta(xs)) == xs
    for n in (-50, -1, 0, 1, 2, 999):
        assert C.unzigzag(C.zigzag(n)) == n


def test_fib_beats_fixed_on_small_deltas():
    xs = D.channel("quiet", 5000, seed=1)
    assert C.bits_delta_zigzag_fib(xs) < C.bits_fixed32(xs)


def test_all_codec_sizes_positive():
    xs = D.channel("moderate", 1000)
    for name, fn in C.CODECS.items():
        b = fn(xs)
        assert b is None or b > 0, name
