"""Word-packed wire contract: exact round-trip (pad dropped), real byte density, and word-padding that
amortizes away as the stream grows."""
import sys
from pathlib import Path

import pytest

_ADAPTER = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ADAPTER))
import packed as p     # noqa: E402
import zeckendorf as z  # noqa: E402


@pytest.mark.parametrize("word_bits", [8, 64])
@pytest.mark.parametrize("ints", [
    [1], [2], [1, 1, 1], [4, 2, 7, 100],
    list(range(1, 300)), [10_000, 1, 2, 3, 6765],
])
def test_round_trip(ints, word_bits):
    assert p.decode(p.encode(ints, word_bits), ) == ints


def test_output_is_whole_words():
    for word_bits in (8, 64):
        wire = p.encode(list(range(1, 200)), word_bits)
        assert len(wire) % (word_bits // 8) == 0        # exact number of words


def test_bits_survive_packing():
    bits = z.encode_stream([4, 2, 7])
    unpacked = p.unpack(p.pack(bits, 64))
    assert unpacked.startswith(bits)                    # original bits recovered; remainder is zero pad
    assert set(unpacked[len(bits):]) <= {"0"}


def test_padding_amortizes():
    small = p.padding_overhead(list(range(1, 11)))       # N=10
    big = p.padding_overhead(list(range(1, 100_001)))    # N=100k
    assert big["pad_pct"] < small["pad_pct"]            # final-word pad shrinks relative to the stream
    assert big["pad_pct"] < 1.0                          # negligible at scale


def test_wire_is_dense():
    ints = list(range(1, 1000))
    bits = len(z.encode_stream(ints))
    wire = p.encode(ints)
    # real bytes ~ bits/8 (vs the reference bit-string, which is one char per bit)
    assert len(wire) * 8 >= bits and len(wire) * 8 < bits + 64
