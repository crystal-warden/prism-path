# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Zeckendorf/Fibonacci codec — the wire's contract, pinned:
  * exact round-trip over positive integers;
  * doc-faithful small-integer codes (1->11, 2->011, 3->0011, 4->1011);
  * the self-framing invariant: the ONLY '11' in a code is its terminator (so a stream is
    self-delimiting and resynchronizes at the next boundary).
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import zeckendorf as z  # noqa: E402


# ---------------------------------------------------------------- doc-faithful small codes
@pytest.mark.parametrize("n,code", [
    (1, "11"), (2, "011"), (3, "0011"), (4, "1011"),
    (5, "00011"), (6, "10011"), (7, "01011"), (8, "000011"),
])
def test_small_codes_match_the_doc(n, code):
    assert z.encode(n) == code
    assert z.decode(code) == n


# ---------------------------------------------------------------- round-trip
@pytest.mark.parametrize("n", [1, 2, 3, 12, 99, 100, 1597, 6765, 10_000, 1_000_000])
def test_round_trip_spot(n):
    assert z.decode(z.encode(n)) == n


def test_round_trip_dense_range():
    for n in range(1, 5001):
        assert z.decode(z.encode(n)) == n, f"round-trip failed at {n}"


# ---------------------------------------------------------------- the self-framing invariant
@pytest.mark.parametrize("n", [1, 2, 3, 4, 17, 250, 4181, 99_999])
def test_only_terminator_is_11(n):
    code = z.encode(n)
    assert code.endswith("11"), code
    # the sole occurrence of '11' is the trailing terminator
    assert code.index("11") == len(code) - 2, f"internal '11' in {code!r}"
    # equivalently: the Zeckendorf part (terminator stripped) has no consecutive 1s
    assert "11" not in code[:-1], f"consecutive 1s in Zeckendorf part of {code!r}"


# ---------------------------------------------------------------- stream = concatenation, self-delimited
@pytest.mark.parametrize("values", [
    [1], [1, 1, 1], [4, 2, 7], [1, 4, 1, 100, 3],
    [10_000, 1, 2, 3, 6765], list(range(1, 200)),
])
def test_stream_round_trip(values):
    assert z.decode_stream(z.encode_stream(values)) == values


def test_small_ints_are_tiny():
    # delta-differenced telemetry lives on small ints; they must be short
    assert all(len(z.encode(n)) <= 6 for n in range(1, 9))


# ---------------------------------------------------------------- rejections
def test_rejects_non_positive():
    with pytest.raises(ValueError):
        z.encode(0)
    with pytest.raises(ValueError):
        z.encode(-3)


def test_rejects_non_code():
    with pytest.raises(ValueError):
        z.decode("10")        # does not end in '11'
    with pytest.raises(ValueError):
        z.decode("1")         # too short
