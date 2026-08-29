# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Unit and conformance tests for the receipt stream profile (PROTOCOL.md section 2.10).

Covers:
- Byte-exact conformance vectors for cause 0 (clean), cause 36 (route:stuck), wire-band cause 52
  (replay-duplicate), and u8 maximum 255.
- Byte-identical round trips: encode -> decode -> re-encode produces exact input bytes.
- Density property: cause 0 encodes to symbol 0 / wire integer 1 ("11"), smallest possible.
- Cause lookup flexibility: passing cause as name string ("route:stuck") or integer code.
- Structural rejections: truncated frames, field mismatch, out-of-range cause codes.
"""
import json
import sys
from pathlib import Path

import pytest

ADAPTER = Path(__file__).resolve().parent.parent
REPO = ADAPTER.parent.parent
sys.path.insert(0, str(ADAPTER))
sys.path.insert(0, str(REPO))

from prismpath import causes  # noqa: E402
from receipts import (
    OK,
    RECEIPT_FIELD_MISMATCH,
    RECEIPT_INVALID_CAUSE,
    RECEIPT_TRUNCATED,
    decode_receipt,
    decode_receipt_bits,
    encode_receipt,
    encode_receipt_bits,
    encode_receipt_dict,
    encode_receipt_symbols,
)  # noqa: E402

FIXTURE_PATH = ADAPTER / "conformance" / "receipts.json"


def test_conformance_vectors_from_fixture():
    with open(FIXTURE_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["vectors"]:
        fields = vec["fields"]
        expected_syms = vec["canonical_symbols"]
        expected_wire_ints = vec["wire_ints"]
        expected_bits = vec["bits"]
        expected_hex = vec["hex_bytes"]

        syms = encode_receipt_symbols(
            seq=fields["seq"],
            prev_node=fields["prev_node"],
            event=fields["event"],
            next_node=fields["next_node"],
            cause_val=fields["cause"],
        )
        assert syms == expected_syms, f"{vec['name']}: symbols {syms} != {expected_syms}"

        wire_ints = [s + 1 for s in syms]
        assert wire_ints == expected_wire_ints, f"{vec['name']}: wire_ints {wire_ints} != {expected_wire_ints}"

        bits = encode_receipt_bits(
            seq=fields["seq"],
            prev_node=fields["prev_node"],
            event=fields["event"],
            next_node=fields["next_node"],
            cause_val=fields["cause"],
        )
        assert bits == expected_bits, f"{vec['name']}: bits {bits} != {expected_bits}"

        frame = encode_receipt(
            seq=fields["seq"],
            prev_node=fields["prev_node"],
            event=fields["event"],
            next_node=fields["next_node"],
            cause_val=fields["cause"],
        )
        assert frame.hex() == expected_hex, f"{vec['name']}: hex {frame.hex()} != {expected_hex}"

        # Round trip test
        decoded, status = decode_receipt(frame)
        assert status == OK
        assert decoded is not None
        assert decoded["cause"] == fields["cause"]
        assert decoded["event"] == fields["event"]
        assert decoded["next_node"] == fields["next_node"]
        assert decoded["prev_node"] == fields["prev_node"]
        assert decoded["seq"] == fields["seq"]

        # Re-encode decoded dict must produce byte-identical frame
        re_encoded = encode_receipt_dict(decoded)
        assert re_encoded == frame


def test_cause_zero_density():
    """Cause 0 (clean decision) encodes as wire int 1 -> '11' (2 bits), densest symbol."""
    syms = encode_receipt_symbols(seq=1, prev_node=0, event=0, next_node=0, cause_val=0)
    assert syms[0] == 0
    bits = encode_receipt_bits(seq=1, prev_node=0, event=0, next_node=0, cause_val=0)
    assert bits.startswith("11")  # First field 'cause' is '11'


def test_encode_with_cause_name_string():
    frame_code = encode_receipt(seq=1, prev_node=0, event=2, next_node=3, cause_val=36)
    frame_name = encode_receipt(seq=1, prev_node=0, event=2, next_node=3, cause_val="route:stuck")
    assert frame_code == frame_name

    decoded, status = decode_receipt(frame_name)
    assert status == OK
    assert decoded["cause"] == 36
    assert decoded["cause_name"] == "route:stuck"


def test_encode_validation_raises():
    with pytest.raises(ValueError):
        encode_receipt(seq=1, prev_node=0, event=0, next_node=0, cause_val=256)
    with pytest.raises(ValueError):
        encode_receipt(seq=1, prev_node=0, event=0, next_node=0, cause_val=-1)
    with pytest.raises(ValueError):
        encode_receipt(seq=1, prev_node=0, event=0, next_node=0, cause_val="invalid_name")
    with pytest.raises(ValueError):
        encode_receipt(seq=-1, prev_node=0, event=0, next_node=0, cause_val=0)


def test_decode_rejections():
    assert decode_receipt(b"") == (None, RECEIPT_TRUNCATED)
    assert decode_receipt_bits("") == (None, RECEIPT_TRUNCATED)

    # Incomplete frame (only 2 fields encoded)
    bits_short = "110011"
    assert decode_receipt_bits(bits_short) == (None, RECEIPT_TRUNCATED)

    # Extra fields (6 fields encoded)
    bits_long = "11001101111011011"
    assert decode_receipt_bits(bits_long) == (None, RECEIPT_FIELD_MISMATCH)


def test_decode_out_of_range_cause():
    # Construct wire ints with cause symbol = 300 (wire int 301)
    import packed
    import zeckendorf as z

    wire_ints = [301, 1, 1, 1, 1]
    bits = z.encode_stream(wire_ints)
    frame = packed.pack(bits, 8)

    decoded, status = decode_receipt(frame)
    assert decoded is None
    assert status == RECEIPT_INVALID_CAUSE
