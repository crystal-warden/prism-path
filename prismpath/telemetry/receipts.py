# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The receipt stream profile (PROTOCOL.md section 2.10): cause code carriage on the wire.

A receipt reading carries the fields proven by the kernel receipt struct: decision identifiers
(``prev_node``, ``event``, ``next_node``), frame sequence tick (``seq``), and the cause byte
(``cause``) defined in the refusal and deviation cause code registry (docs/design/spec-cause-codes.md).

Canonical field order is alphabetical: ``cause``, ``event``, ``next_node``, ``prev_node``, ``seq``.
The cause code IS the symbol, carried under the standard symbol plus one wire mapping (PROTOCOL.md
section 2.2) with no special casing: cause 0 (a clean decision) rides as wire integer 1 ("11"), the
densest code on the wire, and the whole u8 registry space (0..255) is representable.

Two different things used to share the word `cause` here: the u8 registry code that rides the wire,
and the string naming why a decode was refused. They are `cause_code` and `refusal_cause` now, and a
decode returns them as the two named halves of `DecodedReceipt`. The wire is untouched: the canonical
field is still `cause`, carrying the code.

Pure functions with tuple returns for structural rejections, following the exact house patterns of
concentrator.py and replay.py.
"""
from __future__ import annotations

from typing import Any, Dict, List, NamedTuple, Optional, Union

from prismpath.kernel import causes
from prismpath.telemetry import packed
from prismpath.telemetry import zeckendorf as zeck

RECEIPT_FIELDS = ("cause", "event", "next_node", "prev_node", "seq")

OK = "ok"
RECEIPT_TRUNCATED = "receipt-truncated"
RECEIPT_INVALID_CAUSE = "receipt-invalid-cause"
RECEIPT_FIELD_MISMATCH = "receipt-field-mismatch"


class DecodedReceipt(NamedTuple):
    """The result of a decode, with its two halves named apart.

    `refusal_cause` is why the decode was refused (OK when it was not); it is a decoder status
    string and never a registry cause name. The registry code the frame carried is
    `receipt["cause"]`, with its registry name under `receipt["cause_name"]`.
    """

    receipt: Optional[Dict[str, Any]]
    refusal_cause: str


def encode_receipt_symbols(
    seq: int,
    prev_node: int,
    event: int,
    next_node: int,
    cause_code: Union[int, str] = causes.CAUSE_NONE,
) -> List[int]:
    """Convert receipt fields into symbol values (0-based cell indices) in canonical field order:
    [cause, event, next_node, prev_node, seq]. Accepts cause code as int (0..255) or registry name string.
    """
    if isinstance(cause_code, str):
        resolved_code = causes.code(cause_code)
        if resolved_code is None:
            raise ValueError(f"unknown cause name: {cause_code!r}")
    else:
        resolved_code = int(cause_code)

    if not (0 <= resolved_code <= 255):
        raise ValueError(f"cause code out of range 0..255: {resolved_code}")

    for name, val in [("seq", seq), ("prev_node", prev_node), ("event", event), ("next_node", next_node)]:
        if val < 0:
            raise ValueError(f"{name} must be non-negative integer; got {val}")

    return [resolved_code, int(event), int(next_node), int(prev_node), int(seq)]


def encode_receipt_bits(
    seq: int,
    prev_node: int,
    event: int,
    next_node: int,
    cause_code: Union[int, str] = causes.CAUSE_NONE,
) -> str:
    """Encode receipt fields into a self-framing Zeckendorf bitstream."""
    syms = encode_receipt_symbols(seq, prev_node, event, next_node, cause_code)
    wire_ints = [symbol + 1 for symbol in syms]
    return zeck.encode_stream(wire_ints)


def encode_receipt(
    seq: int,
    prev_node: int,
    event: int,
    next_node: int,
    cause_code: Union[int, str] = causes.CAUSE_NONE,
) -> bytes:
    """Encode receipt fields into a word-packed Facet wire frame (bytes)."""
    bits = encode_receipt_bits(seq, prev_node, event, next_node, cause_code)
    return packed.pack(bits, 8)


def encode_receipt_dict(receipt: Dict[str, Any]) -> bytes:
    """Encode a receipt dict containing cause, event, next_node, prev_node, seq into wire bytes."""
    missing = [field for field in RECEIPT_FIELDS if field not in receipt]
    if missing:
        raise KeyError(f"receipt missing required fields: {missing}")
    return encode_receipt(
        seq=receipt["seq"],
        prev_node=receipt["prev_node"],
        event=receipt["event"],
        next_node=receipt["next_node"],
        cause_code=receipt["cause"],
    )


def decode_receipt_bits(bits: str) -> DecodedReceipt:
    """Decode a Zeckendorf bitstream into (receipt, refusal_cause).

    Returns (receipt_dict, OK) on clean decode. On structural failure returns (None, refusal_cause),
    where refusal_cause is one of RECEIPT_TRUNCATED, RECEIPT_FIELD_MISMATCH, or RECEIPT_INVALID_CAUSE.
    """
    if not bits:
        return DecodedReceipt(None, RECEIPT_TRUNCATED)

    wire_ints = zeck.decode_stream(bits)
    if len(wire_ints) == 0:
        return DecodedReceipt(None, RECEIPT_TRUNCATED)
    if len(wire_ints) != len(RECEIPT_FIELDS):
        if len(wire_ints) < len(RECEIPT_FIELDS):
            return DecodedReceipt(None, RECEIPT_TRUNCATED)
        return DecodedReceipt(None, RECEIPT_FIELD_MISMATCH)

    syms = [wire_int - 1 for wire_int in wire_ints]
    cause_code = syms[0]
    if not (0 <= cause_code <= 255):
        return DecodedReceipt(None, RECEIPT_INVALID_CAUSE)

    rcpt = {
        "cause": cause_code,
        "cause_name": causes.name(cause_code),
        "event": syms[1],
        "next_node": syms[2],
        "prev_node": syms[3],
        "seq": syms[4],
    }
    return DecodedReceipt(rcpt, OK)


def decode_receipt(frame: bytes) -> DecodedReceipt:
    """Decode a packed byte frame into (receipt, refusal_cause)."""
    if not frame:
        return DecodedReceipt(None, RECEIPT_TRUNCATED)
    bits = packed.unpack(frame)
    return decode_receipt_bits(bits)
