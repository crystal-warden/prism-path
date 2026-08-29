# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The receipt stream profile (PROTOCOL.md section 2.10): cause code carriage on the wire.

A receipt reading carries the fields proven by the kernel receipt struct: decision identifiers
(``prev_node``, ``event``, ``next_node``), frame sequence tick (``seq``), and the cause byte
(``cause``) defined in the refusal and deviation cause code registry (docs/design/spec-cause-codes.md).

Canonical field order is alphabetical: ``cause``, ``event``, ``next_node``, ``prev_node``, ``seq``.
The cause byte (range 0..255) is carried as an ordinary symbol (code + 1 under Zeckendorf coding)
so that cause 0 (a clean decision) maps to symbol 0 and wire integer 1 ("11"), making clean decisions
the densest symbol on the wire.

Pure functions with tuple returns for structural rejections, following the exact house patterns of
concentrator.py and replay.py.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Union

from prismpath import causes
import packed
import zeckendorf as z

RECEIPT_FIELDS = ("cause", "event", "next_node", "prev_node", "seq")

OK = "ok"
RECEIPT_TRUNCATED = "receipt-truncated"
RECEIPT_INVALID_CAUSE = "receipt-invalid-cause"
RECEIPT_FIELD_MISMATCH = "receipt-field-mismatch"


def encode_receipt_symbols(
    seq: int,
    prev_node: int,
    event: int,
    next_node: int,
    cause_val: Union[int, str] = causes.CAUSE_NONE,
) -> List[int]:
    """Convert receipt fields into symbol values (0-based cell indices) in canonical field order:
    [cause, event, next_node, prev_node, seq]. Accepts cause code as int (0..255) or registry name string.
    """
    if isinstance(cause_val, str):
        c_code = causes.code(cause_val)
        if c_code is None:
            raise ValueError(f"unknown cause name: {cause_val!r}")
        code_int = c_code
    else:
        code_int = int(cause_val)

    if not (0 <= code_int <= 255):
        raise ValueError(f"cause code out of range 0..255: {code_int}")

    for name, val in [("seq", seq), ("prev_node", prev_node), ("event", event), ("next_node", next_node)]:
        if val < 0:
            raise ValueError(f"{name} must be non-negative integer; got {val}")

    return [code_int, int(event), int(next_node), int(prev_node), int(seq)]


def encode_receipt_bits(
    seq: int,
    prev_node: int,
    event: int,
    next_node: int,
    cause_val: Union[int, str] = causes.CAUSE_NONE,
) -> str:
    """Encode receipt fields into a self-framing Zeckendorf bitstream."""
    syms = encode_receipt_symbols(seq, prev_node, event, next_node, cause_val)
    wire_ints = [s + 1 for s in syms]
    return z.encode_stream(wire_ints)


def encode_receipt(
    seq: int,
    prev_node: int,
    event: int,
    next_node: int,
    cause_val: Union[int, str] = causes.CAUSE_NONE,
) -> bytes:
    """Encode receipt fields into a word-packed Facet wire frame (bytes)."""
    bits = encode_receipt_bits(seq, prev_node, event, next_node, cause_val)
    return packed.pack(bits, 8)


def encode_receipt_dict(receipt: Dict[str, Any]) -> bytes:
    """Encode a receipt dict containing cause, event, next_node, prev_node, seq into wire bytes."""
    missing = [f for f in RECEIPT_FIELDS if f not in receipt]
    if missing:
        raise KeyError(f"receipt missing required fields: {missing}")
    return encode_receipt(
        seq=receipt["seq"],
        prev_node=receipt["prev_node"],
        event=receipt["event"],
        next_node=receipt["next_node"],
        cause_val=receipt["cause"],
    )


def decode_receipt_bits(bits: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """Decode a Zeckendorf bitstream into a receipt dict and cause status: (receipt_dict, status_cause).

    Returns (receipt_dict, "ok") on clean decode. On structural failure returns (None, rejection_cause),
    where rejection_cause is one of RECEIPT_TRUNCATED, RECEIPT_FIELD_MISMATCH, or RECEIPT_INVALID_CAUSE.
    """
    if not bits:
        return None, RECEIPT_TRUNCATED

    wire_ints = z.decode_stream(bits)
    if len(wire_ints) == 0:
        return None, RECEIPT_TRUNCATED
    if len(wire_ints) != len(RECEIPT_FIELDS):
        if len(wire_ints) < len(RECEIPT_FIELDS):
            return None, RECEIPT_TRUNCATED
        return None, RECEIPT_FIELD_MISMATCH

    syms = [w - 1 for w in wire_ints]
    cause_code = syms[0]
    if not (0 <= cause_code <= 255):
        return None, RECEIPT_INVALID_CAUSE

    rcpt = {
        "cause": cause_code,
        "cause_name": causes.name(cause_code),
        "event": syms[1],
        "next_node": syms[2],
        "prev_node": syms[3],
        "seq": syms[4],
    }
    return rcpt, OK


def decode_receipt(frame: bytes) -> Tuple[Optional[Dict[str, Any]], str]:
    """Decode a packed byte frame into a receipt dict and cause status: (receipt_dict, status_cause)."""
    if not frame:
        return None, RECEIPT_TRUNCATED
    bits = packed.unpack(frame)
    return decode_receipt_bits(bits)
