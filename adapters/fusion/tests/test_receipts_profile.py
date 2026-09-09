# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The receipt stream profile referee (PROTOCOL.md section 2.10).

Covers:
- Composition with the replay window (section 2.8): tick window checking over receipt sequence numbers
  rejects duplicate and stale receipt frames with their distinct cause codes.
- Composition with the concentrator profile (section 2.9): receipt stream readings aggregate into
  concentrated datagrams alongside other telemetry streams and demux cleanly.
"""
import sys
from pathlib import Path

import pytest

ADAPTER = Path(__file__).resolve().parent.parent
REPO = ADAPTER.parent.parent
sys.path.insert(0, str(REPO))

from prismpath.telemetry.concentrator import concentrate, demux, OK as CONC_OK  # noqa: E402
from prismpath import causes  # noqa: E402
from prismpath.telemetry.receipts import (  # noqa: E402
    OK as RCPT_OK,
    decode_receipt,
    encode_receipt,
    encode_receipt_symbols,
)
from prismpath.telemetry.replay import ACCEPT, REPLAY_DUPLICATE, REPLAY_STALE, TickWindow  # noqa: E402


def test_receipt_stream_composition_with_replay_window():
    win = TickWindow(reorder=2)
    # Stream of receipt frames with seq ticks 1, 2, 3
    frames = [
        (1, encode_receipt(seq=1, prev_node=0, event=2, next_node=1, cause_val=0)),
        (2, encode_receipt(seq=2, prev_node=1, event=0, next_node=3, cause_val=36)),
        (3, encode_receipt(seq=3, prev_node=2, event=1, next_node=0, cause_val=52)),
    ]

    for tick, frame in frames:
        ok, cause_str = win.observe(tick)
        assert ok and cause_str == ACCEPT
        rcpt, status = decode_receipt(frame)
        assert status == RCPT_OK and rcpt["seq"] == tick

    # Replaying seq=2 (duplicate inside window)
    ok, cause_str = win.observe(2)
    assert not ok and cause_str == REPLAY_DUPLICATE

    # Replaying seq=0 (stale outside window)
    ok, cause_str = win.observe(0)
    assert not ok and cause_str == REPLAY_STALE


def test_receipt_stream_composition_with_concentrator():
    # Stream ID 10 is registered as a receipt stream (5 fields: cause, event, next_node, prev_node, seq)
    # Stream ID 1 is registered as a 3-field sensor stream
    registry = {1: 3, 10: 5}

    rcpt_syms1 = encode_receipt_symbols(seq=1, prev_node=0, event=2, next_node=1, cause_val=0)
    rcpt_syms2 = encode_receipt_symbols(seq=2, prev_node=1, event=0, next_node=3, cause_val=36)

    # Wire ints for receipt stream (symbol + 1)
    wire_ints_rcpt1 = [s + 1 for s in rcpt_syms1]
    wire_ints_rcpt2 = [s + 1 for s in rcpt_syms2]

    # Concentrated datagram containing telemetry and receipt records
    records = [
        (1, [2, 1, 5]),
        (10, wire_ints_rcpt1),
        (10, wire_ints_rcpt2),
    ]

    datagram = concentrate(records)
    demuxed, cause = demux(datagram, registry)
    assert cause == CONC_OK
    assert len(demuxed) == 3

    # Verify demuxed receipt stream records
    stream_id_rcpt, ints_out1 = demuxed[1]
    assert stream_id_rcpt == 10
    assert ints_out1 == wire_ints_rcpt1

    # Verify receipt decoding from concentrated wire ints
    syms_out1 = [w - 1 for w in ints_out1]
    assert syms_out1[0] == 0  # cause 0 (clean)
    assert syms_out1[4] == 1  # seq 1

    stream_id_rcpt2, ints_out2 = demuxed[2]
    assert stream_id_rcpt2 == 10
    syms_out2 = [w - 1 for w in ints_out2]
    assert syms_out2[0] == 36  # cause 36 (route:stuck)
    assert causes.name(syms_out2[0]) == "route:stuck"
    assert syms_out2[4] == 2  # seq 2
