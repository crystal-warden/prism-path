# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The concentrator referee (PROTOCOL.md section 2.9): round-trip, fail-closed strictness, and
the honest header-amortization measurement.

The measurement is the profile's reason to exist, so it is asserted, not narrated: per-reading
cost on an IP uplink for per-node datagrams vs one concentrated datagram, at fleet sizes 1 to
50. The envelope constant is IP+UDP (28 bytes); link-layer framing varies by medium and is
deliberately excluded (stated in the spec). The win is header amortization on IP uplinks; a
single-stream concentrated frame costs one extra byte over the bare frame (the stream id) and
the bench asserts that too, because the profile should never be sold for N=1.
"""
import sys
from pathlib import Path

ADAPTER = Path(__file__).resolve().parent.parent
REPO = ADAPTER.parent.parent
sys.path.insert(0, str(REPO / "adapters" / "telemetry"))

import packed                                          # noqa: E402
import zeckendorf as z                                 # noqa: E402
from concentrator import (CONCENTRATOR_TRUNCATED,      # noqa: E402
                          CONCENTRATOR_UNKNOWN_STREAM, OK, concentrate, demux)

IP_UDP = 28                                            # IPv4 (20) + UDP (8), per datagram

# A toy fleet: stream id -> field count (in real use: len(build_partitions(policy))).
REGISTRY = {1: 3, 2: 3, 3: 1, 7: 2}
READINGS = [(1, [2, 1, 5]), (2, [1, 1, 1]), (3, [4]), (7, [3, 610])]


# ------------------------------------------------------------------------------- round-trip
def test_round_trip():
    frame = concentrate(READINGS)
    out, cause = demux(frame, REGISTRY)
    assert cause == OK and out == READINGS


def test_round_trip_single_stream():
    frame = concentrate([(3, [4])])
    out, cause = demux(frame, REGISTRY)
    assert cause == OK and out == [(3, [4])]


def test_repeated_stream_in_one_datagram():
    """A stream may appear more than once (a burst since the last uplink tick)."""
    recs = [(3, [4]), (3, [5]), (3, [4])]
    out, cause = demux(concentrate(recs), REGISTRY)
    assert cause == OK and out == recs


# ------------------------------------------------------------------------------ fail closed
def test_unknown_stream_rejects_whole_datagram():
    frame = concentrate([(1, [2, 1, 5]), (99, [4]), (3, [4])])
    out, cause = demux(frame, REGISTRY)
    assert (out, cause) == ([], CONCENTRATOR_UNKNOWN_STREAM)


def test_truncated_record_rejects_whole_datagram():
    bits = z.encode(1) + z.encode_stream([2, 1])       # stream 1 declares 3 fields, sends 2
    out, cause = demux(packed.pack(bits, 8), REGISTRY)
    assert (out, cause) == ([], CONCENTRATOR_TRUNCATED)


def test_dangling_tail_rejects_whole_datagram():
    frame = concentrate(READINGS) + b"\x80"            # a 1-bit with no terminator
    out, cause = demux(frame, REGISTRY)
    assert (out, cause) == ([], CONCENTRATOR_TRUNCATED)


def test_empty_frame_is_empty_not_error():
    out, cause = demux(b"", REGISTRY)
    assert (out, cause) == ([], OK)


def test_bad_inputs_raise():
    import pytest
    with pytest.raises(ValueError):
        concentrate([(0, [1])])
    with pytest.raises(ValueError):
        concentrate([(1, [])])


# ------------------------------------------------------------- the honest measurement, frozen
def fleet_costs(n_nodes):
    """Per-reading uplink bytes at fleet size n: (per_node_datagrams, concentrated)."""
    per_reading_payload = len(packed.pack(z.encode_stream([2, 1, 5]), 8))
    per_node = per_reading_payload + IP_UDP
    recs = [(1, [2, 1, 5])] * n_nodes
    conc = (len(concentrate(recs)) + IP_UDP) / n_nodes
    return per_node, conc


def test_amortization_wins_for_fleets_and_not_for_one():
    per1, conc1 = fleet_costs(1)
    assert conc1 >= per1                               # N=1: no win, the stream id is pure cost
    for n in (2, 5, 10, 25, 50):
        per, conc = fleet_costs(n)
        assert conc < per, f"concentration must win at fleet size {n}"
    # frozen exact points so the numbers in the spec stay honest
    per50, conc50 = fleet_costs(50)
    assert per50 == 30                                 # 2B payload + 28B envelope
    assert round(conc50, 2) == 2.06                    # measured: 12-bit records, 28B amortized
    print("\n  fleet  per-node B/reading  concentrated B/reading")
    for n in (1, 2, 5, 10, 25, 50):
        per, conc = fleet_costs(n)
        print(f"  {n:>5}  {per:>17} {conc:>22.2f}")
