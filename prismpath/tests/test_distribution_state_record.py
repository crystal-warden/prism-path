# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The state record (spec-policy-distribution.md, section 15.1). Each test names the conformance case it
covers."""
import pytest

pytest.importorskip("cryptography")

from prismpath.distribution import state_record as sr  # noqa: E402
from prismpath.distribution.kinds import Refused  # noqa: E402
from prismpath.tests import _dist  # noqa: E402


def _record(**changes):
    key = _dist.instance_key()
    fields = dict(event="committed", state="active", cause=None, pep_id=sr.pep_id(key.public_raw), counter=7,
                  time=_dist.NOW, stream=sr.stream_prefix(_dist.STREAM), active_policy=b"\x11" * 16,
                  active_release=b"\x22" * 16, active_seq=3, floor=3, staged_release=b"\x33" * 16, staged_seq=4,
                  trust_seq=2, epoch=9, staged=True, held=False)
    fields.update(changes)
    return key, sr.StateRecord(**fields)


def test_case_085_a_state_record_round_trips_and_a_changed_byte_is_invalid():
    """case_085: H1, H2, H6. Every field comes back, the layout is H1's, and any changed byte, a record of
    another PEP and a record under another key are fleet:state-invalid."""
    key, record = _record(body=b"facet", extensions=b"\x01\x00\x00")
    signed = sr.build(record, key)
    assert sr.read(signed, key.public_raw) == record
    assert signed[:4] == b"PPSR" and signed[4] == 1 and signed[5] == 3 and signed[6] == 0x81
    assert signed[24:32] == (7).to_bytes(8, "little") and signed[40:48] == (9).to_bytes(8, "little")
    assert signed[144:146] == (5).to_bytes(2, "little") and len(signed) == 144 + 2 + 5 + 2 + 3 + 64
    for index in range(len(signed)):
        changed = bytearray(signed)
        changed[index] ^= 0x01
        with pytest.raises(Refused) as refused:
            sr.read(bytes(changed), key.public_raw)
        assert refused.value.cause == "fleet:state-invalid"
    other = _dist.instance_key("J")
    for data, public in ((signed, other.public_raw), (sr.build(record, other), other.public_raw),
                         (signed[:-1], key.public_raw), (signed + b"\0", key.public_raw)):
        with pytest.raises(Refused):
            sr.read(data, public)


def test_the_status_byte_carries_the_staged_dev_build_and_held_bits():
    """H1: bit 7 staged, bit 6 dev build, bit 5 held, and the cause is the registered code."""
    key, record = _record(state="no-policy", staged=False, dev_build=True, held=True, cause="dist:held", event="held")
    signed = sr.build(record, key)
    assert signed[6] == 0x60 and signed[7] == 159 and signed[5] == 9
    assert sr.read(signed, key.public_raw).held
    with pytest.raises(ValueError):
        sr.build(_record(cause="no:such-cause")[1], key)
    with pytest.raises(ValueError):
        sr.build(_record(body=b"x" * 1025)[1], key)
