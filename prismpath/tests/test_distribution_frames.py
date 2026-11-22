# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The frame binding (spec-policy-distribution.md, section 8.3): the six frame types and the reassembly of
B6, B7, B9 and B11. Each test names the conformance case of section 20 it covers. The release is the
corpus's round trip case, so what the assembler hands back is verified by the one verifier as a PEP would."""
import importlib.util
import json
import random
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.distribution import frames  # noqa: E402
from prismpath.distribution import verify as verifier  # noqa: E402
from prismpath.distribution.kinds import Refused  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
CORPUS = json.loads((REPO / "portable" / "conformance" / "distribution.json").read_text(encoding="utf-8"))
ROUND_TRIP = next(case for case in CORPUS["cases"] if case["name"] == "001_round_trip")
SEALED, BODY = bytes.fromhex(ROUND_TRIP["sealed"]), bytes.fromhex(ROUND_TRIP["body"])
LIMIT = 64                                         # a small link limit, so each part takes several chunks


def _generator():
    spec = importlib.util.spec_from_file_location("gen_distribution_corpus",
                                                  REPO / "portable" / "gen_distribution_corpus.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEN = _generator()


def _verify(sealed, body):
    return verifier.verify(sealed, body, trust=GEN.trust_store(),
                           pep=verifier.PepView("host", GEN.STREAM, qualification=GEN.QUALIFICATION), now=GEN.NOW)


def _through_v8(sealed):
    return verifier.verify_through_v8(sealed, trust=GEN.trust_store(),
                                      pep=verifier.PepView("host", GEN.STREAM, qualification=GEN.QUALIFICATION),
                                      now=GEN.NOW)


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


def _assembler(ordered=False, clock=None, artifact_bound=env.MAX_BODY):
    return frames.Assembler(frames.admit_through_v8(_through_v8), clock=clock or Clock(), ordered=ordered,
                            limit=LIMIT, artifact_bound=artifact_bound)


def _frames(transfer=7, sealed=SEALED, body=BODY):
    return list(frames.frames_for(transfer, sealed, body, LIMIT))


def _feed(assembler, sequence):
    return [event for event in (assembler.receive(data) for data in sequence) if event is not None]


def _staged(events):
    whole = [event for event in events if isinstance(event, frames.Assembled)]
    assert len(whole) == 1, events
    assert _verify(whole[0].sealed, whole[0].body).ok
    return whole[0]


# ------------------------------------------------------------------ the frame types

def test_every_frame_type_encodes_and_decodes_to_itself():
    policy = "ab" * 32
    for frame in (frames.Offer(1, b"\x01" * 16, 600, 52), frames.Chunk(2, frames.BODY, 40, b"xyz"),
                  frames.State(3, b"PPSR" + bytes(200)), frames.commit_for(4, "mesh/demo", 9, policy, 120),
                  frames.abort_for(5, "mesh/demo", 9, policy), frames.Epoch(6, 2 ** 64 - 1)):
        data = frames.encode(frame)
        assert frames.decode(data) == frame
        assert data[:2] == bytes([{frames.Offer: 1, frames.Chunk: 2, frames.State: 3, frames.Commit: 4,
                                   frames.Abort: 5, frames.Epoch: 6}[type(frame)], 1])
    assert len(frames.encode(frames.Offer(1, b"\x01" * 16, 600, 52))) == 26
    assert len(frames.encode(frames.commit_for(4, "s", 1, policy))) == 46
    assert len(frames.encode(frames.abort_for(4, "s", 1, policy))) == 44


def test_a_state_frame_carries_a_signed_state_record_whole():
    """Frame type 3 carries one state record (H1), which reads back under the PEP's instance key."""
    from prismpath.distribution import state_record as sr
    from prismpath.tests import _dist
    key = _dist.instance_key()
    record = sr.StateRecord(event="staged", state="active", cause=None, pep_id=sr.pep_id(key.public_raw), counter=3,
                            time=_dist.NOW, stream=sr.stream_prefix(_dist.STREAM), active_seq=1, floor=1, staged=True)
    signed = sr.build(record, key)
    data = frames.encode(frames.State(9, signed))
    assert len(data) <= frames.ESPNOW_LIMIT
    assert sr.read(frames.decode(data).record, key.public_raw) == record


def test_commit_and_abort_name_a_release_by_its_prefixes():
    policy = "cd" * 32
    commit = frames.commit_for(1, "mesh/demo", 3, policy, 120)
    assert commit.names("mesh/demo", 3, policy) and commit.delay_ms == 120
    assert not commit.names("mesh/other", 3, policy) and not commit.names("mesh/demo", 4, policy)
    assert not frames.abort_for(1, "mesh/demo", 3, policy).names("mesh/demo", 3, "ce" * 32)


@pytest.mark.parametrize("data", [
    b"\x01\x01",                                               # shorter than the header
    bytes([9, 1, 0, 0]),                                        # an unknown type
    bytes([6, 2, 0, 0]) + bytes(8),                             # another version
    bytes([1, 1, 0, 0]) + bytes(21),                            # an offer one byte short
    bytes([2, 1, 0, 0, 2, 0, 0, 0, 0, 1, 0, 0]),                # a chunk of part 2
    bytes([2, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0]),                # a chunk shorter than its length
    bytes([5, 1, 0, 0]) + bytes(16) + (2 ** 53).to_bytes(8, "little") + bytes(16),   # seq past 2^53 - 1
    bytes([3, 1, 0, 0]) + bytes(frames.ESPNOW_LIMIT),           # over the frame limit
])
def test_a_frame_that_does_not_read_is_frame_invalid(data):
    with pytest.raises(Refused) as refused:
        frames.decode(data)
    assert refused.value.cause == "dist:frame-invalid"
    assert frames.Assembler(lambda sealed: (0, "", "policy.ppt"), clock=Clock()).receive(data) == frames.Dropped(None,
                                                                                               "dist:frame-invalid")


def test_the_writer_refuses_what_the_reader_refuses():
    for frame in (frames.Offer(1, b"\x01" * 15, 600, 52), frames.Chunk(1, 2, 0, b"x"),
                  frames.Commit(1, b"\x00" * 16, 2 ** 53, b"\x00" * 16, 0), frames.State(1, bytes(frames.ESPNOW_LIMIT))):
        with pytest.raises(Refused):
            frames.encode(frame)


def test_the_sender_keeps_every_frame_within_the_link_limit_and_sends_in_offset_order():
    sequence = list(frames.frames_for(1, SEALED, BODY))
    assert all(len(data) <= frames.ESPNOW_LIMIT for data in sequence)
    chunks = [frames.decode(data) for data in sequence[1:]]
    assert b"".join(chunk.data for chunk in chunks if chunk.part == frames.SEALED) == SEALED
    assert b"".join(chunk.data for chunk in chunks if chunk.part == frames.BODY) == BODY
    assert all(len(data) <= LIMIT for data in _frames())


# ------------------------------------------------------------------ reassembly

def test_case_035_chunks_out_of_order_and_repeated_are_staged():
    """case_035: B6. The chunks of both parts arrive shuffled and twice over. A body chunk before the
    envelope is admitted is not read (B9), and its repeat completes the body."""
    offer, *chunks = _frames()
    shuffled = chunks * 2
    random.Random(35).shuffle(shuffled)
    events = _feed(_assembler(), [offer] + shuffled + chunks)
    whole = _staged(events)
    assert (whole.transfer, whole.sealed, whole.body) == (7, SEALED, BODY)


def test_case_036_a_chunk_past_the_offer_with_no_offer_or_a_part_with_a_wrong_hash_is_frame_invalid():
    """case_036: B6. Each drops the transfer, and nothing is staged."""
    offer, *chunks = _frames()
    past = frames.encode(frames.Chunk(7, frames.SEALED, len(SEALED) - 2, b"xyz"), LIMIT)
    assert _feed(_assembler(), [offer, past]) == [frames.Dropped(7, "dist:frame-invalid")]
    assert _feed(_assembler(), chunks[:1]) == [frames.Dropped(7, "dist:frame-invalid")]
    other = frames.encode(frames.Chunk(8, frames.SEALED, 0, b"x"), LIMIT)
    assembler = _assembler()
    assert _feed(assembler, [offer, other]) == [frames.Dropped(8, "dist:frame-invalid")]
    assert _staged(_feed(assembler, chunks)).sealed == SEALED       # the offered transfer is untouched

    tampered = bytearray(SEALED)
    tampered[-1] ^= 1                              # an envelope byte, so its id is not the offered one
    bad_sealed = [offer] + list(frames.frames_for(7, bytes(tampered), BODY, LIMIT))[1:]
    assert frames.Dropped(7, "dist:frame-invalid") in _feed(_assembler(), bad_sealed)
    bad_body = [offer] + _frames(body=BODY[:-1] + bytes([BODY[-1] ^ 1]))[1:]
    events = _feed(_assembler(), bad_body)
    assert events == [frames.Dropped(7, "dist:frame-invalid")]


def test_case_037_an_incomplete_transfer_is_dropped_silently_after_5_seconds_then_staged_when_sent_whole():
    """case_037: B7."""
    clock = Clock()
    assembler = _assembler(clock=clock)
    sequence = _frames()
    assert _feed(assembler, sequence[:-1]) == []
    clock.now += 5.001
    assert _feed(assembler, sequence[-1:]) == [frames.Dropped(7, "dist:frame-invalid")]   # its offer is gone
    assert assembler.transfer is None
    clock.now += 1
    assert _staged(_feed(assembler, sequence)).body == BODY


def test_case_121_a_relay_that_drops_repeats_and_corrupts_frames_stages_nothing_until_it_passes_them_whole():
    """case_121: B10. The relay holds no key and verifies nothing. What it drops costs a retry, what it
    corrupts is refused, and once it passes the frames whole the release is staged."""
    sequence = _frames()
    rng = random.Random(121)

    def relay(data: bytes) -> list:                # no key, no state, nothing to compromise but delivery
        roll = rng.random()
        if roll < 0.2:
            return []
        if roll < 0.4:
            return [data, data]
        if roll < 0.6:
            damaged = bytearray(data)
            damaged[-1] ^= 0xFF
            return [bytes(damaged)]
        return [data]

    assembler = _assembler()
    for _ in range(3):
        events = _feed(assembler, [out for data in sequence for out in relay(data)])
        assert not any(isinstance(event, frames.Assembled) for event in events)
    assert _staged(_feed(assembler, sequence)).sealed == SEALED


def test_an_ordered_link_drops_a_transfer_whose_chunk_is_out_of_order():
    """B11. In order the release is staged, and a chunk out of order or repeated drops the transfer."""
    offer, first, second, *rest = _frames()
    assert _staged(_feed(_assembler(ordered=True), [offer, first, second] + rest)).body == BODY
    assert _feed(_assembler(ordered=True), [offer, second]) == [frames.Dropped(7, "dist:frame-invalid")]
    assert _feed(_assembler(ordered=True), [offer, first, first]) == [frames.Dropped(7, "dist:frame-invalid")]


def test_no_body_is_read_for_an_envelope_that_fails_and_no_part_beyond_its_bound():
    """B9 and E6. A sealed envelope that fails its signature is refused with the verifier's cause and its
    body is never opened. An offer beyond 2,440 sealed bytes or the PEP's body bound, or whose body length
    is not the signed one, drops the transfer."""
    entries = env.unseal(SEALED)[1]
    forged = env.seal_entries(env.unseal(SEALED)[0], [(entries[0][0], bytes(64))])
    assembler = _assembler()
    offer, *chunks = _frames(sealed=forged)
    sealed_chunks = [data for data in chunks if frames.decode(data).part == frames.SEALED]
    events = _feed(assembler, [offer] + sealed_chunks)
    assert events == [frames.Dropped(7, "sig:invalid")] and assembler.transfer is None

    prefix = frames.hash_prefix(env.envelope_id(env.unseal(SEALED)[0]))
    too_long = frames.encode(frames.Offer(7, prefix, env.MAX_SEALED + 1, len(BODY)))
    assert _assembler().receive(too_long) == frames.Dropped(7, "dist:frame-invalid")
    over_both = frames.encode(frames.Offer(7, prefix, len(SEALED), 16385))
    assert _assembler(artifact_bound=len(BODY) - 1).receive(over_both) == frames.Dropped(7, "dist:too-large")
    small = _assembler(artifact_bound=len(BODY) - 1)                  # within the trust bound at the offer, and
    assert frames.Dropped(7, "dist:too-large") in _feed(small, _frames())   # over the artifact's once admitted
    longer = [frames.encode(frames.Offer(7, prefix, len(SEALED), len(BODY) + 1), LIMIT)] + _frames()[1:]
    assert frames.Dropped(7, "dist:frame-invalid") in _feed(_assembler(), longer)


def test_control_frames_pass_through_to_the_enforcement_point():
    commit = frames.commit_for(1, GEN.STREAM, 1, "ab" * 32, 120)
    epoch = frames.Epoch(2, 41)
    assembler = _assembler()
    assert _feed(assembler, [frames.encode(commit, LIMIT), frames.encode(epoch, LIMIT)]) == [commit, epoch]


def test_case_132_a_trust_body_offered_past_the_trust_bound_drops_the_transfer():
    """case_132: E6, B9, the frame half. On a mesh node, whose artifact bound is 640 bytes, a body offered at 16,385
    bytes is past both bounds and the transfer is dropped with dist:too-large before any part is read. A trust
    bound below 16,384 bytes cannot be set."""
    prefix = frames.hash_prefix(env.envelope_id(env.unseal(SEALED)[0]))
    node = frames.Assembler(frames.admit_through_v8(_through_v8), clock=Clock(), limit=LIMIT, artifact_bound=640)
    assert node.receive(frames.encode(frames.Offer(9, prefix, len(SEALED), 16385))) == frames.Dropped(9, "dist:too-large")
    assert node.transfer is None
    node.receive(frames.encode(frames.Offer(9, prefix, len(SEALED), 16384)))
    assert node.transfer is not None
    with pytest.raises(ValueError):
        frames.Assembler(frames.admit_through_v8(_through_v8), clock=Clock(), trust_bound=16383)
