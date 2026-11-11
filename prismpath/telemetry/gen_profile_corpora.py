#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze the wire profile corpora: receipt streams (PROTOCOL.md section 2.10), the replay window (2.8),
the refresh profile (2.7) and the concentrator (2.9). Every expectation is produced by RUNNING the Python
reference module, so a port is measured against what Python actually does, and the Rust crate replays all
four files (`prismpath-telemetry-rs/tests/test_profile_*.rs`).

    python prismpath/telemetry/gen_profile_corpora.py     ->  conformance/{receipt_stream,replay,refresh,concentrator}.json

The frozen `receipts.json` stays as adopted; `receipt_stream.json` extends it with the whole registry,
every structural rejection and a seeded round trip. A seeded generator writes the random cases, so
regenerating on the same Python gives byte identical files and `git diff` is the review.

Where Python decodes an integer of any width, a case lists it under `wide` and the Rust crate, whose
fields are 64 bit, refuses it instead of wrapping (DIVERGENCES.md).
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from prismpath.kernel import causes                                   # noqa: E402
from prismpath.telemetry import concentrator, packed, receipts        # noqa: E402
from prismpath.telemetry import refresh, replay                       # noqa: E402
from prismpath.telemetry import zeckendorf as zeck                    # noqa: E402

OUT = HERE / "conformance"
SEED = 20261109
U64_MAX = 2**64 - 1


def _write(name: str, doc: dict) -> Path:
    path = OUT / name
    path.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


# ------------------------------------------------------------------------------------ receipts
def _receipt_json(receipt):
    return None if receipt is None else dict(receipt)


def _encode_case(name, fields):
    entry = {"name": name, "fields": dict(fields)}
    try:
        args = dict(seq=fields["seq"], prev_node=fields["prev_node"], event=fields["event"], next_node=fields["next_node"],
                    cause_code=fields["cause"])
        symbols = receipts.encode_receipt_symbols(**args)
        # a field of 2**64 - 1 needs the wire integer 2**64, which a 64 bit reader cannot hold
        entry["rust_overflow"] = any(value >= U64_MAX for value in symbols[1:])
        entry.update({"symbols": symbols, "wire_ints": [symbol + 1 for symbol in symbols],
                      "bits": receipts.encode_receipt_bits(**args), "hex": receipts.encode_receipt(**args).hex()})
    except ValueError as refusal:
        entry["refuse"] = str(refusal)
    return entry


def _decode_case(name, *, bits=None, frame=None):
    entry = {"name": name}
    if frame is not None:
        entry["hex"] = frame.hex()
        decoded = receipts.decode_receipt(frame)
    else:
        entry["bits"] = bits
        decoded = receipts.decode_receipt_bits(bits)
    entry["receipt"] = _receipt_json(decoded.receipt)
    entry["refusal_cause"] = decoded.refusal_cause
    entry["registry_cause"] = decoded.cause
    return entry


def receipt_stream_corpus() -> dict:
    rng = random.Random(SEED)
    base = {"seq": 1, "prev_node": 0, "event": 2, "next_node": 1}
    encode = []
    # the whole registry, once by code and once by name, so a drifted table is a failing case
    for cause_code, cause_name, _cls, _desc in causes._REGISTRY:
        fields = {"seq": rng.randrange(0, 5000), "prev_node": rng.randrange(0, 40), "event": rng.randrange(0, 40),
                  "next_node": rng.randrange(0, 40)}
        encode.append(_encode_case(f"code_{cause_code}", {**fields, "cause": cause_code}))
        encode.append(_encode_case(f"name_{cause_name}", {**fields, "cause": cause_name}))
    encode.append(_encode_case("code_0", {**base, "cause": 0}))
    # bytes no row holds (87, 100 and 101 were probes here until the registry appended rows at those codes)
    for cause_code in (150, 200, 254, 255):
        assert causes.name(cause_code) is None, f"{cause_code} is registered now; probe another byte"
        encode.append(_encode_case(f"unregistered_{cause_code}", {**base, "cause": cause_code}))
    for cause_code in (256, 1000, -1, -255):
        encode.append(_encode_case(f"refused_cause_{cause_code}", {**base, "cause": cause_code}))
    for cause_name in ("no-such-cause", "", "ROUTE:STUCK", "route:stuck "):
        encode.append(_encode_case(f"refused_name_{cause_name!r}", {**base, "cause": cause_name}))
    for field in ("seq", "prev_node", "event", "next_node"):
        for value in (-1, -2**40):
            encode.append(_encode_case(f"refused_negative_{field}_{value}", {**base, "cause": 0, field: value}))
    for value in (0, 1, 2, 7, 255, 256, 2**16, 2**31 - 1, 2**32, 2**53, 2**53 + 1, 2**63 - 1, 2**63, U64_MAX - 1, U64_MAX):
        encode.append(_encode_case(f"field_edge_{value}", {"seq": value, "prev_node": value, "event": value, "next_node": value, "cause": 52}))
    # seeded round trip material: magnitudes from one bit to sixty three
    for index in range(150):
        width = rng.randrange(1, 64)
        fields = {key: rng.getrandbits(width) for key in ("seq", "prev_node", "event", "next_node")}
        encode.append(_encode_case(f"seeded_{index}", {**fields, "cause": rng.choice([0, 0, 0, 36, 52, rng.randrange(0, 256)])}))

    decode = []
    for case in encode:
        if "hex" in case and not case["rust_overflow"] and case["name"].startswith(("code_", "seeded_", "field_edge_", "unregistered_")):
            decode.append(_decode_case(f"frame_of_{case['name']}", frame=bytes.fromhex(case["hex"])))
    ok_bits = receipts.encode_receipt_bits(3, 1, 0, 2, 36)
    ok_frame = receipts.encode_receipt(3, 1, 0, 2, 36)
    decode += [
        _decode_case("empty_frame", frame=b""), _decode_case("empty_bits", bits=""),
        _decode_case("zero_bits_only", bits="0000"), _decode_case("zero_frame", frame=b"\x00\x00"),
        _decode_case("one_field", bits=zeck.encode_stream([1])),
        _decode_case("four_fields", bits=zeck.encode_stream([1, 2, 3, 4])),
        _decode_case("six_fields", bits=zeck.encode_stream([1, 2, 3, 4, 5, 6])),
        _decode_case("many_fields", bits=zeck.encode_stream(list(range(1, 40)))),
        _decode_case("cause_256", bits=zeck.encode_stream([257, 1, 1, 1, 1])),
        _decode_case("cause_255", bits=zeck.encode_stream([256, 1, 1, 1, 1])),
        _decode_case("cause_beyond_byte_by_a_lot", bits=zeck.encode_stream([10**6, 1, 1, 1, 1])),
        _decode_case("partial_tail_after_a_whole_receipt", bits=ok_bits + "0101"),
        _decode_case("one_bit_tail_after_a_whole_receipt", bits=ok_bits + "1"),
        _decode_case("two_receipts_back_to_back", bits=ok_bits + ok_bits),
        _decode_case("frame_with_extra_zero_bytes", frame=ok_frame + b"\x00\x00\x00"),
        _decode_case("frame_with_a_trailing_byte_of_ones", frame=ok_frame + b"\xff"),
        _decode_case("a_whole_receipt_minus_its_last_bit", bits=ok_bits[:-1]),
        _decode_case("a_single_one_bit_has_no_complete_codeword", bits="1"),
        _decode_case("ones_with_no_adjacent_pair_have_no_complete_codeword", bits="10101"),
        _decode_case("a_cut_frame_with_a_dangling_codeword_after_a_whole_one", bits=zeck.encode_stream([1, 2]) + "1"),
        _decode_case("a_cut_frame_with_zero_bits_after_a_whole_codeword", bits=zeck.encode_stream([1, 2]) + "000"),
        _decode_case("six_fields_and_a_dangling_tail", bits=zeck.encode_stream([1, 2, 3, 4, 5, 6]) + "1"),
    ]
    for cut in range(1, len(ok_bits)):
        decode.append(_decode_case(f"prefix_{cut}_bits", bits=ok_bits[:cut]))
    for index in range(80):
        decode.append(_decode_case(f"random_bytes_{index}", frame=bytes(rng.randrange(256) for _ in range(rng.randrange(1, 12)))))
    for index in range(80):
        frame = bytearray(ok_frame)
        for _ in range(rng.randrange(1, 4)):
            frame[rng.randrange(len(frame))] ^= 1 << rng.randrange(8)
        decode.append(_decode_case(f"flipped_{index}", frame=bytes(frame)))

    # Integers wider than 64 bits: Python carries them, a 64 bit reader refuses them. A wide cause is
    # beyond the byte and is the invalid cause refusal in both.
    wide = []
    for name, wire_ints in [
        ("wide_seq", [1, 1, 1, 1, 2**64 + 5]), ("wide_event", [1, 2**70, 1, 1, 1]), ("wide_next_node", [1, 1, 2**64, 1, 1]),
        ("wide_prev_node", [1, 1, 1, 2**100, 1]), ("wide_cause", [2**64 + 1, 1, 1, 1, 1]),
        ("u64_max_wire_int", [1, 1, 1, 1, U64_MAX]), ("seq_u64_max", [1, 1, 1, 1, U64_MAX + 1]),
    ]:
        bits = zeck.encode_stream(wire_ints)
        decoded = receipts.decode_receipt_bits(bits)
        receipt = decoded.receipt
        wide.append({"name": name, "bits": bits, "refusal_cause": decoded.refusal_cause, "registry_cause": decoded.cause,
                     "rust_overflow": receipt is not None and any(wire_int > U64_MAX for wire_int in wire_ints[1:]),
                     "python_receipt": None if receipt is None else {key: (str(value) if isinstance(value, int) else value)
                                                                    for key, value in receipt.items()}})
    return {
        "version": 1,
        "comment": "FROZEN. Receipt stream profile (PROTOCOL.md section 2.10): encode and decode cases generated from "
                   "prismpath.telemetry.receipts by gen_profile_corpora.py. `encode` cases carry the symbols, wire integers, "
                   "bits and packed bytes, or `refuse`; `decode` cases carry the receipt or the refusal cause; `wide` cases "
                   "decode to an integer beyond 64 bits in Python, which the Rust crate refuses.",
        "fields": list(receipts.RECEIPT_FIELDS),
        "encode": encode, "decode": decode, "wide": wide,
    }


# --------------------------------------------------------------------------------------- replay
def _replay_case(name, reorder, ops):
    window = replay.TickWindow(reorder)
    expect = []
    for kind, tick in ops:
        ok, cause = window.check(tick) if kind == "check" else window.observe(tick)
        expect.append([ok, cause])
    return {"name": name, "reorder": reorder, "ops": [[kind, tick] for kind, tick in ops], "expect": expect,
            "state": {"top": window._top, "mask": window._mask}}


def replay_corpus() -> dict:
    rng = random.Random(SEED + 1)
    cases = [
        _replay_case("strict_in_order", 0, [("observe", tick) for tick in (0, 1, 2, 3, 10)]),
        _replay_case("strict_duplicate_then_stale", 0, [("observe", 5), ("observe", 5), ("observe", 4), ("observe", 6)]),
        _replay_case("strict_check_does_not_mutate", 0, [("check", 3), ("check", 3), ("observe", 3), ("check", 3), ("check", 2)]),
        _replay_case("strict_first_tick_zero", 0, [("observe", 0), ("observe", 0)]),
        _replay_case("strict_negative_ticks_are_stale", 0, [("observe", -1), ("observe", -5), ("observe", 0)]),
        _replay_case("reorder_two_in_window", 2, [("observe", 10), ("observe", 9), ("observe", 9), ("observe", 8), ("observe", 11), ("observe", 9)]),
        _replay_case("reorder_one_is_strict_plus_nothing", 1, [("observe", 4), ("observe", 3), ("observe", 4), ("observe", 5)]),
        _replay_case("reorder_eight_fill_and_slide", 8, [("observe", tick) for tick in (20, 13, 14, 19, 12, 13, 21, 14, 30, 22, 29)]),
        _replay_case("reorder_sixty_four_edge", 64, [("observe", 100), ("observe", 37), ("observe", 36), ("observe", 100), ("observe", 99)]),
        _replay_case("reorder_sixty_four_jump_exactly_the_width", 64, [("observe", 3), ("observe", 67), ("observe", 4), ("observe", 3)]),
        _replay_case("a_jump_wider_than_the_mask", 8, [("observe", 1), ("observe", 1000), ("observe", 999), ("observe", 992), ("observe", 991)]),
        _replay_case("a_hostile_jump_of_two_to_the_forty", 8, [("observe", 1), ("observe", 2**40), ("observe", 2**40 - 1), ("observe", 2**40 - 8), ("observe", 2**40 - 9)]),
        _replay_case("a_hostile_jump_of_two_to_the_sixty_two", 64, [("observe", 0), ("observe", 2**62), ("observe", 2**62 - 63), ("observe", 2**62 - 64)]),
        _replay_case("extreme_ticks_in_range", 2, [("observe", -2**62), ("observe", 2**62), ("observe", -2**62), ("check", 2**62), ("check", 2**62 - 1)]),
    ]
    for reorder in (0, 1, 2, 3, 8, 16, 31, 63, 64):
        for index in range(8):
            ops, tick = [], rng.randrange(-3, 6)
            for _ in range(rng.randrange(20, 80)):
                step = rng.choice([1, 1, 1, 2, 3, 0, -1, -2, -rng.randrange(1, 70), rng.randrange(1, 200), 2**rng.randrange(20, 50)])
                tick = max(-2**62, min(2**62, tick + step)) if rng.random() < 0.8 else rng.randrange(-5, 400)
                ops.append((rng.choice(["observe", "observe", "observe", "check"]), tick))
            cases.append(_replay_case(f"seeded_reorder{reorder}_{index}", reorder, ops))
    return {
        "version": 1,
        "comment": "FROZEN. Replay window (PROTOCOL.md section 2.8): operation lists and the (accepted, cause) each gives under "
                   "prismpath.telemetry.replay.TickWindow, with the window's highest accepted tick and bit mask at the end. "
                   "Ticks stay within +-2**62, the range the Rust crate holds.",
        "causes": {"accept": replay.ACCEPT, "duplicate": replay.REPLAY_DUPLICATE, "stale": replay.REPLAY_STALE},
        "constructor_refused": [-1, -64, 65, 100, 2**31],
        "constructor_accepted": [0, 1, 32, 64],
        "cases": cases,
    }


# -------------------------------------------------------------------------------------- refresh
def _scheduler_case(name, keyframe_ms, ops):
    scheduler = refresh.KeyframeScheduler(keyframe_ms)
    expect = []
    for op in ops:
        if op[0] == "should_emit":
            expect.append(scheduler.should_emit(op[1], op[2]))
        else:
            scheduler.note_emit(op[1])
            expect.append(None)
    return {"name": name, "keyframe_ms": keyframe_ms, "ops": [list(op) for op in ops], "expect": expect}


def _tracker_case(name, stale_ms, safe_state, ops):
    tracker = refresh.StalenessTracker(stale_ms, safe_state)
    expect = []
    for op in ops:
        if op[0] == "frame":
            tracker.on_frame(op[1], op[2])
            expect.append(None)
        else:
            state, fresh = tracker.acting_state(op[1])
            expect.append([state, fresh])
    return {"name": name, "stale_ms": stale_ms, "safe_state": safe_state, "ops": [list(op) for op in ops], "expect": expect,
            "transitions": [[when, kind] for when, kind in tracker.transitions]}


def refresh_corpus() -> dict:
    rng = random.Random(SEED + 2)
    schedulers = [
        _scheduler_case("send_on_delta_only", None, [("should_emit", 0, False), ("note_emit", 0), ("should_emit", 5, False), ("should_emit", 10**9, False),
                                                      ("should_emit", 10, True)]),
        _scheduler_case("first_call_always_emits", 1000, [("should_emit", 0, False), ("should_emit", 0, False)]),
        _scheduler_case("keyframe_at_the_bound", 100, [("note_emit", 0), ("should_emit", 99, False), ("should_emit", 100, False), ("should_emit", 101, False),
                                                       ("note_emit", 101), ("should_emit", 150, False), ("should_emit", 201, False)]),
        _scheduler_case("a_change_emits_inside_the_bound", 100, [("note_emit", 0), ("should_emit", 1, True), ("should_emit", 2, False)]),
        _scheduler_case("one_millisecond", 1, [("note_emit", 5), ("should_emit", 5, False), ("should_emit", 6, False)]),
        _scheduler_case("a_clock_that_goes_back", 100, [("note_emit", 500), ("should_emit", 100, False), ("should_emit", 599, False), ("should_emit", 600, False)]),
        _scheduler_case("huge_times", 10**12, [("note_emit", 2**62), ("should_emit", 2**62 + 10**12 - 1, False), ("should_emit", 2**62 + 10**12, False)]),
    ]
    for index in range(40):
        keyframe = rng.choice([None, 1, 7, 50, 1000])
        now, ops = 0, []
        for _ in range(rng.randrange(10, 60)):
            now += rng.choice([0, 1, 3, 20, 400])
            changed = rng.random() < 0.2
            ops.append(("should_emit", now, changed))
            if rng.random() < 0.6:
                ops.append(("note_emit", now))
        schedulers.append(_scheduler_case(f"seeded_{index}", keyframe, ops))
    trackers = [
        _tracker_case("born_stale", 100, "SAFE", [("acting", 0), ("acting", 10**6)]),
        _tracker_case("fresh_then_stale_then_recovered", 100, "SAFE",
                      [("frame", 10, "A"), ("acting", 10), ("acting", 109), ("acting", 110), ("acting", 111), ("frame", 200, "B"), ("acting", 201), ("acting", 300)]),
        _tracker_case("structured_states", 50, {"mode": "park", "level": 0},
                      [("frame", 0, {"mode": "run", "level": 3}), ("acting", 49), ("acting", 50), ("frame", 60, [1, 2, 3]), ("acting", 61)]),
        _tracker_case("a_second_frame_while_fresh_is_not_a_transition", 100, "SAFE", [("frame", 0, 1), ("frame", 10, 2), ("frame", 20, 3), ("acting", 21)]),
        _tracker_case("stale_is_recorded_only_when_acting_is_asked", 100, "SAFE", [("frame", 0, 1), ("frame", 5000, 2), ("acting", 5001)]),
        _tracker_case("null_state_is_a_state", 10, "SAFE", [("frame", 0, None), ("acting", 1), ("acting", 10)]),
        _tracker_case("a_clock_that_goes_back", 100, "SAFE", [("frame", 500, "A"), ("acting", 100), ("acting", 599), ("acting", 600)]),
    ]
    for index in range(40):
        stale_ms = rng.choice([1, 5, 100, 1000])
        now, ops = 0, []
        for _ in range(rng.randrange(10, 60)):
            now += rng.choice([0, 1, 3, 20, 400])
            if rng.random() < 0.4:
                ops.append(("frame", now, rng.choice([rng.randrange(100), "s", None, {"v": rng.randrange(5)}])))
            else:
                ops.append(("acting", now))
        trackers.append(_tracker_case(f"seeded_{index}", stale_ms, {"safe": True}, ops))
    return {
        "version": 1,
        "comment": "FROZEN. Refresh profile (PROTOCOL.md section 2.7): KeyframeScheduler and StalenessTracker operation lists and what "
                   "prismpath.telemetry.refresh gives for each. An op is [should_emit, now_ms, changed], [note_emit, now_ms], "
                   "[frame, now_ms, state] or [acting, now_ms]; expect is null for an op that returns nothing. Times stay within +-2**62.",
        "scheduler_refused": [0, -1, -1000],
        "tracker_refused": [0, -1, -1000],
        "schedulers": schedulers,
        "trackers": trackers,
    }


# ---------------------------------------------------------------------------------- concentrator
REGISTRIES = {"fleet": {1: 2, 2: 5, 3: 1, 7: 3, 9: 0, 40: 4}, "tiny": {1: 1}}


def _records_json(records):
    return [[stream_id, list(wire_ints)] for stream_id, wire_ints in records]


def _concentrate_case(name, records):
    entry = {"name": name, "records": _records_json(records)}
    try:
        entry["hex"] = concentrator.concentrate(records).hex()
    except ValueError as refusal:
        entry["refuse"] = str(refusal)
    return entry


def _demux_case(name, frame, registry):
    demuxed = concentrator.demux(frame, REGISTRIES[registry])
    records, cause = demuxed
    return {"name": name, "registry": registry, "hex": frame.hex(), "records": _records_json(records), "cause": cause,
            "registry_cause": demuxed.cause}


def concentrator_corpus() -> dict:
    rng = random.Random(SEED + 3)
    fleet = REGISTRIES["fleet"]

    def reading(stream_id):
        return [rng.randrange(1, rng.choice([3, 9, 60, 5000])) for _ in range(fleet[stream_id])]

    concentrate = [
        _concentrate_case("one_record", [(1, [3, 1])]),
        _concentrate_case("three_streams", [(1, [3, 1]), (3, [2]), (2, [1, 1, 1, 1, 1])]),
        _concentrate_case("same_stream_twice", [(1, [3, 1]), (1, [1, 1])]),
        _concentrate_case("zero_field_stream_has_no_reading_to_carry", [(9, [])]),
        _concentrate_case("a_large_stream_id", [(40, [1, 2, 3, 4]), (10**6, [1])]),
        _concentrate_case("no_records", []),
        _concentrate_case("refused_stream_id_zero", [(0, [1])]),
        _concentrate_case("refused_negative_stream_id", [(-3, [1])]),
        _concentrate_case("refused_empty_reading", [(1, [])]),
        _concentrate_case("refused_wire_int_zero", [(1, [1, 0])]),
        _concentrate_case("refused_negative_wire_int", [(1, [-4, 2])]),
    ]
    for index in range(60):
        records = []
        for _ in range(rng.randrange(1, 9)):
            stream_id = rng.choice([sid for sid in fleet if fleet[sid] > 0])
            records.append((stream_id, reading(stream_id)))
        concentrate.append(_concentrate_case(f"seeded_{index}", records))

    demux = []
    for case in concentrate:
        if "hex" in case and case["records"] and all(sid in fleet and len(ints) == fleet[sid] for sid, ints in case["records"]):
            demux.append(_demux_case(f"datagram_{case['name']}", bytes.fromhex(case["hex"]), "fleet"))
    demux.append(_demux_case("empty_datagram", b"", "fleet"))
    demux.append(_demux_case("all_zero_pad", b"\x00\x00\x00", "fleet"))
    demux.append(_demux_case("zero_field_stream", packed.pack(zeck.encode(9), 8), "fleet"))
    demux.append(_demux_case("registered_stream_in_the_other_registry", concentrator.concentrate([(2, [1, 1, 1, 1, 1])]), "tiny"))
    demux.append(_demux_case("unknown_stream_id_first", concentrator.concentrate([(5, [1])]), "fleet"))
    demux.append(_demux_case("unknown_stream_id_after_a_good_record", concentrator.concentrate([(1, [3, 1]), (5, [1])]), "fleet"))
    demux.append(_demux_case("a_datagram_with_one_bit_and_no_codeword", b"\x80", "fleet"))
    demux.append(_demux_case("a_datagram_with_a_stream_id_cut_after_a_whole_record",
                             packed.pack(zeck.encode(3) + zeck.encode(2) + "1", 8), "fleet"))
    demux.append(_demux_case("a_reading_cut_with_only_zero_bits_left", packed.pack(zeck.encode(2) + zeck.encode(1), 8), "fleet"))
    demux.append(_demux_case("a_reading_cut_with_a_dangling_codeword",
                             packed.pack(zeck.encode(2) + zeck.encode(1) + "01", 8), "fleet"))
    demux.append(_demux_case("short_reading_whole_datagram_rejected", concentrator.concentrate([(1, [3, 1]), (2, [1, 1])]), "fleet"))
    # every cut of a multi record datagram, padded back to bytes: a datagram cut anywhere is either
    # whole records, an all-zero tail, or a rejection with a named cause
    long_bits = "".join(zeck.encode(sid) + zeck.encode_stream(ints) for sid, ints in [(1, [3, 1]), (3, [2]), (2, [1, 4, 1, 1, 9]), (7, [1, 2, 3])])
    for cut in range(len(long_bits) + 1):
        demux.append(_demux_case(f"cut_at_bit_{cut}", packed.pack(long_bits[:cut], 8), "fleet"))
    for index in range(80):
        demux.append(_demux_case(f"random_bytes_{index}", bytes(rng.randrange(256) for _ in range(rng.randrange(1, 14))), "fleet"))
    valid = bytearray(concentrator.concentrate([(1, [3, 1]), (3, [2]), (2, [1, 4, 1, 1, 9])]))
    for index in range(80):
        frame = bytearray(valid)
        for _ in range(rng.randrange(1, 4)):
            frame[rng.randrange(len(frame))] ^= 1 << rng.randrange(8)
        demux.append(_demux_case(f"flipped_{index}", bytes(frame), "fleet"))
    # a long run of zeros inside a code: a legal Zeckendorf code of a large value; the decoder must stay linear
    demux.append(_demux_case("a_code_with_forty_zero_bits", packed.pack(zeck.encode(1) + zeck.encode(2**40), 8), "fleet"))

    wide = []
    for name, records in [("wide_wire_int", [(1, [2**64 + 3, 1])]), ("wide_stream_id_is_unknown", [(2**70, [1])]),
                          ("u64_max_wire_int", [(1, [U64_MAX, 1])]), ("u64_max_plus_one_wire_int", [(1, [U64_MAX + 1, 1])])]:
        frame = concentrator.concentrate(records)
        demuxed = concentrator.demux(frame, REGISTRIES["fleet"])
        decoded, cause = demuxed
        wide.append({"name": name, "registry": "fleet", "hex": frame.hex(), "cause": cause, "registry_cause": demuxed.cause,
                     "rust_overflow": any(wire_int > U64_MAX for _sid, ints in decoded for wire_int in ints),
                     "python_records": [[str(sid), [str(value) for value in ints]] for sid, ints in decoded]})
    return {
        "version": 1,
        "comment": "FROZEN. Concentrator profile (PROTOCOL.md section 2.9): datagrams built by prismpath.telemetry.concentrator.concentrate, "
                   "every cut of a multi record datagram, seeded noise and bit flips, each with the records and status demux returns, and `registry_cause`, the strict decode cause code (48, 49) or null. "
                   "`wide` datagrams carry an integer beyond 64 bits, which Python returns and the Rust crate refuses.",
        "causes": {"ok": concentrator.OK, "unknown": concentrator.CONCENTRATOR_UNKNOWN_STREAM, "truncated": concentrator.CONCENTRATOR_TRUNCATED},
        "registries": {name: {str(sid): count for sid, count in registry.items()} for name, registry in REGISTRIES.items()},
        "concentrate": concentrate, "demux": demux, "wide": wide,
    }


def corpora() -> dict:
    return {"receipt_stream.json": receipt_stream_corpus(), "replay.json": replay_corpus(),
            "refresh.json": refresh_corpus(), "concentrator.json": concentrator_corpus()}


def main() -> int:
    for name, doc in corpora().items():
        path = _write(name, doc)
        sizes = {key: len(value) for key, value in doc.items() if isinstance(value, list)}
        print(f"wrote {path}  {sizes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
