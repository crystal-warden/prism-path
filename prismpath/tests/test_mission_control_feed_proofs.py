# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The console over `prismpath.collector/2`: every seal after the first a connection was sent carries an
RFC 6962 consistency proof from the last seal that connection was sent, so after a `gap` or a reconnect
the records the console missed stay unchecked but the new tree is PROVEN to extend the one it verified
(`tree: proven`), and a span the collector could not prove is named (`tree: unproven`). And the kept
sessions' bounds: a total size and an age, whole oldest segments removed, never the one in use, never
anything outside the store, each removal written down beside the session it came from."""
import hashlib
import json
import os
import time

import pytest

from prismpath.kernel import canon2
from prismpath.ledgers import root_statement as rs
from prismpath.mission_control import evidence, feed, feed_client
from prismpath.mission_control.config import Settings
from prismpath.tests.test_mission_control_feed import (FakeCollector, LATE, SESSION, _check, _client, _dump,  # noqa: F401
                                                       _index_of, _records, _replace, _wait, evidence_root, short_dir)

RECORDS = _records(SESSION)
LEAVES = [record["leaf"] for record in RECORDS if record["kind"] in feed.LEAF_KINDS]
SESSION_ID = RECORDS[0]["session"]


def _seal_at(count):
    return _index_of(SESSION, lambda record: record["kind"] == "seal" and record["count"] == count
                     and record["trigger"] != "join")


def _without(lines, predicate):
    return [raw for raw, record in zip(lines, _records(lines)) if not predicate(record)]


def _proof(old, new):
    return {"from": old, "proof": rs.consistency_proof(LEAVES[:new], old)}


# ----------------------------------------------------------------- the proofs as the collector sends them
def test_the_recorded_seals_carry_the_proof_from_the_seal_before():
    for lines in (SESSION, LATE):
        seals = [record for record in _records(lines) if record["kind"] == "seal"]
        assert "consistency" not in seals[0]
        for before, seal in zip(seals, seals[1:]):
            assert seal["consistency"]["from"] == before["count"]
            if before["count"]:
                assert rs.verify_consistency(before["count"], seal["count"], before["root"], seal["root"],
                                             seal["consistency"]["proof"])


def test_a_good_stream_is_proven_and_checked():
    summary = _check(SESSION).summary()
    assert summary["status"] == "intact" and summary["tree"] == "proven" and summary["records"] == "checked"
    assert summary["seals"]["proven"] == 0 and summary["seals"]["adopted"] == 0 and summary["unproven"] == []
    assert summary["resume"] == {"session": SESSION_ID, "count": 21}


def test_a_gap_between_seals_leaves_records_unchecked_and_the_tree_proven():
    # leaves 9 to 11 dropped for this client; the seal at 14 proves from the seal at 8 the client holds
    lines = _without(SESSION, lambda record: record.get("index") in (9, 10, 11))
    lines.insert(_index_of(lines, lambda record: record.get("index") == 12), _dump({"kind": "gap", "source": "gnet", "dropped": 3}))
    summary = _check(lines).summary()
    assert summary["status"] == "holes", summary["findings"]
    assert summary["tree"] == "proven" and summary["records"] == "unchecked"
    assert summary["holes"] == [{"from": 9, "to": 12, "leaves": 3, "why": "gap", "segment": 0}]
    assert summary["unchecked"] == [{"from": 12, "to": 14, "leaves": 2}]
    assert summary["seals"]["proven"] == 1 and summary["seals"]["adopted"] == 0
    assert summary["root"] == RECORDS[-2]["root"]


def test_a_gap_that_swallowed_seals_is_proved_from_the_last_seal_received():
    # the seal and status at 14 and leaves 12 to 14 are dropped: the client's last seal is the one at 8,
    # so the collector proves the seal at 17 from 8
    lines = _without(SESSION, lambda record: record.get("index") in (12, 13, 14)
                     or (record["kind"] in ("seal", "status") and record.get("count") == 14))
    at = _index_of(lines, lambda record: record.get("index") == 15)
    lines.insert(at, _dump({"kind": "gap", "source": "gnet", "dropped": 5}))
    seal = _index_of(lines, lambda record: record["kind"] == "seal" and record["count"] == 17)
    # the gap counts records, not leaves: the hole is read from the indexes
    proven = _replace(lines, seal, lambda record: record.update(consistency=_proof(8, 17)))
    summary = _check(proven).summary()
    assert summary["findings"] == [] and summary["tree"] == "proven"
    assert summary["holes"] == [{"from": 12, "to": 15, "leaves": 3, "why": "gap", "segment": 0}]
    assert summary["seals"]["proven"] == 1
    # the seal as recorded proves from 14, a seal this connection was never sent: the collector's word
    # against the console's copy, a finding
    summary = _check(lines).summary()
    assert summary["status"] == "broken" and summary["findings"][0]["check"] == "seal-consistency"
    assert "14" in summary["findings"][0]["detail"] and "8" in summary["findings"][0]["detail"]


def test_a_proof_that_does_not_prove_is_a_finding_with_or_without_a_hole():
    seal = _seal_at(14)

    def flip(record):
        proof = record["consistency"]["proof"]
        proof[0] = ("0" if proof[0][0] != "0" else "1") + proof[0][1:]
    summary = _check(_replace(SESSION, seal, flip)).summary()
    assert summary["status"] == "broken" and summary["findings"][0]["check"] == "seal-consistency"
    lines = _without(SESSION, lambda record: record.get("index") in (9, 10))
    lines.insert(_index_of(lines, lambda record: record.get("index") == 11), _dump({"kind": "gap", "source": "gnet", "dropped": 2}))
    summary = _check(_replace(lines, _index_of(lines, lambda record: record["kind"] == "seal" and record["count"] == 14), flip)).summary()
    assert summary["status"] == "broken" and summary["tree"] == "unproven"
    assert summary["findings"][0]["check"] == "seal-consistency"


def test_a_seal_without_its_proof_is_a_finding():
    summary = _check(_replace(SESSION, _seal_at(14), lambda record: record.pop("consistency"))).summary()
    assert summary["status"] == "broken" and summary["findings"][0]["check"] == "seal-consistency"


def test_a_proof_the_collector_no_longer_holds_leaves_the_tree_unproven():
    lines = _without(SESSION, lambda record: record.get("index") in (9, 10, 11))
    lines.insert(_index_of(lines, lambda record: record.get("index") == 12), _dump({"kind": "gap", "source": "gnet", "dropped": 3}))
    seal = _index_of(lines, lambda record: record["kind"] == "seal" and record["count"] == 14)
    lines = _replace(lines, seal, lambda record: record.update(consistency={"from": 8, "missing": "window"}))
    summary = _check(lines).summary()
    assert summary["status"] == "unproven" and summary["findings"] == []
    assert summary["tree"] == "unproven" and summary["records"] == "unchecked"
    assert summary["unproven"] == [{"from": 8, "to": 14, "why": "window", "segment": 0}]
    assert summary["seals"]["adopted"] == 1 and summary["seals"]["proven"] == 0
    # the seals after it are checked against the tree taken up from it, as before
    assert summary["seals"]["checked"] >= 3 and summary["root"] == RECORDS[-2]["root"]


def _second_connection(join_count, consistency):
    join = rs.MerkleAccumulator(LEAVES[:join_count])
    seal = {"kind": "seal", "source": "gnet", "session": SESSION_ID, "trigger": "join", "count": join_count,
            "peaks": join.peaks(), "root": join.root(), "malformed": 0}
    if consistency is not None:
        seal["consistency"] = consistency
    rest = SESSION[_index_of(SESSION, lambda record: record.get("index") == join_count):]
    # the first seal after the join proves from it
    first = _index_of(rest, lambda record: record["kind"] == "seal")
    rest = _replace(rest, first, lambda record: record.update(consistency=_proof(join_count, record["count"])))
    return [SESSION[0], _dump(seal)] + rest


def _reconnected(join_count, consistency):
    check = feed.SessionCheck()
    check.begin_segment(0)
    for raw in SESSION[:_index_of(SESSION, lambda record: record.get("index") == 9)]:
        check.line(raw)
    check.end_segment("eof")
    assert check.resume_point() == (SESSION_ID, 8)
    check.begin_segment(1)
    for raw in _second_connection(join_count, consistency):
        check.line(raw)
    check.end_segment("eof")
    return check.summary()


def test_a_reconnect_resumed_from_the_last_verified_seal_is_proven():
    summary = _reconnected(14, _proof(8, 14))
    assert summary["status"] == "holes" and summary["findings"] == []
    assert summary["tree"] == "proven" and summary["seals"]["proven"] == 1
    assert summary["holes"] == [{"from": 9, "to": 14, "leaves": 5, "why": "disconnected", "segment": 1}]
    assert summary["root"] == RECORDS[-2]["root"]


def test_a_reconnect_the_collector_cannot_prove_is_unproven():
    summary = _reconnected(14, None)
    assert summary["status"] == "unproven" and summary["findings"] == []
    assert summary["unproven"] == [{"from": 8, "to": 14, "why": "no-proof", "segment": 1}]
    summary = _reconnected(14, {"from": 8, "missing": "window"})
    assert summary["unproven"][0]["why"] == "window"
    # a join seal proved from a count the console did not ask for proves nothing it holds
    summary = _reconnected(14, _proof(3, 14))
    assert summary["status"] == "unproven" and summary["unproven"][0]["why"] == "proof-from-3"


def test_a_join_seal_that_does_not_extend_the_verified_tree_is_a_finding():
    forged = list(LEAVES)
    forged[2] = "ee" * 32
    join = rs.MerkleAccumulator(forged[:14])
    seal = {"kind": "seal", "source": "gnet", "session": SESSION_ID, "trigger": "join", "count": 14,
            "peaks": join.peaks(), "root": join.root(), "malformed": 0,
            "consistency": {"from": 8, "proof": rs.consistency_proof(forged[:14], 8)}}
    check = feed.SessionCheck()
    check.begin_segment(0)
    for raw in SESSION[:_index_of(SESSION, lambda record: record.get("index") == 9)]:
        check.line(raw)
    check.end_segment("eof")
    check.begin_segment(1)
    check.line(SESSION[0])
    check.line(_dump(seal))
    summary = check.summary()
    assert summary["status"] == "broken" and summary["findings"][0]["check"] == "seal-consistency"


def test_only_protocol_2_is_accepted():
    assert feed.PROTOCOL == "prismpath.collector/2"
    old = _replace(SESSION, 0, lambda record: record.update(protocol="prismpath.collector/1"))
    summary = _check(old).summary()
    assert summary["status"] == "broken" and summary["findings"][0]["check"] == "protocol"


def test_the_resume_line_is_the_collectors_canonical_resume():
    assert feed.subscription_line(None) == b'{"op":"subscribe","protocol":"prismpath.collector/2"}\n'
    assert feed.subscription_line((SESSION_ID, 8)) == (
        b'{"count":8,"op":"subscribe","protocol":"prismpath.collector/2","session":"' + SESSION_ID.encode() + b'"}\n')
    assert canon2.dumps(json.loads(feed.subscription_line((SESSION_ID, 8)))) + b"\n" == feed.subscription_line((SESSION_ID, 8))


def test_the_client_resumes_from_its_last_verified_seal(short_dir, evidence_root):
    first = SESSION[:_index_of(SESSION, lambda record: record.get("index") == 9)]
    fake = FakeCollector([first, _second_connection(14, _proof(8, 14))], path=os.path.join(short_dir, "f.sock"))
    client = _client(("unix", fake.address), evidence_root / "collector-feed")
    try:
        assert _wait(lambda: client.check is not None and len(client.check.segments) == 2
                     and client.check.segments[1]["ended"] == "eof")
        assert fake.received[0] == feed.subscription_line(None)
        assert fake.received[1] == feed.subscription_line((SESSION_ID, 8))
        chain = client.snapshot()["chain"]
        assert chain["status"] == "holes" and chain["tree"] == "proven" and chain["findings"] == []
        report = feed.feed_report(str(evidence_root / "collector-feed" / SESSION_ID))
        assert report["tree"] == "proven" and report["holes"] == chain["holes"]
    finally:
        client.stop()
        fake.close()


# ----------------------------------------------------------------- retention of the kept sessions
def _segment(store, session, number, size, age_s, ended="eof", now=None):
    """A kept segment of about `size` bytes, last written `age_s` ago, with its end note unless `ended`
    is None."""
    now = time.time() if now is None else now
    directory = store / session
    directory.mkdir(parents=True, exist_ok=True)
    body = b"".join(line + b"\n" for line in SESSION)
    data = body * max(1, round(size / len(body)))
    path = directory / feed.segment_name(number)
    path.write_bytes(data)
    if ended is not None:
        (directory / feed.end_name(number)).write_bytes(canon2.dumps({"format": feed.FEED_FORMAT, "segment": number,
                                                                      "ended": ended, "lines": data.count(b"\n"),
                                                                      "size": len(data), "time_us": 1}) + b"\n")
        os.utime(directory / feed.end_name(number), (now - age_s, now - age_s))
    os.utime(path, (now - age_s, now - age_s))
    return path


def _usage(store):
    return sum(os.path.getsize(os.path.join(top, name)) for top, _dirs, names in os.walk(store) for name in names)


def test_retention_removes_whole_oldest_segments_down_to_the_byte_bound(tmp_path):
    store = tmp_path / "collector-feed"
    a, b = "aa" * 16, "bb" * 16
    oldest = _segment(store, a, 0, 40_000, 5000)
    _segment(store, a, 1, 40_000, 4000)
    _segment(store, b, 0, 40_000, 3000)
    in_use = _segment(store, b, 1, 40_000, 0, ended=None)
    removed = feed.retain(str(store), keep_bytes=100_000, keep_age_s=0, in_use=str(in_use))
    assert [(entry["session"], entry["segment"], entry["removed"]) for entry in removed] == [(a, 0, "bytes"), (a, 1, "bytes")]
    assert _usage(store) <= 100_000
    assert not oldest.exists() and not (store / a / feed.end_name(0)).exists()
    assert (store / b / feed.segment_name(0)).exists() and in_use.exists()
    note = canon2.loads((store / a / feed.removed_name(0)).read_bytes().rstrip(b"\n"))
    assert note["format"] == feed.FEED_FORMAT and note["removed"] == "bytes" and note["bound"] == {"keep_bytes": 100_000}
    assert note["segment"] == 0 and note["session"] == a and note["ended"] == "eof"
    assert note["first_count"] == 0 and note["last_count"] == 21 and note["size"] > 0 and len(note["sha256"]) == 64
    # the segment in use is never removed, even when it alone is over the bound
    assert feed.retain(str(store), keep_bytes=1, keep_age_s=0, in_use=str(in_use))[0]["segment"] == 0
    assert in_use.exists() and sorted(os.listdir(store / b)) == sorted([feed.segment_name(1), feed.removed_name(0)])


def test_retention_removes_segments_past_the_age_bound(tmp_path):
    store = tmp_path / "collector-feed"
    s = "cc" * 16
    _segment(store, s, 0, 2000, 10 * 86400)
    _segment(store, s, 1, 2000, 2 * 86400)
    _segment(store, s, 2, 2000, 60)
    removed = feed.retain(str(store), keep_bytes=1 << 30, keep_age_s=7 * 86400)
    assert [(entry["segment"], entry["removed"]) for entry in removed] == [(0, "age")]
    note = canon2.loads((store / s / feed.removed_name(0)).read_bytes().rstrip(b"\n"))
    assert note["bound"] == {"keep_age_s": 7 * 86400}
    # a segment with no end note, written to lately, may be another console's: it stays; one silent past
    # the age bound does not
    _segment(store, s, 3, 2000, 30, ended=None)
    _segment(store, "dd" * 16, 0, 2000, 30 * 86400, ended=None)
    removed = feed.retain(str(store), keep_bytes=1, keep_age_s=7 * 86400)
    assert (store / s / feed.segment_name(3)).exists()
    assert ("dd" * 16, 0) in [(entry["session"], entry["segment"]) for entry in removed]


def test_retention_never_reaches_outside_its_store(tmp_path):
    store = tmp_path / "collector-feed"
    outside = tmp_path / "outside"
    outside.mkdir()
    keep = _segment(outside, "ee" * 16, 0, 5000, 90 * 86400)
    store.mkdir()
    os.symlink(outside / ("ee" * 16), store / ("ee" * 16))                 # a session directory that is a link
    s = "ff" * 16
    _segment(store, s, 0, 5000, 90 * 86400)
    os.symlink(keep, store / s / feed.segment_name(7))                      # a segment that is a link
    (store / s / "notes.txt").write_text("not a segment")
    (store / "feed-000000.jsonl").write_text("not in a session")
    other = store / "not-a-session"
    other.mkdir()
    (other / feed.segment_name(0)).write_text("x")
    os.utime(other / feed.segment_name(0), (1, 1))
    removed = feed.retain(str(store), keep_bytes=1, keep_age_s=86400)
    assert [(entry["session"], entry["segment"]) for entry in removed] == [(s, 0)]
    assert keep.exists() and os.path.islink(store / s / feed.segment_name(7))
    assert (store / s / "notes.txt").exists() and (store / "feed-000000.jsonl").exists()
    assert (other / feed.segment_name(0)).exists()
    assert feed.retain(str(tmp_path / "absent"), keep_bytes=1, keep_age_s=1) == []


def test_a_removed_segment_is_reported_with_why(tmp_path, evidence_root):
    store = evidence_root / "collector-feed"
    kept = store / SESSION_ID
    kept.mkdir(parents=True)
    cut = _index_of(SESSION, lambda record: record.get("index") == 9)
    second = _second_connection(14, _proof(8, 14))
    (kept / feed.segment_name(0)).write_bytes(b"".join(line + b"\n" for line in SESSION[:cut]))
    (kept / feed.segment_name(1)).write_bytes(b"".join(line + b"\n" for line in second))
    os.utime(kept / feed.segment_name(0), (1, 1))
    removed = feed.retain(str(store), keep_bytes=1, keep_age_s=0, in_use=str(kept / feed.segment_name(1)))
    assert [entry["segment"] for entry in removed] == [0]
    report = feed.feed_report(str(kept))
    assert report["removed"] == [{"segment": 0, "removed": "bytes", "first_count": 0, "last_count": 8,
                                  "size": removed[0]["size"], "sha256": removed[0]["sha256"]}]
    # the console never saw the tree before the join seal of the kept segment: nothing to prove it from
    assert report["status"] == "unproven" and report["findings"] == []
    assert report["unproven"][0]["why"] == "removed"
    assert [entry["segment"] for entry in report["files"]] == [1]


def test_the_client_keeps_its_store_inside_the_bounds(short_dir, evidence_root):
    sessions = []
    for number in range(4):
        sid = f"{number:02d}" * 16
        sessions.append([_dump({**RECORDS[0], "session": sid})] +
                        [_dump({**record, "session": sid}) if "session" in record else raw for raw, record in zip(SESSION[1:], RECORDS[1:])])
    fake = FakeCollector(sessions, path=os.path.join(short_dir, "f.sock"))
    store = evidence_root / "collector-feed"
    size = sum(len(line) + 1 for line in SESSION)
    client = _client(("unix", fake.address), store, keep_bytes=int(size * 2.5), keep_age_s=0)
    try:
        assert _wait(lambda: client.check is not None and client.check.session == "03" * 16
                     and client.check.segments[-1]["ended"] == "eof")
        assert _wait(lambda: client.snapshot()["retention"]["removed_total"] >= 2)
        assert _usage(store) <= size * 2.5
        retention = client.snapshot()["retention"]
        assert retention["keep_bytes"] == int(size * 2.5) and retention["last"][0]["removed"] == "bytes"
        assert (store / ("00" * 16) / feed.removed_name(0)).exists()
        assert (store / ("03" * 16) / feed.segment_name(0)).exists()
    finally:
        client.stop()
        fake.close()


def test_the_bounds_are_settings():
    settings = Settings.from_environment({"MC_COLLECTOR_KEEP_BYTES": "5000000", "MC_COLLECTOR_KEEP_DAYS": "2"})
    assert settings.collector_keep_bytes == 5_000_000 and settings.collector_keep_days == 2
    default = Settings.from_environment({})
    assert default.collector_keep_bytes == 1 << 30 and default.collector_keep_days == 30
    client = feed_client.FeedClient.from_settings(Settings(collector="/run/x.sock", collector_keep_bytes=1 << 20,
                                                           collector_keep_days=1), read_only=False)
    assert client.keep_bytes == 1 << 20 and client.keep_age_s == 86400
