# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The console's reading of the collector's feed (prismpath-ebpf/collector/README.md, "What the console
consumes"): the checks it makes as records arrive, the evidence it keeps, the stored session read back,
and the client against a fake collector on a Unix socket.

The two recordings under fixtures/collector_feed are what the collector's own feed code (its `Hub` and
drain loop, `prismpath-ebpf/collector/src/{feed,collector}.rs`) sent one subscribed client for a recorded
governed net ring buffer of twenty `struct gn_event` frames and one frame of the wrong length, byte for
byte: `gnet_session.jsonl` from the start of a session (a join seal of no leaves), `gnet_late_join.jsonl`
from a client that joined another session after eleven leaves. Each test that tampers with them changes one
record and writes it back in canon/2, so every line the console reads is still canonical unless the test is
about a line that is not.
"""
import hashlib
import json
import os
import shutil
import socket
import tempfile
import threading
import time
from pathlib import Path

import pytest

from prismpath.kernel import canon2
from prismpath.ledgers.root_statement import MerkleAccumulator
from prismpath.mission_control import evidence, feed, feed_client
from prismpath.mission_control.config import Settings

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "collector_feed"


def _lines(name):
    return (FIXTURES / name).read_bytes().split(b"\n")[:-1]


SESSION = _lines("gnet_session.jsonl")
LATE = _lines("gnet_late_join.jsonl")


def _records(lines):
    return [json.loads(line) for line in lines]


def _dump(record):
    return canon2.dumps(record)


def _check(lines, session=None):
    check = feed.SessionCheck(session)
    check.begin_segment(0)
    for raw in lines:
        check.line(raw)
    check.end_segment("eof")
    return check


def _index_of(lines, predicate):
    return next(position for position, record in enumerate(_records(lines)) if predicate(record))


def _replace(lines, position, change):
    record = json.loads(lines[position])
    change(record)
    out = list(lines)
    out[position] = _dump(record)
    return out


# ----------------------------------------------------------------- the recordings are what the README says
def test_the_recordings_are_canon2_feeds_of_the_collector():
    for lines in (SESSION, LATE):
        records = _records(lines)
        assert all(canon2.dumps(record) == raw for record, raw in zip(records, lines))
        assert records[0]["kind"] == "hello" and records[0]["protocol"] == feed.PROTOCOL
        assert records[1]["kind"] == "seal" and records[1]["trigger"] == "join"
        assert records[-2]["trigger"] == "final" and records[-1]["kind"] == "status"
        assert all(len(raw) + 1 <= records[0]["max_record"] for raw in lines)
    assert _records(SESSION)[1]["count"] == 0 and _records(LATE)[1]["count"] == 11
    assert _records(SESSION)[0]["session"] != _records(LATE)[0]["session"]
    kinds = {record["kind"] for record in _records(SESSION)}
    assert {"decision", "malformed", "seal", "status"} <= kinds


# ----------------------------------------------------------------- the checks
def test_a_good_stream_is_intact_with_every_seal_checked():
    check = _check(SESSION)
    summary = check.summary()
    records = _records(SESSION)
    seals = [record for record in records if record["kind"] == "seal"]
    assert summary["status"] == "intact", summary["findings"]
    assert summary["received"] == 21 and summary["count"] == 21 and summary["joined_at"] == 0
    assert summary["seals"]["checked"] == len(seals) - 1 and summary["seals"]["adopted"] == 0
    assert summary["root"] == seals[-1]["root"]
    assert summary["holes"] == [] and summary["unchecked"] == [] and summary["findings"] == []
    assert summary["verdict_of"] == "console" and summary["statement"] == "collector seal, unsigned"
    assert summary["signed"] is False
    assert summary["last_status"]["enforcer"]["counters"] == {"allow": "11", "drop": "7", "malformed": "2", "other": "0"}


def test_a_late_join_starts_the_tree_from_the_join_seals_peaks():
    summary = _check(LATE).summary()
    assert summary["status"] == "intact", summary["findings"]
    assert summary["joined_at"] == 11 and summary["received"] == 10 and summary["count"] == 21
    assert summary["root"] == _records(LATE)[-2]["root"]


def test_a_tampered_leaf_is_found():
    position = _index_of(SESSION, lambda record: record["kind"] == "decision" and record["index"] == 4)
    lines = _replace(SESSION, position, lambda record: record.update(leaf="00" * 32))
    summary = _check(lines).summary()
    assert summary["status"] == "broken"
    assert [(f["check"], f.get("index")) for f in summary["findings"]] == [("leaf", 4)]


def test_a_tampered_frame_breaks_its_leaf_and_every_seal_over_it():
    position = _index_of(SESSION, lambda record: record["kind"] == "decision" and record["index"] == 4)

    def flip(record):
        frame = bytearray.fromhex(record["frame"])
        frame[20] ^= 1                        # the cause byte
        record["frame"] = frame.hex()
    summary = _check(_replace(SESSION, position, flip)).summary()
    checks = [finding["check"] for finding in summary["findings"]]
    assert summary["status"] == "broken"
    assert checks[0] == "leaf" and "seal-root" in checks


def test_a_seal_whose_root_is_not_its_peaks_root_is_found():
    position = _index_of(SESSION, lambda record: record["kind"] == "seal" and record["trigger"] == "interval")
    lines = _replace(SESSION, position, lambda record: record.update(root="11" * 32))
    summary = _check(lines).summary()
    assert summary["status"] == "broken"
    assert summary["findings"][0]["check"] == "seal-root"


def test_a_seal_over_other_leaves_is_found():
    position = _index_of(SESSION, lambda record: record["kind"] == "seal" and record["trigger"] == "interval")
    record = json.loads(SESSION[position])
    other = MerkleAccumulator(hashlib.sha256(bytes([n])).hexdigest() for n in range(record["count"]))
    lines = _replace(SESSION, position, lambda seal: seal.update(peaks=other.peaks(), root=other.root()))
    summary = _check(lines).summary()
    assert summary["status"] == "broken"
    assert summary["findings"][0]["check"] == "seal-root"
    assert "leaves the console received" in summary["findings"][0]["detail"]


def test_a_gap_is_a_hole_and_the_tree_is_taken_up_at_the_next_seal():
    records = _records(SESSION)
    keep = [raw for raw, record in zip(SESSION, records)
            if not (record["kind"] == "decision" and record["index"] in (2, 3))]
    at = _index_of(keep, lambda record: record.get("index") == 4)
    keep.insert(at, _dump({"kind": "gap", "source": "gnet", "dropped": 2}))
    summary = _check(keep).summary()
    assert summary["status"] == "holes" and summary["findings"] == []
    assert summary["holes"] == [{"from": 2, "to": 4, "leaves": 2, "why": "gap", "segment": 0}]
    assert summary["missing"] == 2 and summary["received"] == 19 and summary["count"] == 21
    first_seal = records[_index_of(SESSION, lambda record: record["kind"] == "seal" and record["trigger"] != "join")]
    # the leaves after the hole up to the next seal are held but no root over them could be computed
    assert summary["unchecked"] == [{"from": 4, "to": first_seal["count"], "leaves": first_seal["count"] - 4}]
    assert summary["seals"]["adopted"] == 1
    assert summary["seals"]["checked"] == sum(1 for r in records if r["kind"] == "seal") - 2
    assert summary["root"] == records[-2]["root"]


def test_a_gap_without_a_count_is_a_finding():
    lines = list(SESSION)
    lines.insert(3, _dump({"kind": "gap", "source": "gnet", "dropped": 0}))
    assert _check(lines).summary()["findings"][0]["check"] == "gap"


def test_an_oversized_line_is_refused_unread():
    lines = list(SESSION)
    lines.insert(3, _dump({"kind": "status", "pad": "x" * 9000}))
    summary = _check(lines).summary()
    assert summary["status"] == "broken" and summary["findings"][0]["check"] == "oversized"


def test_an_unknown_kind_is_ignored_and_counted():
    lines = list(SESSION)
    lines.insert(5, _dump({"kind": "weather", "sky": "clear"}))
    lines.insert(9, _dump({"kind": "weather", "sky": "rain"}))
    summary = _check(lines).summary()
    assert summary["status"] == "intact" and summary["ignored"] == {"weather": 2}


def test_a_line_that_is_not_canonical_is_a_finding():
    lines = list(SESSION)
    lines[4] = json.dumps(json.loads(lines[4]), indent=1).replace("\n", " ").encode()
    summary = _check(lines).summary()
    assert summary["findings"][0]["check"] == "not-canon2" and summary["findings"][0]["line"] == 4


def test_an_index_that_skips_is_a_finding():
    position = _index_of(SESSION, lambda record: record.get("index") == 6)
    summary = _check(_replace(SESSION, position, lambda record: record.update(index=7))).summary()
    assert summary["status"] == "broken" and summary["findings"][0]["check"] == "index"


def test_a_stream_must_open_with_hello_and_a_seal():
    assert _check(SESSION[1:]).summary()["findings"][0]["check"] == "no-hello"
    assert _check(SESSION[:1] + SESSION[2:]).summary()["findings"][0]["check"] == "no-starting-seal"
    other = _replace(SESSION, 0, lambda record: record.update(protocol="prismpath.collector/2"))
    assert _check(other).summary()["findings"][0]["check"] == "protocol"


def test_a_hello_for_another_session_is_a_finding():
    summary = _check(SESSION, session="ff" * 16).summary()
    assert summary["findings"][0]["check"] == "session"


def test_a_reconnect_to_the_same_session_is_a_hole_from_the_last_leaf_to_the_new_join():
    records = _records(SESSION)
    cut = _index_of(SESSION, lambda record: record.get("index") == 9)
    check = feed.SessionCheck()
    check.begin_segment(0)
    for raw in SESSION[:cut]:
        check.line(raw)
    check.end_segment("eof")
    # the second connection joins at 14 leaves: the console never received leaves 9 to 13
    leaves = [record["leaf"] for record in records if record["kind"] in feed.LEAF_KINDS]
    join = MerkleAccumulator(leaves[:14])
    check.begin_segment(1)
    check.line(SESSION[0])
    check.line(_dump({"kind": "seal", "source": "gnet", "session": records[0]["session"], "trigger": "join",
                      "count": 14, "peaks": join.peaks(), "root": join.root(), "malformed": 0}))
    for raw in SESSION[_index_of(SESSION, lambda record: record.get("index") == 14):]:
        check.line(raw)
    check.end_segment("eof")
    summary = check.summary()
    assert summary["status"] == "holes" and summary["findings"] == []
    assert summary["holes"] == [{"from": 9, "to": 14, "leaves": 5, "why": "disconnected", "segment": 1}]
    assert summary["root"] == records[-2]["root"]
    # a join seal that goes back is a finding
    check.begin_segment(2)
    check.line(SESSION[0])
    check.line(_dump({"kind": "seal", "source": "gnet", "session": records[0]["session"], "trigger": "join",
                      "count": 14, "peaks": join.peaks(), "root": join.root(), "malformed": 0}))
    assert check.summary()["findings"][0]["check"] == "session-went-back"


def test_from_peaks_is_what_the_join_seal_needs():
    for record in _records(SESSION) + _records(LATE):
        if record["kind"] == "seal":
            assert MerkleAccumulator.from_peaks(record["count"], record["peaks"]).root() == record.get("root", "")


# ----------------------------------------------------------------- the endpoint setting
@pytest.mark.parametrize("text, expected", [
    ("", None), ("  ", None),
    ("/run/prismpath-collector/feed.sock", ("unix", "/run/prismpath-collector/feed.sock")),
    ("unix:/tmp/f.sock", ("unix", "/tmp/f.sock")),
    ("tcp:127.0.0.1:9300", ("tcp", ("127.0.0.1", 9300))),
    ("tcp:127.9.9.9:1", ("tcp", ("127.9.9.9", 1))),
    ("tcp:[::1]:9300", ("tcp", ("::1", 9300))),
])
def test_the_endpoint_is_off_a_socket_path_or_loopback(text, expected):
    assert feed_client.parse_endpoint(text) == expected


@pytest.mark.parametrize("text", ["tcp:10.0.0.5:9300", "tcp:0.0.0.0:9300", "tcp:[::]:9300", "tcp:localhost:9300",
                                  "tcp:example.org:9300", "tcp:127.0.0.1:0", "tcp:127.0.0.1:x", "feed.sock",
                                  "unix:feed.sock", "tcp:192.168.4.2:22"])
def test_an_endpoint_off_loopback_or_by_name_is_refused(text):
    with pytest.raises(feed_client.EndpointRefused):
        feed_client.parse_endpoint(text)


def test_the_store_must_lie_under_an_evidence_root(tmp_path):
    root = tmp_path / "ev"
    root.mkdir()
    assert feed_client.store_dir_for(Settings(state_dir=str(tmp_path / "s")))[0] is None
    chosen, _ = feed_client.store_dir_for(Settings(state_dir=str(tmp_path / "s"), evidence_roots=[str(root)]))
    assert chosen == os.path.join(os.path.realpath(root), "collector-feed")
    outside = Settings(state_dir=str(tmp_path / "s"), evidence_roots=[str(root)], collector_store=str(tmp_path / "x"))
    assert feed_client.store_dir_for(outside)[0] is None
    assert Settings.from_environment({"MC_COLLECTOR": "tcp:127.0.0.1:1"}).collector == "tcp:127.0.0.1:1"
    assert Settings.from_environment({}).collector == ""


def test_nothing_connects_unless_configured_and_never_read_only(tmp_path):
    settings = Settings(state_dir=str(tmp_path))
    assert feed_client.FeedClient.from_settings(settings, read_only=False) is None
    settings.collector = "/run/x.sock"
    assert feed_client.FeedClient.from_settings(settings, read_only=True) is None
    assert feed_client.FeedClient.from_settings(settings, read_only=False) is not None


# ----------------------------------------------------------------- a fake collector
@pytest.fixture
def short_dir():
    """A directory short enough for a Unix socket path (108 bytes)."""
    base = "/tmp" if os.path.isdir("/tmp") else tempfile.gettempdir()
    path = tempfile.mkdtemp(prefix="ppfeed-", dir=base)
    yield path
    shutil.rmtree(path, ignore_errors=True)


class FakeCollector:
    """Serves one scripted list of lines per connection on a Unix socket (or loopback TCP), after holding
    the subscription to the README's exact bytes, then ends the connection. A connection past the scripts
    is held open and silent. A script entry `("pause", s)` waits."""

    def __init__(self, scripts, path=None, tcp=False):
        self.scripts = list(scripts)
        self.received = []
        self.connections = 0
        if tcp:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.bind(("127.0.0.1", 0))
            self.address = self.server.getsockname()
        else:
            self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.server.bind(path)
            self.address = path
        self.server.listen(4)
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        self.server.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self.server.accept()
            except (socket.timeout, OSError):
                continue
            self.connections += 1
            with conn:
                conn.settimeout(5)
                got = b""
                while not got.endswith(b"\n") and len(got) < 256:
                    chunk = conn.recv(256)
                    if not chunk:
                        break
                    got += chunk
                self.received.append(got)
                if not self.scripts:
                    self._stop.wait(30)
                    continue
                for item in self.scripts.pop(0):
                    if isinstance(item, tuple):
                        self._stop.wait(item[1])
                        continue
                    try:
                        conn.sendall(item + b"\n")
                    except OSError:
                        break

    def close(self):
        self._stop.set()
        self.server.close()
        self.thread.join(5)


def _wait(predicate, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def evidence_root(tmp_path, monkeypatch):
    root = tmp_path / "evidence"
    root.mkdir()
    monkeypatch.setattr(evidence.SETTINGS, "evidence_roots", [str(root)])
    return root


def _client(endpoint, store, **kw):
    client = feed_client.FeedClient(endpoint, str(store) if store else None, "test", read_timeout_s=kw.pop("read_timeout_s", 5),
                                    backoff_max_s=0.2, **kw)
    client.start()
    return client


def test_the_client_subscribes_checks_and_keeps_a_good_stream(short_dir, evidence_root):
    fake = FakeCollector([SESSION], path=os.path.join(short_dir, "f.sock"))
    store = evidence_root / "collector-feed"
    client = _client(("unix", fake.address), store)
    try:
        assert _wait(lambda: client.check is not None and client.check.segments and client.check.segments[0]["ended"] == "eof")
        assert fake.received[0] == b'{"op":"subscribe","protocol":"prismpath.collector/1"}\n'
        live = client.live(limit=5)
        assert live["chain"]["status"] == "intact" and live["chain"]["received"] == 21
        assert [entry["index"] for entry in live["recent"]] == [20, 19, 18, 17, 16]
        decision = next(entry for entry in live["recent"] if entry["kind"] == "decision")
        assert decision["cause"]["label"] and "outcome_name" in decision and decision["src_ip"] == "127.0.0.1"
        assert live["enforcer"]["counters"]["allow"] == "11" and live["feed"]["dropped"] == 0
        session = _records(SESSION)[0]["session"]
        kept = store / session
        assert client.kept == str(kept)
        assert (kept / "feed-000000.jsonl").read_bytes() == b"".join(line + b"\n" for line in SESSION)
        assert (kept / "feed-000000.jsonl").stat().st_mode & 0o777 == 0o600
        note = canon2.loads((kept / "feed-000000.end.json").read_bytes().rstrip(b"\n"))
        assert note["format"] == feed.FEED_FORMAT and note["ended"] == "eof" and note["lines"] == len(SESSION)
        report = feed.feed_report(str(kept))
        assert report["status"] == "intact" and report["root"] == live["chain"]["root"]
        assert report["files"][0]["sha256"] == hashlib.sha256((kept / "feed-000000.jsonl").read_bytes()).hexdigest()
        series = client.series(60)
        assert series["source"] == "live" and series["clock"] == "arrival" and series["events"] == 21

        def total(field, key=None):
            return sum(count for bucket in series["buckets"] for name, count in bucket[field].items()
                       if key is None or name == key)
        assert total("by_action") == 21 and total("by_action", "malformed") == 1
        assert total("by_action", "allow") == 11
        assert total("by_cause") == 20       # every decision; the malformed record has no cause
        assert series["causes"]["32"]["name"] == "route:no-matching-edge"
        assert series["causes"]["0"]["clean"] is True
    finally:
        client.stop()
        fake.close()


def test_the_client_reconnects_and_a_new_session_is_a_new_tree(short_dir, evidence_root):
    fake = FakeCollector([SESSION, LATE], path=os.path.join(short_dir, "f.sock"))
    store = evidence_root / "collector-feed"
    client = _client(("unix", fake.address), store)
    try:
        late_session = _records(LATE)[0]["session"]
        assert _wait(lambda: client.check is not None and client.check.session == late_session
                     and client.check.segments[-1]["ended"] == "eof")
        snap = client.snapshot()
        assert snap["connects"] >= 2
        assert snap["previous_session"]["session"] == _records(SESSION)[0]["session"]
        assert snap["previous_session"]["status"] == "intact"
        assert snap["chain"]["status"] == "intact" and snap["chain"]["joined_at"] == 11
        assert sorted(os.listdir(store)) == sorted([_records(SESSION)[0]["session"], late_session])
        assert feed.feed_report(str(store / late_session))["status"] == "intact"
        listed = {entry["session"] for entry in evidence.discover_logs()["feeds"]}
        assert listed == {late_session, _records(SESSION)[0]["session"]}
    finally:
        client.stop()
        fake.close()


def test_a_reconnect_to_the_same_session_keeps_one_session_with_a_hole(short_dir, evidence_root):
    records = _records(SESSION)
    cut = _index_of(SESSION, lambda record: record.get("index") == 9)
    leaves = [record["leaf"] for record in records if record["kind"] in feed.LEAF_KINDS]
    join = MerkleAccumulator(leaves[:14])
    second = [SESSION[0], _dump({"kind": "seal", "source": "gnet", "session": records[0]["session"], "trigger": "join",
                                 "count": 14, "peaks": join.peaks(), "root": join.root(), "malformed": 0})]
    second += SESSION[_index_of(SESSION, lambda record: record.get("index") == 14):]
    fake = FakeCollector([SESSION[:cut], second], path=os.path.join(short_dir, "f.sock"))
    store = evidence_root / "collector-feed"
    client = _client(("unix", fake.address), store)
    try:
        assert _wait(lambda: client.check is not None and len(client.check.segments) == 2
                     and client.check.segments[1]["ended"] == "eof")
        chain = client.snapshot()["chain"]
        assert chain["status"] == "holes" and chain["findings"] == []
        assert chain["holes"] == [{"from": 9, "to": 14, "leaves": 5, "why": "disconnected", "segment": 1}]
        kept = store / records[0]["session"]
        assert sorted(name for name in os.listdir(kept) if name.endswith(".jsonl")) == ["feed-000000.jsonl", "feed-000001.jsonl"]
        report = feed.feed_report(str(kept))
        assert report["status"] == "holes" and report["holes"] == chain["holes"] and report["root"] == chain["root"]
        alone = feed.feed_report(str(kept), segment=1)
        assert alone["status"] == "intact" and alone["joined_at"] == 14
    finally:
        client.stop()
        fake.close()


def test_an_oversized_line_closes_the_connection_and_the_client_reconnects(short_dir, evidence_root):
    big = _dump({"kind": "status", "pad": "x" * 9000})
    fake = FakeCollector([SESSION[:5] + [big] + SESSION[5:], SESSION[:3]], path=os.path.join(short_dir, "f.sock"))
    client = _client(("unix", fake.address), evidence_root / "collector-feed")
    try:
        assert _wait(lambda: client.check is not None and len(client.check.segments) == 2)
        first = client.check.segments[0]
        assert first["ended"] == "oversized"
        chain = client.snapshot()["chain"]
        assert chain["findings"][0]["check"] == "oversized" and chain["status"] == "broken"
        kept = evidence_root / "collector-feed" / _records(SESSION)[0]["session"]
        assert (kept / "feed-000000.jsonl").read_bytes() == b"".join(line + b"\n" for line in SESSION[:5])
        assert canon2.loads((kept / "feed-000000.end.json").read_bytes().rstrip(b"\n"))["ended"] == "oversized"
        assert feed.feed_report(str(kept), segment=0)["findings"][0]["check"] == "oversized"
    finally:
        client.stop()
        fake.close()


def test_a_hello_cannot_raise_the_bound_past_the_hard_limit(short_dir):
    hello = _replace(SESSION, 0, lambda record: record.update(max_record=10_000_000))
    huge = _dump({"kind": "weather", "pad": "y" * (feed.HARD_MAX_RECORD + 10)})
    fake = FakeCollector([hello[:2] + [huge]], path=os.path.join(short_dir, "f.sock"))
    client = _client(("unix", fake.address), None)
    try:
        assert _wait(lambda: client.check is not None and client.check.segments[0]["ended"] == "oversized")
    finally:
        client.stop()
        fake.close()


def test_a_refused_subscription_is_reported_and_retried(short_dir):
    refused = [_dump({"kind": "refused", "reason": "busy"})]
    fake = FakeCollector([refused, SESSION[:4]], path=os.path.join(short_dir, "f.sock"))
    client = _client(("unix", fake.address), None)
    try:
        assert _wait(lambda: client.check is not None and client.check.received == 2)
        assert fake.connections >= 2
        assert client.snapshot()["kept"] is None       # nothing is kept without a store
    finally:
        client.stop()
        fake.close()


def test_a_silent_collector_is_left_and_reconnected(short_dir):
    fake = FakeCollector([SESSION[:3] + [("pause", 2.0)], SESSION[:3]], path=os.path.join(short_dir, "f.sock"))
    client = _client(("unix", fake.address), None, read_timeout_s=0.5)
    try:
        assert _wait(lambda: client.check is not None and client.check.segments[0]["ended"] == "silent")
    finally:
        client.stop()
        fake.close()


def test_the_screens_never_wait_on_the_socket(short_dir):
    fake = FakeCollector([SESSION[:2] + [("pause", 5.0)]], path=os.path.join(short_dir, "f.sock"))
    client = _client(("unix", fake.address), None, read_timeout_s=30)
    try:
        assert _wait(lambda: client.connection == "connected" and client.check is not None)
        started = time.monotonic()
        for _ in range(50):
            client.live()
            client.series(60)
            client.snapshot()
        assert time.monotonic() - started < 1.0
    finally:
        client.stop()
        fake.close()


def test_a_loopback_tcp_collector_is_read():
    fake = FakeCollector([SESSION], tcp=True)
    client = _client(("tcp", fake.address), None)
    try:
        assert _wait(lambda: client.check is not None and client.check.segments[0]["ended"] == "eof")
        assert client.snapshot()["chain"]["status"] == "intact"
    finally:
        client.stop()
        fake.close()


def test_a_long_session_rotates_at_a_seal_and_every_segment_checks_alone(short_dir, evidence_root):
    fake = FakeCollector([SESSION], path=os.path.join(short_dir, "f.sock"))
    store = evidence_root / "collector-feed"
    client = _client(("unix", fake.address), store, rotate_bytes=3000)
    try:
        assert _wait(lambda: client.check is not None and client.check.segments[-1]["ended"] == "eof")
        kept = store / _records(SESSION)[0]["session"]
        segments = sorted(name for name in os.listdir(kept) if feed.SEGMENT_RE.match(name))
        assert len(segments) >= 2
        for name in segments:
            lines = (kept / name).read_bytes().split(b"\n")[:-1]
            assert lines[0] == SESSION[0] and json.loads(lines[1])["kind"] == "seal"
            assert feed.feed_report(str(kept), segment=int(name[5:11]))["status"] in ("intact", "pending")
        whole = feed.feed_report(str(kept))
        assert whole["status"] == "intact" and whole["root"] == _records(SESSION)[-2]["root"]
        assert whole["received"] == 21
        assert client.snapshot()["chain"]["status"] == "intact"
    finally:
        client.stop()
        fake.close()


# ----------------------------------------------------------------- the kept session read back
def test_a_kept_session_is_read_confined_and_bounded(tmp_path, evidence_root, monkeypatch):
    kept = evidence_root / "collector-feed" / _records(SESSION)[0]["session"]
    kept.mkdir(parents=True)
    (kept / "feed-000000.jsonl").write_bytes(b"".join(line + b"\n" for line in SESSION))
    assert feed.feed_report(str(kept))["status"] == "intact"
    assert feed.feed_report("collector-feed/" + kept.name)["status"] == "intact"
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    with pytest.raises(evidence.EvidenceRefused) as refused:
        feed.feed_report(str(outside))
    assert refused.value.reason == "outside-roots"
    with pytest.raises(evidence.EvidenceRefused) as refused:
        feed.feed_report(str(kept), segment=4)
    assert refused.value.reason == "bad-request"
    monkeypatch.setattr(evidence.SETTINGS, "max_evidence_bytes", 1000)
    with pytest.raises(evidence.EvidenceRefused) as refused:
        feed.feed_report(str(kept))
    assert refused.value.reason == "too-large"
    # a kept copy edited after the fact is found on reading
    monkeypatch.setattr(evidence.SETTINGS, "max_evidence_bytes", 1 << 20)
    position = _index_of(SESSION, lambda record: record.get("index") == 3)
    (kept / "feed-000000.jsonl").write_bytes(b"".join(line + b"\n" for line in
                                                      _replace(SESSION, position, lambda r: r.update(leaf="ab" * 32))))
    assert feed.feed_report(str(kept))["status"] == "broken"
    (kept / "feed-000000.jsonl").write_bytes(b"".join(line + b"\n" for line in SESSION)[:-1])
    assert feed.feed_report(str(kept))["findings"][0]["check"] == "truncated"


def test_a_link_out_of_the_roots_is_not_followed(tmp_path, evidence_root):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "feed-000000.jsonl").write_bytes(b"".join(line + b"\n" for line in SESSION))
    kept = evidence_root / "collector-feed" / ("aa" * 16)
    kept.mkdir(parents=True)
    os.symlink(outside / "feed-000000.jsonl", kept / "feed-000000.jsonl")
    with pytest.raises(evidence.EvidenceRefused) as refused:
        feed.feed_report(str(kept))
    assert refused.value.reason == "outside-roots"
