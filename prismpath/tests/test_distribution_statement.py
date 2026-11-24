# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The controller key and the controller statement (spec-policy-distribution.md, K6, K7, H6, H9, H15 and H16):
the `trust.controller` kind, the `/2` anchor, the epoch id a PEP takes only from a verified statement, the
freshness a fresh statement gives, and the controller that counts the epoch id of each stream durably, signs each
statement with its instance key and files a record whose epoch is not current as `fleet:state-replay` while still
using it. Each test names the conformance case of section 20 it covers. The install and operator roles of section
21 are not built, so the halves of cases 260, 261 and 280 that name them stay pending."""
from dataclasses import replace

import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.distribution import frames, http, state_record  # noqa: E402
from prismpath.distribution import statement as statements  # noqa: E402
from prismpath.distribution import trust as trust_module  # noqa: E402
from prismpath.distribution.controller import Controller  # noqa: E402
from prismpath.distribution.http import LocalTransport, PullClient  # noqa: E402
from prismpath.distribution.kinds import Refused  # noqa: E402
from prismpath.distribution.pep import PepRefused  # noqa: E402
from prismpath.tests import _dist  # noqa: E402
from prismpath.tests._dist import GEN, NOW, STREAM  # noqa: E402
from prismpath.tests.test_distribution_controller import Fleet  # noqa: E402

OLD, NEW = _dist.image(5), _dist.image(7)
H = canon.sha256_hex
YEAR = 365 * 86400


def signed(key="C", *, key_seq=0, stream=STREAM, epoch=1, fresh=False, trust_seq=0, stream_seq=0, expires=0) -> bytes:
    """A controller statement signed by the test key `key`."""
    statement = statements.Statement(key_seq=key_seq, stream=state_record.stream_prefix(stream), epoch=epoch,
                                     fresh=fresh, trust_seq=trust_seq, stream_seq=stream_seq, expires=expires)
    return statements.build(statement, _dist.instance_key(key))


def rekey(point, key: str, seq: int, signer: str = "A") -> bytes:
    """Stage a `trust.controller` naming the test key `key` at trust sequence `seq`."""
    body = _dist.controller_key(key)
    return point.pep.stage(_dist.trust_statement("trust.controller", body, seq=seq, signers=(signer,),
                                                 targets=(point.kind,)), body)


def read(point, data):
    return state_record.read(data, point.key.public_raw)


def controller_for(tmp_path, point, key="C", name="controller"):
    controller = Controller(str(tmp_path / name), _dist.instance_key(key), clock=point.clock)
    controller.add_anchor(point.anchor(), dict(GEN.QUALIFICATION) if point.kind == "host" else None)
    pep_id = controller.enroll(point.key.public_raw, point.kind, point.stream)
    return controller, controller.members[pep_id]


def test_the_controller_statement_is_102_or_126_bytes_and_reads_back():
    """H9: the layout, its two lengths and its signature over the bytes before it."""
    short, fresh = signed(epoch=7), signed(epoch=8, fresh=True, trust_seq=2, stream_seq=3, expires=NOW)
    assert (len(short), len(fresh)) == (102, 126) and short[:4] == b"PPEP"
    public = GEN.public_raw(GEN.test_key("C"))
    assert statements.verify(fresh, public) == statements.Statement(0, state_record.stream_prefix(STREAM), 8, True, 2,
                                                                    3, NOW)
    for broken in (short[:-1], short + b"\x00", b"PPEX" + short[4:], short[:37] + b"\x02" + short[38:]):
        with pytest.raises(Refused):
            statements.parse(broken)
        assert statements.verify(broken, public) is None


def test_case_256_a_restarted_pep_reports_epoch_0_until_it_takes_a_current_statement(tmp_path):
    """case_256: H15, H6, H9, the Python half on a `host` and a `mesh` PEP. Each reports epoch 0 after a restart,
    its records are filed `fleet:state-replay` and still used, marked unverified for freshness, and once it takes
    the controller's statement its records are accepted."""
    for maker in (_dist.HostPep, _dist.MeshPep):
        point = maker(tmp_path / maker.__name__, controller="C")
        controller, member = controller_for(tmp_path, point, name=f"c_{maker.__name__}")
        assert point.pep.take_statement(controller.statement(STREAM)) and point.pep.epoch == 1
        assert controller.receive(point.pep.record("beat")) is None
        point.pep = point.open()
        record = read(point, point.pep.record("beat"))
        assert record.epoch == 0
        assert controller.receive(state_record.build(record, point.key)) == "fleet:state-replay"
        assert member.counter == record.counter and member.last["unverified"] is True        # used
        assert controller.fleet()["peps"][0]["unverified"] is True
        assert point.pep.take_statement(controller.statement(STREAM))
        assert controller.receive(point.pep.record("beat")) is None
        assert "fleet:state-replay" not in member.findings and member.last["unverified"] is False


def test_case_257_a_pep_takes_no_epoch_from_anything_but_a_good_statement(tmp_path):
    """case_257: H9, K6. An epoch id with no statement, a statement signed by an authority key, one by an unknown
    key, one with a byte changed and one with another key sequence change nothing and send no record, and a PEP
    with no controller key takes no good statement."""
    point = _dist.HostPep(tmp_path / "host", controller="C")
    point.pep.drain()
    client = PullClient(point.pep, LocalTransport(None))
    client._act({"epoch": 9, "offers": [], "commit": [], "abort": []})
    good = signed(epoch=5)
    changed = good[:30] + bytes([good[30] ^ 1]) + good[31:]
    for bad in (signed("A", epoch=5), signed("U", epoch=5), changed, signed(key_seq=1, epoch=5)):
        assert not point.pep.take_statement(bad)
    assert point.pep.epoch == 0 and point.pep.drain() == []
    bare = _dist.HostPep(tmp_path / "bare")                               # a /1 anchor names no controller key
    bare.pep.drain()
    assert not bare.pep.take_statement(good) and bare.pep.epoch == 0 and bare.pep.drain() == []
    assert http._statement(9) is None and http._statement("") is None


def test_case_258_a_higher_epoch_is_taken_and_never_lowered(tmp_path):
    """case_258: H9. A statement above the id held is taken, the same again and a lower one change nothing."""
    point = _dist.HostPep(tmp_path / "host", controller="C")
    assert point.pep.take_statement(signed(epoch=6))
    assert not point.pep.take_statement(signed(epoch=6)) and not point.pep.take_statement(signed(epoch=2))
    assert point.pep.epoch == 6 and read(point, point.pep.record("beat")).epoch == 6


def test_case_259_a_trust_controller_names_a_new_key_and_starts_the_epoch_again(tmp_path):
    """case_259: K7, H9, H15. The statement is applied with `trust-applied` and epoch 0. Then a statement by the old
    key, one by the new key with the old key sequence, and one by the new key with the new key sequence and an epoch
    id below the one held before: nothing, nothing, taken."""
    point = _dist.HostPep(tmp_path / "host", controller="C")
    point.pep.take_statement(signed(epoch=9))
    applied = read(point, rekey(point, "D", 1))
    assert (applied.event, applied.epoch, applied.trust_seq) == ("trust-applied", 0, 1)
    assert point.pep.trust.controller[0] == _dist.key_id("D") and point.pep.trust.key_seq == 1
    assert _dist.key_id("C") in point.pep.trust.retired
    assert not point.pep.take_statement(signed("C", key_seq=1, epoch=20))
    assert not point.pep.take_statement(signed("D", key_seq=0, epoch=20))
    assert point.pep.take_statement(signed("D", key_seq=1, epoch=3)) and point.pep.epoch == 3
    assert point.open().trust.controller[0] == _dist.key_id("D")         # durable in the trust store


def test_case_260_a_trust_controller_may_not_name_a_key_of_another_role(tmp_path):
    """case_260: K6, K7, K4, the half without install and operator keys (section 21). A `trust.controller` whose key
    is an authority key, the PEP's instance key, a revoked key, the controller key it replaced before and a retired
    key is `dist:rotation-invalid` each time, and an anchor whose controller key is also an authority key is
    refused at provisioning."""
    point = _dist.HostPep(tmp_path / "host", authorities=["A", "B"], controller="C")
    causes = [read(point, rekey(point, "A", 1)).cause, read(point, rekey(point, "I", 1)).cause]
    point.revoke(1, keys=[_dist.key_id("R")])
    causes.append(read(point, rekey(point, "R", 2)).cause)
    assert read(point, rekey(point, "D", 2)).event == "trust-applied"
    causes.append(read(point, rekey(point, "C", 3)).cause)               # the key D replaced
    assert read(point, point.rotate(3, "E", retire="B")).event == "trust-applied"
    causes.append(read(point, rekey(point, "B", 4)).cause)               # retired as an authority key
    assert causes == ["dist:rotation-invalid"] * 5 and point.pep.trust.trust_seq == 3
    with pytest.raises(Refused):
        trust_module.anchor_bytes([GEN.public_raw(GEN.test_key("A"))], target="host", stream=STREAM,
                                  controller=GEN.public_raw(GEN.test_key("A")))
    from prismpath.kernel import canon2
    doc = canon2.loads(point.anchor())
    shared = canon2.dumps({**doc, "controller": GEN.public_raw(GEN.test_key("A")).hex()})
    with pytest.raises(Refused):
        point.pep.provision(shared)
    assert not point.pep.store.exists("anchor.pending")


def test_case_261_the_controller_key_signs_no_envelope_and_no_rotation_adds_it(tmp_path):
    """case_261: K6, K4, S3, O4, the half without install keys (IS11 waits for section 21). A release, a revocation
    and a rotation signed only by the controller key are `dist:unknown-key`, and a rotation that adds the
    controller key is `dist:rotation-invalid`."""
    point = _dist.HostPep(tmp_path / "host", controller="C")
    release = point.pep.stage(_dist.seal("policy.ppt", OLD, signer="C"), OLD)
    body = _dist.revocation()
    revocation = point.pep.stage(_dist.trust_statement("trust.revocation", body, seq=1, signers=("C",)), body)
    rotation = _dist.rotation("B")
    rotated = point.pep.stage(_dist.trust_statement("trust.rotation", rotation, seq=1, signers=("C",)), rotation)
    adds = point.rotate(1, "C")
    assert [read(point, one).cause for one in (release, revocation, rotated, adds)] == [
        "dist:unknown-key", "dist:unknown-key", "dist:unknown-key", "dist:rotation-invalid"]
    assert point.pep.trust.trust_seq == 0 and point.pep.active is None


def test_case_262_a_revoked_controller_key_gives_nothing_until_a_new_key_is_named(tmp_path):
    """case_262: K6, K7, R2. After the controller key is revoked a good statement is not taken. A `trust.controller`
    naming a new key follows, and a statement under it is."""
    point = _dist.HostPep(tmp_path / "host", controller="C")
    point.revoke(1, keys=[_dist.key_id("C")])
    assert not point.pep.take_statement(signed(epoch=4)) and point.pep.epoch == 0
    assert read(point, rekey(point, "D", 2)).event == "trust-applied"
    assert point.pep.take_statement(signed("D", key_seq=2, epoch=4)) and point.pep.epoch == 4


def test_case_263_a_runaway_epoch_is_undone_by_a_new_controller_key_and_by_a_restart(tmp_path):
    """case_263: K7, H9, H6, H15. A PEP whose epoch id a stolen controller key raised far above the controller's
    has its records filed `fleet:state-replay`, and after a `trust.controller` naming the controller's new key and
    the controller's statement they are accepted. Another such PEP restarts, starts again at 0 and takes the
    controller's next statement."""
    first = _dist.HostPep(tmp_path / "first", controller="C", key=_dist.instance_key("p1"))
    second = _dist.HostPep(tmp_path / "second", controller="C", key=_dist.instance_key("p2"))
    controller = Controller(str(tmp_path / "controller"), _dist.instance_key("D"), clock=first.clock)
    controller.add_anchor(first.anchor(), dict(GEN.QUALIFICATION))
    members = [controller.members[controller.enroll(point.key.public_raw, "host", STREAM)] for point in (first, second)]
    for point in (first, second):
        assert point.pep.take_statement(signed("C", epoch=2 ** 40))       # the stolen key
        assert controller.receive(point.pep.record("beat")) == "fleet:state-replay"
        point.pep.drain()
    body = _dist.controller_key("D")
    sealed = _dist.trust_statement("trust.controller", body, seq=1)
    controller.put(sealed, body)
    applied = read(first, first.pep.stage(sealed, body))
    assert (applied.event, applied.epoch) == ("trust-applied", 0)
    assert controller.receive(first.pep.drain()[-1]) is None              # H6: epoch 0 on this record is not a replay
    assert first.pep.take_statement(controller.statement(STREAM))
    assert controller.receive(first.pep.record("beat")) is None and "fleet:state-replay" not in members[0].findings
    second.pep = second.open()
    assert second.pep.epoch == 0
    second.pep.stage(sealed, body)
    second.pep.drain()
    assert second.pep.take_statement(controller.statement(STREAM))
    assert controller.receive(second.pep.record("beat")) is None


def test_case_264_the_controller_signs_each_statement_and_stores_a_new_key_sequence(tmp_path):
    """case_264: H9, K7, F1. A PEP takes a statement the controller signed with its instance key, the controller
    signs the next under the key sequence of a `trust.controller` it stores, and it refuses and does not store one
    with a bad signature."""
    point = _dist.HostPep(tmp_path / "host", controller="C")
    controller, _member = controller_for(tmp_path, point)
    first = controller.statement(STREAM)
    assert point.pep.take_statement(first) and statements.parse(first)[0].key_seq == 0
    body = _dist.controller_key("C")                                     # the key it holds, at a new key sequence
    sealed = _dist.trust_statement("trust.controller", body, seq=1)
    broken = bytearray(sealed)
    broken[6 + 32] ^= 1
    with pytest.raises(Refused) as refused:
        controller.put(bytes(broken), body)
    assert refused.value.cause == "sig:invalid" and controller.chain == []
    controller.put(sealed, body)
    assert controller.key_seq() == 1 and statements.parse(controller.statement(STREAM))[0].key_seq == 1
    point.pep.stage(sealed, body)
    point.clock.now += controller.interval
    assert point.pep.take_statement(controller.statement(STREAM)) and point.pep.trust.key_seq == 1


def test_case_268_epoch_0_is_accepted_where_h6_says_and_a_replay_elsewhere(tmp_path):
    """case_268: H6, H15, P4. A `provisioned` record with epoch 0, the `trust-applied` record of a `trust.controller`
    the controller holds with epoch 0, a `beat` with epoch 0 from a PEP enrolled with a controller key, and a record
    with epoch 0 from a PEP with a `/1` anchor: accepted, accepted, replay, accepted."""
    point = _dist.HostPep(tmp_path / "host", controller="C")
    controller, member = controller_for(tmp_path, point)
    controller.clock = lambda: NOW + 5 * controller.interval
    provisioned = point.pep.drain()[-1]
    assert read(point, provisioned).event == "provisioned" and controller.receive(provisioned) is None
    body = _dist.controller_key("C")
    sealed = _dist.trust_statement("trust.controller", body, seq=1)
    controller.put(sealed, body)
    point.pep.stage(sealed, body)
    assert controller.receive(point.pep.drain()[-1]) is None
    assert controller.receive(point.pep.record("beat")) == "fleet:state-replay"
    bare = _dist.HostPep(tmp_path / "bare", key=_dist.instance_key("p9"))
    other, _ = controller_for(tmp_path, bare, name="other")
    other.clock = controller.clock
    for data in bare.pep.drain() + [bare.pep.record("beat")]:
        assert other.receive(data) is None


def test_a_pep_with_no_controller_key_still_moves_a_rollout_after_many_intervals(tmp_path):
    """H6, P4: a PEP enrolled from a `/1` anchor holds no controller key, so its records carry epoch 0 and are never
    a replay for it, however far the controller's epoch id has moved. Its acks and its commit move a rollout after
    the controller's clock ran past several heartbeat intervals."""
    fleet = Fleet(tmp_path, names=("p1",), controller=None)
    fleet.clock.now += 7 * fleet.controller.interval
    fleet.controller.tick()
    assert fleet.controller.epoch_of(STREAM) == 8
    fleet.put(OLD, 1)
    rollout = fleet.controller.offer("fleet", STREAM, 1)
    for _ in range(3):
        fleet.clock.now += 2 * fleet.controller.interval
        fleet.round()
    member = fleet.member("p1")
    assert rollout.state == "committed" and member.last["epoch"] == 0 and fleet.points["p1"].pep.active.seq == 1
    assert "fleet:state-replay" not in member.findings and member.last["no_controller_key"] is True
    assert fleet.controller.fleet()["peps"][0]["no_controller_key"] is True


def test_case_269_a_pep_cut_off_past_its_fresh_statement_lapses(tmp_path):
    """case_269: H16, X1, the `host` and `mesh` half (the `cfs` HOLD half is in test_cfs_dist.py). With `fresh` 3600
    each takes a fresh statement and, cut off for 3901 seconds, lapses with dist:expired."""
    for maker in (_dist.HostPep, _dist.MeshPep):
        point = maker(tmp_path / maker.__name__, controller="C", fresh=3600)
        controller, _member = controller_for(tmp_path, point, name=f"c_{maker.__name__}")
        for sealed, body in _dist.release_with_statement(point, OLD, 1, widen=True, replaces=""):
            controller.put(sealed, body)                                 # the stream seq the statement names
        point.commit(OLD)
        assert point.pep.take_statement(controller.statement(STREAM)) and point.pep.kept is not None
        point.clock.now += 3900
        assert point.pep.tick() is None and point.pep.state() == "active"
        point.clock.now += 1
        lapsed = read(point, point.pep.tick())
        assert (lapsed.event, lapsed.cause, lapsed.state) == ("lapsed", "dist:expired", "no-policy")


def test_case_270_what_gives_freshness(tmp_path):
    """case_270: H16, H9, T1. With `fresh` 3600, a statement for another stream changes nothing, one whose trust
    sequence is below the PEP's, one whose stream seq is below its floor and one 3901 seconds ahead give no
    freshness, one 3900 seconds ahead gives it and one with `fresh` 0 gives none. The epoch ids of all but the
    first are taken, and the time floor does not move."""
    point = _dist.HostPep(tmp_path / "host", controller="C", fresh=3600)
    point.commit(OLD)
    point.revoke(1)
    floor = point.pep.trust.time_floor
    now = point.clock.now
    good = {"fresh": True, "trust_seq": 1, "stream_seq": 1}
    sent = [signed(stream="other/stream", epoch=1, expires=now + 3600, **good),
            signed(epoch=2, expires=now + 3600, **{**good, "trust_seq": 0}),
            signed(epoch=3, expires=now + 3600, **{**good, "stream_seq": 0}),
            signed(epoch=4, expires=now + 3901, **good),
            signed(epoch=5, expires=now + 3900, **good),
            signed(epoch=6, expires=now + 7200)]
    taken, kept = [], []
    for data in sent:
        taken.append(point.pep.take_statement(data))
        kept.append(point.pep.kept["expires"] if point.pep.kept else None)
    assert taken == [False, True, True, True, True, True]
    assert kept == [None, None, None, None, now + 3900, now + 3900]
    assert point.pep.trust.time_floor == floor and point.pep.epoch == 6


def test_case_271_freshness_off_decides_a_year_and_a_kept_statement_survives_a_restart(tmp_path):
    """case_271: H16, P4. A PEP with `fresh` 0 cut off for a year with a release that expires in two decides under
    it the whole year, and a PEP with `fresh` 3600 still holds its fresh statement after a restart."""
    point = _dist.HostPep(tmp_path / "off", controller="C")
    point.commit(OLD, expires=NOW + 2 * YEAR)
    point.clock.now += YEAR
    assert point.pep.tick() is None and point.pep.decide(lambda: "ran")["decision"] == "ran"
    fresh = _dist.HostPep(tmp_path / "on", controller="C", fresh=3600)
    controller, _member = controller_for(tmp_path, fresh)
    assert fresh.pep.take_statement(controller.statement(STREAM))
    kept = fresh.pep.kept
    fresh.pep = fresh.open()
    assert fresh.pep.kept == kept and fresh.pep.epoch == 0


def test_case_275_a_replay_by_epoch_alone_is_still_used_and_a_stale_counter_is_dropped(tmp_path):
    """case_275: H6. With the last counter at 40, a `refused` record with dist:install-lost, counter 41 and an epoch
    three epochs old is filed `fleet:state-replay` and its event is taken, marked unverified for freshness. A record
    with counter 40 then is dropped."""
    point = _dist.HostPep(tmp_path / "host", controller="C")
    controller, member = controller_for(tmp_path, point)
    point.clock.now += 5 * controller.interval
    controller.tick()
    member.counter = 40
    base = read(point, point.pep.record("beat"))
    old = controller.epoch_of(STREAM) - 3
    lost = replace(base, event="refused", cause="dist:install-lost", counter=41, epoch=old)
    assert controller.receive(state_record.build(lost, point.key)) == "fleet:state-replay"
    assert (member.last["event"], member.last["cause"], member.last["unverified"]) == ("refused", "dist:install-lost",
                                                                                      True)
    assert member.counter == 41
    stale = replace(base, counter=40, epoch=controller.epoch_of(STREAM))
    assert controller.receive(state_record.build(stale, point.key)) == "fleet:state-replay"
    assert member.counter == 41 and member.last["event"] == "refused"


def test_case_276_a_broadcast_starves_no_stream(tmp_path):
    """case_276: H9. A broadcast carries controller statements for `mesh/a` and `mesh/b` in turn, and a `mesh` PEP
    on each stream takes every statement of its own stream and none of the other's."""
    nodes = {stream: _dist.MeshPep(tmp_path / stream.replace("/", "_"), controller="C", stream=stream,
                                   key=_dist.instance_key(stream)) for stream in ("mesh/a", "mesh/b")}
    controller = Controller(str(tmp_path / "controller"), _dist.instance_key("C"), clock=_dist.Clock())
    for node in nodes.values():
        controller.add_anchor(node.anchor())
    assembler = {stream: frames.Assembler(lambda sealed: None, clock=lambda: 0.0) for stream in nodes}
    taken = {stream: [] for stream in nodes}
    for turn in range(3):
        controller.clock.now += controller.interval
        for stream in ("mesh/a", "mesh/b"):
            data = frames.encode(frames.Epoch(turn, controller.statement(stream)))
            for name, node in nodes.items():
                event = assembler[name].receive(data)
                if node.pep.take_statement(event.statement):
                    taken[name].append(statements.parse(event.statement)[0].stream)
    assert taken == {name: [state_record.stream_prefix(name)] * 3 for name in nodes}
    assert {name: node.pep.epoch for name, node in nodes.items()} == {"mesh/a": 4, "mesh/b": 4}


def test_case_277_a_stolen_key_at_the_top_keeps_no_good_statement_from_freshness(tmp_path):
    """case_277: H9, H16, H15. A statement by the stolen controller key with epoch id 2^64 - 1 is taken, a good fresh
    statement from the controller still gives freshness, and after a restart the PEP takes the controller's next
    epoch id."""
    point = _dist.HostPep(tmp_path / "host", controller="C", fresh=3600)
    controller, _member = controller_for(tmp_path, point)
    assert point.pep.take_statement(signed(epoch=2 ** 64 - 1)) and point.pep.epoch == 2 ** 64 - 1
    good = controller.statement(STREAM)
    assert not point.pep.take_statement(good) and point.pep.kept["expires"] == NOW + 3600
    point.pep = point.open()
    point.clock.now += controller.interval
    assert point.pep.take_statement(controller.statement(STREAM)) and point.pep.epoch == 2


def test_case_278_a_clockless_pep_takes_time_once_a_start(tmp_path):
    """case_278: H16, T1, T2. A `mesh` PEP with no clock and `fresh` 3600 that was off for 30 days starts and takes
    a good fresh statement as a raise of its time floor to its `expires` less 3600, with freshness. One a year ahead
    in the same start gives none and moves nothing, and a `host` PEP with a clock takes no time and no freshness from
    one a year ahead."""
    node = _dist.MeshPep(tmp_path / "mesh", controller="C", fresh=3600, has_clock=False)
    node.pep = node.open()                                              # a start, its clock where it stopped
    true_time = NOW + 30 * 86400
    first = signed(epoch=1, fresh=True, expires=true_time + 3600)
    assert node.pep.take_statement(first)
    assert node.pep.trust.time_floor == true_time and node.pep.kept["expires"] == true_time + 3600
    assert node.pep.take_statement(signed(epoch=2, fresh=True, expires=true_time + YEAR))
    assert node.pep.trust.time_floor == true_time and node.pep.kept["expires"] == true_time + 3600
    host = _dist.HostPep(tmp_path / "host", controller="C", fresh=3600)
    floor = host.pep.trust.time_floor
    assert host.pep.take_statement(signed(epoch=1, fresh=True, expires=NOW + YEAR))
    assert host.pep.trust.time_floor == floor and host.pep.kept is None


def test_case_279_a_store_gains_a_controller_key_and_keeps_its_bound(tmp_path):
    """case_279: K7, K5, H6. A PEP provisioned from a `/1` anchor gains the key a `trust.controller` names and takes a
    statement under it. A store of 8 authority keys and no controller key refuses one with dist:too-large. A
    `trust.controller` naming the key already held keeps it at the new key sequence, and a statement under the old
    key sequence is not taken."""
    bare = _dist.HostPep(tmp_path / "bare")
    assert bare.pep.trust.controller is None
    assert read(bare, rekey(bare, "C", 1)).event == "trust-applied"
    assert bare.pep.take_statement(signed(key_seq=1, epoch=3)) and bare.pep.epoch == 3
    full = _dist.HostPep(tmp_path / "full", authorities=list("ABDEFGHJ"))
    assert len(full.pep.trust.keys) == 8 and read(full, rekey(full, "C", 1)).cause == "dist:too-large"
    held = _dist.HostPep(tmp_path / "held", controller="C")
    assert read(held, rekey(held, "C", 1)).event == "trust-applied"
    assert held.pep.trust.controller[0] == _dist.key_id("C") and held.pep.trust.key_seq == 1
    assert _dist.key_id("C") not in held.pep.trust.retired
    assert not held.pep.take_statement(signed(key_seq=0, epoch=5))
    assert held.pep.take_statement(signed(key_seq=1, epoch=5))


def test_case_280_an_anchor_whose_controller_key_is_the_instance_key_is_refused(tmp_path):
    """case_280: P2, K4, K6, the instance key half (the install and operator keys wait for section 21). The anchor is
    refused at provisioning and the PEP is unchanged."""
    point = _dist.HostPep(tmp_path / "host")
    before = point.pep.trust.document(), point.pep.store.path("anchor.json")
    own = trust_module.anchor_bytes([GEN.public_raw(GEN.test_key("A"))], target="host", stream=STREAM,
                                    controller=point.key.public_raw)
    with pytest.raises(PepRefused):
        point.pep.provision(own)
    assert point.pep.trust.document() == before[0] and not point.pep.store.exists("anchor.pending")


def test_a_v2_anchor_reads_and_a_v1_anchor_still_does():
    """P4: the `/2` anchor holds the controller key and `fresh`, a `/1` holds neither, both hold authority keys only,
    and an install member, which this version does not build, refuses the anchor."""
    authority, controller = GEN.public_raw(GEN.test_key("A")), GEN.public_raw(GEN.test_key("C"))
    two = trust_module.read_anchor(trust_module.anchor_bytes([authority], target="host", stream=STREAM,
                                                             controller=controller, fresh=60))
    one = trust_module.read_anchor(trust_module.anchor_bytes([authority], target="host", stream=STREAM))
    assert (two.format, two.controller, two.fresh) == ("prismpath.dist-trust/2", controller, 60)
    assert (one.format, one.controller, one.fresh) == ("prismpath.dist-trust/1", None, 0)
    assert two.store().controller[0] == env.key_id(controller) and one.store().controller is None
    from prismpath.kernel import canon2
    doc = canon2.loads(trust_module.anchor_bytes([authority], target="host", stream=STREAM, controller=controller))
    for changed in ({**doc, "install": {}}, {**doc, "keys": {kid: {**key, "role": "controller"}
                                                             for kid, key in doc["keys"].items()}}):
        with pytest.raises(Refused):
            trust_module.read_anchor(canon2.dumps(changed))
