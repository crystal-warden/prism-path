# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The reference controller (spec-policy-distribution.md, section 15.3, with H6 to H10 and R8), driving host
PEPs in process through the pull client. Each test names the conformance case of section 20 it covers. The
same machine over real HTTP is in test_distribution_http.py."""
import json
from dataclasses import replace

import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.distribution import frames, state_record  # noqa: E402
from prismpath.distribution import trust as trust_module  # noqa: E402
from prismpath.distribution import verify as verifier  # noqa: E402
from prismpath.distribution.controller import Controller, FrameDriver, eat_nonces  # noqa: E402
from prismpath.distribution.http import LocalTransport, PullClient  # noqa: E402
from prismpath.distribution.kinds import Refused  # noqa: E402
from prismpath.distribution.trust import check_drops  # noqa: E402
from prismpath.tests import _dist  # noqa: E402
from prismpath.tests._dist import GEN, STREAM  # noqa: E402

OLD, NEW, NEWER = _dist.image(5), _dist.image(7), _dist.image(9)
H = canon.sha256_hex


class Tampering(LocalTransport):
    """A transport that flips a signature byte of every sealed envelope it carries, as a man in the middle
    could. The envelope id, which names the blob, does not cover the signature."""

    def blob(self, name, bound):
        data = super().blob(name, bound)
        if name in self.controller.stored:
            data = bytearray(data)
            data[6 + 32] ^= 1
            data = bytes(data)
        return data


class Fleet:
    """A controller and host PEPs under one clock, each PEP pulling through `LocalTransport`."""

    def __init__(self, tmp_path, names=("p1", "p2", "p3"), rule="each", group="fleet", kind="host", controller="C",
                 fresh=0):
        self.clock = _dist.Clock()
        self.dir = tmp_path / "controller"
        self.controller = Controller(str(self.dir), _dist.instance_key("C"), clock=self.clock)
        maker = _dist.MeshPep if kind == "mesh" else _dist.HostPep
        self.points = {name: maker(tmp_path / name, clock=self.clock, key=_dist.instance_key(name),
                                   controller=controller, fresh=fresh) for name in names}
        first = next(iter(self.points.values()))
        self.controller.add_anchor(first.anchor(), dict(GEN.QUALIFICATION) if kind == "host" else None)
        self.ids = {name: self.controller.enroll(point.key.public_raw, kind, STREAM, group, rule)
                    for name, point in self.points.items()}
        self.clients = {name: PullClient(point.pep, LocalTransport(self.controller))
                        for name, point in self.points.items()}
        self.first = first

    def put(self, body, seq, *, widen=None, replaces=None, change=False, **args):
        """Store a release of `body` at `seq`. It replaces the release put before it, and the first one, or one
        put with `widen`, goes with a widening statement that covers any PEP (W2, W3). One put with `change` says
        it does not widen and goes with a change statement from the release it replaces (W11)."""
        previous = getattr(self, "previous", None)
        widen = (self.first.policy_of(body) != previous and not change) if widen is None else widen   # W7
        replaces = (previous or "") if replaces is None else replaces
        pairs = _dist.release_with_statement(self.first, body, seq, widen=widen, replaces=replaces, **args)
        if change:
            pairs.insert(0, _dist.change_of(self.first, body, seq, replaces=replaces,
                                            not_before=args.get("not_before", _dist.NOT_BEFORE)))
        for sealed, data in pairs:
            self.controller.put(sealed, data)
        self.previous = self.first.policy_of(body)
        return pairs[-1][0]

    def round(self, *names):
        for name in names or self.clients:
            self.clients[name].poll()

    def member(self, name):
        return self.controller.members[self.ids[name]]

    def record(self, name, event="beat", **changes):
        """A record made and signed by the PEP `name` now, with `changes` to its fields, re-signed."""
        point = self.points[name]
        point.pep.take_statement(self.controller.statement(STREAM))
        signed = point.pep.record(event)
        point.pep.drain()
        if not changes:
            return signed
        record = replace(state_record.read(signed, point.key.public_raw), **changes)
        return state_record.build(record, point.key)


def test_case_093_a_controller_refuses_to_store_an_envelope_with_a_bad_signature(tmp_path):
    """case_093: F1. It is never stored and never offered."""
    fleet = Fleet(tmp_path, names=("p1",))
    sealed = bytearray(fleet.first.seal(OLD))
    sealed[6 + 32] ^= 1
    with pytest.raises(Refused) as refused:
        fleet.controller.put(bytes(sealed), OLD)
    assert refused.value.cause == "sig:invalid" and fleet.controller.stored == {}
    assert fleet.controller.answer(fleet.ids["p1"])["offers"] == []
    with pytest.raises(ValueError):
        fleet.controller.offer("fleet", STREAM, 1)
    assert [event["action"] for event in fleet.controller.audit.events][-1] == "refused"


def test_case_128_the_controller_reads_meta_in_full_where_every_target_skips_it(tmp_path):
    """case_128: E9, E11, F1, the controller half. The one signed envelope whose counts is an integer, which a
    mesh PEP stages, is refused by the controller serving that mesh stream."""
    corpus = json.loads((_dist.REPO / "portable" / "conformance" / "distribution.json").read_text(encoding="utf-8"))
    loose = next(case for case in corpus["cases"] if case["name"].startswith("128_counts_an_integer_where_meta_is_skipped"))
    assert loose["expect"]["cause"] is None and loose["pep"]["kind"] == "mesh"
    controller = Controller(str(tmp_path / "controller"), _dist.instance_key("C"), clock=lambda: loose["now"])
    anchor = trust_module.anchor_bytes([GEN.public_raw(GEN.test_key(name)) for name in ("A", "B")],
                                             target="mesh", stream=loose["pep"]["stream"])
    controller.add_anchor(anchor)
    with pytest.raises(Refused) as refused:
        controller.put(bytes.fromhex(loose["sealed"]), bytes.fromhex(loose["body"]))
    assert refused.value.cause == "dist:bad-format" and controller.stored == {}


def test_case_095_a_group_under_each_commits_where_it_can_and_files_the_two_refusals(tmp_path):
    """case_095: F3, F4, F5, in process. One member commits, one refuses a downgrade with dist:seq-replay and
    one a signature changed on the way with sig:invalid, and the three audit logs and the controller's show it.
    The same over real HTTP on loopback is the done test in test_distribution_http.py."""
    fleet = Fleet(tmp_path)
    controller = fleet.controller
    controller.enroll(fleet.points["p2"].key.public_raw, "host", STREAM, "canary", "each")
    fleet.put(NEWER, 3)
    controller.offer("canary", STREAM, 3)
    for _ in range(2):
        fleet.round("p2")
    assert fleet.points["p2"].pep.active.seq == 3
    controller.enroll(fleet.points["p2"].key.public_raw, "host", STREAM, "fleet", "each")
    fleet.clients["p3"].transport = Tampering(controller)
    fleet.put(NEW, 2, widen=True, replaces="")         # a first install for p1 and p3
    rollout = controller.offer("fleet", STREAM, 2)
    for _ in range(3):
        fleet.round()
    assert rollout.state == "committed"
    assert rollout.members == {fleet.ids["p1"]: "committed", fleet.ids["p2"]: "refused", fleet.ids["p3"]: "refused"}
    assert fleet.points["p1"].pep.active.seq == 2 and fleet.points["p3"].pep.active is None
    assert fleet.member("p1").findings == {}
    assert set(fleet.member("p2").findings) == {"dist:seq-replay"}
    assert set(fleet.member("p3").findings) == {"sig:invalid"}
    causes = {name: [event["data"].get("cause") for event in point.pep.audit.events if event["action"] == "refused"]
              for name, point in fleet.points.items()}
    assert causes == {"p1": [], "p2": ["dist:seq-replay"] * 2, "p3": ["sig:invalid"] * 2}   # the statement, the release
    assert "committed" in [event["action"] for event in fleet.points["p1"].pep.audit.events]
    logged = [(event["action"], event["data"].get("pep"), event["data"].get("finding"))
              for event in controller.audit.events]
    assert ("commit", fleet.ids["p1"], None) in logged
    assert ("finding", fleet.ids["p2"], "dist:seq-replay") in logged
    assert ("finding", fleet.ids["p3"], "sig:invalid") in logged
    assert controller.audit.verify_log()
    view = controller.fleet()
    by_id = {entry["labels"]["id"]: entry for entry in view["peps"]}
    assert by_id[fleet.ids["p1"]]["bundles"][STREAM]["active_revision"].startswith("2:")
    assert by_id[fleet.ids["p2"]]["bundles"][STREAM]["errors"][0]["code"] == "dist:seq-replay"


def test_case_094_a_group_under_all_with_one_refusal_aborts_and_none_commits(tmp_path):
    """case_094: F3. The two that staged are sent abort and drop the release."""
    fleet = Fleet(tmp_path, rule="all")
    fleet.clients["p2"].transport = Tampering(fleet.controller)
    fleet.put(OLD, 1)
    rollout = fleet.controller.offer("fleet", STREAM, 1)
    for _ in range(3):
        fleet.round()
    assert rollout.state == "aborted"
    assert all(point.pep.active is None and point.pep.staged is None for point in fleet.points.values())
    assert rollout.members[fleet.ids["p2"]] == "refused"
    assert {rollout.members[fleet.ids[name]] for name in ("p1", "p3")} == {"aborted"}
    assert "aborted" in [event["action"] for event in fleet.points["p1"].pep.audit.events]


def test_a_group_under_all_commits_only_when_every_member_staged_and_sends_the_flip_delay(tmp_path):
    """F3 and B8: under `all` nobody is sent commit before the last member staged, and the commit carries the
    rollout's delay, so the group flips together at each PEP's own time."""
    fleet = Fleet(tmp_path, rule="all")
    fleet.put(OLD, 1)
    rollout = fleet.controller.offer("fleet", STREAM, 1, delay_ms=0)
    fleet.round("p1", "p2")
    assert rollout.state == "staging" and fleet.controller.answer(fleet.ids["p1"])["commit"] == []
    fleet.round("p3")
    assert fleet.controller.answer(fleet.ids["p1"])["commit"] == [{"stream": STREAM, "seq": 1, "policy": H(OLD), "delay": 0}]
    for _ in range(2):
        fleet.round()
    assert rollout.state == "committed" and all(point.pep.active.seq == 1 for point in fleet.points.values())


def test_a_stage_window_that_ends_under_all_aborts(tmp_path):
    """F3: under `all` a member that never answers within the stage window aborts the group."""
    fleet = Fleet(tmp_path, rule="all")
    fleet.put(OLD, 1)
    rollout = fleet.controller.offer("fleet", STREAM, 1)
    fleet.round("p1", "p2")
    fleet.clock.now += 121
    fleet.controller.tick()
    assert rollout.state == "aborted"


def test_case_096_a_commit_window_that_ends_with_one_member_silent_is_partial_until_it_reports(tmp_path):
    """case_096: F3, F4."""
    fleet = Fleet(tmp_path)
    fleet.put(OLD, 1)
    rollout = fleet.controller.offer("fleet", STREAM, 1)
    fleet.round()                                     # all three stage
    fleet.round("p1", "p2")                           # two commit, p3 goes quiet
    assert rollout.state == "committing"
    fleet.clock.now += 121
    fleet.controller.tick()
    assert rollout.state == "partial" and rollout.members[fleet.ids["p3"]] == "committing"
    view = fleet.controller.fleet()
    assert view["rollouts"][0]["state"] == "partial"
    by_id = {entry["labels"]["id"]: entry for entry in view["peps"]}
    assert by_id[fleet.ids["p3"]]["expected"]["seq"] == 1 and by_id[fleet.ids["p3"]]["reported"]["seq"] == 0
    fleet.round("p3")
    assert rollout.state == "committed" and fleet.points["p3"].pep.active.seq == 1


def test_case_086_a_record_signed_by_an_authority_key_or_from_a_pep_not_enrolled_is_state_invalid(tmp_path):
    """case_086: H2, H6, F2."""
    fleet = Fleet(tmp_path, names=("p1",))
    authority = _dist.instance_key("A")
    record = state_record.read(fleet.record("p1"), fleet.points["p1"].key.public_raw)
    forged = state_record.build(replace(record, counter=record.counter + 1), authority)
    assert fleet.controller.receive(forged) == "fleet:state-invalid"
    assert "fleet:state-invalid" in fleet.member("p1").findings and fleet.member("p1").counter == 0
    stranger = state_record.build(replace(record, pep_id=state_record.pep_id(authority.public_raw)), authority)
    assert fleet.controller.receive(stranger) == "fleet:state-invalid"
    assert fleet.controller.unknown[-1]["pep"] == state_record.pep_id(authority.public_raw).hex()
    assert fleet.controller.receive(b"PPSR") == "fleet:state-invalid"
    assert fleet.controller.receive(fleet.record("p1")) is None          # a good record clears it
    assert fleet.member("p1").findings == {}


def test_case_087_the_same_record_sent_twice_is_state_replay(tmp_path):
    """case_087: H3, H6."""
    fleet = Fleet(tmp_path, names=("p1",))
    signed = fleet.record("p1")
    assert fleet.controller.receive(signed) is None
    assert fleet.controller.receive(signed) == "fleet:state-replay"
    assert fleet.controller.receive(fleet.record("p1")) is None and fleet.member("p1").findings == {}


def test_case_092_a_pep_that_sends_nothing_for_three_intervals_is_silent(tmp_path):
    """case_092: H4, H7."""
    fleet = Fleet(tmp_path, names=("p1",))
    assert fleet.controller.receive(fleet.record("p1")) is None
    fleet.clock.now += 89
    fleet.controller.tick()
    assert "fleet:silent" not in fleet.member("p1").findings
    fleet.clock.now += 1
    fleet.controller.tick()
    assert "fleet:silent" in fleet.member("p1").findings
    assert fleet.controller.receive(fleet.record("p1")) is None and fleet.member("p1").findings == {}


def test_case_124_epochs_the_current_and_the_one_before_are_accepted_and_an_older_one_is_replay(tmp_path):
    """case_124: H9, H6. A PEP sent a lower epoch id than it holds keeps the higher."""
    fleet = Fleet(tmp_path, names=("p1",))
    controller, pep = fleet.controller, fleet.points["p1"].pep
    fleet.clock.now += 3 * controller.interval
    controller.tick()
    epoch = controller.epoch_of(STREAM)
    assert epoch == 4
    assert controller.receive(fleet.record("p1", epoch=epoch)) is None
    assert controller.receive(fleet.record("p1", epoch=epoch - 1)) is None
    assert controller.receive(fleet.record("p1", epoch=epoch - 3)) == "fleet:state-replay"
    current = controller.statement(STREAM)
    assert pep.epoch == epoch
    fleet.clock.now -= 2 * controller.interval
    older = Controller(str(tmp_path / "other"), _dist.instance_key("C"), clock=fleet.clock)
    older.add_anchor(fleet.first.anchor(), dict(GEN.QUALIFICATION))
    assert not pep.take_statement(older.statement(STREAM)) and not pep.take_statement(current)
    assert pep.epoch == epoch and state_record.read(pep.record("beat"), fleet.points["p1"].key.public_raw).epoch == epoch


def _uccs(nonce: bytes) -> bytes:
    """An unsigned EAT (RFC 9711, tag 601) holding only `eat_nonce` (claim 10)."""
    return b"\xd9\x02\x59\xa1\x0a\x58\x20" + nonce


def _extension(kind: int, value: bytes) -> bytes:
    return bytes([kind]) + len(value).to_bytes(2, "little") + value


def test_case_125_an_eat_bound_to_the_record_is_read_an_unknown_type_skipped_and_a_changed_one_refused(tmp_path):
    """case_125: H10."""
    fleet = Fleet(tmp_path, names=("p1",))
    point = fleet.points["p1"]
    base = state_record.read(fleet.record("p1"), point.key.public_raw)

    def signed(counter, extensions):
        """The record at `counter` with the extensions `extensions(nonce)` makes from its own nonce."""
        nonce = bytes.fromhex(canon.sha256_hex(replace(base, counter=counter).unsigned_bytes()[:146 + len(base.body)]))
        return state_record.build(replace(base, counter=counter, extensions=extensions(nonce)), point.key), nonce

    good, nonce = signed(base.counter + 1, lambda nonce: _extension(1, _uccs(nonce)))
    assert eat_nonces(_uccs(nonce)) == [nonce]
    assert fleet.controller.receive(good) is None
    unknown, _ = signed(base.counter + 2, lambda nonce: _extension(9, b"anything") + _extension(1, _uccs(nonce)))
    assert fleet.controller.receive(unknown) is None
    changed, _ = signed(base.counter + 3, lambda nonce: _extension(1, _uccs(nonce)))
    changed = bytearray(changed)
    changed[-64 - 1] ^= 1                                 # the token's last byte, after signing
    assert fleet.controller.receive(bytes(changed)) == "fleet:state-invalid"
    elsewhere, _ = signed(base.counter + 4, lambda nonce: _extension(1, _uccs(bytes(32))))
    assert fleet.controller.receive(elsewhere) == "fleet:state-invalid"


def test_case_113_hold_bits_are_filed_held_from_a_kind_with_hold_and_state_invalid_from_host(tmp_path):
    """case_113: H8. Bit 5 from a mesh node, a kind with HOLD, is dist:held while it lasts and is cleared by a
    record without it. Bit 5 from a host PEP is fleet:state-invalid. The cFS half is in integrations/cfs/tests."""
    mesh = Fleet(tmp_path / "mesh", names=("n1",), kind="mesh")
    assert mesh.controller.receive(mesh.record("n1", held=True)) is None
    assert "dist:held" in mesh.member("n1").findings
    assert mesh.controller.receive(mesh.record("n1")) is None and "dist:held" not in mesh.member("n1").findings
    host = Fleet(tmp_path / "host", names=("p1",))
    assert host.controller.receive(host.record("p1", held=True)) == "fleet:state-invalid"


def test_a_pep_on_another_policy_than_expected_is_policy_mismatch(tmp_path):
    """H6 step 3. A PEP that committed out of band reports a release the controller does not expect."""
    fleet = Fleet(tmp_path, names=("p1",))
    fleet.points["p1"].commit(OLD)
    assert fleet.controller.receive(fleet.record("p1")) == "fleet:policy-mismatch"


def test_the_trust_statements_a_pep_lacks_are_offered_first_and_in_order(tmp_path):
    """R1, F6: the controller offers the trust chain from the PEP's trust sequence on, and the release only once
    the PEP holds the whole chain."""
    fleet = Fleet(tmp_path, names=("p1",))
    first = _dist.trust_statement("trust.rotation", _dist.rotation("B"), seq=1, signers=("A", "B"))
    second = _dist.trust_statement("trust.revocation", _dist.revocation(keys=[_dist.key_id("R")]), seq=2)
    fleet.controller.put(first, _dist.rotation("B"))
    with pytest.raises(Refused) as refused:
        fleet.controller.put(first, _dist.rotation("B"))
    assert refused.value.cause == "dist:trust-replay"
    fleet.controller.put(second, _dist.revocation(keys=[_dist.key_id("R")]))
    fleet.put(OLD, 1)
    fleet.controller.offer("fleet", STREAM, 1)
    answer = fleet.controller.answer(fleet.ids["p1"])
    assert [offer["artifact"] for offer in answer["offers"]] == ["trust.rotation", "trust.revocation"]   # F6
    for _ in range(3):
        fleet.round()
    pep = fleet.points["p1"].pep
    assert pep.trust.trust_seq == 2 and pep.active.seq == 1
    assert [offer["artifact"] for offer in fleet.controller.answer(fleet.ids["p1"])["offers"]] == []


def test_case_130_the_controller_refuses_a_list_that_drops_an_entry_no_floor_has_passed(tmp_path):
    """case_130: R6, R8, the controller half. A list that raises a floor past a revoked envelope is stored,
    the next list may drop it, and a list that drops an envelope no floor has passed, or one the controller
    cannot place, or a key, is refused and not stored."""
    fleet = Fleet(tmp_path, names=("p1",))
    controller = fleet.controller
    old = env.read(env.unseal(fleet.put(OLD, 1))[0])
    later = env.read(env.unseal(fleet.put(NEW, 5))[0])

    def store(seq, **lists):
        body = _dist.revocation(**lists)
        controller.put(_dist.trust_statement("trust.revocation", body, seq=seq), body)

    store(1, envelopes=[old.envelope_id, later.envelope_id], keys=[_dist.key_id("R")])
    store(2, envelopes=[old.envelope_id, later.envelope_id], keys=[_dist.key_id("R")], floors={STREAM: 2})
    store(3, envelopes=[later.envelope_id], keys=[_dist.key_id("R")])       # the floor passed seq 1
    for lists in ({"keys": [_dist.key_id("R")]},                            # drops seq 5, no floor passed it
                  {"envelopes": [later.envelope_id]},                        # drops a key
                  ):
        with pytest.raises(Refused) as refused:
            store(4, **lists)
        assert refused.value.cause == "dist:trust-replay"
    assert controller.trust_seq() == 3
    unplaced = _dist.revocation(envelopes=["ab" * 32, later.envelope_id], keys=[_dist.key_id("R")])
    store(4, envelopes=["ab" * 32, later.envelope_id], keys=[_dist.key_id("R")])
    with pytest.raises(Refused):
        check_drops(_dist.revocation(envelopes=[later.envelope_id], keys=[_dist.key_id("R")]),
                    [unplaced], controller.held_envelopes())


def test_the_controller_audit_log_is_signed_by_its_instance_key_and_holds_every_message(tmp_path):
    """F5: offers, acks, commits, findings and trust statements, signed with the controller's instance key."""
    fleet = Fleet(tmp_path, names=("p1",))
    fleet.put(OLD, 1)
    fleet.controller.offer("fleet", STREAM, 1)
    for _ in range(2):
        fleet.round()
    actions = {event["action"] for event in fleet.controller.audit.events}
    assert {"anchor", "enrolled", "stored", "offered", "ack", "commit", "rollout"} <= actions
    assert fleet.controller.audit.verify_log()
    assert fleet.controller.audit.verify_statements([_dist.instance_key("C").public_raw])["status"] == "signed"


def test_a_command_in_another_process_is_seen_by_the_controller_that_serves(tmp_path):
    """The directory is the state: a second `Controller` over it (a command) and the serving one agree."""
    fleet = Fleet(tmp_path, names=("p1",))
    fleet.controller.save()
    command = Controller(str(fleet.dir), _dist.instance_key("C"), clock=fleet.clock)
    with command.locked():
        for sealed, body in _dist.release_with_statement(fleet.first, OLD, 1, widen=True, replaces=""):
            command.put(sealed, body)
        command.offer("fleet", STREAM, 1)
    with fleet.controller.locked() as serving:
        assert [offer["seq"] for offer in serving.answer(fleet.ids["p1"])["offers"]] == [1, 1]


def test_the_frame_driver_carries_a_rollout_to_mesh_nodes_and_their_records_back(tmp_path):
    """Section 8.3 driven by the controller: the epoch, the offer and chunks, then the commit with the delay,
    reassembled on each node and staged by its PEP, and each node's state frame checked by the controller."""
    fleet = Fleet(tmp_path, names=("n1", "n2"), kind="mesh", rule="all")
    body = OLD
    fleet.put(body, 1)
    rollout = fleet.controller.offer("fleet", STREAM, 1, delay_ms=120)
    driver = FrameDriver(fleet.controller, "fleet", limit=frames.ESPNOW_LIMIT)
    monotonic = {"now": 0.0}

    def node_round(name, sent):
        point = fleet.points[name]
        pep = point.pep
        assembler = frames.Assembler(frames.admit_through_v8(
            lambda sealed: verifier.verify_envelope(sealed, trust=pep.trust, pep=pep.view(),
                                                               now=int(pep.clock()))),
            clock=lambda: monotonic["now"], artifact_bound=pep.target.body_bound)
        for data in sent:
            event = assembler.receive(data)
            if isinstance(event, frames.Assembled):
                pep.stage(event.sealed, event.body)
            elif isinstance(event, frames.Epoch):
                pep.take_statement(event.statement)
            elif isinstance(event, frames.Commit) and pep.staged is not None:
                staged = pep.staged
                if event.names(staged.stream, staged.seq, staged.policy_sha256):
                    pep.commit(staged.stream, staged.seq, staged.policy_sha256, delay_ms=event.delay_ms)
        pep.tick()
        return [frames.encode(frames.State(0, record)) for record in pep.drain()]

    for name in fleet.points:
        fleet.points[name].pep.monotonic = lambda: monotonic["now"]
    for _ in range(2):
        sent = driver.send()
        replies = [reply for name in fleet.points for reply in node_round(name, sent)]
        for reply in replies:
            driver.receive(reply)
    assert all(point.pep.due is not None for point in fleet.points.values())
    monotonic["now"] += 0.12
    for name in fleet.points:
        for reply in node_round(name, []):
            driver.receive(reply)
    assert rollout.state == "committed" and all(point.pep.active.seq == 1 for point in fleet.points.values())
    assert all(member.findings == {} for member in fleet.controller.members.values())


def test_case_130_the_sealing_tool_refuses_a_list_that_drops_an_entry_no_floor_has_passed(tmp_path):
    """case_130: R8, the tool half. `prismpath dist revoke --drop` against the controller directory seals a list
    that leaves out an envelope a floor has passed, and refuses one that leaves out an envelope no floor has
    passed, writing nothing. `seal` of a revocation list without the directory is refused."""
    from prismpath.distribution import cli as dist_cli
    from cryptography.hazmat.primitives import serialization as ser
    pem = tmp_path / "A.pem"
    pem.write_bytes(GEN.test_key("A").private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    fleet = Fleet(tmp_path, names=("p1",))
    old = env.read(env.unseal(fleet.put(OLD, 1))[0])
    later = env.read(env.unseal(fleet.put(NEW, 5))[0])
    fleet.controller.save()
    held = str(fleet.dir)

    def revoke(seq, *flags):
        out = tmp_path / f"list{seq}.sealed"
        args = dist_cli_parser().parse_args(["dist", "revoke", "--held", held, "--key", str(pem), "--target", "host",
                                             "--not-before", str(_dist.NOT_BEFORE), "--out", str(out), *flags])
        code = args.func(args)
        if code == 0:
            with fleet.controller.locked() as controller:
                controller.put(out.read_bytes(), (tmp_path / f"list{seq}.body").read_bytes())
        return code, out

    assert revoke(1, "--entry", f"envelope={old.envelope_id}", "--entry", f"envelope={later.envelope_id}")[0] == 0
    assert revoke(2, "--floor", f"{STREAM}=2")[0] == 0
    code, out = revoke(3, "--drop", f"envelope={later.envelope_id}")
    assert code == 1 and not out.exists()
    assert revoke(3, "--drop", f"envelope={old.envelope_id}")[0] == 0
    assert fleet.controller.trust_seq() == 3
    listed = kinds_read(fleet.controller)
    assert listed["envelopes"] == [later.envelope_id] and listed["floors"] == {STREAM: 2}
    with pytest.raises(Refused) as refused:
        dist_cli.build_sealed("trust.revocation", _dist.revocation(), stream=env.TRUST_STREAM, seq=4, targets=["host"],
                              signers=[GEN.test_key("A")], not_before=_dist.NOT_BEFORE, expires=0)
    assert refused.value.cause == "dist:trust-replay"


def dist_cli_parser():
    from prismpath import cli
    return cli.build_parser()


def kinds_read(controller):
    from prismpath.distribution import kinds
    latest = controller.chain[-1]
    return kinds.read_revocation(controller.blob(controller.stored[latest]["body_sha256"]))


def test_case_133_a_pep_behind_on_the_trust_chain_is_offered_only_the_statement_it_lacks(tmp_path):
    """case_133: F6. The release is not offered until the PEP reports the chain's trust sequence, a refusal while
    it is behind is filed against the statement and leaves the rollout where it was, and once the PEP takes the
    statement the release is offered and commits."""
    fleet = Fleet(tmp_path, names=("p1",))
    controller = fleet.controller
    body = _dist.rotation("B")
    later = _dist.NOT_BEFORE + 4000
    statement = env.seal(env.build("trust.rotation", body, stream=env.TRUST_STREAM, seq=1, targets=["host"],
                                   not_before=later, expires=0, policy_sha256=env.ZERO_HASH, release=env.ZERO_HASH),
                         [GEN.test_key("A"), GEN.test_key("B")])
    fleet.clock.now = later
    controller.put(statement, body)
    statement_id = env.envelope_id(env.unseal(statement)[0])
    fleet.put(OLD, 1)
    rollout = controller.offer("fleet", STREAM, 1)
    answer = controller.answer(fleet.ids["p1"])
    assert [offer["envelope_id"] for offer in answer["offers"]] == [statement_id] and answer["commit"] == []
    fleet.clock.now = _dist.NOW                       # the PEP's clock is behind the statement's not_before
    controller.epoch_at = fleet.clock.now
    fleet.round()
    member = fleet.member("p1")
    assert member.findings == {"dist:not-yet-valid": f"refused the trust statement {statement_id} at trust seq 1"}
    assert rollout.state == "offered" and rollout.members[fleet.ids["p1"]] == "offered"
    fleet.clock.now = later                           # PullClient tries it again once its clock has caught up
    for _ in range(3):
        fleet.round()
    assert fleet.points["p1"].pep.trust.trust_seq == 1 and fleet.points["p1"].pep.active.seq == 1
    assert rollout.state == "committed" and fleet.member("p1").findings == {}


def test_case_134_the_controller_keeps_one_trust_chain_whatever_a_statement_targets(tmp_path):
    """case_134: V5, R1, the controller half. A revocation naming only mesh is stored under a host anchor and
    offered to a host PEP, which applies it, and the rotation after it follows at the next trust sequence."""
    fleet = Fleet(tmp_path, names=("p1",))
    controller = fleet.controller
    body = _dist.revocation(keys=[_dist.key_id("R")])
    controller.put(_dist.trust_statement("trust.revocation", body, seq=1, targets=("mesh",)), body)
    rotation = _dist.rotation("B")
    controller.put(_dist.trust_statement("trust.rotation", rotation, seq=2, signers=("A", "B")), rotation)
    assert [offer["artifact"] for offer in controller.answer(fleet.ids["p1"])["offers"]] == [
        "trust.revocation", "trust.rotation"]
    for _ in range(3):
        fleet.round()
    assert fleet.points["p1"].pep.trust.trust_seq == 2 and controller.members[fleet.ids["p1"]].findings == {}


def test_records_from_unknown_or_unreadable_senders_are_bounded_and_logged_once_an_interval(tmp_path):
    """A flood of records that name no enrolled PEP, or that do not read, keeps at most 64 senders in the view
    and the state, and writes each sender's finding to the audit log at most once an interval."""
    fleet = Fleet(tmp_path, names=("p1",))
    controller = fleet.controller
    stranger = _dist.instance_key("S")
    record = state_record.read(fleet.record("p1"), fleet.points["p1"].key.public_raw)
    before = len(controller.audit.events)
    for counter in range(300):
        forged = replace(record, pep_id=state_record.pep_id(stranger.public_raw), counter=counter + 1)
        assert controller.receive(state_record.build(forged, stranger)) == "fleet:state-invalid"
        assert controller.receive(b"PPSR" + bytes(counter % 7)) == "fleet:state-invalid"
    senders = {one["pep"]: one for one in controller.unknown}
    assert senders[state_record.pep_id(stranger.public_raw).hex()]["count"] == 300 and senders[""]["count"] == 300
    for name in range(100):
        other = _dist.instance_key(f"S{name}")
        controller.receive(state_record.build(replace(record, pep_id=state_record.pep_id(other.public_raw)), other))
    assert len(controller.unknown) == 64
    logged = [event for event in controller.audit.events[before:] if event["action"] == "finding"]
    assert len(logged) == 102
    fleet.clock.now += controller.interval
    controller.receive(b"PPSR")
    assert [event for event in controller.audit.events if event["action"] == "finding"][-1]["data"]["pep"] == ""
    controller.save()
    assert len(json.loads((fleet.dir / "controller.json").read_text())["unknown"]) <= 64


def test_the_commit_window_on_the_mesh_is_the_delay_plus_2_seconds(tmp_path):
    """F3: a mesh rollout committing with a 120 millisecond delay is partial 2.12 seconds after it began to
    commit, and the member still out keeps being sent commit until it reports, so a node that restarted and
    lost the delayed commit it held in memory commits on the next send."""
    fleet = Fleet(tmp_path, names=("n1", "n2"), kind="mesh", rule="each")
    fleet.put(OLD, 1)
    rollout = fleet.controller.offer("fleet", STREAM, 1, delay_ms=120)
    for name in ("n1", "n2"):
        fleet.points[name].pep.monotonic = lambda: 0.0          # the delay never falls due before the window ends
    fleet.round()
    fleet.round()
    assert rollout.state == "committing"
    fleet.clock.now += 2
    fleet.controller.tick()
    assert rollout.state == "committing"
    fleet.clock.now += 1
    fleet.controller.tick()
    assert rollout.state == "partial"
    restarted = fleet.points["n1"].open()                        # B8: the delayed commit is lost on restart
    assert restarted.due is None
    fleet.clients["n1"] = PullClient(restarted, LocalTransport(fleet.controller))
    for name in ("n1", "n2"):
        fleet.points[name].pep = restarted if name == "n1" else fleet.points[name].pep
    restarted.monotonic = lambda: 0.0
    fleet.round()                                                  # n1 is sent commit again and holds it
    assert restarted.due is not None
    restarted.monotonic = fleet.points["n2"].pep.monotonic = lambda: 1.0
    fleet.round()
    assert rollout.state == "committed" and restarted.active.seq == 1


def test_a_member_is_staged_only_once_every_envelope_of_the_release_is(tmp_path):
    """F3: a release of three envelopes, the widening statement of a first install, an image and its spiral
    sidecar, is staged on a member only when every ack came, so the commit is not sent early and the release
    commits whole."""
    fleet = Fleet(tmp_path, names=("p1",))
    sidecar = b"spiral sidecar bytes"
    meta = {**GEN.image_meta(OLD), "packing": {"profile": "spiral", "sidecar_sha256": H(sidecar)}}
    release = env.release_id([("policy.ppt", H(OLD)), ("policy.spiral", H(sidecar))])
    statement = _dist.widening()
    fleet.controller.put(_dist.seal("trust.widening", statement, release=release, policy_sha256=H(OLD),
                                    widens=True), statement)
    fleet.controller.put(_dist.seal("policy.ppt", OLD, meta=meta, release=release, widens=True), OLD)
    fleet.controller.put(_dist.seal("policy.spiral", sidecar, release=release, policy_sha256=H(OLD), widens=True),
                         sidecar)
    rollout = fleet.controller.offer("fleet", STREAM, 1)
    pep = fleet.points["p1"].pep
    pep.take_statement(fleet.controller.statement(STREAM))
    first = rollout.envelopes[0]
    info = fleet.controller.stored[first]
    pep.stage(fleet.controller.sealed(first), fleet.controller.blob(info["body_sha256"]))
    for record in pep.drain():
        fleet.controller.receive(record)
    assert rollout.members[fleet.ids["p1"]] == "offered" and fleet.controller.answer(fleet.ids["p1"])["commit"] == []
    for _ in range(3):
        fleet.round()
    assert rollout.state == "committed" and pep.active.bodies["policy.spiral"] == sidecar


def test_case_065_a_controller_refuses_to_offer_a_larger_release_that_says_it_does_not_widen(tmp_path):
    """case_065: W7. A mesh node cannot decide, so the controller compares the release with the one it holds for
    its `replaces`. A table that is not that one, with `widens` false, is not offered."""
    fleet = Fleet(tmp_path, names=("n1",), kind="mesh")
    fleet.put(OLD, 1)
    fleet.controller.offer("fleet", STREAM, 1)
    fleet.put(NEW, 2, widen=False)                                    # replaces OLD, says it does not widen
    with pytest.raises(Refused) as refused:
        fleet.controller.offer("fleet", STREAM, 2)
    assert refused.value.cause == "dist:widening-unsigned"
    assert [rollout.seq for rollout in fleet.controller.rollouts] == [1]
    assert fleet.controller.audit.events[-1]["data"]["cause"] == "dist:widening-unsigned"
    fleet.put(OLD, 3, widen=False, expires=_dist.EXPIRES + 10)       # a renewal of OLD is not larger
    with pytest.raises(Refused):
        fleet.controller.offer("fleet", STREAM, 3)                     # it replaces NEW, which it is not
    fleet.put(NEW, 4, widen=False, replaces=H(NEW))
    assert fleet.controller.offer("fleet", STREAM, 4).seq == 4


def test_case_136_the_sealing_tool_and_the_controller_hold_widens_to_what_they_hold(tmp_path):
    """case_136: W7, W1, the mesh part. A table that differs from the one it replaces by one constant and allows
    more is written
    with `widens` true by the tool and refused by the controller when it says false, and the same table again
    with a later `expires` is written with `widens` false and offered. The cFS part, a narrower core image and one
    whose rules alone differ, is in integrations/cfs/tests/test_cfs_dist.py."""
    import json
    from prismpath import cli
    from cryptography.hazmat.primitives import serialization as ser
    pem = tmp_path / "A.pem"
    pem.write_bytes(GEN.test_key("A").private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    fleet = Fleet(tmp_path, names=("n1",), kind="mesh")
    fleet.put(OLD, 1)
    fleet.controller.save()
    one_constant = _dist.image(4)                                     # allows x = 4, which the held table refuses

    def seal_with_tool(body, seq, expires):
        (tmp_path / "body").write_bytes(body)
        (tmp_path / "meta.json").write_text(json.dumps(GEN.image_meta(body)))
        args = cli.build_parser().parse_args([
            "dist", "seal", "--artifact", "policy.ppt", "--body", str(tmp_path / "body"), "--stream", STREAM,
            "--seq", str(seq), "--target", "mesh", "--key", str(pem), "--held", str(fleet.dir),
            "--not-before", str(_dist.NOT_BEFORE), "--expires", str(expires), "--meta", str(tmp_path / "meta.json"),
            "--out", str(tmp_path / f"r{seq}.sealed")])
        assert args.func(args) == 0
        return env.read(env.unseal((tmp_path / f"r{seq}.sealed").read_bytes())[0])

    changed = seal_with_tool(one_constant, 2, _dist.EXPIRES)
    assert changed.widens and changed.replaces == H(OLD)
    fleet.put(one_constant, 2, widen=False)
    with pytest.raises(Refused):
        fleet.controller.offer("fleet", STREAM, 2)
    renewal = seal_with_tool(OLD, 3, _dist.EXPIRES + 10)
    assert not renewal.widens and renewal.replaces == H(OLD)
    fleet.controller.put((tmp_path / "r3.sealed").read_bytes(), OLD)
    assert fleet.controller.offer("fleet", STREAM, 3).seq == 3


def _pem_of(tmp_path, name):
    from cryptography.hazmat.primitives import serialization as ser
    pem = tmp_path / f"{name}.pem"
    pem.write_bytes(GEN.test_key(name).private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    return pem


def _seal_with_tool(tmp_path, capsys, pem, held, body, seq, *extra, code=0):
    from prismpath import cli
    (tmp_path / "body").write_bytes(body)
    (tmp_path / "meta.json").write_text(json.dumps(GEN.image_meta(body)))
    args = cli.build_parser().parse_args([
        "dist", "seal", "--artifact", "policy.ppt", "--body", str(tmp_path / "body"), "--stream", STREAM,
        "--seq", str(seq), "--target", "mesh", "--key", str(pem), "--held", str(held),
        "--not-before", str(_dist.NOT_BEFORE), "--expires", str(_dist.EXPIRES), "--meta", str(tmp_path / "meta.json"),
        "--out", str(tmp_path / f"r{seq}.sealed"), *extra])
    assert args.func(args) == code
    captured = capsys.readouterr()
    return (json.loads(captured.out) if code == 0 else None), captured.err


def test_case_290_the_sealing_tool_signs_a_change_statement_only_for_a_table_that_allows_nothing_more(
        tmp_path, capsys):
    """case_290: W8, W9, W10, W11, W2. Against a held mesh table, the tool shows the owner what the comparator found
    for a narrower table and signs nothing without a yes. With `--yes` it seals the table with `widens` false and
    writes a change statement from the held table's hash beside it, and no widening statement. A mesh node refuses
    the table alone, and stages and commits the pair. A wider table is a widening with a witness reading and no
    statement, and a node refuses it without the owner's widening statement."""
    pem = _pem_of(tmp_path, "A")
    fleet = Fleet(tmp_path, names=("n1",), kind="mesh")
    fleet.put(OLD, 1)
    fleet.controller.save()

    _printed, shown = _seal_with_tool(tmp_path, capsys, pem, fleet.dir, NEW, 2, code=1)
    assert '"answer": "not-larger"' in shown and "refused: dist:widening-unsigned" in shown
    assert not (tmp_path / "r2.sealed").exists() and not (tmp_path / "r2.change.sealed").exists()
    printed, _shown = _seal_with_tool(tmp_path, capsys, pem, fleet.dir, NEW, 2, "--yes")
    assert not printed["widens"] and printed["scope"] == "change, not larger" and printed["replaces"] == H(OLD)
    assert printed["comparison"] == {"answer": "not-larger", "reason": "narrower", "witness": None}
    assert printed["change"]["from"] == H(OLD) and printed["change"]["basis"] == "prismpath.table-compare/1"
    assert "next" not in printed and not list(tmp_path.glob("*.widening.*"))
    change = (tmp_path / "r2.change.sealed").read_bytes()
    assert env.read(env.unseal(change)[0]).artifact == "trust.change"

    node = _dist.MeshPep(tmp_path / "node")
    node.commit(OLD)

    def read(signed):
        return state_record.read(signed, node.key.public_raw)
    assert read(node.pep.stage((tmp_path / "r2.sealed").read_bytes(), NEW)).cause == "dist:widening-unsigned"
    assert read(node.pep.stage(change, (tmp_path / "r2.change.body").read_bytes())).event == "staged"
    assert read(node.pep.stage((tmp_path / "r2.sealed").read_bytes(), NEW)).event == "staged"
    assert read(node.pep.commit(STREAM, 2, H(NEW))).event == "committed"

    wider = _dist.image(3)
    printed, _shown = _seal_with_tool(tmp_path, capsys, pem, fleet.dir, wider, 3)
    assert printed["widens"] and printed["scope"] == "widening" and "change" not in printed
    assert printed["comparison"]["answer"] == "larger" and printed["comparison"]["reason"] == "step"
    assert printed["comparison"]["witness"]["active"] is None and printed["next"]
    assert not (tmp_path / "r3.change.sealed").exists()
    assert read(node.pep.stage((tmp_path / "r3.sealed").read_bytes(), wider)).cause == "dist:widening-unsigned"


def test_case_291_the_controller_shows_a_change_apart_from_a_widening_and_keeps_the_witness(tmp_path):
    """case_291: W8, W11, F4, W7. On a host fleet a table that allows less, carried by a change statement with
    `widens` false, is offered and shown as a change, not larger. One that allows more with a widening statement is
    a widening with the comparator's witness, as is one whose signed field dictionary differs, with the frame as
    the witness. The marks and the answers are in the state the controller keeps. A table carried by a change
    statement that the comparator does not bear out, and a table with neither statement, are not offered."""
    from prismpath.distribution.controller import CHANGE_NOT_LARGER, WIDENING
    fleet = Fleet(tmp_path, names=("p1",))
    fleet.put(OLD, 1)
    fleet.controller.offer("fleet", STREAM, 1)
    fleet.put(NEW, 2, change=True)
    rollout = fleet.controller.offer("fleet", STREAM, 2)
    assert rollout.scope == CHANGE_NOT_LARGER and rollout.comparison["answer"] == "not-larger"
    wider = _dist.image(3)
    fleet.put(wider, 3, widen=True)
    rollout = fleet.controller.offer("fleet", STREAM, 3)
    assert rollout.scope == WIDENING
    assert rollout.comparison["reason"] == "step" and rollout.comparison["witness"]["staged"] == {"edge": 0, "target": 1}
    fleet.put(OLD, 4, widen=True, meta=dict(GEN.image_meta(OLD), fields={}))
    rollout = fleet.controller.offer("fleet", STREAM, 4)
    assert rollout.scope == WIDENING and rollout.comparison["witness"]["member"] == "meta.fields"
    fleet.controller.save()
    kept = Controller(str(fleet.dir), _dist.instance_key("C"), clock=fleet.clock)
    rollouts = kept.fleet()["rollouts"]
    assert [one["scope"] for one in rollouts] == [WIDENING, CHANGE_NOT_LARGER, WIDENING, WIDENING]
    assert [one["comparison"] and one["comparison"]["answer"] for one in rollouts] == [None, "not-larger", "larger",
                                                                                        "larger"]
    lower = _dist.image(2)
    fleet.put(lower, 5, change=True, meta=dict(GEN.image_meta(lower), fields={}))
    with pytest.raises(Refused) as refused:
        fleet.controller.offer("fleet", STREAM, 5)                    # a change statement W8 does not bear out
    assert refused.value.cause == "dist:widening-unsigned"
    fleet.put(NEWER, 6, widen=False, replaces=H(OLD))
    with pytest.raises(Refused):
        fleet.controller.offer("fleet", STREAM, 6)


def test_a_rollout_is_shown_as_a_widening_or_a_change_in_the_fleet_view(tmp_path):
    """F4: a widening the owner pushed stands out, and a change that allows nothing more is shown apart from it. A
    first install and a policy.core a comparator finds larger are widenings, a mesh table W8 finds narrower is a
    change, not larger, and a renewal is neither. The mark is in the state the controller keeps, and a state kept
    with the older marks reads as the new ones."""
    from prismpath.agent.policy import starter_path
    from prismpath.distribution.controller import CHANGE_NOT_LARGER, WIDENING, Rollout
    fleet = Fleet(tmp_path / "mesh", names=("n1",), kind="mesh")
    fleet.put(OLD, 1)
    assert fleet.controller.offer("fleet", STREAM, 1).scope == WIDENING
    fleet.put(NEW, 2, change=True)
    assert fleet.controller.offer("fleet", STREAM, 2).scope == CHANGE_NOT_LARGER
    fleet.put(NEW, 3, widen=False, replaces=H(NEW), expires=_dist.EXPIRES + 10)
    assert fleet.controller.offer("fleet", STREAM, 3).scope == ""
    fleet.controller.save()
    kept = Controller(str(fleet.dir), _dist.instance_key("C"), clock=fleet.clock)
    documents = kept.fleet()["rollouts"]
    assert [one["scope"] for one in documents] == [WIDENING, CHANGE_NOT_LARGER, ""]
    older = {key: value for key, value in documents[1].items() if key != "scope"}
    assert Rollout.from_document(dict(older, widening="larger by rule")).scope == CHANGE_NOT_LARGER

    strict, default = (starter_path(name).read_bytes().rstrip(b"\n") for name in ("strict", "default"))
    point = _dist.AgentPep(tmp_path / "agent")
    controller = Controller(str(tmp_path / "agents"), _dist.instance_key("C"), clock=_dist.Clock())
    controller.add_anchor(point.anchor())
    controller.enroll(point.key.public_raw, "agent", STREAM)
    for seq, image, replaces in ((1, strict, ""), (2, default, H(strict))):
        statement = _dist.widening()
        release = point.release_of(image)
        controller.put(_dist.seal("trust.widening", statement, seq=seq, release=release, policy_sha256=H(image),
                                  targets=("agent",), widens=True, replaces=replaces), statement)
        controller.put(point.seal(image, seq, widens=True, replaces=replaces), image)
        controller.put(point.seal_hosts(image, seq, widens=True, replaces=replaces), point.hosts)
        assert controller.offer("default", STREAM, seq).scope == WIDENING
