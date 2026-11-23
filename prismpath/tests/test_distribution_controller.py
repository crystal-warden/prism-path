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

    def __init__(self, tmp_path, names=("p1", "p2", "p3"), rule="each", group="fleet", kind="host"):
        self.clock = _dist.Clock()
        self.dir = tmp_path / "controller"
        self.controller = Controller(str(self.dir), _dist.instance_key("C"), clock=self.clock)
        maker = _dist.MeshPep if kind == "mesh" else _dist.HostPep
        self.points = {name: maker(tmp_path / name, clock=self.clock, key=_dist.instance_key(name)) for name in names}
        first = next(iter(self.points.values()))
        self.controller.add_anchor(first.anchor(), dict(GEN.QUALIFICATION) if kind == "host" else None)
        self.ids = {name: self.controller.enroll(point.key.public_raw, kind, STREAM, group, rule)
                    for name, point in self.points.items()}
        self.clients = {name: PullClient(point.pep, LocalTransport(self.controller))
                        for name, point in self.points.items()}
        self.first = first

    def put(self, body, seq, **args):
        sealed = self.first.seal(body, seq=seq, **args)
        self.controller.put(sealed, body)
        return sealed

    def round(self, *names):
        for name in names or self.clients:
            self.clients[name].poll()

    def member(self, name):
        return self.controller.members[self.ids[name]]

    def record(self, name, event="beat", **changes):
        """A record made and signed by the PEP `name` now, with `changes` to its fields, re-signed."""
        point = self.points[name]
        point.pep.see_epoch(self.controller.epoch)
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
    loose = next(case for case in GEN.build()["cases"] if case["name"].startswith("128_counts_an_integer_where_meta_is_skipped"))
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
    fleet.put(NEW, 2)
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
    assert causes == {"p1": [], "p2": ["dist:seq-replay"], "p3": ["sig:invalid"]}
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
    epoch = controller.epoch
    assert epoch == 4
    assert controller.receive(fleet.record("p1", epoch=epoch)) is None
    assert controller.receive(fleet.record("p1", epoch=epoch - 1)) is None
    assert controller.receive(fleet.record("p1", epoch=epoch - 3)) == "fleet:state-replay"
    pep.see_epoch(epoch)
    pep.see_epoch(epoch - 2)
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
    """R1: the controller offers the trust chain from the PEP's trust sequence on, before any release."""
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
    assert [offer["artifact"] for offer in answer["offers"]] == ["trust.rotation", "trust.revocation", "policy.ppt"]
    for _ in range(2):
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
        command.put(fleet.first.seal(OLD), OLD)
        command.offer("fleet", STREAM, 1)
    with fleet.controller.locked() as serving:
        assert [offer["seq"] for offer in serving.answer(fleet.ids["p1"])["offers"]] == [1]


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
                pep.see_epoch(event.epoch)
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
    from prismpath.hotswap import policy_pack
    _priv, _pub, ser, _invalid = policy_pack._ed25519()
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
