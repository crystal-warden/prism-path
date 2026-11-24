# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The controller's side of section 21 of spec-policy-distribution.md: it stores and offers install statements
(IS8), expects an install id of each PEP and files what its records say (H11, H12), and holds a widening until an
acknowledger acknowledges it (H13). PEPs of the `agent` and `mesh` models pull through `LocalTransport`. Each test
names the conformance case of section 20 it covers."""
from dataclasses import replace

import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.distribution import install, kinds, state_record  # noqa: E402
from prismpath.distribution.controller import Controller  # noqa: E402
from prismpath.distribution.controller_install import install_id_of  # noqa: E402
from prismpath.distribution.http import LocalTransport, PullClient  # noqa: E402
from prismpath.distribution.kinds import Refused  # noqa: E402
from prismpath.kernel.policy_source import compile_source  # noqa: E402
from prismpath.tests import _dist  # noqa: E402
from prismpath.tests._dist import GEN, NOT_BEFORE, STREAM  # noqa: E402
from prismpath.tests.test_distribution_floor import (  # noqa: E402
    LAYOUT, OTHER_LAYOUT, MeshFloor, _table_floor, _table_point, regs, table)

H = canon.sha256_hex
KEYS = ["N1", "N2", "N3"]
FLOOR, FALLBACK, CEILING, TRUST = install.FLOOR, install.FALLBACK, install.CEILING, install.TRUST
HOSTS = canon.canon2_bytes(["api.example.com"])
FIELDS = ("tool", "path_scope", "command_class", "path_control", "zone_reach", "zone_name")


def core(*rules) -> bytes:
    head = "".join(f"field.{name}: {'bool' if name == 'path_control' else 'category'}\n" for name in FIELDS)
    return compile_source("---\nname: floor\nstart: core_decision\n" + head + "---\n## core_decision\n"
                          + "".join(rule + "\n" for rule in rules))


LIST = '-> allow: when tool == "list_dir" and path_scope == "workspace"'
READ = '-> allow: when tool == "read_file" and path_scope == "workspace"'
NARROW, WIDER = core(LIST), core(LIST, READ)
RELEASE = core('-> refuse agent:unclassifiable: when tool == "unknown"', READ)
ASK = {"reading": {"tool": "list_dir", "path_scope": "workspace", "command_class": "none", "path_control": False,
                   "zone_reach": "none", "zone_name": ""}}


def _agent(tmp_path, name, **settings):
    settings.setdefault("install_keys", KEYS)
    settings.setdefault("install_threshold", 2)
    return _dist.AgentPep(tmp_path / name, **settings)


def _mesh(tmp_path, name, **settings):
    settings.setdefault("install_keys", KEYS)
    settings.setdefault("install_threshold", 2)
    return _dist.MeshPep(tmp_path / name, **settings)


def _set(point, kind, policy, seq=1, hosts=HOSTS, **args):
    args.setdefault("widens", kind != CEILING)
    return point.install_set(kind, {"policy.core": policy, "egress.hosts": hosts}, seq, **args)


class Fleet:
    """A controller serving one stream and PEPs on it under one clock, each pulling through `LocalTransport`."""

    def __init__(self, tmp_path, names=("p1",), make=_agent, group="fleet", enroll=True, **settings):
        self.clock = _dist.Clock()
        self.controller = Controller(str(tmp_path / "controller"), _dist.instance_key("C"), clock=self.clock)
        self.points = {name: make(tmp_path, name, clock=self.clock, key=_dist.instance_key(name), **settings)
                       for name in names}
        self.first = next(iter(self.points.values()))
        self.kind = self.first.kind
        self.controller.add_anchor(self.first.anchor())
        self.group = group
        self.ids = {}
        if enroll:
            for name in names:
                self.enroll(name)
        self.clients = {name: PullClient(point.pep, LocalTransport(self.controller))
                        for name, point in self.points.items()}

    def enroll(self, name, install_envelopes=None):
        self.ids[name] = self.controller.enroll(self.points[name].key.public_raw, self.kind, STREAM, self.group,
                                                install_envelopes=install_envelopes)
        return self.ids[name]

    def put(self, pairs):
        return [self.controller.put(sealed, body) for sealed, body in pairs]

    def round(self, *names):
        for name in names or self.clients:
            point = self.points[name]
            self.clients[name].pep = point.pep
            self.clients[name].poll()

    def member(self, name):
        return self.controller.members[self.ids[name]]

    def findings(self, name):
        return dict(self.member(name).findings)

    def held(self, name, kind):
        return self.points[name].pep.installed.held(kind)


def _release(point, policy, seq, *, widen=True, replaces=""):
    """The pairs of an `agent` release of `policy` and HOSTS, with its widening statement when it widens."""
    release = point.release_of(policy)
    return (_dist.release_with_statement(point, policy, seq, widen=widen, replaces=replaces, release=release)
            + [(point.seal_hosts(policy, seq, widens=widen, replaces=replaces), HOSTS)])


def _ids(pairs):
    return [env.envelope_id(env.unseal(sealed)[0]) for sealed, _body in pairs]


def _audit(controller):
    return [(event["action"], event.get("data", {})) for event in controller.audit.events]


def _floor_in_place(fleet, policy=NARROW, seq=1):
    """A first floor the controller stores, held for its acknowledgement, acknowledged, and taken by every PEP."""
    pairs = _set(fleet.first, FLOOR, policy, seq)
    fleet.put(pairs)
    fleet.controller.acknowledge(_ids(pairs), by="engineer")
    for _ in range(2):
        fleet.round()
    return pairs


# ------------------------------------------------------------------ IS8, H12: store, offer, attribute

def test_case_181_the_controller_verifies_offers_trust_first_and_attributes_by_subject(tmp_path):
    """case_181: IS8, H12. A controller handed an install statement with a bad signature refuses it and stores and
    offers the good one. A PEP two install trust statements behind is offered both, in order, before any install set,
    and a `refused` record with subject 1 while a release is on offer is filed against the floor and not the
    release."""
    fleet = Fleet(tmp_path, install_keys=["N1", "N2", "N3", "N4"])
    controller, point = fleet.controller, fleet.first
    good = _set(point, FLOOR, NARROW)
    bad = bytearray(good[0][0])
    bad[6 + 32] ^= 1
    with pytest.raises(Refused) as refused:
        controller.put(bytes(bad), good[0][1])
    assert refused.value.cause == "sig:invalid" and controller.stored == {}
    fleet.put(good)
    controller.acknowledge(_ids(good), by="engineer")         # a first floor widens (IS12, H13)
    first = install.trust_body([_dist.public(name) for name in KEYS], threshold=2)       # drops N4
    second = install.trust_body([_dist.public(name) for name in ("N1", "N2")], threshold=2)   # then N3
    record = point.pep.installed.record
    one = install.seal_trust(record, first, stream=STREAM, seq=1, targets=["agent"],
                             signers=[GEN.test_key("N1"), GEN.test_key("N2")], not_before=NOT_BEFORE)
    two = install.seal_trust(record.apply_trust(env.read(env.unseal(one)[0]), first), second, stream=STREAM, seq=2,
                             targets=["agent"], signers=[GEN.test_key("N1"), GEN.test_key("N3")], not_before=NOT_BEFORE)
    controller.put(one, first)
    controller.put(two, second)
    offers = [offer["artifact"] for offer in controller.answer(fleet.ids["p1"])["offers"]]
    assert offers == [TRUST, TRUST, FLOOR, FLOOR]
    fleet.round()
    assert point.pep.installed.record.trust_seq == 2 and fleet.held("p1", FLOOR) is not None
    assert install_id_of(fleet.member("p1").install) == point.pep.installed.record.install_id()
    # a release on offer, and a refused record with subject 1
    fleet.put(_release(point, RELEASE, 1))
    rollout = controller.offer("fleet", STREAM, 1)
    refusal = point.pep._refuse("dist:floor-broad", subject=FLOOR)
    point.pep.drain()
    controller.receive(refusal)
    assert rollout.members[fleet.ids["p1"]] == "offered"
    assert fleet.findings("p1")["dist:floor-broad"] == f"refused {FLOOR}"


# ------------------------------------------------------------------ H13: a widening waits for its acknowledgement

def _record(fleet, name, event="beat"):
    point = fleet.points[name]
    point.pep.take_statement(fleet.controller.statement(STREAM))
    signed = point.pep.record(event)
    point.pep.drain()
    return signed


def test_case_185_a_widening_is_held_until_it_is_acknowledged_by_its_envelope_ids(tmp_path):
    """case_185: H13, IS12, AF4, the `agent` and `mesh` part. A narrowing floor and a narrowing fallback policy are
    offered at once. A widening floor, an `install.trust` that adds a key and the empty ceiling are held with
    `dist:install-widened` open, and a `mesh` floor table that differs by one byte with `widens` false is refused as
    larger. An acknowledgement by the release id or by 64 zeros is refused, and by the envelope ids lets the floor be
    offered and its install id expected. A PEP that reports `install-widened` for a set the controller never held is
    filed until the set is handed over and acknowledged. The `cfs` floor is in integrations/cfs/tests."""
    fleet = Fleet(tmp_path)
    controller, point = fleet.controller, fleet.first
    _floor_in_place(fleet, WIDER)
    fallback = _set(point, FALLBACK, WIDER)
    fleet.put(fallback)
    controller.acknowledge(_ids(fallback), by="engineer")
    fleet.round()
    narrow = _set(point, FLOOR, NARROW, 2, widens=False, replaces=H(WIDER))
    fleet.put(narrow)
    narrow_fallback = _set(point, FALLBACK, NARROW, 2, widens=False, replaces=H(WIDER))
    fleet.put(narrow_fallback)
    assert [one["state"] for one in controller.install_view()[STREAM]["sets"] if one["seq"] == 2] == ["offered"] * 2
    offered = {offer["envelope_id"] for offer in controller.answer(fleet.ids["p1"])["offers"]}
    assert set(_ids(narrow)) | set(_ids(narrow_fallback)) <= offered
    fleet.round()
    assert fleet.held("p1", FLOOR).seq == 2 and fleet.held("p1", FALLBACK).seq == 2
    widening = _set(point, FLOOR, WIDER, 3)
    fleet.put(widening)
    added = point.install_trust(1, KEYS + ["N4"], threshold=2)
    controller.put(*added)
    empty = point.install_set(CEILING, {kinds.NONE: b""}, 1, widens=True)
    fleet.put(empty)
    held = controller.install_findings
    assert len(held) == 3 and all("widens" in detail or "ceiling" in detail or "trust" in detail
                                  for detail in held.values())
    assert not set(_ids(widening)) & {offer["envelope_id"] for offer in controller.answer(fleet.ids["p1"])["offers"]}
    expected = install_id_of(fleet.member("p1").install)
    assert expected == point.pep.installed.record.install_id()   # the held floor's id is expected of nobody
    release_id = env.read(env.unseal(widening[0][0])[0]).release
    for wrong in ([release_id], ["0" * 64], _ids(widening)[:1]):
        with pytest.raises(ValueError):
            controller.acknowledge(wrong, by="engineer")
    assert [one for one in _audit(controller) if one[0] == "refused"][-3:]
    controller.acknowledge(_ids(widening), by="engineer")
    assert set(_ids(widening)) <= {offer["envelope_id"] for offer in controller.answer(fleet.ids["p1"])["offers"]}
    assert fleet.member("p1").install["sets"][FLOOR][1] == 3
    fleet.round()
    assert fleet.held("p1", FLOOR).seq == 3 and install.WIDENED not in fleet.findings("p1")
    assert ("acknowledged", {"item": next(key for key in controller.install_sets if "/install.floor/3/" in key),
                             "envelopes": sorted(_ids(widening)), "by": "engineer", "result": "acknowledged"}) in \
        _audit(controller)
    # a set the controller never held, reported by the PEP
    elsewhere = _set(point, FLOOR, NARROW, 5)
    point.send(elsewhere)
    for signed in point.pep.drain():
        controller.receive(signed)
    assert install.WIDENED in fleet.findings("p1")
    fleet.round()
    assert install.WIDENED in fleet.findings("p1")
    fleet.put(elsewhere)
    controller.acknowledge(_ids(elsewhere), by="engineer")
    assert install.WIDENED not in fleet.findings("p1")
    controller.receive(_record(fleet, "p1"))
    assert "fleet:policy-mismatch" not in fleet.findings("p1")


def _mesh_floor(point, body, seq, **args):
    return _table_floor(point, body, seq, **args)


def test_case_185_a_mesh_floor_table_that_differs_by_one_byte_is_refused_as_larger(tmp_path):
    """case_185: H13, IS12, the `mesh` table. On `mesh` a table that is not byte for byte the one before is larger,
    so the controller refuses it with `widens` false, and offers a renewal of the same table at once."""
    point = _table_point(MeshFloor, tmp_path, "m1", key=_dist.instance_key("m1"))
    controller = Controller(str(tmp_path / "controller"), _dist.instance_key("C"), clock=point.clock)
    controller.add_anchor(point.anchor(), layout=LAYOUT)
    first = _mesh_floor(point, table("cmd == 3 and p >= 2 and p <= 5"), 1)
    for sealed, body in first:
        controller.put(sealed, body)
    controller.acknowledge(_ids(first), by="engineer")
    other = _mesh_floor(point, table("cmd == 3 and p >= 2 and p <= 6"), 2, widens=False,
                        replaces=env.read(env.unseal(first[0][0])[0]).policy_sha256)
    with pytest.raises(Refused) as refused:
        controller.put(*other[0])
    assert refused.value.cause == install.UNSIGNED and not any("/2/" in key for key in controller.install_sets)
    again = _mesh_floor(point, table("cmd == 3 and p >= 2 and p <= 5"), 3, widens=False,
                        replaces=env.read(env.unseal(first[0][0])[0]).policy_sha256)
    controller.put(*again[0])
    assert [one["state"] for one in controller.install_view()[STREAM]["sets"]] == ["offered", "offered"]


# ------------------------------------------------------------------ IS7, IS8: the two chains never wait

def test_case_173_neither_chain_waits_for_the_other(tmp_path):
    """case_173: IS7, IS8. A PEP two statements behind on the authority's trust chain is offered an action floor with
    them and applies it, and a PEP two behind on the install trust sequence is offered a release with them and commits
    it."""
    fleet = Fleet(tmp_path, names=("p1", "p2"), install_keys=["N1", "N2", "N3", "N4"])
    controller, point = fleet.controller, fleet.first
    for seq, add in ((1, "B"), (2, "D")):
        body = _dist.rotation(add)
        controller.put(_dist.trust_statement("trust.rotation", body, seq=seq, signers=("A", add), targets=("agent",)),
                       body)
    floor = _set(point, FLOOR, NARROW)
    fleet.put(floor)
    controller.acknowledge(_ids(floor), by="engineer")
    answer = controller.answer(fleet.ids["p1"])
    assert [offer["artifact"] for offer in answer["offers"]] == ["trust.rotation"] * 2 + [FLOOR] * 2
    fleet.round("p1")
    assert fleet.held("p1", FLOOR) is not None and fleet.points["p1"].pep.trust.trust_seq == 2
    record = point.pep.installed.record
    first = install.trust_body([_dist.public(name) for name in KEYS], threshold=2)
    one = install.seal_trust(record, first, stream=STREAM, seq=1, targets=["agent"],
                             signers=[GEN.test_key("N1"), GEN.test_key("N2")], not_before=NOT_BEFORE)
    second = install.trust_body([_dist.public(name) for name in ("N1", "N2")], threshold=2)
    two = install.seal_trust(record.apply_trust(env.read(env.unseal(one)[0]), first), second, stream=STREAM, seq=2,
                             targets=["agent"], signers=[GEN.test_key("N1"), GEN.test_key("N2")], not_before=NOT_BEFORE)
    controller.put(one, first)
    controller.put(two, second)
    fleet.put(_release(point, RELEASE, 1))
    controller.offer("fleet", STREAM, 1)
    answer = controller.answer(fleet.ids["p2"])
    artifacts = [offer["artifact"] for offer in answer["offers"]]
    assert artifacts[:2] == ["trust.rotation"] * 2              # still behind on the authority's chain: F6
    for _ in range(3):
        fleet.round("p2")
    p2 = fleet.points["p2"].pep
    assert p2.installed.record.trust_seq == 2 and p2.active is not None and p2.active.seq == 1
    for _ in range(3):
        fleet.round("p1")
    assert fleet.points["p1"].pep.active.seq == 1


def test_case_179_two_install_trust_statements_at_one_sequence_fork_the_stream_visibly(tmp_path):
    """case_179: IS11, IS10, H12. Two PEPs take different well signed `install.trust` statements at the same install
    trust sequence. Both apply, their install ids differ, and the controller files `fleet:policy-mismatch` against
    the one it did not offer."""
    fleet = Fleet(tmp_path, names=("p1", "p2"))
    controller = fleet.controller
    offered = fleet.points["p1"].install_trust(1, ["N1", "N2"], threshold=2)
    other = fleet.points["p2"].install_trust(1, KEYS, threshold=3)
    controller.put(*offered)
    assert fleet.points["p2"].send([other])[-1].event == "install-applied"
    for _ in range(2):
        fleet.round()
    ids = {name: point.pep.installed.record.install_id() for name, point in fleet.points.items()}
    assert ids["p1"] != ids["p2"]
    assert all(point.pep.installed.record.trust_seq == 1 for point in fleet.points.values())
    assert "fleet:policy-mismatch" not in fleet.findings("p1")
    assert fleet.findings("p2")["fleet:policy-mismatch"].startswith("reports install id")


# ------------------------------------------------------------------ H11, H12: the fallback bit and the install id

def test_case_211_the_fallback_bit_and_the_install_id_are_filed_as_h11_and_h12_say(tmp_path):
    """case_211: H11, H12, H6. Records with bit 4 and zeros from a PEP enrolled with a fallback policy whose release
    lapsed open `dist:fallback` with no `fleet:policy-mismatch`, and one without the bit clears it. Bit 4 from a PEP
    enrolled with none and bits 4 and 5 together are `fleet:state-invalid`. An install id that is not the expected one
    and no type 3 where one is expected are `fleet:policy-mismatch`, and the counts file nothing."""
    fleet = Fleet(tmp_path, names=("p1", "p2"))
    controller, point = fleet.controller, fleet.first
    fallback = _set(point, FALLBACK, NARROW)
    fleet.put(fallback)
    controller.acknowledge(_ids(fallback), by="engineer")
    fleet.put(_release(point, RELEASE, 1))
    controller.offer("fleet", STREAM, 1)
    for _ in range(3):
        fleet.round("p1")
    assert point.pep.active.seq == 1 and fleet.held("p1", FALLBACK) is not None
    fleet.clock.now = _dist.EXPIRES + 1
    point.pep.tick()
    fleet.clients["p1"].send()
    member = fleet.member("p1")
    assert member.last["event"] in ("fallback", "beat") and "dist:fallback" in member.findings
    assert "fleet:policy-mismatch" not in member.findings
    signed = _record(fleet, "p1")
    read = state_record.read(signed, point.key.public_raw)
    assert read.fallback and read.active_policy == bytes(16)
    back = replace(read, fallback=False, counter=read.counter + 1,
                   active_policy=state_record.prefix(member.expected[0]),
                   active_release=state_record.prefix(member.expected[1]), active_seq=1)
    assert controller.receive(state_record.build(back, point.key)) is None
    assert "dist:fallback" not in fleet.findings("p1")
    lone = fleet.points["p2"]
    plain = state_record.read(_record(fleet, "p2"), lone.key.public_raw)
    for changes in ({"fallback": True}, {"fallback": True, "held": True}):
        forged = replace(plain, counter=plain.counter + 10, **changes)
        assert controller.receive(state_record.build(forged, lone.key)) == "fleet:state-invalid"
    entry = plain.install
    wrong = replace(entry, install_id=b"\x07" * 16)
    for count, extensions in enumerate((wrong.extension(), b""), 20):
        forged = replace(plain, counter=plain.counter + count, extensions=extensions)
        assert controller.receive(state_record.build(forged, lone.key)) == "fleet:policy-mismatch"
    counted = replace(entry, answers=7, overrides=3)
    forged = replace(plain, counter=plain.counter + 30, extensions=counted.extension())
    assert controller.receive(state_record.build(forged, lone.key)) is None
    shown = next(one for one in controller.fleet()["peps"] if one["labels"]["id"] == fleet.ids["p2"])
    assert (shown["install"]["floor_answers"], shown["install"]["floor_overrides"]) == (7, 3)


def test_case_228_a_record_under_the_fallback_policy_carries_no_body(tmp_path):
    """case_228: H5, H6, H11. A PEP with a release and an action floor decides two requests by its release and one by
    its floor: the body has two frames under the release's preamble. Under its fallback policy it decides one and its
    body has length 0. A record with bit 4 and a body that is not empty is `fleet:policy-mismatch` at step 4. In
    Python the PEP whose release has a `policy.core`, and so a Facet body, is the agent home, so the host here is an
    `agent` PEP."""
    import itertools
    from prismpath.agent import profile
    from prismpath.agent.policy import Policy, starter_path
    from prismpath.distribution import heartbeat
    image = starter_path("default").read_bytes().rstrip(b"\n")
    fleet = Fleet(tmp_path)
    controller, point = fleet.controller, fleet.first
    _floor_in_place(fleet)
    fallback = _set(point, FALLBACK, NARROW)
    fleet.put(fallback)
    controller.acknowledge(_ids(fallback), by="engineer")
    fleet.put(_release(point, image, 1))
    controller.offer("fleet", STREAM, 1)
    for _ in range(3):
        fleet.round()
    assert point.pep.active.seq == 1
    names, constant, groups = profile.domain_classes([Policy(image).doc])
    readings = [dict(zip(names, (group[0] for group in combo)), **constant)
                for combo in itertools.islice(itertools.product(*groups), 2)]
    silent = {"reading": {**ASK["reading"], "tool": "delete_path"}}
    for reading in readings:
        assert point.pep.decide(lambda: "release", reading, request=silent)["basis"] == "release"
    assert point.pep.decide(lambda: "release", readings[0], request=ASK)["basis"] == "floor"
    first = state_record.read(_record(fleet, "p1"), point.key.public_raw)
    assert len(heartbeat.decode(image, first.body)) == 2
    fleet.clock.now = _dist.EXPIRES + 1
    point.pep.tick()
    point.pep.drain()
    assert point.pep.decide(lambda: "fallback", readings[0], request=silent)["basis"] == "fallback"
    second = state_record.read(_record(fleet, "p1"), point.key.public_raw)
    assert second.fallback and second.body == b""
    forged = replace(second, counter=second.counter + 1, body=first.body)
    assert controller.receive(state_record.build(forged, point.key)) == "fleet:policy-mismatch"
    assert "fallback" in fleet.findings("p1")["fleet:policy-mismatch"]


# ------------------------------------------------------------------ H13, H6: a first set at provisioning, and a mix

def _node_round(point, sent, monotonic):
    from prismpath.distribution import frames
    from prismpath.distribution import verify as verifier
    pep = point.pep
    assembler = frames.Assembler(frames.admit_through_v8(
        lambda sealed: verifier.verify_envelope(sealed, trust=pep.trust, pep=pep.view(), now=int(pep.clock()))),
        clock=lambda: monotonic["now"], artifact_bound=pep.target.body_bound)
    for data in sent:
        event = assembler.receive(data)
        if isinstance(event, frames.Assembled):
            pep.stage(event.sealed, event.body)
        elif isinstance(event, frames.Epoch):
            pep.take_statement(event.statement)
    pep.tick()
    return [frames.encode(frames.State(0, record)) for record in pep.drain()]


def test_case_219_a_first_floor_at_provisioning_is_acknowledged_by_enrollment_and_a_group_may_be_mixed(tmp_path):
    """case_219: H13, H6, IS4, the Python half. A PEP provisioned with a first action floor sends its `provisioned`
    record before it is enrolled: the record is kept and not filed, and at the enrollment it carries
    `dist:install-widened`, which the enrollment of its install id clears. Three `mesh` PEPs of one group are sent a
    new floor that one of them refuses: two apply and one does not, with no abort, and their install ids show the
    mix."""
    from prismpath.distribution import frames
    from prismpath.distribution.controller import FrameDriver
    clock = _dist.Clock()
    points = {name: _table_point(MeshFloor, tmp_path, name, clock=clock, key=_dist.instance_key(name))
              for name in ("n1", "n2")}

    class OtherLayout(MeshFloor):
        def adapter(self):
            adapter = super().adapter()
            adapter.floor_layout = OTHER_LAYOUT
            return adapter
    points["n3"] = _table_point(OtherLayout, tmp_path, "n3", clock=clock, key=_dist.instance_key("n3"))
    controller = Controller(str(tmp_path / "controller"), _dist.instance_key("C"), clock=clock)
    first = points["n1"]
    controller.add_anchor(first.anchor(), layout=LAYOUT)
    floor = _mesh_floor(first, table("cmd == 3 and p >= 2 and p <= 5"), 1)
    for sealed, body in floor:
        controller.put(sealed, body)
    records = {}
    for name, point in points.items():
        point.pep.confirm(point.pep.provision(point.anchor(), floor if name != "n3" else ()))
        records[name] = [one for one in point.pep.drain()
                         if state_record.read(one, point.key.public_raw).event == "provisioned"][-1]
    assert state_record.read(records["n1"], first.key.public_raw).cause == install.WIDENED
    assert controller.receive(records["n1"]) is None
    kept = len(controller.audit.events)
    assert controller.pending and not controller.unknown
    pep = controller.enroll(first.key.public_raw, "mesh", STREAM, "fleet", install_envelopes=_ids(floor))
    events = _audit(controller)[kept:]
    assert ("finding", {"pep": pep, "finding": install.WIDENED,
                        "detail": events[[e[0] for e in events].index("finding")][1]["detail"]}) in events
    assert ("cleared", {"pep": pep, "finding": install.WIDENED}) in events
    assert controller.members[pep].findings == {} and controller.members[pep].counter > 0
    controller.enroll(points["n2"].key.public_raw, "mesh", STREAM, "fleet", install_envelopes=_ids(floor))
    controller.enroll(points["n3"].key.public_raw, "mesh", STREAM, "fleet")
    controller.acknowledge(_ids(floor), by="engineer")        # n3 holds none, so the first floor is offered to it
    new = _mesh_floor(first, table("cmd == 3 and p >= 2 and p <= 4"), 2,
                      replaces=env.read(env.unseal(floor[0][0])[0]).policy_sha256)
    for sealed, body in new:
        controller.put(sealed, body)
    controller.acknowledge(_ids(new), by="engineer")          # on mesh every changed table is larger (H13)
    driver = FrameDriver(controller, "fleet", limit=frames.ESPNOW_LIMIT)
    monotonic = {"now": 0.0}
    for _ in range(3):
        sent = driver.send()
        for point in points.values():
            for reply in _node_round(point, sent, monotonic):
                driver.receive(reply)
    held = {name: point.pep.installed.held(FLOOR) for name, point in points.items()}
    assert held["n1"].seq == held["n2"].seq == 2 and held["n3"] is None
    assert not controller.rollouts
    shown = {one["labels"]["id"]: one["install"]["reported"] for one in controller.fleet()["peps"]}
    ids = {name: point.pep.installed.record.install_id().hex() for name, point in points.items()}
    assert sorted(shown.values()) == sorted(ids.values()) and ids["n1"] == ids["n2"] != ids["n3"]
    member = controller.members[state_record.pep_id(points["n3"].key.public_raw).hex()]
    assert member.findings.get("dist:target-mismatch", "").startswith("refused")


def test_case_238_kept_provisioned_records_are_bounded_and_checked(tmp_path):
    """case_238: H6, H3, H13. A PEP whose last counter the controller holds at 40 is enrolled again and its record
    at counter 39 is `fleet:state-replay`. Before another PEP is enrolled, four forged `provisioned` records for its
    id and the real one are kept, and the real one is used at enrollment. After 64 forged ids push the real record
    out, the enrollment still sets the install id and the next record shows it."""
    fleet = Fleet(tmp_path, names=("p1", "p2", "p3"), enroll=False)
    controller = fleet.controller
    fleet.enroll("p1")
    member = fleet.member("p1")
    member.counter = 40
    fleet.enroll("p1")
    signed = _record(fleet, "p1")
    old = replace(state_record.read(signed, fleet.first.key.public_raw), counter=39)
    assert controller.receive(state_record.build(old, fleet.first.key)) == "fleet:state-replay"

    def provisioned(name):
        point = fleet.points[name]
        point.pep.confirm(point.pep.provision(point.anchor()))
        return [one for one in point.pep.drain()
                if state_record.read(one, point.key.public_raw).event == "provisioned"][-1]

    real = provisioned("p2")
    read = state_record.read(real, fleet.points["p2"].key.public_raw)
    forger = _dist.instance_key("forger")
    for count in range(4):
        controller.receive(state_record.build(replace(read, counter=read.counter + 100 + count), forger))
    controller.receive(real)
    pep = fleet.enroll("p2")
    assert fleet.member("p2").counter == read.counter and fleet.member("p2").findings == {}
    real3 = provisioned("p3")
    controller.receive(real3)
    for index in range(64):
        forged = replace(state_record.read(real3, fleet.points["p3"].key.public_raw),
                         pep_id=bytes([index]) * 16)
        controller.receive(state_record.build(forged, forger))
    assert state_record.pep_id(fleet.points["p3"].key.public_raw).hex() not in controller.pending
    assert len(controller.pending) == 64 and pep
    fleet.enroll("p3")
    assert fleet.member("p3").counter == 0
    assert controller.receive(_record(fleet, "p3")) is None
    assert fleet.member("p3").last["install"]["install_id"] == install_id_of(fleet.member("p3").install).hex()


# ------------------------------------------------------------------ OP1, IS11, IS7, K4: the roles stay apart

def test_case_221_an_operator_key_added_by_install_trust_widens_and_signs_nothing_else(tmp_path):
    """case_221: OP1, IS11, H13, the Python half. An anchor enrolls one operator key. An `install.trust` that adds a
    second with `widens` false is `dist:widening-unsigned` at the PEP and the controller, and with `widens` true it is
    applied with `install-widened` and held at the controller for its acknowledgement. One that adds an install key
    as an operator is `dist:rotation-invalid`, and an install statement and a release signed by an operator key are
    `dist:unknown-key`."""
    fleet = Fleet(tmp_path, operators=["O1"])
    controller, point = fleet.controller, fleet.first
    assert set(point.pep.installed.record.operators) == {_dist.key_id("O1")}
    quiet = point.install_trust(1, KEYS, threshold=2, operators=["O1", "O2"], widens=False, signers=["N1", "N2", "O2"])
    assert point.send([quiet])[-1].cause == install.UNSIGNED
    with pytest.raises(Refused) as refused:
        controller.put(*quiet)
    assert refused.value.cause == install.UNSIGNED
    said = point.install_trust(1, KEYS, threshold=2, operators=["O1", "O2"], widens=True, signers=["N1", "N2", "O2"])
    controller.put(*said)
    assert controller.install_findings[env.envelope_id(env.unseal(said[0])[0])].startswith("an install trust")
    assert not controller.answer(fleet.ids["p1"])["offers"]
    applied = point.send([said])[-1]
    assert (applied.event, applied.cause, applied.install.subject) == ("install-widened", install.WIDENED, TRUST)
    install_key = point.install_trust(2, KEYS, threshold=2, operators=["O1", "O2", "N3"], signers=["N1", "N2"])
    assert point.send([install_key])[-1].cause == install.ROTATION_INVALID
    by_operator = point.install_set(FALLBACK, {"policy.core": NARROW, "egress.hosts": HOSTS}, signers=["O1"],
                                    widens=True)
    assert point.send(by_operator)[0].cause == "dist:unknown-key"
    release = point.seal(RELEASE, signer="O1", widens=True)
    assert point.send([(release, RELEASE)])[-1].cause == "dist:unknown-key"


def test_case_239_the_tool_and_the_controller_keep_every_retired_id(tmp_path):
    """case_239: K4, K5, IS11. Seventeen authority keys and nine install keys are retired, so the PEP no longer
    holds the first id of each. The sealing tool and the controller, which keep every retired id, refuse a rotation
    and an `install.trust` that add back the first of each."""
    from prismpath.distribution import cli as dist_cli
    from prismpath.hotswap import policy_pack
    fleet = Fleet(tmp_path)
    controller, point = fleet.controller, fleet.first
    current = "A"
    for seq in range(1, 18):
        new = f"K{seq}"
        body = _dist.rotation(new, retire=current)
        sealed = _dist.trust_statement("trust.rotation", body, seq=seq, signers=(current, new), targets=("agent",))
        controller.put(sealed, body)
        assert state_record.read(point.pep.stage(sealed, body), point.key.public_raw).event == "trust-applied"
        current = new
    keys = list(KEYS)
    for seq in range(1, 10):
        dropped, added = keys[0], f"M{seq}"
        keys = keys[1:] + [added]
        record = point.pep.installed.record
        signers = [name for name in [dropped] + keys if _dist.key_id(name) in record.keys][:2] + [added]
        body = install.trust_body([_dist.public(name) for name in keys], threshold=2)
        sealed = install.seal_trust(record, body, stream=STREAM, seq=seq, targets=["agent"],
                                    signers=[GEN.test_key(name) for name in signers], not_before=NOT_BEFORE)
        controller.put(sealed, body)
        controller.acknowledge([env.envelope_id(env.unseal(sealed)[0])], by="engineer")
        assert point.send([(sealed, body)])[-1].event == "install-widened"
    assert _dist.key_id("A") not in point.pep.trust.retired and len(point.pep.trust.retired) == 16
    assert _dist.key_id("N1") not in point.pep.installed.record.retired
    back = _dist.rotation("A")
    with pytest.raises(Refused) as refused:
        controller.put(_dist.trust_statement("trust.rotation", back, seq=18, signers=(current, "A"),
                                             targets=("agent",)), back)
    assert refused.value.cause == install.ROTATION_INVALID
    record = point.pep.installed.record
    again = install.trust_body([_dist.public(name) for name in keys + ["N1"]], threshold=2)
    sealed = install.seal_trust(record, again, stream=STREAM, seq=10, targets=["agent"],
                                signers=[GEN.test_key(name) for name in keys[-2:] + ["N1"]], not_before=NOT_BEFORE)
    with pytest.raises(Refused) as refused:
        controller.put(sealed, again)
    assert refused.value.cause == install.ROTATION_INVALID
    controller.save()
    _priv, _pub, ser, _invalid = policy_pack._ed25519()

    def pem(name):
        path = tmp_path / f"{name}.pem"
        path.write_bytes(GEN.test_key(name).private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                                          ser.NoEncryption()))
        return str(path)
    rotate = dist_cli.rotate_cmd(_Args(new=pem("A"), retire="", seq=18, target=["agent"], key=[pem(current)],
                                       held=str(tmp_path / "controller"), not_before=NOT_BEFORE,
                                       out=str(tmp_path / "back.sealed")))
    assert rotate == 1 and not (tmp_path / "back.sealed").exists()
    retired = tmp_path / "retired.txt"
    retired.write_text("".join(one + "\n" for one in sorted(controller.install_retired(STREAM))))
    for name in keys + ["N1"]:
        (tmp_path / f"{name}.pub").write_bytes(_dist.public(name))
    sealed_tool = dist_cli.install_trust_cmd(_Args(
        current_pub=[str(tmp_path / f"{name}.pub") for name in keys], current_threshold=2, current_operator=[],
        install_pub=[str(tmp_path / f"{name}.pub") for name in keys + ["N1"]], operator_pub=[], threshold=2,
        retired=str(retired), stream=STREAM, seq=10, target="agent", key=[pem(name) for name in keys[-2:] + ["N1"]],
        not_before=NOT_BEFORE, out=str(tmp_path / "again.sealed")))
    assert sealed_tool == 1 and not (tmp_path / "again.sealed").exists()


class _Args:
    def __init__(self, **values):
        self.__dict__.update(values)


def test_case_172_a_revocation_never_reaches_an_install_key_or_an_install_set(tmp_path):
    """case_172: IS7, AF3, the Python half. A PEP with an action floor applies a revocation that lists an install key
    id, the floor's envelope ids and its policy hash, and its floor decides as before with the install key still
    counting. A `trust.rotation` whose `retire` names an install key is `dist:rotation-invalid`. The sealing tool and
    the controller refuse that revocation list."""
    from prismpath.distribution import cli as dist_cli
    from prismpath.hotswap import policy_pack
    fleet = Fleet(tmp_path)
    controller, point = fleet.controller, fleet.first
    floor = _floor_in_place(fleet)
    held = fleet.held("p1", FLOOR)
    lists = {"keys": [_dist.key_id("N1")], "envelopes": _ids(floor), "policies": [held.policy_sha256]}
    applied = state_record.read(point.revoke(1, **lists), point.key.public_raw)
    assert applied.event == "trust-applied"
    assert point.pep.decide(lambda: "release", request=ASK)["basis"] == "floor"
    fallback = point.install_set(FALLBACK, {"policy.core": NARROW, "egress.hosts": HOSTS}, signers=["N1", "N2"],
                                 widens=True)
    assert point.send(fallback)[-1].event == "install-widened"
    rotated = state_record.read(point.rotate(2, add="B", retire="N1"), point.key.public_raw)
    assert rotated.cause == install.ROTATION_INVALID
    body = _dist.revocation(**lists)
    with pytest.raises(Refused) as refused:
        controller.put(_dist.seal("trust.revocation", body, stream=env.TRUST_STREAM, targets=("agent",)), body)
    assert refused.value.cause == install.ROTATION_INVALID
    controller.save()
    _priv, _pub, ser, _invalid = policy_pack._ed25519()
    pem = tmp_path / "A.pem"
    pem.write_bytes(GEN.test_key("A").private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    out = tmp_path / "list.sealed"
    code = dist_cli.revoke_cmd(_Args(entry=[f"key={_dist.key_id('N1')}"], drop=[], floor=[], seq=None, target=None,
                                     key=[str(pem)], held=str(tmp_path / "controller"), not_before=NOT_BEFORE,
                                     out=str(out)))
    assert code == 1 and not out.exists()


def test_case_190_a_renewal_needs_no_widening_whatever_the_floor_allows(tmp_path):
    """case_190: AF4, the Python half. A PEP whose active release refuses a request its floor allows commits a renewal
    of that release with no widening statement and its floor still allows the request, and the controller offers the
    renewal as it would with no floor."""
    fleet = Fleet(tmp_path)
    controller, point = fleet.controller, fleet.first
    _floor_in_place(fleet)
    fleet.put(_release(point, RELEASE, 1))
    controller.offer("fleet", STREAM, 1)
    for _ in range(3):
        fleet.round()
    assert point.pep.active.seq == 1
    fleet.put(_release(point, RELEASE, 2, widen=False, replaces=H(RELEASE)))
    rollout = controller.offer("fleet", STREAM, 2)
    for _ in range(3):
        fleet.round()
    assert rollout.state == "committed" and point.pep.active.seq == 2
    decided = point.pep.decide(lambda: "release", request=ASK)
    assert decided["basis"] == "floor" and decided["would"]["outcome"] != "allow"


def test_case_210_a_mesh_record_carries_the_install_entry_in_one_frame(tmp_path):
    """case_210: H10, H1, B10, the Python half. A `mesh` PEP with install statements sends a type 3 entry of 27 bytes
    with its install id, the low bits of its install trust sequence and counts of 3 floor answers and 1 override
    after three floor allows of which one was an override, the same counts after none and after a restart, then
    `install-applied` with subject 1 and another install id after a new action floor, each record in one frame of
    246 bytes with no type 1 or type 2 entry."""
    from prismpath.distribution import frames
    point = _table_point(MeshFloor, tmp_path, "m1", key=_dist.instance_key("m1"))
    assert point.send(_table_floor(point, table("cmd == 3 and p >= 2 and p <= 5"), 1))[-1].event == "install-widened"
    point.commit(table("cmd == 3"), expires=_dist.NOW + 86400)
    point.pep.drain()
    asks = [{"regs": regs(cmd=3, p=3)}, {"regs": regs(cmd=3, p=4)}, {"regs": regs(cmd=4, p=3)}]
    release = table("cmd == 3")
    assert point.pep.active.bodies["policy.ppt"] == release

    def frame(event="beat"):
        signed = point.pep.record(event)
        point.pep.drain()
        data = frames.encode(frames.State(0, signed))
        read = state_record.read(signed, point.key.public_raw)
        kinds_of = [kind for kind, _value in state_record.extension_entries(read.extensions)]
        assert len(data) == 246 and kinds_of == [3] and len(read.install.extension()) == 3 + 27
        return read
    decisions = [point.pep.decide(lambda: "release", request=ask) for ask in asks[:2]]
    assert all(one["basis"] == "floor" and not one["override"] for one in decisions)
    first = frame()
    assert (first.install.answers, first.install.overrides) == (2, 0)
    wider = _table_floor(point, table("cmd == 3 and p >= 2 and p <= 5", "cmd == 4 and p >= 2 and p <= 5"), 2)
    assert point.send(wider)[-1].event == "install-widened"
    third = point.pep.decide(lambda: "release", request=asks[2])
    assert third["basis"] == "floor" and third["override"]
    counted = frame()
    assert (counted.install.answers, counted.install.overrides) == (3, 1)
    assert (frame().install.answers, frame().install.overrides) == (3, 1)
    point.pep = point.open()
    after = frame()
    assert (after.install.answers, after.install.overrides) == (3, 1)
    assert after.install.trust_seq == 0 and after.install.install_id == point.pep.installed.record.install_id()
    renewal = _table_floor(point, table("cmd == 3 and p >= 2 and p <= 5", "cmd == 4 and p >= 2 and p <= 5"), 3,
                           widens=False, replaces=point.pep.floor_set().policy_sha256)
    point.send(renewal)
    applied = [state_record.read(one, point.key.public_raw) for one in point.pep.drain()][-1]
    assert applied.event == "install-applied" and applied.install.subject == FLOOR
    assert applied.install.install_id != after.install.install_id
    for one in (applied,):
        assert len(frames.encode(frames.State(0, state_record.build(one, point.key)))) == 246


def test_case_185_the_acknowledger_s_command_names_envelope_ids_and_signs_nothing(tmp_path, capsys):
    """case_185: H13, P2 step 5, the command line. `prismpath dist enroll --install` enrolls the install id from the
    envelope ids the PEP printed, and `prismpath dist acknowledge` acknowledges a held set by the envelope ids of its
    statements as the login that runs it, refusing a release id and 64 zeros."""
    import json
    from prismpath import cli
    from prismpath.hotswap import policy_pack
    _priv, _pub, ser, _invalid = policy_pack._ed25519()
    keyfile = tmp_path / "C.pem"
    keyfile.write_bytes(GEN.test_key("C").private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))

    def run(*argv):
        args = cli.build_parser().parse_args(["dist", *argv])
        code = args.func(args)
        captured = capsys.readouterr()
        out = captured.out
        assert code == 0 or captured.err
        return code, (json.loads(out) if out.strip().startswith("{") else captured.err)

    import time
    point = _agent(tmp_path, "p1", key=_dist.instance_key("p1"))
    floor = _set(point, FLOOR, NARROW, not_before=int(time.time()) - 60)     # the controller runs at the real clock
    point.pep.provision(point.anchor(), floor)
    printed = point.pep.printed["install"]
    point.pep.confirm(point.pep.printed["fingerprint"])
    directory = tmp_path / "controller"
    inbox = directory / "inbox"
    inbox.mkdir(parents=True)
    for index, (sealed, body) in enumerate(floor):
        (inbox / f"f{index}.sealed").write_bytes(sealed)
        (inbox / f"f{index}.body").write_bytes(body)
    (tmp_path / "anchor.json").write_bytes(point.anchor())
    (tmp_path / "p1.pub").write_bytes(point.key.public_raw)
    install_args = [arg for one in printed for arg in ("--install", one)]
    code, out = run("enroll", "--dir", str(directory), "--key", str(keyfile), "--pub", str(tmp_path / "p1.pub"),
                    "--anchor", str(tmp_path / "anchor.json"), *install_args)
    assert code == 0, out
    member = Controller.reader(str(directory)).members[out["enrolled"]]
    assert install_id_of(member.install) == point.pep.installed.record.install_id()
    release_id = env.read(env.unseal(floor[0][0])[0]).release
    for wrong in (release_id, "0" * 64):
        assert run("acknowledge", "--dir", str(directory), "--key", str(keyfile), "--envelope", wrong)[0] == 2
    code, out = run("acknowledge", "--dir", str(directory), "--key", str(keyfile),
                    *[arg for one in _ids(floor) for arg in ("--envelope", one)], "--by", "engineer")
    assert code == 0 and out["by"] == "engineer"
    view = Controller.reader(str(directory)).install_view()[STREAM]["sets"]
    assert [one["state"] for one in view] == ["offered"] and view[0]["acknowledged"]["by"] == "engineer"


def test_case_232_the_fleet_view_shows_each_operator_answer_beside_its_pep(tmp_path):
    """case_232: OP4, H1, the controller's half. Each answer a PEP applies sends a record with event `answered` and
    subject 5, and the controller shows each one in the fleet view beside the PEP, with the floor answer and
    override counts. The answers and their rate on a `cfs` PEP are in integrations/cfs/tests."""
    fleet = Fleet(tmp_path, operators=["O1"])
    controller, point = fleet.controller, fleet.first
    escalating = core('-> escalate agent:change-asked: when tool == "list_dir" and path_scope == "workspace"')
    pairs = _set(point, FLOOR, escalating, answer_rate={"allows": 2, "window": 600})
    fleet.put(pairs)
    controller.acknowledge(_ids(pairs), by="engineer")
    fleet.round()
    assert fleet.held("p1", FLOOR) is not None
    for _ in range(2):
        asked = point.pep.decide(lambda: "release", request=ASK)
        assert asked["decision"] == "escalate"
        sealed, body = _dist.answer(point, asked["receipt_sha256"])
        assert point.send([(sealed, body)])[-1].event == "answered"
    fleet.clients["p1"].send()
    shown = next(one for one in controller.fleet()["peps"] if one["labels"]["id"] == fleet.ids["p1"])["install"]
    assert len(shown["answered"]) == 2 and shown["floor_answers"] == 2 and shown["floor_overrides"] == 2
    assert shown["reported"] == shown["expected"]


def test_case_184_a_pep_holds_the_signer_to_widens_as_far_as_it_can_tell(tmp_path):
    """case_184: IS12, W2, the `mesh` and `agent` parts. A `mesh` PEP applies a first floor and one that allows more,
    each with `widens` true, with `install-widened` and `dist:install-widened`, the same table at a higher `seq` with
    `widens` false and `replaces` the held policy hash with `install-applied`, and refuses one with another
    `replaces` and a table that allows less, both with `widens` false, with `dist:widening-unsigned`. An `agent` PEP
    refuses a floor it computes as larger with `widens` false. The held `cfs` part is in integrations/cfs/tests."""
    point = _table_point(MeshFloor, tmp_path, "m1")
    small, large = table("cmd == 3 and p >= 2 and p <= 5"), table("cmd == 3 and p >= 2 and p <= 5",
                                                                  "cmd == 4 and p >= 2 and p <= 5")
    held = lambda: point.pep.floor_set().policy_sha256      # noqa: E731
    for seq, body in ((1, small), (2, large)):
        applied = point.send(_table_floor(point, body, seq))[-1]
        assert (applied.event, applied.cause) == ("install-widened", install.WIDENED)
    applied = point.send(_table_floor(point, large, 3, widens=False, replaces=held()))[-1]
    assert (applied.event, applied.cause) == ("install-applied", None)
    assert point.send(_table_floor(point, large, 4, widens=False, replaces="ab" * 32))[-1].cause == install.UNSIGNED
    assert point.send(_table_floor(point, small, 5, widens=False, replaces=held()))[-1].cause == install.UNSIGNED
    agent = _agent(tmp_path, "a1")
    assert agent.send(_set(agent, FLOOR, NARROW))[-1].event == "install-widened"
    wider = _set(agent, FLOOR, WIDER, 2, widens=False, replaces=H(NARROW))
    assert install.UNSIGNED in [one.cause for one in agent.send(wider)]


# ------------------------------------------------------------------ CL1, CL2: the ceiling at the PEP and the controller

def _zones(*names):
    return canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": kinds.ZONES_FORMAT,
                               "protected": sorted(names)})


MORE_HOSTS = canon.canon2_bytes(["api.example.com", "docs.example.com"])
WRITE = '-> allow: when tool == "write_file" and path_scope == "workspace"'


def _zoned_release(point, policy, seq, zones, hosts=HOSTS):
    """The pairs of an `agent` release of `policy`, `hosts` and `zones` with its widening statement."""
    release = env.release_id([("agent.zones", H(zones)), ("egress.hosts", H(hosts)), ("policy.core", H(policy))])
    args = {"seq": seq, "targets": ("agent",), "release": release, "policy_sha256": H(policy), "widens": True}
    statement = _dist.widening()
    return [(_dist.seal("trust.widening", statement, **args), statement), (_dist.seal("policy.core", policy, **args), policy),
            (_dist.seal("egress.hosts", hosts, **args), hosts), (_dist.seal("agent.zones", zones, **args), zones)]


def test_case_203_no_release_above_the_ceiling_is_staged_or_offered(tmp_path):
    """case_203: CL1, CL2, IS12, the `agent` and `mesh` parts and the controller's. An `agent` PEP with a ceiling
    refuses a release whose policy allows a reading the ceiling refuses, one with a host the ceiling's `egress.hosts`
    lacks and one that drops a name the ceiling's `agent.zones` protects, and stages one inside it. A `mesh` PEP with a
    list stages a table on it and refuses one off it, refuses a floor table off it, refuses a list that adds that
    floor's hash with `widens` false, applies it with `widens` true, and then the floor. A controller that holds each
    ceiling refuses to offer the releases above it. The `gateway` part is in test_distribution_gateway.py and the
    `cfs` part in integrations/cfs/tests."""
    fleet = Fleet(tmp_path)
    controller, point = fleet.controller, fleet.first
    keys = _zones("keys")
    ceiling = point.install_set(CEILING, {"policy.core": core(LIST, READ), "egress.hosts": HOSTS, "agent.zones": keys},
                                1, widens=False)
    fleet.put(ceiling)
    assert not controller.install_findings                    # a first ceiling does not widen
    fleet.round()
    assert fleet.held("p1", CEILING) is not None
    above = [(core(LIST, READ, WRITE), HOSTS), (NARROW, MORE_HOSTS)]
    for seq, (policy, hosts) in enumerate(above, 1):
        pairs = _zoned_release(point, policy, seq, keys, hosts)
        assert "dist:above-ceiling" in [one.cause for one in point.send(pairs)]
        fleet.put(pairs)
        with pytest.raises(Refused) as refused:
            controller.offer("fleet", STREAM, seq)
        assert refused.value.cause == "dist:above-ceiling"
    dropped = _release(point, NARROW, 3)
    point.send(dropped)
    assert state_record.read(point.pep.commit(STREAM, 3, H(NARROW)), point.key.public_raw).cause == "dist:above-ceiling"
    fleet.put(dropped)
    with pytest.raises(Refused):
        controller.offer("fleet", STREAM, 3)
    inside = _zoned_release(point, NARROW, 4, _zones("keys", "notes"))
    assert point.send(inside)[-1].event == "staged"
    fleet.put(inside)
    assert controller.offer("fleet", STREAM, 4).state == "offered"
    # a mesh PEP with a list
    mesh = _table_point(MeshFloor, tmp_path, "m1", key=_dist.instance_key("m1"))
    first, second = table("cmd == 1"), table("cmd == 2")
    floor_table = table("cmd == 3 and p >= 2 and p <= 5")

    def listed(seq, *tables, widens=False):
        held = mesh.pep.installed.record.sets[CEILING]
        return mesh.install_set(CEILING, {kinds.POLICY_LIST: install.ceiling_body(tables)}, seq, widens=widens,
                                replaces=held.policy_sha256 if held else "")
    assert mesh.send(listed(1, first))[-1].event == "install-applied"
    assert state_record.read(mesh.stage(first, 1), mesh.key.public_raw).event == "staged"
    assert state_record.read(mesh.stage(second, 2), mesh.key.public_raw).cause == "dist:above-ceiling"
    assert mesh.send(_table_floor(mesh, floor_table, 1))[-1].cause == "dist:above-ceiling"
    assert mesh.send(listed(2, first, floor_table))[-1].cause == install.UNSIGNED
    assert mesh.send(listed(2, first, floor_table, widens=True))[-1].event == "install-widened"
    assert mesh.send(_table_floor(mesh, floor_table, 1))[-1].event == "install-widened"
    meshes = Controller(str(tmp_path / "meshes"), _dist.instance_key("C"), clock=mesh.clock)
    meshes.add_anchor(mesh.anchor(), layout=LAYOUT)
    meshes.enroll(mesh.key.public_raw, "mesh", STREAM, "nodes")
    for sealed, body in mesh.install_set(CEILING, {kinds.POLICY_LIST: install.ceiling_body([first])}, 1):
        meshes.put(sealed, body)
    for seq, body in ((1, first), (2, second)):
        for sealed, data in _dist.release_with_statement(mesh, body, seq, widen=True, replaces=""):
            meshes.put(sealed, data)
    assert meshes.offer("nodes", STREAM, 1).state == "offered"
    with pytest.raises(Refused) as refused:
        meshes.offer("nodes", STREAM, 2)
    assert refused.value.cause == "dist:above-ceiling"
