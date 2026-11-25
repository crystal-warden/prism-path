# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""One core policy on three targets (spec-policy-distribution.md, section 20, case 105). One controller offers one
release of one core policy to a `host` PEP, an `agent` PEP over a real agent home and the cFS app's table through
the C harness. The test names the conformance case it covers.

The core policy is compiled once. Each kind gets the artifacts it needs from it, sealed once each: the host takes the
compiled `.ppt` image, the agent the core image itself with its egress hosts, and the cFS app the table built from the
image. All three envelope sets carry the policy hash of the core image (E7), so all three state records name one hash.

It skips, naming the reason, when there is no C compiler or the tree does not carry prismpath-hw and integrations/cfs."""
import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.distribution import state_record  # noqa: E402
from prismpath.distribution.controller import Controller  # noqa: E402
from prismpath.distribution.http import LocalTransport, PullClient  # noqa: E402
from prismpath.tests import _dist  # noqa: E402
from prismpath.tests import test_distribution_c as base  # noqa: E402
from prismpath.tests.test_distribution_agent_home import HomePep  # noqa: E402
from prismpath.tests.test_distribution_c_cfs import hc  # noqa: E402,F401  (the host_check build, as a fixture)

N = _dist.NOW
H = canon.sha256_hex
STREAMS = {"host": "e2e/host", "agent": "e2e/agent", "cfs": "e2e/cfs"}


def _core():
    """The core policy, compiled once: its canon/2 image, the PPT image the host runs and the cFS app's table."""
    from integrations.cfs.ground import table
    from integrations.cfs.prismpath_app.policy import gen_image
    core = gen_image.CORE.read_bytes().rstrip(b"\n")
    compiled = gen_image.build(core)
    data = table.pack(compiled)
    table.set_version(data, 1)
    return core, compiled["image"], bytes(data[:table.OFF["ImageSig"]])


def _release(point, policy, artifacts):
    """The (sealed, body) pairs of a first release of `artifacts` on `point`'s kind and stream, the widening statement
    first (W3). Every envelope carries the one policy hash (E7)."""
    shared = dict(stream=point.stream, seq=1, targets=(point.kind,), policy_sha256=policy, widens=True, replaces="",
                  release=env.release_id(sorted((name, H(body)) for name, body in artifacts)))
    statement = _dist.widening()
    return [(_dist.seal("trust.widening", statement, **shared), statement),
            *((_dist.seal(name, body, **shared), body) for name, body in artifacts)]


class CfsPoint:
    """The cFS app behind the C harness: it stages what the controller offers, commits and sends its state records,
    as `PullClient` does for a Python PEP. The harness runs a script and exits, so each round runs the whole script
    again and reads the lines the new steps added."""

    def __init__(self, hc, controller, key):
        from cryptography.hazmat.primitives import serialization as ser
        seed = _dist.GEN.test_key("F").private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
        self.hc, self.controller, self.key = hc, controller, key
        self.id = state_record.pep_id(key.public_raw).hex()
        self.script = [f"key {_dist.key_id('A')} {_dist.public('A').hex()} 0", f"machine 0 1 {seed.hex()} cfs",
                       f"provision {STREAMS['cfs']} {N}"]
        self.done = set()
        self.seen = []                                  # every state record the app made, read

    def step(self, lines):
        out = base._run21(self.hc, [*self.script, *lines])[-len(lines):]
        self.script += lines
        for line in out:
            for item in line.split()[1:]:
                self.seen.append(state_record.read(bytes.fromhex(item), self.key.public_raw))
                self.controller.receive(bytes.fromhex(item))

    def poll(self):
        answer = self.controller.answer(self.id)
        lines = []
        for offer in answer["offers"]:
            if offer["envelope_id"] not in self.done:
                self.done.add(offer["envelope_id"])
                body = self.controller.blob(self.controller.stored[offer["envelope_id"]]["body_sha256"])
                lines.append(f"stage {self.controller.sealed(offer['envelope_id']).hex()} {body.hex()} {N}")
        lines += [f"commit {one['stream']} {one['seq']} {one['policy']} {one['delay']} 0 {N}" for one in answer["commit"]]
        lines.append(f"record {state_record.EVENTS.index('beat')} {N}")
        self.step(lines)


@pytest.fixture
def fleet(hc, tmp_path):
    """One controller serving three streams, one PEP of each kind enrolled in a group of its own, and the release of
    the one core policy stored for each, sealed once per artifact."""
    from integrations.cfs import dist_kind  # noqa: F401  (registers the cfs row of the Python machine)
    from integrations.cfs.tests.test_cfs_dist import CfsPep
    core, image, table_body = _core()
    clock = _dist.Clock()
    controller = Controller(str(tmp_path / "controller"), _dist.instance_key("C"), clock=clock)
    host = _dist.HostPep(tmp_path / "host", clock=clock, key=_dist.instance_key("H"), stream=STREAMS["host"])
    agent = HomePep(tmp_path / "agent", clock=clock, stream=STREAMS["agent"])
    cfs = CfsPep(tmp_path / "cfs", clock=clock, key=_dist.instance_key("F"), stream=STREAMS["cfs"])
    controller.add_anchor(host.anchor(), dict(_dist.GEN.QUALIFICATION))
    controller.add_anchor(agent.anchor())
    controller.add_anchor(cfs.anchor())
    ids = {name: controller.enroll(point.key.public_raw, point.kind, point.stream, point.kind, "each")
           for name, point in (("host", host), ("agent", agent), ("cfs", cfs))}
    # one policy hash, the core image's, in every envelope of every kind (E7)
    policy = H(core)
    sealed = [_release(host, policy, [("policy.ppt", image)]),
              _release(agent, policy, [("policy.core", core), ("egress.hosts", agent.hosts)]),
              _release(cfs, policy, [("cfs.table", table_body)])]
    for pairs in sealed:
        for envelope, body in pairs:
            controller.put(envelope, body)
    fleet = type("Fleet", (), {})()
    fleet.controller, fleet.policy, fleet.ids = controller, policy, ids
    fleet.points = {"host": host, "agent": agent}
    fleet.clients = {name: PullClient(point.pep, LocalTransport(controller)) for name, point in fleet.points.items()}
    fleet.cfs = CfsPoint(hc, controller, cfs.key)
    fleet.keys = {"host": host.key, "agent": agent.key, "cfs": cfs.key}
    return fleet


def _drive(fleet, rollouts, *, until="committed", rounds=8):
    """Poll every PEP until each rollout reaches `until`."""
    for _ in range(rounds):
        for client in fleet.clients.values():
            client.poll()
        fleet.cfs.poll()
        if all(rollout.state == until for rollout in rollouts):
            return
    raise AssertionError({rollout.group: rollout.state for rollout in rollouts})


def _records(fleet):
    """The newest state record of each PEP, read under its instance key: the Python PEPs make one now, the cFS app's
    is the last it made from the harness."""
    out = {}
    for name, point in fleet.points.items():
        out[name] = state_record.read(point.pep.record("beat"), point.key.public_raw)
        point.pep.drain()
    out["cfs"] = fleet.cfs.seen[-1]
    return out


def test_case_105_one_core_policy_is_one_policy_hash_on_a_host_an_agent_and_a_cfs_table_and_one_revocation_lapses_all(fleet):
    """case_105: E7, H1, F4. One controller offers the one release of one core policy to a `host` PEP, an `agent` PEP and
    a cFS app run by the C harness, and all three commit with the core image's hash in their state records and in the
    controller's view. One revocation of that policy hash, sealed once for the three kinds, lapses all three."""
    controller, prefix = fleet.controller, bytes.fromhex(fleet.policy)[:16]
    rollouts = [controller.offer(kind, STREAMS[kind], 1) for kind in ("host", "agent", "cfs")]
    _drive(fleet, rollouts)

    committed = _records(fleet)
    assert {name: (record.state, record.active_policy, record.active_seq) for name, record in committed.items()} == {
        name: ("active", prefix, 1) for name in ("host", "agent", "cfs")}
    assert {record.active_policy for record in committed.values()} == {prefix}
    assert [rollout.policy for rollout in rollouts] == [fleet.policy] * 3
    viewed = {entry["labels"]["kind"]: entry for entry in controller.fleet()["peps"]}
    assert {kind: (entry["reported"]["policy"], entry["reported"]["state"], entry["findings"])
            for kind, entry in viewed.items()} == {kind: (prefix.hex(), "active", {}) for kind in ("host", "agent", "cfs")}
    assert {kind: entry["expected"]["policy"] for kind, entry in viewed.items()} == {kind: fleet.policy for kind in viewed}

    # one revocation of the policy, sealed once and stored once, which each PEP takes from the trust chain
    revoked = _dist.revocation(policies=[fleet.policy])
    controller.put(_dist.seal("trust.revocation", revoked, stream="@trust", targets=("agent", "cfs", "host")), revoked)
    for _ in range(4):
        for client in fleet.clients.values():
            client.poll()
        fleet.cfs.poll()

    lapsed = _records(fleet)
    assert {name: (record.event, record.state, record.cause) for name, record in lapsed.items()} == {
        name: ("beat", "no-policy", None) for name in lapsed}
    causes = {name: [event["data"].get("cause") for event in point.pep.audit.events if event["action"] == "lapsed"]
              for name, point in fleet.points.items()}
    causes["cfs"] = [record.cause for record in fleet.cfs.seen if record.event == "lapsed"]
    assert causes == {name: ["dist:revoked"] for name in ("host", "agent", "cfs")}        # R5
    viewed = {entry["labels"]["kind"]: entry for entry in controller.fleet()["peps"]}
    assert {kind: (entry["reported"]["state"], entry["reported"]["policy"], sorted(entry["findings"]))
            for kind, entry in viewed.items()} == {kind: ("no-policy", "0" * 32, ["fleet:policy-mismatch"])
                                                   for kind in ("host", "agent", "cfs")}   # the controller still expects it
