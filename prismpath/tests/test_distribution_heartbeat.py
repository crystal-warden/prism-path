# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The heartbeat's Facet body (spec-policy-distribution.md, H5) and the controller's check of it (H6 steps 3 to
5). Each test names the conformance case of section 20 it covers.

Only a release with a `policy.core` has flow text for a Facet stream, so the PEP here is of the `agent` row over
`_dist.ModelAgent`, which holds the committed release in memory. The agent home itself comes later."""
from dataclasses import replace

import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.agent import profile  # noqa: E402
from prismpath.agent.policy import Policy, starter_path  # noqa: E402
from prismpath.distribution import heartbeat, state_record  # noqa: E402
from prismpath.distribution.controller import Controller  # noqa: E402
from prismpath.tests import _dist  # noqa: E402
from prismpath.tests._dist import STREAM  # noqa: E402

H = canon.sha256_hex
DEFAULT = starter_path("default").read_bytes().rstrip(b"\n")
STRICT = starter_path("strict").read_bytes().rstrip(b"\n")


def _readings(image, count):
    """`count` readings of the policy's domain, one per class combination in order."""
    import itertools
    policy = Policy(image)
    names, constant, groups = profile.domain_classes([policy.doc])
    combos = itertools.islice(itertools.product(*groups), count)
    return [dict(zip(names, (group[0] for group in combo)), **constant) for combo in combos]


class Agents:
    """A controller serving one agent stream, and agent PEPs enrolled in it on the default starter."""

    def __init__(self, tmp_path):
        self.clock = _dist.Clock()
        self.controller = Controller(str(tmp_path / "controller"), _dist.instance_key("C"), clock=self.clock)
        self.tmp = tmp_path
        self.points = {}

    def pep(self, name):
        point = _dist.AgentPep(self.tmp / name, clock=self.clock, key=_dist.instance_key(name))
        if not self.controller.anchors:
            self.controller.add_anchor(point.anchor())
        self.points[name] = point
        self.controller.enroll(point.key.public_raw, "agent", STREAM)
        return point

    def release(self, point, image, seq=1):
        """Store `image` at `seq` with the controller and commit it on `point`, which it then expects."""
        statement = _dist.widening()
        release = point.release_of(image)
        for sealed, body in ((_dist.seal("trust.widening", statement, seq=seq, release=release, policy_sha256=H(image),
                                         targets=("agent",), widens=True), statement),
                             (point.seal(image, seq, widens=True, replaces=""), image),
                             (point.seal_hosts(image, seq, widens=True, replaces=""), point.hosts)):
            self.controller.put(sealed, body)
        point.commit(image, seq)
        member = self.controller.members[state_record.pep_id(point.key.public_raw).hex()]
        member.expected = (H(image), point.pep.active.release, seq)
        return member

    def record(self, point, **changes):
        point.pep.see_epoch(self.controller.epoch)
        signed = point.pep.record("beat")
        point.pep.drain()
        if not changes:
            return signed
        return state_record.build(replace(state_record.read(signed, point.key.public_raw), **changes), point.key)


@pytest.fixture
def agents(tmp_path):
    return Agents(tmp_path)


def _decide(point, readings):
    for reading in readings:
        assert point.pep.decide(lambda: "decided", reading)["cause"] is None


def test_case_088_a_pep_on_the_expected_policy_sends_a_body_that_decodes(agents):
    """case_088: H5, H6. The body carries the decisions made since the last record, and the controller decodes
    them under the policy it expects, with no finding."""
    point = agents.pep("a1")
    member = agents.release(point, DEFAULT)
    readings = _readings(DEFAULT, 3)
    _decide(point, readings)
    signed = agents.record(point)
    record = state_record.read(signed, point.key.public_raw)
    assert record.body[:4] == b"PPLF" and len(record.body) > 42
    assert agents.controller.receive(signed) is None and member.findings == {} and member.last["decisions"] == 3
    routes = heartbeat.decode(DEFAULT, record.body)
    policy = Policy(DEFAULT)
    assert [policy.decide(policy.reading_bytes(reading)).verdict.get("target") for reading in readings] == [
        next(iter(route.values())) for route in routes]
    empty = state_record.read(agents.record(point), point.key.public_raw)
    assert heartbeat.decode(DEFAULT, empty.body) == []                 # nothing decided since the last record


def test_case_089_a_pep_on_another_policy_is_found_from_the_hash_before_any_decode(agents, monkeypatch):
    """case_089: H6 step 3. With a body and with none, the header's policy hash is another's, and the body is
    never decoded."""
    point = agents.pep("a1")
    member = agents.release(point, STRICT)
    member.expected = (H(DEFAULT), "ab" * 32, 1)
    monkeypatch.setattr(heartbeat, "check", lambda *_: pytest.fail("a body was read before the hashes"))
    _decide(point, _readings(STRICT, 2))
    with_body = agents.record(point)
    assert state_record.read(with_body, point.key.public_raw).body
    assert agents.controller.receive(with_body) == "fleet:policy-mismatch"
    without = agents.record(point, body=b"")
    assert agents.controller.receive(without) == "fleet:policy-mismatch"


def test_case_090_a_body_whose_preamble_is_another_policy_is_policy_mismatch(agents):
    """case_090: H6 step 4. The header names the expected policy and the body was built from another."""
    point = agents.pep("a1")
    member = agents.release(point, DEFAULT)
    other = heartbeat.body(STRICT, _readings(STRICT, 2))
    assert agents.controller.receive(agents.record(point, body=other)) == "fleet:policy-mismatch"
    assert "policy hash" not in member.findings["fleet:policy-mismatch"]
    assert agents.controller.receive(agents.record(point)) is None and member.findings == {}


def test_case_091_a_body_cut_inside_a_code_is_codebook_mismatch(agents):
    """case_091: H6 step 5. The preamble is the expected one and the frames do not decode under it."""
    point = agents.pep("a1")
    member = agents.release(point, DEFAULT)
    good = heartbeat.body(DEFAULT, _readings(DEFAULT, 5))
    cut = good[:-1] + bytes([good[-1] | 0x01]) if len(good) > 42 else good
    count_too_high = good[:38] + (99).to_bytes(4, "little") + good[42:]
    for body in (cut, count_too_high):
        assert heartbeat.check(DEFAULT, body) == "wire:codebook-mismatch"
    assert agents.controller.receive(agents.record(point, body=count_too_high)) == "wire:codebook-mismatch"
    assert agents.controller.receive(agents.record(point)) is None and member.findings == {}


def test_a_body_holds_the_last_64_decisions_within_the_record_bound(agents):
    """H5: the oldest are dropped first. A reading no rule routes is carried as the band of no route."""
    point = agents.pep("a1")
    agents.release(point, DEFAULT)
    readings = _readings(DEFAULT, 80) + [{"tool": "no such tool"}]
    _decide(point, readings)
    record = state_record.read(agents.record(point), point.key.public_raw)
    assert len(record.body) <= state_record.MAX_BODY
    routes = heartbeat.decode(DEFAULT, record.body)
    assert len(routes) == 64 and routes == heartbeat.decode(DEFAULT, heartbeat.body(DEFAULT, readings[-64:]))


def test_a_pep_with_no_policy_core_sends_an_empty_body(tmp_path):
    """H5: a host release has no flow text, so its records carry a body of length 0."""
    point = _dist.HostPep(tmp_path / "host")
    point.commit(_dist.image(5))
    point.pep.decide(lambda: True, {"x": 6})
    assert state_record.read(point.pep.record("beat"), point.key.public_raw).body == b""
