# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The widening rule (spec-policy-distribution.md, section 9.4, V12 and RB3): the comparators of W1, the
statement of W4, and the PEP machine refusing a release that allows more without the owner's signed statement.
Each test names the conformance case of section 20 it covers.

No target that can decide is built yet (the agent home is PR 9), so the deciding half runs on the `agent` row
of section 3 put in the kind table for the test alone, over a model adapter that only records what it is
given. Everything the PEP machine does with it is the real machine."""
import itertools
import random
from dataclasses import dataclass

import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.agent import profile  # noqa: E402
from prismpath.agent.policy import Policy, starter_path  # noqa: E402
from prismpath.distribution import kinds, state_record, widening  # noqa: E402
from prismpath.distribution.adapters import CANNOT_DECIDE, LARGER, NOT_LARGER, Adapter  # noqa: E402
from prismpath.tests import _dist  # noqa: E402
from prismpath.tests._dist import STREAM, seal  # noqa: E402

H = canon.sha256_hex
OLD, NEW, NEWER = _dist.image(5), _dist.image(7), _dist.image(9)
STARTERS = {name: starter_path(name).read_bytes().rstrip(b"\n") for name in ("strict", "default", "review", "session")}


def _read(point, signed):
    return state_record.read(signed, point.key.public_raw)


def _hosts(*names) -> bytes:
    return canon.canon2_bytes(sorted(names))


def _zones(*names) -> bytes:
    return canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-zones/1",
                               "protected": sorted(names)})


# ------------------------------------------------------------------ W1: the comparators

def test_the_policy_comparator_finds_a_reading_that_moves_up_and_only_then():
    """W1 for policy.core. The strict starter refuses what the default asks the person about, so the default is
    larger than the strict and not the other way round. Two policies whose fields differ are larger, the same
    policy is not, and an image that does not load cannot be decided."""
    assert widening.compare_policies(STARTERS["strict"], STARTERS["default"]) == LARGER
    assert widening.compare_policies(STARTERS["default"], STARTERS["strict"]) == NOT_LARGER
    assert widening.compare_policies(STARTERS["default"], STARTERS["session"]) == LARGER       # other fields
    assert widening.compare_policies(STARTERS["review"], STARTERS["review"]) == NOT_LARGER
    assert widening.compare_policies(STARTERS["default"], b"not an image") == CANNOT_DECIDE


def test_the_walk_decides_each_reading_as_the_reference_does():
    """`profile.kind_of`, which the comparator walks with, gives every reading the kind `Policy.decide` gives
    it, on a sample of every class of every starter's domain."""
    rng = random.Random(9)
    for name in ("strict", "default", "review", "session"):
        policy = Policy(STARTERS[name])
        names, constant, groups = profile.domain_classes([policy.doc])
        combos = list(itertools.islice(itertools.product(*groups), 0, 200000, 997))
        for combo in rng.sample(combos, min(120, len(combos))):
            reading = dict(zip(names, (rng.choice(group) for group in combo)), **constant)
            assert profile.kind_of(policy, reading) == policy.decide(policy.reading_bytes(reading)).kind, reading


def test_the_comparators_of_the_lists():
    """W1 for egress.hosts (a host not in the active list), gateway.routes (any change) and agent.zones (a
    protected name gone, and no zone file protects nothing)."""
    assert widening.compare_hosts(_hosts("a.example"), _hosts("a.example", "b.example")) == LARGER
    assert widening.compare_hosts(_hosts("a.example", "b.example"), _hosts("a.example")) == NOT_LARGER
    assert widening.compare_hosts(_hosts("a.example"), b"{}") == CANNOT_DECIDE
    assert widening.compare_routes(b'{"routes":[]}', b'{"routes":[]}') == NOT_LARGER
    assert widening.compare_routes(b'{"routes":[]}', b'{"routes":[{}]}') == LARGER
    assert widening.compare_zones(_zones("a", "b"), _zones("a")) == LARGER
    assert widening.compare_zones(_zones("a"), _zones("a", "b")) == NOT_LARGER
    assert widening.compare_zones(_zones("a"), None) == LARGER
    assert widening.compare_zones(None, _zones("a")) == NOT_LARGER


def test_a_release_is_larger_when_one_artifact_is_and_than_no_policy():
    """W1 over a release: the most permissive artifact decides, a dropped zone file drops its names, the derived
    artifacts follow the policy, and any release is larger than no policy."""
    active = {"policy.core": STARTERS["default"], "egress.hosts": _hosts("a.example"), "agent.zones": _zones("a")}
    assert widening.compare_release(None, active) == LARGER
    assert widening.compare_release(active, dict(active)) == NOT_LARGER
    assert widening.compare_release(active, {**active, "policy.core": STARTERS["strict"]}) == NOT_LARGER
    assert widening.compare_release(active, {**active, "egress.hosts": _hosts("a.example", "b.example")}) == LARGER
    dropped = {name: body for name, body in active.items() if name != "agent.zones"}
    assert widening.compare_release(active, dropped) == LARGER
    assert widening.compare_release(active, {**active, "sandbox.profile": b"anything"}) == NOT_LARGER
    assert widening.compare_release(active, {**active, "net.dests": b"x"}) == LARGER      # nothing it replaces
    with pytest.raises(ValueError):
        widening.register_comparator("trust.revocation", widening.compare_routes)


def test_a_widening_statement_covers_a_pep_when_from_is_empty_or_holds_its_policy():
    """W4."""
    assert widening.covers(_dist.widening([]), None) and widening.covers(_dist.widening([]), H(OLD))
    assert widening.covers(_dist.widening([H(OLD)]), H(OLD)) and not widening.covers(_dist.widening([H(NEW)]), H(OLD))
    assert not widening.covers(_dist.widening([H(OLD)]), None) and not widening.covers(None, None)


# ------------------------------------------------------------------ W2, W3, W4 on targets that cannot decide

@pytest.fixture
def mesh(tmp_path):
    return _dist.MeshPep(tmp_path / "node")


@pytest.fixture
def host(tmp_path):
    return _dist.HostPep(tmp_path / "host")


def test_case_060_widens_false_replacing_the_active_hash_commits_on_its_signature(mesh):
    """case_060: W2. No statement is needed."""
    mesh.commit(OLD)
    record = _read(mesh, mesh.pep.stage(mesh.seal(NEW, seq=2, replaces=H(OLD)), NEW))
    assert record.event == "staged"
    assert _read(mesh, mesh.pep.commit(STREAM, 2, H(NEW))).event == "committed" and mesh.pep.active.seq == 2


def test_case_061_another_replaces_or_widens_true_without_a_statement_is_widening_unsigned(mesh):
    """case_061: W2, W3."""
    mesh.commit(OLD)
    for args in ({"replaces": H(NEWER)}, {"replaces": H(OLD), "widens": True}, {"replaces": ""}):
        record = _read(mesh, mesh.pep.stage(mesh.seal(NEW, seq=2, **args), NEW))
        assert record.cause == "dist:widening-unsigned", args
    assert mesh.pep.staged is None and mesh.pep.active.seq == 1


def test_case_062_a_statement_covers_when_from_holds_the_active_hash_or_is_empty(tmp_path):
    """case_062: W4, W5, on a host and on a mesh node."""
    for make in (_dist.HostPep, _dist.MeshPep):
        for seq, froms, cause in ((2, [H(OLD)], None), (3, [], None), (4, [H(NEWER)], "dist:widening-unsigned")):
            point = make(tmp_path / f"{make.__name__}{seq}")
            point.commit(OLD)
            args = {"replaces": H(OLD), "widens": True}
            point.widen(NEW, seq, froms, **args)
            record = _read(point, point.pep.stage(point.seal(NEW, seq=seq, **args), NEW))
            assert record.cause == cause, (make.__name__, froms)
            if cause is None:
                assert _read(point, point.pep.commit(STREAM, seq, H(NEW))).event == "committed"


def test_case_063_a_first_install_needs_a_statement(tmp_path):
    """case_063: W2, W3. Going from no policy to any policy is larger."""
    for make in (_dist.HostPep, _dist.MeshPep):
        point = make(tmp_path / make.__name__)
        assert _read(point, point.pep.stage(point.seal(OLD), OLD)).cause == "dist:widening-unsigned"
        point.widen(OLD, 1, widens=True)
        assert _read(point, point.pep.stage(point.seal(OLD, widens=True), OLD)).event == "staged"
        assert _read(point, point.pep.commit(STREAM, 1, H(OLD))).event == "committed"


def test_a_statement_is_checked_again_at_commit_against_what_is_active_then(host):
    """V12 at commit: a release staged on its replaces claim is refused at commit when the active release has
    changed under it since, here by a rollback."""
    host.commit(OLD)
    host.commit(NEW, seq=2)
    host.pep.stage(host.seal(NEWER, seq=3), NEWER)                   # replaces NEW, which is active
    host.pep.active = host.pep.previous                              # as a rollback would leave it
    assert _read(host, host.pep.commit(STREAM, 3, H(NEWER))).cause == "dist:widening-unsigned"


def test_case_109_a_held_node_keeps_every_rule(tmp_path):
    """case_109: X8. A mesh node on hold past expiry is sent a release below its floor, an expired one and a
    larger one without a statement, refused with dist:seq-replay, dist:expired and dist:widening-unsigned, and
    when its floor is then lost it locks with dist:floor-lost."""
    point = _dist.MeshPep(tmp_path / "node", expiry_response="hold")
    point.commit(OLD, seq=2, expires=_dist.NOW + 100)
    point.clock.now = _dist.NOW + 100
    point.pep.tick()
    assert point.pep.held
    later = {"not_before": _dist.NOW + 100, "expires": _dist.NOW + 1000}
    assert _read(point, point.pep.stage(point.seal(NEW, seq=1, **later), NEW)).cause == "dist:seq-replay"
    expired = point.seal(NEW, seq=3, expires=_dist.NOW + 50)
    assert _read(point, point.pep.stage(expired, NEW)).cause == "dist:expired"
    larger = point.seal(NEW, seq=3, replaces=H(NEWER), **later)
    assert _read(point, point.pep.stage(larger, NEW)).cause == "dist:widening-unsigned"
    assert point.pep.held and point.pep.active.seq == 2
    import os
    os.remove(point.pep.store.path("floor.json"))
    pep = point.open()
    assert pep.state() == "locked" and pep.refusal() == "dist:floor-lost"
    assert _read(point, pep.stage(point.seal(NEW, seq=4, replaces=H(OLD), **later), NEW)).cause == "dist:floor-lost"


def test_a_rollback_to_the_same_release_is_never_a_widening(host):
    """RB3: a kept release identical to the active one rolls back with no statement, even where nothing can be
    decided. A renewal keeps the same release id."""
    host.commit(OLD)
    host.commit(OLD, seq=2, expires=_dist.EXPIRES + 10)
    assert host.pep.previous.release == host.pep.active.release
    assert _read(host, host.pep.rollback()).event == "rolled-back" and host.pep.active.seq == 1


# ------------------------------------------------------------------ W1, W6 and RB3 where the PEP can decide

class ModelAgent(Adapter):
    """Records the release it is told to run. The agent home itself is PR 9."""
    kind = "agent"

    def __init__(self):
        self.running = None

    def activate(self, release) -> None:
        self.running = release.policy_sha256

    def deactivate(self, cause: str) -> None:
        self.running = None


@dataclass
class AgentPep(_dist.Point):
    kind: str = "agent"
    artifact: str = "policy.core"

    def adapter(self):
        return ModelAgent()


@pytest.fixture
def agent(tmp_path, monkeypatch):
    monkeypatch.setitem(kinds.TARGETS, "agent", kinds.Target(needs=frozenset({"policy.core"}), decides=True))
    return AgentPep(tmp_path / "agent")


def test_a_pep_that_can_decide_compares_and_does_not_trust_widens(agent):
    """W1, W3, W6. A narrower policy commits on its signature whatever `replaces` says, a larger one needs the
    statement and widens true, and a larger one that says it does not widen is refused even with a statement."""
    agent.commit(STARTERS["default"])                                 # a first install, widens true, statement
    strict = STARTERS["strict"]
    record = _read(agent, agent.pep.stage(agent.seal(strict, seq=2, replaces="ab" * 32), strict))
    assert record.event == "staged"
    assert _read(agent, agent.pep.commit(STREAM, 2, H(strict))).event == "committed"
    default = STARTERS["default"]
    assert _read(agent, agent.pep.stage(agent.seal(default, seq=3, widens=True), default)).cause == \
        "dist:widening-unsigned"
    agent.widen(default, 4, [H(strict)])
    assert _read(agent, agent.pep.stage(agent.seal(default, seq=4), default)).cause == "dist:widening-unsigned"
    agent.widen(default, 5, [H(strict)], widens=True)
    assert _read(agent, agent.pep.stage(agent.seal(default, seq=5, widens=True), default)).event == "staged"
    assert _read(agent, agent.pep.commit(STREAM, 5, H(default))).event == "committed"
    assert agent.pep.adapter.running == H(default)


def _release(point, body, seq, *, widens=False, froms=None):
    """Stage and commit `body` at `seq` on `point`, with a widening statement of `froms` when it is given."""
    if froms is not None:
        point.widen(body, seq, froms, widens=widens)
    point.pep.stage(point.seal(body, seq=seq, widens=widens), body)
    assert _read(point, point.pep.commit(STREAM, seq, H(body))).event == "committed"


def test_case_055_a_rollback_to_a_larger_release_needs_a_covering_statement_where_the_pep_decides(agent, tmp_path):
    """case_055: RB3, the half for a PEP that can decide. Going back from strict to the default, which allows
    more, is refused with dist:widening-unsigned when the default holds no statement covering strict, and rolls
    back when it holds one. A rollback to a release that is not larger needs none. The half for a PEP that
    cannot decide is the rollback test in test_distribution_pep.py."""
    default, strict = STARTERS["default"], STARTERS["strict"]
    review = STARTERS["review"]
    agent.commit(review)
    _release(agent, default, 2, widens=True, froms=[H(review)])     # it covers review, not strict
    _release(agent, strict, 3)
    assert _read(agent, agent.pep.rollback()).cause == "dist:widening-unsigned" and agent.pep.active.seq == 3

    covered = AgentPep(tmp_path / "covered")
    covered.commit(strict)
    _release(covered, default, 2, widens=True, froms=[H(strict)])
    _release(covered, strict, 3)
    assert _read(covered, covered.pep.rollback()).event == "rolled-back" and covered.pep.active.seq == 2

    narrower = AgentPep(tmp_path / "narrower")
    narrower.commit(default)
    _release(narrower, strict, 2)                                     # narrower, so on its signature alone
    _release(narrower, default, 3, widens=True, froms=[H(strict)])
    assert "trust.widening" not in narrower.pep.previous.bodies
    assert _read(narrower, narrower.pep.rollback()).event == "rolled-back" and narrower.pep.active.seq == 2
