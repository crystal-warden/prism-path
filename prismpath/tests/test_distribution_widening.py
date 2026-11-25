# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The widening rule (spec-policy-distribution.md, section 9.4, V12, W1 to W7 and RB3): the comparators of
W1, the statement of W4, the PEP machine refusing a release that allows more without the owner's signed
statement, and the controller and the sealing tool holding `widens` to what they hold (W7). Each test names the
conformance case of section 20 it covers.

The deciding half runs on the `agent` row of the kind table over `_dist.ModelAgent`, which holds the committed
release in memory as the mesh model holds its table. Its policies are small ones written here, so the
comparator walks their whole domain at once. The comparison of the shipped starters, which takes seconds a
pair, is the checkpoint test at the end, with a seeded sample of its readings on every push."""
import itertools
import random

import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.agent import profile  # noqa: E402
from prismpath.agent.policy import Policy, starter_path  # noqa: E402
from prismpath.distribution import kinds, state_record, widening  # noqa: E402
from prismpath.distribution.adapters import CANNOT_DECIDE, LARGER, NOT_LARGER  # noqa: E402
from prismpath.distribution.kinds import Refused  # noqa: E402
from prismpath.kernel.policy_source import compile_source  # noqa: E402
from prismpath.tests import _dist  # noqa: E402
from prismpath.tests._dist import STREAM, seal  # noqa: E402

H = canon.sha256_hex
OLD, NEW, NEWER = _dist.image(5), _dist.image(7), _dist.image(9)
STARTERS = {name: starter_path(name).read_bytes().rstrip(b"\n") for name in ("strict", "default", "review", "session")}


def _policy(*rules: str) -> bytes:
    """A small policy over `tool` and `path_scope` that reads a file in the workspace and then `rules`."""
    return compile_source("---\nname: small\nstart: core_decision\nfield.tool: category\nfield.path_scope: category\n"
                          "---\n## core_decision\n"
                          '-> refuse agent:unclassifiable: when tool == "unknown" or path_scope == "unknown"\n'
                          '-> allow: when tool == "read_file" and path_scope == "workspace"\n'
                          + "".join(rule + "\n" for rule in rules))


NARROW = _policy()                                                   # a write is refused, no rule routes it
ASKS = _policy('-> escalate agent:change-asked: when tool == "write_file" and path_scope == "workspace"')
WIDER = _policy('-> allow: when tool == "write_file" and path_scope == "workspace"')
OTHER_FIELDS = compile_source("---\nname: small\nstart: core_decision\nfield.tool: category\n---\n## core_decision\n"
                              '-> allow: when tool == "read_file"\n')


def _read(point, signed):
    return state_record.read(signed, point.key.public_raw)


def _hosts(*names) -> bytes:
    return canon.canon2_bytes(sorted(names))


def _zones(*names) -> bytes:
    return canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-zones/1",
                               "protected": sorted(names)})


# ------------------------------------------------------------------ W1: the comparators

def test_the_policy_comparator_finds_a_reading_that_moves_up_and_only_then():
    """W1 for policy.core. Refuse to escalate and escalate to allow are larger, the reverse is not, two policies
    whose fields differ are larger, the same policy is not, and an image that does not load cannot be decided."""
    assert widening.compare_policies(NARROW, ASKS) == LARGER and widening.compare_policies(ASKS, WIDER) == LARGER
    assert widening.compare_policies(WIDER, ASKS) == NOT_LARGER and widening.compare_policies(ASKS, NARROW) == NOT_LARGER
    assert widening.compare_policies(NARROW, OTHER_FIELDS) == LARGER
    assert widening.compare_policies(WIDER, WIDER) == NOT_LARGER
    assert widening.compare_policies(NARROW, b"not an image") == CANNOT_DECIDE


def _sample(policy, rng, count):
    names, constant, groups = profile.domain_classes([policy.doc])
    combos = list(itertools.islice(itertools.product(*groups), 0, 200000, 997))
    return [dict(zip(names, (rng.choice(group) for group in combo)), **constant)
            for combo in rng.sample(combos, min(count, len(combos)))]


def test_the_walk_decides_each_reading_as_the_reference_does():
    """`profile.kind_of`, which the comparator walks with, gives a seeded sample of every starter's readings the
    kind `Policy.decide` gives them."""
    rng = random.Random(9)
    for name, image in STARTERS.items():
        policy = Policy(image)
        for reading in _sample(policy, rng, 40):
            assert profile.kind_of(policy, reading) == policy.decide(policy.reading_bytes(reading)).kind, reading


@pytest.mark.checkpoint
def test_the_starters_compare_as_their_rules_say():
    """W1 over the shipped starters, every reading of their domain, the combinations the classifier never gives
    included: the default asks the person about what the strict refuses, so it is larger, and the strict is not
    larger than the default, since where it differs it refuses more. The review asks about a change the strict
    allows, and the session reads fields the others do not. Every reading is decided as the reference decides
    it."""
    assert widening.compare_policies(STARTERS["strict"], STARTERS["default"]) == LARGER
    assert widening.compare_policies(STARTERS["default"], STARTERS["strict"]) == NOT_LARGER
    assert widening.compare_policies(STARTERS["review"], STARTERS["strict"]) == LARGER
    assert widening.compare_policies(STARTERS["default"], STARTERS["session"]) == LARGER
    for image in STARTERS.values():
        policy = Policy(image)
        names, constant, groups = profile.domain_classes([policy.doc])
        for combo in itertools.islice(itertools.product(*groups), 0, None, 211):
            reading = dict(zip(names, (group[0] for group in combo)), **constant)
            assert profile.kind_of(policy, reading) == policy.decide(policy.reading_bytes(reading)).kind


def test_the_comparators_of_the_lists_and_the_tables():
    """W1 for egress.hosts (a host not in the active list), gateway.routes (any change), agent.zones (a protected
    name gone, and no zone file protects nothing) and policy.ppt (any change of the image)."""
    assert widening.compare_hosts(_hosts("a.example"), _hosts("a.example", "b.example")) == LARGER
    assert widening.compare_hosts(_hosts("a.example", "b.example"), _hosts("a.example")) == NOT_LARGER
    assert widening.compare_hosts(_hosts("a.example"), b"{}") == CANNOT_DECIDE
    assert widening.compare_routes(b'{"routes":[]}', b'{"routes":[]}') == NOT_LARGER
    assert widening.compare_routes(b'{"routes":[]}', b'{"routes":[{}]}') == LARGER
    assert widening.compare_zones(_zones("a", "b"), _zones("a")) == LARGER
    assert widening.compare_zones(_zones("a"), _zones("a", "b")) == NOT_LARGER
    assert widening.compare_zones(_zones("a"), None) == LARGER
    assert widening.compare_zones(None, _zones("a")) == NOT_LARGER
    assert widening.compare_ppt(OLD, OLD) == NOT_LARGER and widening.compare_ppt(NEW, OLD) == LARGER


def test_a_wide_integer_field_is_walked_by_its_boundary_values():
    """W1 over a field whose range is too wide to list: its ends and each constant an atom compares with, with
    their neighbours, stand for every value, so moving a threshold by one is found and the same policy is not."""
    def threshold(n):
        return compile_source("---\nname: wide\nstart: core_decision\nfield.n: int min=0 max=1000\n---\n"
                              f"## core_decision\n-> allow: when n > {n}\n")
    assert widening.compare_policies(threshold(500), threshold(499)) == LARGER
    assert widening.compare_policies(threshold(500), threshold(501)) == NOT_LARGER
    with pytest.raises(profile.ProfileError):
        profile.domain_classes([Policy(threshold(500)).doc])             # the profile compiler never guesses


def test_a_release_is_larger_when_one_artifact_is_and_than_no_policy():
    """W1 over a release: the most permissive artifact decides, a dropped zone file drops its names, the derived
    artifacts follow the policy, and any release is larger than no policy."""
    active = {"policy.core": WIDER, "egress.hosts": _hosts("a.example"), "agent.zones": _zones("a")}
    assert widening.compare_release(None, active) == LARGER
    assert widening.compare_release(active, dict(active)) == NOT_LARGER
    assert widening.compare_release(active, {**active, "policy.core": NARROW}) == NOT_LARGER
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


def test_case_135_a_widening_statement_holds_at_most_64_hashes(tmp_path):
    """case_135: W4. On a host PEP a statement from 64 hashes is staged and one from 65 is dist:too-large."""
    hashes = [H(bytes([n])) for n in range(65)]
    for count, event, cause in ((64, "staged", None), (65, "refused", "dist:too-large")):
        point = _dist.HostPep(tmp_path / f"host{count}")
        statement = _dist.widening(hashes[:count])
        record = _read(point, point.pep.stage(seal("trust.widening", statement, widens=True,
                                                   release=_dist.env.release_id([("policy.ppt", H(OLD))]),
                                                   policy_sha256=H(OLD)), statement))
        assert (record.event, record.cause) == (event, cause)
    with pytest.raises(Refused) as refused:
        kinds.read_widening(_dist.widening(hashes))
    assert refused.value.cause == "dist:too-large"


# ------------------------------------------------------------------ W2, W3, W4 on targets that cannot decide

@pytest.fixture
def mesh(tmp_path):
    return _dist.MeshPep(tmp_path / "node")


@pytest.fixture
def host(tmp_path):
    return _dist.HostPep(tmp_path / "host")


def test_case_060_a_renewal_commits_on_its_signature(mesh):
    """case_060: W2, the mesh half. The table active again at a higher seq, with `widens` false and `replaces` the
    active hash, needs no statement. The cFS half, a table taken on the signer's word, is in
    integrations/cfs/tests/test_cfs_dist.py."""
    mesh.commit(OLD)
    record = _read(mesh, mesh.pep.stage(mesh.seal(OLD, seq=2, replaces=H(OLD), expires=_dist.EXPIRES + 10), OLD))
    assert record.event == "staged"
    assert _read(mesh, mesh.pep.commit(STREAM, 2, H(OLD))).event == "committed" and mesh.pep.active.seq == 2


def test_case_061_another_replaces_or_widens_true_without_a_statement_is_widening_unsigned(mesh):
    """case_061: W2, W3."""
    mesh.commit(OLD)
    for args in ({"replaces": H(NEWER)}, {"replaces": H(OLD), "widens": True}, {"replaces": ""},
                 {"replaces": H(OLD)}):                               # the last another table, said not to widen
        record = _read(mesh, mesh.pep.stage(mesh.seal(NEW, seq=2, **args), NEW))
        assert record.cause == "dist:widening-unsigned", args
    mesh.widen(NEW, 3, [], replaces=H(OLD))                           # W6: the signer's word is wrong
    assert _read(mesh, mesh.pep.stage(mesh.seal(NEW, seq=3, replaces=H(OLD)), NEW)).cause == "dist:widening-unsigned"
    assert mesh.pep.active.seq == 1


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
    host.widen(NEWER, 3, [H(NEW)], widens=True)                       # it covers NEW alone
    host.pep.stage(host.seal(NEWER, seq=3, widens=True), NEWER)      # replaces NEW, which is active
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

@pytest.fixture
def agent(tmp_path):
    return _dist.AgentPep(tmp_path / "agent")


def _release(point, body, seq, *, widens=False, froms=None, hosts=None):
    """Stage and commit `body` at `seq`, with a widening statement of `froms` when it is given."""
    if froms is not None:
        point.widen(body, seq, froms, widens=widens, hosts=hosts)
    point.stage(body, seq, widens=widens, hosts=hosts)
    assert _read(point, point.pep.commit(STREAM, seq, H(body))).event == "committed"


def test_case_056_a_policy_that_allows_one_more_reading_with_widens_false_is_refused(agent):
    """case_056: W1, W3, W6, V12. An agent PEP finds for itself that the release allows a write it refused, and
    with `widens` false and no statement it is dist:widening-unsigned."""
    agent.commit(NARROW)
    assert _read(agent, agent.stage(WIDER, 2)).cause == "dist:widening-unsigned"
    assert agent.pep.active.seq == 1


def test_case_057_a_policy_that_allows_less_commits_on_its_signature(agent):
    """case_057: W1. The PEP computes the answer itself, so a `replaces` that is not its active hash changes
    nothing."""
    agent.commit(WIDER)
    assert _read(agent, agent.stage(NARROW, 2, replaces="ab" * 32)).event == "staged"
    assert _read(agent, agent.pep.commit(STREAM, 2, H(NARROW))).event == "committed"
    assert agent.pep.adapter.running.policy_sha256 == H(NARROW)


def test_case_058_a_reading_moved_from_refuse_to_escalate_is_larger(agent):
    """case_058: W1."""
    agent.commit(NARROW)
    assert _read(agent, agent.stage(ASKS, 2)).cause == "dist:widening-unsigned"


def test_case_064_a_statement_does_not_save_a_larger_release_that_says_it_does_not_widen(agent):
    """case_064: W6. With a covering statement staged, the PEP computes larger and `widens` is false."""
    agent.commit(NARROW)
    agent.widen(WIDER, 2, [H(NARROW)])
    assert _read(agent, agent.stage(WIDER, 2)).cause == "dist:widening-unsigned"
    agent.widen(WIDER, 3, [H(NARROW)], widens=True)
    assert _read(agent, agent.stage(WIDER, 3, widens=True)).event == "staged"
    assert _read(agent, agent.pep.commit(STREAM, 3, H(WIDER))).event == "committed"


def test_case_059_a_host_list_with_one_more_host_is_larger_on_an_agent_pep(agent):
    """case_059: W1, the agent half. The gateway half, a changed route table, is in test_distribution_gateway.py."""
    agent.commit(NARROW)
    more = _hosts("api.example.com", "other.example.com")
    assert _read(agent, agent.stage(NARROW, 2, hosts=more)).cause == "dist:widening-unsigned"
    fewer = _hosts()
    assert _read(agent, agent.stage(NARROW, 3, hosts=fewer)).event == "staged"


def test_case_055_a_rollback_to_a_larger_release_needs_a_covering_statement_where_the_pep_decides(agent, tmp_path):
    """case_055: RB3, the half for a PEP that can decide. Going back from NARROW to WIDER is refused with
    dist:widening-unsigned when WIDER holds no statement covering NARROW, and rolls back when it holds one. A
    rollback to a release that is not larger needs none. The half for a PEP that cannot decide is the rollback
    test in test_distribution_pep.py."""
    agent.commit(ASKS)
    _release(agent, WIDER, 2, widens=True, froms=[H(ASKS)])          # it covers ASKS, not NARROW
    _release(agent, NARROW, 3)
    assert _read(agent, agent.pep.rollback()).cause == "dist:widening-unsigned" and agent.pep.active.seq == 3

    covered = _dist.AgentPep(tmp_path / "covered")
    covered.commit(NARROW)
    _release(covered, WIDER, 2, widens=True, froms=[H(NARROW)])
    _release(covered, NARROW, 3)
    assert _read(covered, covered.pep.rollback()).event == "rolled-back" and covered.pep.active.seq == 2

    narrower = _dist.AgentPep(tmp_path / "narrower")
    narrower.commit(WIDER)
    _release(narrower, NARROW, 2)                                     # narrower, so on its signature alone
    _release(narrower, WIDER, 3, widens=True, froms=[H(NARROW)])
    assert "trust.widening" not in narrower.pep.previous.bodies
    assert _read(narrower, narrower.pep.rollback()).event == "rolled-back" and narrower.pep.active.seq == 2


def test_the_agent_row_needs_its_host_list_and_reads_a_declared_zone_file(agent):
    """Section 3: an agent release needs `policy.core` and `egress.hosts` (C2), takes `agent.zones` when the owner
    declares zones, and refuses a zone file that is not of its form."""
    agent.widen(NARROW, 1, widens=True)
    agent.pep.stage(agent.seal(NARROW, widens=True), NARROW)
    assert _read(agent, agent.pep.commit(STREAM, 1, H(NARROW))).cause == "dist:incomplete"
    bad = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-zones/1",
                              "protected": ["b", "a"]})
    release = agent.release_of(NARROW)
    zone = seal("agent.zones", bad, release=release, policy_sha256=H(NARROW), targets=("agent",), widens=True)
    assert _read(agent, agent.pep.stage(zone, bad)).cause == "dist:bad-format"
    assert kinds.read_zones(_zones("a", "b"))["protected"] == ["a", "b"]


# ------------------------------------------------------------------ C2, E10: a release commits whole

SPIRAL = b"a spiral sidecar the transport withheld"


def _with_spiral(point, body, seq, **args):
    """Stage a `policy.ppt` release of `body` at `seq` whose signed release id also names a `policy.spiral` that
    is never staged, with the widening statement it needs, the table declaring no packing."""
    release = _dist.env.release_id([("policy.ppt", H(body)), ("policy.spiral", H(SPIRAL))])
    args = {"release": release, "widens": True, **args}
    point.widen(body, seq, [], **args)
    return _read(point, point.pep.stage(point.seal(body, seq=seq, **args), body))


def _agent_release(point, body, seq, hosts, zones, *, replaces, withheld=()):
    """Stage an agent release of `body`, `hosts` and `zones`, with its widening statement, leaving out the
    envelopes of `withheld`. Returns the last stage-ack."""
    arts = {"policy.core": body, "egress.hosts": hosts, "agent.zones": zones}
    release = _dist.env.release_id([(name, H(data)) for name, data in arts.items()])
    common = dict(seq=seq, release=release, policy_sha256=H(body), targets=("agent",), widens=True, replaces=replaces)
    statement = _dist.widening([])
    ack = point.pep.stage(seal("trust.widening", statement, **common), statement)
    for name, data in arts.items():
        if name not in withheld:
            ack = point.pep.stage(seal(name, data, **common), data)
    return _read(point, ack)


def test_case_137_a_first_install_without_an_artifact_its_release_id_names_is_incomplete(tmp_path):
    """case_137: C2, E10. A host release whose table declares no packing but whose signed release id names a
    `policy.spiral`, the same on a mesh node, and an agent release whose `agent.zones` envelope is withheld each
    stage what they carry and are refused at commit, with nothing active."""
    for make in (_dist.HostPep, _dist.MeshPep):
        point = make(tmp_path / make.__name__)
        assert _with_spiral(point, OLD, 1).event == "staged"
        assert _read(point, point.pep.commit(STREAM, 1, H(OLD))).cause == "dist:incomplete", make.__name__
        assert point.pep.active is None
    agent = _dist.AgentPep(tmp_path / "agent")
    assert _agent_release(agent, NARROW, 1, _dist.HOSTS, _zones("billing"), replaces="",
                          withheld=("agent.zones",)).event == "staged"
    assert _read(agent, agent.pep.commit(STREAM, 1, H(NARROW))).cause == "dist:incomplete"
    assert agent.pep.active is None and agent.pep.adapter.running is None


def test_case_138_an_update_without_an_artifact_its_release_id_names_is_incomplete(tmp_path):
    """case_138: C2, E10. After a first install, an update whose release id names a withheld `policy.spiral` on a
    host and a mesh node, and an agent update that keeps the protected zones and adds a host with its
    `agent.zones` envelope withheld, are refused at commit and the old release stays active. The same agent
    update with every envelope commits."""
    for make in (_dist.HostPep, _dist.MeshPep):
        point = make(tmp_path / make.__name__)
        point.commit(OLD)
        assert _with_spiral(point, NEW, 2, replaces=H(OLD)).event == "staged"
        assert _read(point, point.pep.commit(STREAM, 2, H(NEW))).cause == "dist:incomplete", make.__name__
        assert point.pep.active.seq == 1
    zones, more = _zones("billing", "payroll"), _hosts("api.example.com", "b.example.com")
    agent = _dist.AgentPep(tmp_path / "agent")
    _agent_release(agent, NARROW, 1, _dist.HOSTS, zones, replaces="")
    assert _read(agent, agent.pep.commit(STREAM, 1, H(NARROW))).event == "committed"
    assert "agent.zones" in agent.pep.active.bodies
    assert _agent_release(agent, NARROW, 2, more, zones, replaces=H(NARROW), withheld=("agent.zones",)).event == "staged"
    assert _read(agent, agent.pep.commit(STREAM, 2, H(NARROW))).cause == "dist:incomplete"
    assert agent.pep.active.seq == 1 and agent.pep.adapter.running.seq == 1
    assert _agent_release(agent, NARROW, 3, more, zones, replaces=H(NARROW)).event == "staged"
    assert _read(agent, agent.pep.commit(STREAM, 3, H(NARROW))).event == "committed"
    assert agent.pep.active.bodies["agent.zones"] == zones


def test_case_139_a_first_install_that_says_it_does_not_widen_is_refused_even_with_a_statement(tmp_path):
    """case_139: W2, W6. Going from no policy to one is larger on every kind, so on a host and a mesh node a
    first install with `widens` false is dist:widening-unsigned at staging, with a statement whose `from` is empty
    staged first, and nothing goes active."""
    for make in (_dist.HostPep, _dist.MeshPep):
        point = make(tmp_path / make.__name__)
        assert _read(point, point.widen(OLD, 1, [], widens=False)).event == "staged"
        record = _read(point, point.pep.stage(point.seal(OLD, widens=False), OLD))
        assert record.cause == "dist:widening-unsigned", make.__name__
        assert _read(point, point.pep.commit(STREAM, 1, H(OLD))).cause == "dist:incomplete"
        assert point.pep.active is None


def test_case_140_a_rollback_to_a_renewal_that_says_it_does_not_widen_is_refused_on_a_host_and_a_mesh_node(tmp_path):
    """case_140: RB3, W2, W6. The kept release renews table A with `widens` false and carries a statement whose
    `from` is empty. From table B a rollback to it is another table, so larger, and its signer said it does not
    widen: dist:widening-unsigned, and B stays active."""
    for make in (_dist.HostPep, _dist.MeshPep):
        point = make(tmp_path / make.__name__)
        point.commit(OLD, 1)
        point.widen(OLD, 2, [], replaces=H(OLD), widens=False)
        assert _read(point, point.pep.stage(point.seal(OLD, seq=2, widens=False), OLD)).event == "staged"
        assert _read(point, point.pep.commit(STREAM, 2, H(OLD))).event == "committed"
        point.commit(NEW, 3)
        assert point.pep.previous.seq == 2 and not point.pep.previous.widens
        assert "trust.widening" in point.pep.previous.bodies
        assert _read(point, point.pep.rollback()).cause == "dist:widening-unsigned", make.__name__
        assert point.pep.active.seq == 3 and point.pep.active.bodies["policy.ppt"] == NEW


# ------------------------------------------------------------------ 9.4: the reading domain

OUTSIDE = _policy('-> allow: when tool == "mcp__x"')


def test_case_141_a_policy_that_names_a_tool_outside_the_domain_is_refused(agent):
    """case_141: 9.4, V11. A rule that allows a tool the classifier does not produce names a resource nobody
    accounted for. The agent's policy loader refuses the image with policy:out-of-domain, and so does an agent
    PEP at V11, so the comparator never has to see it. A value outside the domain is refused for a bool and for
    an int named outside its range as well, and a policy naming only values inside the domain loads."""
    from prismpath.agent.policy import OutsideDomain
    with pytest.raises(OutsideDomain, match="policy:out-of-domain"):
        Policy(OUTSIDE)
    assert _read(agent, agent.stage(OUTSIDE, 1)).cause == "policy:out-of-domain"
    assert agent.pep.active is None
    assert profile.outside_domain(Policy(WIDER).doc) is None
    listed = {"fields": {"tool": "category"}, "rules": [{"target": "allow", "when": ["in", "tool", [["str", "git"], ["str", "mcp__y"]]]}]}
    assert "mcp__y" in profile.outside_domain(listed)
    counted = {"fields": {"n": "int min=0 max=9"}, "rules": [{"target": "allow", "when": ["cmp", "n", "==", ["num", 12]]}]}
    assert "12" in profile.outside_domain(counted)
    bounded = {"fields": {"n": "int min=0 max=9"}, "rules": [{"target": "allow", "when": ["cmp", "n", "<", ["num", 12]]}]}
    assert profile.outside_domain(bounded) is None
    free = {"fields": {"label": "category"}, "rules": [{"target": "allow", "when": ["cmp", "label", "==", ["str", "x"]]}]}
    assert profile.outside_domain(free) is None                       # a category the installer set no bounds for


NET = "field.tool: category\nfield.path_scope: category\nfield.net_dest: category\n"


def _net(*rules: str) -> bytes:
    return compile_source("---\nname: small\nstart: core_decision\n" + NET + "---\n## core_decision\n"
                          '-> allow: when tool == "read_file" and path_scope == "workspace"\n'
                          + "".join(rule + "\n" for rule in rules))


def test_case_142_only_allowing_more_on_a_combination_the_classifier_never_gives_is_larger(agent, tmp_path):
    """case_142: 9.4, W1, W6. A `net_dest` other than none comes only with a `connect`, so a `read_file` with one
    is a combination the classifier never gives. The walk covers it: a release that allows it is larger, and with
    `widens` false it is dist:widening-unsigned, while one that refuses there what the active one asks about is a
    tightening and commits on its signature. A policy whose rules name only values in the domain, the complement
    of the tools it knows, still refuses a reading whose tool is outside the domain, with policy:out-of-domain,
    before the policy runs."""
    base, unproduced = _net(), _net('-> allow: when tool == "read_file" and net_dest == "other"')
    assert widening.compare_policies(base, unproduced) == LARGER
    asks = _net('-> escalate agent:change-asked: when tool == "read_file" and net_dest == "other"')
    assert widening.compare_policies(asks, base) == NOT_LARGER
    agent.commit(base)
    assert _read(agent, agent.stage(unproduced, 2)).cause == "dist:widening-unsigned"
    other = _dist.AgentPep(tmp_path / "asks")
    other.commit(asks)
    assert _read(other, other.stage(base, 2)).event == "staged"
    assert _read(other, other.pep.commit(STREAM, 2, H(base))).event == "committed"
    known = " and ".join(f'tool != "{tool}"' for tool in profile.KNOWN_CATEGORIES["tool"])
    complement = Policy(compile_source("---\nname: small\nstart: core_decision\nfield.tool: category\n"
                                       "field.path_scope: category\n---\n## core_decision\n"
                                       f"-> allow: when {known}\n"))
    outside = complement.decide(complement.reading_bytes({"tool": "zzz", "path_scope": "none"}))
    assert (outside.kind, outside.cause) == ("refuse", "policy:out-of-domain") and not outside.runs
    inside = complement.decide(complement.reading_bytes({"tool": "read_file", "path_scope": "none"}))
    assert inside.cause != "policy:out-of-domain"
    scoped = complement.decide(complement.reading_bytes({"tool": "git", "path_scope": "elsewhere"}))
    assert scoped.cause == "policy:out-of-domain"


def test_case_143_a_renewal_whose_active_release_lapsed_before_its_commit_needs_a_statement(tmp_path):
    """case_143: C3, V12, W2. A renewal staged on a host and a mesh node with `widens` false and no statement
    stages against the active release, which then expires before the commit. The commit holds it to the widening
    rule again against what is active then, nothing, so it goes from no policy to one and is
    dist:widening-unsigned, nothing goes active, and the renewal stays staged."""
    for make in (_dist.HostPep, _dist.MeshPep):
        point = make(tmp_path / make.__name__)
        point.commit(OLD, 1, expires=_dist.NOW + 100)
        record = _read(point, point.pep.stage(point.seal(OLD, seq=2, widens=False), OLD))
        assert record.event == "staged", make.__name__
        point.clock.now = _dist.NOW + 100
        assert _read(point, point.pep.tick()).event == "lapsed"
        assert _read(point, point.pep.commit(STREAM, 2, H(OLD))).cause == "dist:widening-unsigned", make.__name__
        assert point.pep.active is None and point.pep.staged.seq == 2


# ------------------------------------------------------------------ W10, W11: the change statement

def test_case_294_a_table_carried_by_a_change_statement_commits_without_a_widening_statement(tmp_path):
    """case_294: W10, W11, W2. On a host and a mesh node with OLD active, NEW with `widens` false and `replaces` the
    active hash is refused alone, and staged and committed after a change statement from that hash. The PEP compares
    nothing new: the change statement stands in place of the widening statement."""
    for make in (_dist.HostPep, _dist.MeshPep):
        point = make(tmp_path / make.__name__)
        point.commit(OLD)
        release = point.seal(NEW, seq=2, replaces=H(OLD))
        assert _read(point, point.pep.stage(release, NEW)).cause == "dist:widening-unsigned"
        sealed, body = _dist.change_of(point, NEW, 2, replaces=H(OLD))
        assert _read(point, point.pep.stage(sealed, body)).event == "staged"
        assert _read(point, point.pep.stage(release, NEW)).event == "staged"
        assert _read(point, point.pep.commit(STREAM, 2, H(NEW))).event == "committed"
        assert point.pep.active.seq == 2


def test_case_295_a_change_statement_never_stands_for_a_widening(tmp_path, agent):
    """case_295: W10, W11, V5. On a host and a mesh node a change statement that says it widens is dist:bad-format,
    one on a first install and one from another hash are dist:widening-unsigned, and one after a widening statement
    of its release is dist:bad-format, each with nothing changed. An agent PEP, which decides for itself, does not
    take the kind at all."""
    other = H(b"another policy")
    for make in (_dist.HostPep, _dist.MeshPep):
        first = make(tmp_path / f"{make.__name__}-first")
        sealed, body = _dist.change_of(first, OLD, 1, replaces=other)
        assert _read(first, first.pep.stage(sealed, body)).cause == "dist:widening-unsigned"
        assert first.pep.active is None and first.pep.staged is None
        point = make(tmp_path / make.__name__)
        point.commit(OLD)
        for args, cause in (({"replaces": H(OLD), "widens": True}, "dist:bad-format"),
                            ({"replaces": other}, "dist:widening-unsigned")):
            sealed, body = _dist.change_of(point, NEW, 2, **args)
            assert _read(point, point.pep.stage(sealed, body)).cause == cause, (make.__name__, args)
        point.widen(NEW, 2, [H(OLD)], replaces=H(OLD))
        sealed, body = _dist.change_of(point, NEW, 2, replaces=H(OLD))
        assert _read(point, point.pep.stage(sealed, body)).cause == "dist:bad-format"
        assert point.pep.active.seq == 1
    sealed, body = _dist.change_of(agent, NARROW, 1, replaces=H(NARROW))
    assert _read(agent, agent.pep.stage(sealed, body)).cause == "dist:target-mismatch"
