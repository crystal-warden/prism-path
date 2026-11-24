# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The action floor and the receipts of policy distribution (spec-policy-distribution.md, section 21.2 and 21.6) in
the Python machine, on `agent`, `gateway`, `host` and `mesh`. The `cfs` halves are in
integrations/cfs/tests/test_cfs_dist.py. Each test names the conformance case of section 20 it covers."""
from dataclasses import dataclass

import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.distribution import floor, install, kinds, state_record  # noqa: E402
from prismpath.distribution.kinds import Refused  # noqa: E402
from prismpath.kernel import ppt_compile  # noqa: E402
from prismpath.kernel.policy_source import compile_source  # noqa: E402
from prismpath.tests import _dist  # noqa: E402
from prismpath.tests._dist import EXPIRES, GEN, NOT_BEFORE, NOW, STREAM, image  # noqa: E402

H = canon.sha256_hex
KEYS = ["N1", "N2", "N3"]
FLOOR, FALLBACK, CEILING = "install.floor", "install.fallback", "install.ceiling"
HOSTS = canon.canon2_bytes(["api.example.com"])
FIELDS = ("tool", "path_scope", "command_class", "path_control", "zone_reach", "zone_name")


def _read(point, signed):
    return state_record.read(signed, point.key.public_raw)


def core(*rules, fields=FIELDS) -> bytes:
    """A core policy of `rules` over the agent fields `fields`."""
    kinds_of = {"path_control": "bool"}
    head = "".join(f"field.{name}: {kinds_of.get(name, 'category')}\n" for name in fields)
    return compile_source("---\nname: floor\nstart: core_decision\n" + head + "---\n## core_decision\n"
                          + "".join(rule + "\n" for rule in rules))


# the release refuses everything but a read in the workspace
RELEASE = core('-> refuse agent:unclassifiable: when tool == "unknown" or path_scope == "unknown"',
               '-> allow: when tool == "read_file" and path_scope == "workspace"')
LIST = '-> allow: when tool == "list_dir" and path_scope == "workspace"'
NARROW = core(LIST)
ASK = {"reading": {"tool": "list_dir", "path_scope": "workspace", "command_class": "none", "path_control": False,
                   "zone_reach": "none", "zone_name": ""}}
READ = {"reading": {**ASK["reading"], "tool": "read_file"}}
OTHER = {"reading": {**ASK["reading"], "tool": "delete_path"}}


def _agent(tmp_path, name="agent", **settings):
    settings.setdefault("install_keys", KEYS)
    settings.setdefault("install_threshold", 2)
    return _dist.AgentPep(tmp_path / name, **settings)


def _set(point, kind, policy, seq=1, hosts=HOSTS, zones=None, **args):
    bodies = {"policy.core": policy, "egress.hosts": hosts}
    if zones is not None:
        bodies["agent.zones"] = zones
    args.setdefault("widens", kind != CEILING)
    return point.install_set(kind, bodies, seq, **args)


def _floor(point, policy=NARROW, seq=1, **args):
    return point.send(_set(point, FLOOR, policy, seq, **args))[-1]


def _zones(*names):
    return canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": kinds.ZONES_FORMAT,
                               "protected": sorted(names)})


def _lock(point):
    (point.state_dir / "dist" / "floor.json").write_bytes(b"not a floor")
    point.pep = point.open(provision=False)
    assert point.pep.state() == "locked"


def _decide(point, request=ASK):
    return point.pep.decide(lambda: "release", request=request)


# ------------------------------------------------------------------ a table kind with its layout (AF10)

LAYOUT = floor.layout_body([
    {"name": "cmd", "register": 0, "role": "command", "min": 0, "max": 255, "stale": 0},
    {"name": "p", "register": 1, "role": "parameter", "min": 0, "max": 100, "stale": 0},
    {"name": "w", "register": 2, "role": "independent", "min": 0, "max": 1, "stale": 5},
    {"name": "q", "register": 3, "role": "proposer", "min": 0, "max": 1, "stale": 0}])
OTHER_LAYOUT = floor.layout_body([{"name": "cmd", "register": 0, "role": "command", "min": 0, "max": 9, "stale": 0}])


def table(*conditions, nodes=None) -> bytes:
    """A table whose start node holds one edge per condition to a terminal node, over the registers cmd, p, w and q
    in that order."""
    img = ppt_compile.TableImage(max_steps=1)
    for index, name in enumerate(("cmd", "p", "w", "q")):
        img.fields[name] = index
    img.nodes = nodes(img) if nodes else [("p", [(1, cond, img.compile_condition("when " + cond)) for cond in conditions]),
                                         ("t", [])]
    img.start = 0
    return img.serialize()


def regs(cmd=0, p=0, w=0, q=0) -> bytes:
    import struct
    return struct.pack("<I", 0) + b"".join(struct.pack("<ii", 2, value) for value in (cmd, p, w, q))


GOOD_TABLE = table("cmd == 3 and p >= 2 and p <= 5")


class _Layout:
    def adapter(self):
        adapter = super().adapter()
        adapter.floor_layout = LAYOUT
        return adapter


@dataclass
class MeshFloor(_Layout, _dist.MeshPep):
    pass


@dataclass
class HostFloor(_Layout, _dist.HostPep):
    pass


def _table_point(cls, tmp_path, name, **settings):
    settings.setdefault("install_keys", KEYS)
    settings.setdefault("install_threshold", 2)
    return cls(tmp_path / name, **settings)


def _table_floor(point, body=GOOD_TABLE, seq=1, *, layout=LAYOUT, command=0, check=False, **args):
    args.setdefault("widens", True)
    meta = {**GEN.image_meta(body), "command": command}
    return point.install_set(FLOOR, {"policy.ppt": body}, seq, metas={"policy.ppt": meta}, layout=layout,
                             check=check, **args)


# ------------------------------------------------------------------ AF1, AF2: asked first, allow or escalate

def test_case_186_the_floor_allows_in_every_state(tmp_path):
    """case_186: AF1. A request the action floor allows is allowed with basis `floor` by a PEP whose active release
    refuses it, in `no-policy`, in `locked` and under the fallback policy. The held `cfs` half is in
    integrations/cfs/tests/test_cfs_dist.py."""
    point = _agent(tmp_path)
    assert _floor(point).event == "install-widened"
    assert _decide(point)["basis"] == "floor" and point.pep.state() == "no-policy"
    point.commit(RELEASE)
    assert floor.ask("agent", point.pep.active.bodies, ASK).outcome == "refuse"
    decided = _decide(point)
    assert (decided["decision"], decided["basis"], decided["cause"]) == ("allow", "floor", "dist:floor-allowed")
    under = _agent(tmp_path, "fallback")
    _floor(under)
    under.send(_set(under, FALLBACK, RELEASE))
    assert under.pep.fallback_decides() and _decide(under)["basis"] == "floor"
    assert _decide(under, READ)["basis"] == "fallback"
    _lock(under)
    assert _decide(under)["basis"] == "floor" and _decide(under, READ)["basis"] == "fallback"


def test_case_188_the_floor_allows_or_escalates_and_is_silent_otherwise(tmp_path):
    """case_188: AF2. A request the floor refuses and one it cannot read leave the release's own answer, and in
    `no-policy` with no fallback policy `dist:policy-lapsed`, the floor's refusal cause never reported. An
    escalation is escalated with the floor's own cause and basis `floor`. A `mesh` floor is silent for a request it
    does not allow. The escalation on a `cfs` PEP whose release allows it is in test_cfs_dist.py."""
    refusing = core(LIST, '-> refuse agent:network: when tool == "read_file"',
                    '-> escalate agent:change-asked: when tool == "delete_path" and path_scope == "workspace" '
                    'and not path_control')
    point = _agent(tmp_path)
    assert _floor(point, refusing, answer_rate={"allows": 1, "window": 60}).event == "install-widened"
    for request in (READ, {"reading": {"tool": "read_file"}}):
        decided = _decide(point, request)
        assert (decided["decision"], decided["cause"]) == (None, "dist:policy-lapsed") and "basis" not in decided
    point.commit(RELEASE)
    decided = _decide(point, READ)
    assert (decided["decision"], decided["basis"], decided["cause"]) == ("release", "release", None)
    assert _decide(point, {"reading": {"tool": "read_file"}})["basis"] == "release"
    escalated = _decide(point, OTHER)
    assert (escalated["decision"], escalated["basis"], escalated["cause"]) == (
        "escalate", "floor", "agent:change-asked")
    mesh = _table_point(MeshFloor, tmp_path, "mesh")
    assert mesh.send(_table_floor(mesh))[-1].event == "install-widened"
    assert mesh.pep.decide(lambda: "release", request={"regs": regs(cmd=4, p=3)})["cause"] == "dist:policy-lapsed"
    assert mesh.pep.decide(lambda: "release", request={"regs": regs(cmd=3, p=3)})["basis"] == "floor"


def test_case_189_nothing_but_the_engineer_changes_the_floor(tmp_path):
    """case_189: AF3. The floor allows the same request after its release expires, after a revocation of everything
    the authority signed, with its floor of section 6 lost, after every unsigned message type, after the install key
    that signed it is retired, and ten years past its `not_before`."""
    point = _agent(tmp_path)
    _floor(point)
    point.commit(RELEASE, expires=NOW + 100)

    def allows():
        assert _decide(point)["basis"] == "floor"
    point.clock.now = NOW + 100
    point.pep.tick()
    allows()
    point.revoke(1, keys=[_dist.key_id("A")], envelopes=sorted(point.pep.installed.statement_ids()),
                 policies=[point.pep.floor_set().policy_sha256])
    allows()
    point.pep.commit(STREAM, 9, "00" * 32)
    point.pep.abort(STREAM, 9, "00" * 32)
    point.pep.tick()
    allows()
    sealed, body = point.install_trust(1, ["N2", "N3"], threshold=2, signers=["N1", "N2"])
    assert _read(point, point.pep.stage(sealed, body)).event == "install-applied"
    assert _dist.key_id("N1") in point.pep.installed.record.retired
    allows()
    point.pep = point.open()
    allows()
    _lock(point)
    allows()
    point.clock.now = NOT_BEFORE + 10 * 365 * 86400
    allows()


def test_case_197_a_floor_and_no_fallback_policy_lapse_to_no_policy(tmp_path):
    """case_197: FB1, X3. A PEP with an action floor and no fallback policy whose release expires goes to `no-policy`
    with `lapsed` and `dist:expired`, bit 4 clear, and every request the floor is silent on is `dist:policy-lapsed`."""
    point = _agent(tmp_path)
    _floor(point)
    point.commit(RELEASE, expires=NOW + 100)
    point.clock.now = NOW + 100
    record = _read(point, point.pep.tick())
    assert (record.event, record.cause, record.state, record.fallback) == ("lapsed", "dist:expired", "no-policy",
                                                                         False)
    assert _decide(point, READ)["cause"] == "dist:policy-lapsed" and _decide(point)["basis"] == "floor"


# ------------------------------------------------------------------ IS4, IS6, IS11, IS13 with an action floor

def test_case_166_an_install_threshold_of_1_takes_a_floor_by_provisioning_only(tmp_path):
    """case_166: IS4, IS2. On a PEP whose install threshold is 1 a well signed action floor and a well signed
    `install.trust` in a message are each `dist:target-mismatch` and change nothing, and the same floor brought by an
    install provisioning is then held."""
    point = _agent(tmp_path, install_threshold=1)
    pairs = _set(point, FLOOR, NARROW)
    before = point.pep.installed.record
    assert [one.cause for one in point.send(pairs)] == ["dist:target-mismatch", "dist:target-mismatch"]
    sealed, body = point.install_trust(1, ["N1", "N2"], threshold=1, signers=["N1"])
    assert _read(point, point.pep.stage(sealed, body)).cause == "dist:target-mismatch"
    assert point.pep.installed.record == before and point.pep.floor_set() is None
    records = [_read(point, one) for one in point.pep.provision_install(pairs)]
    assert records[-1].event == "install-widened" and point.pep.floor_set() is not None


def test_case_169_an_action_floor_is_taken_only_at_a_seq_above_the_held_one(tmp_path):
    """case_169: IS6. A PEP that holds a floor at `seq` 3 refuses one at 2 and another at 3 with `dist:seq-replay`,
    the same one again changes nothing, one at 5 is applied, one at 4 is then `dist:seq-replay`, and a fallback
    policy at 1 is applied, since each install kind keeps its own sequence."""
    point = _agent(tmp_path)
    same = _set(point, FLOOR, NARROW, 3)
    assert point.send(same)[-1].event == "install-widened"
    wider = core(LIST, '-> allow: when tool == "read_file" and path_scope == "workspace"')
    assert point.send(_set(point, FLOOR, wider, 2))[-1].cause == "dist:seq-replay"
    assert point.send(_set(point, FLOOR, wider, 3))[-1].cause == "dist:seq-replay"
    assert [one.event for one in point.send(same)] == ["beat", "beat"]
    assert point.send(_set(point, FLOOR, wider, 5))[-1].event == "install-widened"
    assert point.send(_set(point, FLOOR, NARROW, 4, widens=False))[-1].cause == "dist:seq-replay"
    assert point.send(_set(point, FALLBACK, RELEASE, 1))[-1].event == "install-widened"
    assert point.pep.floor_set().seq == 5 and point.pep.installed.fallback.seq == 1


def test_case_174_an_install_key_retired_later_does_not_remove_what_it_signed(tmp_path):
    """case_174: IS11, AF3. An `install.trust` signed by two old keys and a new one adds it, a floor signed with the
    new key follows, a second `install.trust` drops an old key, a floor signed by the dropped key and one other is
    `sig:revoked-key`, and a PEP that restarts holding a fallback policy the dropped key signed still holds it."""
    point = _agent(tmp_path)
    point.send(_set(point, FALLBACK, RELEASE, 1, signers=["N1", "N2"]))
    sealed, body = point.install_trust(1, ["N1", "N2", "N3", "N4"], threshold=2, signers=["N1", "N2", "N4"])
    assert _read(point, point.pep.stage(sealed, body)).event == "install-widened"
    assert point.send(_set(point, FLOOR, NARROW, 1, signers=["N4", "N3"]))[-1].event == "install-widened"
    sealed, body = point.install_trust(2, ["N2", "N3", "N4"], threshold=2, signers=["N2", "N3"])
    assert _read(point, point.pep.stage(sealed, body)).event == "install-applied"
    assert point.send(_set(point, FLOOR, NARROW, 2, signers=["N1", "N4"], widens=False))[-1].cause \
        == "sig:revoked-key"
    point.pep = point.open()
    assert point.pep.installed.fallback is not None and point.pep.floor_set().seq == 1


def test_case_177_the_ninth_retirement_forgets_the_first_id(tmp_path):
    """case_177: IS11. Nine install keys are retired one after another, and a floor signed by the first retired key
    and one current key is then `dist:unknown-key`, since the ninth retirement forgot the first id."""
    point = _agent(tmp_path, install_keys=["K0", "K1"], install_threshold=2)
    current = ["K0", "K1"]
    for index in range(9):
        new = f"K{index + 2}"
        sealed, body = point.install_trust(index + 1, [current[1], new], threshold=2,
                                           signers=[current[0], current[1], new])
        assert _read(point, point.pep.stage(sealed, body)).event == "install-widened"
        current = [current[1], new]
    record = point.pep.installed.record
    assert _dist.key_id("K0") not in record.retired and len(record.retired) == 8
    assert point.send(_set(point, FLOOR, NARROW, 1, signers=["K0", current[1]]))[-1].cause == "dist:unknown-key"
    assert point.pep.floor_set() is None


def test_case_178_the_empty_set_withdraws_a_floor_and_a_ceiling(tmp_path):
    """case_178: IS1, IS6, IS12. The empty set of the action floor at a higher `seq` withdraws the floor with event
    `install-applied`, the held floor sent again is `dist:seq-replay`, and the empty set of the ceiling withdraws it
    with event `install-widened`."""
    point = _agent(tmp_path)
    held = _set(point, FLOOR, NARROW, 1)
    point.send(held)
    assert point.send(_set(point, CEILING, core(LIST, '-> allow: when tool == "read_file"'), 1))[-1].event \
        == "install-applied"
    empty = point.send(point.install_set(FLOOR, {"none": b""}, 2))[-1]
    assert (empty.event, empty.cause) == ("install-applied", None) and point.pep.floor_set() is None
    assert point.send(held)[-1].cause == "dist:seq-replay"
    assert _decide(point)["cause"] == "dist:policy-lapsed"
    ceiling = point.send(point.install_set(CEILING, {"none": b""}, 2, widens=True))[-1]
    assert (ceiling.event, ceiling.cause) == ("install-widened", "dist:install-widened")
    assert point.pep.installed.ceiling is None


def test_case_227_an_install_provisioning_brings_a_floor_and_changes_nothing_else(tmp_path):
    """case_227: IS13, IS6, P3. A PEP with an install threshold of 1, a floor of section 6 at 7, a time floor a day
    ahead of its clock and an action floor at 2 takes an install provisioning with a floor at 3 with event
    `install-applied`, its floor of section 6, trust sequence and time floor unchanged; the same again changes nothing,
    one at 2 is `dist:seq-replay`, a release at `seq` 6 is then `dist:seq-replay`, and a `locked` PEP takes a floor by
    install provisioning and stays `locked`."""
    from dataclasses import replace
    point = _agent(tmp_path, install_threshold=1)
    point.pep.provision_install(_set(point, FLOOR, NARROW, 2, signers=["N1"]))
    point.commit(RELEASE, 7)
    point.pep.trust = replace(point.pep.trust, time_floor=NOW + 86400).save()
    assert point.pep.floor.seq == 7
    trust, time_floor = point.pep.trust.trust_seq, point.pep.trust.time_floor
    three = _set(point, FLOOR, NARROW, 3, signers=["N1"], widens=False, replaces=H(NARROW))
    records = [_read(point, one) for one in point.pep.provision_install(three)]
    assert records[-1].event == "install-applied" and point.pep.floor_set().seq == 3
    assert (point.pep.floor.seq, point.pep.trust.trust_seq, point.pep.trust.time_floor) == (7, trust, time_floor)
    assert [one.event for one in map(lambda r: _read(point, r), point.pep.provision_install(three))] == ["beat", "beat"]
    two = _set(point, FLOOR, NARROW, 2, signers=["N1"], widens=False)
    assert _read(point, point.pep.provision_install(two)[-1]).cause == "dist:seq-replay"
    assert _read(point, point.pep.stage(point.seal(RELEASE, 6), RELEASE)).cause == "dist:seq-replay"
    locked = _agent(tmp_path, "locked", install_threshold=1)
    _lock(locked)
    records = [_read(locked, one) for one in locked.pep.provision_install(_set(locked, FLOOR, NARROW, 1, signers=["N1"]))]
    assert records[-1].event == "install-widened" and locked.pep.state() == "locked"
    assert _decide(locked)["basis"] == "floor"


def test_case_218_a_looser_rate_widens_and_an_install_trust_says_so(tmp_path):
    """case_218: IS11, IS12, AF8. An `install.trust` that adds a key with `widens` false is `dist:widening-unsigned`,
    one that lowers the threshold with `widens` true is applied with event `install-widened`, and a floor at a higher
    `seq` with the same policy and a looser `rate` and `widens` false is `dist:widening-unsigned`."""
    point = _agent(tmp_path)
    rated = dict(rate={"allows": 3, "window": 60}, answer_rate={"allows": 1, "window": 600})
    point.send(_set(point, FLOOR, NARROW, 1, **rated))
    sealed, body = point.install_trust(1, KEYS + ["N4"], threshold=2, widens=False)
    assert _read(point, point.pep.stage(sealed, body)).cause == "dist:widening-unsigned"
    sealed, body = point.install_trust(1, KEYS, threshold=1, widens=True)
    assert _read(point, point.pep.stage(sealed, body)).event == "install-widened"
    point.install_threshold = 2
    sealed, body = point.install_trust(2, KEYS, threshold=2, signers=["N1"])
    assert _read(point, point.pep.stage(sealed, body)).cause == "dist:target-mismatch"     # IS4: threshold 1
    point.pep.provision_install([(sealed, body)])
    assert point.pep.installed.record.threshold == 2
    looser = point.send(_set(point, FLOOR, NARROW, 2, widens=False, replaces=H(NARROW),
                             rate={"allows": 4, "window": 60}, answer_rate=rated["answer_rate"]))
    assert looser[-1].cause == "dist:widening-unsigned"
    same = point.send(_set(point, FLOOR, NARROW, 2, widens=False, replaces=H(NARROW), **rated))
    assert same[-1].event == "install-applied"


# ------------------------------------------------------------------ CL3 with an action floor, and AF1's zones

def test_case_205_everything_a_pep_decides_under_is_inside_its_ceiling(tmp_path):
    """case_205: CL3, IS12, AF1. A PEP with a ceiling refuses a floor above it, a fallback policy above it and a
    ceiling its held floor is above, each `dist:above-ceiling` with nothing changed. A ceiling its active release is
    above, with `widens` false, narrows, so it is applied with event `install-applied` and the release lapses with
    `dist:above-ceiling`, to the fallback policy and to `no-policy`. An `agent` PEP whose ceiling protects a name is
    asked for a call on that name that a floor rule testing `zone_reach` allows, and the floor is silent."""
    ceiling = core(LIST, '-> allow: when tool == "read_file" and path_scope == "workspace"')
    for name, fallback in (("with", True), ("without", False)):
        point = _agent(tmp_path, name)
        point.send(_set(point, CEILING, ceiling))
        point.commit(RELEASE)
        above = core('-> allow: when tool == "delete_path" and path_scope == "workspace" and not path_control')
        held = point.pep.installed.record
        assert point.send(_set(point, FLOOR, above))[-1].cause == "dist:above-ceiling"
        assert point.send(_set(point, FALLBACK, above))[-1].cause == "dist:above-ceiling"
        assert point.pep.installed.record == held
        assert point.send(_set(point, FLOOR, NARROW, 2))[-1].event == "install-widened"    # seq 1 holds a staged
        if fallback:                                                                       # statement (V10)
            assert point.send(_set(point, FALLBACK, NARROW, 2))[-1].event == "install-widened"
        narrower = core('-> allow: when tool == "read_file" and path_scope == "workspace"')
        assert point.send(_set(point, CEILING, narrower, 2, widens=False))[-1].cause == "dist:above-ceiling"
        point.pep.drain()
        applied = point.send(_set(point, CEILING, NARROW, 2, widens=False))[-1]
        assert (applied.event, applied.cause) == ("install-applied", None)               # IS12: it narrows
        lapsed = [_read(point, one) for one in point.pep.drain()][-1]
        assert (lapsed.event, lapsed.cause) == (("fallback" if fallback else "lapsed"), "dist:above-ceiling")
        assert point.pep.state() == "no-policy" and point.pep.fallback_decides() == fallback
    zoned = _agent(tmp_path, "zoned")
    write = ('-> allow: when tool == "write_file" and path_scope == "workspace" and not path_control '
             'and zone_reach == "protected" and zone_name == "keys"')
    zoned.send(_set(zoned, CEILING, core(LIST, write), zones=_zones("keys")))
    assert _floor(zoned, core(write)).event == "install-widened"
    call = {"reading": {**ASK["reading"], "tool": "write_file", "zone_reach": "protected", "zone_name": "keys"}}
    assert _decide(zoned, call)["cause"] == "dist:policy-lapsed"


def _write(*tests):
    return ('-> allow: when tool == "write_file" and path_scope == "workspace" and not path_control'
            + "".join(f" and {test}" for test in tests))


def test_case_214_a_floor_rule_overrides_a_zone_only_where_it_names_it(tmp_path):
    """case_214: AF1, IS12, RC1. An `agent` PEP whose release protects `keys` and `ledger` is asked for a
    `write_file` call that reaches `keys`. A floor rule that tests no zone, one that tests `zone_reach` alone and one
    that names `ledger` are silent and the call is refused as the release says; one that names `keys` allows it with
    basis `floor` and the zone override mark naming `keys`; with that rule a call that reaches both zones, whose
    `zone_reach` is `unknown`, is silent. A floor that newly names `keys` and drops two tools is sent with `widens`
    false and is `dist:widening-unsigned`."""
    point = _agent(tmp_path)
    release = core('-> refuse agent:change-asked: when zone_reach != "none"',
                   '-> allow: when tool == "read_file" and path_scope == "workspace"')
    point.commit(release)
    call = {"reading": {**ASK["reading"], "tool": "write_file", "zone_reach": "protected", "zone_name": "keys"}}
    floors = [core(_write()), core(_write('zone_reach == "protected"')),
              core(_write('zone_reach == "protected"', 'zone_name == "ledger"'), LIST,
                   '-> allow: when tool == "read_file" and path_scope == "workspace"')]
    for seq, policy in enumerate(floors, 1):
        assert _floor(point, policy, seq).event in ("install-widened", "install-applied")
        decided = _decide(point, call)
        assert (decided["basis"], decided["cause"]) == ("release", None)
        assert floor.ask("agent", point.pep.active.bodies, call).cause == "agent:change-asked"
    keys = core(_write('zone_reach == "protected"', 'zone_name == "keys"'))
    assert _floor(point, keys, 4, widens=False, replaces=H(floors[-1])).cause == "dist:widening-unsigned"
    assert _floor(point, keys, 4).event == "install-widened"
    decided = _decide(point, call)
    assert (decided["basis"], decided["zone"], decided["decision"]) == ("floor", "keys", "allow")
    assert b'"zone":"keys"' in decided["receipt"]
    both = {"reading": {**call["reading"], "zone_reach": "unknown", "zone_name": ""}}
    assert _decide(point, both)["basis"] == "release"


def test_case_229_zone_name_is_tested_for_equality_with_one_readable_name(tmp_path):
    """case_229: AF1, W1, W6. An `agent` PEP refuses a floor whose rule tests `zone_name` as not equal to `keys` and
    one that names a zone name the zone point cannot read with `policy:out-of-domain`. A release that allows
    `write_file` where `zone_name` is `keys`, offered over one that allows it where `zone_name` is `ledger` with
    `widens` false, is `dist:widening-unsigned`, since the walk finds `keys` allowed where it was not."""
    point = _agent(tmp_path)
    for seq, test in enumerate(('zone_name != "keys"', 'zone_name == "a/b"'), 1):
        policy = core(_write('zone_reach == "protected"', test))
        assert "policy:out-of-domain" in [one.cause for one in point.send(_set(point, FLOOR, policy, seq, check=False))]
    assert floor.narrow("agent", "policy.core", core(_write('not zone_name == "keys"')), {}, None) \
        == "policy:out-of-domain"
    point.commit(core(_write('zone_name == "ledger"')))
    staged = _read(point, point.stage(core(_write('zone_name == "keys"')), 2, widens=False))
    assert staged.cause == "dist:widening-unsigned"


# ------------------------------------------------------------------ AF9, AF10: narrowness

BROAD_AGENT = [
    (core('-> allow: always'), HOSTS),
    (core('-> allow: when path_scope == "workspace"'), HOSTS),
    (core('-> allow: when tool == "list_dir" or path_scope == "workspace"'), HOSTS),
    (core('-> allow: when tool == "unknown"'), HOSTS),
    (core('-> allow: when tool == "run_command"'), HOSTS),
    (core('-> allow: when tool == "write_file" and not path_control'), HOSTS),
    (core('-> allow: when tool == "write_file" and path_scope == "workspace"'), HOSTS),
    (core(*[f'-> allow: when tool == "list_dir" and path_scope == "{scope}"' for scope in ("workspace", "outside",
                                                                                           "none")] * 3), HOSTS),
    (NARROW, canon.canon2_bytes(["*.example.com"])),
    (NARROW, canon.canon2_bytes(sorted(f"h{index}.example.com" for index in range(9)))),
]


def test_case_212_an_agent_floor_is_narrow_at_the_pep_and_the_sealing_tool(tmp_path):
    """case_212: AF9, IS5. An `agent` PEP and the sealing tool each refuse with `dist:floor-broad` a floor that allows
    what no rule matched, one whose rule allows every tool of a category, one whose rule tests `tool` only in one
    branch of an or, one that allows `tool` `unknown`, one that allows `run_command` with no test of
    `command_class`, `write_file` with no test of `path_scope`, `write_file` with no `path_control`, nine allowing
    rules, an `egress.hosts` with a wildcard and one with nine hosts. One with eight rules, of which one allows
    `run_command` with `command_class` `read_only`, is applied and sealed, and a read only command is allowed with
    basis `floor` while a mutating one is left to the release."""
    point = _agent(tmp_path)
    for seq, (policy, hosts) in enumerate(BROAD_AGENT, 1):
        with pytest.raises(Refused) as refused:
            point.install_set(FLOOR, {"policy.core": policy, "egress.hosts": hosts}, seq, widens=True, check=True)
        assert refused.value.cause == floor.BROAD
        answers = point.send(point.install_set(FLOOR, {"policy.core": policy, "egress.hosts": hosts}, seq,
                                               widens=True, check=False))
        assert floor.BROAD in [one.cause for one in answers], seq
        assert point.pep.floor_set() is None
    eight = core('-> allow: when tool == "run_command" and command_class == "read_only"',
                 *[f'-> allow: when tool == "{tool}" and path_scope == "workspace"'
                   for tool in ("list_dir", "read_file")],
                 *[f'-> allow: when tool == "{tool}" and path_scope == "workspace" and not path_control'
                   for tool in ("write_file", "delete_path")],
                 '-> allow: when tool == "git" and path_scope == "workspace" and path_control == False',
                 '-> allow: when tool == "list_dir" and path_scope == "outside"',
                 '-> allow: when tool == "read_file" and path_scope == "outside"')
    sealed = point.install_set(FLOOR, {"policy.core": eight, "egress.hosts": HOSTS}, 20, widens=True, check=True)
    assert point.send(sealed)[-1].event == "install-widened"
    point.commit(RELEASE)
    command = {"reading": {**ASK["reading"], "tool": "run_command", "command_class": "read_only"}}
    assert _decide(point, command)["basis"] == "floor"
    assert _decide(point, {"reading": {**command["reading"], "command_class": "mutating"}})["basis"] == "release"


BROAD_TABLES = [
    dict(body=table("True")),
    dict(body=table("p >= 2 and p <= 5")),
    dict(body=table(nodes=lambda img: [("a", [(1, "", img.compile_condition("when cmd == 3 and p >= 2 and p <= 5"))]),
                                       ("b", [(2, "", img.compile_condition("when cmd == 4 and p >= 2 and p <= 5"))]),
                                       ("t", [])])),
    dict(body=table(*[f"cmd == {index} and p >= 2 and p <= 5" for index in range(9)])),
    dict(command=7),
    dict(body=table("cmd == 3")),
    dict(body=table("cmd == 3 and p >= 0 and p <= 100")),
]
EIGHT_TABLE = table(*[f"cmd == {index} and p >= 2 and p <= 5" for index in range(8)])


def case_213_table_floors(point):
    """case_213 on one table kind: seven broad floors, a floor naming another layout, then eight narrow edges."""
    for seq, change in enumerate(BROAD_TABLES, 1):
        assert point.send(_table_floor(point, seq=seq, **change))[-1].cause == floor.BROAD, (seq, change)
    assert point.send(_table_floor(point, seq=8, layout=OTHER_LAYOUT))[-1].cause == "dist:target-mismatch"
    assert point.pep.floor_set() is None
    with pytest.raises(Refused):
        _table_floor(point, seq=9, check=True, **BROAD_TABLES[1])
    assert point.send(_table_floor(point, EIGHT_TABLE, seq=9, check=True))[-1].event == "install-widened"
    inside = point.pep.decide(lambda: "release", request={"regs": regs(cmd=6, p=3)})
    outside = point.pep.decide(lambda: "release", request={"regs": regs(cmd=6, p=7)})
    assert inside["basis"] == "floor" and outside["cause"] == "dist:policy-lapsed"


def test_case_213_host_and_mesh_table_floors_are_narrow(tmp_path):
    """case_213: AF9, AF10, the `host` and `mesh` halves. A floor table whose outcome with no matching edge is the
    allow, one with an edge that tests no command, one with two decision nodes, one with nine edges, one whose
    `command` names a register the layout does not label, one that allows a command with no bound on a parameter and
    one whose bound is the field's whole domain are `dist:floor-broad`, one whose `layout` is another layout's hash
    is `dist:target-mismatch`, and one with eight edges that each test one command and bound the parameter is applied,
    allowing that command inside the bound with basis `floor` and leaving it to the release outside. The `cfs` half
    is in test_cfs_dist.py."""
    case_213_table_floors(_table_point(MeshFloor, tmp_path, "mesh"))
    case_213_table_floors(_table_point(HostFloor, tmp_path, "host"))


def test_a_pep_built_with_no_layout_takes_no_table_floor(tmp_path):
    """AF9: the register a table floor names as its command is the one the layout labels, and a PEP built with none
    takes no action floor."""
    point = _table_point(_dist.MeshPep, tmp_path, "bare")
    assert point.send(_table_floor(point))[-1].cause == "dist:target-mismatch"


def test_a_layout_document_is_refused_with_a_staleness_bound_of_0():
    """AF10: an independent field has a staleness bound in seconds that is never 0, and the sealing tool refuses a
    layout that gives one."""
    with pytest.raises(Refused):
        floor.layout_body([{"name": "cmd", "register": 0, "role": "command", "min": 0, "max": 9, "stale": 0},
                           {"name": "w", "register": 1, "role": "independent", "min": 0, "max": 1, "stale": 0}])


def test_case_180_a_floor_never_moves_the_time_floor_of_a_pep_with_no_clock(tmp_path):
    """case_180: IS5, T1. A `mesh` PEP with no clock whose release expires in a month applies an action floor whose
    `not_before` is a year ahead, its time floor does not move and the release is still active."""
    point = _table_point(MeshFloor, tmp_path, "mesh", has_clock=False)
    point.commit(table("cmd == 1"), expires=NOW + 30 * 86400)
    before = point.pep.trust.time_floor
    assert point.send(_table_floor(point, not_before=NOW + 365 * 86400))[-1].event == "install-widened"
    assert point.pep.trust.time_floor == before and point.pep.state() == "active"


# ------------------------------------------------------------------ AF7, AF8, RC1 to RC3: receipts and rates

def test_case_193_a_floor_receipt_records_what_it_overrode(tmp_path):
    """case_193: AF7, RC1, the `agent` part. A floor allow where the release would allow, refuse and escalate records
    `would` with the release's outcome, its cause and its policy hash, and the override count rises by two; with no
    release and no fallback policy `would` is none. The `cfs` lines and the `xdp` count wait for their kinds (see
    test_distribution_trace.py PARTIAL)."""
    point = _agent(tmp_path)
    _floor(point)
    wills = [("allow", None, core(LIST)), ("refuse", "agent:network", core('-> refuse agent:network: when tool == "list_dir"')),
             ("escalate", "agent:change-asked", core('-> escalate agent:change-asked: when tool == "list_dir"'))]
    for seq, (outcome, cause, release) in enumerate(wills, 1):
        if seq == 1:
            point.commit(release)
        else:
            point.widen(release, seq, widens=True)
            point.stage(release, seq, widens=True)
            point.pep.commit(STREAM, seq, H(release))
        assert point.pep.active.seq == seq
        decided = _decide(point)
        assert decided["would"] == {"outcome": outcome, "cause": cause, "policy_sha256": H(release)}
        assert decided["basis"] == "floor" and decided["override"] == (outcome != "allow")
    assert (point.pep.installed.record.answers, point.pep.installed.record.overrides) == (3, 2)
    alone = _agent(tmp_path, "alone")
    _floor(alone)
    assert _decide(alone)["would"] == {"outcome": "none"}


def test_case_207_every_receipt_names_its_basis_and_the_set_that_decided(tmp_path):
    """case_207: RC1. Receipts for a request the release allows and one it refuses carry basis `release`, one the
    floor allows `floor`, one the fallback policy allows and one it refuses `fallback`, each with the policy hash of
    the set that decided, and a PEP with no fallback policy refuses in `no-policy` with no basis and
    `dist:policy-lapsed`."""
    point = _agent(tmp_path)
    _floor(point)
    fallback = core('-> allow: when tool == "read_file" and path_scope == "workspace"',
                    '-> refuse agent:network: when tool == "delete_path"')
    point.send(_set(point, FALLBACK, fallback))
    point.commit(RELEASE, expires=NOW + 100)
    seen = [(_decide(point, request)["basis"], _decide(point, request)["policy_sha256"]) for request in (READ, OTHER, ASK)]
    assert seen == [("release", H(RELEASE)), ("release", H(RELEASE)), ("floor", H(NARROW))]
    assert floor.ask("agent", point.pep.active.bodies, OTHER).outcome == "refuse"
    point.clock.now = NOW + 100
    point.pep.tick()
    for request, outcome in ((READ, "allow"), (OTHER, "refuse")):
        decided = _decide(point, request)
        assert (decided["basis"], decided["policy_sha256"]) == ("fallback", H(fallback))
        assert f'"outcome":"{outcome}"'.encode() in decided["receipt"]
    bare = _agent(tmp_path, "bare")
    decided = _decide(bare, READ)
    assert decided["cause"] == "dist:policy-lapsed" and "basis" not in decided and b'"basis"' not in decided["receipt"]


def test_case_194_a_signed_rate_limits_overrides_on_a_kind_with_no_escalation(tmp_path):
    """case_194: AF8, AF5, the `mesh` half. A `mesh` PEP whose floor has a rate of 3 in 60 seconds is asked five
    times for an action its release refuses, and the last two are decided by the release, since a kind with no
    escalation is silent past the rate. A release whose `not_before` is two windows ahead arrives in mid window and
    the window ends early. The `cfs` half is in test_cfs_dist.py and the `xdp` half waits for its kind."""
    point = _table_point(MeshFloor, tmp_path, "mesh", has_clock=False)
    assert point.send(_table_floor(point, rate={"allows": 3, "window": 60}))[-1].event == "install-widened"
    point.commit(table("cmd == 1"), expires=NOW + 86400)
    ask = {"regs": regs(cmd=3, p=3)}
    bases = [point.pep.decide(lambda: "release", request=ask)["basis"] for _ in range(5)]
    assert bases == ["floor", "floor", "floor", "release", "release"]
    point.pep = point.open()
    assert point.pep.decide(lambda: "release", request=ask)["basis"] == "release"
    point.stage(table("cmd == 2"), 2, not_before=NOW + 120, expires=NOW + 86400)
    assert point.pep.time() == NOW + 120
    assert point.pep.decide(lambda: "release", request=ask)["basis"] == "floor"


def test_case_208_a_held_pep_marks_its_receipts_apart_from_their_basis(tmp_path):
    """case_208: RC2, RC3. A held PEP writes a receipt for a request its release allows with basis `release` and the
    hold mark, and one the action floor allows with basis `floor`, the hold mark and `dist:floor-allowed`."""
    point = _table_point(MeshFloor, tmp_path, "mesh", expiry_response="hold")
    point.send(_table_floor(point))
    point.commit(table("cmd == 1"))
    point.clock.now = EXPIRES
    point.pep.tick()
    assert point.pep.held
    release = point.pep.decide(lambda: "release", request={"regs": regs(cmd=1)})
    floor_allowed = point.pep.decide(lambda: "release", request={"regs": regs(cmd=3, p=3)})
    assert (release["basis"], release["mark"]) == ("release", "held")
    assert (floor_allowed["basis"], floor_allowed["mark"], floor_allowed["cause"]) == ("floor", "held",
                                                                                         "dist:floor-allowed")
    assert b'"mark":"held"' in floor_allowed["receipt"] and b'dist:floor-allowed' in floor_allowed["receipt"]


# ------------------------------------------------------------------ C8: the floor answers while reconciling

def test_case_265_a_reconciling_pep_asks_its_floor_first(tmp_path):
    """case_265: C8, AF1, FB1, FB2. A `host` PEP with an action floor and a fallback policy, reconciling with its
    runtime withdrawn, allows a request the floor allows with basis `floor` and has the fallback policy decide one
    the floor is silent on, with bit 4 set and status 3. A second such PEP whose withdrawal failed allows the first
    with basis `floor` and refuses the second with `dist:reconciling`."""
    from prismpath.tests.test_distribution_reconciling import Flaky, FlakyHost

    class FloorFlaky(Flaky):
        floor_layout = LAYOUT

        def withdraw_to(self, fallback, cause):
            self.switches.withdrawals += 1
            if self.switches.withdraw:
                raise RuntimeError("the runtime did not withdraw")
            HostAdapter.activate(self, fallback)

    from prismpath.distribution.adapters.host import HostAdapter

    @dataclass
    class FloorHost(FlakyHost):
        def adapter(self):
            return FloorFlaky(self.host(), self.switches)

    for name, withdraws in (("withdrawn", True), ("stuck", False)):
        point = _table_point(FloorHost, tmp_path, name)
        point.send(_table_floor(point))
        point.send(point.install_set(FALLBACK, {"policy.ppt": table("cmd == 1")}, widens=True))
        point.commit(table("cmd == 2"))
        point.stage(table("cmd == 4"), 2)
        point.switches.set(True, not withdraws)
        assert point.read(point.pep.commit(STREAM, 2, H(table("cmd == 4")))).state == "reconciling"
        assert point.pep.decide(lambda: "fallback", request={"regs": regs(cmd=3, p=3)})["basis"] == "floor"
        silent = point.pep.decide(lambda: "fallback", request={"regs": regs(cmd=1)})
        beat = point.read(point.pep.record("beat"))
        if withdraws:
            assert silent["basis"] == "fallback" and (beat.fallback, beat.state) == (True, "reconciling")
        else:
            assert silent["cause"] == "dist:reconciling" and not beat.fallback


# ------------------------------------------------------------------ OP1, K4: the operator keys

def test_case_224_no_key_is_held_in_two_roles(tmp_path):
    """case_224: K4, O4, IS11. An anchor whose operator key is an authority key and one whose operator key is an
    install key are refused at provisioning. A `trust.rotation` whose `add` is an operator key and one whose `add` is
    a retired operator key, an `install.trust` that puts one key in `keys` and in `operators` and one that adds to
    `operators` a key the PEP retired as an install key are `dist:rotation-invalid`. One that drops an operator key
    is applied with the key retired, and one that adds it again is `dist:rotation-invalid`."""
    from prismpath.distribution.pep import PepRefused
    fresh = _agent(tmp_path, "fresh", install_keys=[])
    for changes in (dict(keys=["N1", "N2"], operators=["A"]), dict(keys=["N1", "N2"], operators=["N1"])):
        with pytest.raises((Refused, PepRefused)):
            fresh.pep.provision(_agent(tmp_path, "template").anchor(**changes))
    assert fresh.pep.installed.record is None
    point = _agent(tmp_path, operators=["O1", "O2"])
    assert _read(point, point.rotate(1, "O1")).cause == "dist:rotation-invalid"
    sealed, body = point.install_trust(1, KEYS, threshold=2, operators=["O1"], signers=["N1", "N2"])
    assert _read(point, point.pep.stage(sealed, body)).event == "install-applied"
    assert _dist.key_id("O2") in point.pep.installed.record.retired
    assert _read(point, point.rotate(1, "O2")).cause == "dist:rotation-invalid"
    both = install.trust_body([_dist.public(name) for name in KEYS], threshold=2,
                              operators=[_dist.public("O1"), _dist.public("N3")])
    raw = env.build("install.trust", both, stream=STREAM, seq=2, targets=("agent",), not_before=NOT_BEFORE,
                    expires=0, policy_sha256=env.ZERO_HASH, release=env.ZERO_HASH, widens=True)
    assert _read(point, point.pep.stage(env.seal(raw, [GEN.test_key(name) for name in ("N1", "N2")]), both)).cause \
        == "dist:rotation-invalid"
    sealed, body = point.install_trust(2, ["N1", "N2"], threshold=2, operators=["O1"], signers=["N1", "N2"])
    assert _read(point, point.pep.stage(sealed, body)).event == "install-applied"
    sealed, body = point.install_trust(3, ["N1", "N2"], threshold=2, operators=["N3", "O1"],
                                       signers=["N1", "N2", "N3"], widens=True)
    assert _read(point, point.pep.stage(sealed, body)).cause == "dist:rotation-invalid"
    sealed, body = point.install_trust(3, ["N1", "N2"], threshold=2, operators=["O1", "O2"],
                                       signers=["N1", "N2", "O2"], widens=True)
    assert _read(point, point.pep.stage(sealed, body)).cause == "dist:rotation-invalid"


def test_case_233_an_install_provisioning_takes_an_operator_key_back(tmp_path):
    """case_233: IS13, IS11. A PEP with an install threshold of 1 and two operator keys takes an install provisioning
    whose `install.trust` drops one of them, which is retired with its trust state and floor unchanged, and an answer
    that key signs is `dist:target-mismatch`, as the threshold is 1."""
    point = _agent(tmp_path, install_threshold=1, operators=["O1", "O2"])
    trust, sequence = point.pep.trust.to_bytes(), point.pep.floor
    sealed, body = point.install_trust(1, KEYS, threshold=1, operators=["O1"], signers=["N1"])
    records = [_read(point, one) for one in point.pep.provision_install([(sealed, body)])]
    assert records[-1].event == "install-applied" and _dist.key_id("O2") in point.pep.installed.record.retired
    assert point.pep.trust.to_bytes() == trust and point.pep.floor == sequence
    assert _read(point, point.pep.stage(*_dist.answer(point, "ab" * 32, signer="O2"))).cause == "dist:target-mismatch"


def test_case_236_an_anchor_keeps_the_instance_key_out_of_every_role(tmp_path):
    """case_236: P2, K4. An anchor whose operator key is the PEP's instance key, one whose install key is also an
    operator key, and one whose install key is the instance key are each refused at provisioning and the PEP is
    unchanged."""
    from prismpath.distribution.pep import PepRefused
    point = _agent(tmp_path)
    before = (point.pep.trust.to_bytes(), point.pep.installed.record)
    template = _agent(tmp_path, "template")
    for changes in (dict(operators=["I"]), dict(keys=["N1", "N2"], operators=["N2"]), dict(keys=["I", "N2"])):
        with pytest.raises((Refused, PepRefused)):
            point.pep.provision(template.anchor(**changes))
    assert (point.pep.trust.to_bytes(), point.pep.installed.record) == before


def test_case_235_an_anchor_without_an_install_part_leaves_the_install_record(tmp_path):
    """case_235: P4, P2, K4. An anchor whose `keys` holds an entry in the role `install` is `dist:bad-format`. A PEP
    that holds an install record is provisioned with a `/1` anchor and with a `/2` anchor with no `install` member,
    its install record, sets and sequences unchanged each time, and refuses a `/1` anchor whose authority key is a
    held install key and one whose authority key is an operator key it retired."""
    from prismpath.distribution import trust as trust_module
    from prismpath.distribution.pep import PepRefused
    point = _agent(tmp_path, operators=["O1", "O2"])
    doc = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-trust/1",
                              "keys": {_dist.key_id("A"): {"public": _dist.public("A").hex(), "role": "install"}},
                              "stream": STREAM, "target": "agent", "threshold": 1})
    with pytest.raises(Refused) as refused:
        trust_module.read_anchor(doc)
    assert refused.value.cause == "dist:bad-format"
    _floor(point)
    sealed, body = point.install_trust(1, KEYS, threshold=2, operators=["O1"], signers=["N1", "N2"])
    point.pep.stage(sealed, body)
    held = point.pep.installed.record
    for anchor in (trust_module.anchor_bytes([_dist.public("A")], target="agent", stream=STREAM),
                   trust_module.anchor_bytes([_dist.public("A")], target="agent", stream=STREAM,
                                             controller=_dist.public("C"))):
        point.pep.confirm(point.pep.provision(anchor))
        record = point.pep.installed.record
        assert (record.sets, record.seqs, record.keys, record.trust_seq) == (held.sets, held.seqs, held.keys,
                                                                             held.trust_seq)
    for authority in ("N1", "O2"):
        with pytest.raises((Refused, PepRefused)):
            point.pep.provision(trust_module.anchor_bytes([_dist.public(authority)], target="agent", stream=STREAM))


# ------------------------------------------------------------------ IS14, IS15: the install change statement

NARROWER = table("cmd == 3 and p >= 3 and p <= 5")      # allows less than GOOD_TABLE, by W8


def _change(point, pairs, *, signers=None):
    """The install change statement the install keys sign for the set whose first statement is in `pairs`."""
    names = signers if signers is not None else point.install_keys[:point.install_threshold]
    return install.seal_change(pairs[0][0], [GEN.test_key(name) for name in names])


def _change_doc(point, kind, carried, seq, source, *, replaces=None, widens=False, policy=None, signers=None,
                not_before=NOT_BEFORE, targets=None):
    """An install change statement sealed by hand, so a test can make one the tool never writes."""
    body = canon.canon2_bytes({"basis": kinds.CHANGE_BASIS, canon.ENCODING_KEY: canon.CANON2,
                               "format": kinds.INSTALL_CHANGE_FORMAT, "from": source, "set": kind})
    envelope = env.build(install.CHANGE, body, stream=point.stream, seq=seq, targets=list(targets or [point.kind]),
                         not_before=not_before, expires=0, policy_sha256=policy or H(carried),
                         release=env.install_release_id([("policy.ppt", H(carried))]),
                         replaces=source if replaces is None else replaces, widens=widens)
    names = signers if signers is not None else point.install_keys[:point.install_threshold]
    return env.seal(envelope, [GEN.test_key(name) for name in names]), body


@pytest.mark.parametrize("cls", [MeshFloor, HostFloor])
def test_case_296_an_install_change_statement_out_of_its_form_is_refused(tmp_path, cls):
    """case_296: IS14, IS2, V5, IS4. A `host` and a `mesh` PEP holding an action floor refuse an install change
    statement that says it widens, replaces nothing, names another hash than its replaces, carries a ceiling or the
    empty set with `dist:bad-format`, one signed by authority keys with `dist:unknown-key`, and a second one for a set
    that has one staged with `dist:incomplete`. An `agent` PEP and a PEP whose install threshold is 1 take none in a
    message. Nothing is staged."""
    point = _table_point(cls, tmp_path, "p")
    point.send(_table_floor(point))
    held = H(GOOD_TABLE)
    wrong = [_change_doc(point, FLOOR, NARROWER, 2, held, widens=True),
             _change_doc(point, FLOOR, NARROWER, 2, held, replaces=""),
             _change_doc(point, FLOOR, NARROWER, 2, held, replaces=H(image(9))),
             _change_doc(point, CEILING, NARROWER, 2, held),
             _change_doc(point, FLOOR, NARROWER, 2, held, policy=env.ZERO_HASH)]
    assert [point.send([one])[-1].cause for one in wrong] == ["dist:bad-format"] * 5
    assert point.send([_change_doc(point, FLOOR, NARROWER, 2, held, signers=["A"])])[-1].cause == "dist:unknown-key"
    assert point.pep.installed.staged == {}
    staged = point.send([_change_doc(point, FLOOR, NARROWER, 2, held)])[-1]
    assert (staged.event, staged.install.subject) == ("staged", FLOOR)
    again = point.send([_change_doc(point, FLOOR, NARROWER, 2, held, not_before=NOT_BEFORE + 1)])[-1]
    assert (again.cause, again.install.subject) == ("dist:incomplete", FLOOR)
    agent = _agent(tmp_path, "agent")
    agent.send(_set(agent, FLOOR, NARROW))
    assert agent.send([_change_doc(agent, FLOOR, NARROWER, 2, H(NARROW))])[-1].cause == "dist:target-mismatch"
    one = _table_point(cls, tmp_path, "one", install_threshold=1)
    one.pep.provision_install(_table_floor(one))
    assert one.send([_change_doc(one, FLOOR, NARROWER, 2, held)])[-1].cause == "dist:target-mismatch"


@pytest.mark.parametrize("cls", [MeshFloor, HostFloor])
def test_case_297_a_narrower_floor_or_fallback_carried_by_a_change_statement_is_applied(tmp_path, cls):
    """case_297: IS15, IS12. With a change statement from the held set's policy hash, a floor table and a fallback
    table that allow less with `widens` false are applied with event `install-applied` and no cause, with the
    statement named in the audit event, and a narrower floor with no change statement is `dist:widening-unsigned`
    with the floor before it still held."""
    point = _table_point(cls, tmp_path, "p")
    point.send(_table_floor(point))
    point.send(point.install_set(FALLBACK, {"policy.ppt": image(9)}, 1, widens=True))
    narrow = _table_floor(point, NARROWER, 2, widens=False, replaces=H(GOOD_TABLE))
    records = point.send([_change(point, narrow)] + narrow)
    assert [(one.event, one.cause) for one in records] == [("staged", None), ("install-applied", None)]
    assert point.pep.installed.held(FLOOR).policy_sha256 == H(NARROWER)
    fallback = point.install_set(FALLBACK, {"policy.ppt": image(10)}, 2, widens=False, replaces=H(image(9)))
    records = point.send([_change(point, fallback)] + fallback)
    assert [(one.event, one.cause) for one in records] == [("staged", None), ("install-applied", None)]
    applied = [event for event in point.pep.audit.events if event["action"] == "install-applied"][-1]
    assert applied["data"]["change"] == env.envelope_id(env.unseal(_change(point, fallback)[0])[0])
    alone = _table_floor(point, table("cmd == 3 and p >= 4 and p <= 5"), 3, widens=False, replaces=H(NARROWER))
    assert point.send(alone)[-1].cause == "dist:widening-unsigned"
    assert point.pep.installed.held(FLOOR).policy_sha256 == H(NARROWER)


@pytest.mark.parametrize("cls", [MeshFloor, HostFloor])
def test_case_298_a_change_statement_stands_only_for_a_set_it_can_carry(tmp_path, cls):
    """case_298: IS15, AF8, V10. A change statement on a PEP with no floor, and one from another hash, are
    `dist:widening-unsigned` with nothing staged. Beside a change statement a floor with a looser rate is
    `dist:widening-unsigned`, and a set that says it widens is `dist:incomplete`."""
    point = _table_point(cls, tmp_path, "p")
    held = H(GOOD_TABLE)
    assert point.send([_change_doc(point, FLOOR, NARROWER, 2, held)])[-1].cause == "dist:widening-unsigned"
    point.send(_table_floor(point, rate={"allows": 3, "window": 60}))
    other = H(image(9))
    assert point.send([_change_doc(point, FLOOR, NARROWER, 2, other)])[-1].cause == "dist:widening-unsigned"
    assert point.pep.installed.staged == {}
    looser = _table_floor(point, NARROWER, 2, widens=False, replaces=held, rate={"allows": 5, "window": 60})
    assert [one.cause for one in point.send([_change(point, looser)] + looser)] == [None, "dist:widening-unsigned"]
    carried = _table_floor(point, NARROWER, 3, widens=False, replaces=held, rate={"allows": 3, "window": 60})
    widens = _table_floor(point, NARROWER, 3, widens=True, replaces=held, rate={"allows": 3, "window": 60})
    assert [one.cause for one in point.send([_change(point, carried)] + widens)] == [None, "dist:incomplete"]


def test_a_floor_read_with_another_command_register_is_not_carried(tmp_path):
    """IS15, AF9: beside a change statement, a floor whose `command` is not the held floor's is larger, as the PEP
    compares it itself, so with `widens` false it is `dist:widening-unsigned`."""
    point = _table_point(MeshFloor, tmp_path, "p")
    assert point.send(_table_floor(point))[-1].event == "install-widened"
    held, narrow = H(GOOD_TABLE), NARROWER
    new = point.install_set(FLOOR, {"policy.ppt": narrow}, 2, widens=False, replaces=held,
                            metas={"policy.ppt": {**GEN.image_meta(narrow), "command": 3}}, layout=LAYOUT, check=False)
    envelopes = {"policy.ppt": env.read(env.unseal(new[0][0])[0])}
    body = install.change_body(FLOOR, held)
    assert install.widens_ok("mesh", FLOOR, point.pep.installed.held(FLOOR), {"policy.ppt": narrow}, widens=False,
                             replaces=held, envelopes=envelopes, change=body) == (install.UNSIGNED, True)
    same = point.install_set(FLOOR, {"policy.ppt": narrow}, 2, widens=False, replaces=held,
                             metas={"policy.ppt": {**GEN.image_meta(narrow), "command": 0}}, layout=LAYOUT, check=False)
    envelopes = {"policy.ppt": env.read(env.unseal(same[0][0])[0])}
    assert install.widens_ok("mesh", FLOOR, point.pep.installed.held(FLOOR), {"policy.ppt": narrow}, widens=False,
                             replaces=held, envelopes=envelopes, change=body) == (None, False)


@pytest.mark.parametrize("cls", [MeshFloor, HostFloor])
def test_case_299_a_staged_change_statement_survives_a_restart(tmp_path, cls):
    """case_299: IS15, IS4. A change statement staged survives a restart, and the narrower floor it carries is then
    applied with event `install-applied`."""
    point = _table_point(cls, tmp_path, "p")
    point.send(_table_floor(point))
    narrow = _table_floor(point, NARROWER, 2, widens=False, replaces=H(GOOD_TABLE))
    point.send([_change(point, narrow)])
    point.pep = point.open()
    assert point.pep.installed.staged[FLOOR].change is not None
    applied = point.send(narrow)[-1]
    assert (applied.event, applied.cause) == ("install-applied", None)
