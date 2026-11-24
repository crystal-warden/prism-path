# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The `cfs` target of policy distribution in the Python machine (integrations/cfs/dist_kind.py): the table check
and the hold cases on a modelled cFS app. The mesh half of each hold case is in prismpath/tests."""
from dataclasses import dataclass
import hashlib

import pytest

pytest.importorskip("cryptography")

from integrations.cfs import dist_kind  # noqa: E402
from integrations.cfs.ground import table  # noqa: E402
from integrations.cfs.prismpath_app.policy import gen_image  # noqa: E402
from prismpath.distribution import kinds, state_record  # noqa: E402
from prismpath.tests import _dist  # noqa: E402

CORE = gen_image.CORE.read_bytes().rstrip(b"\n")
READING = dict(cmd_class=2, ground_contact=1, slew_deg=10, thrust_pct=60)


def _body(version: int) -> bytes:
    data = table.pack(gen_image.build(CORE))
    table.set_version(data, version)
    return bytes(data[:dist_kind.BODY_SIZE])


@dataclass
class CfsPep(_dist.Point):
    kind: str = "cfs"
    artifact: str = "cfs.table"

    def adapter(self):
        return dist_kind.CfsAdapter()

    def policy_of(self, body: bytes) -> str:
        return hashlib.sha256(table.core_of(body)).hexdigest()


def _cfs(tmp_path):
    counter = iter(range(100))

    def make(**settings):
        return CfsPep(tmp_path / f"app{next(counter)}", **settings)
    return make, [_body(1), _body(2)], (lambda pep: pep.adapter.decide(READING))


def test_the_cfs_row_is_registered_once_with_hold_and_the_table_bound():
    target = kinds.TARGETS["cfs"]
    assert target.expiry_hold and target.needs == {"cfs.table"} and target.body_bound == table.OFF["ImageSig"]
    kinds.register_target("cfs", dist_kind.TARGET)                   # the same row again changes nothing
    with pytest.raises(ValueError):
        kinds.register_target("cfs", kinds.Target(needs=frozenset({"cfs.table"}), decides=True,
                                                  checks={"cfs.table": dist_kind.check_cfs_table}))
    with pytest.raises(ValueError):
        kinds.register_target("toaster", dist_kind.TARGET)


def test_a_cfs_table_is_checked_as_the_app_checks_it(tmp_path):
    """V11: the app's kernel check with its cause, and the core image's hash against the policy hash."""
    point = CfsPep(tmp_path)
    good = _body(1)
    assert state_record.read(point.stage(good), point.key.public_raw).event == "staged"
    for broken, cause in ((good[:-1], "image:truncated-header"),
                          (bytes(bytearray(good[:8]) + b"\x00\x00" + good[10:]), "image:truncated-header"),
                          (_body(0), "image:truncated-header")):
        signed = point.seal(broken, seq=2, policy_sha256=point.policy_of(good))
        assert state_record.read(point.pep.stage(signed, broken), point.key.public_raw).cause == cause
    other = point.seal(_body(3), seq=4, policy_sha256="ab" * 32)
    assert state_record.read(point.pep.stage(other, _body(3)), point.key.public_raw).cause == "image:sha256-mismatch"


def test_case_106_a_cfs_app_left_at_refuse_lapses_at_expiry(tmp_path):
    """case_106: X6, X1, on a modelled cFS app."""
    _dist.case_106_refuse_lapses(*_cfs(tmp_path))


def test_case_107_a_cfs_app_on_hold_keeps_deciding_and_marks_everything(tmp_path):
    """case_107: X6, X7, on a modelled cFS app."""
    _dist.case_107_hold_keeps_deciding_and_marks_everything(*_cfs(tmp_path))


def test_case_108_a_revocation_ends_a_cfs_app_s_hold(tmp_path):
    """case_108: X8, R5, on a modelled cFS app."""
    _dist.case_108_a_revocation_ends_a_hold(*_cfs(tmp_path))


def test_case_110_a_held_cfs_app_never_widens(tmp_path):
    """case_110: X9, on a modelled cFS app."""
    _dist.case_110_a_held_pep_never_widens(*_cfs(tmp_path))


def test_case_112_no_message_changes_a_cfs_app_s_setting(tmp_path):
    """case_112: X10, on a modelled cFS app."""
    _dist.case_112_no_message_changes_the_setting(*_cfs(tmp_path))


def test_case_113_a_controller_files_a_cfs_app_held_while_its_records_carry_bit_5(tmp_path):
    """case_113: H8, the cFS half. A cFS app on hold past expiry reports bit 5, which the controller files as
    dist:held, and its first record without the bit clears it."""
    from prismpath.distribution.controller import Controller
    point = CfsPep(tmp_path / "app", expiry_response="hold")
    controller = Controller(str(tmp_path / "controller"), _dist.instance_key("C"), clock=point.clock)
    controller.add_anchor(point.anchor())
    pep_id = controller.enroll(point.key.public_raw, "cfs", _dist.STREAM)
    first, second = _body(1), _body(2)
    point.commit(first)
    point.clock.now = _dist.EXPIRES
    controller.tick()
    point.pep.take_statement(controller.statement(_dist.STREAM))   # a /1 anchor: no key to take it under
    point.pep.tick()
    controller.members[pep_id].expected = (point.policy_of(first), point.pep.active.release, 1)
    held = point.pep.drain()
    assert held and controller.receive(held[-1]) is None and "dist:held" in controller.members[pep_id].findings
    later = point.seal(second, seq=2, not_before=_dist.EXPIRES, expires=_dist.EXPIRES + 1000)
    point.pep.stage(later, second)
    point.pep.commit(_dist.STREAM, 2, point.policy_of(second))
    controller.members[pep_id].expected = (point.policy_of(second), point.pep.active.release, 2)
    for record in point.pep.drain():
        controller.receive(record)
    assert "dist:held" not in controller.members[pep_id].findings


def test_a_cfs_table_is_ordered_by_its_core_image_and_any_other_change_is_larger():
    """case_136, the cFS part (W1): a table whose core image allows less is not larger, a table with the same core
    image and other rules is larger, and the same table is not."""
    from prismpath.distribution import widening
    core = gen_image.CORE.read_bytes().rstrip(b"\n")
    base = _body(1)
    assert dist_kind.compare_cfs_tables(base, base) == widening.NOT_LARGER
    other_rules = bytearray(base)
    other_rules[table.OFF["ImageSig"] - 1] ^= 1                         # a byte outside the core image
    assert table.core_of(bytes(other_rules)) == table.core_of(base)
    assert dist_kind.compare_cfs_tables(base, bytes(other_rules)) == widening.LARGER
    assert widening.COMPARATORS["cfs.table"] is dist_kind.compare_cfs_tables
    from prismpath.kernel import canon2
    doc = canon2.loads(core)
    doc["rules"][-1]["target"] = "escalate_34"                          # the last allow asks instead
    narrower = table.pack(gen_image.build(canon2.dumps(doc)))
    table.set_version(narrower, 1)
    narrower = bytes(narrower[:dist_kind.BODY_SIZE])
    assert dist_kind.compare_cfs_tables(base, narrower) == widening.NOT_LARGER
    assert dist_kind.compare_cfs_tables(narrower, base) == widening.LARGER


def test_a_cfs_table_with_another_core_image_is_taken_on_the_signers_word():
    """case_060, the cFS half (W2): the cFS app compares nothing itself, so a table whose core image differs, with
    `widens` false and `replaces` its active hash, commits on its signature alone."""
    import tempfile
    from pathlib import Path
    from prismpath.kernel import canon2
    point = CfsPep(Path(tempfile.mkdtemp()) / "app")
    base = _body(1)
    point.commit(base)
    doc = canon2.loads(gen_image.CORE.read_bytes().rstrip(b"\n"))
    doc["rules"][-1]["target"] = "escalate_34"
    other = table.pack(gen_image.build(canon2.dumps(doc)))
    table.set_version(other, 2)
    other = bytes(other[:dist_kind.BODY_SIZE])
    active = point.policy_of(base)
    record = state_record.read(point.pep.stage(point.seal(other, seq=2, replaces=active, widens=False), other),
                               point.key.public_raw)
    assert record.event == "staged"
    committed = point.pep.commit(_dist.STREAM, 2, point.policy_of(other))
    assert state_record.read(committed, point.key.public_raw).event == "committed"


def test_case_269_a_cfs_app_with_hold_cut_off_past_its_fresh_statement_is_held(tmp_path):
    """case_269: H16, X7, the `cfs` half. With `fresh` 3600 and HOLD, a cFS app that took a fresh statement and is
    cut off for 3901 seconds is held, with bit 5 set, and keeps deciding under its release."""
    from prismpath.distribution.controller import Controller
    point = CfsPep(tmp_path / "app", expiry_response="hold", controller="C", fresh=3600)
    controller = Controller(str(tmp_path / "controller"), _dist.instance_key("C"), clock=point.clock)
    controller.add_anchor(point.anchor())
    controller.enroll(point.key.public_raw, "cfs", _dist.STREAM)
    first = _body(1)
    for sealed, body in _dist.release_with_statement(point, first, 1, widen=True, replaces=""):
        controller.put(sealed, body)
    point.commit(first)
    assert point.pep.take_statement(controller.statement(_dist.STREAM)) and point.pep.kept is not None
    point.clock.now += 3901
    held = state_record.read(point.pep.tick(), point.key.public_raw)
    assert (held.event, held.cause, held.held, held.state) == ("held", "dist:held", True, "active")
    assert point.pep.decide(lambda: point.pep.adapter.decide(READING))["mark"] == "held"


# ------------------------------------------------------------------ section 21 on a modelled cFS app

def _install(tmp_path, name="app", **settings):
    settings.setdefault("install_keys", ["N1", "N2", "N3"])
    settings.setdefault("install_threshold", 2)
    return CfsPep(tmp_path / name, **settings)


def _fallback(point, body, seq=1, **args):
    args.setdefault("widens", True)
    return point.install_set("install.fallback", {"cfs.table": body}, seq, **args)


def test_case_200_hold_and_a_fallback_policy_on_a_cfs_app(tmp_path):
    """case_200: FB6, X7, X8. A cFS app with HOLD and a fallback policy is held at expiry with bit 5 set and bit 4
    clear, and a revocation of its release then hands it to its fallback policy with bit 4 set, bit 5 clear and event
    `fallback` with `dist:revoked`."""
    point = _install(tmp_path, expiry_response="hold")
    assert point.send(_fallback(point, _body(2)))[-1].event == "install-widened"
    point.commit(_body(1))
    point.clock.now = _dist.EXPIRES
    held = state_record.read(point.pep.tick(), point.key.public_raw)
    assert (held.event, held.held, held.fallback) == ("held", True, False)
    assert point.pep.decide(lambda: point.pep.adapter.table)["decision"] == _body(1)
    point.pep.drain()
    point.revoke(1, policies=[point.policy_of(_body(1))])
    sent = [state_record.read(one, point.key.public_raw) for one in point.pep.drain()]
    fallback = [one for one in sent if one.event == "fallback"]
    assert [(one.cause, one.held, one.fallback) for one in fallback] == [("dist:revoked", False, True)]
    decided = point.pep.decide(lambda: point.pep.adapter.table)
    assert decided["basis"] == "fallback" and decided["decision"] == _body(2)


def test_case_226_a_cfs_app_keeps_its_second_copy_in_a_critical_data_store_area(tmp_path):
    """case_226: IS10, the cFS half. A cFS app whose second copy of its install record is in a Critical Data Store
    area loses the file that holds the first, uses the second copy and holds its sets."""
    point = _install(tmp_path, install_copy=tmp_path / "cds")
    point.send(_fallback(point, _body(2)))
    import shutil
    shutil.rmtree(point.state_dir / "dist" / "install")
    point.pep = point.open()
    assert point.pep.installed.fallback is not None and not point.pep.installed.record_lost
    decided = point.pep.decide(lambda: point.pep.adapter.table)
    assert decided["basis"] == "fallback" and decided["decision"] == _body(2)


# ------------------------------------------------------------------ the action floor on a modelled cFS app (21.2)

from prismpath.distribution import floor  # noqa: E402
from prismpath.kernel import canon2  # noqa: E402

FIELDS = canon2.loads(CORE)["fields"]
CFS_LAYOUT = floor.layout_body([
    {"name": "cmd_class", "register": 0, "role": "command", "min": 0, "max": 10, "stale": 0},
    {"name": "ground_contact", "register": 1, "role": "proposer", "min": 0, "max": 1, "stale": 0},
    {"name": "monitor_ok", "register": 2, "role": "independent", "min": 0, "max": 1, "stale": 5},
    {"name": "slew_deg", "register": 3, "role": "parameter", "min": 0, "max": 180, "stale": 0},
    {"name": "thrust_pct", "register": 4, "role": "parameter", "min": 0, "max": 200, "stale": 0}])
OTHER_LAYOUT = floor.layout_body([{"name": "cmd_class", "register": 0, "role": "command", "min": 0, "max": 10,
                                   "stale": 0}])


def _cmd(value, *more):
    """A rule body: the command `value`, both parameters bounded, and `more`."""
    return ["and", ["cmp", "cmd_class", "==", ["num", value]], ["cmp", "slew_deg", ">=", ["num", 0]],
            ["cmp", "slew_deg", "<=", ["num", 10]], ["cmp", "thrust_pct", ">=", ["num", 0]],
            ["cmp", "thrust_pct", "<=", ["num", 20]], *more]


def _table_of(*rules, image=None) -> bytes:
    """A `cfs.table` of the core policy `rules` over the app's fields."""
    built = gen_image.build(canon2.dumps({"fields": FIELDS, "format": "prismpath.core/1",
                                          "rules": [{"target": target, "when": when} for target, when in rules]}))
    if image is not None:
        built["image"] = image(built["image"])
    data = table.pack(built)
    table.set_version(data, 1)
    return bytes(data[:dist_kind.BODY_SIZE])


@dataclass
class CfsFloor(CfsPep):
    def adapter(self):
        adapter = dist_kind.CfsAdapter()
        adapter.floor_layout = CFS_LAYOUT
        return adapter


def _floor_point(tmp_path, name="app", **settings):
    settings.setdefault("install_keys", ["N1", "N2", "N3"])
    settings.setdefault("install_threshold", 2)
    return CfsFloor(tmp_path / name, **settings)


ANSWERS = {"allows": 4, "window": 600}


def _cfs_floor(point, body, seq=1, *, layout=CFS_LAYOUT, command=0, check=False, **args):
    args.setdefault("widens", True)
    args.setdefault("answer_rate", ANSWERS)
    return point.install_set("install.floor", {"cfs.table": body}, seq, metas={"cfs.table": {"command": command}},
                             layout=layout, check=check, **args)


def _ask(cmd_class, monitor=(True, 1), **reading):
    """A proposal of `cmd_class`, and the monitor's own verdict with its age, or none."""
    proposal = {"cmd_class": cmd_class, "ground_contact": False, "slew_deg": 5, "thrust_pct": 10, "monitor_ok": True,
                **reading}
    return {"reading": proposal, "independent": {} if monitor is None else {"monitor_ok": list(monitor)}}


ALLOW_3 = _table_of(("allow", _cmd(3)))


def _decide(point, request):
    return point.pep.decide(lambda: point.pep.adapter.table, request=request)


def test_case_186_a_held_cfs_app_still_asks_its_floor(tmp_path):
    """case_186: AF1, the held `cfs` half. A held cFS app allows what its floor allows with basis `floor`."""
    point = _floor_point(tmp_path, expiry_response="hold")
    assert point.send(_cfs_floor(point, ALLOW_3))[-1].event == "install-widened"
    point.commit(_body(1))
    point.clock.now = _dist.EXPIRES
    point.pep.tick()
    decided = _decide(point, _ask(3))
    assert point.pep.held and (decided["basis"], decided["mark"]) == ("floor", "held")


def test_case_188_a_cfs_floor_escalates_with_its_own_cause(tmp_path):
    """case_188: AF2, the `cfs` half. A request the floor escalates is escalated with basis `floor` and the floor's
    cause on a cFS app whose release allows it."""
    point = _floor_point(tmp_path)
    point.send(_cfs_floor(point, _table_of(("escalate_34", _cmd(2)))))
    point.commit(_body(1))
    request = _ask(2, ground_contact=True)
    assert floor.ask("cfs", point.pep.active.bodies, request).outcome == "allow"
    decided = _decide(point, request)
    assert (decided["decision"], decided["basis"], decided["cause"]) == ("escalate", "floor", "route:needs-human")


def test_case_192_a_cfs_floor_reads_the_monitor_as_the_engineer_chose(tmp_path):
    """case_192: AF6, AF2. A cFS app whose floor allows a command only when the monitor agrees allows it with basis
    `floor` when the monitor's verdict is good, and with no release and no fallback policy refuses it with
    `dist:policy-lapsed` when the verdict is bad."""
    point = _floor_point(tmp_path)
    point.send(_cfs_floor(point, _table_of(("allow", _cmd(3, ["truthy", "monitor_ok"])))))
    assert _decide(point, _ask(3))["basis"] == "floor"
    assert _decide(point, _ask(3, monitor=(False, 1)))["cause"] == "dist:policy-lapsed"


def test_case_194_a_cfs_floor_counts_overrides_per_rule_in_durable_windows(tmp_path):
    """case_194: AF8, AF5, the `cfs` half. A floor with two rules and a rate of 3 in 60 seconds is asked for the
    first rule's action, which the release refuses, five times in one window with a restart after the second:
    allowed three times and escalated twice with `dist:floor-rate` and basis `floor`, the restart changing nothing.
    The second rule's action is allowed once, an action the release allows is decided ten times with no count, and
    the first is allowed again in the next window."""
    point = _floor_point(tmp_path)
    point.send(_cfs_floor(point, _table_of(("allow", _cmd(4)), ("allow", _cmd(5))), rate={"allows": 3, "window": 60}))
    point.commit(_body(1))
    answers = []
    for index in range(5):
        if index == 2:
            point.pep = point.open()
        decided = _decide(point, _ask(4))
        answers.append((decided["decision"], decided["cause"], decided["basis"]))
    assert answers == [("allow", "dist:floor-allowed", "floor")] * 3 + [("escalate", "dist:floor-rate", "floor")] * 2
    assert _decide(point, _ask(5))["decision"] == "allow"
    rules = dict(point.pep.book().rules)
    for _ in range(10):
        assert _decide(point, _ask(1, ground_contact=True))["basis"] == "release"
    assert point.pep.book().rules == rules == {"cfs.table:0": [_dist.NOW, 3], "cfs.table:1": [_dist.NOW, 1]}
    point.clock.now += 60
    decided = _decide(point, _ask(4))
    assert (decided["decision"], decided["count"], decided["window"]) == ("allow", 1, _dist.NOW + 60)


def _two_nodes(image: bytes) -> bytes:
    """The table image with its first terminal node given the start node's first edge, a second decision node."""
    from prismpath.hotswap import policy_pack
    data = bytearray(image)
    header = policy_pack.read_ppt_header(image)
    nodes = policy_pack.HEADER.size + policy_pack.ATOM.size * header["atoms"]
    start_offset, _count = policy_pack.NODE.unpack_from(image, nodes + policy_pack.NODE.size * header["start"])
    other = 1 if header["start"] == 0 else 0
    policy_pack.NODE.pack_into(data, nodes + policy_pack.NODE.size * other, start_offset, 1)
    return bytes(data)


BROAD_CFS = [
    dict(body=_table_of(("allow", ["always"]))),
    dict(body=_table_of(("allow", ["and", ["cmp", "slew_deg", "<=", ["num", 10]], ["cmp", "slew_deg", ">=", ["num", 0]]]))),
    dict(body=_table_of(("allow", _cmd(3)), ("allow", _cmd(4)), image=lambda image: _two_nodes(image))),
    dict(body=_table_of(*[("allow", ["cmp", "cmd_class", "==", ["num", value]]) for value in range(9)])),
    dict(body=ALLOW_3, command=3),
    dict(body=_table_of(("allow", ["cmp", "cmd_class", "==", ["num", 3]]))),
    dict(body=_table_of(("allow", ["and", ["cmp", "cmd_class", "==", ["num", 3]], ["cmp", "slew_deg", ">=", ["num", 0]],
                                  ["cmp", "slew_deg", "<=", ["num", 180]], ["cmp", "thrust_pct", ">=", ["num", 0]],
                                  ["cmp", "thrust_pct", "<=", ["num", 200]]]))),
]


def test_case_213_a_cfs_floor_is_narrow(tmp_path):
    """case_213: AF9, AF10, the `cfs` half. A floor whose outcome with no matching rule is the allow, one whose rule
    tests no command, one with two decision nodes, one with nine allowing rules, one whose `command` names a field
    the layout does not label as the command, one with no bound on a parameter and one whose bound is the whole
    domain are `dist:floor-broad`, one whose `layout` is another layout's hash is `dist:target-mismatch`, and one with
    eight rules each of one command with its parameters bounded is applied, allowing a command inside the bound with
    basis `floor` and leaving it to the release outside."""
    point = _floor_point(tmp_path)
    for seq, change in enumerate(BROAD_CFS, 1):
        assert point.send(_cfs_floor(point, seq=seq, **change))[-1].cause == floor.BROAD, seq
    assert point.send(_cfs_floor(point, ALLOW_3, 8, layout=OTHER_LAYOUT))[-1].cause == "dist:target-mismatch"
    eight = _table_of(*[("allow", _cmd(value)) for value in range(3, 11)])
    assert point.send(_cfs_floor(point, eight, 9, check=True))[-1].event == "install-widened"
    assert _decide(point, _ask(6))["basis"] == "floor"
    assert _decide(point, _ask(6, slew_deg=50))["cause"] == "dist:policy-lapsed"


def test_case_216_a_cfs_floor_tests_only_what_the_proposer_cannot_write(tmp_path):
    """case_216: AF10. With `monitor_ok` independent with a staleness bound of 5 seconds and `ground_contact` the
    proposer's, a floor whose rule tests `ground_contact` is `dist:floor-broad` and one whose rule tests `monitor_ok`
    is applied. It is silent for a proposal that claims the monitor agrees while the monitor's own message says it
    does not, with the monitor's last message 6 seconds old, and with none ever received. The sealing tool refuses a
    layout with a staleness bound of 0."""
    point = _floor_point(tmp_path)
    assert point.send(_cfs_floor(point, _table_of(("allow", _cmd(3, ["truthy", "ground_contact"])))))[-1].cause \
        == floor.BROAD
    assert point.send(_cfs_floor(point, _table_of(("allow", _cmd(3, ["truthy", "monitor_ok"]))), 2))[-1].event \
        == "install-widened"
    assert _decide(point, _ask(3))["basis"] == "floor"
    for monitor in ((False, 1), (True, 6), None):
        assert _decide(point, _ask(3, monitor=monitor))["cause"] == "dist:policy-lapsed"
    with pytest.raises(kinds.Refused):
        floor.layout_body([{"name": "cmd_class", "register": 0, "role": "command", "min": 0, "max": 10, "stale": 0},
                           {"name": "monitor_ok", "register": 2, "role": "independent", "min": 0, "max": 1,
                            "stale": 0}])
