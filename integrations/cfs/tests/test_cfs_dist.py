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
    point.pep.see_epoch(controller.epoch)
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
    """Case 136's cFS part (W1): a table whose core image allows less is not larger, a table with the same core
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
