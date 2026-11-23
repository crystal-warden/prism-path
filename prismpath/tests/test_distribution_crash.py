# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A commit killed at each of its steps (spec-policy-distribution.md, C4). The death is an exception raised
before the step, the process is gone with it, and a fresh enforcement point over the same state directory
stands for the restart."""
import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.distribution import state_record  # noqa: E402
from prismpath.tests import _dist  # noqa: E402

STEPS = ("intent", "floor", "evidence", "active_record", "runtime", "cleanup")
HOST_STEPS = ("host_intent", "host_evidence", "host_image", "host_record")
BEFORE_FLIP = {"intent", "floor", "evidence", "active_record"}


class Died(Exception):
    pass


def _fault(pep, step, monkeypatch):
    """Make the next commit raise before `step`."""
    def die(*_args, **_kwargs):
        raise Died(step)

    write, append = pep.store.write, pep.audit.append
    names = {"intent": "pending.json", "floor": "floor.json", "active_record": "active.json"}
    if step in names:
        monkeypatch.setattr(pep.store, "write", lambda name, *rest: die() if name == names[step] else write(name, *rest))
    elif step == "evidence":
        monkeypatch.setattr(pep.audit, "append", lambda actor, action, data: die() if action == "committed"
                            else append(actor, action, data))
    elif step == "runtime":
        monkeypatch.setattr(pep.adapter, "activate", die)
    elif step == "cleanup":
        monkeypatch.setattr(pep, "_cleanup", die)
    else:                                                            # inside PolicyHost.install_verified
        host = pep.adapter.host
        if step == "host_intent":
            monkeypatch.setattr(host, "_write_pending", die)
        elif step == "host_evidence":
            real = host.audit.append
            monkeypatch.setattr(host.audit, "append", lambda actor, action, data: die() if action == "swap"
                                else real(actor, action, data))
        else:
            real_write = canon.atomic_write_bytes
            suffix = "active_policy.json" if step == "host_record" else ".ppt"
            monkeypatch.setattr(canon, "atomic_write_bytes", lambda path, data: die()
                                if str(path).endswith(suffix) and "/dist/" not in str(path) else real_write(path, data))


def _one_policy(point, expect_seq):
    """The restarted PEP and its host hold one release, the expected one, and nothing else is active."""
    pep = point.open()
    old, new = _dist.image(5), _dist.image(7)
    assert pep.state() == "active" and pep.active.seq == expect_seq
    body = {1: old, 2: new}[expect_seq]
    host = pep.adapter.host.active()
    assert host["active"] == canon.sha256_hex(body) and host["version"] == expect_seq
    assert pep.active.bodies["policy.ppt"] == body and not pep.store.exists("pending.json")
    return pep


@pytest.mark.parametrize("step", STEPS + HOST_STEPS)
def test_case_051_a_commit_killed_at_each_step_leaves_one_policy(tmp_path, monkeypatch, step):
    """case_051: C4. Killed before the active record flips, the old release is active after a restart and the
    commit can be made again. Killed after, the new release is active, and the host's own record follows
    the PEP's, whatever step of its own install died."""
    point = _dist.HostPep(tmp_path)
    old, new = _dist.image(5), _dist.image(7)
    point.commit(old, seq=1)
    point.stage(new, 2)
    _fault(point.pep, step, monkeypatch)
    with pytest.raises(Died):
        point.pep.commit(_dist.STREAM, 2, canon.sha256_hex(new))
    monkeypatch.undo()
    pep = _one_policy(point, 1 if step in BEFORE_FLIP else 2)
    if step in BEFORE_FLIP:
        assert pep.staged is not None and pep.staged.seq == 2
        record = state_record.read(pep.commit(_dist.STREAM, 2, canon.sha256_hex(new)), point.key.public_raw)
        assert record.event == "committed" and record.active_seq == 2
        point.pep = pep
        _one_policy(point, 2)
    events = [event["action"] for event in pep.audit.events]
    assert events.count("commit_incomplete") == (1 if step in BEFORE_FLIP - {"intent"} else 0)   # the intent was written
