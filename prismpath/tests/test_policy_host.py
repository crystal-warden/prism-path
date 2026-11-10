# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""PolicyHost (spec-secure-hotswap §3.3-§3.4): a swap is authorized + in-envelope + monotonic +
atomic, every attempt is one audit event, the swap chain reconstructs from the ledger, and a
failure at any stage leaves the previous policy active. Uses the real compiler + real Ed25519."""
import sys
from pathlib import Path

import json
import os

import pytest

pytest.importorskip("cryptography")

from prismpath.hotswap import policy_pack as pp# noqa: E402
from prismpath.hotswap import policy_host as ph# noqa: E402
from prismpath.ledgers.audit_log import AuditLog  # noqa: E402
from prismpath.kernel.parser import parse  # noqa: E402

from prismpath.tests._repo import repo_file

_hw = repo_file("prismpath-hw")
sys.path.insert(0, str(_hw))
import ppt_compile as pc  # noqa: E402

FIELDS = {"temp": "int"}


def _flow(hot_thresh):
    return f"""# f
## start
-> hot: when temp >= {hot_thresh}
-> cold: else
## hot
-> end
## cold
-> end
## end
"""


@pytest.fixture()
def env(tmp_path):
    keys = pp.keygen(str(tmp_path / "keys"))
    envelope = pp.build_envelope("env1", FIELDS, None, keys["private"], keys["public"],
                                 str(tmp_path / "env"))
    return {"keys": keys, "envelope": envelope, "tmp": tmp_path}


def _pack(env, name, version, hot=100, envelope_id="env1", fields=FIELDS):
    ppt = env["tmp"] / f"{name}.ppt"
    ppt.write_bytes(pc.compile_flow(parse(_flow(hot))).serialize())
    pp.build_pack(str(ppt), fields, version=version, envelope_id=envelope_id,
                  priv_path=env["keys"]["private"], pub_path=env["keys"]["public"])
    return str(ppt)


def _host(env):
    return ph.PolicyHost(str(env["tmp"] / "state"), [env["keys"]["public"]], env["envelope"])


def test_accepted_swap_becomes_active(env):
    host = _host(env)
    swap_result = host.swap(_pack(env, "v1", 1))
    assert swap_result["ok"] and swap_result["version"] == 1
    assert host.active()["active"] == swap_result["active"]


def test_swap_chain_reconstructs_from_ledger(env):
    host = _host(env)
    h1 = host.swap(_pack(env, "v1", 1))["active"]
    h2 = host.swap(_pack(env, "v2", 2, hot=80))["active"]
    swaps = [event for event in host.history() if event["action"] == "swap"]
    assert [swap["data"]["to_hash"] for swap in swaps] == [h1, h2]
    assert swaps[1]["data"]["from_hash"] == h1          # chain is linked
    assert host.audit.verify_log()                       # Merkle-intact


def test_rollback_replay_is_rejected_and_logged(env):
    host = _host(env)
    host.swap(_pack(env, "v2", 2))
    swap_result = host.swap(_pack(env, "v1", 1))                    # older version -> replay
    assert not swap_result["ok"] and any("version:not-monotonic" in reason for reason in swap_result["reasons"])
    rej = [event for event in host.history() if event["action"] == "swap_rejected"]
    assert len(rej) == 1 and host.active()["version"] == 2


def test_out_of_envelope_swap_rejected_active_unchanged(env):
    host = _host(env)
    host.swap(_pack(env, "v1", 1))
    before = host.active()
    # a pack that adds a field the envelope never provisioned
    bad = _pack(env, "bad", 2, fields={"temp": "int", "humidity": "int"})
    # rewrite the flow to actually use humidity so the field lands in the manifest schema
    ppt = env["tmp"] / "bad.ppt"
    ppt.write_bytes(pc.compile_flow(parse(
        "# f\n## start\n-> hot: when humidity >= 5\n-> cold: else\n## hot\n-> end\n## cold\n-> end\n## end\n"
    )).serialize())
    pp.build_pack(str(ppt), {"humidity": "int"}, version=2, envelope_id="env1",
                  priv_path=env["keys"]["private"], pub_path=env["keys"]["public"])
    swap_result = host.swap(str(ppt))
    assert not swap_result["ok"] and any("unknown-field" in reason for reason in swap_result["reasons"])
    assert host.active() == before                        # untouched


def test_tampered_image_rejected(env):
    host = _host(env)
    pack_path = _pack(env, "v1", 1)
    raw = bytearray(Path(pack_path).read_bytes()); raw[-1] ^= 1; Path(pack_path).write_bytes(bytes(raw))
    swap_result = host.swap(pack_path)
    assert not swap_result["ok"] and swap_result["reasons"] == ["image:sha256-mismatch"]
    assert host.active()["active"] is None


def test_rollback_restores_previous(env):
    host = _host(env)
    h1 = host.swap(_pack(env, "v1", 1))["active"]
    host.swap(_pack(env, "v2", 2, hot=80))
    rollback_result = host.rollback()
    assert rollback_result["ok"] and rollback_result["active"] == h1
    assert [event["action"] for event in host.history()][-1] == "rollback"


def test_strict_raises(env):
    host = _host(env)
    host.swap(_pack(env, "v2", 2))
    with pytest.raises(ph.SwapRejected):
        host.swap(_pack(env, "v1", 1), strict=True)


def test_allow_unsigned_stamps_the_event(env):
    host = _host(env)
    ppt = env["tmp"] / "raw.ppt"
    ppt.write_bytes(pc.compile_flow(parse(_flow(100))).serialize())
    swap_result = host.swap(str(ppt), allow_unsigned=True)
    assert swap_result["ok"] and swap_result["unsigned"] is True
    ev = [event for event in host.history() if event["action"] == "swap"][-1]
    assert ev["data"]["unsigned"] is True


def test_attest_writes_a_ledger_row(env):
    host = _host(env)
    host.swap(_pack(env, "v1", 1))
    host.attest()
    att = [event for event in host.history() if event["action"] == "attestation"]
    assert len(att) == 1 and att[0]["data"]["version"] == 1


def test_unexpected_exception_is_atomic(env, monkeypatch):
    """The flip is the last statement: an uncaught exception mid-pipeline propagates but never
    leaves a partially-applied policy."""
    host = _host(env)
    host.swap(_pack(env, "v1", 1))
    before = host.active()
    monkeypatch.setattr(pp, "check_envelope",
                        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError, match="boom"):
        host.swap(_pack(env, "v2", 2))
    assert host.active() == before                        # nothing flipped


def test_version_floor_persists_across_restart(env):
    host = _host(env)
    host.swap(_pack(env, "v3", 3))
    host2 = _host(env)                                    # fresh host, same state_dir
    swap_result = host2.swap(_pack(env, "v2", 2))                  # below the persisted floor
    assert not swap_result["ok"] and any("version:not-monotonic" in reason for reason in swap_result["reasons"])

def _events(host, action):
    return [event for event in host.audit.events if event["action"] == action]


def test_floor_write_failure_leaves_previous_policy_active(env, monkeypatch):
    """A failure after validation, at the version floor write, must not activate the new policy, must
    not record an accepted swap, and must let the same swap complete on retry."""
    host = _host(env)
    host.swap(_pack(env, "v1", 1))
    before = host.active()
    v2 = _pack(env, "v2", 2)
    real_persist = host._persist_version

    def failing_persist(version):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(host, "_persist_version", failing_persist)
    with pytest.raises(OSError):
        host.swap(v2)
    assert host.active() == before, "the previous policy stays active"
    assert host._stored_version() == 1, "the floor did not move"
    assert [event["data"]["version"] for event in _events(host, "swap")] == [1], "no accepted swap for version 2 was recorded"
    monkeypatch.setattr(host, "_persist_version", real_persist)
    result = host.swap(v2)
    assert result["ok"] and result["version"] == 2
    assert [event["data"]["version"] for event in _events(host, "swap")] == [1, 2]
    assert not os.path.exists(host._pending_path())


def test_evidence_write_failure_after_the_floor_is_recoverable(env, monkeypatch):
    """The floor advanced, the evidence did not: the previous policy stays active, a restart records the
    interruption, and the same image at the same version is admitted although the floor equals it."""
    from prismpath.ledgers import audit_log as audit_module
    host = _host(env)
    host.swap(_pack(env, "v1", 1))
    before = host.active()
    v2 = _pack(env, "v2", 2)

    def failing_append(*args, **kwargs):
        raise audit_module.AuditWriteError("disk gone")
    monkeypatch.setattr(host.audit, "append", failing_append)
    with pytest.raises(audit_module.AuditWriteError):
        host.swap(v2)
    assert host.active() == before
    assert host._stored_version() == 2, "the floor had already advanced when the evidence write failed"
    assert os.path.exists(host._pending_path()), "the intent record marks the interrupted commit"
    restarted = _host(env)
    assert [event["data"]["version"] for event in _events(restarted, "swap_incomplete")] == [2]
    other_image_same_version = restarted.swap(_pack(env, "v2b", 2, hot=50))
    assert not other_image_same_version["ok"], "a different image at the floor version is still rejected"
    result = restarted.swap(v2)
    assert result["ok"] and result["version"] == 2, "the interrupted swap completes on retry"
    assert not os.path.exists(restarted._pending_path())
    assert [event["data"]["version"] for event in _events(restarted, "swap")] == [1, 2]
    assert restarted.audit.verify_persisted()


def test_a_floor_below_the_intent_is_not_admitted_twice(env):
    """After a completed swap the intent record is gone, so the floor is strict again."""
    host = _host(env)
    host.swap(_pack(env, "v1", 1))
    host.swap(_pack(env, "v2", 2))
    again = host.swap(_pack(env, "v2c", 2, hot=60))
    assert not again["ok"] and any("version:not-monotonic" in reason for reason in again["reasons"])


def test_active_policy_survives_a_new_host(env):
    """The process that swapped is not the only one that knows what is active: `swap attest` and the
    console each build a fresh host over the state directory and must report the committed policy."""
    first = _host(env)
    accepted = first.swap(_pack(env, "v1", 1))
    second = _host(env)
    assert second.active()["active"] == accepted["active"]
    assert second.attest()["version"] == 1
    third_swap = second.swap(_pack(env, "v2", 2, hot=50))
    assert third_swap["ok"]
    assert _host(env).active()["active"] == third_swap["active"] != accepted["active"]
    rows = [ev for ev in AuditLog(str(env["tmp"] / "state" / "swaps.log")).events if ev["action"] == "attestation"]
    assert rows and rows[-1]["data"]["active"] == accepted["active"]


def test_a_tampered_active_image_is_not_restored(env):
    first = _host(env)
    accepted = first.swap(_pack(env, "v1", 1))
    (env["tmp"] / "state" / ph.image_file_name(accepted["active"])).write_bytes(b"not the image")
    second = _host(env)
    assert second.active() == {"active": None}
    last = AuditLog(str(env["tmp"] / "state" / "swaps.log")).events[-1]
    assert last["action"] == "active_unreadable"
    assert last["data"] == {"to_hash": accepted["active"], "reason": "image:digest-mismatch", "result": "not_restored"}


def test_a_record_that_is_not_an_object_is_not_restored(env):
    """A record that parses but is not an object, with its image gone too, must still get the audited
    fail closed answer at start rather than an exception from reading a field off a list."""
    state = env["tmp"] / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "active_policy.json").write_text('["not", "an", "object"]')
    host = _host(env)
    assert host.active() == {"active": None}
    last = AuditLog(str(state / "swaps.log")).events[-1]
    assert last["action"] == "active_unreadable"
    assert last["data"] == {"reason": "record:not-an-object", "result": "not_restored"}


def test_rollback_is_what_a_new_host_restores(env):
    host = _host(env)
    first = host.swap(_pack(env, "v1", 1))
    host.swap(_pack(env, "v2", 2, hot=50))
    assert host.rollback()["active"] == first["active"]
    assert _host(env).active()["active"] == first["active"]


# -- a death at any step of a commit, and the order a rollback commits in --

class _Died(Exception):
    """Stands for a process that stopped here."""


def _die_before(host, step, action):
    """Make the commit raise `_Died` before `step`; returns the undo."""
    from prismpath import canon
    saved = []

    def patch(target, name, replacement):
        saved.append((target, name, getattr(target, name)))
        setattr(target, name, replacement)

    def boom(*args, **kwargs):
        raise _Died(step)

    if step == "intent":
        patch(host, "_write_pending", boom)
    elif step == "floor":
        patch(host, "_persist_version", boom)
    elif step == "evidence":
        real = host.audit.append
        patch(host.audit, "append", lambda actor, name, data: boom() if name == action else real(actor, name, data))
    elif step == "active_image":
        real_bytes = canon.atomic_write_bytes
        patch(canon, "atomic_write_bytes",
              lambda path, data: boom() if os.path.basename(str(path)).startswith("active-") else real_bytes(path, data))
    elif step == "active_record":
        real_record = canon.atomic_write_bytes
        patch(canon, "atomic_write_bytes",
              lambda path, data: boom() if str(path).endswith("active_policy.json") else real_record(path, data))
    else:
        patch(host, "_clear_pending", boom)

    def undo():
        for target, name, original in reversed(saved):
            setattr(target, name, original)
    return undo


def _images(env):
    return sorted(name for name in os.listdir(env["tmp"] / "state") if name.startswith("active") and name.endswith(".ppt"))


SWAP_STEPS = ["intent", "floor", "evidence", "active_image", "active_record", "clear"]


@pytest.mark.parametrize("step", SWAP_STEPS)
def test_a_death_at_any_swap_step_leaves_one_policy_and_the_retry_completes(env, step):
    host = _host(env)
    h1 = host.swap(_pack(env, "v1", 1))["active"]
    v2 = _pack(env, "v2", 2, hot=80)
    undo = _die_before(host, step, "swap")
    try:
        with pytest.raises(_Died):
            host.swap(v2)
    finally:
        undo()
    restarted = _host(env)
    h2 = pp.sha256_hex(Path(v2).read_bytes())
    # the record flips at active_record's rename: before it the old policy, after it the new one
    assert restarted.active()["active"] == (h2 if step == "clear" else h1)
    assert not any(event["action"] == "active_unreadable" for event in restarted.audit.events)
    assert restarted.audit.verify_log() and restarted.audit.verify_persisted()
    done = restarted.swap(v2)
    if step == "clear":
        # the record had flipped and recovery finished the commit, so the swap is already done and the
        # floor refuses it a second time
        assert not done["ok"] and done["reasons"] == ["version:not-monotonic:2<=2"]
    else:
        assert done["ok"] and done["active"] == h2
    assert _images(env) == [ph.image_file_name(h2)] and not os.path.exists(restarted._pending_path())
    assert _host(env).active()["active"] == h2


@pytest.mark.parametrize("step", ["intent", "evidence", "active_image", "active_record", "clear"])
def test_a_death_at_any_rollback_step_leaves_one_policy(env, step):
    host = _host(env)
    h1 = host.swap(_pack(env, "v1", 1))["active"]
    h2 = host.swap(_pack(env, "v2", 2, hot=80))["active"]
    undo = _die_before(host, step, "rollback")
    try:
        with pytest.raises(_Died):
            host.rollback()
    finally:
        undo()
    restarted = _host(env)
    assert restarted.active()["active"] == (h1 if step == "clear" else h2)
    assert not any(event["action"] == "active_unreadable" for event in restarted.audit.events)
    assert restarted.audit.verify_log() and restarted.audit.verify_persisted()
    assert restarted._stored_version() == 2, "a rollback never moves the floor"
    # the next commit finishes and leaves one image, whatever the dead rollback left behind
    h3 = restarted.swap(_pack(env, "v3", 3, hot=60))["active"]
    assert _images(env) == [ph.image_file_name(h3)] and not os.path.exists(restarted._pending_path())


def test_the_old_image_is_readable_until_the_record_flips(env):
    host = _host(env)
    h1 = host.swap(_pack(env, "v1", 1))["active"]
    undo = _die_before(host, "active_record", "swap")
    try:
        with pytest.raises(_Died):
            host.swap(_pack(env, "v2", 2, hot=80))
    finally:
        undo()
    assert len(_images(env)) == 2, "the new image sits beside the one the record names"
    assert (env["tmp"] / "state" / ph.image_file_name(h1)).exists()
    assert _host(env).active()["active"] == h1


def test_a_stray_image_is_never_trusted(env):
    """An image no record names is ignored by a restart, even one holding the right bytes, and the commit
    that wants that name writes it again over whatever it holds."""
    host = _host(env)
    h1 = host.swap(_pack(env, "v1", 1))["active"]
    v2 = _pack(env, "v2", 2, hot=80)
    h2 = pp.sha256_hex(Path(v2).read_bytes())
    stray = env["tmp"] / "state" / ph.image_file_name(h2)
    stray.write_bytes(b"left by a process that died")
    assert _host(env).active()["active"] == h1
    assert host.swap(v2)["ok"]
    assert pp.sha256_hex(stray.read_bytes()) == h2
    assert _host(env).active()["active"] == h2 and _images(env) == [stray.name]


def test_a_rollback_that_cannot_write_its_event_changes_nothing(env, monkeypatch):
    from prismpath.ledgers import audit_log as audit_module
    host = _host(env)
    h1 = host.swap(_pack(env, "v1", 1))["active"]
    h2 = host.swap(_pack(env, "v2", 2, hot=80))["active"]
    record_before = (env["tmp"] / "state" / "active_policy.json").read_bytes()
    real = host.audit.append

    def failing(actor, action, data):
        if action == "rollback":
            raise audit_module.AuditWriteError("disk gone")
        return real(actor, action, data)
    monkeypatch.setattr(host.audit, "append", failing)
    with pytest.raises(audit_module.AuditWriteError):
        host.rollback()
    assert host.active()["active"] == h2, "the previous policy stays active"
    assert (env["tmp"] / "state" / "active_policy.json").read_bytes() == record_before
    assert _images(env) == [ph.image_file_name(h2)]
    assert not [event for event in host.history() if event["action"] == "rollback"]
    monkeypatch.setattr(host.audit, "append", real)
    assert host.rollback()["active"] == h1, "the rollback is still available and completes"
    assert _host(env).active()["active"] == h1


def test_an_old_layout_state_directory_is_read_and_migrated_by_the_next_swap(env):
    host = _host(env)
    h1 = host.swap(_pack(env, "v1", 1))["active"]
    state = env["tmp"] / "state"
    # rewrite what this host wrote into the layout before content addressed images
    (state / ph.image_file_name(h1)).rename(state / "active.ppt")
    record = json.loads((state / "active_policy.json").read_text())
    del record["image_file"]
    (state / "active_policy.json").write_text(json.dumps(record, sort_keys=True))
    old = _host(env)
    assert old.active()["active"] == h1, "the old layout is still restored"
    h2 = old.swap(_pack(env, "v2", 2, hot=80))["active"]
    assert _images(env) == [ph.image_file_name(h2)], "active.ppt is gone once the new layout's record is durable"
    assert json.loads((state / "active_policy.json").read_text())["image_file"] == ph.image_file_name(h2)
    assert _host(env).active()["active"] == h2


def test_a_record_naming_an_image_outside_the_layout_is_not_restored(env):
    host = _host(env)
    h1 = host.swap(_pack(env, "v1", 1))["active"]
    state = env["tmp"] / "state"
    record = json.loads((state / "active_policy.json").read_text())
    record["image_file"] = "../" + record["image_file"]
    (state / "active_policy.json").write_text(json.dumps(record, sort_keys=True))
    assert _host(env).active() == {"active": None}
    assert AuditLog(str(state / "swaps.log")).events[-1]["data"]["reason"] == "record:image-file-invalid"


@pytest.mark.parametrize("text", ["NaN", "1e400", "-Infinity"])
def test_a_record_holding_a_non_finite_number_is_not_restored(env, text):
    """Canonical JSON has no non finite number, so a record that holds one is damage: audited, not restored."""
    first = _host(env)
    first.swap(_pack(env, "v1", 1))
    record = env["tmp"] / "state" / "active_policy.json"
    record.write_text(record.read_text().replace('"version":1', f'"version":{text}'))
    assert _host(env).active() == {"active": None}
    last = AuditLog(str(env["tmp"] / "state" / "swaps.log")).events[-1]
    assert last["action"] == "active_unreadable"
    assert last["data"]["reason"].startswith("record:unreadable:") and last["data"]["result"] == "not_restored"


@pytest.mark.parametrize("record", ['{"to_hash": null, "version": NaN}', '{"to_hash": null, "version": 1e400}',
                                    '{"to_hash": "x", "version": 2, "op": "rollback", "extra": Infinity}'])
def test_an_intent_record_holding_a_non_finite_number_is_unreadable(env, record):
    host = _host(env)
    host.swap(_pack(env, "v1", 1))
    (env["tmp"] / "state" / "pending_swap").write_text(record)
    with pytest.raises(RuntimeError, match="unreadable intent record"):
        _host(env)
    with pytest.raises(RuntimeError, match="unreadable intent record"):
        host.swap(_pack(env, "v2", 2))
    assert host.active()["active"] is not None


def test_a_pack_whose_manifest_holds_a_non_finite_number_is_an_audited_bad_format_rejection(env):
    """`verify_pack` answers an unparseable manifest with `manifest:bad-format` instead of raising
    `CanonicalReadError`, so the swap audits a rejection and the Rust host does the same."""
    host = _host(env)
    host.swap(_pack(env, "v1", 1))
    path = _pack(env, "v2", 2)
    manifest = Path(path + ".manifest.json")
    original = manifest.read_text()
    for number in ("NaN", "1e400", "-Infinity"):
        manifest.write_text(original.replace('"version":2', f'"version":{number}'))
        events = len(host.audit.events)
        assert host.swap(path) == {"ok": False, "reasons": ["manifest:bad-format"]}
        assert len(host.audit.events) == events + 1 and host.audit.events[-1]["action"] == "swap_rejected"
        assert host.active()["version"] == 1
