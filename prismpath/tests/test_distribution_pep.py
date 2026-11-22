# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The enforcement point machine with the host adapter (spec-policy-distribution.md, sections 5, 6, 9, 12,
14 and 17). Each test names the conformance case of section 20 it covers. A restart is a fresh `Pep` over
the same state directory."""
from dataclasses import replace

import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.distribution import kinds, state_record  # noqa: E402
from prismpath.distribution.pep import Pep, PepRefused  # noqa: E402
from prismpath.distribution.adapters.host import HostAdapter  # noqa: E402
from prismpath.hotswap import policy_pack as pp  # noqa: E402
from prismpath.tests import _dist  # noqa: E402
from prismpath.tests._dist import STREAM, seal  # noqa: E402

OLD, NEW, NEWER = _dist.image(5), _dist.image(7), _dist.image(9)
H = canon.sha256_hex


def _read(point, signed):
    return state_record.read(signed, point.key.public_raw)


def _host_active(pep):
    return pep.adapter.host.active().get("active")


def _actions(pep):
    return [event["action"] for event in pep.audit.events]


@pytest.fixture
def point(tmp_path):
    return _dist.HostPep(tmp_path / "host")


def test_case_016_an_unreadable_trust_store_decides_nothing(point):
    """case_016: K1, X3. After the trust store becomes unreadable the restarted PEP refuses every envelope
    with dist:unknown-key, refuses every decision and its host holds no policy."""
    point.commit(OLD)
    trust = point.pep.store.path("trust.json")
    with open(trust, "rb+") as handle:
        handle.truncate(10)
    pep = point.open()
    assert pep.state() == "no-policy" and pep.refusal() == "dist:policy-lapsed" and _host_active(pep) is None
    assert _read(point, pep.stage(seal("policy.ppt", NEW, seq=2), NEW)).cause == "dist:unknown-key"


def test_case_017_an_instance_key_that_is_a_trusted_key_is_refused_at_start(tmp_path):
    """case_017: K2. At provisioning, and at a later start over a store that trusts it."""
    with pytest.raises(PepRefused):
        _dist.HostPep(tmp_path / "a", key=_dist.instance_key("A"))
    point = _dist.HostPep(tmp_path / "b", authorities=["A", "B"])
    point.key = _dist.instance_key("B")
    with pytest.raises(PepRefused):
        point.open()


def test_case_018_a_host_pep_with_an_authority_private_key_in_its_home_refuses_to_start(point):
    """case_018: K2. A PEM private key in the host's home whose public half the store trusts."""
    _priv, _pub, ser, _invalid = pp._ed25519()
    pem = _dist.GEN.test_key("A").private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    (point.state_dir / "keys").mkdir()
    (point.state_dir / "keys" / "authority.key").write_bytes(pem)
    with pytest.raises(PepRefused):
        point.open()
    other = _dist.GEN.test_key("U").private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    (point.state_dir / "keys" / "authority.key").write_bytes(other)
    assert point.open().state() == "no-policy"                       # a key the store does not trust


def test_case_019_commit_abort_an_offer_and_a_state_record_never_change_the_trust_store(point):
    """case_019: K3. The trust store of K1, its keys, retired keys, revocations, trust sequence and threshold.
    The time floor rides in the same file and rises with every verified envelope (V13)."""
    def k1(pep):
        doc = pep.trust.document()
        del doc["time_floor"]
        return doc
    before = k1(point.pep)
    point.commit(OLD)
    point.pep.stage(seal("policy.ppt", NEW, seq=2), NEW)
    point.pep.abort(STREAM, 2, H(NEW))
    point.pep.needs([H(NEW), H(NEWER)])
    point.pep.record("beat")
    point.pep.see_epoch(5)
    point.pep.commit(STREAM, 9, H(NEW))
    assert k1(point.pep) == before == k1(point.open())


def test_case_023_a_rollback_and_an_abort_leave_the_floor_where_it_was(point):
    """case_023: Q4, RB1, A1. The kept release carries a widening statement, so the rollback is not a silent
    widening (RB3)."""
    release = _dist.env.release_id([("policy.ppt", H(OLD))])
    point.pep.stage(seal("policy.ppt", OLD, seq=1, release=release), OLD)
    statement = _widening([])
    point.pep.stage(seal("trust.widening", statement, seq=1, release=release, policy_sha256=H(OLD)), statement)
    point.pep.commit(STREAM, 1, H(OLD))
    point.commit(NEW, seq=2)
    record = _read(point, point.pep.rollback())
    assert record.event == "rolled-back" and record.active_seq == 1 and record.floor == 2
    assert _host_active(point.pep) == H(OLD) and point.pep.floor.seq == 2
    point.pep.stage(seal("policy.ppt", NEWER, seq=3), NEWER)
    point.pep.abort(STREAM, 3, H(NEWER))
    pep = point.open()
    assert pep.floor.seq == 2 and pep.active.seq == 1 and pep.previous is None
    assert _read(point, pep.stage(seal("policy.ppt", NEW, seq=2), NEW)).event == "beat"   # Q3, at the floor
    assert _read(point, pep.stage(seal("policy.ppt", OLD, seq=1), OLD)).cause == "dist:seq-replay"


def test_case_024_a_floor_that_cannot_be_read_locks_the_pep(point):
    """case_024: Q5, X3."""
    point.commit(OLD)
    with open(point.pep.store.path("floor.json"), "wb") as handle:
        handle.write(b"{")
    pep = point.open()
    assert pep.state() == "locked" and pep.refusal() == "dist:floor-lost" and _host_active(pep) is None
    assert _read(point, pep.stage(seal("policy.ppt", NEW, seq=2), NEW)).cause == "dist:floor-lost"
    assert _read(point, pep.commit(STREAM, 1, H(OLD))).cause == "dist:floor-lost"
    assert _read(point, pep.record("beat")).state == "locked"


def test_case_026_a_clock_set_back_cannot_bring_an_expired_envelope_back(point):
    """case_026: T1, V13. The time floor is durable, so a restart with the clock set back still refuses."""
    late = _dist.EXPIRES - 100
    point.clock.now = late
    point.pep.stage(seal("policy.ppt", OLD, seq=1, not_before=late), OLD)
    point.clock.now = _dist.NOW
    early = seal("policy.ppt", NEW, seq=2, expires=late - 10)
    assert _read(point, point.pep.stage(early, NEW)).cause == "dist:expired"
    assert _read(point, point.open().stage(early, NEW)).cause == "dist:expired"


def test_case_043_another_policy_at_the_staged_seq_is_incomplete(point):
    """case_043: E7, V10."""
    point.pep.stage(seal("policy.ppt", OLD, seq=1), OLD)
    other = seal("policy.ppt", OLD, seq=1, policy_sha256="ab" * 32)
    assert _read(point, point.pep.stage(other, OLD)).cause == "dist:incomplete"
    assert point.pep.staged.policy_sha256 == H(OLD)


def test_case_046_staged_and_refused_are_acked_and_in_the_audit_log(point):
    """case_046: G1."""
    record = _read(point, point.pep.stage(seal("policy.ppt", OLD), OLD))
    assert record.event == "staged" and record.staged and record.staged_seq == 1 and record.cause is None
    refused = _read(point, point.pep.stage(seal("policy.ppt", NEW, seq=2, signer="U"), NEW))
    assert refused.event == "refused" and refused.cause == "dist:unknown-key"
    staged_events = [event for event in point.pep.audit.events if event["action"] in ("staged", "refused")]
    assert [(event["action"], event["data"].get("cause")) for event in staged_events] == [
        ("staged", None), ("refused", "dist:unknown-key")]
    assert point.open().staged.seq == 1                              # durable before the ack


def test_case_047_a_higher_seq_replaces_the_staged_release_and_a_lower_one_is_refused(point):
    """case_047: G2."""
    point.pep.stage(seal("policy.ppt", OLD, seq=2), OLD)
    assert _read(point, point.pep.stage(seal("policy.ppt", NEW, seq=3), NEW)).staged_seq == 3
    assert _read(point, point.pep.stage(seal("policy.ppt", OLD, seq=2), OLD)).cause == "dist:seq-replay"
    assert point.pep.staged.seq == 3 and point.pep.store.get(H(OLD)) is None


def test_case_048_a_commit_that_names_nothing_staged(point):
    """case_048: C1."""
    record = _read(point, point.pep.commit(STREAM, 1, H(OLD)))
    assert record.cause == "dist:not-staged" and record.state == "no-policy"
    point.pep.stage(seal("policy.ppt", OLD), OLD)
    assert _read(point, point.pep.commit(STREAM, 1, H(NEW))).cause == "dist:not-staged"
    assert point.pep.staged is not None


def test_case_050_a_staged_release_that_expires_or_is_revoked_before_its_commit_is_dropped(point):
    """case_050: C3. The revoked half stands for a revocation applied after staging, as the store holds it."""
    point.pep.stage(seal("policy.ppt", OLD, seq=1, expires=_dist.NOW + 10), OLD)
    point.clock.now = _dist.NOW + 10
    assert _read(point, point.pep.commit(STREAM, 1, H(OLD))).cause == "dist:expired" and point.pep.staged is None
    sealed = seal("policy.ppt", NEW, seq=2)
    point.pep.stage(sealed, NEW)
    point.pep.trust = replace(point.pep.trust, revoked_policies=frozenset({H(NEW)}))
    assert _read(point, point.pep.commit(STREAM, 2, H(NEW))).cause == "dist:revoked" and point.pep.staged is None
    assert point.pep.state() == "no-policy"


def test_case_052_a_commit_reports_committed_with_the_new_hash(point):
    """case_052: C5, H4."""
    record = _read(point, point.commit(OLD))
    assert record.event == "committed" and record.state == "active" and record.active_seq == 1 and record.floor == 1
    assert record.active_policy == bytes.fromhex(H(OLD))[:16] and not record.staged
    release = point.pep.active.release
    assert record.active_release == bytes.fromhex(release)[:16]
    assert _host_active(point.pep) == H(OLD)


def test_case_053_an_abort_drops_the_staged_release_and_an_abort_for_another_changes_nothing(point):
    """case_053: A1."""
    point.commit(OLD)
    point.pep.stage(seal("policy.ppt", NEW, seq=2), NEW)
    assert _read(point, point.pep.abort(STREAM, 3, H(NEW))).event == "beat" and point.pep.staged is not None
    record = _read(point, point.pep.abort(STREAM, 2, H(NEW)))
    assert record.event == "aborted" and not record.staged and record.active_seq == 1 and record.floor == 1
    assert "aborted" in _actions(point.pep) and point.open().staged is None


def test_case_077_a_release_lapses_at_expiry_with_no_message(point):
    """case_077: X1, X2, X3."""
    point.commit(OLD)
    point.clock.now = _dist.EXPIRES - 1
    assert point.pep.tick() is None and point.pep.refusal() is None
    point.clock.now = _dist.EXPIRES
    record = _read(point, point.pep.tick())
    assert (record.event, record.cause, record.state) == ("lapsed", "dist:expired", "no-policy")
    assert point.pep.refusal() == "dist:policy-lapsed" and _host_active(point.pep) is None
    assert point.open().state() == "no-policy" and point.pep.tick() is None


def test_case_078_a_cut_off_pep_decides_under_a_revoked_release_until_it_expires_and_not_after(point):
    """case_078: X2. The authority revoked the release, and this PEP never heard: its store holds no
    revocation, so it decides until the envelope's expiry, which bounds the exposure."""
    point.commit(OLD)
    for now in (_dist.NOW, _dist.EXPIRES - 1):
        point.clock.now = now
        point.pep.tick()
        assert point.pep.refusal() is None
    point.clock.now = _dist.EXPIRES
    point.pep.tick()
    assert point.pep.refusal() == "dist:policy-lapsed"


def test_case_082_a_pep_with_an_empty_trust_store_takes_no_rotation(tmp_path):
    """case_082: P1. No message installs a first key."""
    point = _dist.HostPep.__new__(_dist.HostPep)
    point.state_dir, point.clock, point.key, point.authorities = tmp_path, _dist.Clock(), _dist.instance_key(), ["A"]
    point.expiry_response = "refuse"
    pep = point.open(provision=False)
    rotation = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-rotation/1",
                                   "add": _dist.GEN.public_raw(_dist.GEN.test_key("B")).hex(), "retire": ""})
    sealed = seal("trust.rotation", rotation, stream="@trust", signer="B")
    assert _read(point, pep.stage(sealed, rotation)).cause == "dist:unknown-key"
    assert not pep.store.exists("trust.json") and not pep.trust.keys


def test_case_083_an_anchor_the_operator_has_not_confirmed_follows_no_stream(tmp_path):
    """case_083: P2."""
    point = _dist.HostPep.__new__(_dist.HostPep)
    point.state_dir, point.clock, point.key, point.authorities = tmp_path, _dist.Clock(), _dist.instance_key(), ["A"]
    point.expiry_response = "refuse"
    pep = point.open(provision=False)
    fingerprint = pep.provision(point.anchor())
    assert fingerprint == H(point.anchor())
    assert _read(point, pep.stage(seal("policy.ppt", OLD), OLD)).cause == "dist:unknown-key"
    pep = point.open(provision=False)
    assert not pep.provisioned
    with pytest.raises(PepRefused):
        pep.confirm("00" * 32)
    pep.confirm(fingerprint)
    assert _read(point, pep.stage(seal("policy.ppt", OLD), OLD)).event == "staged"


def test_case_084_provisioning_unlocks_a_locked_pep(point):
    """case_084: P3, Q5. Provisioning starts the trust store, the floor and the time floor again, and is its
    own event in the audit log."""
    point.commit(OLD, seq=4)
    with open(point.pep.store.path("floor.json"), "wb") as handle:
        handle.write(b"")
    pep = point.open()
    assert pep.state() == "locked"
    record = _read(point, pep.confirm(pep.provision(point.anchor())))
    assert record.event == "provisioned" and record.state == "no-policy" and record.floor == 0
    assert "provisioned" in _actions(pep) and pep.refusal() == "dist:policy-lapsed"
    assert point.open().state() == "no-policy"


def test_case_101_a_pep_that_committed_refuses_the_older_pack_form(point, tmp_path):
    """case_101: L2. A valid ppt-pack/1 with a higher version, swapped into the host the PEP follows."""
    point.commit(OLD)
    keys = pp.keygen(str(tmp_path / "keys"))
    ppt = tmp_path / "policy.ppt"
    ppt.write_bytes(NEW)
    pp.build_pack(str(ppt), {"x": "int"}, 99, "dist-demo", keys["private"], keys["public"])
    from prismpath.hotswap.policy_host import PolicyHost
    host = PolicyHost(str(point.state_dir), [keys["public"]], dict(_dist.GEN.QUALIFICATION), instance_key=point.key)
    assert host.swap(str(ppt)) == {"ok": False, "reasons": ["dist:legacy-refused"]}
    assert host.rollback() == {"ok": False, "reasons": ["dist:legacy-refused"]}
    assert host.active()["active"] == H(OLD)


def test_the_older_pack_form_still_swaps_where_nothing_was_distributed(tmp_path):
    """L2, L3: a host whose state directory holds no distribution floor, or one that was provisioned and
    committed nothing, swaps a ppt-pack/1 as before."""
    keys = pp.keygen(str(tmp_path / "keys"))
    ppt = tmp_path / "policy.ppt"
    ppt.write_bytes(NEW)
    pp.build_pack(str(ppt), {"x": "int"}, 1, "dist-demo", keys["private"], keys["public"])
    from prismpath.hotswap.policy_host import PolicyHost
    point = _dist.HostPep(tmp_path / "host")
    host = PolicyHost(str(point.state_dir), [keys["public"]], dict(_dist.GEN.QUALIFICATION), instance_key=point.key)
    assert host.swap(str(ppt))["ok"]


def test_case_103_the_forms_that_are_not_distributed_verify_as_before(point, tmp_path):
    """case_103: L4. A flow manifest, a qualification envelope and the root statements over the PEP's own
    audit log, beside a PEP that committed a release."""
    from prismpath.hotswap import flow_authority
    point.commit(OLD)
    keys = pp.keygen(str(tmp_path / "keys"))
    flow = tmp_path / "flow.md"
    flow.write_text((_dist.REPO / "tests" / "fixtures" / "alert_router.md").read_text(encoding="utf-8"))
    flow_authority.sign_flow(str(flow), 1, keys["private"], keys["public"])
    assert flow_authority.verify_flow(str(flow), [keys["public"]])[0]
    pp.build_envelope("dist-demo", {"x": "int"}, None, keys["private"], keys["public"], str(tmp_path / "env"))
    envelope, reasons = pp.load_envelope(str(tmp_path / "env" / "dist-demo.envelope"), [keys["public"]])
    assert envelope is not None and reasons == []
    report = point.pep.audit.verify_statements([point.key.public_raw])
    assert report["status"] == "signed" and report["pinned"] and report["findings"] == []


def test_case_126_a_declared_spiral_sidecar_is_needed_and_must_be_the_declared_one(point):
    """case_126: V11, C2. With no policy.spiral the commit is spiral:sidecar-missing, with a wrong one
    spiral:sidecar-hash-mismatch, and with the right one it commits. A packing without its sidecar hash is
    refused when it is staged."""
    sidecar, wrong = b"spiral sidecar bytes", b"another sidecar"
    meta = {**_dist.GEN.image_meta(OLD), "packing": {"profile": "spiral", "sidecar_sha256": H(sidecar)}}
    for seq, spiral, cause in ((1, None, "spiral:sidecar-missing"), (2, wrong, "spiral:sidecar-hash-mismatch"),
                               (3, sidecar, None)):
        pairs = [("policy.ppt", H(OLD))] + ([("policy.spiral", H(spiral))] if spiral else [])
        release = _dist.env.release_id(pairs)
        point.pep.stage(seal("policy.ppt", OLD, seq=seq, meta=meta, release=release, policy_sha256=H(OLD)), OLD)
        if spiral:
            ack = point.pep.stage(seal("policy.spiral", spiral, seq=seq, release=release, policy_sha256=H(OLD)), spiral)
            assert _read(point, ack).event == "staged"
        record = _read(point, point.pep.commit(STREAM, seq, H(OLD)))
        assert record.cause == cause, seq
    assert point.pep.active.seq == 3 and point.pep.active.bodies["policy.spiral"] == sidecar
    bare = {**_dist.GEN.image_meta(NEW), "packing": {"profile": "spiral"}}
    assert _read(point, point.pep.stage(seal("policy.ppt", NEW, seq=4, meta=bare), NEW)).cause == "packing:unknown-profile"


def test_case_111_a_host_pep_refuses_to_start_with_hold(tmp_path):
    """case_111: X6, X10. A host has no HOLD setting, so a host PEP given one refuses to start, and so does a
    PEP of a kind with no row yet (the agent, gateway and xdp rows join the table with their adapters)."""
    with pytest.raises(PepRefused):
        _dist.HostPep(tmp_path, expiry_response="hold")

    class Agent(HostAdapter):
        kind = "agent"
    with pytest.raises(PepRefused):
        Pep(str(tmp_path / "agent"), Agent(_dist.HostPep(tmp_path / "h").host()), _dist.instance_key(), _dist.Clock())


def test_the_hold_machine_on_a_kind_that_allows_hold(tmp_path, monkeypatch):
    """X7 to X9 on the machine itself, with the host row given the column that only mesh and cfs carry. The
    mesh and cfs targets the conformance cases name join the table with their own rows."""
    monkeypatch.setitem(kinds.TARGETS, "host", replace(kinds.TARGETS["host"], expiry_hold=True))
    point = _dist.HostPep(tmp_path, expiry_response="hold")
    point.commit(OLD, seq=1)
    point.commit(NEW, seq=2)
    point.clock.now = _dist.EXPIRES
    record = _read(point, point.pep.tick())
    assert (record.event, record.cause, record.state, record.held) == ("held", "dist:held", "active", True)
    assert point.pep.refusal() is None and point.pep.receipt_mark() == "held" and point.pep.tick() is None
    assert _read(point, point.pep.record("beat")).held
    assert _read(point, point.pep.rollback()).cause == "dist:held" and point.pep.active.seq == 2
    replay = seal("policy.ppt", OLD, seq=1, not_before=_dist.EXPIRES, expires=_dist.EXPIRES + 1000)
    assert _read(point, point.pep.stage(replay, OLD)).cause == "dist:seq-replay"           # X8
    later = seal("policy.ppt", NEWER, seq=3, not_before=_dist.EXPIRES, expires=_dist.EXPIRES + 1000)
    point.pep.stage(later, NEWER)
    committed = _read(point, point.pep.commit(STREAM, 3, H(NEWER)))
    assert committed.event == "committed" and not committed.held and point.pep.receipt_mark() is None
    assert point.open().expiry_response == "hold"


def test_a_commit_with_an_unreadable_trust_store_never_activates_the_runtime(point):
    """K1, X3: a release staged before the store became unreadable is not committed, and the host stays
    without a policy."""
    point.pep.stage(seal("policy.ppt", OLD), OLD)
    with open(point.pep.store.path("trust.json"), "wb") as handle:
        handle.write(b"")
    pep = point.open()
    assert pep.staged is not None
    assert _read(point, pep.commit(STREAM, 1, H(OLD))).cause == "dist:unknown-key"
    assert pep.active is None and _host_active(pep) is None and pep.refusal() == "dist:policy-lapsed"


@pytest.mark.parametrize("entry", ["record", "abort", "commit", "stage", "rollback"])
def test_every_entry_point_checks_expiry_before_it_reports(tmp_path, entry):
    """X1: a release past its expiry has lapsed before any record says otherwise, and the lapse is reported
    first, in the order the records were made."""
    point = _dist.HostPep(tmp_path)
    point.commit(OLD)
    point.clock.now = _dist.EXPIRES
    point.pep.drain()
    calls = {"record": lambda pep: pep.record("beat"), "abort": lambda pep: pep.abort(STREAM, 9, H(NEW)),
             "commit": lambda pep: pep.commit(STREAM, 9, H(NEW)), "stage": lambda pep: pep.stage(b"", b""),
             "rollback": lambda pep: pep.rollback()}
    if entry == "rollback":
        with pytest.raises(PepRefused):
            calls[entry](point.pep)
    else:
        record = _read(point, calls[entry](point.pep))
        assert record.state == "no-policy" and record.active_seq == 0
    sent = [_read(point, data) for data in point.pep.drain()]
    assert sent[0].event == "lapsed" and sent[0].cause == "dist:expired"
    assert _host_active(point.pep) is None


def test_the_counter_survives_a_lost_floor(point):
    """H3: the counter is kept apart from the floor, so a locked PEP never sends a counter again."""
    point.commit(OLD)
    sent = _read(point, point.pep.record("beat")).counter
    with open(point.pep.store.path("floor.json"), "wb") as handle:
        handle.write(b"")
    pep = point.open()
    assert pep.state() == "locked" and _read(point, pep.record("beat")).counter > sent
    assert _read(point, point.open().record("beat")).counter > sent + 1


def test_the_older_path_stays_closed_when_the_floor_file_is_missing(point, tmp_path):
    """L2: a provisioned PEP whose floor file is gone opens no way around it for a ppt-pack/1."""
    point.commit(OLD)
    keys = pp.keygen(str(tmp_path / "keys"))
    ppt = tmp_path / "policy.ppt"
    ppt.write_bytes(NEW)
    pp.build_pack(str(ppt), {"x": "int"}, 99, "dist-demo", keys["private"], keys["public"])
    from prismpath.hotswap.policy_host import PolicyHost
    import os
    os.remove(point.pep.store.path("floor.json"))
    host = PolicyHost(str(point.state_dir), [keys["public"]], dict(_dist.GEN.QUALIFICATION), instance_key=point.key)
    assert host.swap(str(ppt)) == {"ok": False, "reasons": ["dist:legacy-refused"]}


def test_no_record_is_refused_without_a_cause(point):
    """H1: a verified trust statement is refused with dist:target-mismatch until its kind is applied, a
    rollback with nothing kept is an error and no record, and a refused record always carries its cause."""
    revocation = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "envelopes": [], "floors": {},
                                     "format": "prismpath.dist-revocation/1", "keys": [], "policies": []})
    record = _read(point, point.pep.stage(seal("trust.revocation", revocation, stream="@trust"), revocation))
    assert (record.event, record.cause) == ("refused", "dist:target-mismatch")
    counter = point.pep.counter
    with pytest.raises(PepRefused):
        point.pep.rollback()
    assert point.pep.counter == counter
    with pytest.raises(ValueError):
        state_record.StateRecord(event="refused", state="no-policy", cause=None, pep_id=b"\0" * 16, counter=1,
                                 time=0, stream=b"\0" * 16).unsigned_bytes()


def _widening(froms):
    return canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-widening/1",
                               "from": sorted(froms)})


def test_a_rollback_on_a_target_that_cannot_decide_needs_a_covering_widening_statement(point):
    """RB3, W2: the host cannot decide larger, so a rollback to the kept release is refused with
    dist:widening-unsigned unless that release holds a widening statement whose from is empty or holds the
    active policy hash. This is case 55's half for a target that cannot decide."""
    point.commit(OLD, seq=1)
    point.commit(NEW, seq=2)
    assert _read(point, point.pep.rollback()).cause == "dist:widening-unsigned" and point.pep.active.seq == 2
    for seq, froms, cause in ((3, [H(NEWER)], "dist:widening-unsigned"), (5, [H(NEW)], None), (7, [], None)):
        point.pep = point.open()
        release = _dist.env.release_id([("policy.ppt", H(OLD))])
        point.pep.stage(seal("policy.ppt", OLD, seq=seq, release=release), OLD)
        statement = _widening(froms)
        point.pep.stage(seal("trust.widening", statement, seq=seq, release=release, policy_sha256=H(OLD)), statement)
        point.pep.commit(STREAM, seq, H(OLD))
        point.pep.stage(seal("policy.ppt", NEW, seq=seq + 1), NEW)
        point.pep.commit(STREAM, seq + 1, H(NEW))
        record = _read(point, point.pep.rollback())
        assert record.cause == cause, froms
        assert point.pep.active.seq == (seq if cause is None else seq + 1)
