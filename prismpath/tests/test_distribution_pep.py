# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The enforcement point machine with the host adapter (spec-policy-distribution.md, sections 5, 6, 9, 12,
14 and 17). Each test names the conformance case of section 20 it covers. A restart is a fresh `Pep` over
the same state directory."""
from dataclasses import replace

import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.distribution import state_record  # noqa: E402
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
    assert _read(point, point.stage(NEW, seq=2, pep=pep)).cause == "dist:unknown-key"


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
    from cryptography.hazmat.primitives import serialization as ser
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
    point.stage(NEW, seq=2)
    point.pep.abort(STREAM, 2, H(NEW))
    point.pep.needs([H(NEW), H(NEWER)])
    point.pep.record("beat")
    point.pep.take_statement(b"PPEP" + bytes(98))                  # a statement no key verifies (H9)
    point.pep.commit(STREAM, 9, H(NEW))
    assert k1(point.pep) == before == k1(point.open())


def test_case_023_a_rollback_and_an_abort_leave_the_floor_where_it_was(point):
    """case_023: Q4, RB1, A1. The kept release carries a widening statement, so the rollback is not a silent
    widening (RB3)."""
    release = _dist.env.release_id([("policy.ppt", H(OLD))])
    point.stage(OLD, seq=1, release=release)
    statement = _widening([])
    point.pep.stage(seal("trust.widening", statement, seq=1, release=release, policy_sha256=H(OLD)), statement)
    point.pep.commit(STREAM, 1, H(OLD))
    point.commit(NEW, seq=2)
    record = _read(point, point.pep.rollback())
    assert record.event == "rolled-back" and record.active_seq == 1 and record.floor == 2
    assert _host_active(point.pep) == H(OLD) and point.pep.floor.seq == 2
    point.stage(NEWER, seq=3)
    point.pep.abort(STREAM, 3, H(NEWER))
    pep = point.open()
    assert pep.floor.seq == 2 and pep.active.seq == 1 and pep.previous is None
    assert _read(point, point.stage(NEW, seq=2, pep=pep)).event == "beat"   # Q3, at the floor
    assert _read(point, point.stage(OLD, seq=1, pep=pep)).cause == "dist:seq-replay"


def test_case_024_a_floor_that_cannot_be_read_locks_the_pep(point):
    """case_024: Q5, X3."""
    point.commit(OLD)
    with open(point.pep.store.path("floor.json"), "wb") as handle:
        handle.write(b"{")
    pep = point.open()
    assert pep.state() == "locked" and pep.refusal() == "dist:floor-lost" and _host_active(pep) is None
    assert _read(point, point.stage(NEW, seq=2, pep=pep)).cause == "dist:floor-lost"
    assert _read(point, pep.commit(STREAM, 1, H(OLD))).cause == "dist:floor-lost"
    assert _read(point, pep.record("beat")).state == "locked"


def test_case_026_a_clock_set_back_cannot_bring_an_expired_envelope_back(point):
    """case_026: T1, V13. The time floor is durable, so a restart with the clock set back still refuses."""
    late = _dist.EXPIRES - 100
    point.clock.now = late
    point.stage(OLD, seq=1, not_before=late)
    point.clock.now = _dist.NOW
    early = seal("policy.ppt", NEW, seq=2, expires=late - 10)
    assert _read(point, point.pep.stage(early, NEW)).cause == "dist:expired"
    assert _read(point, point.open().stage(early, NEW)).cause == "dist:expired"


def test_case_043_another_policy_at_the_staged_seq_is_incomplete(point):
    """case_043: E7, V10."""
    point.stage(OLD, seq=1)
    other = seal("policy.ppt", OLD, seq=1, policy_sha256="ab" * 32)
    assert _read(point, point.pep.stage(other, OLD)).cause == "dist:incomplete"
    assert point.pep.staged.policy_sha256 == H(OLD)


def test_case_308_a_withheld_artifact_at_commit_on_host_is_incomplete(point):
    """case_308: C2, E10, the `host` half. A release whose signed release id covers a `policy.ppt` and a
    `policy.spiral` is committed with only its `policy.ppt` staged: `dist:incomplete`, and the release active before
    stays active. The same table with a release id over what is staged then commits."""
    from prismpath.distribution import envelope as env
    point.commit(OLD)
    release = env.release_id([("policy.ppt", H(NEW)), ("policy.spiral", H(b"a withheld spiral"))])
    record = _read(point, point.commit(NEW, 2, release=release))
    assert (record.event, record.cause) == ("refused", "dist:incomplete")
    assert point.pep.active.policy_sha256 == H(OLD) and point.pep.floor.seq == 1
    assert _read(point, point.commit(NEW, 3)).event == "committed"


def test_case_046_staged_and_refused_are_acked_and_in_the_audit_log(point):
    """case_046: G1."""
    record = _read(point, point.stage(OLD))
    assert record.event == "staged" and record.staged and record.staged_seq == 1 and record.cause is None
    refused = _read(point, point.pep.stage(point.seal(NEW, seq=2, signer="U"), NEW))
    assert refused.event == "refused" and refused.cause == "dist:unknown-key"
    staged_events = [event for event in point.pep.audit.events if event["action"] in ("staged", "refused")]
    assert [(event["action"], event["data"].get("artifact"), event["data"].get("cause"))
            for event in staged_events] == [("staged", "trust.widening", None), ("staged", "policy.ppt", None),
                                            ("refused", None, "dist:unknown-key")]
    assert point.open().staged.seq == 1                              # durable before the ack


def test_case_047_a_higher_seq_replaces_the_staged_release_and_a_lower_one_is_refused(point):
    """case_047: G2."""
    point.stage(OLD, seq=2)
    assert _read(point, point.stage(NEW, seq=3)).staged_seq == 3
    assert _read(point, point.stage(OLD, seq=2)).cause == "dist:seq-replay"
    assert point.pep.staged.seq == 3 and point.pep.store.get(H(OLD)) is None


def test_case_048_a_commit_that_names_nothing_staged(point):
    """case_048: C1."""
    record = _read(point, point.pep.commit(STREAM, 1, H(OLD)))
    assert record.cause == "dist:not-staged" and record.state == "no-policy"
    point.stage(OLD)
    assert _read(point, point.pep.commit(STREAM, 1, H(NEW))).cause == "dist:not-staged"
    assert point.pep.staged is not None


def test_case_050_a_staged_release_that_expires_or_is_revoked_before_its_commit_is_dropped(point):
    """case_050: C3. The revoked half stands for a revocation applied after staging, as the store holds it."""
    point.stage(OLD, seq=1, expires=_dist.NOW + 10)
    point.clock.now = _dist.NOW + 10
    assert _read(point, point.pep.commit(STREAM, 1, H(OLD))).cause == "dist:expired" and point.pep.staged is None
    point.stage(NEW, seq=2)
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
    point.stage(NEW, seq=2)
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
    assert _read(point, point.stage(OLD, pep=pep)).cause == "dist:unknown-key"
    pep = point.open(provision=False)
    assert not pep.provisioned
    with pytest.raises(PepRefused):
        pep.confirm("00" * 32)
    pep.confirm(fingerprint)
    assert _read(point, point.stage(OLD, pep=pep)).event == "staged"


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
    spiral:sidecar-hash-mismatch, and with the right one it commits. A packing whose profile is not the
    spiral is refused when it is staged, and one without its sidecar hash is not of its form (case 127)."""
    sidecar, wrong = b"spiral sidecar bytes", b"another sidecar"
    meta = {**_dist.GEN.image_meta(OLD), "packing": {"profile": "spiral", "sidecar_sha256": H(sidecar)}}
    for seq, spiral, cause in ((1, None, "spiral:sidecar-missing"), (2, wrong, "spiral:sidecar-hash-mismatch"),
                               (3, sidecar, None)):
        pairs = [("policy.ppt", H(OLD))] + ([("policy.spiral", H(spiral))] if spiral else [])
        release = _dist.env.release_id(pairs)
        point.stage(OLD, seq=seq, meta=meta, release=release, policy_sha256=H(OLD))
        if spiral:
            ack = point.pep.stage(seal("policy.spiral", spiral, seq=seq, release=release, policy_sha256=H(OLD),
                                       widens=True), spiral)
            assert _read(point, ack).event == "staged"
        record = _read(point, point.pep.commit(STREAM, seq, H(OLD)))
        assert record.cause == cause, seq
    assert point.pep.active.seq == 3 and point.pep.active.bodies["policy.spiral"] == sidecar
    other = {**_dist.GEN.image_meta(NEW), "packing": {"profile": "zigzag", "sidecar_sha256": H(sidecar)}}
    assert _read(point, point.stage(NEW, seq=4, meta=other)).cause == "packing:unknown-profile"


def test_case_111_a_host_pep_refuses_to_start_with_hold(tmp_path, monkeypatch):
    """case_111: X6, X10. A host has no HOLD setting, so a host PEP given one refuses to start, as do an agent and a
    gateway PEP (the xdp PEP is test_distribution_xdp.py's). A PEP of a
    kind whose row is not in the table refuses to start whatever its setting: every kind of the closed list has a
    row now, so the test takes the xdp row out to show it."""
    from prismpath.distribution import kinds
    from prismpath.agent.dist_kind import AgentHomeAdapter
    from prismpath.gateway.dist_kind import GatewayHomeAdapter
    with pytest.raises(PepRefused):
        _dist.HostPep(tmp_path, expiry_response="hold")
    for name, adapter in (("agent", AgentHomeAdapter), ("gateway", GatewayHomeAdapter)):
        with pytest.raises(PepRefused, match="no HOLD setting"):
            Pep(str(tmp_path / name), adapter(tmp_path / name), _dist.instance_key(), _dist.Clock(),
                expiry_response="hold")

    class Edge(HostAdapter):
        kind = "xdp"
    monkeypatch.delitem(kinds.TARGETS, "xdp")
    with pytest.raises(PepRefused, match="no enforcement point"):
        Pep(str(tmp_path / "xdp"), Edge(_dist.HostPep(tmp_path / "h").host()), _dist.instance_key(), _dist.Clock())


def _mesh(tmp_path):
    from prismpath.kernel import ppt_compile
    counter = iter(range(100))
    images = [ppt_compile.compile_predicate(f"when x >= {n}") for n in (5, 7)]
    regs = ppt_compile.encode_regs(images[0], {"x": 6})

    def make(**settings):
        return _dist.MeshPep(tmp_path / f"node{next(counter)}", **settings)
    return make, [image.serialize() for image in images], (lambda pep: pep.adapter.decide(regs))


def test_case_106_a_mesh_node_left_at_refuse_lapses_at_expiry(tmp_path):
    """case_106: X6, X1, on a modelled mesh node. The cFS half is in integrations/cfs/tests."""
    _dist.case_106_refuse_lapses(*_mesh(tmp_path))


def test_case_107_a_mesh_node_on_hold_keeps_deciding_and_marks_everything(tmp_path):
    """case_107: X6, X7, on a modelled mesh node."""
    _dist.case_107_hold_keeps_deciding_and_marks_everything(*_mesh(tmp_path))


def test_case_108_a_revocation_ends_a_mesh_node_s_hold(tmp_path):
    """case_108: X8, R5, on a modelled mesh node."""
    _dist.case_108_a_revocation_ends_a_hold(*_mesh(tmp_path))


def test_case_110_a_held_mesh_node_never_widens(tmp_path):
    """case_110: X9, on a modelled mesh node."""
    _dist.case_110_a_held_pep_never_widens(*_mesh(tmp_path))


def test_case_112_no_message_changes_a_mesh_node_s_setting(tmp_path):
    """case_112: X10, on a modelled mesh node."""
    _dist.case_112_no_message_changes_the_setting(*_mesh(tmp_path))


def test_a_mesh_node_reads_a_table_with_its_own_parser_and_bound(tmp_path):
    """Section 3, E6: a mesh node ignores meta, so a table whose meta disagrees with it is admitted, and a body
    over 640 bytes is too large."""
    make, bodies, _decide = _mesh(tmp_path)
    point = make()
    wrong = {**_dist.GEN.image_meta(bodies[0]), "wcet_cycles": 1, "qualification": "elsewhere"}
    assert _read(point, point.stage(bodies[0], meta=wrong)).event == "staged"
    big = bodies[0] + b"\0" * 700
    assert _read(point, point.pep.stage(point.seal(big, seq=2), big)).cause == "dist:too-large"


def test_the_mesh_evaluator_agrees_with_the_predicate_reference():
    """The model's evaluator is the embedded PPT evaluator in Python. On every predicate vector the compiler
    takes, the start node's edge holds exactly when the Python predicate reference says the condition holds."""
    import json
    from prismpath.distribution.adapters.mesh import evaluate
    from prismpath.kernel import ppt_compile
    corpus = json.loads((_dist.REPO / "portable" / "conformance" / "predicates.json").read_text(encoding="utf-8"))
    checked = 0
    for case in corpus["cases"]:
        try:                                          # the compiler's declared subset: conditions and values it takes
            image = ppt_compile.compile_predicate(case["cond"])
            regs = ppt_compile.encode_regs(image, case["ctx"])
        except (ppt_compile.SubsetError, ValueError):
            continue
        step = evaluate(image.serialize(), regs, 0)
        assert (step is not None) == case["expect"], case
        checked += 1
    assert checked >= 100

def test_a_commit_with_an_unreadable_trust_store_never_activates_the_runtime(point):
    """K1, X3: a release staged before the store became unreadable is not committed, and the host stays
    without a policy."""
    point.stage(OLD)
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
    """H1: a refusal always carries its cause, a rollback with nothing kept is an error and no record, and a
    refused record without a cause cannot be built."""
    record = _read(point, point.pep.stage(seal("policy.ppt", OLD, targets=("mesh",)), OLD))
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
    point.commit(NEWER, seq=1)                   # the first install, with its statement
    point.widen(OLD, 2, [H(NEWER)], widens=True)  # each change of the table with a statement for what it replaces
    point.commit(OLD, seq=2, widens=True)
    point.widen(NEW, 3, [H(OLD)], widens=True)
    point.commit(NEW, seq=3, widens=True)
    assert _read(point, point.pep.rollback()).cause == "dist:widening-unsigned" and point.pep.active.seq == 3
    for name, froms, cause in (("another", [H(NEW)], "dist:widening-unsigned"), ("active", [H(NEWER)], None),
                               ("any", [], None)):
        other = _dist.HostPep(point.state_dir.parent / name)
        other.commit(NEW, seq=1)
        other.widen(OLD, 2, sorted({H(NEW), *froms}) if froms else [], widens=True)
        other.commit(OLD, seq=2, widens=True)                          # kept, with its statement
        other.commit(NEWER, seq=3)                                     # the release a rollback leaves
        record = _read(other, other.pep.rollback())
        assert record.cause == cause, froms
        assert other.pep.active.seq == (2 if cause is None else 3)


def test_a_mesh_node_reads_its_stored_envelopes_as_it_staged_them(tmp_path):
    """E9: a mesh node that staged an envelope whose meta it skips reads it back the same way after a restart."""
    make, bodies, _decide = _mesh(tmp_path)
    point = make()
    doc = _dist.GEN.envelope_doc(bodies[0], targets=["mesh"], meta={**_dist.GEN.image_meta(bodies[0]), "counts": 7},
                                 widens=True)
    sealed = _dist.env.seal(canon.canon2_bytes(doc), [_dist.GEN.test_key("A")])   # no writer emits it (F1)
    point.widen(bodies[0], widens=True)
    assert _read(point, point.pep.stage(sealed, bodies[0])).event == "staged"
    assert point.open().staged.seq == 1


def test_case_132_a_mesh_node_takes_a_full_size_list_and_holds_a_table_to_its_own_bound(tmp_path):
    """case_132: E6, V5, R7, B9, the PEP half (the frame half, a trust body offered over frames at 16,385 bytes,
    is the frame binding's). A full-size revocation list is applied under the trust bound, and a 641 byte table
    is dist:too-large from its signed size with no body given."""
    make, bodies, _decide = _mesh(tmp_path)
    point = make()
    assert _dist.GEN.replay(_corpus_case("132_a_full_size_revocation_list_on_mesh"))["cause"] is None
    assert _dist.GEN.replay(_corpus_case("132_a_641_byte_table_from_its_signed_size_on_mesh"))["cause"] == "dist:too-large"
    full = bytes.fromhex(_corpus_case("132_a_full_size_revocation_list_on_mesh")["body"])
    sealed = _dist.seal("trust.revocation", full, seq=1, stream="@trust", targets=("mesh",))
    assert len(full) > 640 and _read(point, point.pep.stage(sealed, full)).event == "trust-applied"
    big = bodies[0] + b"\0" * (641 - len(bodies[0]))
    assert _read(point, point.pep.stage(point.seal(big, seq=2), b"")).cause == "dist:too-large"


def _corpus_case(name):
    import json
    corpus = json.loads((_dist.REPO / "portable" / "conformance" / "distribution.json").read_text(encoding="utf-8"))
    return next(case for case in corpus["cases"] if case["name"] == name)


class _Monotonic:
    """A monotonic clock the test moves by hand, in seconds."""

    def __init__(self):
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def _delayed(point):
    monotonic = _Monotonic()
    point.pep = Pep(str(point.state_dir), point.adapter(), point.key, point.clock, monotonic=monotonic)
    return point.pep, monotonic


def test_a_commit_with_a_delay_is_active_at_the_peps_time_plus_the_delay_and_not_before(point):
    """B8 on the host (case 38 is the C core's). A commit with a delay of 120 milliseconds keeps the old
    release until the PEP's own monotonic time passes the delay, then commits on the next entry point."""
    point.commit(OLD)
    pep, monotonic = _delayed(point)
    point.stage(NEW, seq=2, pep=pep)
    record = _read(point, pep.commit(STREAM, 2, H(NEW), delay_ms=120))
    assert record.event == "beat" and record.active_seq == 1 and record.staged and _host_active(pep) == H(OLD)
    monotonic.now += 0.119
    assert pep.tick() is None and pep.active.seq == 1 and _host_active(pep) == H(OLD)
    monotonic.now += 0.001
    pep.tick()
    assert pep.active.seq == 2 and pep.floor.seq == 2 and _host_active(pep) == H(NEW) and pep.due is None
    assert "committed" in _actions(pep)


def test_a_delayed_commit_runs_its_checks_again_when_it_falls_due(point):
    """B8 with C3. A staged release that expires inside the delay is dropped when the delay ends and never
    becomes active, and the floor stays where it was."""
    point.commit(OLD)
    pep, monotonic = _delayed(point)
    point.stage(NEW, seq=2, expires=_dist.NOW + 10, pep=pep)
    pep.commit(STREAM, 2, H(NEW), delay_ms=500)
    point.clock.now = _dist.NOW + 10
    monotonic.now += 1.0
    pep.tick()
    assert pep.active.seq == 1 and pep.floor.seq == 1 and _host_active(pep) == H(OLD)
    assert pep.staged is None and pep.due is None


def test_a_revocation_inside_the_delay_drops_the_release_before_it_falls_due(point):
    """B8 with R5. A revocation of the staged envelope inside the delay drops it at once."""
    point.commit(OLD)
    pep, monotonic = _delayed(point)
    point.pep = pep
    point.stage(NEW, seq=2, pep=pep)
    pep.commit(STREAM, 2, H(NEW), delay_ms=500)
    point.revoke(1, envelopes=sorted(pep.staged.envelope_ids))
    monotonic.now += 1.0
    pep.tick()
    assert pep.active.seq == 1 and pep.staged is None and pep.due is None and _host_active(pep) == H(OLD)


def test_an_abort_inside_the_delay_cancels_the_delayed_commit(point):
    """B8 with A1. An abort that names the staged release drops it, so nothing flips when the time comes."""
    point.commit(OLD)
    pep, monotonic = _delayed(point)
    point.stage(NEW, seq=2, pep=pep)
    pep.commit(STREAM, 2, H(NEW), delay_ms=50)
    assert _read(point, pep.abort(STREAM, 2, H(NEW))).event == "aborted"
    monotonic.now += 1.0
    pep.tick()
    assert pep.active.seq == 1 and _host_active(pep) == H(OLD) and pep.due is None


def test_a_commit_delay_out_of_range_is_refused(point):
    """B8: the delay is two bytes on the wire, 0 to 65535 milliseconds."""
    point.stage(NEW, seq=1)
    for delay in (-1, 65536, 1.5, True):
        with pytest.raises(ValueError):
            point.pep.commit(STREAM, 1, H(NEW), delay_ms=delay)


def _kept(tmp_path, name, *, kept_expires=_dist.EXPIRES):
    """A host PEP trusting A and B whose kept release, seq 1 signed by A with a widening statement that covers any
    rollback (RB3), was replaced by seq 2 signed by B."""
    point = _dist.HostPep(tmp_path / name, authorities=["A", "B"])
    release = _dist.env.release_id([("policy.ppt", H(OLD))])
    kept = seal("policy.ppt", OLD, seq=1, release=release, expires=kept_expires, widens=True)
    statement = _widening([])
    point.pep.stage(seal("trust.widening", statement, seq=1, release=release, policy_sha256=H(OLD), widens=True),
                    statement)
    point.pep.stage(kept, OLD)
    point.pep.commit(STREAM, 1, H(OLD))
    point.commit(NEW, seq=2, signer="B")
    return point, _dist.env.envelope_id(_dist.env.unseal(kept)[0])


def test_case_054_a_rollback_is_held_to_what_a_commit_is_held_to(tmp_path):
    """case_054: RB2. A rollback to a kept release that has expired, that is revoked, whose only signing key is
    revoked, whose only signing key was retired, and that is below a raised floor is refused with the cause of
    the failed check, and the release active under B keeps deciding."""
    def refused(point):
        record = _read(point, point.pep.rollback())
        assert record.event == "refused" and point.pep.active.seq == 2 and _host_active(point.pep) == H(NEW)
        return record.cause

    point, _kept_id = _kept(tmp_path, "expired", kept_expires=_dist.NOW + 10)
    point.clock.now = _dist.NOW + 10
    assert refused(point) == "dist:expired"
    point, kept_id = _kept(tmp_path, "revoked")
    point.revoke(1, envelopes=[kept_id])
    assert refused(point) == "dist:revoked"
    point, _kept_id = _kept(tmp_path, "revoked_key")
    point.revoke(1, keys=[_dist.key_id("A")])
    assert refused(point) == "sig:revoked-key"
    point, _kept_id = _kept(tmp_path, "retired_key")
    point.rotate(1, add="C", retire="A")
    assert refused(point) == "sig:revoked-key"
    point, _kept_id = _kept(tmp_path, "floor")
    point.revoke(1, floors={STREAM: 2})
    assert refused(point) == "dist:seq-replay"
    point, _kept_id = _kept(tmp_path, "standing")
    assert _read(point, point.pep.rollback()).event == "rolled-back"
