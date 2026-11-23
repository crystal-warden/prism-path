# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Signed revocation lists (spec-policy-distribution.md, section 10), applied by the enforcement point. Each test
names the conformance case of section 20 it covers."""
import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.distribution import state_record  # noqa: E402
from prismpath.distribution.trust import TrustStore  # noqa: E402
from prismpath.tests import _dist  # noqa: E402
from prismpath.tests._dist import STREAM, revocation, seal  # noqa: E402

OLD, NEW, NEWER = _dist.image(5), _dist.image(7), _dist.image(9)
H = canon.sha256_hex


def _read(point, signed):
    return state_record.read(signed, point.key.public_raw)


@pytest.fixture
def point(tmp_path):
    return _dist.HostPep(tmp_path / "host", authorities=["A", "B"])


def test_case_031_a_revocation_is_applied_when_it_verifies_with_no_commit(point):
    """case_031: B2, R3. The trust store on disk already holds it when the PEP reports `trust-applied`."""
    record = _read(point, point.revoke(1, keys=[_dist.key_id("B")]))
    assert (record.event, record.cause, record.trust_seq) == ("trust-applied", None, 1)
    on_disk = TrustStore.load(point.pep.store.path("trust.json"))
    assert on_disk.trust_seq == 1 and _dist.key_id("B") in on_disk.revoked_keys
    assert "trust-applied" in [event["action"] for event in point.pep.audit.events]
    assert point.open().trust.revoked_keys == on_disk.revoked_keys


def test_case_013_a_key_revoked_by_an_applied_list_does_not_count(point):
    """case_013: S5, the revoked half through an applied list (the retired half is rotation's)."""
    point.revoke(1, keys=[_dist.key_id("B")])
    assert _read(point, point.pep.stage(seal("policy.ppt", OLD, signer="B"), OLD)).cause == "sig:revoked-key"


def test_case_041_an_applied_list_revokes_by_envelope_id_and_by_policy_hash(point):
    """case_041: V7, R2."""
    by_id = seal("policy.ppt", OLD, seq=1)
    point.revoke(1, envelopes=[env.envelope_id(env.unseal(by_id)[0])], policies=[H(NEW)])
    assert _read(point, point.pep.stage(by_id, OLD)).cause == "dist:revoked"
    assert _read(point, point.pep.stage(seal("policy.ppt", NEW, seq=2), NEW)).cause == "dist:revoked"
    assert _read(point, point.pep.stage(seal("policy.ppt", OLD, seq=3), OLD)).event == "staged"


def test_case_066_a_revocation_is_taken_at_the_next_trust_sequence_only(point):
    """case_066: R1. One above the trust sequence is applied, the same again changes nothing, an older one and
    one that skips a number are dist:trust-replay."""
    first = revocation(keys=[_dist.key_id("B")])
    sealed = seal("trust.revocation", first, seq=1, stream="@trust")
    assert _read(point, point.pep.stage(sealed, first)).event == "trust-applied"
    again = _read(point, point.pep.stage(sealed, first))
    assert (again.event, again.trust_seq) == ("beat", 1)
    point.revoke(2, keys=[_dist.key_id("B")])
    assert _read(point, point.revoke(1, keys=[_dist.key_id("B")])).cause == "dist:trust-replay"
    assert _read(point, point.revoke(4, keys=[_dist.key_id("B")])).cause == "dist:trust-replay"
    assert point.pep.trust.trust_seq == 2


def test_case_067_after_a_key_is_revoked_a_pack_it_signed_is_refused(point):
    """case_067: R2."""
    point.revoke(1, keys=[_dist.key_id("B")])
    assert _read(point, point.pep.stage(seal("policy.ppt", NEW, signer="B"), NEW)).cause == "sig:revoked-key"
    assert _read(point, point.pep.stage(seal("policy.ppt", NEW, signer="A"), NEW)).event == "staged"


def test_case_068_a_raised_floor_refuses_a_release_below_it(point):
    """case_068: R4, Q4."""
    point.revoke(1, floors={STREAM: 9})
    assert _read(point, point.pep.stage(seal("policy.ppt", OLD, seq=8), OLD)).cause == "dist:seq-replay"
    assert _read(point, point.pep.stage(seal("policy.ppt", OLD, seq=9), OLD)).cause == "dist:seq-replay"
    assert _read(point, point.pep.stage(seal("policy.ppt", OLD, seq=10), OLD)).event == "staged"
    point.revoke(2, floors={STREAM: 5})
    assert point.pep.trust.floors[STREAM] == 9                       # a lower number never lowers it


@pytest.mark.parametrize("ground", ["envelope", "policy", "key", "floor"])
def test_case_069_a_revocation_that_removes_the_active_release_s_ground_lapses_it(tmp_path, ground):
    """case_069: R5. The active envelope, the active policy hash, the only key that signed it, or a floor above its
    seq: each time the PEP goes to no-policy with event lapsed and dist:revoked, and a staged release on the same
    ground is dropped."""
    point = _dist.HostPep(tmp_path, authorities=["A", "B"])
    point.commit(OLD, seq=3, signer="B")
    staged = seal("policy.ppt", OLD, seq=4, signer="B")
    point.pep.stage(staged, OLD)
    lists = {"envelope": {"envelopes": [point.pep.active.held["policy.ppt"].envelope_id,
                                        env.envelope_id(env.unseal(staged)[0])]},
             "policy": {"policies": [H(OLD)]}, "key": {"keys": [_dist.key_id("B")]},
             "floor": {"floors": {STREAM: 5}}}[ground]
    point.pep.drain()
    point.revoke(1, **lists)
    sent = [_read(point, data) for data in point.pep.drain()]
    assert [(record.event, record.cause) for record in sent] == [("lapsed", "dist:revoked"), ("trust-applied", None)]
    assert point.pep.state() == "no-policy" and point.pep.staged is None
    assert point.pep.adapter.host.active()["active"] is None and point.open().state() == "no-policy"


def test_a_revocation_that_misses_the_active_release_leaves_it_deciding(point):
    """R5: only a revocation that removes the ground lapses the release."""
    point.commit(OLD, seq=3)
    point.revoke(1, keys=[_dist.key_id("B")], policies=[H(NEW)], floors={STREAM: 3})
    assert point.pep.state() == "active" and point.pep.refusal() is None


def test_case_070_a_later_list_that_drops_a_key_is_refused(point):
    """case_070: R6. The list is dist:trust-replay and is not applied, and the key is still refused."""
    point.revoke(1, keys=[_dist.key_id("B")])
    assert _read(point, point.revoke(2)).cause == "dist:trust-replay"
    assert point.pep.trust.trust_seq == 1 and _dist.key_id("B") in point.pep.trust.revoked_keys
    assert _read(point, point.pep.stage(seal("policy.ppt", NEW, signer="B"), NEW)).cause == "sig:revoked-key"


def test_case_071_a_revocation_list_past_its_bounds_is_too_large(point):
    """case_071: R7. 65 entries in a list, or 17 streams of floors."""
    many = [H(bytes([index])) for index in range(65)]
    assert _read(point, point.revoke(1, envelopes=many)).cause == "dist:too-large"
    assert _read(point, point.revoke(1, floors={f"s{index}": 1 for index in range(17)})).cause == "dist:too-large"
    assert _read(point, point.revoke(1, envelopes=many[:64], floors={f"s{index}": 1 for index in range(16)})).event \
        == "trust-applied"


def test_case_079_a_trust_envelope_never_expires(point):
    """case_079: X4, E5. A trust envelope with expires other than 0 is bad format, and a revocation made ten years
    before it is read is applied."""
    body = revocation(keys=[_dist.key_id("B")])
    doc = {"artifact": "trust.revocation", "body_sha256": H(body), "body_size": len(body),
           canon.ENCODING_KEY: canon.CANON2, "expires": _dist.NOW + 1, "format": env.FORMAT, "meta": {},
           "not_before": _dist.NOW - 10 * 365 * 86400, "policy_sha256": env.ZERO_HASH, "release": env.ZERO_HASH,
           "replaces": "", "seq": 1, "stream": env.TRUST_STREAM, "targets": ["host"], "widens": False}
    expiring = env.seal(canon.canon2_bytes(doc), [_dist.GEN.test_key("A")])
    assert _read(point, point.pep.stage(expiring, body)).cause == "dist:bad-format"
    lasting = env.seal(canon.canon2_bytes({**doc, "expires": 0}), [_dist.GEN.test_key("A")])
    assert _read(point, point.pep.stage(lasting, body)).event == "trust-applied"


def test_a_death_between_saving_a_revocation_and_the_lapse_comes_back_lapsed(point, monkeypatch):
    """R5, fail closed: the store is durable before the lapse, so a PEP killed between the two finds on restart
    that the active release no longer stands, lapses it with dist:revoked and drops the staged one."""
    point.commit(OLD, seq=1)
    point.pep.stage(seal("policy.ppt", NEW, seq=2), NEW)

    class Died(Exception):
        pass

    def die(*_args, **_kwargs):
        raise Died()
    monkeypatch.setattr(point.pep, "lapse", die)
    with pytest.raises(Died):
        point.revoke(1, policies=[H(OLD), H(NEW)])
    monkeypatch.undo()
    pep = point.open()
    assert pep.trust.trust_seq == 1 and pep.state() == "no-policy" and pep.staged is None
    assert pep.adapter.host.active()["active"] is None
    sent = [_read(point, data) for data in pep.drain()]
    assert ("lapsed", "dist:revoked") in [(record.event, record.cause) for record in sent]


def test_the_periodic_check_lapses_a_release_that_no_longer_stands(point):
    """R5, X1: tick and every entry point run the same test as a revocation, not only the expiry."""
    point.commit(OLD, seq=1)
    from dataclasses import replace
    point.pep.trust = replace(point.pep.trust, revoked_policies=frozenset({H(OLD)}))
    record = _read(point, point.pep.tick())
    assert (record.event, record.cause, record.state) == ("lapsed", "dist:revoked", "no-policy")


def test_a_state_record_reports_the_floor_a_revocation_raised(point):
    """R4, H1: the floor in a record is the one V8 holds, the larger of the committed floor and the raised one."""
    point.commit(OLD, seq=1)
    assert _read(point, point.revoke(1, floors={STREAM: 7})).floor == 7
    assert _read(point, point.pep.record("beat")).floor == 7 and point.pep.floor.seq == 1


def test_a_pep_holds_only_the_latest_list_and_a_floor_keeps_out_what_it_dropped(point):
    """R6, R4: the PEP half of case 130 (the sealing tool and the controller refuse a list that drops what no floor
    passed, which is theirs). A list raises the floor past a revoked envelope, the next list drops the envelope,
    the PEP then holds only that list, and the envelope sent again is refused by the floor. Floors of other
    streams are not kept."""
    revoked = seal("policy.ppt", OLD, seq=5)
    revoked_id = env.envelope_id(env.unseal(revoked)[0])
    assert _read(point, point.revoke(1, envelopes=[revoked_id], floors={STREAM: 6, "other/stream": 3})).event \
        == "trust-applied"
    assert point.pep.trust.floors == {STREAM: 6}
    assert _read(point, point.revoke(2, floors={STREAM: 6})).event == "trust-applied"
    assert point.pep.trust.revoked_envelopes == frozenset() and point.pep.trust.trust_seq == 2
    assert _read(point, point.pep.stage(revoked, OLD)).cause == "dist:seq-replay"


def test_case_134_a_trust_statement_reaches_every_pep_whatever_its_targets(tmp_path):
    """case_134: V5, R1. A revocation whose targets names only mesh is applied by a host PEP and a mesh PEP alike,
    so the one trust sequence counts the same for both, and both take the rotation that follows."""
    host, mesh = _dist.HostPep(tmp_path / "host"), _dist.MeshPep(tmp_path / "mesh")
    body = revocation(keys=[_dist.key_id("R")])
    only_mesh = _dist.trust_statement("trust.revocation", body, seq=1, targets=("mesh",))
    rotation = _dist.rotation("B")
    every = _dist.trust_statement("trust.rotation", rotation, seq=2, signers=("A", "B"), targets=("host", "mesh"))
    for point in (host, mesh):
        assert _read(point, point.pep.stage(only_mesh, body)).event == "trust-applied"
        assert _read(point, point.pep.stage(every, rotation)).event == "trust-applied"
        assert point.pep.trust.trust_seq == 2 and _dist.key_id("B") in point.pep.trust.keys
