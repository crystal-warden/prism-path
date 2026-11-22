# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Authority key rotation (spec-policy-distribution.md, section 11), applied by the enforcement point. Each test
names the conformance case of section 20 it covers."""
import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.distribution import state_record  # noqa: E402
from prismpath.distribution.trust import TrustStore  # noqa: E402
from prismpath.tests import _dist  # noqa: E402
from prismpath.tests._dist import STREAM, rotation, seal, trust_statement  # noqa: E402

OLD, NEW = _dist.image(5), _dist.image(7)
H = canon.sha256_hex


def _read(point, signed):
    return state_record.read(signed, point.key.public_raw)


@pytest.fixture
def point(tmp_path):
    return _dist.HostPep(tmp_path / "host")


def test_case_072_a_rotation_signed_by_the_old_and_the_new_key_then_a_pack_under_the_new_key(point):
    """case_072: O1, O2, O3. Applied with no commit and durable before it is reported, then a pack signed only by
    the new key commits."""
    record = _read(point, point.rotate(1, add="B"))
    assert (record.event, record.trust_seq) == ("trust-applied", 1)
    assert _dist.key_id("B") in TrustStore.load(point.pep.store.path("trust.json")).keys
    assert _read(point, point.commit(OLD, signer="B")).event == "committed"


def test_case_073_a_retired_key_no_longer_counts_and_its_active_release_keeps_deciding(point):
    """case_073: O3, S5. Also the retired half of case_013."""
    point.commit(OLD, signer="A")
    assert _read(point, point.rotate(1, add="B", retire="A")).event == "trust-applied"
    assert _dist.key_id("A") in point.pep.trust.retired
    assert _read(point, point.pep.stage(seal("policy.ppt", NEW, seq=2, signer="A"), NEW)).cause == "sig:revoked-key"
    assert point.pep.state() == "active" and point.pep.refusal() is None
    assert point.open().state() == "active"
    assert _read(point, point.commit(NEW, seq=2, signer="B")).event == "committed"


def test_case_074_a_rotation_signed_only_by_an_unknown_key_or_without_the_new_key(point):
    """case_074: O2."""
    assert _read(point, point.rotate(1, add="B", signers=("B",))).cause == "dist:unknown-key"
    assert _read(point, point.rotate(1, add="B", signers=("A",))).cause == "dist:rotation-invalid"
    assert _read(point, point.rotate(1, add="B", signers=("A", "U"))).cause == "dist:rotation-invalid"
    assert point.pep.trust.trust_seq == 0 and _dist.key_id("B") not in point.pep.trust.keys


def test_case_075_a_rotation_that_names_a_key_it_may_not(point):
    """case_075: O3, O4. A retire that names an unknown key, an add that is the PEP's own instance key, and an add
    that the revocation list holds."""
    assert _read(point, point.rotate(1, add="B", retire="U")).cause == "dist:rotation-invalid"
    instance = point.key.public_raw.hex()
    body = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-rotation/1",
                               "add": instance, "retire": ""})
    sealed = trust_statement("trust.rotation", body, seq=1, signers=("A", "I"))
    assert _read(point, point.pep.stage(sealed, body)).cause == "dist:rotation-invalid"
    point.revoke(1, keys=[_dist.key_id("B")])
    assert _read(point, point.rotate(2, add="B")).cause == "dist:rotation-invalid"
    assert point.pep.trust.trust_seq == 1


def test_case_076_a_rotation_and_a_revocation_share_one_trust_sequence(point):
    """case_076: O1. Whichever comes second at the same seq is dist:trust-replay."""
    point.rotate(1, add="B")
    assert _read(point, point.revoke(1)).cause == "dist:trust-replay"
    other = _dist.HostPep(point.state_dir.parent / "other")
    other.revoke(1)
    assert _read(other, other.rotate(1, add="B")).cause == "dist:trust-replay"


def test_case_123_a_rotation_that_skips_a_number_waits_for_the_one_it_skipped(point):
    """case_123: O1, R1. Two above the trust sequence is dist:trust-replay, then the one it skipped is applied, then
    the first again is applied, since it is now the next."""
    body = rotation("Q")
    second = trust_statement("trust.rotation", body, seq=2, signers=("A", "Q"))
    assert _read(point, point.pep.stage(second, body)).cause == "dist:trust-replay"
    assert _read(point, point.rotate(1, add="B")).event == "trust-applied"
    assert _read(point, point.pep.stage(second, body)).event == "trust-applied"
    assert point.pep.trust.trust_seq == 2 and {_dist.key_id("B"), _dist.key_id("Q")} <= set(point.pep.trust.keys)


def test_a_restart_keeps_a_release_under_a_retired_key_and_lapses_one_under_a_revoked_key(tmp_path):
    """O3, R5: the restart check holds the active release to the revocation test. A key only retired still holds
    the release up, and a key revoked does not."""
    point = _dist.HostPep(tmp_path / "retired")
    point.commit(OLD, signer="A")
    point.rotate(1, add="B", retire="A")
    assert point.open().state() == "active"
    point.pep = point.open()
    point.revoke(2, signer="B", keys=[_dist.key_id("A")])
    assert point.pep.state() == "no-policy" and point.open().state() == "no-policy"


def test_case_131_the_trust_store_is_bounded(tmp_path):
    """case_131: K5. A rotation that would make a ninth key is dist:too-large. Seventeen keys retired one after
    another forget the first, and a pack signed by it then reads as signed by an unknown key."""
    point = _dist.HostPep(tmp_path / "nine")
    for index in range(1, 8):
        assert _read(point, point.rotate(index, add=f"K{index}", signers=("A", f"K{index}"))).event == "trust-applied"
    assert len(point.pep.trust.keys) == 8
    assert _read(point, point.rotate(8, add="K8", signers=("A", "K8"))).cause == "dist:too-large"

    point = _dist.HostPep(tmp_path / "retired")
    previous = "A"
    for index in range(1, 18):
        record = _read(point, point.rotate(index, add=f"R{index}", retire=previous, signers=(previous, f"R{index}")))
        assert record.event == "trust-applied", index
        previous = f"R{index}"
    assert len(point.pep.trust.retired) == 16 and _dist.key_id("A") not in point.pep.trust.keys
    assert _read(point, point.pep.stage(seal("policy.ppt", OLD, signer="A"), OLD)).cause == "dist:unknown-key"
    assert _read(point, point.pep.stage(seal("policy.ppt", OLD, signer="R1"), OLD)).cause == "sig:revoked-key"
    assert point.open().trust.retired == point.pep.trust.retired
