# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The trust store, the verifier and the dev build gate (spec-policy-distribution.md, sections 5, 7, 9.1
and 16). Each test names the conformance case of section 20 it covers and checks the cause the spec gives,
on the corpus case of that name (portable/gen_distribution_corpus.py) and, where the case says more, on the
API directly."""
import importlib.util
import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.distribution import devbuild, verify as verifier  # noqa: E402
from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.distribution.trust import TrustStore  # noqa: E402
from prismpath.ledgers.audit_log import AuditLog  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
CORPUS = json.loads((REPO / "portable" / "conformance" / "distribution.json").read_text(encoding="utf-8"))
BY_NAME = {case["name"]: case for case in CORPUS["cases"]}


def _generator():
    spec = importlib.util.spec_from_file_location("gen_distribution_corpus",
                                                  REPO / "portable" / "gen_distribution_corpus.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEN = _generator()


def _cause(name):
    return GEN.replay(BY_NAME[name])["cause"]


def _verify(sealed, *, trust=None, pep=None, now=GEN.NOW, body=None):
    return verifier.verify(sealed, GEN.image() if body is None else body,
                           trust=GEN.trust_store() if trust is None else trust,
                           pep=pep or verifier.PepView("host", GEN.STREAM, qualification=GEN.QUALIFICATION), now=now)


def test_case_007_a_body_over_the_pep_bound_is_too_large():
    """case_007: E6, V2. The envelope half is in test_distribution_envelope."""
    assert _cause("007_body_over_bound") == "dist:too-large"
    assert _cause("007_envelope_2049_bytes") == "dist:bad-format"


def test_case_009_a_signature_without_the_domain_prefix_is_invalid():
    """case_009: S1."""
    assert _cause("009_no_domain_prefix") == "sig:invalid"


def test_case_010_signed_only_by_an_unknown_key():
    """case_010: S3, V3."""
    assert _cause("010_unknown_key_only") == "dist:unknown-key"
    assert _verify(bytes.fromhex(BY_NAME["001_round_trip"]["sealed"]), trust=TrustStore()).cause == "dist:unknown-key"


def test_case_011_an_unknown_entry_beside_a_good_one_is_ignored():
    """case_011: S3, S6."""
    assert _cause("011_trusted_and_unknown") is None


def test_case_012_a_failing_entry_by_a_trusted_key_refuses_whatever_the_others_say():
    """case_012: S4."""
    assert _cause("012_trusted_good_and_trusted_failing") == "sig:invalid"


def test_case_013_entries_by_a_revoked_key_or_a_retired_key_do_not_count():
    """case_013: S5. The trust store holds the revoked and the retired key, so their signatures verify and
    none counts. Applying a revocation (R2) and a rotation (O3) that put them there is the owners' test."""
    assert _cause("013_revoked_key_only") == "sig:revoked-key"
    assert _cause("013_retired_key_only") == "sig:revoked-key"


def test_case_016_an_unreadable_trust_store_refuses_every_envelope(tmp_path):
    """case_016: K1, X3. A missing, torn or malformed store file is a store that counts nothing."""
    assert _cause("016_trust_store_unreadable") == "dist:unknown-key"
    good = bytes.fromhex(BY_NAME["001_round_trip"]["sealed"])
    stored = GEN.trust_store().save(str(tmp_path / "trust.json"))
    assert TrustStore.load(stored.path) == stored and _verify(good, trust=TrustStore.load(stored.path)).ok
    raw = (tmp_path / "trust.json").read_bytes()
    for broken in (raw[:-1], raw + b"\n", raw.replace(b'"threshold":1', b'"threshold":2'), b""):
        (tmp_path / "trust.json").write_bytes(broken)
        store = TrustStore.load(str(tmp_path / "trust.json"))
        assert not store.readable and _verify(good, trust=store).cause == "dist:unknown-key"
        with pytest.raises(ValueError):
            store.save()
    assert not TrustStore.load(str(tmp_path / "absent.json")).readable


def test_case_020_seq_below_the_floor():
    """case_020: Q1, Q2, V8."""
    assert _cause("020_seq_below_floor") == "dist:seq-replay"


def test_case_021_seq_at_the_floor_with_the_committed_id_changes_nothing():
    """case_021: Q3."""
    result = GEN.replay(BY_NAME["021_seq_at_floor_committed_id"])
    assert result["cause"] is None and result["unchanged"] is True


def test_case_022_seq_at_the_floor_with_another_id():
    """case_022: Q3."""
    assert _cause("022_seq_at_floor_other_id") == "dist:seq-replay"


def test_case_028_not_before_more_than_the_skew_ahead():
    """case_028: T3, V6. 301 seconds ahead is refused and 299 is accepted, and V13 raises the time floor to
    not_before."""
    assert _cause("028_not_before_301_ahead") == "dist:not-yet-valid"
    accepted = GEN.replay(BY_NAME["028_not_before_299_ahead"])
    assert accepted["cause"] is None and accepted["time_floor"] == GEN.NOT_BEFORE
    assert verifier.SKEW == 300


def test_case_029_expiry_has_no_grace():
    """case_029: T4, V6."""
    assert _cause("029_time_equals_expires") == "dist:expired"
    assert _cause("029_time_one_second_before_expires") is None
    good = bytes.fromhex(BY_NAME["001_round_trip"]["sealed"])
    assert _verify(good, now=0, trust=GEN.trust_store(time_floor=GEN.EXPIRES)).cause == "dist:expired"


def test_case_039_two_failures_report_only_the_earlier():
    """case_039: V1. Wrong target (V5) and expired (V6): only V5's cause."""
    assert _cause("039_two_failures_report_the_earlier") == "dist:target-mismatch"


def test_case_040_another_kind_an_unused_artifact_and_another_stream():
    """case_040: V5."""
    for name in ("040_another_target_kind", "040_an_artifact_the_kind_does_not_use", "040_another_stream"):
        assert _cause(name) == "dist:target-mismatch", name


def test_case_041_a_revoked_envelope_id_and_a_revoked_policy_hash():
    """case_041: V7, R2."""
    assert _cause("041_envelope_id_revoked") == "dist:revoked"
    assert _cause("041_policy_hash_revoked") == "dist:revoked"


def test_case_042_a_body_one_byte_short_and_one_byte_changed():
    """case_042: V9."""
    assert _cause("042_body_one_byte_short") == "dist:body-mismatch"
    assert _cause("042_body_one_byte_changed") == "dist:body-mismatch"


def test_case_044_the_policy_ppt_check_keeps_its_existing_causes():
    """case_044: V11."""
    assert _cause("044_counts_differ") == "manifest:count-mismatch"
    assert _cause("044_over_a_qualification_cap") == "image:caps-exceeded"
    assert _cause("044_wrong_wcet") == "manifest:wcet-mismatch"
    good = bytes.fromhex(BY_NAME["001_round_trip"]["sealed"])
    assert _verify(good, pep=verifier.PepView("host", GEN.STREAM)).cause == "envelope:missing"
    other = {**GEN.QUALIFICATION, "envelope_id": "another"}
    assert _verify(good, pep=verifier.PepView("host", GEN.STREAM, qualification=other)).cause == "envelope:id-mismatch"


def test_case_079_a_trust_envelope_never_expires():
    """case_079: X4, E5. A trust envelope with expires other than 0 is bad format, and a revocation made ten
    years before it is read verifies. What applying it does is R1 to R7."""
    assert _cause("079_trust_kind_with_expires") == "dist:bad-format"
    result = GEN.replay(BY_NAME["079_revocation_read_years_later"])
    assert result["cause"] is None and result["unchanged"] is False


def test_the_staged_release_must_agree_at_its_seq():
    """V10, E7: an envelope at the staged seq that disagrees with the staged policy hash is incomplete."""
    good = bytes.fromhex(BY_NAME["001_round_trip"]["sealed"])
    staged = verifier.Staged(GEN.STREAM, 1, "ab" * 32, "", False)
    pep = verifier.PepView("host", GEN.STREAM, qualification=GEN.QUALIFICATION, staged=staged)
    assert _verify(good, pep=pep).cause == "dist:incomplete"
    agreeing = verifier.Staged(GEN.STREAM, 1, canon.sha256_hex(GEN.image()), "", False)
    assert _verify(good, pep=verifier.PepView("host", GEN.STREAM, qualification=GEN.QUALIFICATION,
                                              staged=agreeing)).ok


def test_a_pep_view_names_a_built_kind_and_a_stream():
    with pytest.raises(ValueError):
        verifier.PepView("mesh", GEN.STREAM)
    with pytest.raises(ValueError):
        verifier.PepView("host", env.TRUST_STREAM)


def test_case_097_a_hatch_in_a_production_build_is_refused_and_audited(tmp_path, monkeypatch):
    """case_097: D1, D2. Without prismpath._dev_build the hatch is refused with dist:hatch-refused, which the
    caller answers by running the check, and its audit event says so. With the module it passes. The
    repository carries the module and the product does not, so both builds are set here by what the import
    system finds, as D2 says, and nothing else."""
    log = AuditLog(str(tmp_path / "dev.log"))
    real_find_spec = importlib.util.find_spec
    assert devbuild.is_dev_build() == ((REPO / "_dev_build.py").exists())

    def build(dev):
        marker = real_find_spec("prismpath.distribution")
        monkeypatch.setattr(importlib.util, "find_spec", lambda name, *rest: (marker if dev else None)
                            if name == devbuild.DEV_BUILD_MODULE else real_find_spec(name, *rest))

    build(dev=False)
    assert not devbuild.is_dev_build()
    with pytest.raises(devbuild.HatchRefused) as refused:
        devbuild.hatch("PPT_NET_ALLOW_UNVERIFIED", log)
    assert refused.value.cause == "dist:hatch-refused"
    assert log.events[-1]["data"] == {"hatch": "PPT_NET_ALLOW_UNVERIFIED", "dev_build": False, "result": "refused",
                                      "cause": "dist:hatch-refused"}
    with pytest.raises(devbuild.HatchRefused):
        devbuild.hatch("--allow-unsigned")
    build(dev=True)
    devbuild.hatch("--allow-unsigned", log)
    assert log.events[-1]["data"] == {"hatch": "--allow-unsigned", "dev_build": True, "result": "allowed"}
