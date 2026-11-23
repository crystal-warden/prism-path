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


def test_case_009_a_signature_over_other_bytes_is_invalid():
    """case_009: S1, S5. Over the envelope bytes alone, and under another DSSE payload type."""
    assert _cause("009_over_the_envelope_bytes_alone") == "sig:invalid"
    assert _cause("009_another_payload_type") == "sig:invalid"


def test_case_010_signed_only_by_an_unknown_key():
    """case_010: S3, S5, V3."""
    assert _cause("010_unknown_key_only") == "dist:unknown-key"
    assert _verify(bytes.fromhex(BY_NAME["001_round_trip"]["sealed"]), trust=TrustStore()).cause == "dist:unknown-key"


def test_case_011_an_unknown_entry_beside_a_good_one_is_ignored():
    """case_011: S3, S4."""
    assert _cause("011_trusted_and_unknown") is None


def test_case_012_a_failing_entry_by_a_trusted_key_is_skipped():
    """case_012: S3, S4. One good entry counts, and the failing one beside it is skipped, as DSSE skips it."""
    assert _cause("012_trusted_good_and_trusted_failing_is_skipped") is None


def test_case_013_entries_by_a_revoked_key_or_a_retired_key_do_not_count():
    """case_013: S5. The trust store holds the revoked and the retired key, so their signatures verify and
    none counts, and S5 names that before any other cause. Applying a revocation (R2) and a rotation (O3) that
    put them there is the owners' test."""
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


def test_case_114_envelopes_of_one_seq_and_policy_with_another_release_id_are_incomplete():
    """case_114: E7, E10, V10."""
    assert _cause("114_staged_release_id_differs") == "dist:incomplete"


def test_case_117_entries_added_or_removed_never_sign_an_unsigned_envelope():
    """case_117: S6. A signed envelope stays signed with an entry added and needs its counting entry, and an
    unsigned one stays refused with an entry added. The envelope id half is in test_distribution_envelope."""
    assert _cause("117_signed_with_an_entry_added") is None
    assert _cause("117_signed_with_its_counting_entry_removed") == "dist:unknown-key"
    assert _cause("117_unsigned_with_a_failing_entry_added") == "sig:invalid"


def test_case_118_a_key_in_a_role_this_version_does_not_know_never_counts(tmp_path):
    """case_118: K4, S3. It is refused with dist:unknown-key and the key stays in the store, also across a
    save and a load."""
    assert _cause("118_unknown_role_signs") == "dist:unknown-key"
    x = env.key_id(GEN.public_raw(GEN.test_key("X")))
    stored = TrustStore.load(GEN.trust_store().save(str(tmp_path / "trust.json")).path)
    assert stored.keys[x].role == "timestamp" and stored.readable
    assert _verify(bytes.fromhex(BY_NAME["118_unknown_role_signs"]["sealed"]), trust=stored).cause == "dist:unknown-key"


def test_case_119_a_pep_with_no_clock_takes_not_before_as_its_time():
    """case_119: T2, T3, V13. A month behind after a power loss it accepts a current envelope and its time
    floor moves to not_before. A PEP with a clock a month early refuses the same envelope."""
    accepted = GEN.replay(BY_NAME["119_no_clock_a_month_behind_on_mesh"])
    assert accepted["cause"] is None and accepted["time_floor"] == GEN.NOT_BEFORE
    assert _cause("119_clock_a_month_early_on_mesh") == "dist:not-yet-valid"
    expired = verifier.PepView("host", GEN.STREAM, qualification=GEN.QUALIFICATION, has_clock=False)
    good = bytes.fromhex(BY_NAME["001_round_trip"]["sealed"])
    assert _verify(good, pep=expired, now=GEN.EXPIRES).cause == "dist:expired"


def test_the_staged_release_must_agree_at_its_seq():
    """V10, E7: an envelope at the staged seq that disagrees with the staged policy hash is incomplete."""
    good = bytes.fromhex(BY_NAME["001_round_trip"]["sealed"])
    release = GEN.release_of(GEN.image())
    staged = verifier.Staged(GEN.STREAM, 1, "ab" * 32, release, "", False)
    pep = verifier.PepView("host", GEN.STREAM, qualification=GEN.QUALIFICATION, staged=staged)
    assert _verify(good, pep=pep).cause == "dist:incomplete"
    agreeing = verifier.Staged(GEN.STREAM, 1, canon.sha256_hex(GEN.image()), release, "", False)
    assert _verify(good, pep=verifier.PepView("host", GEN.STREAM, qualification=GEN.QUALIFICATION,
                                              staged=agreeing)).ok


def test_a_pep_view_names_a_built_kind_and_a_stream():
    with pytest.raises(ValueError):
        verifier.PepView("agent", GEN.STREAM)
    with pytest.raises(ValueError):
        verifier.PepView("host", env.TRUST_STREAM)


def test_the_hatch_gate_refuses_in_a_production_build_and_audits(tmp_path, monkeypatch):
    """D1, D2. The gate every escape hatch will pass (conformance case 97 is covered once the hatches go
    through it). In a production build the hatch is refused with dist:hatch-refused, which the caller
    answers by running the check, and its audit event says so. In a dev build it passes. Which build this is
    comes from the tree around the package alone, shown on temporary trees."""
    tree = tmp_path / "checkout"
    package = tree / "prismpath"
    package.mkdir(parents=True)
    assert not devbuild.is_dev_build(package)
    (tree / devbuild.MARKER).write_text("dev\n")
    assert not devbuild.is_dev_build(package)                     # the marker alone is not a checkout
    (tree / "pyproject.toml").write_text("[project]\n")
    assert devbuild.is_dev_build(package)
    (tree / devbuild.MARKER).unlink()
    assert not devbuild.is_dev_build(package)

    log = AuditLog(str(tmp_path / "hatch.log"))
    monkeypatch.setattr(devbuild, "is_dev_build", lambda package_dir=None: False)
    with pytest.raises(devbuild.HatchRefused) as refused:
        devbuild.hatch("PPT_NET_ALLOW_UNVERIFIED", log)
    assert refused.value.cause == "dist:hatch-refused"
    assert log.events[-1]["data"] == {"hatch": "PPT_NET_ALLOW_UNVERIFIED", "dev_build": False, "result": "refused",
                                      "cause": "dist:hatch-refused"}
    with pytest.raises(devbuild.HatchRefused):
        devbuild.hatch("--allow-unsigned")
    monkeypatch.setattr(devbuild, "is_dev_build", lambda package_dir=None: True)
    devbuild.hatch("--allow-unsigned", log)
    assert log.events[-1]["data"] == {"hatch": "--allow-unsigned", "dev_build": True, "result": "allowed"}


@pytest.mark.parametrize("member", ["fields", "counts"])
@pytest.mark.parametrize("value", [[], "x", 7, {"x": ["y"]}])
def test_a_policy_ppt_meta_member_that_is_not_its_form_is_refused_never_raised(member, value):
    """V11, V1: `fields` and `counts` of a signed policy.ppt that are not objects of their members' forms are
    dist:bad-format. The verifier answers every signed envelope with a verdict and never raises."""
    if member == "counts" and isinstance(value, dict):
        value = {"atoms": "one"}
    meta = {**GEN.image_meta(GEN.image()), member: value}
    sealed = env.seal(canon.canon2_bytes(GEN.envelope_doc(GEN.image(), meta=meta)), [GEN.test_key("A")])
    assert _verify(sealed).cause == "dist:bad-format"


def test_case_127_a_meta_member_of_another_form_is_refused_where_it_is_read(tmp_path):
    """case_127: E11, V4. A policy.ppt whose fields is a string, whose counts is an integer, whose counts lacks a
    member and whose packing has no sidecar_sha256 is dist:bad-format each, and a ppt-pack/1 manifest whose
    fields is a string is manifest:bad-format from the older gate. Nothing raises."""
    for name in ("fields_a_string", "counts_an_integer", "counts_lacking_a_member", "packing_without_its_sidecar"):
        assert _cause(f"127_{name}") == "dist:bad-format", name
    from prismpath.hotswap import policy_pack as pp
    keys = pp.keygen(str(tmp_path / "keys"))
    image = GEN.image()
    envelope = {"envelope_id": "dist-demo", "fields": {"x": "int"}, "caps": dict(pp.DEFAULT_CAPS)}
    for member in ("fields", "counts"):
        ppt = tmp_path / f"{member}.ppt"
        ppt.write_bytes(image)
        manifest = pp.build_pack(str(ppt), {"x": "int"}, 1, "dist-demo", keys["private"], keys["public"])
        manifest[member] = "x"
        pp.write_signed_document(str(ppt) + ".manifest.json", manifest)
        with open(str(ppt) + ".manifest.sig", "wb") as handle:
            handle.write(pp._load_private(keys["private"]).sign(pp.signed_bytes(manifest)))
        ok, reasons, _manifest = pp.verify_pack(str(ppt), [keys["public"]])
        assert (ok, reasons) == (False, ["manifest:bad-format"]), member
        assert pp.check_envelope(manifest, image, envelope) == (False, ["manifest:bad-format"])
        assert pp.check_counts(manifest, image) == (["manifest:bad-format"] if member == "counts" else [])


def test_a_kind_that_does_not_read_meta_only_bounds_it():
    """The PEP half of case 128 (the controller half is PR 4's), E9, E11. One signed policy.ppt whose counts is an integer is accepted on mesh, whose reader skips
    meta, and dist:bad-format on host, which reads it. On mesh a meta that is a string, one nested four levels and
    one running past the envelope are each dist:bad-format. The controller's part, which always reads meta in full
    (F1), is the controller's."""
    assert _cause("128_counts_an_integer_where_meta_is_read") == "dist:bad-format"
    assert _cause("128_counts_an_integer_where_meta_is_skipped_on_mesh") is None
    for name in ("meta_a_string", "meta_nested_four_levels", "meta_running_past_the_envelope"):
        assert _cause(f"128_{name}_on_mesh") == "dist:bad-format", name
    doc = {**GEN.envelope_doc(GEN.image()), "meta": {"a": {"b": {}}}}
    assert env.read(canon.canon2_bytes(doc), reads_meta=False).meta == {"a": {"b": {}}}
    with pytest.raises(env.Refused):
        env.read(canon.canon2_bytes(doc))


def test_verify_envelope_stops_before_the_body_and_agrees_with_the_whole_verify():
    """B9: V2 to V8 with no body read. Every corpus case refused before V9 gets the same cause, and one that
    passes V8 comes back with its envelope, whose size and hash name the body to read."""
    for case in CORPUS["cases"]:
        whole = GEN.replay(case)
        early = verifier.verify_envelope(bytes.fromhex(case["sealed"]), trust=GEN.trust_from_document(case["trust"]),
                                           pep=GEN.pep_from_document(case["pep"]), now=case["now"])
        if early.cause is not None:
            assert early.cause == whole["cause"], case["name"]
        elif early.envelope is not None:
            assert whole["cause"] not in {"dist:bad-format", "dist:unknown-key", "sig:invalid", "dist:target-mismatch",
                                          "dist:not-yet-valid", "dist:expired", "dist:revoked", "dist:seq-replay"} \
                or case["body"] == "", case["name"]           # dist:trust-replay may also come of R6 at V11
