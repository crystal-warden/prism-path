# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze the policy distribution corpus (spec-policy-distribution.md, I1): each conformance case of
section 20 that the verifier decides, as bytes in and a result out, so Python, Rust and the C core replay
the same file.

    python prismpath/portable/gen_distribution_corpus.py   ->  conformance/distribution.json

Every key comes from a fixed 32 byte test seed, so the Ed25519 signatures, the envelope ids and the file
are the same on every run. Each case is `{case, name, runs_on, trust, pep, now, sealed, body, expect}`,
bytes in lower case hex. `runs_on` is the case's row of section 20, and `pep.kind` the target kind it runs
on (I1). The C core has only `mesh` and `cfs`, so a case on `host` is replayed by Python and Rust. `trust`
is the trust store document, or null for a store that cannot be read. `expect` is what the Python verifier
decides, and the generator also asserts that it is the cause the spec gives, so the file never freezes a
wrong verdict. `release_ids` holds the release id vectors of E10.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from dataclasses import replace
from typing import Dict, List, Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO))

from prismpath import canon  # noqa: E402
from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.distribution import verify as verifier  # noqa: E402
from prismpath.distribution.trust import TrustStore  # noqa: E402
from prismpath.hotswap import policy_pack as pp  # noqa: E402
from prismpath.kernel import canon2, ppt_compile  # noqa: E402

OUT = HERE / "conformance" / "distribution.json"
SPEC = REPO / "docs" / "design" / "spec-policy-distribution.md"
_ROW = re.compile(r"^\| (\d+) \| (.+) \| (.+) \| (.+) \| ([PRC](?: [PRC])*) \|$")

STREAM = "host/demo"
NOT_BEFORE = 1_800_000_000
EXPIRES = NOT_BEFORE + 30 * 86400
NOW = NOT_BEFORE + 3600
QUALIFICATION = {"caps": dict(pp.DEFAULT_CAPS), "envelope_id": "dist-demo", "fields": {"x": "int"}}


def spec_cases(path: Path = SPEC) -> Dict[int, dict]:
    """Section 20 of the spec as {case: {case, expect, rules, runs_on}}, read from its table."""
    cases = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _ROW.match(line)
        if match:
            number = int(match.group(1))
            cases[number] = {"case": number, "text": match.group(2), "expect": match.group(3),
                             "rules": match.group(4), "runs_on": match.group(5).split()}
    return cases


def test_key(name: str):
    """The Ed25519 test key whose seed is the SHA-256 of `prismpath.dist test key <name>`."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"prismpath.dist test key {name}".encode()).digest())


def public_raw(private) -> bytes:
    _priv, _pub, ser, _invalid = pp._ed25519()
    return private.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)


def image() -> bytes:
    return ppt_compile.compile_predicate("when x >= 5").serialize()


def image_meta(body: bytes) -> dict:
    header = pp.read_ppt_header(body)
    counts = {key: header[key] for key in ("atoms", "nodes", "edges", "prog_words", "max_steps", "max_stack")}
    return {"counts": counts, "fields": {"x": "int"}, "qualification": QUALIFICATION["envelope_id"],
            "wcet_cycles": pp.wcet_cycles(body)}


def release_of(body: bytes) -> str:
    return env.release_id([("policy.ppt", canon.sha256_hex(body))])


def envelope_doc(body: bytes, **changes) -> dict:
    """The envelope document of a `policy.ppt` release of `body`, with `changes` applied."""
    doc = {"artifact": "policy.ppt", "body_sha256": canon.sha256_hex(body), "body_size": len(body),
           canon.ENCODING_KEY: canon.CANON2, "expires": EXPIRES, "format": env.FORMAT, "meta": image_meta(body),
           "not_before": NOT_BEFORE, "policy_sha256": canon.sha256_hex(body), "release": release_of(body), "replaces": "", "seq": 1,
           "stream": STREAM, "targets": ["host"], "widens": False}
    doc.update(changes)
    return doc


def trust_store(**members) -> TrustStore:
    """A, B, R and Q in the authority role, R revoked and Q retired, and X in a role this version does not
    know (K4). U is held by no store."""
    keys = [public_raw(test_key(name)) for name in ("A", "B", "R", "Q")]
    ids = {name: env.key_id(public_raw(test_key(name))) for name in ("R", "Q")}
    store = TrustStore.with_keys(keys, revoked_keys=frozenset({ids["R"]}), retired=frozenset({ids["Q"]}), **members)
    other = TrustStore.with_keys([public_raw(test_key("X"))], role="timestamp")
    return replace(store, keys={**store.keys, **other.keys})


def pep_document(pep: verifier.PepView) -> dict:
    staged = pep.staged
    return {"kind": pep.kind, "stream": pep.stream, "floor": {"seq": pep.floor.seq, "ids": sorted(pep.floor.ids)},
            "active": pep.active, "qualification": pep.qualification, "body_bound": pep.body_bound,
            "has_clock": pep.has_clock,
            "staged": None if staged is None else {"stream": staged.stream, "seq": staged.seq,
                                                    "policy_sha256": staged.policy_sha256, "release": staged.release,
                                                    "replaces": staged.replaces, "widens": staged.widens}}


def pep_from_document(doc: dict) -> verifier.PepView:
    staged = doc["staged"]
    return verifier.PepView(kind=doc["kind"], stream=doc["stream"],
                            floor=verifier.Floor(doc["floor"]["seq"], frozenset(doc["floor"]["ids"])),
                            active=doc["active"], qualification=doc["qualification"], body_bound=doc["body_bound"],
                            has_clock=doc["has_clock"],
                            staged=None if staged is None else verifier.Staged(**staged))


def trust_from_document(doc: Optional[dict]) -> TrustStore:
    return TrustStore(readable=False) if doc is None else TrustStore.from_bytes(canon.canon2_bytes(doc))


def replay(case: dict) -> dict:
    """The verdict of the Python verifier on one corpus case, in the corpus's `expect` form."""
    verdict = verifier.verify(bytes.fromhex(case["sealed"]), bytes.fromhex(case["body"]),
                              trust=trust_from_document(case["trust"]), pep=pep_from_document(case["pep"]),
                              now=case["now"])
    return {"cause": verdict.cause, "unchanged": verdict.unchanged, "time_floor": verdict.time_floor,
            "envelope_id": verdict.envelope.envelope_id if verdict.envelope is not None else None}


def build_cases(kind: str, spec: Dict[int, dict]) -> List[dict]:
    """The verifier cases on a PEP of `kind`: on `host` every case that runs in Rust or only in Python, for
    Python and Rust, and on `mesh` every case that runs in the C core, for Python and the C core (I1)."""
    body = image()
    signer = test_key("A")
    implementations = {"host": ("P", "R"), "mesh": ("P", "C")}[kind]
    cases: List[dict] = []

    def view(**members) -> verifier.PepView:
        if kind != "host":
            members.pop("qualification", None)               # only a host admits images under a qualification
        return verifier.PepView(kind, STREAM, **members)

    def kind_doc(body_: bytes, **changes) -> dict:
        return envelope_doc(body_, **{"targets": [kind], **changes})

    default_pep = view(qualification=QUALIFICATION)

    def add(number: int, name: str, expected: Optional[str], sealed: bytes, *, payload: bytes = body,
            trust: Optional[TrustStore] = None, pep: verifier.PepView = default_pep, now: int = NOW,
            unreadable: bool = False, unchanged: bool = False) -> None:
        runs_on = spec[number]["runs_on"]
        if not ("C" in runs_on if kind == "mesh" else "R" in runs_on or "C" not in runs_on):
            return
        store = trust_store() if trust is None else trust
        suffix = "" if kind == "host" else f"_on_{kind}"
        case = {"case": number, "name": f"{number:03d}_{name}{suffix}",
                "runs_on": [implementation for implementation in runs_on if implementation in implementations],
                "trust": None if unreadable else store.document(), "pep": pep_document(pep), "now": now,
                "sealed": sealed.hex(), "body": payload.hex()}
        case["expect"] = replay(case)
        assert (case["expect"]["cause"], case["expect"]["unchanged"]) == (expected, unchanged), (
            case["name"], case["expect"], expected)
        cases.append(case)

    def raw(doc: dict) -> bytes:
        return canon2.dumps(doc)

    def sealed_by(envelope_bytes: bytes, *names: str) -> bytes:
        return env.seal(envelope_bytes, [test_key(name) for name in names])

    good = raw(kind_doc(body))
    good_sealed = sealed_by(good, "A")
    good_id = env.envelope_id(good)

    # E1 to E8, S1, S2: the envelope and the container read
    add(1, "round_trip", None, good_sealed)
    doc = kind_doc(body)
    del doc["meta"]
    add(2, "member_missing", "dist:bad-format", sealed_by(raw(doc), "A"))
    add(3, "member_extra", "dist:bad-format", sealed_by(raw(kind_doc(body, note="x")), "A"))
    reversed_doc = json.dumps(dict(sorted(kind_doc(body).items(), reverse=True)), separators=(",", ":"),
                              sort_keys=False, ensure_ascii=False).encode()
    add(4, "members_out_of_order", "document:not-canonical", sealed_by(reversed_doc, "A"))
    add(5, "unknown_artifact", "dist:bad-format", sealed_by(raw(kind_doc(body, artifact="policy.zip")), "A"))
    add(5, "unknown_target", "dist:bad-format", sealed_by(raw(kind_doc(body, targets=[kind, "toaster"])), "A"))
    add(6, "expires_not_above_not_before", "dist:bad-format",
        sealed_by(raw(kind_doc(body, expires=NOT_BEFORE)), "A"))
    long_doc = kind_doc(body)
    long_doc["meta"] = {**long_doc["meta"], "fields": {**long_doc["meta"]["fields"], "pad": ""}}
    long_doc["meta"]["fields"]["pad"] = "o" * (env.MAX_ENVELOPE + 1 - len(raw(long_doc)))
    long = raw(long_doc)
    assert len(long) == env.MAX_ENVELOPE + 1
    add(7, "envelope_2049_bytes", "dist:bad-format",
        env.seal_entries(long, [(env.key_id(public_raw(signer)), signer.sign(env.signed_message(long)))]))
    add(7, "body_over_bound", "dist:too-large", good_sealed,
        pep=view(qualification=QUALIFICATION, body_bound=len(body) - 1))

    a_entry = env.unseal(good_sealed)[1][0]
    b_entry = env.unseal(sealed_by(good, "B"))[1][0]
    two = sorted([a_entry, b_entry])
    add(8, "wrong_magic", "dist:bad-format", b"XXDE" + good_sealed[4:])
    add(8, "wrong_version", "dist:bad-format", good_sealed[:4] + b"\x02" + good_sealed[5:])
    add(8, "short", "dist:bad-format", good_sealed[:-1])
    add(8, "unsorted_entries", "dist:bad-format", env.seal_entries(good, [two[1], two[0]]))
    add(8, "repeated_key", "dist:bad-format", env.seal_entries(good, [a_entry, a_entry]))
    add(8, "zero_entries", "dist:bad-format", env.seal_entries(good, []))
    five = sorted(env.unseal(sealed_by(good, name))[1][0] for name in ("A", "B", "R", "Q", "U"))
    add(8, "five_entries", "dist:bad-format", env.seal_entries(good, five))

    # S1, S3 to S6: the signatures
    from prismpath.ledgers.intoto import pae
    add(9, "over_the_envelope_bytes_alone", "sig:invalid", env.seal_entries(good, [(a_entry[0], signer.sign(good))]))
    add(9, "another_payload_type", "sig:invalid",
        env.seal_entries(good, [(a_entry[0], signer.sign(pae("application/vnd.in-toto+json", good)))]))
    add(10, "unknown_key_only", "dist:unknown-key", sealed_by(good, "U"))
    add(11, "trusted_and_unknown", None, sealed_by(good, "A", "U"))
    forged_b = (b_entry[0], test_key("B").sign(env.signed_message(good + b" ")))
    add(12, "trusted_good_and_trusted_failing_is_skipped", None, env.seal_entries(good, sorted([a_entry, forged_b])))
    add(13, "revoked_key_only", "sig:revoked-key", sealed_by(good, "R"))
    add(13, "retired_key_only", "sig:revoked-key", sealed_by(good, "Q"))

    # E4, K1
    add(15, "body_unchanged_is_the_image", None, good_sealed)
    add(16, "trust_store_unreadable", "dist:unknown-key", good_sealed, unreadable=True)

    # Q1 to Q3, V8: the floor
    floored = sealed_by(raw(kind_doc(body, seq=5)), "A")
    floored_id = env.envelope_id(raw(kind_doc(body, seq=5)))
    add(20, "seq_below_floor", "dist:seq-replay", sealed_by(raw(kind_doc(body, seq=4)), "A"),
        pep=view(floor=verifier.Floor(5, frozenset({floored_id})),
                             qualification=QUALIFICATION))
    add(21, "seq_at_floor_committed_id", None, floored, unchanged=True,
        pep=view(floor=verifier.Floor(5, frozenset({floored_id})),
                             qualification=QUALIFICATION))
    add(22, "seq_at_floor_other_id", "dist:seq-replay", floored,
        pep=view(floor=verifier.Floor(5, frozenset({good_id})),
                             qualification=QUALIFICATION))

    # T3, T4, V6: time
    add(28, "not_before_301_ahead", "dist:not-yet-valid", good_sealed, now=NOT_BEFORE - 301)
    add(28, "not_before_299_ahead", None, good_sealed, now=NOT_BEFORE - 299)
    add(29, "time_equals_expires", "dist:expired", good_sealed, now=EXPIRES)
    add(29, "time_one_second_before_expires", None, good_sealed, now=EXPIRES - 1)

    # V1, V5, V7, V9, V11
    add(39, "two_failures_report_the_earlier", "dist:target-mismatch",
        sealed_by(raw(kind_doc(body, targets=["xdp"])), "A"), now=EXPIRES)
    add(40, "another_target_kind", "dist:target-mismatch", sealed_by(raw(kind_doc(body, targets=["agent"])), "A"))
    add(40, "an_artifact_the_kind_does_not_use", "dist:target-mismatch",
        sealed_by(raw(kind_doc(body, artifact="policy.core", meta={})), "A"))
    add(40, "another_stream", "dist:target-mismatch", sealed_by(raw(kind_doc(body, stream="host/other")), "A"))
    add(41, "envelope_id_revoked", "dist:revoked", good_sealed, trust=trust_store(revoked_envelopes=frozenset({good_id})))
    add(41, "policy_hash_revoked", "dist:revoked", good_sealed,
        trust=trust_store(revoked_policies=frozenset({canon.sha256_hex(body)})))
    add(42, "body_one_byte_short", "dist:body-mismatch", good_sealed, payload=body[:-1])
    add(42, "body_one_byte_changed", "dist:body-mismatch", good_sealed, payload=body[:-1] + bytes([body[-1] ^ 1]))
    meta = image_meta(body)
    add(44, "counts_differ", "manifest:count-mismatch",
        sealed_by(raw(kind_doc(body, meta={**meta, "counts": {**meta["counts"], "atoms": meta["counts"]["atoms"] + 1}})), "A"))
    add(44, "over_a_qualification_cap", "image:caps-exceeded", good_sealed,
        pep=view(qualification={**QUALIFICATION, "caps": {"atoms": 0}}))
    add(44, "wrong_wcet", "manifest:wcet-mismatch",
        sealed_by(raw(kind_doc(body, meta={**meta, "wcet_cycles": meta["wcet_cycles"] + 1})), "A"))

    # E11, V4: every meta member of its form, read before any check uses it
    for name, changes in (("fields_a_string", {"fields": "x"}), ("counts_an_integer", {"counts": 7}),
                          ("counts_lacking_a_member", {"counts": {key: value for key, value in meta["counts"].items()
                                                                  if key != "max_stack"}}),
                          ("packing_without_its_sidecar", {"packing": {"profile": "spiral"}})):
        add(127, name, "dist:bad-format", sealed_by(raw(kind_doc(body, meta={**meta, **changes})), "A"))

    # E7, E10, V10: one release id per release
    other_release = env.release_id([("policy.ppt", canon.sha256_hex(body)), ("policy.spiral", "ab" * 32)])
    add(114, "staged_release_id_differs", "dist:incomplete", good_sealed,
        pep=view(qualification=QUALIFICATION,
                             staged=verifier.Staged(STREAM, 1, canon.sha256_hex(body), other_release, "", False)))

    # S6: the signature block is not signed
    u_entry = env.unseal(sealed_by(good, "U"))[1][0]
    add(117, "signed_with_an_entry_added", None, env.seal_entries(good, sorted([a_entry, u_entry])))
    add(117, "signed_with_its_counting_entry_removed", "dist:unknown-key", env.seal_entries(good, [u_entry]))
    add(117, "unsigned_with_a_failing_entry_added", "sig:invalid", env.seal_entries(good, sorted([u_entry, forged_b])))

    # K4: a key in a role this version does not know is kept and never counts
    add(118, "unknown_role_signs", "dist:unknown-key", sealed_by(good, "X"))

    # T2, T3, V13: a PEP with no clock takes the authority's not_before as its time
    month = 30 * 86400
    add(119, "no_clock_a_month_behind", None, good_sealed, now=NOT_BEFORE - month,
        pep=view(qualification=QUALIFICATION, has_clock=False))
    add(119, "clock_a_month_early", "dist:not-yet-valid", good_sealed, now=NOT_BEFORE - month)

    return cases


def build() -> dict:
    spec = spec_cases()
    cases = build_cases("host", spec) + build_cases("mesh", spec)
    release_ids = []
    three = [("policy.core", canon.sha256_hex(b"core")), ("egress.hosts", canon.sha256_hex(b"[]")),
             ("sandbox.profile", canon.sha256_hex(b"profile"))]
    for name, artifacts in (("three_artifacts", three),
                            ("one_body_changed", three[:2] + [("sandbox.profile", canon.sha256_hex(b"profile2"))])):
        release_ids.append({"case": 115, "name": f"115_{name}", "runs_on": spec[115]["runs_on"],
                            "artifacts": [list(pair) for pair in artifacts], "release": env.release_id(artifacts)})
    assert release_ids[0]["release"] != release_ids[1]["release"]

    return {"format": "prismpath.dist-corpus/1", "spec": "docs/design/spec-policy-distribution.md",
            "note": "Each case is bytes in and the Python verifier's result out. Every implementation named in "
                    "runs_on replays it and must report exactly the expected cause, unchanged flag, time floor "
                    "and envelope id. Keys come from fixed seeds (gen_distribution_corpus.test_key).",
            "cases": cases, "release_ids": release_ids}


def main() -> int:
    doc = build()
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print(f"wrote {OUT}  ({len(doc['cases'])} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
