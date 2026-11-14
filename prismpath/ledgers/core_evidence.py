# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A signed core run, produced and verified (docs/design/spec-verified-core.md, section 11).

A core run is a directory of one implementation's decisions on a set of cases, written so that a reader who
trusts neither the implementation nor the person who ran it can check what was decided:

  * every policy image's canon/2 bytes are signed with the authority key (`images.jsonl`, an image
    attestation per case, Ed25519 over `IMAGE_DOMAIN` and the image bytes);
  * every decision has a receipt (`receipts.jsonl`, one canon/2 line each) binding the image's hash, the
    reading's hash and the decision with its registered cause; a receipt is not signed by itself;
  * the receipts are the leaves of a Merkle tree, and one root statement signed with the instance key
    (`receipts.roots.jsonl`, `prismpath.core-run-root/1`, log `core-run`) states their root and count, and
    binds the run's manifest (`run.json`) through its `policy` member. It is a canon/2 document with its
    time an integer count of microseconds (`time_us`), signed over its own domain prefix.

`verify` checks the keys against the pins and the manifest, the root statement, the Merkle root over the
receipts, every image attestation, every receipt's image and reading hashes, and replays every decision, or
a sample, through the Python reference kernel (`prismpath.kernel.core_reference`). A case outside the core
(section 1) is excluded with its reason, which the verifier recomputes from the image with the oracle's own
check ported from Lean (`prismpath.kernel.core_policy`), so every receipted decision must be the core's. A
run whose keys the reader does not pin verifies as `signed-unpinned`: its signatures hold under the keys it
carries, which says nothing about whose keys they are.

This module ships in the package and needs the standard library, the kernel and the `signing` extra
(`cryptography`), never numpy. The research tool `formal/diff/core_evidence.py` is this module with the
differential's case generator and a replay through the Lean oracle (`--oracle`) on top; the Rust twin is
`prismpath-hotswap-rs/examples/core_evidence.rs`. `prismpath evidence verify RUN` is the command line.
"""
from __future__ import annotations

import hashlib
import random
from pathlib import Path

from prismpath.kernel import canon2, causes, core_policy, core_reference
from prismpath.ledgers import root_statement

RUN_FORMAT = "prismpath.core-run/1"
IMAGE_FORMAT = "prismpath.core-image/1"
RECEIPT_FORMAT = "prismpath.core-receipt/1"
# The run's root statement: a canon/2 document of its own format, signed over its own domain prefix, so
# it can never be presented as an audit log's root statement (`prismpath-root-statement/2`), an image
# attestation or a pack signature, or the reverse.
ROOT_FORMAT = "prismpath.core-run-root/1"
ROOT_DOMAIN = b"prismpath.core-run-root/1\x00"
ROOT_MEMBERS = ("format", "log", "root", "leaves", "time_us", "trigger", "key_id", "public_key", "policy", "sig")
# Prefixed to the image bytes before signing, so an image attestation can never be presented as a pack
# manifest or root statement signature, or the reverse.
IMAGE_DOMAIN = b"prismpath.core-image/1\x00"
LOG_CORE_RUN = "core-run"
FILES = ("run.json", "cases.jsonl", "images.jsonl", "receipts.jsonl", "receipts.roots.jsonl",
         "authority.pub", "instance.pub")
REFERENCE = "the reference kernel"   # what `replay_through_reference` holds a receipt to, in its messages


class Bad(Exception):
    """A run the verifier refuses; the message names the first check that failed."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _lines(path: Path):
    text = Path(path).read_bytes()
    lines = text.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    return lines


# ----------------------------------------------------------------- the cases
def read_cases(path: Path):
    """A run's inputs, one canon/2 line per case: the image and the readings as hex of their bytes, and the
    flow the image renders to (the text the reference reads), or null."""
    cases = []
    for line in _lines(path):
        row = canon2.loads(line)
        cases.append({"id": row["case"], "image": bytes.fromhex(row["image"]), "flow": row["flow"],
                      "flow_why": None if row["flow"] is not None else _why(bytes.fromhex(row["image"])),
                      "readings": [bytes.fromhex(raw) for raw in row["readings"]]})
    return cases


def _why(image: bytes) -> str:
    try:
        canon2.loads(image)
    except canon2.Canon2Error as error:
        return f"unreadable:{error.rule}"
    return "unrenderable:image"


# ----------------------------------------------------------------- the core's scope
def outside_core(image: bytes, flow):
    """Why a case is not a decision of the core, or None (spec section 1): an image the oracle refuses for
    reading an engine counter, which is no reading field (`engine-counter`), decided by the oracle's own
    check of the image ported from Lean (`core_policy.refuses_for_counter`, Lean `counterRefusal`); one that
    reads but has no flow rendering (`unrenderable`); and one that defines no field yet routes on a
    condition, which the reference takes by its inferred path (`inferred-path`). Decided from the image
    alone, so the verifier recomputes it; every other case is receipted, and every one of its decisions must
    be the oracle's. An image that mentions a counter but is refused for an earlier problem is receipted:
    the oracle refuses it for that problem, and so must the implementation."""
    try:
        doc = canon2.loads(image)
    except canon2.Canon2Error:
        return None
    if core_policy.refuses_for_counter(image):
        return "engine-counter"
    if flow is None:
        return "unrenderable"
    rules = doc.get("rules") if isinstance(doc, dict) else None
    whens = [rule.get("when") for rule in rules if isinstance(rule, dict)] if isinstance(rules, list) else []
    if doc.get("fields") == {} and any(when not in (["always"], ["never"]) for when in whens):
        return "inferred-path"
    return None


# ----------------------------------------------------------------- the decisions
def _decision(verdict) -> dict:
    """A receipt's decision members from a verdict in the oracle's shape."""
    if verdict["verdict"] == "route":
        return {"decision": "route", "target": verdict["target"]}
    out = {"decision": "refuse", "cause": verdict["cause"], "cause_code": verdict["code"]}
    if verdict.get("field"):
        out["field"] = verdict["field"]
    if verdict.get("reason"):
        out["reason"] = verdict["reason"]
    return out


def _reference_row(case, row):
    """The reference's decisions on one case from its python leg row, as (decisions, problem): a list of
    receipt decision members per reading, or None for a case it has no decision on (an image with no flow
    rendering), and a problem that makes the reference's answer no decision (a crash, an uncoded refusal)."""
    if row["policy"] == "accepted":
        if any(verdict.get("cause") == "crash" for verdict in row["readings"]):
            return None, f"case {case['id']}: the reference crashed: {row['readings']}"
        return [_decision(verdict) for verdict in row["readings"]], None
    if row["policy"] == "refused":
        if row.get("code") is None:
            return None, f"case {case['id']}: an uncoded refusal {row}"
        refusal = {"verdict": "refuse", "cause": row["cause"], "code": row["code"],
                   "field": row.get("field"), "reason": row.get("policy_reason") or
                   (row.get("reason") if row["cause"] in core_reference.UNREADABLE_POLICY else None)}
        return [_decision(refusal) for _raw in case["readings"]], None
    return None, None


def python_decisions(cases):
    """{case id: [decision per reading]} from the Python reference, or None for a case it has no decision on
    (an image with no flow rendering)."""
    rows = core_reference.python_leg(cases)
    out = {}
    for case in cases:
        decisions, problem = _reference_row(case, rows[case["id"]])
        if problem is not None:
            raise RuntimeError(problem)
        out[case["id"]] = decisions
    return out


# ----------------------------------------------------------------- producing a run
def ensure_keys(keys: Path):
    """The authority key (which says which policy may run) and the instance key (which attests what the run
    recorded), generated here when absent: test keys, never a deployment's."""
    from prismpath.hotswap import policy_pack
    keys = Path(keys)
    keys.mkdir(parents=True, exist_ok=True)
    if not (keys / "authority.key").exists():
        policy_pack.keygen(str(keys), "authority")
    if not (keys / "instance.key").exists():
        root_statement.keygen(str(keys), "instance")
    return keys / "authority.key", keys / "authority.pub", keys / "instance.key", keys / "instance.pub"


def produce(cases_path: Path, out: Path, keys: Path, decider: str = "python", time_us: int = None) -> dict:
    """Decide every case of a cases file with the Python reference and write the run to `out`."""
    from prismpath.hotswap import policy_pack
    cases_path, out = Path(cases_path), Path(out)
    authority_key, authority_pub, instance_key, instance_pub = ensure_keys(keys)
    root_statement.check_separation(root_statement.InstanceKey.load(str(instance_key)),
                                    [sha256_hex(authority_pub.read_bytes())])
    out.mkdir(parents=True, exist_ok=True)
    cases_bytes = cases_path.read_bytes()
    (out / "cases.jsonl").write_bytes(cases_bytes)
    cases = read_cases(out / "cases.jsonl")
    decisions = python_decisions(cases)

    signer = policy_pack._load_private(str(authority_key))
    authority_id = sha256_hex(authority_pub.read_bytes())
    images = bytearray()
    for case in cases:
        images += canon2.dumps({"format": IMAGE_FORMAT, "case": case["id"], "image_sha256": sha256_hex(case["image"]),
                                "key_id": authority_id, "sig": signer.sign(IMAGE_DOMAIN + case["image"]).hex()}) + b"\n"
    (out / "images.jsonl").write_bytes(bytes(images))

    receipts, leaves, excluded = bytearray(), [], []
    for case in cases:
        why = outside_core(case["image"], case["flow"])
        if why is not None:
            excluded.append({"case": case["id"], "why": why})
            continue
        if decisions[case["id"]] is None:
            raise RuntimeError(f"case {case['id']}: no decision on a case inside the core")
        for index, (raw, decision) in enumerate(zip(case["readings"], decisions[case["id"]])):
            receipt = {"format": RECEIPT_FORMAT, "idx": len(leaves), "case": case["id"], "reading": index,
                       "image_sha256": sha256_hex(case["image"]), "reading_sha256": sha256_hex(raw),
                       "decider": decider, **decision}
            line = canon2.dumps(receipt)
            receipts += line + b"\n"
            leaves.append(sha256_hex(line))
    (out / "receipts.jsonl").write_bytes(bytes(receipts))

    instance = root_statement.InstanceKey.load(str(instance_key))
    manifest = {"format": RUN_FORMAT, "decider": decider, "cases": len(cases), "receipts": len(leaves),
                "excluded": excluded, "cases_sha256": sha256_hex(cases_bytes),
                "images_sha256": sha256_hex(bytes(images)), "authority_key_id": authority_id,
                "instance_key_id": instance.key_id}
    manifest_bytes = canon2.dumps(manifest)
    (out / "run.json").write_bytes(manifest_bytes + b"\n")
    (out / "authority.pub").write_bytes(authority_pub.read_bytes())
    (out / "instance.pub").write_bytes(instance_pub.read_bytes())
    # one canon/2 root statement over every receipt, binding the manifest
    statement = make_root_statement(instance, root_statement.merkle_root(leaves), len(leaves), manifest_bytes,
                                    time_us=time_us)
    (out / "receipts.roots.jsonl").write_bytes(canon2.dumps(statement) + b"\n")
    return manifest


# ----------------------------------------------------------------- the run's root statement
def root_signed_bytes(statement: dict) -> bytes:
    """What the root statement's signature covers: its domain prefix, then the canon/2 bytes of every
    member but `sig`."""
    return ROOT_DOMAIN + canon2.dumps({key: value for key, value in statement.items() if key != "sig"})


def make_root_statement(instance, root: str, leaves: int, manifest_bytes: bytes, time_us: int = None) -> dict:
    """The run's root statement, `prismpath.core-run-root/1`, signed with the instance key: the Merkle root
    of the receipts' leaves and their count, the signer's clock as an integer count of microseconds since
    the epoch, and the SHA-256 of the manifest. Integers and strings only, so it is a canon/2 document."""
    import time as _time
    statement = {"format": ROOT_FORMAT, "log": LOG_CORE_RUN, "root": root, "leaves": int(leaves),
                 "time_us": int(time_us if time_us is not None else _time.time_ns() // 1000), "trigger": LOG_CORE_RUN,
                 "key_id": instance.key_id, "public_key": instance.public_raw.hex(),
                 "policy": {"core_run_sha256": sha256_hex(manifest_bytes)}}
    statement["sig"] = instance.sign(root_signed_bytes(statement)).hex()
    return statement


def _hex_of(value, size: int) -> bool:
    return isinstance(value, str) and len(value) == 2 * size and all(char in "0123456789abcdef" for char in value)


def _public_key(raw: bytes, what: str):
    """An Ed25519 public key from a run's raw 32 bytes, or Bad naming which key does not read."""
    _Priv, Pub, _ser, _Invalid = root_statement._ed25519()
    try:
        return Pub.from_public_bytes(raw)
    except ValueError:
        raise Bad(f"the run's {what} key is not a raw 32 byte Ed25519 public key") from None


def verify_root_statement(data: bytes, leaves, manifest_bytes: bytes, instance_raw: bytes) -> dict:
    """The run's root statement, checked in full, or Bad: one canon/2 line in its canonical spelling, exactly
    the members of `prismpath.core-run-root/1` with their types, the run's instance key, a signature under
    that key over the domain prefix and the body, the Merkle root of every receipt and their count, and the
    manifest's hash."""
    _Priv, _Pub, _ser, InvalidSignature = root_statement._ed25519()
    lines = data.split(b"\n")
    if len(lines) != 2 or lines[1] != b"":
        raise Bad("the root statement is not one line")
    try:
        statement = canon2.loads(lines[0])
    except canon2.Canon2Error as error:
        raise Bad(f"the root statement is not a canon/2 document ({error.rule})") from None
    if not isinstance(statement, dict) or canon2.dumps(statement) != lines[0]:
        raise Bad("the root statement is not in its canonical canon/2 spelling")
    if set(statement) != set(ROOT_MEMBERS) or statement["format"] != ROOT_FORMAT or statement["log"] != LOG_CORE_RUN \
            or statement["trigger"] != LOG_CORE_RUN:
        raise Bad("the root statement is not a prismpath.core-run-root/1 statement")
    for key in ("leaves", "time_us"):
        if type(statement[key]) is not int or statement[key] < 0:
            raise Bad(f"the root statement's {key} is not a nonnegative integer")
    if not isinstance(statement["root"], str) or not _hex_of(statement["key_id"], 32) \
            or not _hex_of(statement["public_key"], 32) or not _hex_of(statement["sig"], 64):
        raise Bad("the root statement's root, key or signature is malformed")
    if statement["public_key"] != instance_raw.hex() or statement["key_id"] != sha256_hex(instance_raw):
        raise Bad("the root statement is not signed with the run's instance key")
    try:
        _public_key(instance_raw, "instance").verify(bytes.fromhex(statement["sig"]), root_signed_bytes(statement))
    except (InvalidSignature, ValueError):
        raise Bad("the root statement's signature does not verify") from None
    if statement["leaves"] != len(leaves) or statement["root"] != root_statement.merkle_root(leaves):
        raise Bad("the root statement does not verify: its root is not the receipts' Merkle root")
    if statement["policy"] != {"core_run_sha256": sha256_hex(manifest_bytes)}:
        raise Bad("the root statement does not bind this run.json")
    return statement


# ----------------------------------------------------------------- verifying a run
def _norm(verdict) -> tuple:
    """A decision as a comparable tuple; an empty field (the oracle spells a threshold on no field `""`) is
    no field."""
    if verdict.get("decision", verdict.get("verdict")) == "route":
        return ("route", verdict["target"])
    return ("refuse", verdict["cause"], verdict.get("cause_code", verdict.get("code")), verdict.get("field") or None,
            verdict.get("reason") or None)


def verify(run: Path, *, sample=200, seed=0, pin_authority=None, pin_instance=None, replay=None) -> dict:
    """Every check of a run, or Bad naming the first that fails. Returns a summary.

    `sample` is how many receipts to replay (None for every one), chosen with `seed`; `pin_authority` and
    `pin_instance` name the reader's own copies of the two public keys, and without both the root statement
    is `signed-unpinned`. `replay` decides the chosen receipts again, `replay_through_reference` when None;
    the research tool passes its replay through the Lean oracle. A file that does not read as its format is
    refused like any other failed check."""
    try:
        summary, receipts = _check(Path(run), pin_authority, pin_instance)
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as error:   # a malformed part of the run
        raise Bad(f"the run does not read as a core run ({type(error).__name__}: {error})") from None
    # every decision, or a sample, decided again
    rng = random.Random(seed)
    chosen = receipts if sample is None or sample >= len(receipts) else rng.sample(receipts, sample)
    counts = (replay or replay_through_reference)(chosen)
    if counts["disagree"]:
        raise Bad(f"{counts['disagree']} replayed decisions differ from {counts['against']}: {counts['first']}")
    return {**summary, **counts}


def _check(run: Path, pin_authority, pin_instance):
    """Every check of a run but the replay: the summary so far and the receipts, each with its case and
    reading index, or Bad."""
    for name in FILES:
        if not (run / name).exists():
            raise Bad(f"the run has no {name}")
    manifest_bytes = (run / "run.json").read_bytes().rstrip(b"\n")
    try:
        manifest = canon2.loads(manifest_bytes)
    except canon2.Canon2Error as error:
        raise Bad(f"run.json is not a canon/2 document ({error.rule})") from None
    if not isinstance(manifest, dict) or manifest.get("format") != RUN_FORMAT:
        raise Bad("run.json is not a prismpath.core-run/1 manifest")
    if canon2.dumps(manifest) != manifest_bytes:
        raise Bad("run.json is not in its canonical canon/2 spelling")

    # the keys: pinned when the reader names them, else the ones the run carries
    authority_raw = (run / "authority.pub").read_bytes()
    instance_raw = (run / "instance.pub").read_bytes()
    pinned = pin_authority is not None and pin_instance is not None
    if pin_authority is not None and Path(pin_authority).read_bytes() != authority_raw:
        raise Bad("the run's authority key is not the pinned authority key")
    if pin_instance is not None and Path(pin_instance).read_bytes() != instance_raw:
        raise Bad("the run's instance key is not the pinned instance key")
    authority_id, instance_id = sha256_hex(authority_raw), sha256_hex(instance_raw)
    if manifest["authority_key_id"] != authority_id or manifest["instance_key_id"] != instance_id:
        raise Bad("run.json names other keys than the run carries")
    if authority_id == instance_id:
        raise Bad("the instance key is also the authority key")

    # the root statement over the receipts, and the manifest it binds
    receipt_lines = _lines(run / "receipts.jsonl")
    leaves = [sha256_hex(line) for line in receipt_lines]
    statement = verify_root_statement((run / "receipts.roots.jsonl").read_bytes(), leaves, manifest_bytes, instance_raw)
    if manifest["receipts"] != len(leaves):
        raise Bad("run.json counts other receipts than the run holds")

    # the cases and the image attestations
    if sha256_hex((run / "cases.jsonl").read_bytes()) != manifest["cases_sha256"]:
        raise Bad("cases.jsonl is not the file run.json names")
    if sha256_hex((run / "images.jsonl").read_bytes()) != manifest["images_sha256"]:
        raise Bad("images.jsonl is not the file run.json names")
    cases = read_cases(run / "cases.jsonl")
    if len(cases) != manifest["cases"]:
        raise Bad("run.json counts other cases than cases.jsonl holds")
    _Priv, _Pub, _ser, InvalidSignature = root_statement._ed25519()
    authority = _public_key(authority_raw, "authority")
    image_lines = _lines(run / "images.jsonl")
    if len(image_lines) != len(cases):
        raise Bad("images.jsonl does not hold one attestation per case")
    for case, line in zip(cases, image_lines):
        attestation = canon2.loads(line)
        if canon2.dumps(attestation) != line or attestation.get("format") != IMAGE_FORMAT \
                or attestation.get("case") != case["id"] or attestation.get("key_id") != authority_id \
                or attestation.get("image_sha256") != sha256_hex(case["image"]):
            raise Bad(f"case {case['id']}: the image attestation does not match the image")
        try:
            authority.verify(bytes.fromhex(attestation["sig"]), IMAGE_DOMAIN + case["image"])
        except (InvalidSignature, ValueError):
            raise Bad(f"case {case['id']}: the image signature does not verify") from None

    # every receipt, in order: every reading of every case the run did not exclude, once
    excluded = {}
    for row in manifest["excluded"]:
        if not isinstance(row, dict) or set(row) != {"case", "why"}:
            raise Bad("run.json lists an excluded case without its reason")
        excluded[row["case"]] = row["why"]
    for case in cases:
        why = outside_core(case["image"], case["flow"])
        if excluded.get(case["id"]) != why:
            raise Bad(f"case {case['id']}: excluded as {excluded.get(case['id'])}, but the image says {why}")
    expected = [(case, index) for case in cases if case["id"] not in excluded for index in range(len(case["readings"]))]
    if len(expected) != len(receipt_lines):
        raise Bad(f"{len(receipt_lines)} receipts for {len(expected)} decisions")
    receipts = []
    for idx, ((case, index), line) in enumerate(zip(expected, receipt_lines)):
        receipt = canon2.loads(line)
        if canon2.dumps(receipt) != line:
            raise Bad(f"receipt {idx} is not in its canonical canon/2 spelling")
        want = {"format": RECEIPT_FORMAT, "idx": idx, "case": case["id"], "reading": index,
                "image_sha256": sha256_hex(case["image"]), "reading_sha256": sha256_hex(case["readings"][index]),
                "decider": manifest["decider"]}
        if any(receipt.get(key) != value for key, value in want.items()):
            raise Bad(f"receipt {idx} does not bind case {case['id']} reading {index}")
        if receipt.get("decision") == "route":
            if set(receipt) != set(want) | {"decision", "target"}:
                raise Bad(f"receipt {idx}: a route names a target and nothing else")
        elif receipt.get("decision") == "refuse":
            if causes.code(receipt.get("cause")) != receipt.get("cause_code") or receipt.get("cause_code") in (None, 0) \
                    or not set(receipt) <= set(want) | {"decision", "cause", "cause_code", "field", "reason"}:
                raise Bad(f"receipt {idx}: a refusal carries a registered nonzero cause code")
        else:
            raise Bad(f"receipt {idx}: the decision is a route or a refusal")
        receipts.append((case, index, receipt))
    return {"run": str(run), "decider": manifest["decider"], "cases": len(cases), "excluded": len(excluded),
            "receipts": len(receipts), "root": statement["root"],
            "root_statement": "signed" if pinned else "signed-unpinned", "images": len(cases)}, receipts


def replay_through_reference(chosen) -> dict:
    """Each chosen receipt's image and reading decided again by the Python reference kernel, and the
    decisions compared: every receipted case is inside the core, so every decision must be the reference's,
    with its cause, code, field and reason. Each case's flow is parsed once for all of its chosen readings."""
    by_case = {}
    for case, index, receipt in chosen:
        by_case.setdefault(case["id"], (case, []))[1].append((index, receipt))
    subcases = [{"id": case["id"], "image": case["image"], "flow": case["flow"], "flow_why": case["flow_why"],
                 "readings": [case["readings"][index] for index, _receipt in picked]}
                for case, picked in by_case.values()]
    rows = core_reference.python_leg(subcases)
    counts = {"replayed": len(chosen), "agree": 0, "disagree": 0, "first": None, "against": REFERENCE}
    for sub in subcases:
        decisions, problem = _reference_row(sub, rows[sub["id"]])
        for position, (_index, receipt) in enumerate(by_case[sub["id"]][1]):
            reference = decisions[position] if decisions is not None else (problem or "no decision")
            if decisions is not None and _norm(reference) == _norm(receipt):
                counts["agree"] += 1
            else:
                counts["disagree"] += 1
                counts["first"] = counts["first"] or {"case": sub["id"], "receipt": receipt, "reference": reference}
    return counts
