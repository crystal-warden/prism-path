# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A signed core run, produced and verified (docs/design/spec-verified-core.md, section 11).

A core run is a directory of one implementation's decisions on a set of cases, written so that a reader who
trusts neither the implementation nor the person who ran it can check what was decided:

  * every policy image's canon/2 bytes are signed with the authority key (`images.jsonl`, an image
    attestation per case, Ed25519 over `IMAGE_DOMAIN` and the image bytes);
  * every decision has a receipt (`receipts.jsonl`, one canon/2 line each) binding the image's hash, the
    reading's hash and the decision with its registered cause; a receipt is not signed by itself;
  * the receipts are the leaves of a Merkle tree, RFC 6962's (`ledger_ots.MERKLE_SCHEME`: a leaf hashes as
    SHA-256(0x00 || leaf), a node as SHA-256(0x01 || left || right), split at the largest power of two below
    the count, nothing duplicated), and one root statement signed with the instance key
    (`receipts.roots.jsonl`, `prismpath.core-run-root/2`, log `core-run`) states their root and count, and
    binds the run's manifest (`run.json`) through its `policy` member. It is a canon/2 document with its
    time an integer count of microseconds (`time_us`), signed over its own domain prefix.

`verify` checks the keys against the pins and the manifest, the root statement, the Merkle root over the
receipts, every image attestation, that every case's stored flow is the canonical rendering of its signed
image (`prismpath.kernel.core_render`, since the reference decides from the flow and an edited flow would have
it decide a policy the authority never signed), every receipt's image and reading hashes, and replays every
decision, or
a sample, through the Python reference kernel (`prismpath.kernel.core_reference`). A case outside the core
(section 1) is excluded with its reason, which the verifier recomputes from the image with the oracle's own
check ported from Lean (`prismpath.kernel.core_policy`), so every receipted decision must be the core's. A
run whose keys the reader does not pin verifies as `signed-unpinned`: its signatures hold under the keys it
carries, which says nothing about whose keys they are.

A cFS core run with an action floor or a fallback policy (spec-policy-distribution.md, RC4) gives each basis its own
case, `release` (the default), `floor` or `fallback`, and the `would` lines of AF7 a case of the release marked not
enacted. `install.jsonl` holds every install statement the PEP decided under and every `install.trust` it applied, as
sealed envelopes in the order applied, and `rates.jsonl` one line per counted override (RC3): the floor rule, the
start of its window, the count after it and the hash of its receipt. `run.json` names both by hash and the install
trust sequence the run ends at. The image attestation of a `floor` or `fallback` case is the signature block of its
install statement, named by its envelope id. `verify` then pins the install key set beside the authority key
(`pin_install`, the `install` part of an anchor), refuses a run that holds a `floor` or `fallback` case without it,
applies each `install.trust` from the pinned set by IS11, requires each install set to be signed at the threshold
under the key set in force when it was applied, holds each such case's image to the policy hash its statement signs,
requires a not enacted line of the release, or of the fallback policy when that decided, for every reading the floor
decided with a set to ask (a floor case with `asked` false had none, so its `would` is none), and checks that the
counts of AF8 rise by one within a window and never pass the signed `allows`. Every case, `would` lines included, is
then replayed under its own image. The receipt lines keep their format.

An `operator` case (OP2, OP3) holds one request an operator answered: its image is the floor's, `install` names the
floor's statement and `answer` the operator's `operator.answer`, which `install.jsonl` holds in the order applied,
signed by one operator key of the install record then in force. The answer's `receipt` is the SHA-256 of a line of
`escalations.jsonl`, the escalation document the PEP opened (`prismpath.cfs-escalation/1`), under the same floor and
for the same reading, and each answer answers once. Its receipt is the answer's: a route to `allow`, or the
escalation's own refusal. It is checked against the answer, never replayed.

A run whose root statement is `prismpath.core-run-root/1` was written over the retired Merkle tree (no domain
prefixes, the last node of an odd layer duplicated, so [a, b, c] and [a, b, c, c] shared a root); it is refused
as such, never checked under the new tree, and has to be produced again.

This module ships in the package and needs the standard library, the kernel and the `signing` extra
(`cryptography`, `pip install prismpath[signing]`), never numpy: producing a run signs with Ed25519 and
verifying one checks Ed25519 signatures, and both raise `MissingExtra` without it. The research tool `formal/diff/core_evidence.py` is this module with the
differential's case generator and a replay through the Lean oracle (`--oracle`) on top; the Rust twin is
`prismpath-hotswap-rs/examples/core_evidence.rs`. `prismpath evidence verify RUN` is the command line.
"""
from __future__ import annotations

import hashlib
import random
from pathlib import Path

from prismpath.kernel import canon2, causes, core_policy, core_reference, core_render
from prismpath.ledgers import ledger_ots, root_statement
from prismpath.onion import keys as onion_keys

RUN_FORMAT = "prismpath.core-run/1"
IMAGE_FORMAT = "prismpath.core-image/1"
RECEIPT_FORMAT = "prismpath.core-receipt/1"
# The run's root statement: a canon/2 document of its own format, signed over its own domain prefix, so
# it can never be presented as an audit log's root statement (`prismpath-root-statement/3`), an image
# attestation or a pack signature, or the reverse. `/2` states a root of the RFC 6962 tree; `/1` stated one of
# the retired tree and is refused by name (OLD_ROOT_FORMATS).
ROOT_FORMAT = "prismpath.core-run-root/2"
ROOT_DOMAIN = b"prismpath.core-run-root/2\x00"
OLD_ROOT_FORMATS = ("prismpath.core-run-root/1",)
ROOT_MEMBERS = ("format", "log", "root", "leaves", "time_us", "trigger", "key_id", "public_key", "policy", "sig")
# Prefixed to the image bytes before signing, so an image attestation can never be presented as a pack
# manifest or root statement signature, or the reverse.
IMAGE_DOMAIN = b"prismpath.core-image/1\x00"
LOG_CORE_RUN = "core-run"
FILES = ("run.json", "cases.jsonl", "images.jsonl", "receipts.jsonl", "receipts.roots.jsonl",
         "authority.pub", "instance.pub")
INSTALL_FILES = ("install.jsonl", "rates.jsonl")   # RC4: in a run whose run.json names them
ANSWER_LIFE = 600                                   # OP2, OP3: an answer's and an escalation's life
BASES = ("release", "floor", "fallback", "operator")   # RC1, RC4: a case's basis; `release` when none is named
ESCALATION_FORMAT = "prismpath.cfs-escalation/1"   # OP3: what an operator's answer names on cfs
INSTALL_OF = {"floor": "install.floor", "fallback": "install.fallback"}
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
    flow the image renders to (the text the reference reads), or null. `flow_why` is why the image has no
    rendering, recomputed from the image; whether the stored flow is the image's rendering is `flow_problem`'s
    question, which the verifier asks of every case."""
    cases = []
    for line in _lines(path):
        row = canon2.loads(line)
        image = bytes.fromhex(row["image"])
        cases.append({"id": row["case"], "image": image, "flow": row["flow"],
                      "flow_why": None if row["flow"] is not None else core_render.flow_of(image)[1],
                      "readings": [bytes.fromhex(raw) for raw in row["readings"]],
                      "basis": row.get("basis", "release"), "enacted": row.get("enacted", True),
                      "install": row.get("install"), "asked": row.get("asked", True), "answer": row.get("answer")})
    return cases


def write_cases(cases, out: Path) -> None:
    """A run's inputs from cases with an `id`, an `image` and `readings` (bytes): one canon/2 line per case,
    the image and the readings as hex, and the image's canonical rendering as its flow (null for an image with
    none), so the file is what `verify` holds a run's cases to."""
    with open(out, "wb") as handle:
        for case in cases:
            flow, _why = core_render.flow_of(case["image"])
            row = {"case": case["id"], "image": case["image"].hex(), "flow": flow,
                   "readings": [raw.hex() for raw in case["readings"]]}
            for key, default in (("basis", "release"), ("enacted", True), ("install", None), ("asked", True),
                                 ("answer", None)):
                if case.get(key, default) != default:
                    row[key] = case[key]               # RC4: only a cFS run with install statements names these
            handle.write(canon2.dumps(row) + b"\n")


def flow_problem(case) -> str:
    """Why a case's stored flow is not its signed image's rendering, or None. The reference kernel decides from
    the flow, so a flow edited away from the image would have it decide, and the run receipt, a policy the
    authority never signed while every hash still matched the image."""
    flow, why = core_render.flow_of(case["image"])
    if case["flow"] == flow:
        return None
    if flow is None:
        return f"case {case['id']}: the stored flow renders no image: the signed image has no rendering ({why})"
    return f"case {case['id']}: the stored flow is not the rendering of the signed image"


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


def produce(cases_path: Path, out: Path, keys: Path, decider: str = "python", time_us: int = None, *,
            install=None, rates=None, escalations=None, operator=None) -> dict:
    """Decide every case of a cases file with the Python reference and write the run to `out`. For a cFS run with
    install statements (RC4), `install` is every (sealed, body) the PEP decided under or applied, in order, operator
    answers included, and `rates` the counted overrides, each {rule, window, count, case, reading} naming its receipt.
    `escalations` is the escalation documents the PEP opened (bytes each), and `operator` the decision members of
    each `operator` case's receipt by case id, the answer's (OP3)."""
    cases_path, out = Path(cases_path), Path(out)
    authority_key, authority_pub, instance_key, instance_pub = ensure_keys(keys)
    root_statement.check_separation(root_statement.InstanceKey.load(str(instance_key)),
                                    [sha256_hex(authority_pub.read_bytes())])
    out.mkdir(parents=True, exist_ok=True)
    cases_bytes = cases_path.read_bytes()
    (out / "cases.jsonl").write_bytes(cases_bytes)
    cases = read_cases(out / "cases.jsonl")
    for case in cases:
        problem = flow_problem(case)
        if problem is not None:
            raise RuntimeError(f"{problem}; write the cases with `write_cases`")
    decisions = python_decisions([case for case in cases if case["basis"] != "operator"])
    for case in cases:
        if case["basis"] == "operator":
            decisions[case["id"]] = [dict(operator[case["id"]]) for _raw in case["readings"]]

    signer = onion_keys.load_signer(str(authority_key))
    authority_id = sha256_hex(authority_pub.read_bytes())
    images = bytearray()
    for case in cases:
        if case["basis"] != "release":            # RC4: attested by the signature block of its install statement
            line = {"format": IMAGE_FORMAT, "case": case["id"], "image_sha256": sha256_hex(case["image"]),
                    "install": case["install"]}
            if case["basis"] == "operator":
                line["answer"] = case["answer"]
            images += canon2.dumps(line) + b"\n"
            continue
        images += canon2.dumps({"format": IMAGE_FORMAT, "case": case["id"], "image_sha256": sha256_hex(case["image"]),
                                "key_id": authority_id, "sig": signer.sign(IMAGE_DOMAIN + case["image"]).hex()}) + b"\n"
    (out / "images.jsonl").write_bytes(bytes(images))

    receipts, leaves, excluded, placed = bytearray(), [], [], {}
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
            placed[(case["id"], index)] = sha256_hex(line)
    (out / "receipts.jsonl").write_bytes(bytes(receipts))
    extra = {}
    if install is not None:
        from prismpath.distribution import envelope as env
        lines = b"".join(canon2.dumps({"body": bytes(body).hex(), "sealed": bytes(sealed).hex()}) + b"\n"
                         for sealed, body in install)
        rate_lines = b"".join(canon2.dumps({"count": one["count"], "receipt_sha256": placed[(one["case"], one["reading"])],
                                            "rule": one["rule"], "window": one["window"]}) + b"\n"
                              for one in rates or [])
        (out / "install.jsonl").write_bytes(lines)
        (out / "rates.jsonl").write_bytes(rate_lines)
        trusts = [env.read(env.unseal(sealed)[0]).seq for sealed, _body in install
                  if env.read(env.unseal(sealed)[0]).artifact == "install.trust"]
        extra = {"install_sha256": sha256_hex(lines), "rates_sha256": sha256_hex(rate_lines),
                 "install_trust_seq": max(trusts) if trusts else None}
        if escalations is not None:
            escalation_lines = b"".join(bytes(doc) + b"\n" for doc in escalations)
            (out / "escalations.jsonl").write_bytes(escalation_lines)
            extra["escalations_sha256"] = sha256_hex(escalation_lines)

    instance = root_statement.InstanceKey.load(str(instance_key))
    manifest = {"format": RUN_FORMAT, "decider": decider, "cases": len(cases), "receipts": len(leaves),
                "excluded": excluded, "cases_sha256": sha256_hex(cases_bytes),
                "images_sha256": sha256_hex(bytes(images)), "authority_key_id": authority_id,
                "instance_key_id": instance.key_id, **extra}
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
    """The run's root statement, `prismpath.core-run-root/2`, signed with the instance key: the RFC 6962 Merkle
    root of the receipts' leaves and their count, the signer's clock as an integer count of microseconds since
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
    try:
        return onion_keys.public_key(raw)
    except ValueError:
        raise Bad(f"the run's {what} key is not a raw 32 byte Ed25519 public key") from None


def verify_root_statement(data: bytes, leaves, manifest_bytes: bytes, instance_raw: bytes) -> dict:
    """The run's root statement, checked in full, or Bad: one canon/2 line in its canonical spelling, exactly
    the members of `prismpath.core-run-root/2` with their types, the run's instance key, a signature under
    that key over the domain prefix and the body, the Merkle root of every receipt and their count, and the
    manifest's hash."""
    onion_keys.require()
    lines = data.split(b"\n")
    if len(lines) != 2 or lines[1] != b"":
        raise Bad("the root statement is not one line")
    try:
        statement = canon2.loads(lines[0])
    except canon2.Canon2Error as error:
        raise Bad(f"the root statement is not a canon/2 document ({error.rule})") from None
    if not isinstance(statement, dict) or canon2.dumps(statement) != lines[0]:
        raise Bad("the root statement is not in its canonical canon/2 spelling")
    if statement.get("format") in OLD_ROOT_FORMATS:
        raise Bad(f"the root statement is {statement['format']}, whose root is of the retired Merkle tree (no domain "
                  f"prefixes, the last node of an odd layer duplicated); this verifier reads only {ROOT_FORMAT} "
                  f"({ledger_ots.MERKLE_SCHEME}), so produce the run again")
    if set(statement) != set(ROOT_MEMBERS) or statement["format"] != ROOT_FORMAT or statement["log"] != LOG_CORE_RUN \
            or statement["trigger"] != LOG_CORE_RUN:
        raise Bad(f"the root statement is not a {ROOT_FORMAT} statement")
    for key in ("leaves", "time_us"):
        if type(statement[key]) is not int or statement[key] < 0:
            raise Bad(f"the root statement's {key} is not a nonnegative integer")
    if not isinstance(statement["root"], str) or not _hex_of(statement["key_id"], 32) \
            or not _hex_of(statement["public_key"], 32) or not _hex_of(statement["sig"], 64):
        raise Bad("the root statement's root, key or signature is malformed")
    if statement["public_key"] != instance_raw.hex() or statement["key_id"] != sha256_hex(instance_raw):
        raise Bad("the root statement is not signed with the run's instance key")
    _public_key(instance_raw, "instance")
    public = bytes(instance_raw)
    try:
        signature, message = bytes.fromhex(statement["sig"]), root_signed_bytes(statement)
    except ValueError:
        raise Bad("the root statement's signature does not verify") from None
    if not onion_keys.verify(public, signature, message):
        raise Bad("the root statement's signature does not verify")
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


def verify(run: Path, *, sample=200, seed=0, pin_authority=None, pin_instance=None, replay=None,
           pin_install=None) -> dict:
    """Every check of a run, or Bad naming the first that fails. Returns a summary.

    `sample` is how many receipts to replay (None for every one), chosen with `seed`; `pin_authority` and
    `pin_instance` name the reader's own copies of the two public keys. Without both the checks all run and the
    pass is refused with `dist:hatch-refused`, except in a dev build, where the root statement is `signed-unpinned`. `replay` decides the chosen receipts again, `replay_through_reference` when None;
    the research tool passes its replay through the Lean oracle. A file that does not read as its format is
    refused like any other failed check. `pin_install` names the reader's copy of the install key set the run's PEP
    started from, the `install` part of its anchor, which a run with a `floor` or `fallback` case needs (RC4)."""
    try:
        summary, receipts = _check(Path(run), pin_authority, pin_instance, pin_install)
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as error:   # a malformed part of the run
        raise Bad(f"the run does not read as a core run ({type(error).__name__}: {error})") from None
    # every decision, or a sample, decided again; an operator's answer was checked against the answer itself (OP3)
    receipts = [one for one in receipts if one[0]["basis"] != "operator"]
    rng = random.Random(seed)
    chosen = receipts if sample is None or sample >= len(receipts) else rng.sample(receipts, sample)
    counts = (replay or replay_through_reference)(chosen)
    if counts["disagree"]:
        raise Bad(f"{counts['disagree']} replayed decisions differ from {counts['against']}: {counts['first']}")
    if pin_authority is None or pin_instance is None:
        # every check above ran; a pass without both keys pinned says nothing about who made the run, so it is an
        # escape hatch that only a dev build lets through (docs/design/spec-policy-distribution.md, D1, D2)
        from prismpath.distribution import devbuild
        try:
            devbuild.hatch("evidence verify without both keys pinned")
        except devbuild.HatchRefused:
            raise Bad("dist:hatch-refused: a run verified without both keys pinned says nothing about who made it; "
                      "pin the authority and the instance public keys") from None
    return {**summary, **counts}


def _check(run: Path, pin_authority, pin_instance, pin_install=None):
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
    for case in cases:
        problem = flow_problem(case)
        if problem is not None:
            raise Bad(problem)
    onion_keys.require()
    _public_key(authority_raw, "authority")
    authority = bytes(authority_raw)
    image_lines = _lines(run / "images.jsonl")
    if len(image_lines) != len(cases):
        raise Bad("images.jsonl does not hold one attestation per case")
    sets = _install_chain(run, manifest, cases, pin_install)
    for case, line in zip(cases, image_lines):
        if case["basis"] != "release":
            _check_install_image(case, canon2.loads(line), line, sets)
            continue
        attestation = canon2.loads(line)
        if canon2.dumps(attestation) != line or attestation.get("format") != IMAGE_FORMAT \
                or attestation.get("case") != case["id"] or attestation.get("key_id") != authority_id \
                or attestation.get("image_sha256") != sha256_hex(case["image"]):
            raise Bad(f"case {case['id']}: the image attestation does not match the image")
        try:
            signature = bytes.fromhex(attestation["sig"])
        except ValueError:
            raise Bad(f"case {case['id']}: the image signature does not verify") from None
        if not onion_keys.verify(authority, signature, IMAGE_DOMAIN + case["image"]):
            raise Bad(f"case {case['id']}: the image signature does not verify")

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
    if sets is not None:
        _check_install_receipts(run, cases, receipts, sets)
    return {"run": str(run), "decider": manifest["decider"], "cases": len(cases), "excluded": len(excluded),
            "receipts": len(receipts), "root": statement["root"],
            "root_statement": "signed" if pinned else "signed-unpinned", "images": len(cases)}, receipts


# ----------------------------------------------------------------- RC4: the install statements of a cFS run
def _install_chain(run: Path, manifest: dict, cases, pin_install):
    """RC4: {envelope id: envelope} of the install sets in `install.jsonl`, each signed at the threshold under the
    install key set in force when it was applied, from the pinned set through each `install.trust` by IS11; None for
    a run with no install statements. Bad for a `floor` or `fallback` case with no install key pinned."""
    for case in cases:
        if case["basis"] not in BASES or not isinstance(case["enacted"], bool) or (
                case["basis"] != "release") != (case["install"] is not None) or (
                not case["enacted"] and case["basis"] not in ("release", "fallback", "operator")) or (
                case["asked"] is not True and (case["asked"] is not False or case["basis"] != "floor")) or (
                case["basis"] == "operator") != (case["answer"] is not None) or (
                case["basis"] == "operator" and len(case["readings"]) != 1):
            raise Bad(f"case {case['id']}: a basis of release, floor, fallback or operator, only a release, fallback "
                      f"or operator line not enacted, `asked` only on a floor case and one answered reading per operator case")
    installed = any(case["basis"] != "release" for case in cases) or "install_sha256" in manifest
    if not installed:
        return None
    if pin_install is None:
        raise Bad("a run with a floor or fallback case needs the install key set pinned beside the authority key (RC4)")
    for name in INSTALL_FILES:
        if not (run / name).exists():
            raise Bad(f"the run has no {name}")
    if sha256_hex((run / "install.jsonl").read_bytes()) != manifest.get("install_sha256") or \
            sha256_hex((run / "rates.jsonl").read_bytes()) != manifest.get("rates_sha256"):
        raise Bad("install.jsonl or rates.jsonl is not the file run.json names")
    import json
    from prismpath.distribution import envelope as env
    from prismpath.distribution import install
    from prismpath.distribution.kinds import Refused
    try:
        record = install.read_anchor_part(json.loads(Path(pin_install).read_bytes().decode("utf-8")))
    except (Refused, ValueError, UnicodeDecodeError) as error:
        raise Bad(f"the pinned install key set does not read ({error})") from None
    sets, answers, start = {}, {}, record.trust_seq
    for number, line in enumerate(_lines(run / "install.jsonl")):
        row = canon2.loads(line)
        sealed, body = bytes.fromhex(row["sealed"]), bytes.fromhex(row["body"])
        try:
            envelope_bytes, entries = env.unseal(sealed)
            envelope = env.read(envelope_bytes, reads_meta=True)
        except Refused as refused:
            raise Bad(f"install statement {number} does not read ({refused.cause})") from None
        if envelope.body_sha256 != sha256_hex(body) or envelope.body_size != len(body):
            raise Bad(f"install statement {number}: its body is not the one it signs")
        message = env.signed_message(envelope_bytes)
        if envelope.artifact == kinds_answer():
            answered = record.answering(entries, message)
            if not answered.ok:
                raise Bad(f"install statement {number}: an operator answer not signed by an operator key in force when "
                          f"it was applied ({answered.cause})")
            answers[envelope.envelope_id] = (envelope, body)
            continue
        counted = record.counting(entries, message)
        if not counted.ok:
            raise Bad(f"install statement {number} is not signed at the threshold under the install keys in force "
                      f"when it was applied ({counted.cause})")
        if envelope.artifact == install.TRUST:
            if envelope.seq != record.trust_seq + 1:
                raise Bad(f"install statement {number}: an install.trust at {envelope.seq} where "
                          f"{record.trust_seq + 1} is next, so one is left out (IS11)")
            cause = install.check_trust(record, body, entries, message, widens=envelope.widens, instance_key_id=None,
                                        trust=None)
            if cause is not None:
                raise Bad(f"install statement {number}: an install.trust IS11 refuses ({cause})")
            record = record.apply_trust(envelope, body)
        elif envelope.artifact in install.SET_KINDS:
            sets[envelope.envelope_id] = envelope
        else:
            raise Bad(f"install statement {number} is not an install kind")
    if record.trust_seq != (start if manifest.get("install_trust_seq") is None else manifest["install_trust_seq"]):
        raise Bad(f"run.json names install trust sequence {manifest.get('install_trust_seq')} and install.jsonl ends "
                  f"at {record.trust_seq}, so an install.trust is left out")
    sets[ANSWERS] = answers
    return sets


ANSWERS = "answers"   # the key of `_install_chain`'s answers, {envelope id: (envelope, body)}, beside the sets


def kinds_answer() -> str:
    from prismpath.distribution import kinds
    return kinds.ANSWER


def _check_install_image(case, attestation, line: bytes, sets) -> None:
    """RC4: a `floor` or `fallback` case is attested by the install statement it names, of its basis's kind, whose
    signed policy hash is the case's image."""
    if sets is None:
        raise Bad(f"case {case['id']}: a {case['basis']} case in a run with no install statements")
    members = {"format", "case", "image_sha256", "install"} | ({"answer"} if case["basis"] == "operator" else set())
    if canon2.dumps(attestation) != line or set(attestation) != members \
            or attestation["format"] != IMAGE_FORMAT or attestation["case"] != case["id"] \
            or attestation["image_sha256"] != sha256_hex(case["image"]) or attestation["install"] != case["install"] \
            or attestation.get("answer") != case["answer"]:
        raise Bad(f"case {case['id']}: the image attestation does not name the case's install statement")
    kind = INSTALL_OF["floor" if case["basis"] == "operator" else case["basis"]]
    envelope = sets.get(case["install"])
    if envelope is None or envelope.artifact != kind:
        raise Bad(f"case {case['id']}: no {kind} statement of the run attests its image")
    if envelope.policy_sha256 != sha256_hex(case["image"]):
        raise Bad(f"case {case['id']}: its image is not the policy its install statement signs")


def _check_install_receipts(run: Path, cases, receipts, sets) -> None:
    """RC4, AF7, AF8: every reading the floor decided has a not enacted line of the release, and each counted override
    names a floor receipt, rises by one within a window of its rule and never passes the signed `allows`."""
    wanted = {}
    for case in cases:
        if case["basis"] == "floor" and case["asked"]:
            for raw in case["readings"]:
                wanted[sha256_hex(raw)] = wanted.get(sha256_hex(raw), 0) + 1
    for case in cases:
        if not case["enacted"]:
            for raw in case["readings"]:
                if wanted.get(sha256_hex(raw)):
                    wanted[sha256_hex(raw)] -= 1
    if any(wanted.values()):
        raise Bad("a reading the floor decided has no not enacted line of the release that records `would` (AF7)")
    by_leaf = {sha256_hex(canon2.dumps(receipt)): (case, receipt) for case, _index, receipt in receipts}
    last = {}
    for number, line in enumerate(_lines(run / "rates.jsonl")):
        row = canon2.loads(line)
        if canon2.dumps(row) != line or set(row) != {"count", "receipt_sha256", "rule", "window"} or not all(
                type(row[key]) is int and row[key] >= 0 for key in ("count", "rule", "window")):
            raise Bad(f"rates line {number} is not a counted override")
        found = by_leaf.get(row["receipt_sha256"])
        if found is None or found[0]["basis"] != "floor":
            raise Bad(f"rates line {number} names no floor receipt of the run")
        rate = sets[found[0]["install"]].meta.get("rate")
        if not isinstance(rate, dict):
            raise Bad(f"rates line {number}: a counted override under a floor that signs no rate")
        key = (found[0]["install"], row["rule"])
        window, count = last.get(key, (None, 0))
        if window == row["window"]:
            expected = count + 1
        elif window is None or row["window"] > window:
            expected = 1
        else:
            raise Bad(f"rates line {number}: a window that goes back")
        if row["count"] != expected:
            raise Bad(f"rates line {number}: the count is {row['count']} where {expected} is next (AF8)")
        if row["count"] > rate["allows"]:
            raise Bad(f"rates line {number}: {row['count']} overrides in a window that allows {rate['allows']} (AF8)")
        last[key] = (row["window"], row["count"])
    _check_operator_receipts(run, cases, receipts, sets)


def _check_operator_receipts(run: Path, cases, receipts, sets) -> None:
    """OP2, OP3: each `operator` case's one reading was escalated under the floor its case names, by an escalation
    document of the run, and answered once by the answer its case names, whose policy is that floor's; its receipt is
    the answer's decision, a route to `allow` or the escalation's own refusal. An escalation closes at its one answer,
    and the answer was in force at some time inside the escalation's 600 second life. A case not enacted records an
    answer the PEP applied but whose command it could not send."""
    if not any(case["basis"] == "operator" for case in cases):
        return
    from prismpath.distribution import kinds
    if not (run / "escalations.jsonl").exists() or \
            sha256_hex((run / "escalations.jsonl").read_bytes()) != _manifest(run).get("escalations_sha256"):
        raise Bad("escalations.jsonl is not the file run.json names")
    escalations = {}
    for line in _lines(run / "escalations.jsonl"):
        doc = canon2.loads(line)
        if canon2.dumps(doc) != line or not isinstance(doc, dict) or doc.get("format") != ESCALATION_FORMAT:
            raise Bad("an escalations.jsonl line is not an escalation document")
        escalations[sha256_hex(line)] = doc
    used, closed = set(), set()
    # OP2: an answer is bound to the PEP it answers, by the PEP id of H1 (the first 16 bytes of the SHA-256 of the
    # instance public key). A cFS run's receipts are signed by that same instance key, so the run names its PEP.
    pep = hashlib.sha256((run / "instance.pub").read_bytes()).digest()[:16].hex()
    for case, index, receipt in receipts:
        if case["basis"] != "operator":
            continue
        found = sets[ANSWERS].get(case["answer"])
        if found is None or case["answer"] in used:
            raise Bad(f"case {case['id']}: no operator answer of the run, or one that answers twice (OP3)")
        used.add(case["answer"])
        envelope, body = found
        answer = kinds.read_answer(body)
        if answer["pep"] != pep:
            raise Bad(f"case {case['id']}: the operator answer is bound to another PEP (OP2)")
        if answer["receipt"] in closed:
            raise Bad(f"case {case['id']}: a second answer to an escalation its first answer closed (OP3)")
        closed.add(answer["receipt"])
        doc = escalations.get(answer["receipt"])
        floor = sets[case["install"]]
        if doc is None or doc["policy_sha256"] != floor.policy_sha256 or envelope.policy_sha256 != floor.policy_sha256 \
                or doc["reading_sha256"] != sha256_hex(case["readings"][index]):
            raise Bad(f"case {case['id']}: the answer names no escalation of this floor for this reading (OP3)")
        opened = doc.get("time")
        if not isinstance(opened, int) or isinstance(opened, bool) or \
                max(envelope.not_before, opened) > min(envelope.expires, opened + ANSWER_LIFE):
            raise Bad(f"case {case['id']}: the answer was never in force while its escalation was open (OP2, OP3)")
        want = {"decision": "route", "target": "allow"} if answer["answer"] == "allow" else {
            "decision": "refuse", "cause": causes.name(doc["cause_code"]), "cause_code": doc["cause_code"]}
        if {key: receipt.get(key) for key in ("decision", "target", "cause", "cause_code")} != {
                key: want.get(key) for key in ("decision", "target", "cause", "cause_code")}:
            raise Bad(f"case {case['id']}: the receipt is not the operator's answer (OP3)")


def _manifest(run: Path) -> dict:
    return canon2.loads((run / "run.json").read_bytes().rstrip(b"\n"))


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
