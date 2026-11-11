# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A differential run as evidence (docs/design/spec-verified-core.md, section 11).

A run is one implementation's decisions on a set of cases, written so that a reader who trusts neither
the implementation nor the person who ran it can check what was decided:

  * every policy image's canon/2 bytes are signed with the authority key (`images.jsonl`, an image
    attestation per case, Ed25519 over `IMAGE_DOMAIN` and the image bytes);
  * every decision has a receipt (`receipts.jsonl`, one canon/2 line each) binding the image's hash, the
    reading's hash and the decision with its registered cause; a receipt is not signed by itself;
  * the receipts are the leaves of a Merkle tree, and one root statement signed with the instance key
    (`receipts.roots.jsonl`, `prismpath.core-run-root/1`, log `core-run`) states their root and count,
    and binds the run's manifest (`run.json`) through its `policy` member. It is a canon/2 document with
    its time an integer count of microseconds (`time_us`), signed over its own domain prefix, so the
    run's evidence is canon/2 end to end, as the root statements of audit logs and epoch chains
    (`prismpath.ledgers.root_statement`, `prismpath-root-statement/2`) are.

The verifier re-checks the root statement, every receipt and every image attestation, and replays a
sample of the decisions through the Lean oracle; a case outside the core (section 1) is excluded with
its reason, which the verifier recomputes from the image, so every receipted decision must be the
oracle's. The Rust twin is
`prismpath-hotswap-rs/examples/core_evidence.rs`; each verifies a run the other produced.

    python formal/diff/core_evidence.py cases --cases 2000 --seed 7 --out cases.jsonl
    python formal/diff/core_evidence.py produce --from cases.jsonl --out RUN --keys KEYS
    python formal/diff/core_evidence.py verify RUN --sample 500

Keys are test keys: `produce` generates an authority key and an instance key in `--keys` when none are
there (the repository's own `swap keygen` and `ledger keygen` code), and the run holds only their public
halves. The verifier pins the public keys it is given, or reads them from the run and says the run is
signed but unpinned.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import core_diff  # noqa: E402
import core_policy  # noqa: E402

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


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _lines(path: Path):
    text = path.read_bytes()
    lines = text.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    return lines


# ----------------------------------------------------------------- the cases
def write_cases(cases, out: Path) -> None:
    """The run's inputs, one canon/2 line per case: the image and the readings as hex of their bytes, and
    the flow the image renders to (the text the reference and the ports read), or null."""
    from prismpath.kernel import canon2
    core_diff.prepare(cases)
    with open(out, "wb") as handle:
        for case in cases:
            handle.write(canon2.dumps({"case": case["id"], "image": case["image"].hex(), "flow": case["flow"],
                                       "readings": [raw.hex() for raw in case["readings"]]}) + b"\n")


def read_cases(path: Path):
    from prismpath.kernel import canon2
    cases = []
    for line in _lines(path):
        row = canon2.loads(line)
        cases.append({"id": row["case"], "image": bytes.fromhex(row["image"]), "flow": row["flow"],
                      "flow_why": None if row["flow"] is not None else _why(bytes.fromhex(row["image"])),
                      "readings": [bytes.fromhex(raw) for raw in row["readings"]]})
    return cases


def _why(image: bytes) -> str:
    from prismpath.kernel import canon2
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
    from prismpath.kernel import canon2
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


def oracle_policies(cases, oracle=None) -> list:
    """The oracle's check of every case's image, as (cause, code, field, reason) or None when accepted."""
    binary = Path(oracle) if oracle else core_diff.ORACLE
    data = bytearray()
    for number, case in enumerate(cases):
        data += f"case s{number} 0\n{len(case['image'])}\n".encode() + case["image"] + b"\n"
    lines = subprocess.run([str(binary), "--batch"], input=bytes(data), capture_output=True, check=True).stdout
    rows = {row["id"]: row["policy"] for row in map(json.loads, lines.decode().splitlines())}
    out = []
    for number in range(len(cases)):
        row = rows[f"s{number}"]
        out.append(None if row["policy"] == "accepted" else (row["cause"], row["code"], row.get("field"), row.get("reason")))
    return out


def scope_check(cases, oracle=None, rust_lines=None) -> dict:
    """The ported checks of a policy image against the oracle's on every image: the Python port
    (`core_policy.load_policy`) and, given the Rust port's lines (`core_evidence policy`, one canon/2 line
    per case), the Rust port; whether each image is accepted, and the cause, code, field and reason of every
    refusal. The exclusion of `engine-counter` cases is sound only while they agree."""
    from prismpath.kernel import canon2
    want = oracle_policies(cases, oracle)
    ports = {"python": [core_policy.load_policy(case["image"]) for case in cases]}
    if rust_lines is not None:
        rows = [canon2.loads(line) for line in rust_lines]
        if len(rows) != len(cases) or any(row.get("case") != case["id"] for row, case in zip(rows, cases)):
            raise Bad("the Rust port's lines are not one per case in order")
        ports["rust"] = [None if row["policy"] == "accepted" else (row["cause"], row["code"], row.get("field"),
                                                                    row.get("reason")) for row in rows]
    counts = {"images": len(cases), "accepted": sum(item is None for item in want),
              "counter": sum(item is not None and item[0] == "policy:engine-counter" for item in want),
              "first": None}
    for name, got in ports.items():
        agree = [a == b for a, b in zip(got, want)]
        counts[name] = {"agree": sum(agree), "disagree": len(agree) - sum(agree)}
        if not all(agree):
            at = agree.index(False)
            counts["first"] = counts["first"] or {"port": name, "case": cases[at]["id"], "got": got[at], "oracle": want[at]}
    return counts


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


def python_decisions(cases):
    """{case id: [decision per reading]} from the Python reference (the harness's python leg), or None for
    a case it has no decision on (an image with no flow rendering)."""
    rows = core_diff.python_leg(cases)
    out = {}
    for case in cases:
        row = rows[case["id"]]
        if row["policy"] == "accepted":
            if any(verdict.get("cause") == "crash" for verdict in row["readings"]):
                raise RuntimeError(f"case {case['id']}: the reference crashed: {row['readings']}")
            out[case["id"]] = [_decision(verdict) for verdict in row["readings"]]
        elif row["policy"] == "refused":
            if row.get("code") is None:
                raise RuntimeError(f"case {case['id']}: an uncoded refusal {row}")
            refusal = {"verdict": "refuse", "cause": row["cause"], "code": row["code"],
                       "field": row.get("field"), "reason": row.get("policy_reason") or
                       (row.get("reason") if row["cause"] == "policy:unreadable" else None)}
            out[case["id"]] = [_decision(refusal) for _raw in case["readings"]]
        else:
            out[case["id"]] = None
    return out


# ----------------------------------------------------------------- producing a run
def ensure_keys(keys: Path):
    """The authority key (which says which policy may run) and the instance key (which attests what the run
    recorded), generated here when absent: test keys, never a deployment's."""
    from prismpath.hotswap import policy_pack
    from prismpath.ledgers import root_statement
    keys.mkdir(parents=True, exist_ok=True)
    if not (keys / "authority.key").exists():
        policy_pack.keygen(str(keys), "authority")
    if not (keys / "instance.key").exists():
        root_statement.keygen(str(keys), "instance")
    return keys / "authority.key", keys / "authority.pub", keys / "instance.key", keys / "instance.pub"


def produce(cases_path: Path, out: Path, keys: Path, decider: str = "python", time_us: int = None) -> dict:
    """Decide every case with the Python reference and write the run to `out`."""
    from prismpath.hotswap import policy_pack
    from prismpath.kernel import canon2
    from prismpath.ledgers import root_statement
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
    from prismpath.kernel import canon2
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


def verify_root_statement(data: bytes, leaves, manifest_bytes: bytes, instance_raw: bytes) -> dict:
    """The run's root statement, checked in full, or Bad: one canon/2 line in its canonical spelling, exactly
    the members of `prismpath.core-run-root/1` with their types, the run's instance key, a signature under
    that key over the domain prefix and the body, the Merkle root of every receipt and their count, and the
    manifest's hash."""
    from prismpath.kernel import canon2
    from prismpath.ledgers import root_statement
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
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
        Ed25519PublicKey.from_public_bytes(instance_raw).verify(bytes.fromhex(statement["sig"]),
                                                                root_signed_bytes(statement))
    except (InvalidSignature, ValueError):
        raise Bad("the root statement's signature does not verify") from None
    if statement["leaves"] != len(leaves) or statement["root"] != root_statement.merkle_root(leaves):
        raise Bad("the root statement does not verify: its root is not the receipts' Merkle root")
    if statement["policy"] != {"core_run_sha256": sha256_hex(manifest_bytes)}:
        raise Bad("the root statement does not bind this run.json")
    return statement


# ----------------------------------------------------------------- verifying a run
class Bad(Exception):
    pass


def _norm(verdict) -> tuple:
    """A decision as a comparable tuple; an empty field (the oracle spells a threshold on no field `""`) is
    no field."""
    if verdict.get("decision", verdict.get("verdict")) == "route":
        return ("route", verdict["target"])
    return ("refuse", verdict["cause"], verdict.get("cause_code", verdict.get("code")), verdict.get("field") or None,
            verdict.get("reason") or None)


def verify(run: Path, *, sample=200, seed=0, pin_authority=None, pin_instance=None, oracle=None) -> dict:
    """Every check of a run, or Bad naming the first that fails. Returns a summary."""
    from prismpath.kernel import canon2, causes
    for name in FILES:
        if not (run / name).exists():
            raise Bad(f"the run has no {name}")
    manifest_bytes = (run / "run.json").read_bytes().rstrip(b"\n")
    manifest = canon2.loads(manifest_bytes)
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
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    authority = Ed25519PublicKey.from_public_bytes(authority_raw)
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

    # a sample of the decisions, replayed through the oracle
    rng = random.Random(seed)
    chosen = receipts if sample is None or sample >= len(receipts) else rng.sample(receipts, sample)
    replay = replay_through_oracle(chosen, oracle)
    if replay["disagree"]:
        raise Bad(f"{replay['disagree']} replayed decisions differ from the oracle: {replay['first']}")
    return {"run": str(run), "decider": manifest["decider"], "cases": len(cases), "excluded": len(excluded),
            "receipts": len(receipts), "root": statement["root"],
            "root_statement": "signed" if pinned else "signed-unpinned", "images": len(cases), **replay}


def replay_through_oracle(chosen, oracle=None) -> dict:
    """Each chosen receipt's image and reading through the oracle, one case each, and the decisions
    compared: every receipted case is inside the core, so every decision must be the oracle's."""
    binary = Path(oracle) if oracle else core_diff.ORACLE
    data = bytearray()
    for number, (case, index, _receipt) in enumerate(chosen):
        reading = case["readings"][index]
        data += f"case r{number} 1\n".encode() + f"{len(case['image'])}\n".encode() + case["image"] + b"\n"
        data += f"{len(reading)}\n".encode() + reading + b"\n"
    lines = subprocess.run([str(binary), "--batch"], input=bytes(data), capture_output=True, check=True).stdout
    rows = {row["id"]: row for row in map(json.loads, lines.decode().splitlines())}
    counts = {"replayed": len(chosen), "agree": 0, "disagree": 0, "first": None}
    for number, (case, _index, receipt) in enumerate(chosen):
        oracle_verdict = rows[f"r{number}"]["readings"][0]
        if _norm(oracle_verdict) == _norm(receipt):
            counts["agree"] += 1
        else:
            counts["disagree"] += 1
            counts["first"] = counts["first"] or {"case": case["id"], "receipt": receipt, "oracle": oracle_verdict}
    return counts


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("cases", help="generate the harness's cases and write them as a run's inputs")
    gen.add_argument("--cases", type=int, default=2000)
    gen.add_argument("--seed", type=int, default=7)
    gen.add_argument("--out", required=True)
    make = sub.add_parser("produce", help="decide the cases with the Python reference and write a run")
    make.add_argument("--from", dest="source", required=True)
    make.add_argument("--out", required=True)
    make.add_argument("--keys", required=True, help="the test keys' directory (generated when empty)")
    scope = sub.add_parser("scope-check", help="hold the ported policy check to the oracle's on every image")
    scope.add_argument("--from", dest="source", required=True)
    scope.add_argument("--rust", help="the Rust port's lines (`core_evidence policy --from CASES`), held to the oracle too")
    scope.add_argument("--oracle")
    check = sub.add_parser("verify", help="re-check a run and replay a sample through the oracle")
    check.add_argument("run")
    check.add_argument("--sample", default="200", help="how many decisions to replay, or 'all'")
    check.add_argument("--seed", type=int, default=0)
    check.add_argument("--pin-authority")
    check.add_argument("--pin-instance")
    check.add_argument("--oracle")
    args = parser.parse_args(argv)
    if args.command == "cases":
        write_cases(core_diff.generate(args.cases, args.seed), Path(args.out))
        print(f"core_evidence: wrote {args.cases} cases to {args.out}")
        return 0
    if args.command == "scope-check":
        cases = read_cases(Path(args.source))
        counts = scope_check(cases, args.oracle, _lines(Path(args.rust)) if args.rust else None)
        ports = ", ".join(f"{name} port {counts[name]['agree']} agree, {counts[name]['disagree']} disagree"
                          for name in ("python", "rust") if name in counts)
        failed = counts["first"] is not None
        print(f"core_evidence: scope check {args.source}: {counts['images']} images ({counts['accepted']} accepted, "
              f"{counts['counter']} refused for an engine counter): {ports}" + (f"; first {counts['first']}" if failed else ""))
        return 1 if failed else 0
    if args.command == "produce":
        manifest = produce(Path(args.source), Path(args.out), Path(args.keys))
        print(f"core_evidence: produced {args.out}: decider {manifest['decider']}, {manifest['cases']} cases, "
              f"{manifest['receipts']} receipts, {len(manifest['excluded'])} excluded")
        return 0
    try:
        summary = verify(Path(args.run), sample=None if args.sample == "all" else int(args.sample), seed=args.seed,
                         pin_authority=args.pin_authority, pin_instance=args.pin_instance, oracle=args.oracle)
    except Bad as bad:
        print(f"core_evidence: REFUSED {args.run}: {bad}")
        return 1
    print(f"core_evidence: verified {args.run}: decider {summary['decider']}, {summary['receipts']} receipts, "
          f"{summary['images']} image attestations, root statement {summary['root_statement']}, "
          f"{summary['replayed']} replayed: {summary['agree']} agree, "
          f"{summary['disagree']} disagree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
