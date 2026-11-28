# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""An outside witness: a second party that cosigns signed roots it has checked.

A root statement is signed by the deployment's instance key. Whoever holds that key can delete the tail of a
log together with the tail of its statements, or start a second chain that tells another story, and both still
verify on their own (`root_statement` says so in its own words). Anchoring a statement hash shows a third party
saw that hash at a time. A witness does a little more. It is a separate party with its own Ed25519 key. It keeps
the last root it cosigned for each signer and log, and it cosigns a new statement only when the new root extends
that one: a higher `seq`, no fewer leaves, and an RFC 6962 consistency proof that the old tree is a prefix of the
new one. A deployment that later shortens or forks its log cannot get the witness to cosign the new story, and a
cosignature held by anyone shows what the log held when the witness saw it.

The witness is optional and additive. It reads statements as they are and writes nothing into them. Its
cosignatures live in a file of their own beside the statements file (`witness_path_for`), so receipts, root
statements and every frozen corpus keep their bytes. A reader with no witness file, or who pins no witness key,
gets what it got before.

A cosignature, one canon/2 line:

    {"format": "prismpath-root-witness/1", "encoding": "canon/2",
     "statement_format": "prismpath-root-statement/3", "statement_sha256": "<hex>",
     "log": "audit-log", "seq": 3, "leaves": 42, "root": "<hex>",
     "signer_key_id": "<sha256 of the instance key>",
     "witness_key_id": "<sha256 of the witness key>", "witness_public_key": "<hex>",
     "time_us": 1762257600123000, "sig": "<Ed25519, hex>"}

The signature covers `SIGNING_DOMAIN` and the canon/2 bytes of every member but `sig`. `statement_sha256` is the
statement's own hash, signature included: `root_statement.statement_hash` for a `prismpath-root-statement/3`
statement, and the SHA-256 of the canon/2 line for a core run's `prismpath.core-run-root/2` statement, which has no
`seq` (it is written as null). The witness's clock in `time_us` is the witness's own claim.

What a cosignature proves and what it does not. It proves that the holder of the witness key saw a statement with
this hash, signed by that instance key, and that the statement extended every earlier one it cosigned for that
signer and log. It does not prove the receipts are complete. A deployment can leave a decision out before it signs
a root, and no signature, anchor or witness can show what was never recorded.
"""
from __future__ import annotations

import os
from typing import Dict, Iterable, List, Optional, Tuple

from prismpath import canon
from prismpath.ledgers import root_statement as rs
from prismpath.onion import keys

FORMAT = "prismpath-root-witness/1"
SIGNING_DOMAIN = b"prismpath-root-witness/1\x00"
STATE_FORMAT = "prismpath-witness-state/1"
CORE_RUN_ROOT_FORMAT = "prismpath.core-run-root/2"       # core_evidence.ROOT_FORMAT, named here to avoid a cycle
CORE_RUN_ROOT_DOMAIN = b"prismpath.core-run-root/2\x00"
_BODY = ("format", "encoding", "statement_format", "statement_sha256", "log", "seq", "leaves", "root",
         "signer_key_id", "witness_key_id", "witness_public_key", "time_us")

# Statuses a reader reports. A missing witness is never a failure unless the reader asks for one.
WITNESSED = "witnessed"          # the last statement carries a cosignature under a pinned witness key
UNWITNESSED = "unwitnessed"      # no cosignature under a pinned witness key
INVALID = "invalid"              # a cosignature is malformed, does not verify, or names another statement


class Refused(ValueError):
    """The witness will not cosign this statement. `reason` is one short word for the log."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


def witness_path_for(statements_path: str) -> str:
    """Where a statements file's cosignatures live: `x.roots.jsonl` -> `x.roots.witness.jsonl`."""
    if statements_path.endswith(".jsonl"):
        return statements_path[:-len(".jsonl")] + ".witness.jsonl"
    return statements_path + ".witness.jsonl"


def signed_bytes(cosignature: dict) -> bytes:
    return SIGNING_DOMAIN + canon.canon2_bytes({key: cosignature[key] for key in _BODY})


def _hex(value, size: int) -> bool:
    return isinstance(value, str) and len(value) == 2 * size and not value.strip("0123456789abcdef")


def _verify(public_hex: str, sig_hex: str, message: bytes) -> bool:
    keys.require()
    try:
        public_raw, signature = bytes.fromhex(public_hex), bytes.fromhex(sig_hex)
    except ValueError:
        return False
    return keys.verify(public_raw, signature, message)


def _core_run_signed_bytes(statement: dict) -> bytes:
    from prismpath.kernel import canon2
    return CORE_RUN_ROOT_DOMAIN + canon2.dumps({key: value for key, value in statement.items() if key != "sig"})


def subject_of(statement: dict) -> Tuple[str, str, Optional[int]]:
    """(format, statement hash, seq) of a statement the witness can read, or Refused."""
    fmt = statement.get("format") if isinstance(statement, dict) else None
    if fmt == rs.STATEMENT_FORMAT:
        if not rs._well_formed(statement, statement.get("log")):
            raise Refused("bad_format", "the statement is not a well formed prismpath-root-statement/3")
        return fmt, rs.statement_hash(statement), statement["seq"]
    if fmt == CORE_RUN_ROOT_FORMAT:
        from prismpath.kernel import canon2
        members = {"format", "log", "root", "leaves", "time_us", "trigger", "key_id", "public_key", "policy", "sig"}
        if set(statement) != members or type(statement["leaves"]) is not int or not isinstance(statement["root"], str) \
                or not _hex(statement["public_key"], 32) or not _hex(statement["sig"], 64):
            raise Refused("bad_format", "the statement is not a well formed prismpath.core-run-root/2")
        return fmt, canon.sha256_hex(canon2.dumps(statement)), None
    raise Refused("bad_format", f"the witness reads {rs.STATEMENT_FORMAT} and {CORE_RUN_ROOT_FORMAT} statements")


def _statement_signature_ok(statement: dict) -> bool:
    if rs.key_id_of(bytes.fromhex(statement["public_key"])) != statement["key_id"]:
        return False
    if statement["format"] == rs.STATEMENT_FORMAT:
        return rs._verify_signature(statement)
    return _verify(statement["public_key"], statement["sig"], _core_run_signed_bytes(statement))


class Witness:
    """A witness: its own key, the signer keys it accepts, and the last root it cosigned for each signer and log.

    `state_path` is a canon/2 file the witness writes atomically after every cosignature, so a witness that
    restarts resumes where it stopped and still refuses a shorter or forked log."""

    def __init__(self, key: keys.Signer, signers: Iterable[bytes], state_path: str):
        self.key = key
        self.signers = {rs.key_id_of(raw) for raw in signers}
        if not self.signers:
            raise ValueError("a witness pins at least one signer key: it vouches only for keys it was told to")
        if key.key_id in self.signers:
            raise ValueError("the witness key is also a signer key; a witness must be a second party")
        self.state_path = state_path
        self.state: Dict[str, dict] = self._load()

    def _load(self) -> Dict[str, dict]:
        if not os.path.exists(self.state_path):
            return {}
        with open(self.state_path, "rb") as handle:
            doc = canon.loads_document(handle.read().decode("utf-8"))
        if not isinstance(doc, dict) or doc.get("format") != STATE_FORMAT or not isinstance(doc.get("heads"), dict):
            raise ValueError(f"{self.state_path} is not a {STATE_FORMAT} file")
        return dict(doc["heads"])

    def _save(self) -> None:
        doc = {"format": STATE_FORMAT, canon.ENCODING_KEY: canon.CANON2, "heads": self.state}
        canon.atomic_write(self.state_path, canon.canon2_bytes(doc).decode("utf-8") + "\n")

    @staticmethod
    def _head_key(statement: dict) -> str:
        return f"{statement['key_id']}/{statement['format']}/{statement['log']}"

    def cosign(self, statement: dict, proof: Optional[List[str]] = None, time_us: Optional[int] = None) -> dict:
        """Check `statement` and cosign it, or raise Refused. `proof` is the RFC 6962 consistency proof from the
        last root this witness cosigned for the same signer and log to the new one (`root_statement.consistency_proof`);
        it is needed only when the log grew."""
        fmt, digest, seq = subject_of(statement)
        if statement["key_id"] not in self.signers:
            raise Refused("unpinned_signer", "the statement is signed by a key this witness does not accept")
        if not _statement_signature_ok(statement):
            raise Refused("bad_signature", "the statement's signature does not verify under the key it names")
        head_key = self._head_key(statement)
        head = self.state.get(head_key)
        if fmt == CORE_RUN_ROOT_FORMAT:
            # A core run has one root statement and no chain: cosigned once, and the same hash again is the same answer.
            seen = (head or {}).get("seen", [])
            if digest not in seen:
                self.state[head_key] = {"seen": sorted(seen + [digest])}
        else:
            if head is not None:
                if seq == head["seq"] and digest != head["statement_sha256"]:
                    raise Refused("fork", f"a second statement at seq {seq}: the log was forked")
                if seq <= head["seq"] and digest != head["statement_sha256"]:
                    raise Refused("stale", f"seq {seq} is not after seq {head['seq']}, the last cosigned")
                if seq == head["seq"] + 1 and statement["prev"] != head["statement_sha256"]:
                    raise Refused("chain_broken", "the statement does not name the last cosigned statement as prev")
                if statement["leaves"] < head["leaves"]:
                    raise Refused("truncated", f"{statement['leaves']} leaves after {head['leaves']} were cosigned")
                if statement["leaves"] == head["leaves"] and statement["root"] != head["root"]:
                    raise Refused("fork", "the same number of leaves under another root")
                if statement["leaves"] > head["leaves"] and head["leaves"] > 0 and not rs.verify_consistency(
                        head["leaves"], statement["leaves"], head["root"], statement["root"], proof or []):
                    raise Refused("inconsistent", "the new root does not extend the last cosigned root")
            self.state[head_key] = {"seq": seq, "leaves": statement["leaves"], "root": statement["root"],
                                    "statement_sha256": digest}
        cosignature = {"format": FORMAT, canon.ENCODING_KEY: canon.CANON2, "statement_format": fmt,
                       "statement_sha256": digest, "log": statement["log"], "seq": seq,
                       "leaves": statement["leaves"], "root": statement["root"], "signer_key_id": statement["key_id"],
                       "witness_key_id": self.key.key_id, "witness_public_key": self.key.public_raw.hex(),
                       "time_us": int(time_us) if time_us is not None else rs._now_us()}
        cosignature["sig"] = self.key.sign(signed_bytes(cosignature)).hex()
        self._save()
        return cosignature


def append(path: str, cosignature: dict) -> None:
    """Append one cosignature line to a witness file, flushed to disk."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(canon.canon2_bytes(cosignature).decode("utf-8") + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def read(path: str) -> Tuple[List[dict], List[dict]]:
    """Every cosignature in a witness file and the findings reading it produced."""
    if not path or not os.path.exists(path):
        return [], []
    out, findings = [], []
    with open(path, encoding="utf-8", newline="") as handle:
        lines = handle.read().split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for index, line in enumerate(lines):
        try:
            doc = canon.loads_document(line)
            if not isinstance(doc, dict):
                raise ValueError("not an object")
        except ValueError:
            findings.append({"finding": "bad_cosignature", "line": index + 1})
            continue
        out.append(doc)
    return out, findings


def cosignature_problem(cosignature: dict) -> Optional[str]:
    """Why a cosignature is not well formed or does not verify under the key it carries, or None."""
    if not isinstance(cosignature, dict) or set(cosignature) != set(_BODY) | {"sig"} or cosignature["format"] != FORMAT \
            or cosignature["encoding"] != canon.CANON2:
        return "bad_cosignature"
    if not _hex(cosignature["witness_public_key"], 32) or not _hex(cosignature["sig"], 64) \
            or not _hex(cosignature["statement_sha256"], 32):
        return "bad_cosignature"
    if rs.key_id_of(bytes.fromhex(cosignature["witness_public_key"])) != cosignature["witness_key_id"]:
        return "witness_key_id_mismatch"
    try:
        message = signed_bytes(cosignature)
    except canon.CanonicalError:
        return "bad_cosignature"
    if not _verify(cosignature["witness_public_key"], cosignature["sig"], message):
        return "bad_witness_signature"
    return None


def verify(statements: List[dict], cosignatures: List[dict], pinned_witnesses: Iterable[bytes],
           read_findings: Iterable[dict] = ()) -> dict:
    """Check the cosignatures of a chain (or of one core run statement) under pinned witness keys.

    A cosignature counts when it verifies under a pinned witness key and names a statement of `statements` by its
    hash with the same log, seq, leaves, root and signer. One that names no statement here is a finding: the log
    the witness saw held a statement this one does not, so it was cut or replaced. The status is `witnessed`
    when the last statement carries a counted cosignature, else `unwitnessed`, and `invalid` on any finding.
    Every statement before a witnessed one is covered too, because the witness checked that each root it
    cosigned extends the one before."""
    pinned = {rs.key_id_of(raw) for raw in pinned_witnesses}
    findings = list(read_findings)
    by_hash: Dict[str, Tuple[int, dict, str]] = {}
    for index, statement in enumerate(statements):
        try:
            fmt, digest, _seq = subject_of(statement)
        except (Refused, canon.CanonicalError):
            continue
        by_hash[digest] = (index, statement, fmt)
    witnessed_upto = -1
    witnesses: List[str] = []
    for line, cosignature in enumerate(cosignatures):
        problem = cosignature_problem(cosignature)
        if problem:
            findings.append({"finding": problem, "cosignature": line})
            continue
        if cosignature["witness_key_id"] not in pinned:
            continue                       # a witness the reader does not trust says nothing either way
        entry = by_hash.get(cosignature["statement_sha256"])
        if entry is None:
            findings.append({"finding": "statement_missing", "cosignature": line,
                             "seq": cosignature["seq"], "leaves": cosignature["leaves"]})
            continue
        index, statement, fmt = entry
        seq = statement.get("seq") if fmt == rs.STATEMENT_FORMAT else None
        if (cosignature["statement_format"], cosignature["log"], cosignature["seq"], cosignature["leaves"],
                cosignature["root"], cosignature["signer_key_id"]) != (
                fmt, statement["log"], seq, statement["leaves"], statement["root"], statement["key_id"]):
            findings.append({"finding": "cosignature_mismatch", "cosignature": line})
            continue
        witnessed_upto = max(witnessed_upto, index)
        fp = rs.fingerprint(cosignature["witness_key_id"])
        if fp not in witnesses:
            witnesses.append(fp)
    if findings:
        status = INVALID
    elif statements and witnessed_upto == len(statements) - 1:
        status = WITNESSED
    else:
        status = UNWITNESSED
    return {"status": status, "witnesses": witnesses, "witnessed_statements": witnessed_upto + 1,
            "statements": len(statements), "unwitnessed_tail": len(statements) - witnessed_upto - 1,
            "findings": findings}
