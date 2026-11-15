# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Root statements: a deployment's own signature over the Merkle root of what it recorded.

A receipt is a Merkle leaf of the audit log (`prismpath.ledgers.audit_log`), so the log's root changes
when any past receipt changes. The root alone does not say who computed it, and until it is anchored a
person with write access can rewrite the log and compute a consistent new root. A **root statement**
closes that gap. It is a small record, signed with the deployment's **instance key**, that says "this
log held this many leaves and their root was this, after that previous statement, at this time, under
that policy". The statements form a chain, each naming the hash of the one before, so a statement
cannot be dropped from the middle or reordered, and a log can no longer be shortened or edited under a
signed root without the verifier saying so.

The instance key is not the policy authority key. The authority key says which policy may run; the
instance key says what a deployment recorded while it ran. One key doing both would let whoever holds
it write the policy and the evidence that the policy held, which is the separation of duties this
design exists to keep. The signature is computed over a domain prefix as well as the canonical bytes,
so a root statement signature can never be presented as a pack manifest signature or the reverse, and
a host that is handed an authority key as its instance key refuses it (`check_separation`).

A statement, one JSON line in the statements file beside the log:

    {"format": "prismpath-root-statement/3", "encoding": "canon/2", "log": "audit-log", "seq": 3,
     "root": "<hex>", "leaves": 42, "prev": "<sha256 of statement 2, or empty for the first>",
     "time_us": 1762257600123000, "trigger": "run-end",
     "key_id": "<sha256 of the raw public key>", "public_key": "<raw public key, hex>",
     "policy": {"flow_sha256": "<hex>"} or null,
     "sig": "<Ed25519 signature, hex>"}

The signature covers `SIGNING_DOMAIN` followed by the canon/2 bytes of every field except `sig`. A
statement's own hash, which the next statement names as `prev` and which `ledger anchor` anchors, is the
sha256 of the canon/2 bytes of the whole statement, signature included, so an anchored timestamp covers
the signature as well as the root. A `prismpath-root-statement/1` statement, written before canon/2 (an
ISO `time`, no `encoding`, canon/1 compact JSON), is no longer read: canon/1 is retired, and such a
statement is a `bad_format` finding. A `prismpath-root-statement/2` statement is the same document as `/3`
over the retired Merkle tree, which used no domain prefixes and repeated the last node of an odd layer, so
that [a, b, c] and [a, b, c, c] had one root; `/3` states the root of the RFC 6962 tree
(`ledger_ots.MERKLE_SCHEME`), and a `/2` statement is refused as `old_merkle_scheme` rather than checked
against a tree it was not computed over.

What it proves and what it does not. A pinned public key and a chain that verifies show that the
holder of the instance key stated these roots, in this order, and that the log still holds the leaves
under them. It does not show when: the time field is the signer's clock. Anchoring a statement hash
(OpenTimestamps or RFC 3161) adds the time a third party saw it. Deleting the tail of the log together
with the tail of the statements file leaves a shorter chain that still verifies; only a statement held
elsewhere (anchored, or copied off the host) shows that more was stated. Whoever holds the instance key
can sign anything, which is why it is a separate key and why it never leaves the deployment.

Ed25519 comes from `cryptography`, the `signing` extra. Signing and checking a signature raise
`MissingExtra` without it, so the command line prints the install line alone; reading an unsigned log
needs nothing.
"""
from __future__ import annotations

import datetime as _dt
import os
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from prismpath import canon
from prismpath.extras import MissingExtra
from prismpath.ledgers import ledger_ots as merkle

# A statement is written as `prismpath-root-statement/3`, a canon/2 document that names its encoding,
# carries its time as an integer of microseconds, and states a root of the RFC 6962 tree
# (`ledger_ots.MERKLE_SCHEME`). `/2` is the same document over the retired tree (no domain prefixes, the last
# node of an odd layer duplicated), so its root cannot be checked here and it is refused as `old_merkle_scheme`;
# `/1` (canon/1, an ISO time) is retired and not read.
STATEMENT_FORMAT = "prismpath-root-statement/3"
SIGNING_DOMAIN = b"prismpath-root-statement/3\x00"
OLD_SCHEME_FORMATS = ("prismpath-root-statement/2",)
INSTANCE_KEY_ENV = "PRISMPATH_INSTANCE_KEY"
DEFAULT_KEY_NAME = "instance"

# What the root commits to. An audit log's root is the Merkle root of its first `leaves` events; an
# epoch chain's root is the chained root of its first `leaves` epochs.
LOG_AUDIT = "audit-log"
LOG_EPOCH_CHAIN = "epoch-chain"

_BODY_FIELDS = ("format", "encoding", "log", "seq", "root", "leaves", "prev", "time_us", "trigger",
                "key_id", "public_key", "policy")

# Findings that make a chain invalid. `interrupted_statement` (a torn final line from a crash mid
# write) is reported and is not one of them: the statement it would have been never existed.
FATAL_FINDINGS = frozenset({
    "bad_format", "key_id_mismatch", "bad_signature", "unpinned_key", "authority_key",
    "chain_broken", "leaf_count_regressed", "log_truncated", "root_mismatch", "no_statements",
    "old_merkle_scheme",
})

# Statuses a verification reports.
SIGNED = "signed"                    # every statement verifies under a pinned public key
SIGNED_UNPINNED = "signed-unpinned"  # every statement verifies under the key it carries; no key was pinned
UNSIGNED = "unsigned"                # no statements, and no key was pinned: a log from before signing
INVALID = "invalid"                  # at least one fatal finding


def _ed25519():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        from cryptography.hazmat.primitives import serialization
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:
        raise MissingExtra("signing", "cryptography") from exc
    return Ed25519PrivateKey, Ed25519PublicKey, serialization, InvalidSignature


def key_id_of(public_raw: bytes) -> str:
    """sha256 hex of the raw 32 byte public key: the same identity rule the authority keys use, so one
    revocation list and one comparison serve both."""
    return canon.sha256_hex(public_raw)


def fingerprint(key_id: str) -> str:
    """The short form people read and compare: the first 16 hex characters of the key id."""
    return key_id[:16]


class InstanceKey:
    """A loaded instance private key. It never renders its private half: `repr` shows the fingerprint."""

    def __init__(self, private_key, public_raw: bytes, path: Optional[str] = None):
        self._private = private_key
        self.public_raw = public_raw
        self.key_id = key_id_of(public_raw)
        self.fingerprint = fingerprint(self.key_id)
        self.path = path

    @classmethod
    def load(cls, path: str) -> "InstanceKey":
        _Priv, _Pub, ser, _Inv = _ed25519()
        with open(path, "rb") as handle:
            private_key = ser.load_pem_private_key(handle.read(), password=None)
        public_raw = private_key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        return cls(private_key, public_raw, path)

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)

    def __repr__(self) -> str:
        return f"InstanceKey(fingerprint={self.fingerprint!r})"


def keygen(out_dir: str, name: str = DEFAULT_KEY_NAME) -> dict:
    """Generate an instance keypair: `<name>.key` (PKCS8 PEM, mode 0600) and `<name>.pub` (raw 32
    bytes), the same file shapes `swap keygen` writes. It refuses to replace an existing key, because
    the statements an old key signed verify only against that key. Returns paths, key id and
    fingerprint; never the private material."""
    Priv, _Pub, ser, _Inv = _ed25519()
    os.makedirs(out_dir, exist_ok=True)
    priv_path = os.path.join(out_dir, f"{name}.key")
    pub_path = os.path.join(out_dir, f"{name}.pub")
    for path in (priv_path, pub_path):
        if os.path.exists(path):
            raise FileExistsError(17, "refusing to replace an existing key (statements it signed verify only "
                                      "against it); choose another --name or --out", path)
    private_key = Priv.generate()
    pem = private_key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    public_raw = private_key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    with open(pub_path, "wb") as handle:
        handle.write(public_raw)
    key_id = key_id_of(public_raw)
    return {"private": priv_path, "public": pub_path, "key_id": key_id, "fingerprint": fingerprint(key_id),
            "role": "instance"}


def load_public(path: str) -> bytes:
    """A raw 32 byte Ed25519 public key file, as `keygen` and `swap keygen` write it."""
    with open(path, "rb") as handle:
        raw = handle.read()
    if len(raw) != 32:
        raise ValueError(f"{path}: not a raw 32 byte Ed25519 public key ({len(raw)} bytes)")
    return raw


def key_from_env(environ=None) -> Optional[InstanceKey]:
    """The instance key named by PRISMPATH_INSTANCE_KEY, or None when it is unset or empty."""
    environ = os.environ if environ is None else environ
    path = environ.get(INSTANCE_KEY_ENV, "").strip()
    return InstanceKey.load(path) if path else None


def check_separation(instance_key: Optional[InstanceKey], authority_key_ids: Iterable[str]) -> None:
    """Refuse an instance key that is also a policy authority key: the key that authorizes policy must
    not be the key that attests what the deployment recorded under it."""
    if instance_key is not None and instance_key.key_id in set(authority_key_ids):
        raise ValueError(f"the instance key {instance_key.fingerprint} is also a policy authority key; "
                         f"generate a separate one with `prismpath ledger keygen`")


def statements_path_for(log_path: str) -> str:
    """Where a log's statements live: beside it, `run.audit.jsonl` -> `run.audit.roots.jsonl`, and any
    other name gains `.roots.jsonl` (`swaps.log` -> `swaps.log.roots.jsonl`)."""
    if log_path.endswith(".jsonl"):
        return log_path[:-len(".jsonl")] + ".roots.jsonl"
    return log_path + ".roots.jsonl"


def merkle_root(leaves: List[str]) -> str:
    """The root `ledger_ots.merkle_root_and_paths` computes (RFC 6962), without building every path, or "" for
    no leaves."""
    return merkle.merkle_root(leaves) or ""


class MerkleAccumulator:
    """The same root, kept as leaves arrive: O(1) amortized to add a leaf and O(log n) to read the root.

    It holds the roots of the complete subtrees (the "peaks", one per set bit of the leaf count) rather
    than the leaves. RFC 6962 splits a tree over n leaves at the largest power of two below n, so the left
    part is the tallest peak and the right part is the tree over the rest, which splits the same way: the
    root is the tallest peak hashed with the root of the shorter peaks, all the way down. Folding the peaks
    from the shortest up, each hashed as the right child of the next taller one, computes exactly that,
    with nothing duplicated, so a statement signed from either verifies against the other;
    `test_root_statement` pins the two equal for every count up to a few hundred. Writing a signed
    statement after every event, and checking a chain that has one, then cost O(n) in all instead of
    O(n squared)."""

    def __init__(self, leaves: Iterable[str] = ()):
        self._peaks: List[Tuple[int, bytes]] = []        # (height, hash), tallest first
        self.count = 0
        for leaf in leaves:
            self.add(leaf)

    def add(self, leaf_hex: str) -> None:
        height, node = 0, merkle.leaf_hash(bytes.fromhex(leaf_hex))
        # The peaks are a stack of perfect subtrees with strictly falling heights, like the set bits of the
        # leaf count written in binary. A new leaf is a subtree of height 0; while the top of the stack has
        # the same height the two are siblings, so they merge into one subtree a level higher (the old peak
        # on the left, because it holds the earlier leaves). This is binary counter carry, which is why a
        # leaf costs O(1) amortized.
        while self._peaks and self._peaks[-1][0] == height:
            node = merkle.node_hash(self._peaks.pop()[1], node)
            height += 1
        self._peaks.append((height, node))
        self.count += 1

    def root(self) -> str:
        if not self._peaks:
            return ""
        # Fold the peaks from the shortest, which holds the latest leaves, up to the tallest: each taller
        # peak is the left child and what is folded so far the right, which is RFC 6962's split applied
        # once per peak.
        node = self._peaks[-1][1]
        for _height, peak in reversed(self._peaks[:-1]):
            node = merkle.node_hash(peak, node)
        return node.hex()


def prefix_roots(leaves: List[str], counts: Iterable[int]) -> Dict[int, str]:
    """The root over the first n leaves for each n in `counts`, in one pass over the leaves. A count
    past the end of `leaves` is left out."""
    # A count that is not an int, or is outside the log, is left out and not an error: `verify_chain` asks
    # `roots.get(count, "")` and reports a statement that claims more leaves than the log holds as
    # `log_truncated` before it ever compares roots.
    wanted = sorted({count for count in counts if isinstance(count, int) and 0 <= count <= len(leaves)})
    roots: Dict[int, str] = {}
    accumulator = MerkleAccumulator()
    # Ascending order lets one accumulator serve every count: it only ever has to take more leaves.
    for count in wanted:
        while accumulator.count < count:
            accumulator.add(leaves[accumulator.count])
        roots[count] = accumulator.root()
    return roots


def signed_bytes(statement: dict) -> bytes:
    """The bytes the signature covers: the domain prefix, then every field but `sig` in canon/2."""
    return SIGNING_DOMAIN + canon.canon2_bytes({key: statement[key] for key in _BODY_FIELDS})


def statement_hash(statement: dict) -> str:
    """The statement's content address, signature included: what the next statement chains to and what
    `ledger anchor` stamps: sha256 over its canon/2 bytes. A statement that does not name canon/2 is refused
    with an EncodingError."""
    return canon.document_hash(statement)


def _link_hash(statement: dict) -> str:
    """`statement_hash` for a link that may be damaged: the hash of what is there, or `unreadable` when it
    has no canon/2 form, so the next statement's `prev` is still compared with something that is not the
    empty first link."""
    try:
        return statement_hash(statement)
    except canon.CanonicalError:
        return "unreadable"


def _now_us() -> int:
    import time as _time
    return _time.time_ns() // 1000


def make_statement(key: InstanceKey, *, log: str, seq: int, root: str, leaves: int, prev: str,
                   trigger: str, policy: Optional[dict] = None, time_us: Optional[int] = None) -> dict:
    body = {"format": STATEMENT_FORMAT, canon.ENCODING_KEY: canon.CANON2, "log": log, "seq": int(seq),
            "root": root, "leaves": int(leaves), "prev": prev,
            "time_us": int(time_us) if time_us is not None else _now_us(), "trigger": trigger,
            "key_id": key.key_id, "public_key": key.public_raw.hex(), "policy": policy}
    body["sig"] = key.sign(signed_bytes(body)).hex()
    return body


def _is_json(line: str) -> bool:
    """The line parses as JSON at all: a final line that does not is a write a crash cut short, and one
    that does but is not a canonical statement is `bad_format`."""
    import json
    try:
        json.loads(line)
    except ValueError:
        return False
    return True


def read_statements(path: str) -> Tuple[List[dict], List[dict]]:
    """Every statement in the file, and the findings reading it produced. A final line that is not JSON
    is a write a crash cut short, reported as `interrupted_statement`; a bad line anywhere else is
    `bad_format`, because a chain with an unreadable link proves nothing past it."""
    if not path or not os.path.exists(path):
        return [], []
    with open(path, encoding="utf-8", newline="") as handle:     # bytes as written: a CR is not dropped
        raw_lines = handle.read().split("\n")
    if raw_lines and raw_lines[-1] == "":
        raw_lines.pop()
    statements, findings = [], []
    for index, line in enumerate(raw_lines):
        try:
            record = canon.loads_document(line)
            if not isinstance(record, dict):
                raise ValueError("not an object")
        except ValueError:
            if index == len(raw_lines) - 1 and not _is_json(line):
                findings.append({"finding": "interrupted_statement", "line": index + 1})
            else:
                findings.append({"finding": "bad_format", "line": index + 1})
                statements.append({})
            continue
        statements.append(record)
    return statements, findings


class RootSigner:
    """Appends signed statements to one statements file, continuing the chain already in it."""

    def __init__(self, key: InstanceKey, path: str, log: str = LOG_AUDIT):
        self.key = key
        self.path = path
        self.log = log
        statements, findings = read_statements(path)
        if any(finding["finding"] == "interrupted_statement" for finding in findings):
            # Drop the torn line so the next statement starts on a clean line; it was never a statement.
            with open(path, encoding="utf-8") as handle:
                lines = handle.read().split("\n")
            kept = [line for line in lines[:-1] if line] if lines[-1] == "" else lines[:-1]
            canon.atomic_write(path, "".join(line + "\n" for line in kept))
        self._seq = len(statements)
        self._prev = _link_hash(statements[-1]) if statements else ""

    def sign(self, root: str, leaves: int, trigger: str, policy: Optional[dict] = None) -> dict:
        statement = make_statement(self.key, log=self.log, seq=self._seq, root=root, leaves=leaves,
                                   prev=self._prev, trigger=trigger, policy=policy)
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(canon.canon2_bytes(statement).decode("utf-8") + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._seq += 1
        self._prev = statement_hash(statement)
        return statement


def _verify_signature(statement: dict) -> bool:
    _Priv, Pub, _ser, InvalidSignature = _ed25519()
    try:
        Pub.from_public_bytes(bytes.fromhex(statement["public_key"])).verify(
            bytes.fromhex(statement["sig"]), signed_bytes(statement))
        return True
    except (InvalidSignature, ValueError):
        return False


def _well_formed(statement: dict, log: str) -> bool:
    if statement.get("format") != STATEMENT_FORMAT or statement.get("log") != log:
        return False
    if any(key not in statement for key in _BODY_FIELDS + ("sig",)) or len(statement) != len(_BODY_FIELDS) + 1:
        return False
    if (statement["encoding"] != canon.CANON2 or not isinstance(statement["time_us"], int)
            or isinstance(statement["time_us"], bool)):
        return False
    if not (isinstance(statement["seq"], int) and isinstance(statement["leaves"], int)
            and isinstance(statement["root"], str) and isinstance(statement["prev"], str)
            and isinstance(statement["key_id"], str)):
        return False
    try:
        return len(bytes.fromhex(statement["public_key"])) == 32 and len(bytes.fromhex(statement["sig"])) == 64
    except (TypeError, ValueError):
        return False


def verify_chain(statements: List[dict], read_findings: List[dict], root_at: Callable[[int], str],
                 total_leaves: int, *, log: str = LOG_AUDIT, pinned: Optional[Iterable[bytes]] = None,
                 authority_key_ids: Iterable[str] = ()) -> dict:
    """Check a chain of statements against the log it covers.

    `root_at(n)` is the root of the log's first n leaves; `total_leaves` is how many the log holds now.
    `pinned` is the public keys the reader trusts (raw bytes); with none, each statement is checked
    under the key it carries and the result is at best `signed-unpinned`. With a pinned key, a log with
    no statements is invalid (`no_statements`), so removing the statements file cannot pass a signed log
    off as an old unsigned one. `authority_key_ids` are policy authority keys seen in the log; a
    statement signed by one is `authority_key`."""
    pinned_ids = {key_id_of(raw) for raw in pinned} if pinned else set()
    authority = set(authority_key_ids)
    findings = list(read_findings)
    prev_hash, prev_leaves = "", 0
    mismatch_from: Optional[int] = None
    key_ids: List[str] = []
    for index, statement in enumerate(statements):
        # An empty statement is a line that could not be read (already a finding from the reader); a
        # statement of the wrong shape is reported here. Either way it stays in the chain as a link, with
        # the hash of what is there (nothing, for a line that could not be read), so the next statement's
        # `prev` is compared with the truth and a chain cannot be mended by deleting the damaged link.
        if not statement or not _well_formed(statement, log):
            if statement and statement.get("format") in OLD_SCHEME_FORMATS:
                findings.append({"finding": "old_merkle_scheme", "statement": index, "format": statement["format"]})
            elif statement:
                findings.append({"finding": "bad_format", "statement": index})
            prev_hash = _link_hash(statement) if statement else ""
            continue
        seq = statement["seq"]
        # The key id must be the hash of the key the statement carries; only then is the signature checked
        # (under that key), so a statement that names one key and was signed by another is one finding, not two.
        if key_id_of(bytes.fromhex(statement["public_key"])) != statement["key_id"]:
            findings.append({"finding": "key_id_mismatch", "statement": seq})
        elif not _verify_signature(statement):
            findings.append({"finding": "bad_signature", "statement": seq})
        if pinned_ids and statement["key_id"] not in pinned_ids:
            findings.append({"finding": "unpinned_key", "statement": seq,
                             "key": fingerprint(statement["key_id"])})
        # A policy authority key authorizes flows and packs; it must never also attest what a deployment
        # recorded, or whoever can replace the policy could also vouch for the record of running it.
        if statement["key_id"] in authority:
            findings.append({"finding": "authority_key", "statement": seq, "key": fingerprint(statement["key_id"])})
        if statement["key_id"] not in key_ids:
            key_ids.append(statement["key_id"])
        # Each statement names the hash of the one before it, and carries its position, so a statement
        # dropped, reordered, duplicated or replaced shows as a break at the first place it matters.
        if seq != index or statement["prev"] != prev_hash:
            findings.append({"finding": "chain_broken", "statement": seq, "position": index})
        # A log only grows, so a later statement covering fewer leaves means events were dropped between them.
        if statement["leaves"] < prev_leaves:
            findings.append({"finding": "leaf_count_regressed", "statement": seq,
                             "leaves": statement["leaves"], "before": prev_leaves})
        # A statement that covers more leaves than the log holds proves the log was cut after it was signed;
        # there is no root to compare, because the leaves it signed are gone.
        if statement["leaves"] > total_leaves:
            findings.append({"finding": "log_truncated", "statement": seq,
                             "signed_leaves": statement["leaves"], "log_leaves": total_leaves})
        elif root_at(statement["leaves"]) != statement["root"]:
            # The first statement whose root no longer matches bounds the edit: a receipt at an index
            # in this range (event `idx`, from 0) changed after the statement before it was signed.
            # Once one root fails, every later one covers the same edit, so the range keeps its start.
            if mismatch_from is None:
                mismatch_from = min(prev_leaves, statement["leaves"])
            findings.append({"finding": "root_mismatch", "statement": seq,
                             "leaf_range": [mismatch_from, statement["leaves"] - 1]})
        prev_hash, prev_leaves = statement_hash(statement), statement["leaves"]
    if pinned_ids and not statements:
        findings.append({"finding": "no_statements"})
    fatal = [finding for finding in findings if finding["finding"] in FATAL_FINDINGS]
    if fatal:
        status = INVALID
    elif not statements:
        status = UNSIGNED
    else:
        status = SIGNED if pinned_ids else SIGNED_UNPINNED
    last = next((statement for statement in reversed(statements) if statement), None)
    signed_leaves = last.get("leaves", 0) if last else 0
    return {"status": status, "statements": len(statements), "signed_leaves": signed_leaves,
            "log_leaves": total_leaves,
            "unsigned_tail": max(0, total_leaves - signed_leaves) if statements else total_leaves,
            "keys": [fingerprint(key_id) for key_id in key_ids], "pinned": bool(pinned_ids),
            "last_statement_sha256": _link_hash(last) if last else None,
            "findings": findings}


# ------------------------------------------------------------------ one receipt, offline

def receipt_bundle(event: dict, leaves: List[str], index: int, statements: List[dict]) -> dict:
    """Everything a reader needs to check one receipt with nothing else: the receipt, its leaf, its
    inclusion path in the tree of the first statement that covers it, and that statement. Raises
    LookupError when no statement covers the receipt yet."""
    covering = next((statement for statement in statements
                     if statement and isinstance(statement.get("leaves"), int) and statement["leaves"] > index), None)
    if covering is None:
        raise LookupError(f"no root statement covers receipt {index} yet (the log has "
                          f"{len(leaves)} leaves; sign a checkpoint first)")
    _root, paths = merkle.merkle_root_and_paths(leaves[:covering["leaves"]])
    return {"receipt": event, "index": index, "leaf": leaves[index], "path": paths[index], "statement": covering}


def bundle_problem(bundle) -> Optional[str]:
    """Why `bundle` is not shaped like a receipt bundle, or None. A bundle read from a file is untrusted
    input, so every field the check touches is looked at before it is used."""
    if not isinstance(bundle, dict):
        return "a bundle is a JSON object"
    for name, kind in (("receipt", dict), ("index", int), ("leaf", str), ("path", list), ("statement", dict)):
        if not isinstance(bundle.get(name), kind) or isinstance(bundle.get(name), bool):
            return f"missing or malformed field {name!r}"
    try:
        bytes.fromhex(bundle["leaf"])
        for step in bundle["path"]:
            if not (isinstance(step, (list, tuple)) and len(step) == 2 and step[0] in ("L", "R")):
                return "malformed inclusion path"
            bytes.fromhex(step[1])
    except (TypeError, ValueError):
        return "the leaf and the inclusion path are hex hashes"
    for name in ("receipt", "statement"):
        try:
            canon.encoding_of(bundle[name])
        except canon.CanonicalError:
            return f"the {name} does not name canon/2 (canon/1 is retired)"
    return None


def verify_receipt_bundle(bundle: dict, pinned: Optional[Iterable[bytes]] = None) -> dict:
    """receipt -> leaf -> inclusion path -> signed root -> signature, and the key against `pinned`.
    Offline and self contained. It checks the one statement in the bundle, not the chain around it;
    `trail` checks the chain. `status` is `signed` (a pinned key made the signature), `signed-unpinned`
    (the key the statement carries made it; none was pinned) or `invalid`; a bundle that is not shaped
    like one is invalid with `problem` saying how, never an exception."""
    problem = bundle_problem(bundle)
    if problem is None and bundle["statement"].get("format") in OLD_SCHEME_FORMATS:
        problem = (f"the statement is {bundle['statement']['format']}, whose root is of the retired Merkle tree; "
                   f"this verifier reads only {STATEMENT_FORMAT} ({merkle.MERKLE_SCHEME})")
    if problem is not None:
        return {"ok": False, "status": INVALID, "pinned": bool(pinned), "checks": {"well_formed": False},
                "problem": problem, "index": None, "statement": None, "statement_sha256": None, "key": ""}
    statement = bundle["statement"]
    try:
        leaf = canon.document_hash(bundle["receipt"])
    except canon.CanonicalError:
        leaf = ""
    checks = {"leaf": leaf == bundle["leaf"],
              "index": bundle["receipt"].get("idx") == bundle["index"],
              "inclusion": merkle.verify_leaf(bundle["leaf"], [tuple(step) for step in bundle["path"]],
                                              statement.get("root", "")),
              "well_formed": _well_formed(statement, LOG_AUDIT)}
    checks["covered"] = checks["well_formed"] and 0 <= bundle["index"] < statement["leaves"]
    checks["key_id"] = checks["well_formed"] and key_id_of(bytes.fromhex(statement["public_key"])) == statement["key_id"]
    checks["signature"] = checks["key_id"] and _verify_signature(statement)
    pinned_ids = {key_id_of(raw) for raw in pinned} if pinned else set()
    checks["pinned"] = (statement.get("key_id") in pinned_ids) if pinned_ids else None
    ok = all(value for name, value in checks.items() if name != "pinned") and checks["pinned"] is not False
    return {"ok": ok, "status": (SIGNED if pinned_ids else SIGNED_UNPINNED) if ok else INVALID,
            "pinned": bool(pinned_ids), "checks": checks, "index": bundle.get("index"),
            "statement": statement.get("seq"), "statement_sha256": _link_hash(statement),
            "key": fingerprint(statement.get("key_id", ""))}


def authority_key_ids_in(events: Iterable[dict]) -> List[str]:
    """The policy authority key ids an audit log names: every accepted swap carries the pack's key id."""
    found: Dict[str, None] = {}
    for event in events:
        data = event.get("data") if isinstance(event, dict) else None
        if isinstance(data, dict) and event.get("action") == "swap" and data.get("key_id"):
            found[str(data["key_id"])] = None
    return list(found)
