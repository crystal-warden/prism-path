# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The install statements of policy distribution (spec-policy-distribution.md, section 21.1, 21.3 and 21.4): the
install record, the install trust statement, the held and the staged install sets, the ceiling and the comparisons
an install set is held to.

The engineer who installs PrismPath on a resource signs three bounds with install keys, which are held apart from
the trust store in the install record (IS10, K3): the action floor, the fallback policy and the ceiling. This module
holds what the PEP machine (`prismpath.distribution.pep`) and the sealing tool share:

    Record          IS10: the install keys and threshold, the operator keys, the retired ids, the install trust
                    sequence and id, the three install sequences, the held sets and the counts of AF8
    counting        S3 to S5 for the role `install`, against the install threshold (IS2)
    check_trust     IS11: what an `install.trust` must be beyond its signatures
    Installed       the PEP's install part on disk: two copies of the record and of every held statement (IS10),
                    the staged sets (IS4), and the marks kept in the anchor part (IS9, IS10)
    inside          CL1: whether a release or an install set is inside a ceiling
    set_larger      IS12: whether an install set allows more than the one it follows
    domain_sha256   P4, CL4: the hash of the reading domain a PEP was built with

This version builds the fallback policy and the ceiling. An action floor is refused at V5 with
`dist:target-mismatch` until the floor's own rules (section 21.2) are built, so a PEP that has none refuses as
before (X3), and no PEP holds a floor it would not ask.

Files, under the PEP's `dist/` directory and its second medium (`copy`), each written whole:

    install/record.json   the install record, and the same document at `<copy>/record.json`
    install/blobs/        every held and staged statement and body under its SHA-256, the held ones also at
                          `<copy>/blobs/`
    install/staged.json   the staged install sets, at most one per install kind (IS4)
    install/zones.json    the protected names of the last committed `agent` release (FB9), and at `<copy>/zones.json`
    marks.json            the marks of the anchor part: an install statement was held (IS9), a ceiling was (IS10),
                          and the streams a release was committed on (L2)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple

from prismpath import canon
from prismpath.distribution import envelope as env
from prismpath.distribution import kinds
from prismpath.distribution.adapters import CANNOT_DECIDE, LARGER, NOT_LARGER
from prismpath.distribution.kinds import Refused, Verdict, is_hex64, is_int

RECORD_FORMAT = "prismpath.dist-install/1"
STAGED_FORMAT = "prismpath.dist-install-staged/1"
ZONES_FORMAT = "prismpath.dist-install-zones/1"
MARKS_FORMAT = "prismpath.dist-marks/1"
MAX_RETIRED = 8                                    # IS10: the retired install and operator key ids remembered
FLOOR, FALLBACK, CEILING, TRUST = "install.floor", "install.fallback", "install.ceiling", "install.trust"
SET_KINDS = (FLOOR, FALLBACK, CEILING)             # H10: the order of the install id
SUBJECT = {FLOOR: 1, FALLBACK: 2, CEILING: 3, TRUST: 4, "operator.answer": 5}       # H10
BUILT = frozenset({FALLBACK, CEILING, TRUST})      # the install kinds this version admits (see the module note)
INSTALL_LOST, ABOVE_CEILING, WIDENED = "dist:install-lost", "dist:above-ceiling", "dist:install-widened"
UNKNOWN_KEY, INVALID, REVOKED_KEY = "dist:unknown-key", "sig:invalid", "sig:revoked-key"
ROTATION_INVALID, UNSIGNED = "dist:rotation-invalid", "dist:widening-unsigned"


def _hexes(value: Any) -> bool:
    return isinstance(value, list) and all(is_hex64(item) for item in value)


# ------------------------------------------------------------------ the install record (IS10)

@dataclass(frozen=True)
class HeldSet:
    """One install set as the PEP holds it: its kind, `seq`, set id and the members its statements share (V10), and
    per artifact `as` the (envelope id, sealed blob, body blob) of its statement. `envelopes` and `bodies` are read
    back from the blobs."""
    kind: str
    seq: int
    set_id: str
    policy_sha256: str
    release: str
    replaces: str
    widens: bool
    statements: Mapping[str, Tuple[str, str, str]]
    envelopes: Mapping[str, Any] = field(default_factory=dict, compare=False)
    bodies: Mapping[str, bytes] = field(default_factory=dict, compare=False)

    @property
    def envelope_ids(self) -> FrozenSet[str]:
        return frozenset(one[0] for one in self.statements.values())

    @property
    def empty(self) -> bool:
        """IS1: the empty set, which withdraws its install kind."""
        return set(self.statements) == {kinds.NONE}

    def document(self) -> dict:
        return {"policy_sha256": self.policy_sha256, "release": self.release, "replaces": self.replaces,
                "seq": self.seq, "set_id": self.set_id, "widens": self.widens,
                "statements": {name: {"envelope_id": one[0], "sealed": one[1], "body": one[2]}
                               for name, one in sorted(self.statements.items())}}

    @classmethod
    def from_document(cls, kind: str, doc: dict) -> "HeldSet":
        statements = {}
        for name, one in doc["statements"].items():
            if not (isinstance(one, dict) and set(one) == {"envelope_id", "sealed", "body"}
                    and all(is_hex64(one[member]) for member in one)):
                raise Refused(kinds.BAD_FORMAT, "a held statement")
            statements[name] = (one["envelope_id"], one["sealed"], one["body"])
        if not (is_int(doc["seq"], 1, kinds.MAX_SEQ) and is_hex64(doc["set_id"]) and statements
                and isinstance(doc["widens"], bool)):
            raise Refused(kinds.BAD_FORMAT, "a held set")
        return cls(kind, doc["seq"], doc["set_id"], doc["policy_sha256"], doc["release"], doc["replaces"],
                   doc["widens"], statements)

    def as_release(self):
        """The set in the shape of a release, for a runtime that runs it in place of one (FB1)."""
        from prismpath.distribution.pep import Held, Release
        release = Release(self.envelopes[next(iter(self.envelopes))].stream if self.envelopes else "", self.seq,
                          self.policy_sha256, self.release, self.replaces, self.widens)
        for name, (envelope_id, sealed, body) in self.statements.items():
            release.held[name] = Held(envelope_id, sealed, body)
            release.envelopes[name], release.bodies[name] = self.envelopes[name], self.bodies[name]
        return release


@dataclass(frozen=True)
class Record:
    """IS10: what a PEP holds of its install part. `keys` and `operators` map a key id to its 32 raw public bytes.
    `retired` is the retired install and operator key ids, oldest first, at most 8. `seqs` is the install sequence
    of each set kind and `sets` the set held of each, None when none is. `answers` and `overrides` are the counts of
    H10. `domain` is the hash of the reading domain the anchor named (P4)."""
    keys: Mapping[str, bytes]
    threshold: int
    operators: Mapping[str, bytes] = field(default_factory=dict)
    retired: Tuple[str, ...] = ()
    trust_seq: int = 0
    trust_id: str = ""
    seqs: Mapping[str, int] = field(default_factory=lambda: {kind: 0 for kind in SET_KINDS})
    sets: Mapping[str, Optional[HeldSet]] = field(default_factory=lambda: {kind: None for kind in SET_KINDS})
    answers: int = 0
    overrides: int = 0
    domain: str = ""

    def document(self) -> dict:
        return {canon.ENCODING_KEY: canon.CANON2, "format": RECORD_FORMAT, "answers": self.answers,
                "domain": self.domain, "keys": sorted(public.hex() for public in self.keys.values()),
                "operators": sorted(public.hex() for public in self.operators.values()),
                "overrides": self.overrides, "retired": list(self.retired),
                "seqs": {kind: self.seqs[kind] for kind in SET_KINDS},
                "sets": {kind: (None if self.sets[kind] is None else self.sets[kind].document()) for kind in SET_KINDS},
                "threshold": self.threshold, "trust_id": self.trust_id, "trust_seq": self.trust_seq}

    def to_bytes(self) -> bytes:
        return canon.canon2_bytes(self.document())

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Record":
        doc = kinds.load_canonical(raw, "install record")
        members = {"encoding", "format", "answers", "domain", "keys", "operators", "overrides", "retired", "seqs",
                   "sets", "threshold", "trust_id", "trust_seq"}
        if not (isinstance(doc, dict) and set(doc) == members and doc["format"] == RECORD_FORMAT
                and _hexes(doc["keys"]) and _hexes(doc["operators"]) and _hexes(doc["retired"])
                and 1 <= len(doc["keys"]) <= kinds.INSTALL_KEYS and len(doc["operators"]) <= kinds.OPERATOR_KEYS
                and len(doc["retired"]) <= MAX_RETIRED and is_int(doc["threshold"], 1, len(doc["keys"]))
                and is_int(doc["trust_seq"], 0, kinds.MAX_SEQ) and (doc["trust_id"] == "" or is_hex64(doc["trust_id"]))
                and (doc["domain"] == "" or is_hex64(doc["domain"]))
                and isinstance(doc["seqs"], dict) and set(doc["seqs"]) == set(SET_KINDS)
                and all(is_int(seq, 0, kinds.MAX_SEQ) for seq in doc["seqs"].values())
                and isinstance(doc["sets"], dict) and set(doc["sets"]) == set(SET_KINDS)
                and all(is_int(doc[name], 0, 2 ** 32 - 1) for name in ("answers", "overrides"))):
            raise Refused(kinds.BAD_FORMAT, "not an install record")
        try:
            sets = {kind: None if doc["sets"][kind] is None else HeldSet.from_document(kind, doc["sets"][kind])
                    for kind in SET_KINDS}
        except (KeyError, TypeError) as error:
            raise Refused(kinds.BAD_FORMAT, f"an install record's sets ({error})") from None
        keys = {env.key_id(bytes.fromhex(one)): bytes.fromhex(one) for one in doc["keys"]}
        operators = {env.key_id(bytes.fromhex(one)): bytes.fromhex(one) for one in doc["operators"]}
        return cls(keys=keys, threshold=doc["threshold"], operators=operators, retired=tuple(doc["retired"]),
                   trust_seq=doc["trust_seq"], trust_id=doc["trust_id"], seqs=dict(doc["seqs"]), sets=sets,
                   answers=doc["answers"], overrides=doc["overrides"], domain=doc["domain"])

    # ------------------------------------------------------------------ S3 to S5 for the role install
    def counting(self, entries: Sequence[Tuple[str, bytes]], message: bytes) -> Verdict:
        """IS2, S3 to S5: an entry counts when its key id names an install key the record holds and its signature
        verifies. The envelope is signed when at least the install threshold count. Otherwise `sig:revoked-key`
        when an entry verifies under a retired install or operator key, `sig:invalid` when one names a held key and
        does not verify, and `dist:unknown-key`. A retired id past the eight remembered reads as unknown (IS11)."""
        from prismpath.hotswap import policy_pack
        _priv, Public, _ser, InvalidSignature = policy_pack._ed25519()
        counted, held_fails = 0, False
        for kid, signature in entries:
            key = self.keys.get(kid)
            if key is None:
                continue
            try:
                Public.from_public_bytes(key).verify(signature, message)
                counted += 1
            except (InvalidSignature, ValueError):
                held_fails = True
        if counted >= self.threshold:
            return Verdict(None)
        if any(kid in self.retired for kid, _signature in entries):
            return Verdict(REVOKED_KEY)
        return Verdict(INVALID if held_fails else UNKNOWN_KEY)

    @property
    def ids(self) -> FrozenSet[str]:
        """Every install and operator key id the record holds or remembers as retired (K4)."""
        return frozenset(self.keys) | frozenset(self.operators) | frozenset(self.retired)

    def install_id(self) -> bytes:
        """H10: the first 16 bytes of the SHA-256 of the set id and `seq` of the action floor, the fallback policy and
        the ceiling held, zeros for a set not held, then the install trust sequence and the install trust id. A kind the
        empty set withdrew holds nothing (IS6), so it is zeros too."""
        import hashlib
        import struct
        out = b""
        for kind in SET_KINDS:
            held = self.sets[kind]
            out += (bytes.fromhex(held.set_id) + struct.pack("<Q", held.seq)) if held is not None and not held.empty \
                else b"\x00" * 40
        out += struct.pack("<Q", self.trust_seq) + (bytes.fromhex(self.trust_id) if self.trust_id else b"\x00" * 32)
        assert len(out) == 160
        return hashlib.sha256(out).digest()[:16]

    def apply_trust(self, envelope, body: bytes) -> "Record":
        """IS11: the record after a verified `install.trust`. Its keys, operators and threshold replace the held
        ones, every key it leaves out is retired, the ninth retired id forgets the oldest, and its `seq` and
        envelope id are the install trust sequence and id."""
        doc = kinds.read_install_trust(body)
        keys = {env.key_id(bytes.fromhex(one)): bytes.fromhex(one) for one in doc["keys"]}
        operators = {env.key_id(bytes.fromhex(one)): bytes.fromhex(one) for one in doc["operators"]}
        return replace(self, keys=keys, operators=operators, threshold=doc["threshold"],
                       retired=_retire(self.retired, (set(self.keys) | set(self.operators)) - set(keys) - set(operators)),
                       trust_seq=envelope.seq, trust_id=envelope.envelope_id)


def _retire(retired: Sequence[str], dropped: Iterable[str]) -> Tuple[str, ...]:
    out = list(retired) + [kid for kid in sorted(dropped) if kid not in retired]
    return tuple(out[-MAX_RETIRED:])


def trust_widens(record: Record, body: bytes) -> bool:
    """IS11: an `install.trust` widens when it adds a key of either role or lowers the threshold."""
    doc = kinds.read_install_trust(body)
    added = {env.key_id(bytes.fromhex(one)) for one in doc["keys"] + doc["operators"]} - set(record.keys) - set(record.operators)
    return bool(added) or doc["threshold"] < record.threshold


def check_trust(record: Record, body: bytes, entries: Sequence[Tuple[str, bytes]], message: bytes, *, widens: bool,
                instance_key_id: Optional[str], trust) -> Optional[str]:
    """IS11 for an `install.trust` that already counts under the record (V3) and reads (V11). Every key it adds signs
    it (`dist:rotation-invalid`), and none it adds is the PEP's instance key, a key the trust store holds or has
    retired, a key id on the revocation list or a retired install or operator key. A key it adds to `keys` is not a
    held operator key, one it adds to `operators` not a held install key, and no key is in both lists. A wrong
    `widens` false is `dist:widening-unsigned`. None when it may be applied."""
    from prismpath.hotswap import policy_pack
    _priv, Public, _ser, InvalidSignature = policy_pack._ed25519()
    doc = kinds.read_install_trust(body)
    keys = {env.key_id(bytes.fromhex(one)): bytes.fromhex(one) for one in doc["keys"]}
    operators = {env.key_id(bytes.fromhex(one)): bytes.fromhex(one) for one in doc["operators"]}
    if set(keys) & set(operators):
        return ROTATION_INVALID
    added = {**{kid: public for kid, public in keys.items() if kid not in record.keys},
             **{kid: public for kid, public in operators.items() if kid not in record.operators}}
    held_elsewhere = set(trust.keys) | set(trust.retired) | set(trust.revoked_keys) if trust is not None else set()
    for kid in added:
        if (kid == instance_key_id or kid in held_elsewhere or kid in record.retired
                or (kid in keys and kid in record.operators) or (kid in operators and kid in record.keys)):
            return ROTATION_INVALID
    signed = dict(entries)
    for kid, public in added.items():
        if kid not in signed:
            return ROTATION_INVALID
        try:
            Public.from_public_bytes(public).verify(signed[kid], message)
        except (InvalidSignature, ValueError):
            return ROTATION_INVALID
    if not widens and trust_widens(record, body):
        return UNSIGNED
    return None


# ------------------------------------------------------------------ the install part of an anchor (P4)

def read_anchor_part(part: Any) -> Record:
    """P4: the `install` member of a `/2` anchor, which holds `keys`, `threshold` and `operators` as the body of an
    `install.trust` does, `seq`, the install trust sequence they stand at, and `domain`. `Refused` with
    `dist:bad-format` when it does not read, and with `dist:too-large` past four keys of either role."""
    if not (isinstance(part, dict) and set(part) == {"domain", "keys", "operators", "seq", "threshold"}):
        raise Refused(kinds.BAD_FORMAT, "an anchor's install member")
    body = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": kinds.INSTALL_TRUST_FORMAT,
                               "keys": part["keys"], "operators": part["operators"], "threshold": part["threshold"]})
    doc = kinds.read_install_trust(body)
    if not is_int(part["seq"], 0, kinds.MAX_SEQ) or not is_hex64(part["domain"]):
        raise Refused(kinds.BAD_FORMAT, "an anchor's install seq or domain")
    keys = {env.key_id(bytes.fromhex(one)): bytes.fromhex(one) for one in doc["keys"]}
    operators = {env.key_id(bytes.fromhex(one)): bytes.fromhex(one) for one in doc["operators"]}
    if set(keys) & set(operators):
        raise Refused(kinds.BAD_FORMAT, "an anchor that holds one key as an install and an operator key (K4)")
    return Record(keys=keys, threshold=doc["threshold"], operators=operators, trust_seq=part["seq"],
                  domain=part["domain"])


def anchor_part(install_keys: Sequence[bytes], *, threshold: int, operators: Sequence[bytes] = (), seq: int = 0,
                domain: str) -> dict:
    """The `install` member of an anchor, for the engineer's tool."""
    return {"domain": domain, "keys": sorted(bytes(one).hex() for one in install_keys),
            "operators": sorted(bytes(one).hex() for one in operators), "seq": seq, "threshold": threshold}


def domain_document(adapter) -> bytes:
    """CL4, P4: the reading domain the PEP was built with, as canon/2 bytes. On `agent` it is the values the
    classifier produces for each category; on `gateway` the classes its reading gives; on a kind that cannot decide it
    is the layout the PEP was built for, the adapter's `layout` document, which on `host` is the qualification
    envelope's fields. An adapter may name its own with `domain`."""
    own = getattr(adapter, "domain", None)
    if own is not None:
        return bytes(own)
    kind = adapter.kind
    if kind == "agent":
        from prismpath.agent import profile
        doc: Any = {"kind": kind, "categories": {name: list(values) for name, values in profile.KNOWN_CATEGORIES.items()}}
    elif kind == "gateway":
        from prismpath.gateway import reading
        doc = {"kind": kind, "fields": list(reading.FIELDS),
               "categories": {"method_class": list(reading.METHOD_CLASSES), "body_class": list(reading.BODY_CLASSES),
                              "content_class": list(reading.CONTENT_CLASSES), "query": list(reading.QUERY_CLASSES),
                              "grant": list(reading.GRANT_STATES)}}
    elif kind == "host":
        qualification = getattr(adapter, "qualification", None) or {}
        doc = {"kind": kind, "fields": dict(qualification.get("fields") or {})}
    else:
        doc = {"kind": kind, "layout": getattr(adapter, "layout", None)}
    return canon.canon2_bytes(doc)


def domain_sha256(adapter) -> str:
    return canon.sha256_hex(domain_document(adapter))


# ------------------------------------------------------------------ CL1: inside the ceiling

def _routes_inside(ceiling: bytes, staged: bytes) -> bool:
    """CL1: every path of every route of `staged` gets the same class from the ceiling's table. A route that ends in
    `/*` covers every path below it, and the ceiling must give all of them its class, so any entry of the ceiling
    that reaches one of them with another class, or a path the ceiling leaves to `other`, puts it outside."""
    try:
        ceiling_routes, staged_routes = kinds.read_routes(ceiling), kinds.read_routes(staged)
    except Refused:
        return False
    for base, prefix, name in staged_routes.entries:
        if not prefix:
            if ceiling_routes.classify(base) != name:
                return False
            continue
        covered = False
        for cbase, cprefix, cname in ceiling_routes.entries:
            whole = cprefix and (cbase == "" or base == cbase or base.startswith(cbase + "/"))
            reaches = whole or cbase == base or base == "" or cbase.startswith(base + "/")
            if reaches and cname != name:
                return False
            if whole:
                covered = True
                break
        if not covered:
            return False
    return True


def _names(body: Optional[bytes]) -> FrozenSet[str]:
    return frozenset() if body is None else frozenset(kinds.read_zones(body)["protected"])


def artifact_inside(name: str, ceiling: Optional[bytes], body: bytes) -> bool:
    """CL1 for one artifact of a set the ceiling is in the form of: not larger than the ceiling's by section 9.4,
    with a route table held as `_routes_inside` says and the derived artifacts following their policy."""
    from prismpath.distribution import widening
    if name in ("sandbox.profile", "net.edge", "policy.spiral"):
        return True
    if name == "agent.zones":
        try:
            return _names(ceiling) <= _names(body)
        except Refused:
            return False
    if ceiling is None:
        return False
    if name == "gateway.routes":
        return _routes_inside(ceiling, body)
    return widening.compare_artifact(name, ceiling, body) == NOT_LARGER


def inside(kind: str, ceiling: Optional[HeldSet], bodies: Mapping[str, bytes], *, whole: bool = True) -> bool:
    """CL1: `bodies`, {artifact: body} of a release or an install set, is inside `ceiling`, the held ceiling or None.
    On a kind that cannot decide the `body_sha256` of its `policy.ppt` or `cfs.table` is on the ceiling's list, and
    the empty list holds nothing. On a kind that can decide each artifact is inside the ceiling's, and with `whole`
    every name the ceiling's `agent.zones` protects is protected."""
    if ceiling is None or ceiling.empty:
        return True
    if kinds.POLICY_LIST in ceiling.bodies:
        listed = set(kinds.read_ceiling_list(ceiling.bodies[kinds.POLICY_LIST])["bodies"])
        tables = [bodies[name] for name in ("policy.ppt", "cfs.table") if name in bodies]
        return all(canon.sha256_hex(table) in listed for table in tables)
    names = set(bodies) - kinds.TRUST_ARTIFACTS
    if whole:
        names |= {"agent.zones"} & set(ceiling.bodies)
    return all(artifact_inside(name, ceiling.bodies.get(name), bodies.get(name)) for name in sorted(names)
               if name in bodies or name == "agent.zones")


# ------------------------------------------------------------------ IS12: the widening of an install set

def set_larger(kind: str, install_kind: str, held: Optional[HeldSet], bodies: Mapping[str, bytes]) -> Optional[bool]:
    """IS12: whether the set `bodies` allows or escalates more than `held`, the set it follows or None, or None when
    the PEP cannot tell. A first action floor and a first fallback policy widen, the empty one does not; a first
    ceiling does not, the empty ceiling does, and a ceiling that allows more does. A list that holds a hash the one
    before did not is larger, and every PEP compares two lists. On a kind that can decide the sets are compared by
    section 9.4, and on `host` and `mesh` a table that is not byte for byte the held one is larger. A `cfs` PEP
    cannot tell for a table, and takes the signer's word (H13)."""
    from prismpath.distribution import widening
    empty = set(bodies) == {kinds.NONE}
    before = None if held is None or held.empty else dict(held.bodies)
    if install_kind == CEILING:
        if empty:
            return before is not None
        if before is None:
            return False
        if kinds.POLICY_LIST in bodies:
            if kinds.POLICY_LIST not in before:
                return True
            old = set(kinds.read_ceiling_list(before[kinds.POLICY_LIST])["bodies"])
            return not set(kinds.read_ceiling_list(bodies[kinds.POLICY_LIST])["bodies"]) <= old
    elif empty:
        return False
    elif before is None:
        return True
    if kinds.TARGETS[kind].decides:
        return widening.compare_release(before, dict(bodies)) != NOT_LARGER
    if kind in ("host", "mesh"):
        return {name: bytes(body) for name, body in before.items()} != {name: bytes(body) for name, body in bodies.items()}
    return None


def widens_ok(kind: str, install_kind: str, held: Optional[HeldSet], bodies: Mapping[str, bytes], *, widens: bool,
              replaces: str) -> Tuple[Optional[str], bool]:
    """IS12: (cause, stands out) of a set whose signer said `widens` and `replaces`. A set the PEP computes as larger
    whose `widens` is false is `dist:widening-unsigned`. A PEP that cannot decide also takes `widens` false only when
    `replaces` is the policy hash of the set it holds, the empty string when it holds none. A set stands out, with
    event `install-widened`, when its `widens` is true or the PEP computes it as larger. A kind the empty set withdrew
    holds none, so the set after it names the empty string (IS6)."""
    larger = set_larger(kind, install_kind, held, bodies)
    if widens:
        return None, True
    if larger:
        return UNSIGNED, True
    if not kinds.TARGETS[kind].decides:
        held_policy = held.policy_sha256 if held is not None and not held.empty else ""
        if replaces != held_policy:
            return UNSIGNED, True
    return None, False


# ------------------------------------------------------------------ the PEP's install part on disk

def _write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    canon.atomic_write_bytes(path, data)
    canon.fsync_dir(os.path.dirname(path))


def _get(directory: str, name: str) -> Optional[bytes]:
    try:
        with open(os.path.join(directory, name), "rb") as handle:
            data = handle.read()
    except OSError:
        return None
    return data if canon.sha256_hex(data) == name else None


@dataclass
class Staged:
    """IS4: a staged install set of one kind, the statements that have arrived, each verified, and what they share."""
    kind: str
    seq: int
    policy_sha256: str
    release: str
    replaces: str
    widens: bool
    statements: Dict[str, Tuple[str, str, str]] = field(default_factory=dict)
    envelopes: Dict[str, Any] = field(default_factory=dict)
    bodies: Dict[str, bytes] = field(default_factory=dict)

    def document(self) -> dict:
        return {"policy_sha256": self.policy_sha256, "release": self.release, "replaces": self.replaces,
                "seq": self.seq, "widens": self.widens,
                "statements": {name: {"envelope_id": one[0], "sealed": one[1], "body": one[2]}
                               for name, one in sorted(self.statements.items())}}

    def whole(self, kind: str) -> bool:
        """IS4: the set is whole when it holds what its kind needs and the release id computed over the statements is
        the signed one. The empty set is whole alone."""
        names = set(self.statements)
        if names != {kinds.NONE} and kinds.POLICY_LIST not in names:
            needed, _allowed = kinds.install_form(kind, self.kind)
            if not needed <= names:
                return False
        pairs = [(name, envelope.body_sha256) for name, envelope in self.envelopes.items()]
        return bool(pairs) and env.install_release_id(pairs) == self.release

    def held(self) -> HeldSet:
        return HeldSet(self.kind, self.seq, env.set_id(one[0] for one in self.statements.values()),
                       self.policy_sha256, self.release, self.replaces, self.widens, dict(self.statements),
                       dict(self.envelopes), dict(self.bodies))


class Installed:
    """The install part of one PEP over its `dist/` directory, the second copies at `copy` (IS10). `load` reads it as a
    start does and answers the install kinds whose set was lost. `record` is None when the PEP holds no install
    record; `record_lost` is true when it held one and no copy reads."""

    def __init__(self, dist_dir: str, copy: Optional[str] = None, *, reads_meta: bool = True):
        self.dist = dist_dir
        self.dir = os.path.join(dist_dir, "install")
        self.copy = copy or os.path.join(dist_dir, "install-copy")
        self.reads_meta = reads_meta
        self.record: Optional[Record] = None
        self.record_lost = False
        self.ceiling_lost = False
        self.staged: Dict[str, Staged] = {}
        self.marks = {"ceiling": False, "install": False}
        self.streams: FrozenSet[str] = frozenset()
        self.zones: Optional[List[str]] = None

    # ------------------------------------------------------------------ the marks of the anchor part
    def _read_marks(self) -> None:
        self.marks, self.streams, _readable = read_marks(self.dist)

    def mark(self, **marks: bool) -> None:
        """Set marks of the anchor part. A mark is never cleared (IS9)."""
        changed = {name: self.marks[name] or value for name, value in marks.items()}
        if all(self.marks[name] == changed[name] for name in changed):
            return
        self.marks.update(changed)
        self._write_marks()

    def mark_stream(self, stream: str) -> None:
        """L2: a release was committed on `stream`, so the older forms stay refused on it whatever provisioning
        follows. Set before the commit's floor is written, and never cleared."""
        if stream in self.streams:
            return
        self.streams = self.streams | {stream}
        self._write_marks()

    def _write_marks(self) -> None:
        _write(os.path.join(self.dist, "marks.json"),
               canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": MARKS_FORMAT, **self.marks,
                                   "streams": sorted(self.streams)}))

    # ------------------------------------------------------------------ load
    def _paths(self) -> Tuple[str, str]:
        return os.path.join(self.dir, "record.json"), os.path.join(self.copy, "record.json")

    def load(self) -> List[str]:
        """IS10: read the record from the first copy that reads, and each held statement from the first copy that is
        the one the record names with the signed body hash. A set none of whose copies passes is lost and left out.
        Returns the install kinds lost this start. A record no copy reads is lost when a mark says one was held."""
        self._read_marks()
        self.record, self.record_lost, self.ceiling_lost, lost = None, False, False, []
        for path in self._paths():
            try:
                with open(path, "rb") as handle:
                    self.record = Record.from_bytes(handle.read())
                break
            except (OSError, Refused):
                continue
        if self.record is None:
            self.record_lost = self.marks["install"] or any(os.path.exists(path) for path in self._paths())
            self.ceiling_lost = self.record_lost and self.marks["ceiling"]
            return []
        sets = dict(self.record.sets)
        for kind in SET_KINDS:
            held = sets[kind]
            if held is None or held.empty:
                continue                            # IS6: a kind the empty set withdrew holds nothing to read
            read = self._read_set(held)
            if read is None:
                sets[kind] = None
                lost.append(kind)
            else:
                sets[kind] = read
        self.record = replace(self.record, sets=sets)
        if CEILING in lost:
            self.ceiling_lost = True
        elif sets[CEILING] is None and self.marks["ceiling"] and self.record.seqs[CEILING] and not self._withdrawn():
            self.ceiling_lost = True
        self._read_staged()
        self._read_zones()
        return lost

    def _withdrawn(self) -> bool:
        """A ceiling the engineer withdrew with the empty set is not a lost one: the record then names the empty set."""
        held = self.record.sets[CEILING] if self.record else None
        return held is not None and held.empty

    def _read_statement(self, envelope_id: str, sealed_name: str, body_name: str):
        for directory in (os.path.join(self.dir, "blobs"), os.path.join(self.copy, "blobs")):
            sealed, body = _get(directory, sealed_name), _get(directory, body_name)
            if sealed is None or body is None:
                continue
            try:
                envelope_bytes, _entries = env.unseal(sealed)
                envelope = env.read(envelope_bytes, reads_meta=self.reads_meta)
            except Refused:
                continue
            if envelope.envelope_id == envelope_id and envelope.body_sha256 == canon.sha256_hex(body):
                return envelope, body
        return None

    def _read_set(self, held: HeldSet) -> Optional[HeldSet]:
        envelopes, bodies = {}, {}
        for name, (envelope_id, sealed_name, body_name) in held.statements.items():
            read = self._read_statement(envelope_id, sealed_name, body_name)
            if read is None:
                return None
            envelopes[name], bodies[name] = read
        return replace(held, envelopes=envelopes, bodies=bodies)

    def _read_staged(self) -> None:
        self.staged = {}
        try:
            with open(os.path.join(self.dir, "staged.json"), "rb") as handle:
                doc = kinds.load_canonical(handle.read(), "staged install sets")
        except (OSError, Refused):
            return
        if not isinstance(doc, dict) or doc.get("format") != STAGED_FORMAT or not isinstance(doc.get("sets"), dict):
            return
        for kind, one in doc["sets"].items():
            try:
                staged = Staged(kind, one["seq"], one["policy_sha256"], one["release"], one["replaces"], one["widens"])
                for name, held in one["statements"].items():
                    read = self._read_statement(held["envelope_id"], held["sealed"], held["body"])
                    if read is None:
                        raise KeyError(name)
                    staged.statements[name] = (held["envelope_id"], held["sealed"], held["body"])
                    staged.envelopes[name], staged.bodies[name] = read
            except (KeyError, TypeError):
                continue                            # a staged set that does not read is dropped, as a staged release is
            if kind in SET_KINDS:
                self.staged[kind] = staged

    # ------------------------------------------------------------------ write
    def put(self, sealed: bytes, body: bytes, *, both: bool) -> Tuple[str, str]:
        """The blobs of a statement, in the first copy and, for a held one, in the second (IS10)."""
        names = []
        for data in (bytes(sealed), bytes(body)):
            name = canon.sha256_hex(data)
            for directory in ((self.dir, self.copy) if both else (self.dir,)):
                path = os.path.join(directory, "blobs", name)
                if _get(os.path.join(directory, "blobs"), name) is None:
                    _write(path, data)
            names.append(name)
        return names[0], names[1]

    def save(self, record: Record) -> None:
        """Both copies of the record, the first then the second, each whole. Every statement it names is already in
        both copies (`put`)."""
        data = record.to_bytes()
        for path in self._paths():
            _write(path, data)
        self.record, self.record_lost = record, False
        self.keep()

    def save_staged(self) -> None:
        _write(os.path.join(self.dir, "staged.json"), canon.canon2_bytes({
            canon.ENCODING_KEY: canon.CANON2, "format": STAGED_FORMAT,
            "sets": {kind: staged.document() for kind, staged in sorted(self.staged.items())}}))
        self.keep()

    def keep(self) -> None:
        """Remove every blob neither a held nor a staged statement names."""
        keep = set()
        if self.record is not None:
            for held in self.record.sets.values():
                if held is not None:
                    keep |= {name for one in held.statements.values() for name in one[1:]}
        for staged in self.staged.values():
            keep |= {name for one in staged.statements.values() for name in one[1:]}
        for directory in (os.path.join(self.dir, "blobs"), os.path.join(self.copy, "blobs")):
            try:
                names = os.listdir(directory)
            except OSError:
                continue
            for name in names:
                if name not in keep:
                    try:
                        os.remove(os.path.join(directory, name))
                    except OSError:
                        pass

    def clear(self) -> None:
        """A provisioning that holds no install part: nothing is held, and the marks stay (IS9)."""
        for path in self._paths() + (os.path.join(self.dir, "staged.json"),):
            try:
                os.remove(path)
            except OSError:
                pass
        self.record, self.record_lost, self.ceiling_lost, self.staged = None, False, False, {}
        self.keep()

    # ------------------------------------------------------------------ FB9: the last committed zones
    def _zone_paths(self) -> Tuple[str, str]:
        return os.path.join(self.dir, "zones.json"), os.path.join(self.copy, "zones.json")

    def _read_zones(self) -> None:
        self.zones = read_zones_file(self._zone_paths())

    def keep_zones(self, names: Sequence[str]) -> None:
        """FB9: the protected names of the release just committed, kept with the install record and read at start."""
        names = sorted(set(names))
        if self.zones == names:
            return
        data = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": ZONES_FORMAT, "protected": names})
        for path in self._zone_paths():
            _write(path, data)
        self.zones = names

    # ------------------------------------------------------------------ what the PEP holds
    def held(self, kind: str) -> Optional[HeldSet]:
        """The held set of `kind`, None when none or the empty set is held."""
        if self.record is None:
            return None
        held = self.record.sets[kind]
        return None if held is None or held.empty else held

    @property
    def ceiling(self) -> Optional[HeldSet]:
        return self.held(CEILING)

    @property
    def fallback(self) -> Optional[HeldSet]:
        return self.held(FALLBACK)

    def release_of(self, held: HeldSet):
        """The set in the shape of a release (FB1), each body's path the first copy of it that reads."""
        release = held.as_release()
        for name, (_envelope_id, _sealed, body_name) in held.statements.items():
            first = os.path.join(self.dir, "blobs", body_name)
            release.paths[name] = first if _get(os.path.join(self.dir, "blobs"), body_name) is not None \
                else os.path.join(self.copy, "blobs", body_name)
        return release

    def statement_ids(self) -> List[str]:
        """The envelope ids of every install statement held (IS8)."""
        if self.record is None:
            return []
        return sorted(one for held in self.record.sets.values() if held is not None for one in held.envelope_ids)


def read_marks(dist_dir: str) -> Tuple[Dict[str, bool], FrozenSet[str], bool]:
    """The marks of the anchor part under `dist_dir`: ({ceiling, install}, the streams committed on, readable). A
    file that does not read is taken as every mark set, so a lost file never reopens anything (IS9, IS10, L2)."""
    path = os.path.join(dist_dir, "marks.json")
    try:
        with open(path, "rb") as handle:
            doc = kinds.load_canonical(handle.read(), "marks")
    except OSError:
        if os.path.exists(path):
            return {"ceiling": True, "install": True}, frozenset(), False
        return {"ceiling": False, "install": False}, frozenset(), True
    except Refused:
        return {"ceiling": True, "install": True}, frozenset(), False
    streams = doc.get("streams", []) if isinstance(doc, dict) else None
    if not (isinstance(doc, dict) and doc.get("format") == MARKS_FORMAT and isinstance(streams, list)
            and all(isinstance(one, str) for one in streams)):
        return {"ceiling": True, "install": True}, frozenset(), False
    return {"ceiling": doc.get("ceiling") is True, "install": doc.get("install") is True}, frozenset(streams), True


def older_forms_refused(dist_dir: str, stream: Optional[str]) -> bool:
    """L2, IS9: the PEP under `dist_dir` refuses the older signed forms on `stream`, the stream it follows, because it
    has held an install statement or committed a release on that stream, or because its marks do not read."""
    marks, streams, readable = read_marks(dist_dir)
    return not readable or marks["install"] or (stream is not None and stream in streams)


def read_zones_file(paths: Sequence[str]) -> Optional[List[str]]:
    for path in paths:
        try:
            with open(path, "rb") as handle:
                doc = kinds.load_canonical(handle.read(), "kept zones")
        except (OSError, Refused):
            continue
        if isinstance(doc, dict) and doc.get("format") == ZONES_FORMAT and isinstance(doc.get("protected"), list):
            return list(doc["protected"])
    return None


def protected_names(kind: str, fallback: Optional[HeldSet], ceiling: Optional[HeldSet],
                    last: Optional[Sequence[str]]) -> Optional[bytes]:
    """FB9: the `agent.zones` body an `agent` PEP decides under when no release is active: the names of the fallback
    policy's zones and of the ceiling's, and where the ceiling has no `agent.zones` the names of the last committed
    release as well. None when no name is protected."""
    if kind != "agent":
        return None
    names = set()
    for held in (fallback, ceiling):
        if held is not None and "agent.zones" in held.bodies:
            names |= set(kinds.read_zones(held.bodies["agent.zones"])["protected"])
    if ceiling is None or "agent.zones" not in ceiling.bodies:
        names |= set(last or ())
    if not names:
        return None
    return canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": kinds.ZONES_FORMAT,
                               "protected": sorted(names)})


# ------------------------------------------------------------------ the sealing tool

def seal_set(install_kind: str, bodies: Mapping[str, bytes], *, stream: str, seq: int, target: str, signers,
             policy_sha256: Optional[str] = None, replaces: str = "", widens: bool = False,
             metas: Optional[Mapping[str, Mapping[str, Any]]] = None, not_before: int = 0) -> List[Tuple[bytes, bytes]]:
    """The (sealed, body) pairs of one install set of `install_kind` for a PEP of kind `target`, signed by every key in
    `signers`. `bodies` maps each artifact `as` to its body, `{"none": b""}` for the empty set. `metas` gives the
    `meta` members of each artifact beyond `as`. The policy hash is the set's `policy.core` or the table's, the list's
    hash for a policy list, and 64 zeros for the empty set, unless given."""
    names = sorted(bodies)
    release = env.install_release_id([(name, canon.sha256_hex(bodies[name])) for name in names])
    if policy_sha256 is None:
        if names == [kinds.NONE]:
            policy_sha256 = env.ZERO_HASH
        else:
            primary = next((name for name in ("policy.core", "policy.ppt", kinds.POLICY_LIST) if name in bodies), None)
            if primary is None and "cfs.table" in bodies:
                from integrations.cfs.ground import table
                policy_sha256 = canon.sha256_hex(table.core_of(bodies["cfs.table"]))
            else:
                policy_sha256 = canon.sha256_hex(bodies[primary or names[0]])
    out = []
    for name in names:
        meta = {"as": name, **dict((metas or {}).get(name, {}))}
        envelope_bytes = env.build(install_kind, bodies[name], stream=stream, seq=seq, targets=[target],
                                   not_before=not_before, expires=0, policy_sha256=policy_sha256, release=release,
                                   replaces=replaces, widens=widens, meta=meta)
        out.append((env.seal(envelope_bytes, signers), bytes(bodies[name])))
    return out


def trust_body(keys: Sequence[bytes], *, threshold: int, operators: Sequence[bytes] = ()) -> bytes:
    """IS11: the canon/2 body of an install trust statement."""
    body = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": kinds.INSTALL_TRUST_FORMAT,
                               "keys": sorted(bytes(one).hex() for one in keys),
                               "operators": sorted(bytes(one).hex() for one in operators), "threshold": threshold})
    kinds.read_install_trust(body)
    return body


def seal_trust(record: Record, body: bytes, *, stream: str, seq: int, targets: Sequence[str], signers,
               not_before: int = 0, retired: Iterable[str] = (), widens: Optional[bool] = None) -> bytes:
    """IS11, K4: the sealed `install.trust`, written only when it can be accepted. It is signed under the install key
    set as it is now at the threshold as it is now and by every key it adds, a sealed envelope holds four
    signatures (S2), and no key it adds was ever retired in any role: `retired` is every id the engineer's tool keeps,
    which outlasts what a PEP remembers. `Refused` otherwise."""
    from prismpath.hotswap import policy_pack
    _priv, _pub, ser, _invalid = policy_pack._ed25519()
    doc = kinds.read_install_trust(body)
    added = {env.key_id(bytes.fromhex(one)) for one in doc["keys"] + doc["operators"]} - set(record.keys) - set(record.operators)
    if added & (set(retired) | set(record.retired)):
        raise Refused(ROTATION_INVALID, "the statement adds a key that was retired (K4)")
    signer_ids = {env.key_id(key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)) for key in signers}
    current = signer_ids & set(record.keys)
    if len(current) < record.threshold or not added <= signer_ids:
        need = record.threshold + len(added)
        raise Refused(UNKNOWN_KEY if len(current) < record.threshold else ROTATION_INVALID,
                      f"the statement needs {need} signatures: the threshold of current keys and every key it adds")
    if record.threshold + len(added) > env.MAX_ENTRIES:
        raise Refused("dist:too-large", f"the statement needs {record.threshold + len(added)} signatures and a sealed "
                                        f"envelope holds {env.MAX_ENTRIES} (S2); drop a key or lower the threshold first")
    if widens is None:
        widens = trust_widens(record, body)
    envelope_bytes = env.build(TRUST, body, stream=stream, seq=seq, targets=targets, not_before=not_before, expires=0,
                               policy_sha256=env.ZERO_HASH, release=env.ZERO_HASH, widens=widens)
    return env.seal(envelope_bytes, signers)


def ceiling_body(tables: Iterable[bytes]) -> bytes:
    """CL1: the policy list of the tables `tables`, by their body hash."""
    body = canon.canon2_bytes({"bodies": sorted({canon.sha256_hex(bytes(one)) for one in tables}),
                               canon.ENCODING_KEY: canon.CANON2, "format": kinds.CEILING_FORMAT})
    kinds.read_ceiling_list(body)
    return body


__all__ = ["Record", "HeldSet", "Staged", "Installed", "check_trust", "trust_widens", "read_anchor_part",
           "anchor_part", "domain_sha256", "inside", "set_larger", "widens_ok", "protected_names", "seal_set",
           "trust_body", "seal_trust", "ceiling_body", "CANNOT_DECIDE", "LARGER"]
