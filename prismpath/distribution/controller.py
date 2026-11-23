# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The reference controller of policy distribution (spec-policy-distribution.md, section 15.3), with no
network of its own. The HTTP binding (`http.py`) and the frame driver below carry its messages.

A controller holds no authority private key (F1). It stores sealed envelopes and their bodies only after the
one verifier passed them for every target kind and stream it serves that the envelope names, reading `meta`
in full (E1, E11), and it refuses a revocation list that drops an entry no floor has passed (R8). It keeps,
per PEP, the enrolled instance key, the kind, the stream, the group, the expected policy and `seq`, the last
accepted record and the open findings (F2). Per group and release it runs the machine of F3 under the rule
`each` or `all`. It checks each state record in the order of H6 and files the first finding, files a PEP
silent after three intervals (H7) and held while its records carry the hold bit (H8), and names the present
with a rising epoch id (H9). Every offer, ack, commit, abort, finding and trust statement goes to its own
audit log, signed with the controller's instance key (F5).

Its directory:

    controller.json  members, groups, rollouts, the trust chain, the epoch, as JSON written whole
    anchors/         each trust anchor it serves, under its fingerprint, with a host stream's qualification
    blobs/           sealed envelopes under `<envelope id>.sealed`, bodies under their SHA-256
    audit.log        the controller's audit log
    lock             held while a command or a request reads or changes the state

H6 steps 4 and 5 read the Facet body of a record. Every PEP of this version sends an empty body (H5 names
the grouped spiral profile, which the heartbeat body PR adds), so a record with a body is held to the hash
steps only and the decode joins with that body.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import struct
import time as _time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from prismpath import canon
from prismpath.distribution import envelope as env
from prismpath.distribution import frames, kinds, state_record
from prismpath.distribution.kinds import Refused
from prismpath.distribution.trust import TrustStore, check_drops, read_anchor
from prismpath.distribution.verify import PepView, verify
from prismpath.ledgers.audit_log import AuditLog

FORMAT = "prismpath.dist-controller/1"
EACH, ALL = "each", "all"
OFFERED, STAGING, COMMITTING, COMMITTED, ABORTED, PARTIAL = (
    "offered", "staging", "committing", "committed", "aborted", "partial")
INTERVAL = 30.0                                    # B3, H4: seconds between a host's beats
STAGE_WINDOW = 120.0                               # F3, and 500 milliseconds on the mesh
MESH_STAGE_WINDOW = 0.5
COMMIT_WINDOW = 120.0
SILENT_AFTER = 3                                   # H7: intervals with no accepted record
STATE_INVALID, STATE_REPLAY, POLICY_MISMATCH, SILENT, HELD = (
    "fleet:state-invalid", "fleet:state-replay", "fleet:policy-mismatch", "fleet:silent", "dist:held")
EAT = 1                                            # H10: the extension type of an Entity Attestation Token
_ZERO = "0" * 32


def _hex(raw: bytes) -> str:
    return bytes(raw).hex()


def _prefix(hex64: Optional[str]) -> str:
    return hex64[:32] if hex64 else _ZERO


# ------------------------------------------------------------------ H10: the extensions

class _Cbor:
    """Just enough CBOR (RFC 8949) to find `eat_nonce` (claim 10) in an EAT: unsigned (UCCS, tag 601), inside a
    COSE_Sign1 (tag 18) or a CWT (tag 61), or a bare claims map. Definite lengths only, as COSE requires."""

    def __init__(self, data: bytes):
        self.data, self.at = data, 0

    def _take(self, size: int) -> bytes:
        if self.at + size > len(self.data):
            raise ValueError("cut short")
        out = self.data[self.at:self.at + size]
        self.at += size
        return out

    def _argument(self, info: int) -> int:
        if info < 24:
            return info
        if info in (24, 25, 26, 27):
            return int.from_bytes(self._take(1 << (info - 24)), "big")
        raise ValueError("an indefinite or reserved length")

    def item(self, depth: int = 0) -> Any:
        if depth > 16:
            raise ValueError("nested too deep")
        head = self._take(1)[0]
        major, info = head >> 5, head & 0x1F
        if major == 7:
            if info in (20, 21, 22):
                return {20: False, 21: True, 22: None}[info]
            raise ValueError("a float or simple value")
        value = self._argument(info)
        if major == 0:
            return value
        if major == 1:
            return -1 - value
        if major in (2, 3):
            raw = self._take(value)
            return raw if major == 2 else raw.decode("utf-8")
        if major == 4:
            return [self.item(depth + 1) for _ in range(value)]
        if major == 5:
            out = {}
            for _ in range(value):
                key = self.item(depth + 1)
                out[key if not isinstance(key, list) else tuple(key)] = self.item(depth + 1)
            return out
        return ("tag", value, self.item(depth + 1))

    def whole(self) -> Any:
        value = self.item()
        if self.at != len(self.data):
            raise ValueError("bytes after the item")
        return value


def eat_nonces(token: bytes) -> List[bytes]:
    """The `eat_nonce` values of an EAT, or `ValueError` when it does not read as one."""
    value = _Cbor(bytes(token)).whole()
    while isinstance(value, tuple) and value[0] == "tag":
        if value[1] in (18, 61) and isinstance(value[2], list) and len(value[2]) == 4:
            payload = value[2][2]
            if not isinstance(payload, bytes):
                raise ValueError("a COSE_Sign1 with no payload")
            value = _Cbor(payload).whole()
        elif value[1] in (18, 61, 601):
            value = value[2]
        else:
            raise ValueError(f"tag {value[1]} is not an EAT")
    if not isinstance(value, dict) or 10 not in value:
        raise ValueError("no eat_nonce")
    nonce = value[10]
    nonces = nonce if isinstance(nonce, list) else [nonce]
    if not nonces or not all(isinstance(one, bytes) for one in nonces):
        raise ValueError("an eat_nonce that is not a byte string")
    return nonces


def check_extensions(record: state_record.StateRecord, unsigned: bytes) -> None:
    """H10: the extensions are a run of type, two byte length and bytes. A type 1 token is read and its
    `eat_nonce` must be the SHA-256 of bytes 0 to 146+m of the record; another type is skipped. No extension
    is ever taken for a signature on the record. `Refused` with `fleet:state-invalid` otherwise."""
    run, at = record.extensions, 0
    bound = hashlib.sha256(unsigned[:state_record._HEAD.size + 2 + len(record.body)]).digest()
    while at < len(run):
        if at + 3 > len(run):
            raise Refused(STATE_INVALID, "an extension entry cut short")
        kind, size = run[at], struct.unpack_from("<H", run, at + 1)[0]
        value = run[at + 3:at + 3 + size]
        if len(value) != size:
            raise Refused(STATE_INVALID, "an extension longer than the area")
        at += 3 + size
        if kind != EAT:
            continue
        try:
            nonces = eat_nonces(value)
        except (ValueError, UnicodeDecodeError) as error:
            raise Refused(STATE_INVALID, f"an attestation token that does not read ({error})") from None
        if bound not in nonces:
            raise Refused(STATE_INVALID, "an attestation token bound to another record")


# ------------------------------------------------------------------ the state

@dataclass
class Member:
    """F2: one enrolled PEP. `expected` is (policy hash, release id, seq), all hex but the seq."""
    pep: str
    public: str
    kind: str
    stream: str
    group: str
    expected: Tuple[str, str, int] = ("", "", 0)
    counter: int = 0
    last: Optional[dict] = None
    seen: float = 0.0
    findings: Dict[str, str] = field(default_factory=dict)

    def document(self) -> dict:
        return {"pep": self.pep, "public": self.public, "kind": self.kind, "stream": self.stream, "group": self.group,
                "expected": list(self.expected), "counter": self.counter, "last": self.last, "seen": self.seen,
                "findings": dict(self.findings)}

    @classmethod
    def from_document(cls, doc: dict) -> "Member":
        return cls(pep=doc["pep"], public=doc["public"], kind=doc["kind"], stream=doc["stream"], group=doc["group"],
                   expected=tuple(doc["expected"]), counter=doc["counter"], last=doc["last"], seen=doc["seen"],
                   findings=dict(doc["findings"]))


@dataclass
class Rollout:
    """F3: one release to one group. `members` maps a PEP id to offered, staged, refused, committed or aborted."""
    group: str
    rule: str
    stream: str
    seq: int
    policy: str
    release: str
    envelopes: List[str]
    state: str
    started: float
    members: Dict[str, str]
    previous: Dict[str, List] = field(default_factory=dict)
    committing_since: float = 0.0
    delay_ms: int = 0

    def document(self) -> dict:
        return {"group": self.group, "rule": self.rule, "stream": self.stream, "seq": self.seq, "policy": self.policy,
                "release": self.release, "envelopes": list(self.envelopes), "state": self.state,
                "started": self.started, "members": dict(self.members), "previous": dict(self.previous),
                "committing_since": self.committing_since, "delay_ms": self.delay_ms}

    @classmethod
    def from_document(cls, doc: dict) -> "Rollout":
        return cls(**{**doc, "envelopes": list(doc["envelopes"]), "members": dict(doc["members"]),
                      "previous": dict(doc["previous"])})

    @property
    def open(self) -> bool:
        return self.state in (OFFERED, STAGING, COMMITTING, PARTIAL)


class Controller:
    """The controller over `directory`. `instance_key` signs its audit log and is never an authority key
    (F1, K2). `clock` answers Unix seconds and drives the windows and the epoch, so every process that opens the
    directory agrees on them."""

    def __init__(self, directory: str, instance_key, *, clock: Callable[[], float] = _time.time,
                 interval: float = INTERVAL, stage_window: Optional[float] = None,
                 commit_window: float = COMMIT_WINDOW):
        if instance_key is None:
            raise ValueError("a controller needs its own instance key to sign its audit log (F5)")
        self.dir, self.instance_key, self.clock = directory, instance_key, clock
        self.interval, self.stage_window, self.commit_window = interval, stage_window, commit_window
        for name in ("anchors", "blobs"):
            os.makedirs(os.path.join(directory, name), exist_ok=True)
        self.audit = AuditLog(os.path.join(directory, "audit.log"), instance_key=instance_key, sign_appends=True)
        self._loaded_at: Optional[float] = None
        self._load()

    # ------------------------------------------------------------------ the durable state
    @property
    def _state_path(self) -> str:
        return os.path.join(self.dir, "controller.json")

    def _load(self) -> None:
        self.members: Dict[str, Member] = {}
        self.groups: Dict[str, str] = {}
        self.rollouts: List[Rollout] = []
        self.chain: List[str] = []                   # the trust statements stored, by envelope id, in trust order
        self.stored: Dict[str, dict] = {}            # envelope id -> {artifact, stream, seq, policy, release, ...}
        self.unknown: List[dict] = []                # findings for records that name no enrolled PEP
        self.epoch, self.epoch_at = 1, self.clock()
        self.anchors: Dict[str, dict] = {}           # fingerprint -> {target, stream, qualification}
        if not os.path.exists(self._state_path):
            return
        with open(self._state_path, "rb") as handle:
            doc = json.loads(handle.read().decode("utf-8"))
        if not isinstance(doc, dict) or doc.get("format") != FORMAT:
            raise Refused(kinds.BAD_FORMAT, "controller.json is not a controller's state")
        self.members = {pep: Member.from_document(one) for pep, one in doc["members"].items()}
        self.groups = dict(doc["groups"])
        self.rollouts = [Rollout.from_document(one) for one in doc["rollouts"]]
        self.chain, self.stored, self.unknown = list(doc["chain"]), dict(doc["stored"]), list(doc["unknown"])
        self.epoch, self.epoch_at, self.anchors = doc["epoch"], doc["epoch_at"], dict(doc["anchors"])
        self._loaded_at = os.stat(self._state_path).st_mtime_ns

    def save(self) -> None:
        doc = {"format": FORMAT,
               "members": {pep: member.document() for pep, member in self.members.items()},
               "groups": self.groups, "rollouts": [one.document() for one in self.rollouts], "chain": self.chain,
               "stored": self.stored, "unknown": self.unknown[-64:], "epoch": self.epoch, "epoch_at": self.epoch_at,
               "anchors": self.anchors}
        canon.atomic_write_bytes(self._state_path, json.dumps(_plain(doc), sort_keys=True).encode("utf-8"))
        canon.fsync_dir(self.dir)
        self._loaded_at = os.stat(self._state_path).st_mtime_ns

    def refresh(self) -> None:
        """Read the state again when another process (a command) changed it since this one last did."""
        if os.path.exists(self._state_path) and os.stat(self._state_path).st_mtime_ns != self._loaded_at:
            self._load()

    @contextmanager
    def locked(self) -> Iterator["Controller"]:
        """Hold the directory's lock, with the state as the last writer left it, and save it after."""
        with open(os.path.join(self.dir, "lock"), "a+b") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                self.refresh()
                yield self
                self.save()
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def _log(self, action: str, **data) -> None:
        self.audit.append("controller", action, _plain(data))

    # ------------------------------------------------------------------ anchors and trust
    def add_anchor(self, raw: bytes, qualification: Optional[dict] = None) -> str:
        """Serve the stream of a trust anchor (P2): the controller verifies what it stores for that kind and
        stream under the anchor's keys and the trust statements stored since. A `host` stream needs the
        qualification envelope its PEPs admit images under (V11)."""
        anchor = read_anchor(raw)
        if anchor.target == "host" and qualification is None:
            raise ValueError("a host stream needs the qualification envelope its PEPs hold")
        with open(os.path.join(self.dir, "anchors", anchor.fingerprint), "wb") as handle:
            handle.write(bytes(raw))
        self.anchors[anchor.fingerprint] = {"target": anchor.target, "stream": anchor.stream,
                                            "qualification": qualification}
        self._log("anchor", fingerprint=anchor.fingerprint, target=anchor.target, stream=anchor.stream)
        return anchor.fingerprint

    def _anchor_store(self, fingerprint: str) -> TrustStore:
        """The trust store an anchor's PEPs hold after every trust statement stored, in order."""
        with open(os.path.join(self.dir, "anchors", fingerprint), "rb") as handle:
            store = read_anchor(handle.read()).store()
        target = self.anchors[fingerprint]["target"]
        for envelope_id in self.chain:
            sealed, body = self.sealed(envelope_id), self.blob(self.stored[envelope_id]["body_sha256"])
            if target not in self.stored[envelope_id]["targets"]:
                continue
            envelope = env.read(env.unseal(sealed)[0])
            store = (store.apply_revocation(envelope, body) if envelope.artifact == "trust.revocation"
                     else store.apply_rotation(envelope, body))
        return store

    def _view(self, fingerprint: str) -> PepView:
        anchor = self.anchors[fingerprint]
        return PepView(kind=anchor["target"], stream=anchor["stream"], qualification=anchor["qualification"])

    def trust_seq(self) -> int:
        return len(self.chain)

    # ------------------------------------------------------------------ F1: store
    def put(self, sealed: bytes, body: bytes) -> env.Envelope:
        """F1: verify `sealed` and `body` for every kind and stream the controller serves that the envelope names,
        reading `meta` in full, and store them. A trust statement is the next one of the trust chain (R1) and a
        revocation list drops nothing no floor has passed (R8). `Refused` with the first cause, and nothing
        is stored or offered."""
        sealed, body = bytes(sealed), bytes(body)
        try:
            envelope = env.read(env.unseal(sealed)[0], reads_meta=True)          # F1: E1 and E11 whatever the kind
            checked = 0
            for fingerprint, anchor in sorted(self.anchors.items()):
                if anchor["target"] not in envelope.targets:
                    continue
                if not envelope.is_trust and anchor["stream"] != envelope.stream:
                    continue
                verdict = verify(sealed, body, trust=self._anchor_store(fingerprint), pep=self._view(fingerprint),
                                 now=int(self.clock()), reads_meta=True)
                if not verdict.ok:
                    raise Refused(verdict.cause, f"for the {anchor['target']} stream {anchor['stream']}")
                if verdict.unchanged:
                    raise Refused("dist:trust-replay" if envelope.is_trust else "dist:seq-replay", "already stored")
                checked += 1
            if not checked:
                raise Refused("dist:target-mismatch", "the controller serves no kind and stream this envelope names")
            if envelope.artifact == "trust.revocation":
                earlier = [self.blob(self.stored[one]["body_sha256"]) for one in self.chain
                           if self.stored[one]["artifact"] == "trust.revocation"]
                check_drops(body, earlier, self.held_envelopes())
        except Refused as refused:
            self._log("refused", cause=refused.cause, detail=str(refused), result="refused")
            raise
        envelope_id = envelope.envelope_id
        self._write_blob(f"{envelope_id}.sealed", sealed)
        self._write_blob(envelope.body_sha256, body)
        self.stored[envelope_id] = {"artifact": envelope.artifact, "stream": envelope.stream, "seq": envelope.seq,
                                    "policy": envelope.policy_sha256, "release": envelope.release,
                                    "targets": list(envelope.targets), "body_sha256": envelope.body_sha256,
                                    "sealed_size": len(sealed), "body_size": len(body)}
        if envelope.is_trust:
            self.chain.append(envelope_id)
            self._log("trust", envelope_id=envelope_id, artifact=envelope.artifact, seq=envelope.seq, result="stored")
        else:
            self._log("stored", envelope_id=envelope_id, artifact=envelope.artifact, stream=envelope.stream,
                      seq=envelope.seq, result="stored")
        return envelope

    def _write_blob(self, name: str, data: bytes) -> None:
        canon.atomic_write_bytes(os.path.join(self.dir, "blobs", name), data)

    def blob(self, name: str) -> Optional[bytes]:
        """B3: a body by its SHA-256, or a sealed envelope by its envelope id. None when it is not held."""
        if not kinds.is_hex64(name):
            return None
        if name in self.stored:
            return self.sealed(name)
        try:
            with open(os.path.join(self.dir, "blobs", name), "rb") as handle:
                data = handle.read()
        except OSError:
            return None
        return data if canon.sha256_hex(data) == name else None

    def sealed(self, envelope_id: str) -> Optional[bytes]:
        try:
            with open(os.path.join(self.dir, "blobs", f"{envelope_id}.sealed"), "rb") as handle:
                data = handle.read()
        except OSError:
            return None
        return data if env.envelope_id(env.unseal(data)[0]) == envelope_id else None

    def held_envelopes(self) -> List[env.Envelope]:
        """Every envelope stored, read, for R8."""
        return [env.read(env.unseal(self.sealed(one))[0]) for one in self.stored]

    # ------------------------------------------------------------------ F2: enrolment and groups
    def enroll(self, instance_public: bytes, kind: str, stream: str, group: str = "default", rule: str = EACH) -> str:
        """F2: enrol a PEP by its instance public key into `group`. Its kind and stream must be ones an anchor
        serves, and the key is never one of the anchor's (K2). Enrolling a PEP again moves it to `group` and
        keeps what the controller knows of it."""
        if not any(anchor["target"] == kind and anchor["stream"] == stream for anchor in self.anchors.values()):
            raise ValueError(f"no anchor is served for the {kind} stream {stream}")
        key_id = canon.sha256_hex(bytes(instance_public))
        for fingerprint in self.anchors:
            if key_id in self._anchor_store(fingerprint).keys:
                raise ValueError("an instance key is never a trusted authority key (K2)")
        if rule not in (EACH, ALL):
            raise ValueError("a group's rule is each or all")
        pep = _hex(state_record.pep_id(bytes(instance_public)))
        if self.groups.get(group, rule) != rule:
            raise ValueError(f"the group {group} runs under {self.groups[group]}")
        self.groups[group] = rule
        known = self.members.get(pep)
        if known is not None and (known.kind, known.stream) == (kind, stream):
            known.group = group                       # moved to another group, with its counter and expectation
        else:
            self.members[pep] = Member(pep=pep, public=_hex(instance_public), kind=kind, stream=stream, group=group,
                                       seen=self.clock())
        self._log("enrolled", pep=pep, kind=kind, stream=stream, group=group)
        return pep

    # ------------------------------------------------------------------ F3: rollouts
    def offer(self, group: str, stream: str, seq: int, delay_ms: int = 0) -> Rollout:
        """F3: offer the stored release at `stream` and `seq` to every member of `group`. A rollout still open
        for the group ends as aborted first."""
        members = sorted(pep for pep, member in self.members.items() if member.group == group and member.stream == stream)
        if not members:
            raise ValueError(f"the group {group} has no member on {stream}")
        ids = sorted(one for one, info in self.stored.items()
                     if info["stream"] == stream and info["seq"] == seq and not info["artifact"].startswith("trust.r"))
        if not ids:
            raise ValueError(f"no release is stored at {stream} seq {seq}")
        releases = {(self.stored[one]["policy"], self.stored[one]["release"]) for one in ids}
        if len(releases) != 1:
            raise ValueError(f"the envelopes stored at {stream} seq {seq} name more than one release")
        for rollout in self.rollouts:
            if rollout.group == group and rollout.open:
                self._end(rollout, ABORTED)
        policy, release = releases.pop()
        rollout = Rollout(group=group, rule=self.groups[group], stream=stream, seq=seq, policy=policy, release=release,
                          envelopes=ids, state=OFFERED, started=self.clock(), members={pep: OFFERED for pep in members},
                          previous={pep: list(self.members[pep].expected) for pep in members}, delay_ms=delay_ms)
        self.rollouts.append(rollout)
        for pep in members:
            self._log("offered", pep=pep, group=group, stream=stream, seq=seq, envelopes=ids)
        return rollout

    def commit(self, group: str) -> Rollout:
        """The operator's commit: send `commit` to every member of the group's open rollout that staged."""
        rollout = self._open(group)
        for pep, state in rollout.members.items():
            if state == "staged":
                self._send_commit(rollout, pep)
        self._advance(rollout)
        return rollout

    def abort(self, group: str) -> Rollout:
        """The operator's abort: the group's open rollout ends as aborted, and its staged members are sent `abort`."""
        rollout = self._open(group)
        self._end(rollout, ABORTED)
        return rollout

    def _open(self, group: str) -> Rollout:
        for rollout in reversed(self.rollouts):
            if rollout.group == group and rollout.open:
                return rollout
        raise ValueError(f"the group {group} has no open rollout")

    def _window(self, rollout: Rollout) -> float:
        if self.stage_window is not None:
            return self.stage_window
        kinds_of = {self.members[pep].kind for pep in rollout.members if pep in self.members}
        return MESH_STAGE_WINDOW if kinds_of == {"mesh"} else STAGE_WINDOW

    def _send_commit(self, rollout: Rollout, pep: str) -> None:
        rollout.members[pep] = "committing"
        self.members[pep].expected = (rollout.policy, rollout.release, rollout.seq)
        self._log("commit", pep=pep, group=rollout.group, stream=rollout.stream, seq=rollout.seq,
                  policy=rollout.policy, delay_ms=rollout.delay_ms)

    def _end(self, rollout: Rollout, state: str) -> None:
        rollout.state = state
        if state == ABORTED:
            for pep, member_state in rollout.members.items():
                if member_state in ("staged", "committing", OFFERED):
                    if member_state == "committing":
                        self.members[pep].expected = tuple(rollout.previous.get(pep, ("", "", 0)))
                    rollout.members[pep] = "aborting"
                    self._log("abort", pep=pep, group=rollout.group, stream=rollout.stream, seq=rollout.seq,
                              policy=rollout.policy)
        self._log("rollout", group=rollout.group, stream=rollout.stream, seq=rollout.seq, state=state)

    def _advance(self, rollout: Rollout) -> None:
        """F3's transitions that the members' acks and the windows decide. Under `each` a member is sent `commit`
        as soon as it staged, and the group leaves staging when every member answered or the stage window ended.
        Under `all` the group commits only when every member staged, and a refusal or the end of the window
        aborts it."""
        if not rollout.open:
            return
        states, now = rollout.members, self.clock()
        if rollout.state == OFFERED and any(state != OFFERED for state in states.values()):
            rollout.state = STAGING
        if rollout.state in (OFFERED, STAGING):
            waited = now - rollout.started >= self._window(rollout)
            if rollout.rule == ALL:
                if "refused" in states.values() or (waited and OFFERED in states.values()):
                    self._end(rollout, ABORTED)
                    return
                if not all(state == "staged" for state in states.values()):
                    return
            else:
                self._commit_staged(rollout)
                if OFFERED in states.values() and not waited:
                    return
                if not any(state in ("committing", "committed") for state in states.values()):
                    self._end(rollout, ABORTED)
                    return
            self._commit_staged(rollout)
            rollout.state, rollout.committing_since = COMMITTING, now
        if rollout.rule == EACH:
            self._commit_staged(rollout)                                  # a member that staged late
        if "committing" not in states.values():
            self._end(rollout, COMMITTED)
        elif rollout.state == COMMITTING and now - rollout.committing_since >= self.commit_window:
            self._end(rollout, PARTIAL)

    def _commit_staged(self, rollout: Rollout) -> None:
        for pep, state in list(rollout.members.items()):
            if state == "staged":
                self._send_commit(rollout, pep)

    def tick(self) -> None:
        """The windows of F3, the silence of H7 and the epoch of H9, at the controller's clock."""
        now = self.clock()
        while now - self.epoch_at >= self.interval:
            self.epoch, self.epoch_at = self.epoch + 1, self.epoch_at + self.interval
        for rollout in self.rollouts:
            self._advance(rollout)
        for member in self.members.values():
            if now - member.seen >= SILENT_AFTER * self.interval and SILENT not in member.findings:
                self._file(member, SILENT, f"no accepted record for {SILENT_AFTER} intervals")

    # ------------------------------------------------------------------ what a PEP is sent
    def answer(self, pep: str) -> dict:
        """B3: the `offers` answer for `pep`. The trust statements it lacks come first and in order (R1), then the
        envelopes of its group's open rollout for its kind, then its `commit` and `abort` entries. An unknown
        PEP is given the epoch and nothing else."""
        self.tick()
        out: dict = {"epoch": self.epoch, "offers": [], "commit": [], "abort": []}
        member = self.members.get(pep)
        if member is None:
            return out
        held = member.last["trust_seq"] if member.last else 0
        for envelope_id in self.chain[held:]:
            if member.kind in self.stored[envelope_id]["targets"]:
                out["offers"].append(self._offer(envelope_id))
        for rollout in self.rollouts:
            state = rollout.members.get(pep)
            if rollout.stream != member.stream or state is None:
                continue
            entry = {"stream": rollout.stream, "seq": rollout.seq, "policy": rollout.policy}
            if state == OFFERED and rollout.open:
                out["offers"] += [self._offer(one) for one in rollout.envelopes
                                  if member.kind in self.stored[one]["targets"]]
            elif state == "committing":
                out["commit"].append({**entry, "delay": rollout.delay_ms})
            elif state == "aborting":
                out["abort"].append(entry)
        return out

    def _offer(self, envelope_id: str) -> dict:
        info = self.stored[envelope_id]
        return {"envelope_id": envelope_id, "stream": info["stream"], "seq": info["seq"], "artifact": info["artifact"],
                "sealed_size": info["sealed_size"], "body_size": info["body_size"]}

    # ------------------------------------------------------------------ H6 to H10: state records
    def receive(self, data: bytes) -> Optional[str]:
        """H6: check one state record in order and file the first finding, or None when it is accepted. An
        accepted record clears the findings it answers and moves the rollouts its PEP is in."""
        data = bytes(data)
        try:
            pep = _hex(state_record.named_pep(data))
        except Refused as refused:
            return self._file_unknown("", str(refused))
        member = self.members.get(pep)
        if member is None:                                                # F2: not enrolled
            return self._file_unknown(pep, "a record from a PEP that is not enrolled")
        try:                                                             # step 1, H2, H8, H10
            record = state_record.read(data, bytes.fromhex(member.public))
            if record.held and not kinds.TARGETS[member.kind].expiry_hold:
                raise Refused(STATE_INVALID, f"the hold bit from a {member.kind} PEP, which has no HOLD setting")
            check_extensions(record, data[:-state_record.SIGNATURE_SIZE])
        except Refused as refused:
            return self._file(member, STATE_INVALID, str(refused))
        self.tick()
        if record.counter <= member.counter:                              # step 2, H3
            return self._file(member, STATE_REPLAY, f"counter {record.counter} is not above {member.counter}")
        if record.epoch not in (self.epoch, self.epoch - 1):              # H9
            return self._file(member, STATE_REPLAY, f"epoch {record.epoch} is not {self.epoch} or the one before")
        member.counter, member.seen = record.counter, self.clock()
        member.last = {"event": record.event, "state": record.state, "cause": record.cause, "counter": record.counter,
                       "time": record.time, "epoch": record.epoch, "policy": _hex(record.active_policy),
                       "release": _hex(record.active_release), "seq": record.active_seq, "floor": record.floor,
                       "staged_release": _hex(record.staged_release), "staged_seq": record.staged_seq,
                       "trust_seq": record.trust_seq, "held": record.held, "dev_build": record.dev_build}
        self._log("ack", pep=pep, event=record.event, cause=record.cause, counter=record.counter, seq=record.active_seq)
        for cleared in (STATE_INVALID, STATE_REPLAY, SILENT):
            self._clear(member, cleared)
        if record.held:                                                   # H8
            self._file(member, HELD, "deciding under an expired release on hold")
        else:
            self._clear(member, HELD)
        self._progress(member, record)
        reported = (_hex(record.active_policy), _hex(record.active_release), record.active_seq)
        if reported in self._allowed(member):                             # step 3
            self._clear(member, POLICY_MISMATCH)
            return None
        return self._file(member, POLICY_MISMATCH, f"reports seq {record.active_seq} policy {reported[0]}, "
                                                   f"expected seq {member.expected[2]} policy {_prefix(member.expected[0])}")

    def _allowed(self, member: Member) -> List[Tuple[str, str, int]]:
        """Step 3: the expected policy, release and `seq`, as prefixes. While the member's rollout is committing,
        the release it replaces is also what it may report, so a swap in flight is no finding (F4)."""
        allowed = [(_prefix(member.expected[0]), _prefix(member.expected[1]), member.expected[2])]
        for rollout in self.rollouts:
            if rollout.open and rollout.members.get(member.pep) in ("committing", "staged", OFFERED, "aborting"):
                previous = rollout.previous.get(member.pep, ("", "", 0))
                allowed.append((_prefix(previous[0]), _prefix(previous[1]), previous[2]))
        return allowed

    def _progress(self, member: Member, record: state_record.StateRecord) -> None:
        """F3: what one accepted record says of the rollouts its PEP is in."""
        for rollout in self.rollouts:
            state = rollout.members.get(member.pep)
            if state is None or not (rollout.open or state == "aborting"):
                continue
            release = bytes.fromhex(_prefix(rollout.release))
            if state == OFFERED:
                if record.event == "staged" and record.staged_release == release:
                    rollout.members[member.pep] = "staged"
                elif record.event == "refused" and record.cause:
                    rollout.members[member.pep] = "refused"
                    self._file(member, record.cause, f"refused seq {rollout.seq} of {rollout.stream}")
            elif state == "committing" and record.active_release == release and record.active_seq == rollout.seq:
                rollout.members[member.pep] = "committed"
                for cause in [code for code in member.findings if not code.startswith("fleet:") and code != HELD]:
                    self._clear(member, cause)
            elif state == "aborting" and not (record.staged and record.staged_release == release):
                rollout.members[member.pep] = "aborted"
            self._advance(rollout)

    def _file(self, member: Member, code: str, detail: str) -> str:
        if member.findings.get(code) != detail:
            member.findings[code] = detail
            self._log("finding", pep=member.pep, finding=code, detail=detail)
        return code

    def _clear(self, member: Member, code: str) -> None:
        if code in member.findings:
            del member.findings[code]
            self._log("cleared", pep=member.pep, finding=code)

    def _file_unknown(self, pep: str, detail: str) -> str:
        self.unknown.append({"pep": pep, "finding": STATE_INVALID, "detail": detail, "at": self.clock()})
        self._log("finding", pep=pep, finding=STATE_INVALID, detail=detail)
        return STATE_INVALID

    # ------------------------------------------------------------------ F4: the fleet view
    def fleet(self) -> dict:
        """F4: per PEP the expected and the reported policy and `seq` and the open findings, and every rollout.
        A PEP's entry follows the field names of OPA's status API where they fit: `labels.id`, and per stream
        `active_revision`, `last_successful_activation` and `errors`."""
        self.tick()
        peps = []
        for pep, member in sorted(self.members.items()):
            last = member.last or {}
            revision = f"{last['seq']}:{last['policy']}" if last else None
            peps.append({"labels": {"id": pep, "kind": member.kind, "group": member.group},
                         "bundles": {member.stream: {
                             "name": member.stream, "active_revision": revision,
                             "expected_revision": f"{member.expected[2]}:{_prefix(member.expected[0])}",
                             "last_successful_activation": last.get("time") if last.get("event") == "committed" else None,
                             "errors": [{"code": code, "message": detail}
                                        for code, detail in sorted(member.findings.items())]}},
                         "expected": {"policy": member.expected[0], "release": member.expected[1],
                                      "seq": member.expected[2]},
                         "reported": {key: last.get(key) for key in ("policy", "release", "seq", "floor", "trust_seq",
                                                                     "state", "event", "counter", "epoch")},
                         "findings": dict(sorted(member.findings.items()))})
        return {"epoch": self.epoch, "trust_seq": self.trust_seq(), "peps": peps,
                "rollouts": [one.document() for one in self.rollouts], "unknown": list(self.unknown)}


class FrameDriver:
    """The controller's side of the frame binding (section 8.3) for one group on a broadcast medium, where one
    send reaches every member. `send` is what the group is owed now: the epoch (H9), each envelope a member
    lacks once, as an offer and its chunks in offset order (so an ordered link takes it, B11), then the
    commits, with the rollout's delay (B8), and the aborts. `receive` hands a state frame to the controller."""

    def __init__(self, controller: Controller, group: str, limit: int = frames.ESPNOW_LIMIT):
        self.controller, self.group, self.limit = controller, group, limit
        self.transfer = 0

    def _next(self) -> int:
        self.transfer = (self.transfer + 1) & 0xFFFF
        return self.transfer

    def send(self) -> List[bytes]:
        controller = self.controller
        owed: List[str] = []
        commits: List[tuple] = []
        aborts: List[tuple] = []
        for pep, member in sorted(controller.members.items()):
            if member.group != self.group:
                continue
            answer = controller.answer(pep)
            owed += [offer["envelope_id"] for offer in answer["offers"] if offer["envelope_id"] not in owed]
            commits += [one for one in ((entry["stream"], entry["seq"], entry["policy"], entry["delay"])
                                        for entry in answer["commit"]) if one not in commits]
            aborts += [one for one in ((entry["stream"], entry["seq"], entry["policy"])
                                       for entry in answer["abort"]) if one not in aborts]
        out = [frames.encode(frames.Epoch(self._next(), controller.epoch), self.limit)]
        for envelope_id in owed:
            body = controller.blob(controller.stored[envelope_id]["body_sha256"])
            out += list(frames.frames_for(self._next(), controller.sealed(envelope_id), body, self.limit))
        out += [frames.encode(frames.commit_for(self._next(), *one), self.limit) for one in commits]
        out += [frames.encode(frames.abort_for(self._next(), *one), self.limit) for one in aborts]
        return out

    def receive(self, data: bytes) -> Optional[str]:
        """A state frame's record checked as any other (H6). Any other frame from a member is not the
        controller's to act on, and a frame that does not read is dropped."""
        try:
            frame = frames.decode(bytes(data), self.limit)
        except Refused:
            return None
        if isinstance(frame, frames.State):
            return self.controller.receive(frame.record)
        return None


def _plain(value: Any) -> Any:
    """A document JSON writes with tuples as lists."""
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value
