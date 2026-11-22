# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The enforcement point machine of policy distribution (spec-policy-distribution.md, section 9), one per
stream, the same for every Python target. What a target does with a committed release is its adapter's
(`prismpath.distribution.adapters`). The machine verifies, keeps the floor, the time floor and the trust
store, stages, commits, aborts, rolls back, lapses at expiry or holds, and signs a state record for every
transition.

Its durable store is `<state>/dist/`, each file canon/2 and written whole (the old one or the new one):

    anchor.json    the confirmed trust anchor (P2), which names the target kind and the stream
    anchor.pending an anchor the operator has not confirmed yet (P2 step 4)
    trust.json     the trust store (K1)
    floor.json     the floor (Q1)
    counter.json   the state record counter (H3)
    staged.json    the staged release
    pending.json   the intent record of a commit or a rollback
    active.json    the active release and the one it replaced (RB1)
    blobs/         sealed envelopes and bodies under their SHA-256
    audit.log      the audit log, signed by the instance key

A commit is durable in the order of C4: the intent, the floor, the audit event, the artifacts under content
addressed names (staging already wrote them, each synced), the active record, the runtime switch, the clean
up. A restart reads only what the active record names, and finishes or reports an interrupted commit.

A store that cannot be read is answered by failing closed: an unreadable trust store refuses every envelope
and decides nothing (K1, X3), and an unreadable floor, counter or anchor locks the PEP (Q5) until it is
provisioned again (P3).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, FrozenSet, Iterable, Mapping, Optional, Tuple

from prismpath import canon
from prismpath.distribution import devbuild, kinds, state_record
from prismpath.distribution import envelope as env
from prismpath.distribution.kinds import Refused
from prismpath.distribution.trust import TrustStore, read_anchor
from prismpath.distribution.verify import SKEW, Floor, PepView, Staged, verify
from prismpath.ledgers.audit_log import AuditLog

REFUSE, HOLD = "refuse", "hold"
_FLOOR, _ACTIVE, _STAGED, _PENDING, _COUNTER = ("prismpath.dist-floor/1", "prismpath.dist-active/1",
                                                "prismpath.dist-staged/1", "prismpath.dist-pending/1",
                                                "prismpath.dist-counter/1")


class PepRefused(Exception):
    """The PEP refuses to start or to be provisioned (K2, X10, an anchor for another kind)."""


@dataclass(frozen=True)
class Held:
    """One envelope of a release as the store holds it: its envelope id and the blob names of the sealed
    envelope and of the body."""
    envelope_id: str
    sealed: str
    body: str


@dataclass
class Release:
    """A release as the PEP holds it (E7). `envelopes`, `bodies` and `paths` are read from the blobs."""
    stream: str
    seq: int
    policy_sha256: str
    release: str
    replaces: str
    widens: bool
    held: Dict[str, Held] = field(default_factory=dict)
    envelopes: Dict[str, Any] = field(default_factory=dict)
    bodies: Dict[str, bytes] = field(default_factory=dict)
    paths: Dict[str, str] = field(default_factory=dict)

    def document(self) -> dict:
        return {"stream": self.stream, "seq": self.seq, "policy_sha256": self.policy_sha256, "release": self.release,
                "replaces": self.replaces, "widens": self.widens,
                "held": {artifact: {"envelope_id": held.envelope_id, "sealed": held.sealed, "body": held.body}
                         for artifact, held in sorted(self.held.items())}}

    @property
    def envelope_ids(self) -> FrozenSet[str]:
        return frozenset(held.envelope_id for held in self.held.values())

    def names(self, stream: str, seq: int, policy_sha256: str) -> bool:
        return (self.stream, self.seq, self.policy_sha256) == (stream, seq, policy_sha256)


class _Store:
    """The PEP's directory: whole canon/2 documents and content addressed blobs, each write synced."""

    def __init__(self, directory: str):
        self.dir = directory
        self.blobs = os.path.join(directory, "blobs")
        os.makedirs(self.blobs, exist_ok=True)

    def path(self, name: str) -> str:
        return os.path.join(self.dir, name)

    def exists(self, name: str) -> bool:
        return os.path.exists(self.path(name))

    def read(self, name: str, form: str) -> dict:
        """The document `name` of format `form`, or `Refused` when it is missing or does not read."""
        try:
            with open(self.path(name), "rb") as handle:
                doc = kinds.load_canonical(handle.read(), name)
        except OSError:
            raise Refused(kinds.BAD_FORMAT, f"{name} cannot be read") from None
        if not isinstance(doc, dict) or doc.get("format") != form or doc.get(canon.ENCODING_KEY) != canon.CANON2:
            raise Refused(kinds.BAD_FORMAT, f"{name} is not {form}")
        return doc

    def write(self, name: str, form: str, doc: dict) -> None:
        canon.atomic_write_bytes(self.path(name), canon.canon2_bytes({**doc, "format": form,
                                                                     canon.ENCODING_KEY: canon.CANON2}))
        canon.fsync_dir(self.dir)

    def write_bytes(self, name: str, data: bytes) -> None:
        canon.atomic_write_bytes(self.path(name), data)
        canon.fsync_dir(self.dir)

    def remove(self, name: str) -> None:
        try:
            os.remove(self.path(name))
        except FileNotFoundError:
            return
        canon.fsync_dir(self.dir)

    def put(self, data: bytes) -> str:
        name = canon.sha256_hex(data)
        path = os.path.join(self.blobs, name)
        if not os.path.exists(path) or self.get(name) is None:
            canon.atomic_write_bytes(path, data)
            canon.fsync_dir(self.blobs)
        return name

    def get(self, name: str) -> Optional[bytes]:
        """The blob `name`, or None when it is missing or its bytes are not its name's."""
        try:
            with open(os.path.join(self.blobs, name), "rb") as handle:
                data = handle.read()
        except OSError:
            return None
        return data if canon.sha256_hex(data) == name else None

    def blob_path(self, name: str) -> str:
        return os.path.join(self.blobs, name)

    def keep_only(self, names: Iterable[str]) -> None:
        """Remove every blob not in `names`. A removal that fails leaves a file nothing reads."""
        keep = set(names)
        removed = False
        for name in os.listdir(self.blobs):
            if name not in keep:
                try:
                    os.remove(os.path.join(self.blobs, name))
                    removed = True
                except OSError:
                    pass
        if removed:
            canon.fsync_dir(self.blobs)


class Pep:
    """One enforcement point following one stream. `adapter` is the target's, `instance_key` the PEP's own
    `root_statement.InstanceKey`, `clock` a function answering Unix seconds. `has_clock` False is a PEP with
    no real time clock (T2, T3). `expiry_response` is the deployment's setting (X6), `refuse` unless the
    target kind allows `hold`, and it is fixed for the life of the object (X10)."""

    def __init__(self, state_dir: str, adapter, instance_key, clock: Callable[[], int], *,
                 expiry_response: str = REFUSE, has_clock: bool = True):
        target = kinds.TARGETS.get(adapter.kind)
        if target is None:
            raise PepRefused(f"no enforcement point of kind {adapter.kind!r} is built")
        if expiry_response not in (REFUSE, HOLD):
            raise PepRefused(f"the expiry response is {REFUSE} or {HOLD}, not {expiry_response!r}")
        if expiry_response == HOLD and not target.expiry_hold:
            raise PepRefused(f"a {adapter.kind} PEP has no HOLD setting; it always refuses at expiry (X6, X10)")
        if instance_key is None:
            raise PepRefused("a PEP needs its own instance key (K2)")
        self.adapter, self.target, self.instance_key, self.clock = adapter, target, instance_key, clock
        self.expiry_response, self.has_clock = expiry_response, has_clock
        self.store = _Store(os.path.join(state_dir, "dist"))
        self.audit = AuditLog(self.store.path("audit.log"), instance_key=instance_key, sign_appends=True)
        self.epoch = 0
        self.held = False
        self._load()
        self._check_separation(self.trust)
        self._recover()

    # ------------------------------------------------------------------ the durable state
    def _load(self) -> None:
        self.locked = False
        self.stream: Optional[str] = None
        self.trust = TrustStore(readable=False)
        self.floor = Floor()
        self.counter = 0
        self.active: Optional[Release] = None
        self.previous: Optional[Release] = None
        self.staged: Optional[Release] = None
        self.pending: Optional[dict] = None
        self.provisioned = self.store.exists("anchor.json")
        if not self.provisioned:
            return                                                  # P1: nothing to believe yet
        self.trust = TrustStore.load(self.store.path("trust.json"))
        try:
            with open(self.store.path("anchor.json"), "rb") as handle:
                self.stream = read_anchor(handle.read()).stream
            floor = self.store.read("floor.json", _FLOOR)
            counter = self.store.read("counter.json", _COUNTER)
            if floor["stream"] != self.stream or not kinds.is_int(floor["seq"], 0, kinds.MAX_SEQ):
                raise Refused(kinds.BAD_FORMAT, "floor.json")
            self.floor = Floor(floor["seq"], frozenset(floor["ids"]))
            self.counter = counter["counter"]
        except (OSError, Refused, KeyError, TypeError):
            self.locked = True                                       # Q5
            return
        if self.store.exists("active.json"):
            try:
                doc = self.store.read("active.json", _ACTIVE)
                self.active = self._release(doc["release"])
                self.previous = self._release(doc["previous"])
            except (Refused, KeyError, TypeError) as refused:
                self.active = self.previous = None
                self.audit.append("distribution", "active_unreadable", {"reason": str(refused), "result": "not_restored"})
        if self.store.exists("staged.json"):
            try:
                self.staged = self._release(self.store.read("staged.json", _STAGED)["release"])
            except (Refused, KeyError, TypeError):
                self.staged = None
        if self.store.exists("pending.json"):
            try:
                self.pending = self.store.read("pending.json", _PENDING)
            except Refused:
                self.pending = {"op": "unknown", "release": None}

    def _release(self, doc: Optional[dict]) -> Optional[Release]:
        """A release document read back with every blob it names, or `Refused` when one is missing or not
        its name's. Nothing the record does not name is ever read (C4)."""
        if doc is None:
            return None
        release = Release(stream=doc["stream"], seq=doc["seq"], policy_sha256=doc["policy_sha256"],
                          release=doc["release"], replaces=doc["replaces"], widens=doc["widens"])
        for artifact, held in doc["held"].items():
            sealed, body = self.store.get(held["sealed"]), self.store.get(held["body"])
            if sealed is None or body is None:
                raise Refused(kinds.BAD_FORMAT, f"a blob of {artifact} is missing or not its name's")
            envelope = env.read(env.unseal(sealed)[0])
            if envelope.envelope_id != held["envelope_id"] or envelope.artifact != artifact:
                raise Refused(kinds.BAD_FORMAT, f"the blob of {artifact} is another envelope")
            release.held[artifact] = Held(held["envelope_id"], held["sealed"], held["body"])
            release.envelopes[artifact], release.bodies[artifact] = envelope, body
            release.paths[artifact] = self.store.blob_path(held["body"])
        return release

    def _check_separation(self, trust: TrustStore) -> None:
        """K2: the instance key is never a trusted key, and the home holds no private half of one."""
        if self.instance_key.key_id in trust.keys:
            raise PepRefused("the instance key is also a trusted authority key (K2)")
        home = getattr(self.adapter, "home", None)
        if not home or not trust.keys or not os.path.isdir(home):
            return
        from prismpath.hotswap import policy_pack
        _priv, _pub, ser, _invalid = policy_pack._ed25519()
        for directory, subdirectories, files in os.walk(home):
            subdirectories[:] = [name for name in subdirectories if os.path.join(directory, name) != self.store.dir]
            for name in files:
                path = os.path.join(directory, name)
                try:
                    with open(path, "rb") as handle:
                        head = handle.read(64)
                    if not (head.startswith(b"-----BEGIN") and b"PRIVATE KEY" in head):
                        continue
                    key = policy_pack._load_private(path)
                    public = key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
                except (OSError, ValueError, TypeError, AttributeError):
                    continue
                if env.key_id(public) in trust.keys:
                    raise PepRefused(f"{path} holds the private half of a trusted authority key (K2)")

    def _recover(self) -> None:
        """Finish or report an interrupted commit or rollback (C4), then make the runtime match what the
        PEP holds and check expiry (X1)."""
        if self.pending is not None:
            target = self.pending.get("release")
            if self.active is not None and target is not None and self.active.document() == target:
                self._cleanup()
            else:
                self.audit.append("distribution", "commit_incomplete", {"op": self.pending.get("op"),
                                                                         "result": "incomplete"})
                self.store.remove("pending.json")
            self.pending = None
        cause = self.refusal()
        if cause is None:
            self.adapter.activate(self.active)
        else:
            self.adapter.deactivate(cause)
        self.tick()

    # ------------------------------------------------------------------ what the PEP is
    def state(self) -> str:
        if self.locked:
            return "locked"
        return "active" if self.active is not None and self.trust.readable else "no-policy"

    def refusal(self) -> Optional[str]:
        """X3: None while a release is active, else the cause every decision is refused with."""
        if self.locked:
            return "dist:floor-lost"
        return None if self.state() == "active" else "dist:policy-lapsed"

    def time(self) -> int:
        """T1: the larger of the clock and the time floor."""
        return max(int(self.clock()), self.trust.time_floor if self.trust.readable else 0)

    def view(self) -> PepView:
        staged = self.staged
        return PepView(kind=self.adapter.kind, stream=self.stream, floor=self.floor,
                       active=self.active.policy_sha256 if self.active else None,
                       staged=None if staged is None else Staged(staged.stream, staged.seq, staged.policy_sha256,
                                                                 staged.release, staged.replaces, staged.widens),
                       qualification=self.adapter.qualification, body_bound=self.adapter.body_bound,
                       has_clock=self.has_clock)

    def record(self, event: str, cause: Optional[str] = None) -> bytes:
        """A signed state record of the PEP as it is now (H1), its counter durable first (H3)."""
        self.counter += 1
        if self.provisioned and not self.locked:
            self.store.write("counter.json", _COUNTER, {"counter": self.counter})
        active, staged = self.active, self.staged
        record = state_record.StateRecord(
            event=event, state=self.state(), cause=cause, pep_id=state_record.pep_id(self.instance_key.public_raw),
            counter=self.counter, time=self.time(), epoch=self.epoch,
            stream=state_record.stream_prefix(self.stream or ""),
            active_policy=state_record.prefix(active.policy_sha256 if active else None),
            active_release=state_record.prefix(active.release if active else None),
            active_seq=active.seq if active else 0, floor=self.floor.seq,
            staged_release=state_record.prefix(staged.release if staged else None),
            staged_seq=staged.seq if staged else 0, trust_seq=self.trust.trust_seq if self.trust.readable else 0,
            staged=staged is not None, dev_build=devbuild.is_dev_build(), held=self.held)
        return state_record.build(record, self.instance_key)

    def see_epoch(self, epoch: int) -> None:
        """H9: keep the highest epoch id the controller sent. It changes nothing else."""
        if kinds.is_int(epoch, 0, 2 ** 64 - 1):
            self.epoch = max(self.epoch, epoch)

    def needs(self, blob_sha256s: Iterable[str]) -> Tuple[str, ...]:
        """X5, B5: which of the offered blobs this PEP does not hold. An offer is a hint and changes nothing."""
        return tuple(name for name in blob_sha256s if self.store.get(name) is None)

    # ------------------------------------------------------------------ G1, G2: stage
    def _refuse(self, cause: Optional[str], **details) -> bytes:
        self.audit.append("distribution", "refused", {**details, "cause": cause, "result": "refused"})
        return self.record("refused", cause)

    def stage(self, sealed: bytes, body: bytes) -> bytes:
        """Verify one sealed envelope and its body and hold it (G1). Returns the stage-ack state record."""
        if self.locked:
            return self._refuse("dist:floor-lost")
        if not self.provisioned:
            return self._refuse("dist:unknown-key")                 # P1, P2 step 4
        verdict = verify(sealed, body, trust=self.trust, pep=self.view(), now=int(self.clock()))
        if verdict.time_floor is not None and self.trust.readable and verdict.time_floor > self.trust.time_floor:
            self.trust = replace(self.trust, time_floor=verdict.time_floor).save()      # V13, T1
        envelope = verdict.envelope
        envelope_id = envelope.envelope_id if envelope is not None else None
        if not verdict.ok:
            return self._refuse(verdict.cause, envelope_id=envelope_id)
        if envelope.artifact in kinds.ON_TRUST_STREAM:
            # B2: a trust statement is applied when it verifies. Revocation (R1 to R7) and rotation (O1 to O4)
            # are applied by their own work packages; until then a verified statement is refused unapplied.
            return self._refuse(None, envelope_id=envelope_id, reason="trust statements are not applied yet")
        if verdict.unchanged:
            return self.record("beat")                               # Q3: changes nothing, reports its state
        staged = self.staged
        if staged is not None and staged.stream == envelope.stream and envelope.seq < staged.seq:
            return self._refuse("dist:seq-replay", envelope_id=envelope_id)   # G2
        if staged is None or staged.seq != envelope.seq:
            staged = Release(envelope.stream, envelope.seq, envelope.policy_sha256, envelope.release,
                             envelope.replaces, envelope.widens)
        names = Held(envelope_id, self.store.put(bytes(sealed)), self.store.put(bytes(body)))
        staged.held[envelope.artifact] = names
        staged.envelopes[envelope.artifact], staged.bodies[envelope.artifact] = envelope, bytes(body)
        staged.paths[envelope.artifact] = self.store.blob_path(names.body)
        self.store.write("staged.json", _STAGED, {"release": staged.document()})
        self.staged = staged
        self._keep_blobs()                                           # a replaced release's blobs go (G2)
        self.audit.append("distribution", "staged", {"envelope_id": envelope_id, "artifact": envelope.artifact,
                                                     "seq": envelope.seq, "release": envelope.release,
                                                     "result": "staged"})
        return self.record("staged")

    # ------------------------------------------------------------------ C1 to C5: commit
    def _drop_staged(self) -> None:
        self.staged = None
        self.store.remove("staged.json")
        self._keep_blobs()

    def _keep_blobs(self) -> None:
        held = [release for release in (self.active, self.previous, self.staged) if release is not None]
        self.store.keep_only(name for release in held for one in release.held.values() for name in (one.sealed, one.body))

    def _still_valid(self, release: Release, *, early: bool) -> Optional[str]:
        """C3, RB2: time (T3 when `early`, T4) and revocation (V7) again for every envelope of `release`."""
        time = self.time()
        for envelope in release.envelopes.values():
            if early and self.has_clock and envelope.not_before - time > SKEW:
                return "dist:not-yet-valid"
            if envelope.expires and time >= envelope.expires:
                return "dist:expired"
            if (envelope.envelope_id in self.trust.revoked_envelopes
                    or envelope.policy_sha256 in self.trust.revoked_policies):
                return "dist:revoked"
        return None

    def commit(self, stream: str, seq: int, policy_sha256: str) -> bytes:
        """Make the staged release named by `stream`, `seq` and `policy_sha256` active (C1 to C5)."""
        if self.locked:
            return self._refuse("dist:floor-lost")
        staged = self.staged
        if staged is None or not staged.names(stream, seq, policy_sha256):
            return self.record("refused", "dist:not-staged")         # C1: nothing changes
        if not self.target.needs <= set(staged.held):
            return self._refuse("dist:incomplete", seq=seq)          # C2
        whole = {artifact: (staged.envelopes[artifact], staged.bodies[artifact]) for artifact in staged.held}
        for artifact in sorted(staged.held):
            cause = self.adapter.check(artifact, staged.bodies[artifact], whole)
            if cause is not None:
                return self._refuse(cause, seq=seq)
        cause = self._still_valid(staged, early=True)                 # C3
        if cause is not None:
            self._drop_staged()
            return self._refuse(cause, seq=seq)
        return self._flip("commit", staged, previous=self.active, floor=Floor(staged.seq, staged.envelope_ids))

    def _flip(self, op: str, release: Release, *, previous: Optional[Release], floor: Floor) -> bytes:
        """C4, one step after another, each synced: intent, floor (a commit only), evidence, the artifacts
        (already blobs), the active record, the runtime, the clean up."""
        self.store.write("pending.json", _PENDING, {"op": op, "release": release.document()})
        if op == "commit":
            self.store.write("floor.json", _FLOOR, {"stream": self.stream, "seq": floor.seq, "ids": sorted(floor.ids)})
            self.floor = floor
        event = "committed" if op == "commit" else "rolled-back"
        self.audit.append("distribution", event, {"stream": release.stream, "seq": release.seq,
                                                  "release": release.release, "policy_sha256": release.policy_sha256,
                                                  "envelopes": sorted(release.envelope_ids), "result": event})
        self.store.write("active.json", _ACTIVE, {"release": release.document(),
                                                 "previous": previous.document() if previous else None})
        self.active, self.previous, self.held = release, previous, False
        if self.staged is not None and self.staged.seq <= release.seq:
            self.staged = None
        self.adapter.activate(release)
        self._cleanup()
        return self.record(event)

    def _cleanup(self) -> None:
        if self.staged is None:
            self.store.remove("staged.json")
        self._keep_blobs()
        self.store.remove("pending.json")

    # ------------------------------------------------------------------ A1: abort
    def abort(self, stream: str, seq: int, policy_sha256: str) -> bytes:
        """Drop the staged release when the abort names it, and change nothing otherwise (A1)."""
        if self.staged is None or not self.staged.names(stream, seq, policy_sha256):
            return self.record("beat")
        self._drop_staged()
        self.audit.append("distribution", "aborted", {"stream": stream, "seq": seq, "result": "aborted"})
        return self.record("aborted")

    # ------------------------------------------------------------------ X1 to X9: expiry and hold
    def tick(self) -> Optional[bytes]:
        """X1: check the active release's expiry. It lapses to `no-policy`, or under HOLD is held (X7).
        Returns the state record of a transition, None when nothing changed."""
        if self.active is None or self.locked or not self.trust.readable:
            return None
        if self._still_valid(self.active, early=False) != "dist:expired":
            return None
        if self.expiry_response == HOLD:
            if self.held:
                return None
            self.held = True
            self.audit.append("distribution", "held", {"seq": self.active.seq, "cause": "dist:held", "result": "held"})
            return self.record("held", "dist:held")
        return self.lapse("dist:expired")

    def lapse(self, cause: str) -> bytes:
        """X1, R5: go to `no-policy` with `cause`, durably, and make the runtime refuse."""
        lapsed = self.active
        self.store.write("active.json", _ACTIVE, {"release": None,
                                                 "previous": self.previous.document() if self.previous else None})
        self.active, self.held = None, False
        self.adapter.deactivate(cause)
        self._keep_blobs()
        self.audit.append("distribution", "lapsed", {"seq": lapsed.seq if lapsed else None, "cause": cause,
                                                     "result": "lapsed"})
        return self.record("lapsed", cause)

    def receipt_mark(self) -> Optional[str]:
        """X7: `held` on every receipt written while the PEP holds an expired release, else None."""
        return "held" if self.held else None

    # ------------------------------------------------------------------ RB1, RB2, X9: rollback
    def rollback(self) -> bytes:
        """Return to the release the active one replaced (RB1), never lowering the floor. Refused while held
        (X9) and when an envelope of the kept release has expired or is revoked (RB2)."""
        if self.held:
            return self._refuse("dist:held")
        if self.locked:
            return self._refuse("dist:floor-lost")
        kept = self.previous
        if kept is None:
            return self._refuse(None, reason="no release is kept")
        cause = self._still_valid(kept, early=False)
        if cause is not None:
            return self._refuse(cause, seq=kept.seq)
        return self._flip("rollback", kept, previous=None, floor=self.floor)

    # ------------------------------------------------------------------ P2, P3: provisioning
    def provision(self, anchor: bytes) -> str:
        """P2 step 3: receive a trust anchor and return its fingerprint for the operator to compare. The PEP
        follows no stream until `confirm` is given that fingerprint (P2 step 4)."""
        read = read_anchor(anchor)
        if read.target != self.adapter.kind:
            raise PepRefused(f"the anchor is for a {read.target} PEP, not a {self.adapter.kind} one")
        self.store.write_bytes("anchor.pending", bytes(anchor))
        self.audit.append("distribution", "anchor_received", {"fingerprint": read.fingerprint, "result": "pending"})
        return read.fingerprint

    def confirm(self, fingerprint: str) -> bytes:
        """P2 step 4, P3: the operator confirmed `fingerprint`. The trust store, the floor and the time floor
        start again from the anchor, whatever was held before, and a locked PEP is unlocked."""
        try:
            with open(self.store.path("anchor.pending"), "rb") as handle:
                raw = handle.read()
        except OSError:
            raise PepRefused("no anchor is waiting to be confirmed") from None
        read = read_anchor(raw)
        if fingerprint != read.fingerprint:
            raise PepRefused("the fingerprint is not the waiting anchor's")
        store = read.store()
        self._check_separation(store)
        self.adapter.deactivate("dist:policy-lapsed")
        for name in ("active.json", "staged.json", "pending.json"):
            self.store.remove(name)
        self.trust = store.save(self.store.path("trust.json"))
        self.store.write("floor.json", _FLOOR, {"stream": read.stream, "seq": 0, "ids": []})
        self.store.write("counter.json", _COUNTER, {"counter": self.counter})
        self.store.write_bytes("anchor.json", raw)
        self.store.remove("anchor.pending")
        self.stream, self.floor, self.locked, self.provisioned, self.held = read.stream, Floor(), False, True, False
        self.active = self.previous = self.staged = None
        self._keep_blobs()
        self.audit.append("distribution", "provisioned", {"fingerprint": read.fingerprint, "stream": read.stream,
                                                          "result": "provisioned"})
        return self.record("provisioned")
