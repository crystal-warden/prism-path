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
    setting.json   the expiry response the PEP was provisioned with (X10)
    staged.json    the staged release
    pending.json   the intent record of a commit, a rollback or a lapse (C7): the transition, the release it
                   makes active or none, the cause of a lapse, the release the runtime ran when it started and
                   whether the runtime was withdrawn since (C10)
    active.json    the active release and the one it replaced (RB1)
    fresh.json     the latest fresh controller statement, where freshness is on (H16)
    blobs/         sealed envelopes and bodies under their SHA-256
    audit.log      the audit log, signed by the instance key

A commit is durable in the order of C4: the intent, the floor, the audit event, the artifacts under content
addressed names (staging already wrote them, each synced), the active record, the runtime switch, the clean
up. A restart reads only what the active record names, and finishes or reports an interrupted commit.

When the last step of a transition, making the runtime run what the PEP now holds, fails after the record is
durable, the PEP is `reconciling` (section 9.5): it withdraws the runtime at once, refuses every decision, commit
and rollback with `dist:reconciling`, and only a tick or a start tries the runtime again. Its records carry status
3 and the reconciling entry of H14, and the record the transition owed goes once a try works. This version builds
no action floor and no fallback policy (section 21), so a withdrawal leaves the runtime running nothing.

The epoch id (H9) is taken only from a controller statement that verifies under the controller key the trust store
holds at its key sequence, and is kept in memory only (H15). Where the anchor sets `fresh`, a fresh statement is
kept durably and the PEP lapses at expiry when it is not renewed in time (H16).

A store that cannot be read is answered by failing closed: an unreadable trust store refuses every envelope
and decides nothing (K1, X3), and an unreadable floor, counter or anchor locks the PEP (Q5) until it is
provisioned again (P3).
"""
from __future__ import annotations

import os
import time as _time
from collections import deque
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, FrozenSet, Iterable, Optional, Tuple

from prismpath import canon
from prismpath.distribution import devbuild, heartbeat, kinds, state_record, statement as statements, widening
from prismpath.distribution.adapters import LARGER, NOT_LARGER
from prismpath.distribution import envelope as env
from prismpath.distribution.kinds import Refused
from prismpath.distribution.trust import TrustStore, read_anchor
from prismpath.distribution.verify import SKEW, Floor, PepView, Staged, verify
from prismpath.ledgers.audit_log import AuditLog

REFUSE, HOLD = "refuse", "hold"
RECONCILING, POLICY_LAPSED, FLOOR_LOST, EXPIRED, REVOKED = (
    "dist:reconciling", "dist:policy-lapsed", "dist:floor-lost", "dist:expired", "dist:revoked")
_FRESH = "prismpath.dist-fresh/1"
K2_SCAN, K2_SKIP = 4096, frozenset({"runs"})          # K2: the bound of the scan of a home for an authority key
_FLOOR, _ACTIVE, _STAGED, _PENDING, _COUNTER, _SETTING = (
    "prismpath.dist-floor/1", "prismpath.dist-active/1", "prismpath.dist-staged/1", "prismpath.dist-pending/1",
    "prismpath.dist-counter/1", "prismpath.dist-setting/1")


def _signed_by_a_held_key(trust: TrustStore, entries, message: bytes) -> bool:
    """A stored sealed envelope still carries a signature that verifies under a key the store holds, whatever that
    key's standing: a blob changed on disk is caught when it is read back, and revocation and retirement are
    R5's to judge, after the load."""
    from prismpath.hotswap import policy_pack
    _priv, Public, _ser, InvalidSignature = policy_pack._ed25519()
    for kid, signature in entries:
        key = trust.keys.get(kid)
        if key is None:
            continue
        try:
            Public.from_public_bytes(key.public).verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            continue
    return False


def read_release(store: "_Store", trust: TrustStore, reads_meta: bool, doc: Optional[dict]) -> Optional["Release"]:
    """A release document read back with every blob it names, or `Refused` when one is missing, not its name's, or
    no longer carries a signature by a key the store holds. Nothing the record does not name is ever read (C4)."""
    if doc is None:
        return None
    release = Release(stream=doc["stream"], seq=doc["seq"], policy_sha256=doc["policy_sha256"],
                      release=doc["release"], replaces=doc["replaces"], widens=doc["widens"])
    for artifact, held in doc["held"].items():
        sealed, body = store.get(held["sealed"]), store.get(held["body"])
        if sealed is None or body is None:
            raise Refused(kinds.BAD_FORMAT, f"a blob of {artifact} is missing or not its name's")
        envelope_bytes, entries = env.unseal(sealed)
        envelope = env.read(envelope_bytes, reads_meta=reads_meta)
        if envelope.envelope_id != held["envelope_id"] or envelope.artifact != artifact:
            raise Refused(kinds.BAD_FORMAT, f"the blob of {artifact} is another envelope")
        if trust.readable and not _signed_by_a_held_key(trust, entries, env.signed_message(envelope_bytes)):
            raise Refused(kinds.BAD_FORMAT, f"the stored blob of {artifact} is not signed by a key the store holds")
        release.held[artifact] = Held(held["envelope_id"], held["sealed"], held["body"])
        release.envelopes[artifact], release.bodies[artifact] = envelope, body
        release.paths[artifact] = store.blob_path(held["body"])
    return release


def stands(trust: TrustStore, release: "Release", sealed_of: Callable[[str], Optional[bytes]], *, active: bool) -> bool:
    """R5: a release still stands when no envelope of it is listed by id or policy hash, its `seq` is not below a
    floor a revocation raised, and every envelope of it is still signed. A key that was only retired still holds up
    a release already active under it (O3), and a staged release needs a counting signature (S5), as at commit.
    `sealed_of(name)` reads a sealed blob. The machine and every reader of a committed release ask this."""
    if release.seq < trust.floors.get(release.stream, 0):
        return False
    for held in release.held.values():
        if held.envelope_id in trust.revoked_envelopes or release.policy_sha256 in trust.revoked_policies:
            return False
        sealed = sealed_of(held.sealed)
        if sealed is None:
            return False
        envelope_bytes, entries = env.unseal(sealed)
        message = env.signed_message(envelope_bytes)
        if not (trust.holds_up(entries, message, kinds.AUTHORITY) if active
                else trust.counting(entries, message, kinds.AUTHORITY).ok):
            return False
    return True


def standing(trust: TrustStore, release: "Release", sealed_of: Callable[[str], Optional[bytes]],
             time: int) -> Optional[str]:
    """Why an active release no longer decides at the PEP's `time`: `dist:revoked` when it no longer stands (R5),
    `dist:expired` when an envelope of it has expired (X1), else None."""
    if not stands(trust, release, sealed_of, active=True):
        return "dist:revoked"
    if any(envelope.expires and time >= envelope.expires for envelope in release.envelopes.values()):
        return "dist:expired"
    return None


def read_committed(state_dir: str, kind: str, now: int) -> Dict[str, bytes]:
    """The bodies of `read_committed_release`."""
    return dict(read_committed_release(state_dir, kind, now).bodies)


def read_committed_release(state_dir: str, kind: str, now: int) -> "Release":
    """The release the PEP over `state_dir` has active, read as a restart reads them and held to the
    tests the machine holds it to on every entry point, for a reader in another process (the agent home's hook and
    proxies). `Refused`: `dist:floor-lost` when the anchor, the setting, the counter or the floor does not read,
    since the PEP is then locked (Q5); `dist:unknown-key` when the trust store does not read (K1);
    `dist:policy-lapsed` with nothing active; and the cause of `standing` when the release no longer decides. A
    HOLD past expiry is the machine's to mark, so a reader refuses an expired release."""
    store = _Store(os.path.join(state_dir, "dist"))
    if not store.exists("anchor.json"):
        raise Refused("dist:policy-lapsed", "the PEP is not provisioned")
    trust = TrustStore.load(store.path("trust.json"))
    if not trust.readable:
        raise Refused("dist:unknown-key", "the trust store cannot be read")
    try:
        with open(store.path("anchor.json"), "rb") as handle:
            stream = read_anchor(handle.read()).stream
        counter = store.read("counter.json", _COUNTER)["counter"]
        floor = store.read("floor.json", _FLOOR)
        store.read("setting.json", _SETTING)["expiry"]
        if (not kinds.is_int(counter, 0, 2 ** 64 - 1) or floor["stream"] != stream
                or not kinds.is_int(floor["seq"], 0, kinds.MAX_SEQ)):
            raise Refused(kinds.BAD_FORMAT, "counter.json or floor.json")
    except (OSError, Refused, KeyError, TypeError):
        raise Refused("dist:floor-lost", "the PEP's anchor, setting, counter or floor cannot be read") from None
    try:
        release = read_release(store, trust, kinds.TARGETS[kind].reads_meta,
                               store.read("active.json", _ACTIVE)["release"])
    except (Refused, KeyError, TypeError):
        release = None
    if release is None:
        raise Refused("dist:policy-lapsed", "no release is active")
    cause = standing(trust, release, store.get, max(int(now), trust.time_floor))
    if cause is not None:
        raise Refused(cause, "the active release no longer decides")
    return release


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
                 expiry_response: str = REFUSE, has_clock: bool = True,
                 monotonic: Callable[[], float] = _time.monotonic):
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
        self.epoch = 0                                               # H15: in memory only, 0 at every start
        self.time_taken = False                                      # H16: a clockless PEP takes time once a start
        self.reconciling: Optional[dict] = None                      # section 9.5, while the runtime may differ
        self.retry_runtime = False                                   # C10: a renewal's failed runtime step
        self.held = False
        self.monotonic = monotonic
        self.due: Optional[Tuple[str, int, str, float]] = None      # B8: a commit with a delay, and when it falls
        self.outbox: list = []
        self.recent: deque = deque(maxlen=heartbeat.MAX_FRAMES)    # H5: the readings decided since the last record
        self.bad_readings = 0                                        # readings the Facet codec refused, not carried
        self._load()
        self._check_setting()
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
        self.fresh, self.kept = 0, None
        self.provisioned = self.store.exists("anchor.json")
        if not self.provisioned:
            return                                                  # P1: nothing to believe yet
        self.trust = TrustStore.load(self.store.path("trust.json"))
        try:                                                         # H3: the counter is kept apart from the floor
            counter = self.store.read("counter.json", _COUNTER)["counter"]
            if not kinds.is_int(counter, 0, 2 ** 64 - 1):
                raise Refused(kinds.BAD_FORMAT, "counter.json")
            self.counter = counter
        except (Refused, KeyError, TypeError):
            # A counter that cannot be read must still never repeat: the PEP locks, and its records count on
            # from its time in microseconds, above any counter it can have sent one record at a time.
            self.counter, self.locked = self.time() * 1_000_000, True
        try:
            with open(self.store.path("anchor.json"), "rb") as handle:
                anchor = read_anchor(handle.read())
            self.stream, self.fresh = anchor.stream, anchor.fresh
            floor = self.store.read("floor.json", _FLOOR)
            if floor["stream"] != self.stream or not kinds.is_int(floor["seq"], 0, kinds.MAX_SEQ):
                raise Refused(kinds.BAD_FORMAT, "floor.json")
            self.floor = Floor(floor["seq"], frozenset(floor["ids"]))
        except (OSError, Refused, KeyError, TypeError):
            self.locked = True                                       # Q5
        if self.locked:
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
        self.kept = self._read_fresh()

    def _check_setting(self) -> None:
        """X10: the expiry response is fixed at provisioning. A start with another one is refused, and one that
        cannot be read locks the PEP."""
        if not self.provisioned:
            return
        try:
            provisioned = self.store.read("setting.json", _SETTING)["expiry"]
        except (Refused, KeyError):
            self.locked = True
            return
        if provisioned != self.expiry_response:
            raise PepRefused(f"this PEP was provisioned to {provisioned} at expiry, not to {self.expiry_response} (X10)")

    def _release(self, doc: Optional[dict]) -> Optional[Release]:
        """A release document read back with every blob it names (`read_release`)."""
        return read_release(self.store, self.trust, self.target.reads_meta, doc)

    def _check_separation(self, trust: TrustStore) -> None:
        """K2, K4: the instance key is never a key the store holds in any role, and the home holds no private half
        of a trusted authority key."""
        if self.instance_key.key_id in trust.keys:
            raise PepRefused("the instance key is also a key the trust store holds (K2, K4)")
        home = getattr(self.adapter, "home", None)
        if not home or not trust.keys or not os.path.isdir(home):
            return
        from prismpath.hotswap import policy_pack
        _priv, _pub, ser, _invalid = policy_pack._ed25519()
        looked = 0
        for directory, subdirectories, files in os.walk(home):
            # the scan is bounded: not the PEP's own store, not the runs a home keeps, no deeper than two levels,
            # and at most K2_SCAN files, since a private key is a small file among the home's own
            depth = os.path.relpath(directory, home).count(os.sep) + (directory != home)
            subdirectories[:] = [] if depth >= 2 else [
                name for name in subdirectories
                if os.path.join(directory, name) != self.store.dir and name not in K2_SKIP]
            for name in files:
                looked += 1
                if looked > K2_SCAN:
                    return
                path = os.path.join(directory, name)
                try:
                    if os.path.getsize(path) > 16384:
                        continue
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
        """A start: finish or report an interrupted transition (C4, C7), hold the staged and the active release to
        the revocation test again (R5) and check expiry (X1), then make the runtime run what the active record
        names. A transition the intent record shows durable is owed its record, which goes once the runtime step
        works, and the intent record with it (C12). A held release that fell while the PEP was down is never
        installed (C10). A start whose runtime step fails still starts, `reconciling` (C6)."""
        owed: Tuple[str, Optional[str]] = ("beat", None)
        running = self.active                     # C7: with no intent record the held release may still run
        withdrawn = False
        if self.pending is not None:              # a locked PEP read no intent record: provisioning removes it
            intent, self.pending = self.pending, None
            op, target = intent.get("op"), intent.get("release")
            if op in ("commit", "rollback"):
                flipped = self.active is not None and target is not None and self.active.document() == target
            else:
                flipped = op == "lapse" and self.active is None and target is None
            if flipped:
                owed = ({"commit": "committed", "rollback": "rolled-back"}.get(op, "lapsed"),
                        (intent.get("cause") or POLICY_LAPSED) if op == "lapse" else None)
                withdrawn = intent.get("withdrawn") is True
                running = None if withdrawn else self._running_of(intent.get("running"))
            else:
                self.audit.append("distribution", "commit_incomplete", {"op": op, "result": "incomplete"})
                self.store.remove("pending.json")
        if (self.staged is not None and self.active is not None and self.staged.stream == self.active.stream
                and self.staged.seq <= self.active.seq):
            self._drop_staged()                   # a flip that died before its clean up: the staged release is done
        self._drop_fallen_staged()
        if owed[0] == "beat":
            before = self.active
            self._check_ground()
            if before is not None and self.active is None or self.reconciling is not None:
                return                            # a lapse made its own runtime step
        else:
            self.reconciling = self._state(owed, running, withdrawn)
            self._run_tests(never_ran=False)      # C10: the tests come before the step, as in every try
            state, self.reconciling = self.reconciling, None
            owed, running, withdrawn = (state["owed"], state["cause"]), state["running"], state["withdrawn"]
        try:
            self._step(owed[1])
        except Exception as error:  # noqa: BLE001 - any failure of the runtime is a failed runtime step (C6)
            self._enter(owed, running, error)       # withdrawn again: a runtime may restore what it ran
            return
        if owed[0] != "beat":
            self._settle(owed)

    def _running_of(self, doc: Optional[dict]) -> Optional[Release]:
        """C7: the release the intent record says the runtime ran. Its blobs are read when they still are, and it is
        still named when they are not (C11)."""
        if doc is None:
            return None
        try:
            return self._release(doc)
        except (Refused, KeyError, TypeError):
            return Release(doc["stream"], doc["seq"], doc["policy_sha256"], doc["release"], doc["replaces"],
                           doc["widens"], held={artifact: Held(one["envelope_id"], one["sealed"], one["body"])
                                                for artifact, one in doc["held"].items()})

    @staticmethod
    def _state(owed: Tuple[str, Optional[str]], running: Optional[Release], withdrawn: bool) -> dict:
        return {"owed": owed[0], "cause": owed[1], "running": None if withdrawn else running,
                "withdrawn": withdrawn, "running_fell": None}

    def _step(self, cause: Optional[str] = None) -> None:
        """The runtime step: run the held release, or nothing when none is held or the PEP is locked (X3, C13).
        Raises whatever the runtime raised."""
        refusal = self.own_refusal()
        if refusal is None:
            self.adapter.activate(self.active)
        else:
            self.adapter.deactivate(cause or refusal)

    # ------------------------------------------------------------------ what the PEP is
    def state(self) -> str:
        if self.locked:
            return "locked"
        if self.reconciling is not None:
            return "reconciling"
        return "active" if self.active is not None and self.trust.readable else "no-policy"

    def refusal(self) -> Optional[str]:
        """X3, C8: None while a release decides, else the cause every decision is refused with."""
        if not self.locked and self.reconciling is not None:
            return RECONCILING
        return self.own_refusal()

    def own_refusal(self) -> Optional[str]:
        """The refusal of what the PEP holds, whatever its runtime runs: what the runtime step makes it do."""
        if self.locked:
            return FLOOR_LOST
        return None if self.active is not None and self.trust.readable else POLICY_LAPSED

    def running(self) -> Optional[Release]:
        """C10: the release the runtime may still run while the withdrawal has not worked, else None."""
        state = self.reconciling
        return None if state is None or state["withdrawn"] else state["running"]

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
                       has_clock=self.has_clock, instance_key_id=self.instance_key.key_id)

    def record(self, event: str, cause: Optional[str] = None) -> bytes:
        """A signed state record of the PEP as it is now (H1), after the expiry check every report comes
        after (X1)."""
        self._check_active()
        return self._record(event, cause)

    def drain(self) -> list:
        """Every state record made since the last drain, oldest first: what the PEP sends (H4). A transition
        found on the way into a call, such as a lapse, is in it before the call's own record."""
        sent, self.outbox = self.outbox, []
        return sent

    def _record(self, event: str, cause: Optional[str] = None) -> bytes:
        """Make one record, its counter durable first (H3), and put it in the outbox. The active fields name the
        held release in every state, and a reconciling PEP's record carries the entry of H14."""
        self.counter += 1
        if self.provisioned:
            self.store.write("counter.json", _COUNTER, {"counter": self.counter})
        active, staged = self.active, self.staged
        image = active.bodies.get("policy.core") if active is not None and self.state() == "active" else None
        if image is not None and hasattr(self.adapter, "readings"):
            for reading in self.adapter.readings():                   # decided in another process of the home
                self._keep(image, reading)
        try:
            body = heartbeat.body(image, self.recent) if image is not None else b""
        except (ValueError, KeyError, TypeError, AttributeError):
            self.bad_readings += len(self.recent)                     # never a ring that stops every record
            body = b""
        self.recent.clear()
        entry = self.reconciling_entry()
        record = state_record.StateRecord(
            event=event, state=self.state(), cause=cause, pep_id=state_record.pep_id(self.instance_key.public_raw),
            counter=self.counter, time=self.time(), epoch=self.epoch,
            stream=state_record.stream_prefix(self.stream or ""),
            active_policy=state_record.prefix(active.policy_sha256 if active else None),
            active_release=state_record.prefix(active.release if active else None),
            active_seq=active.seq if active else 0, floor=self.reported_floor(),
            staged_release=state_record.prefix(staged.release if staged else None),
            staged_seq=staged.seq if staged else 0, trust_seq=self.trust.trust_seq if self.trust.readable else 0,
            staged=staged is not None, dev_build=devbuild.is_dev_build(), held=self.held, body=body,
            extensions=entry.extension() if entry is not None else b"")
        signed = state_record.build(record, self.instance_key)
        self.outbox.append(signed)
        return signed

    def reconciling_entry(self) -> Optional[state_record.ReconcilingEntry]:
        """H14: the reconciling entry, or None outside the state. A locked PEP names `dist:floor-lost` and no
        running release (C13). This version holds no action floor, so the floor field is zeros (section 21)."""
        state = self.reconciling
        if state is None:
            return None
        running = self.running()
        cause = FLOOR_LOST if self.locked else (state["cause"] or state["running_fell"])
        return state_record.ReconcilingEntry(
            owed=state["owed"], cause=cause,
            running_policy=state_record.prefix(running.policy_sha256 if running else None),
            running_release=state_record.prefix(running.release if running else None),
            running_seq=running.seq if running else 0)

    def _keep(self, image: bytes, reading: Any) -> bool:
        """H5: put `reading` in the ring when the Facet codec of `image` encodes it, as `decide` and the readings
        another process of the home noted are both held. A reading it refuses is counted in `bad_readings` and
        not carried."""
        from prismpath.telemetry.spiral_groups import TIER_BAND
        try:
            if not isinstance(reading, dict):
                raise TypeError("a reading is an object")
            heartbeat.facet(image).encode_reading(reading, TIER_BAND)
        except (ValueError, KeyError, TypeError, AttributeError):
            self.bad_readings += 1
            return False
        self.recent.append(dict(reading))
        return True

    def reported_floor(self) -> int:
        """H1, R4: the floor V8 holds, the larger of the committed floor and the one a revocation raised."""
        raised = self.trust.floors.get(self.stream, 0) if self.trust.readable and self.stream else 0
        return max(self.floor.seq, raised)

    # ------------------------------------------------------------------ H9, H15, H16: the controller statement
    def take_statement(self, data: bytes) -> bool:
        """H9: take the epoch id of a controller statement that reads, names this PEP's stream, verifies under the
        controller key the trust store holds (not revoked, K6) and carries the key sequence the store holds for it,
        when that id is above the one held. Any other statement changes nothing and sends no record. Where
        freshness is on (H16), a statement that passes those checks may also give freshness. Returns whether the
        epoch id was taken. A statement changes nothing but the epoch id, the kept fresh statement and, once per
        start on a PEP with no clock, the time floor."""
        if not self.provisioned or self.locked or not self.trust.readable or not self.stream:
            return False
        read = statements.verify(data, self.trust.controller_public())
        if read is None or read.stream != state_record.stream_prefix(self.stream) or read.key_seq != self.trust.key_seq:
            return False
        taken = read.epoch > self.epoch
        if taken:
            self.epoch = read.epoch                                   # H9: never lowered
        if self.fresh:
            self._freshen(read, bytes(data))
        return taken

    def _freshen(self, read: "statements.Statement", data: bytes) -> None:
        """H16: a fresh statement has `fresh` 1, a trust sequence not below the PEP's, a stream seq not below its
        floor, an `expires` later than the kept one's and at most `fresh` plus SKEW ahead of the PEP's time. A PEP
        with no clock takes, from the first statement after each start that passes every other check, its
        `expires` less `fresh` as a raise of its time floor (T1). The latest fresh statement is kept durably,
        written before it counts, and a newer one is written only when the kept one has used half its life."""
        if not read.fresh or read.trust_seq < self.trust.trust_seq or read.stream_seq < self.reported_floor():
            return
        kept = self.kept
        if kept is not None and read.expires <= kept["expires"]:
            return
        if not self.has_clock and not self.time_taken:
            self.time_taken = True                                    # once per start, from no other statement
            floor = read.expires - self.fresh
            if floor > self.trust.time_floor:
                self.trust = replace(self.trust, time_floor=floor).save()
        time = self.time()
        if read.expires - time > self.fresh + SKEW:
            return
        if kept is not None and time - kept["at"] < (kept["expires"] - kept["at"]) / 2:
            return                                                    # the kept one has not used half its life
        self.kept = {"statement": data.hex(), "expires": read.expires, "at": time}
        self.store.write("fresh.json", _FRESH, dict(self.kept))

    def _read_fresh(self) -> Optional[dict]:
        """The kept fresh statement (H16), or None. One that does not read is none, so the PEP lapses at its next
        statement's lapse rather than on a file it cannot trust; it is checked again under the controller key."""
        if not self.fresh or not self.store.exists("fresh.json"):
            return None
        try:
            doc = self.store.read("fresh.json", _FRESH)
            read = statements.verify(bytes.fromhex(doc["statement"]), self.trust.controller_public())
            if read is None or read.expires != doc["expires"] or not kinds.is_int(doc["at"], 0, 2 ** 64 - 1):
                return None
            return {"statement": doc["statement"], "expires": doc["expires"], "at": doc["at"]}
        except (Refused, KeyError, TypeError, ValueError):
            return None

    def _stale(self) -> bool:
        """H16: freshness is on and the PEP's time passed the kept statement's `expires` plus SKEW."""
        return bool(self.fresh) and self.kept is not None and self.time() > self.kept["expires"] + SKEW

    def needs(self, blob_sha256s: Iterable[str]) -> Tuple[str, ...]:
        """X5, B5: which of the offered blobs this PEP does not hold. An offer is a hint and changes nothing."""
        return tuple(name for name in blob_sha256s if self.store.get(name) is None)

    # ------------------------------------------------------------------ G1, G2: stage
    def _refuse(self, cause: str, **details) -> bytes:
        self.audit.append("distribution", "refused", {**details, "cause": cause, "result": "refused"})
        return self._record("refused", cause)

    def refuse_fetched(self, cause: str, name: str) -> bytes:
        """B4, B9: the binding refused the blob `name` before anything was staged, for a hash that is not the
        one asked for or more bytes than were promised. The refusal is the PEP's own, in its audit log and its
        records, and nothing else changes."""
        self._check_active()
        return self._refuse(cause, blob=name)

    def blob(self, name: str) -> Optional[bytes]:
        """X5: a blob the PEP already holds under its SHA-256, so a renewal fetches no body it has."""
        return self.store.get(name)

    def stage(self, sealed: bytes, body: bytes) -> bytes:
        """Verify one sealed envelope and its body and hold it (G1). Returns the stage-ack state record. A
        reconciling PEP stages as in any other state, and the widening rule compares with the held release (C8)."""
        self._check_active()
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
        if verdict.unchanged:
            return self._record("beat")                               # Q3, R1: changes nothing, reports its state
        if envelope.artifact == "trust.revocation":
            return self._apply_revocation(envelope, body)
        if envelope.artifact == "trust.rotation":
            return self._apply_rotation(envelope, body)
        if envelope.artifact == "trust.controller":
            return self._apply_controller(envelope, body)
        staged = self.staged
        if staged is not None and staged.stream == envelope.stream and envelope.seq < staged.seq:
            return self._refuse("dist:seq-replay", envelope_id=envelope_id)   # G2
        if envelope.artifact != "trust.widening":
            same = staged is not None and staged.stream == envelope.stream and staged.seq == envelope.seq
            cause = self._widening(envelope.widens, envelope.replaces,
                                   {envelope.artifact: bytes(body)}, staged.bodies if same else {}, whole=False)
            if cause is not None:
                return self._refuse(cause, envelope_id=envelope_id)           # V12
        if staged is None or staged.seq != envelope.seq:
            staged = Release(envelope.stream, envelope.seq, envelope.policy_sha256, envelope.release,
                             envelope.replaces, envelope.widens)
        names = Held(envelope_id, self.store.put(bytes(sealed)), self.store.put(bytes(body)))
        staged.held[envelope.artifact] = names
        staged.envelopes[envelope.artifact], staged.bodies[envelope.artifact] = envelope, bytes(body)
        staged.paths[envelope.artifact] = self.store.blob_path(names.body)
        self.store.write("staged.json", _STAGED, {"release": staged.document()})
        self.staged = staged
        self._keep_blobs()                                           # a replaced release's blobs go (G2), not C11's
        self.audit.append("distribution", "staged", {"envelope_id": envelope_id, "artifact": envelope.artifact,
                                                     "seq": envelope.seq, "release": envelope.release,
                                                     "result": "staged"})
        return self._record("staged")

    def _widening(self, widens: bool, replaces: str, artifacts: Dict[str, bytes], staged: Dict[str, bytes], *,
                  whole: bool) -> Optional[str]:
        """V12 against the active release. `artifacts` are the bodies being judged and `staged` what is already
        staged of the same release, where its widening statement is. A PEP that can decide compares one artifact
        at staging and, at commit (`whole`), the whole release, which also sees an artifact the release drops."""
        active = self.active
        answer = None
        if not self.target.decides and active is not None:              # W2: the comparisons it can make (W6)
            for name in sorted(self.target.compares & set(artifacts)):
                if name in active.bodies and widening.compare_artifact(name, active.bodies[name],
                                                                       artifacts[name]) != NOT_LARGER:
                    answer = LARGER
        if self.target.decides:
            if whole:
                answer = widening.compare_release(None if active is None else active.bodies, artifacts)
            elif active is None:
                answer = LARGER
            else:
                ((name, body),) = artifacts.items()
                answer = widening.compare_artifact(name, active.bodies.get(name), body)
        return widening.check(self.target, widens=widens, replaces=replaces,
                              active_policy=active.policy_sha256 if active else None, answer=answer,
                              statement=staged.get("trust.widening"))

    # ------------------------------------------------------------------ B2: the trust statements
    def _adopt(self, envelope, store: TrustStore) -> None:
        """Make the store a verified trust statement leaves durable before anything reports it (B2, R3)."""
        self.trust = store.save()
        self.audit.append("distribution", "trust-applied", {"envelope_id": envelope.envelope_id, "seq": envelope.seq,
                                                           "artifact": envelope.artifact, "result": "applied"})

    def _apply_revocation(self, envelope, body: bytes) -> bytes:
        """Apply a verified revocation at once, then drop the staged release and lapse the active one when the
        revocation removed the ground they stand on (R5). A held PEP lapses the same way, which ends the hold
        (X8). A reconciling PEP holds both its releases to the test (C10) and tries no runtime."""
        self._adopt(envelope, self.trust.apply_revocation(envelope, body, self.stream))
        self._drop_fallen_staged()
        self._check_active()
        return self._record("trust-applied")

    def _apply_rotation(self, envelope, body: bytes) -> bytes:
        """Apply a verified rotation at once (O3). A release active under a key it retires stays active until it
        expires or is replaced, and a staged one that no longer has a counting signature is dropped (S5)."""
        self._adopt(envelope, self.trust.apply_rotation(envelope, body))
        self._drop_fallen_staged()
        self._check_active()
        return self._record("trust-applied")

    def _apply_controller(self, envelope, body: bytes) -> bytes:
        """Apply a verified `trust.controller` at once (K7). The epoch id starts again at 0 (H15), so the next
        statement under the new key sequence is taken whatever id it carries."""
        self._adopt(envelope, self.trust.apply_controller(envelope, body))
        self.epoch = 0
        self._check_active()
        return self._record("trust-applied")

    def _drop_fallen_staged(self) -> None:
        """R5: a staged release that no longer stands is dropped."""
        if self.staged is not None and self.trust.readable and not self._stands(self.staged, active=False):
            self._drop_staged()

    def _stands(self, release: Release, *, active: bool = True) -> bool:
        """R5 for `release` under the store as it is now (`stands`)."""
        return stands(self.trust, release, self.store.get, active=active)

    # ------------------------------------------------------------------ C1 to C5: commit
    def _drop_staged(self) -> None:
        self.staged = None
        self.store.remove("staged.json")
        self._keep_blobs()

    def _keep_blobs(self) -> None:
        """The blobs of the active, the kept and the staged release stay, and those of the running release until
        the withdrawal works (C11). Every other blob goes."""
        held = [release for release in (self.active, self.previous, self.staged, self.running()) if release is not None]
        self.store.keep_only(name for release in held for one in release.held.values() for name in (one.sealed, one.body))

    def _still_valid(self, release: Release, *, early: bool) -> Optional[str]:
        """C3, RB2: time (T3 when `early`, T4) and revocation (V7) again for every envelope of `release`, and at a
        commit (`early`) a counting signature again (V3), since a rotation may have retired its key."""
        time = self.time()
        for artifact, envelope in release.envelopes.items():
            if early:
                sealed = self.store.get(release.held[artifact].sealed)
                envelope_bytes, entries = env.unseal(sealed) if sealed is not None else (b"", [])
                counted = self.trust.counting(entries, env.signed_message(envelope_bytes), kinds.AUTHORITY)
                if not counted.ok:
                    return counted.cause
            if early and self.has_clock and envelope.not_before - time > SKEW:
                return "dist:not-yet-valid"
            if envelope.expires and time >= envelope.expires:
                return "dist:expired"
            if (envelope.envelope_id in self.trust.revoked_envelopes
                    or envelope.policy_sha256 in self.trust.revoked_policies):
                return "dist:revoked"
        return None

    def commit(self, stream: str, seq: int, policy_sha256: str, delay_ms: int = 0) -> bytes:
        """Make the staged release named by `stream`, `seq` and `policy_sha256` active (C1 to C5). With a delay
        it becomes active at the PEP's own monotonic time plus the delay and not before (B8), so a group flips
        together with no shared clock: the checks run now, and again when it falls due. A reconciling PEP answers
        `refused` with `dist:reconciling`, now and when a delay falls due, and keeps the staged release (C8)."""
        self._check_active()
        if not kinds.is_int(delay_ms, 0, 65535):
            raise ValueError("a commit delay is 0 to 65535 milliseconds")
        if delay_ms:
            cause = self._commit_refusal(stream, seq, policy_sha256)
            if cause is not None:
                return cause
            self.due = (stream, seq, policy_sha256, self.monotonic() + delay_ms / 1000.0)
            return self._record("beat")
        return self._commit_now(stream, seq, policy_sha256)

    def _commit_refusal(self, stream: str, seq: int, policy_sha256: str) -> Optional[bytes]:
        """C1 to C3 without the flip: None when the named release may commit, else the refusal's record."""
        if self.locked:
            return self._refuse("dist:floor-lost")
        if self.reconciling is not None:
            return self._refuse(RECONCILING, seq=seq)                 # C8: nothing changes
        if not self.trust.readable:
            return self._refuse("dist:unknown-key")                 # K1: decides nothing, commits nothing
        staged = self.staged
        if staged is None or not staged.names(stream, seq, policy_sha256):
            return self._record("refused", "dist:not-staged")        # C1: nothing changes
        return None

    def _fall_due(self) -> None:
        """B8: a delayed commit whose time has come is made now, its checks run again."""
        if self.due is None:
            return
        stream, seq, policy_sha256, when = self.due
        if self.staged is None or not self.staged.names(stream, seq, policy_sha256):
            self.due = None                                          # its release was dropped or replaced
        elif self.monotonic() >= when:
            self.due = None
            self._commit_now(stream, seq, policy_sha256)

    def _commit_now(self, stream: str, seq: int, policy_sha256: str) -> bytes:
        cause = self._commit_refusal(stream, seq, policy_sha256)
        if cause is not None:
            return cause
        staged = self.staged
        if not self.target.needs <= set(staged.held):
            return self._refuse("dist:incomplete", seq=seq)          # C2
        whole = {artifact: (staged.envelopes[artifact], staged.bodies[artifact]) for artifact in staged.held}
        for artifact in sorted(staged.held):
            cause = self.adapter.check(artifact, staged.bodies[artifact], whole)
            if cause is not None:
                return self._refuse(cause, seq=seq)
        if not self._whole(staged):
            return self._refuse("dist:incomplete", seq=seq)          # C2, E10: an artifact of the release is not staged
        cause = self._still_valid(staged, early=True)                 # C3
        if cause is not None:
            self._drop_staged()
            return self._refuse(cause, seq=seq)
        cause = self._widening(staged.widens, staged.replaces, staged.bodies, staged.bodies, whole=True)
        if cause is not None:
            return self._refuse(cause, seq=seq)                       # V12 again, against what is active now
        return self._flip("commit", staged, previous=self.active, floor=Floor(staged.seq, staged.envelope_ids))

    @staticmethod
    def _whole(staged: Release) -> bool:
        """C2, E10: the artifacts staged, trust kinds left out, are the whole release the authority signed. Their
        release id, computed again over what is staged, is the `release` every envelope carries, so a transport
        that withholds one artifact of a signed release, such as its `agent.zones`, cannot commit the rest."""
        pairs = [(artifact, envelope.body_sha256) for artifact, envelope in staged.envelopes.items()
                 if artifact not in kinds.TRUST_ARTIFACTS]
        return bool(pairs) and env.release_id(pairs) == staged.release

    def _intent(self, op: str, release: Optional[Release], cause: Optional[str], running: Optional[Release],
                withdrawn: bool) -> None:
        """C7: the intent record of a transition, with the release the runtime runs when it starts, in full."""
        self.store.write("pending.json", _PENDING, {
            "op": op, "release": release.document() if release else None, "cause": cause,
            "running": running.document() if running else None, "withdrawn": withdrawn})

    def _flip(self, op: str, release: Release, *, previous: Optional[Release], floor: Floor) -> bytes:
        """C4, one step after another, each synced: intent, floor (a commit only), evidence, the artifacts
        (already blobs), the active record, the runtime step, the state record, the clean up."""
        running = self.active                     # the runtime runs the held release, since the PEP is not reconciling
        self._intent(op, release, None, running, False)
        if op == "commit":
            self.store.write("floor.json", _FLOOR, {"stream": self.stream, "seq": floor.seq, "ids": sorted(floor.ids)})
            self.floor = floor
        event = "committed" if op == "commit" else "rolled-back"
        self.audit.append("distribution", event, {"stream": release.stream, "seq": release.seq,
                                                  "release": release.release, "policy_sha256": release.policy_sha256,
                                                  "envelopes": sorted(release.envelope_ids), "result": event})
        self.store.write("active.json", _ACTIVE, {"release": release.document(),
                                                 "previous": previous.document() if previous else None})
        self._end_ring(release)
        self.active, self.previous, self.held, self.retry_runtime = release, previous, False, False
        if self.staged is not None and self.staged.seq <= release.seq:
            self.staged = None
        return self._runtime_step((event, None), running)

    def _runtime_step(self, owed: Tuple[str, Optional[str]], running: Optional[Release]) -> bytes:
        """The runtime step of a transition whose record is durable. When it works the state record goes, then the
        clean up. When it fails between two releases whose bodies are the same the PEP stays as it is and each tick
        tries again, and otherwise it is reconciling (C6, C10)."""
        try:
            self._step(owed[1])
        except Exception as error:  # noqa: BLE001 - any failure of the runtime is a failed runtime step (C6)
            if not self._same_bodies(running):
                return self._enter(owed, running, error)
            self.audit.append("distribution", "runtime_failed", {"error": str(error),
                                                                 "result": "tried again at the next tick"})
            self.retry_runtime = True
        return self._settle(owed)

    def _same_bodies(self, running: Optional[Release]) -> bool:
        """C10: the held release and `running` have the same bodies, as a renewal's are (X5), so a switch between
        them changes nothing the runtime decides with. The trust kinds are not run, so they are left out."""
        held = self.active
        if held is None or running is None:
            return False
        run = lambda release: {name: body for name, body in release.bodies.items()  # noqa: E731
                               if name not in kinds.TRUST_ARTIFACTS}
        return bool(run(held)) and run(held) == run(running)

    def _settle(self, owed: Tuple[str, Optional[str]]) -> bytes:
        """The state record a transition owes, then the clean up, which takes the intent record (C12)."""
        record = self._record(*owed)
        self._cleanup()
        return record

    def _end_ring(self, release: Optional[Release]) -> None:
        """H5: the decisions in the ring were made under the active policy, and the next record's stream is built
        from the policy `release` makes active. When that is another policy or none, they are dropped, so no
        decision is reported under a policy that did not make it."""
        before = self.active.bodies.get("policy.core") if self.active is not None else None
        after = release.bodies.get("policy.core") if release is not None else None
        if before is None or before != after:
            self.recent.clear()
            if hasattr(self.adapter, "readings"):
                self.adapter.readings()                               # and what the home's other deciders noted

    def _cleanup(self) -> None:
        if self.staged is None:
            self.store.remove("staged.json")
        self._keep_blobs()
        self.store.remove("pending.json")

    # ------------------------------------------------------------------ section 9.5: reconciling
    def _withdraw_cause(self) -> str:
        """What the runtime is told when it is withdrawn."""
        if self.locked:
            return FLOOR_LOST
        state = self.reconciling
        return state["cause"] if state is not None and state["owed"] == "lapsed" and state["cause"] else RECONCILING

    def _enter(self, owed: Tuple[str, Optional[str]], running: Optional[Release], error: Exception, *,
               withdrawn: bool = False) -> bytes:
        """C6, C10, C12: the runtime step failed. The PEP withdraws the runtime at once, unless the step that failed
        was the withdrawal itself, writes `reconciling` with the runtime's error and sends a record with that
        event. When the withdrawal works the intent record notes it and only the held release is tracked."""
        stepped_withdrawal = self.own_refusal() is not None
        self.reconciling = self._state(owed, running, withdrawn)
        if not withdrawn and not stepped_withdrawal:
            try:
                self.adapter.deactivate(self._withdraw_cause())
                self._note_withdrawn()
            except Exception:  # noqa: BLE001 - a withdrawal that fails is tried again at every tick (C10)
                pass
        self.audit.append("distribution", "reconciling", {"error": str(error), "withdrawn": self.reconciling["withdrawn"],
                                                         "result": "reconciling"})
        self._run_tests(never_ran=True)
        return self._record("reconciling")

    def _note_withdrawn(self) -> None:
        """C10: the withdrawal worked. The runtime runs no release, and the intent record says so."""
        state = self.reconciling
        state["withdrawn"], state["running"], state["running_fell"] = True, None, None
        if self.store.exists("pending.json"):
            try:
                intent = self.store.read("pending.json", _PENDING)
            except Refused:
                return
            self.store.write("pending.json", _PENDING, {**intent, "running": None, "withdrawn": True})

    def _fell(self, release: Release) -> Optional[str]:
        """Why `release` falls, the test of R5 and then expiry (X1, and H16's freshness), else None. HOLD is for
        `mesh` and `cfs`, which never reconcile, so expiry always fells a release here (C10)."""
        if release.envelopes.keys() != release.held.keys():
            return None                           # a running release whose blobs do not read: still named (C11)
        cause = standing(self.trust, release, self.store.get, self.time())
        return cause or (EXPIRED if self._stale() else None)

    def _run_tests(self, *, never_ran: bool) -> None:
        """C10: hold the held release, and the running one while the withdrawal has not worked, to the tests. A
        held release that falls becomes a lapse with the cause it fell for, never installed. A PEP whose trust
        store does not read treats the held release as none and runs no test. No runtime is tried here."""
        state = self.reconciling
        if state is None or self.locked or not self.trust.readable:
            return
        running = self.running()
        if running is not None and state["running_fell"] is None:
            state["running_fell"] = self._fell(running)
        cause = self._fell(self.active) if self.active is not None else None
        if cause is not None:
            self._held_falls(cause, never_ran)

    def _held_falls(self, cause: str, never_ran: bool) -> None:
        """C10: a held release that falls was never run. Its transition becomes a lapse: the intent record is
        written again, the `lapsed` audit event, then an active record that names no release. The PEP owes `lapsed`
        with that cause and no longer the record of the commit or the rollback, and the floor stays (Q4)."""
        fell, state = self.active, self.reconciling
        self._intent("lapse", None, cause, state["running"], state["withdrawn"])
        details = {"seq": fell.seq, "cause": cause, **({"ran": False} if never_ran else {}), "result": "lapsed"}
        self.audit.append("distribution", "lapsed", details)
        self.store.write("active.json", _ACTIVE, {"release": None,
                                                 "previous": self.previous.document() if self.previous else None})
        self._end_ring(None)
        self.active, self.held = None, False
        state["owed"], state["cause"] = "lapsed", cause
        self._keep_blobs()

    def _try(self) -> Optional[bytes]:
        """C9: one try. The tests of C10, the withdrawal again when it has not worked, then the held release run.
        When the switch works the state ends and the record the transition owed goes, a `beat` when nothing was.
        When it fails nothing more changes and the next tick tries again."""
        self._run_tests(never_ran=True)
        state = self.reconciling
        if state is None:
            return None
        if not state["withdrawn"]:
            try:
                self.adapter.deactivate(self._withdraw_cause())
            except Exception:  # noqa: BLE001 - the next tick tries again
                return None
            self._note_withdrawn()
        if self.own_refusal() is None:
            try:
                self.adapter.activate(self.active)
            except Exception:  # noqa: BLE001 - the next tick tries again
                return None
        return self._leave()

    def _end_if_switched(self) -> Optional[bytes]:
        """C9, C10: with the runtime withdrawn and no release held the switch is done, so the state ends at once,
        with no runtime call."""
        state = self.reconciling
        if state is not None and state["withdrawn"] and not self.locked and self.active is None:
            return self._leave()
        return None

    def _leave(self) -> bytes:
        """C9, C12: the state ends. The owed record, then `reconciled`, then the clean up, which takes the intent
        record. A locked PEP read no active record, so its clean up waits for provisioning."""
        state, self.reconciling = self.reconciling, None
        try:
            record = self._record(state["owed"], state["cause"])
        except Exception:
            self.reconciling = state
            raise
        self.audit.append("distribution", "reconciled", {"result": "reconciled"})
        if not self.locked:
            self._cleanup()
        return record

    # ------------------------------------------------------------------ A1: abort
    def abort(self, stream: str, seq: int, policy_sha256: str) -> bytes:
        """Drop the staged release when the abort names it, and change nothing otherwise (A1)."""
        self._check_active()
        if self.staged is None or not self.staged.names(stream, seq, policy_sha256):
            return self._record("beat")
        self._drop_staged()
        self.audit.append("distribution", "aborted", {"stream": stream, "seq": seq, "result": "aborted"})
        return self._record("aborted")

    # ------------------------------------------------------------------ X1 to X9: expiry and hold
    def tick(self) -> Optional[bytes]:
        """X1: check the active release's expiry, at least once a minute. It lapses to `no-policy`, or under
        HOLD is held (X7). Returns the state record of a transition, None when nothing changed. A tick is one of
        the two calls that try the runtime again (C9), and the one that tries again the failed runtime step of a
        renewal (C10)."""
        self._fall_due()
        if self.reconciling is not None:
            return self._try()
        record = self._check_active()
        if self.retry_runtime and self.reconciling is None:
            try:
                if self.active is not None:
                    self.adapter.activate(self.active)
                self.retry_runtime = False
            except Exception:  # noqa: BLE001 - still the same bodies; the next tick tries again
                pass
        return record

    def _check_active(self) -> Optional[bytes]:
        self._fall_due()
        return self._check_ground()

    def _check_ground(self) -> Optional[bytes]:
        """What every entry point and the periodic tick run first: an active release that no longer stands lapses
        with `dist:revoked` (R5), and an expired one, or one whose freshness ran out (H16), lapses or is held (X1,
        X7). A reconciling PEP runs the tests of C10 instead, which try no runtime. A staged release is held to the
        same test when a revocation is applied and at a restart, and again at its commit (C3)."""
        if self.reconciling is not None:
            self._run_tests(never_ran=True)
            return self._end_if_switched()
        if self.locked or not self.trust.readable:
            return None
        if self.active is None:
            return None
        cause = standing(self.trust, self.active, self.store.get, self.time())
        if cause == REVOKED:
            return self.lapse(cause)
        if cause != EXPIRED and not self._stale():
            return None
        if self.expiry_response == HOLD:
            if self.held:
                return None
            self.held = True
            self.audit.append("distribution", "held", {"seq": self.active.seq, "cause": "dist:held", "result": "held"})
            return self._record("held", "dist:held")
        return self.lapse(EXPIRED)

    def lapse(self, cause: str) -> bytes:
        """X1, R5: go to `no-policy` with `cause`, durably in the order of C7, and make the runtime run nothing. A
        reconciling PEP lapses its held release as C10 does one that fell."""
        if self.reconciling is not None:
            if not self.locked and self.active is not None:
                self._held_falls(cause, True)
            switched = self._end_if_switched()
            return switched if switched is not None else self._record("beat")
        running = self.active
        self._intent("lapse", None, cause, running, False)
        self.audit.append("distribution", "lapsed", {"seq": running.seq if running else None, "cause": cause,
                                                     "result": "lapsed"})
        self.store.write("active.json", _ACTIVE, {"release": None,
                                                 "previous": self.previous.document() if self.previous else None})
        self._end_ring(None)
        self.active, self.held, self.retry_runtime = None, False, False
        return self._runtime_step(("lapsed", cause), running)

    def receipt_mark(self) -> Optional[str]:
        """X7: `held` on every receipt written while the PEP holds an expired release, else None."""
        return "held" if self.held else None

    def decide(self, under_release: Callable[[], Any], reading: Optional[Dict[str, Any]] = None) -> dict:
        """One decision through the PEP, after the expiry check (X1). With no active release, locked or
        reconciling, it is refused with the cause of X3 or C8 and `under_release` is not called, and no decision
        tries the runtime. Otherwise its answer is the decision, and the receipt carries the hold mark while the
        PEP is held (X7). The adapter hands the `reading` it decided, which the next state record carries in its
        Facet body when the active release has a `policy.core` (H5). A reading the Facet codec refuses is decided
        and not carried."""
        self._check_active()
        cause = self.refusal()
        if cause is not None:
            return {"decision": None, "cause": cause, "mark": None}
        decision = under_release()
        image = self.active.bodies.get("policy.core") if reading is not None else None
        if image is not None:
            self._keep(image, reading)
        return {"decision": decision, "cause": None, "mark": self.receipt_mark()}

    # ------------------------------------------------------------------ RB1, RB2, X9: rollback
    def rollback(self) -> bytes:
        """Return to the release the active one replaced (RB1), never lowering the floor. Refused while held
        (X9), while reconciling (C8), when an envelope of the kept release has expired, is revoked, has no counting
        signature or is below a floor a revocation raised, each with that check's own cause (RB2), and when the
        kept release may allow more than the active one without a widening statement that covers it (RB3). With
        no release kept there is nothing to return to, and `PepRefused` says so."""
        self._check_active()
        if self.held:
            return self._refuse("dist:held")
        if self.locked:
            return self._refuse("dist:floor-lost")
        if self.reconciling is not None:
            return self._refuse(RECONCILING)
        if not self.trust.readable:
            return self._refuse("dist:unknown-key")
        kept = self.previous
        if kept is None:
            raise PepRefused("no release is kept to roll back to (RB1)")
        cause = self._still_valid(kept, early=True)                  # RB2: what a commit checks, as it is active anew
        if cause is None and kept.seq < self.trust.floors.get(kept.stream, 0):
            cause = "dist:seq-replay"                                 # R4: below a floor a revocation raised
        if cause is not None:
            return self._refuse(cause, seq=kept.seq)
        if not self._covers(kept):
            return self._refuse("dist:widening-unsigned", seq=kept.seq)
        return self._flip("rollback", kept, previous=None, floor=self.floor)

    def _covers(self, kept: Release) -> bool:
        """RB3: a rollback to `kept` falls under W1 to W7 as a release staged against the active one would. A
        release identical to the active one is never larger. A PEP that can decide compares the two (W1), and
        one that cannot compares what its row compares, so on a `host` or a `mesh` node a kept table that is not
        the active one is larger (W2). A larger `kept` whose `widens` is false is refused even with a statement
        (W6), and otherwise needs a widening statement whose `from` is empty or holds the active policy hash
        (W4). Going from no policy to any is larger."""
        active = self.active
        if active is not None and kept.release == active.release:
            return True
        return self._widening(kept.widens, kept.replaces, kept.bodies, kept.bodies, whole=True) is None

    # ------------------------------------------------------------------ P2, P3, P5: provisioning
    def provision(self, anchor: bytes) -> str:
        """P2 step 3: receive a trust anchor and return its fingerprint for the operator to compare. The PEP
        follows no stream until `confirm` is given that fingerprint (P2 step 4). An anchor whose keys are not
        apart from each other and from the instance key is refused and leaves the PEP as it was (K4)."""
        read = read_anchor(anchor)
        if read.target != self.adapter.kind:
            raise PepRefused(f"the anchor is for a {read.target} PEP, not a {self.adapter.kind} one")
        self._check_separation(read.store())
        self.store.write_bytes("anchor.pending", bytes(anchor))
        self.audit.append("distribution", "anchor_received", {"fingerprint": read.fingerprint, "result": "pending"})
        return read.fingerprint

    def confirm(self, fingerprint: str) -> bytes:
        """P2 step 4, P3, P5: the operator confirmed `fingerprint`. The runtime is withdrawn first, and when it does
        not withdraw provisioning is refused and nothing changes. Then the trust store, the floor, the time floor
        and the epoch id start again from the anchor, whatever was held before, a locked PEP is unlocked, and a
        reconciling one leaves the state with its intent record gone and the record it owed not sent."""
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
        try:
            self.adapter.deactivate(POLICY_LAPSED)
        except Exception as error:  # noqa: BLE001 - P5: never provisioned over a runtime that still runs a release
            raise PepRefused(f"the runtime does not withdraw, so the PEP is not provisioned over it (P5): {error}") from None
        self.reconciling, self.retry_runtime, self.due = None, False, None
        for name in ("active.json", "staged.json", "pending.json", "fresh.json"):
            self.store.remove(name)
        self.trust = store.save(self.store.path("trust.json"))
        self.store.write("floor.json", _FLOOR, {"stream": read.stream, "seq": 0, "ids": []})
        self.store.write("counter.json", _COUNTER, {"counter": self.counter})
        self.store.write("setting.json", _SETTING, {"expiry": self.expiry_response})
        self.store.write_bytes("anchor.json", raw)
        self.store.remove("anchor.pending")
        self.stream, self.floor, self.locked, self.provisioned, self.held = read.stream, Floor(), False, True, False
        self.fresh, self.kept, self.epoch, self.time_taken = read.fresh, None, 0, False      # P3, H15, H16
        self.active = self.previous = self.staged = None
        self.recent.clear()                                          # H5: no policy made what the ring holds
        self._keep_blobs()
        self.audit.append("distribution", "provisioned", {"fingerprint": read.fingerprint, "stream": read.stream,
                                                          "result": "provisioned"})
        return self._record("provisioned")
