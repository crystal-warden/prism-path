# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""PolicyHost — the Attested + Audited-and-atomic half of the secure hot-swap
(spec-secure-hotswap §3.3-§3.4).

Holds the single active policy. `swap(pack)` runs the full pipeline — signature -> envelope ->
monotonic-version -> stage-and-parse a shadow -> commit -> single atomic reference flip, and writes
every attempt, accepted or rejected, to the Merkle-rooted audit log (`audit_log.py`, OTS-anchorable via
`ledger_ots`). Any failure at any stage leaves the previous policy active with no partial state,
and the last-known-good pack is retained for `rollback()`.

Anti-rollback is a file-backed monotonic counter (`<state_dir>/active_version`, fsync'd) — the
software tier: tamper-evident through the ledger, not tamper-proof. The eFUSE/secure-element
counter is the hardware follow-on (spec §7).

The active policy is also on disk, so the process that swapped is not the only one that knows what is
active: the `swap attest` command and the console's attestation panel each build a fresh host over the
same state directory and report the policy the last accepted swap committed. The record,
`<state_dir>/active_policy.json`, names its image in `image_file`, a content addressed file
`active-<sha256>.ppt` beside it, so the previous image stays readable until the record flips and a
death at any step leaves exactly one policy that a restarted host can restore. A record whose image is
missing or whose digest disagrees is not restored; the host then starts with no active policy and
writes `active_unreadable` to the ledger. A state directory written before the image was content
addressed has a record without `image_file` beside `active.ppt`; it is read as it was and replaced by
the new layout at the next swap or rollback.
"""
from __future__ import annotations

import os
import re
import threading
from datetime import datetime, timezone
from typing import List, Optional

from prismpath.distribution import devbuild, legacy
from prismpath.hotswap import policy_pack as pp
from prismpath.ledgers.audit_log import AuditLog
from prismpath.ledgers import root_statement
from prismpath.onion import keys
from prismpath import canon

LEGACY_IMAGE = "active.ppt"
_IMAGE_FILE = re.compile(r"^active-[0-9a-f]{64}\.ppt$")
_IMAGE_LEAVINGS = re.compile(r"^active(-[0-9a-f]{64})?\.ppt(\.tmp)?$")


_fsync_dir = canon.fsync_dir


def image_file_name(sha256: str) -> str:
    return f"active-{sha256}.ppt"


def _authority_key_ids(pubkey_paths: List[str]) -> List[str]:
    """The key id of each authority public key file (sha256 of its raw bytes), unreadable ones skipped:
    the host itself reports those when it verifies."""
    ids = []
    for path in pubkey_paths:
        try:
            with open(path, "rb") as handle:
                ids.append(canon.sha256_hex(handle.read()))
        except OSError:
            continue
    return ids


class SwapRejected(Exception):
    """Raised by swap(..., strict=True) when a swap is refused; reasons on `.reasons`."""

    def __init__(self, reasons: List[str]):
        super().__init__(",".join(reasons))
        self.reasons = reasons


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class PolicyHost:
    def __init__(self, state_dir: str, pubkey_paths: List[str], envelope: dict,
                 audit_path: Optional[str] = None, revoked: frozenset = frozenset(),
                 instance_key: Optional[keys.Signer] = None):
        self.state_dir = state_dir
        self.pubkey_paths = list(pubkey_paths)
        self.envelope = envelope
        self.revoked = revoked
        os.makedirs(state_dir, exist_ok=True)
        # The instance key signs a root statement after every audit event, so each swap, refusal and
        # attestation is covered by a signed root as soon as it is written. It defaults to
        # $PRISMPATH_INSTANCE_KEY and must not be one of the authority keys this host trusts.
        if instance_key is None:
            instance_key = root_statement.key_from_env()
        root_statement.check_separation(instance_key, _authority_key_ids(self.pubkey_paths))
        self.audit = AuditLog(audit_path or os.path.join(state_dir, "swaps.log"), instance_key=instance_key,
                              sign_appends=True, policy_of=self._policy_identity)
        self._lock = threading.RLock()
        self._active: Optional[dict] = None    # {sha256, version, key_id, envelope_id, image, since}
        self._prev: Optional[dict] = None      # last-known-good, for rollback
        self._version_path = os.path.join(state_dir, "active_version")
        self._recovery_recorded = False
        self._active_file = LEGACY_IMAGE
        pending = self._recover()
        self._load_active()
        self._complete_recovery(pending)

    # -- persisted monotonic version (anti-rollback floor) --
    def _stored_version(self) -> int:
        try:
            with open(self._version_path) as version_file:
                return int(version_file.read().strip() or "0")
        except (FileNotFoundError, ValueError):
            return 0

    def _persist_version(self, version: int) -> None:
        canon.atomic_write(self._version_path, str(version))
        _fsync_dir(self.state_dir)

    # -- the commit protocol --
    # A swap that passed every check is committed in a fixed order, each step durable (the file and
    # its directory entry fsynced) before the next:
    #   1. the intent record, <state_dir>/pending_swap, naming the image hash and version;
    #   2. the version floor;
    #   3. the audit event, the evidence that the swap was accepted;
    #   4. the new image, `active-<sha256>.ppt`, written beside the one in use and never over it;
    #   5. the active policy record, `active_policy.json` naming that image: the flip point, an atomic
    #      rename, followed by the reference flip in memory, an assignment that cannot fail;
    #   6. the superseded images removed, then the intent record removed.
    # Rollback is the same commit with the last-known-good policy as the target: the intent record
    # (marked "op": "rollback"), the audit event, the image, the record, the clean up, with no floor
    # step because a rollback never lowers the floor.
    # A failure at 1 to 5 raises and leaves the previous policy active, because the record still names
    # an image that is still there. A death at any step leaves exactly one policy a restarted host can
    # restore: the previous one up to the record rename, the new one after it. What it leaves behind is
    # an intent record, possibly a floor one step ahead of the last accepted swap, and possibly an image
    # the record does not name, which is never read and is removed by the next commit that finishes.
    # Recovery reads the intent record at the next start and at the next swap: it is written to the
    # audit log as `swap_incomplete` (`rollback_incomplete` for a rollback), and when the record
    # already names the intended policy the commit is finished, the superseded images and the intent
    # removed. The same image at the same version is allowed to commit again even though the floor
    # already equals its version, so a crash between the floor and the evidence does not strand a
    # legitimate policy behind its own floor. A different version or a different image at that version
    # is still rejected by the floor.
    def _pending_path(self) -> str:
        return os.path.join(self.state_dir, "pending_swap")

    def _read_pending(self) -> Optional[dict]:
        try:
            with open(self._pending_path(), encoding="utf-8", newline="") as pending_file:
                return canon.loads_document(pending_file.read())
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as error:
            raise RuntimeError(f"unreadable intent record {self._pending_path()}: {error}") from error

    def _write_pending(self, to_hash: str, version, op: Optional[str] = None) -> None:
        record = {"to_hash": to_hash, "version": version}
        if op is not None:
            record["op"] = op
        canon.atomic_write_bytes(self._pending_path(), canon.canon2_bytes(canon.tagged(record)))
        _fsync_dir(self.state_dir)

    def _clear_pending(self) -> None:
        try:
            os.remove(self._pending_path())
        except FileNotFoundError:
            return
        _fsync_dir(self.state_dir)

    def _recover(self) -> Optional[dict]:
        """Record an interrupted commit, once per process, and return its intent so the floor check can
        let the same swap complete. The audit append may itself fail; then the exception propagates and
        nothing else happens, which is the fail closed answer when evidence cannot be recorded."""
        pending = self._read_pending()
        if pending is not None and not self._recovery_recorded:
            action = "rollback_incomplete" if pending.get("op") == "rollback" else "swap_incomplete"
            self.audit.append("policy_host", action, {
                "to_hash": pending.get("to_hash"), "version": pending.get("version"),
                "stored_version": self._stored_version(), "result": "incomplete"})
            self._recovery_recorded = True
        return pending

    def _complete_recovery(self, pending: Optional[dict]) -> None:
        """A commit that died after the record flip, before its clean up, is finished: the record names
        the intended policy, so the superseded images and the intent record are removed. A commit that
        died before the flip is left as it is; the old policy is active and the retry completes it.
        Clean up that fails is left for the next start."""
        active = self._active
        if pending is None or active is None:
            return
        if active.get("sha256") == pending.get("to_hash") and active.get("version") == pending.get("version"):
            try:
                self._finish_commit(self._active_file)
            except OSError:
                pass

    # -- the active policy record: what a fresh host over this state directory restores --
    def _active_record_path(self) -> str:
        return os.path.join(self.state_dir, "active_policy.json")

    def _persist_active(self, policy: dict) -> str:
        """The image under its own name, then the record naming it, each durable before the next. The
        image of the policy in use is never written over, and an image already there under the new
        name is written again whatever it holds, so a leftover is never trusted. Returns the file name."""
        name = image_file_name(policy["sha256"])
        canon.atomic_write_bytes(os.path.join(self.state_dir, name), policy["image"])
        _fsync_dir(self.state_dir)
        record = {key: value for key, value in policy.items() if key != "image"}
        record["image_file"] = name
        canon.atomic_write_bytes(self._active_record_path(), canon.canon2_bytes(canon.tagged(record)))
        _fsync_dir(self.state_dir)
        return name

    def _finish_commit(self, keep: str) -> None:
        """After the record is durable: remove every image the record does not name (the superseded
        one, a leftover of a dead commit, the image of the old layout), then the intent record. A
        removal that fails only leaves a file nothing reads."""
        try:
            leavings = [name for name in os.listdir(self.state_dir) if name != keep and _IMAGE_LEAVINGS.fullmatch(name)]
        except OSError:
            leavings = []
        removed = False
        for name in leavings:
            try:
                os.remove(os.path.join(self.state_dir, name))
                removed = True
            except OSError:
                pass
        if removed:
            try:
                _fsync_dir(self.state_dir)
            except OSError:
                pass
        self._clear_pending()

    def _load_active(self) -> None:
        """Restore the policy a previous process committed. Nothing on disk means nothing active. A
        record whose image is missing, unreadable or of another digest is not restored, and the
        ledger says so; the host then holds no active policy, the fail closed answer."""
        try:
            with open(self._active_record_path(), encoding="utf-8", newline="") as record_file:
                record = canon.loads_document(record_file.read())
        except FileNotFoundError:
            return
        except (OSError, ValueError) as error:
            self.audit.append("policy_host", "active_unreadable", {"reason": f"record:unreadable:{error}", "result": "not_restored"})
            return
        # The shape check comes before anything reads a field, so every branch below can rely on a dict.
        if not isinstance(record, dict):
            self.audit.append("policy_host", "active_unreadable", {"reason": "record:not-an-object", "result": "not_restored"})
            return
        record.pop(canon.ENCODING_KEY, None)     # the tag says how the record was read, not what is active
        # A record without `image_file` is the old layout, whose image is `active.ppt`.
        name = record.get("image_file", LEGACY_IMAGE)
        if name != LEGACY_IMAGE and not (isinstance(name, str) and _IMAGE_FILE.fullmatch(name)):
            self.audit.append("policy_host", "active_unreadable", {"to_hash": record.get("sha256"), "reason": "record:image-file-invalid", "result": "not_restored"})
            return
        try:
            with open(os.path.join(self.state_dir, name), "rb") as image_file:
                image = image_file.read()
        except OSError as error:
            self.audit.append("policy_host", "active_unreadable", {"to_hash": record.get("sha256"), "reason": f"image:unreadable:{error.errno}", "result": "not_restored"})
            return
        if pp.sha256_hex(image) != record.get("sha256"):
            self.audit.append("policy_host", "active_unreadable", {"to_hash": record.get("sha256"), "reason": "image:digest-mismatch", "result": "not_restored"})
            return
        self._active = {**record, "image": image}
        self._active_file = name

    def _reject(self, to_hash: Optional[str], version, reasons: List[str], strict: bool) -> dict:
        self.audit.append("policy_host", "swap_rejected", {
            "from_hash": self._active["sha256"] if self._active else None,
            "to_hash": to_hash, "version": version, "reasons": reasons, "result": "rejected"})
        if strict:
            raise SwapRejected(reasons)
        return {"ok": False, "reasons": reasons}

    # -- the distribution floor: once a release came by distribution, the older path is closed (L2) --
    def _distribution_floor(self) -> bool:
        """True when this state directory's enforcement point has committed a distribution envelope, or when
        it was provisioned and its floor file is missing or cannot be read, which is answered the same way
        (fail closed). The marks of its anchor part close the path too: an install statement it ever held (IS9),
        and a release it committed on the stream it follows, whatever provisioning came after (L2, P3). Only a
        directory no enforcement point was provisioned in, or one whose readable floor is still 0 and whose marks
        say neither, keeps the older path open."""
        from prismpath.distribution import install, kinds, trust
        dist = os.path.join(self.state_dir, "dist")
        stream = None
        if os.path.exists(os.path.join(dist, "anchor.json")):
            try:
                with open(os.path.join(dist, "anchor.json"), "rb") as anchor_file:
                    stream = trust.read_anchor(anchor_file.read()).stream
            except (OSError, ValueError, kinds.Refused):
                return True
        if install.older_forms_refused(dist, stream):
            return True
        path = os.path.join(dist, "floor.json")
        if not os.path.exists(path):
            return os.path.exists(os.path.join(dist, "anchor.json"))
        try:
            with open(path, "rb") as floor_file:
                floor = canon.loads_document(floor_file.read())
            return not (isinstance(floor, dict) and floor.get("seq") == 0)
        except (OSError, ValueError):
            return True

    def swap(self, ppt_path: str, *, allow_unsigned: bool = False, strict: bool = False) -> dict:
        """Verify -> envelope -> version -> stage -> atomic flip. Returns {ok, reasons} (or the
        active dict on success). Every outcome is one audit event; the active policy only changes
        on full success. A state directory whose enforcement point committed a distribution envelope
        refuses every pack with `dist:legacy-refused` (L2). A pack is the sealed `policy.ppt` envelope beside the
        image, or the older `ppt-pack/1` manifest, read with a `legacy_form` audit event (L3). `allow_unsigned` is an escape hatch that works
        only in a dev build. In a production build the hatch is refused and the pack is checked as signed."""
        with self._lock:
            if self._distribution_floor():
                return self._reject(None, None, ["dist:legacy-refused"], strict)
            pending = self._recover()
            if allow_unsigned:
                # an escape hatch: a dev build lets it through, a production build refuses it and the signed check
                # runs instead (docs/design/spec-policy-distribution.md, D1, D2)
                try:
                    devbuild.hatch("--allow-unsigned", self.audit)
                except devbuild.HatchRefused:
                    allow_unsigned = False
            image = None
            try:
                with open(ppt_path, "rb") as image_file:
                    image = image_file.read()
            except OSError as error:
                return self._reject(None, None, [f"image:unreadable:{error.errno}"], strict)

            to_hash = pp.sha256_hex(image)

            if allow_unsigned:
                ok, reasons = pp.validate_image(image, caps=self.envelope.get("caps"))
                if not ok:
                    return self._reject(to_hash, None, reasons, strict)
                manifest = {"image_sha256": to_hash, "version": None, "key_id": None,
                            "envelope_id": self.envelope.get("envelope_id"), "unsigned": True}
            else:
                ok, reasons, manifest = pp.verify_pack(ppt_path, self.pubkey_paths, self.revoked)
                if not ok:
                    return self._reject(to_hash, None, reasons, strict)
                if pp.is_older(manifest):           # L3: an older pack is read, and says so in the log
                    legacy.record(self.audit, legacy.PACK, reader="policy_host.swap", sha256=to_hash,
                                  key_id=manifest.get("key_id"))
                ok, reasons = pp.check_envelope(manifest, image, self.envelope)
                if not ok:
                    return self._reject(to_hash, manifest.get("version"), reasons, strict)
                version = manifest["version"]
                stored = self._stored_version()
                # The floor admits one exception: the very swap an interrupted commit had already
                # advanced the floor for, identified by both its version and its image hash.
                resuming = (pending is not None and pending.get("op") != "rollback"
                            and pending.get("version") == version and pending.get("to_hash") == to_hash)
                if version < stored or (version == stored and not resuming):
                    return self._reject(to_hash, version,
                                        [f"version:not-monotonic:{version}<={stored}"], strict)

            # stage a shadow: fully parse the image into the register-machine views before any flip
            try:
                staged = pp.read_ppt_header(image)
            except ValueError as error:
                return self._reject(to_hash, manifest.get("version"), [str(error)], strict)

            record = {"sha256": to_hash, "version": manifest.get("version"),
                      "key_id": manifest.get("key_id"),
                      "envelope_id": manifest.get("envelope_id"),
                      "unsigned": bool(manifest.get("unsigned")),
                      "overlay_of": manifest.get("overlay_of"),
                      "counts": staged, "since": _now(),
                      "ppt_path": os.path.abspath(ppt_path)}
            return self.install_verified(image, record)

    def install_verified(self, image: bytes, record: dict, evidence: Optional[dict] = None) -> dict:
        """The commit half of a swap, for an image every check has already passed: by `swap` after its own
        checks, and by the distribution enforcement point after the verifier (spec-policy-distribution.md,
        C4). `record` is the active record without the image. Intent, floor when the record has a version,
        evidence, image, record and flip, clean up; see the protocol note above. `evidence` adds members to
        the audit event."""
        with self._lock:
            new_active = {**record, "image": image}
            to_hash = record["sha256"]
            self._write_pending(to_hash, record.get("version"))
            if record.get("version") is not None:
                self._persist_version(record["version"])
            self.audit.append("policy_host", "swap", {
                "from_hash": self._active["sha256"] if self._active else None,
                "to_hash": to_hash, "version": record.get("version"),
                "key_id": record.get("key_id"), "envelope_id": record.get("envelope_id"),
                "unsigned": bool(record.get("unsigned")), "overlay_of": record.get("overlay_of"),
                "result": "accepted", **(evidence or {})})
            self._active_file = self._persist_active(new_active)
            self._prev, self._active = self._active, new_active
            self._finish_commit(self._active_file)
            return {"ok": True, **self.active()}

    def withdraw(self, cause: str) -> dict:
        """Hold no policy from now on: the distribution enforcement point lapsed, is locked or cannot read
        its trust store (spec-policy-distribution.md, X3). The evidence first, then the record, then the
        images, so a death at any step leaves either the old policy or none, never a half."""
        with self._lock:
            if self._active is None:
                return {"ok": True, "active": None}
            self.audit.append("policy_host", "withdraw", {"from_hash": self._active["sha256"], "cause": cause,
                                                          "result": "withdrawn"})
            try:
                os.remove(self._active_record_path())
            except FileNotFoundError:
                pass
            _fsync_dir(self.state_dir)
            self._active, self._prev = None, None
            self._finish_commit("")
            return {"ok": True, "active": None}

    def _policy_identity(self) -> Optional[dict]:
        """The pack in force when a root statement is signed, as the statement records it."""
        active_policy = getattr(self, "_active", None)
        if active_policy is None:
            return None
        return {"image_sha256": active_policy["sha256"], "version": active_policy["version"],
                "key_id": active_policy.get("key_id"), "unsigned": active_policy.get("unsigned")}

    def active(self) -> dict:
        if self._active is None:
            return {"active": None}
        active_policy = self._active
        return {"active": active_policy["sha256"], "version": active_policy["version"], "since": active_policy["since"],
                "unsigned": active_policy["unsigned"], "envelope_id": active_policy["envelope_id"],
                "overlay_of": active_policy.get("overlay_of")}

    def rollback(self) -> dict:
        """Restore the last-known-good policy (one deep). Committed in the swap's order, intent then
        evidence then the image and the record, so an event that cannot be written raises
        AuditWriteError with the previous policy still active and nothing flipped. Does NOT lower the
        version floor (anti-rollback still holds against replayed old packs)."""
        with self._lock:
            if self._distribution_floor():
                return {"ok": False, "reasons": ["dist:legacy-refused"]}
            self._recover()
            if self._prev is None:
                return {"ok": False, "reasons": ["rollback:no-previous"]}
            target = self._prev
            self._write_pending(target["sha256"], target["version"], op="rollback")
            self.audit.append("policy_host", "rollback", {
                "to_hash": target["sha256"], "version": target["version"],
                "result": "rolled_back"})
            self._active_file = self._persist_active(target)
            self._active, self._prev = target, None
            self._finish_commit(self._active_file)
            return {"ok": True, **self.active()}

    def attest(self) -> dict:
        """Append a point-in-time attestation of the active policy to the ledger."""
        active_policy = self.active()
        self.audit.append("policy_host", "attestation",
                          {"active": active_policy.get("active"), "version": active_policy.get("version"),
                           "overlay_of": active_policy.get("overlay_of"), "ts": _now()})
        return active_policy

    def anchor_attestations(self, out_dir: str, label: str) -> dict:
        """Anchor the audit trail's leaves to Bitcoin via OTS (delegates to ledger_ots)."""
        from prismpath.ledgers import ledger_ots
        return ledger_ots.anchor(list(self.audit.leaves), out_dir, label)

    def history(self) -> List[dict]:
        """The swap/attestation timeline, oldest first — reconstructs 'policy X live [T1,T2]'."""
        return list(self.audit.events)
