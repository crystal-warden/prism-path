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
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import List, Optional

from prismpath.hotswap import policy_pack as pp
from prismpath.ledgers.audit_log import AuditLog
from prismpath import canon

class SwapRejected(Exception):
    """Raised by swap(..., strict=True) when a swap is refused; reasons on `.reasons`."""

    def __init__(self, reasons: List[str]):
        super().__init__(",".join(reasons))
        self.reasons = reasons


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class PolicyHost:
    def __init__(self, state_dir: str, pubkey_paths: List[str], envelope: dict,
                 audit_path: Optional[str] = None, revoked: frozenset = frozenset()):
        self.state_dir = state_dir
        self.pubkey_paths = list(pubkey_paths)
        self.envelope = envelope
        self.revoked = revoked
        os.makedirs(state_dir, exist_ok=True)
        self.audit = AuditLog(audit_path or os.path.join(state_dir, "swaps.log"))
        self._lock = threading.Lock()
        self._active: Optional[dict] = None    # {sha256, version, key_id, envelope_id, image, since}
        self._prev: Optional[dict] = None      # last-known-good, for rollback
        self._version_path = os.path.join(state_dir, "active_version")
        self._recovery_recorded = False
        self._recover()

    # -- persisted monotonic version (anti-rollback floor) --
    def _stored_version(self) -> int:
        try:
            with open(self._version_path) as version_file:
                return int(version_file.read().strip() or "0")
        except (FileNotFoundError, ValueError):
            return 0

    def _persist_version(self, version: int) -> None:
        canon.atomic_write(self._version_path, str(version))

    # -- the commit protocol --
    # A swap that passed every check is committed in a fixed order, each step durable before the next:
    #   1. the intent record, <state_dir>/pending_swap, naming the image hash and version;
    #   2. the version floor;
    #   3. the audit event, the evidence that the swap was accepted;
    #   4. the reference flip, an assignment that cannot fail;
    #   5. the intent record removed.
    # A failure at 1, 2 or 3 raises and leaves the previous policy active, because nothing has flipped.
    # What it leaves behind is an intent record, and possibly a floor one step ahead of the last
    # accepted swap. Recovery reads that record at the next start and at the next swap: it is written
    # to the audit log as `swap_incomplete`, and the same image at the same version is allowed to
    # commit again even though the floor already equals its version, so a crash between the floor and
    # the evidence does not strand a legitimate policy behind its own floor. A different version or a
    # different image at that version is still rejected by the floor.
    def _pending_path(self) -> str:
        return os.path.join(self.state_dir, "pending_swap")

    def _read_pending(self) -> Optional[dict]:
        try:
            with open(self._pending_path()) as pending_file:
                return json.loads(pending_file.read())
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as error:
            raise RuntimeError(f"unreadable intent record {self._pending_path()}: {error}") from error

    def _write_pending(self, to_hash: str, version) -> None:
        canon.atomic_write(self._pending_path(), json.dumps({"to_hash": to_hash, "version": version}))

    def _clear_pending(self) -> None:
        try:
            os.remove(self._pending_path())
        except FileNotFoundError:
            pass

    def _recover(self) -> Optional[dict]:
        """Record an interrupted commit, once per process, and return its intent so the floor check can
        let the same swap complete. The audit append may itself fail; then the exception propagates and
        nothing else happens, which is the fail closed answer when evidence cannot be recorded."""
        pending = self._read_pending()
        if pending is not None and not self._recovery_recorded:
            self.audit.append("policy_host", "swap_incomplete", {
                "to_hash": pending.get("to_hash"), "version": pending.get("version"),
                "stored_version": self._stored_version(), "result": "incomplete"})
            self._recovery_recorded = True
        return pending

    def _reject(self, to_hash: Optional[str], version, reasons: List[str], strict: bool) -> dict:
        self.audit.append("policy_host", "swap_rejected", {
            "from_hash": self._active["sha256"] if self._active else None,
            "to_hash": to_hash, "version": version, "reasons": reasons, "result": "rejected"})
        if strict:
            raise SwapRejected(reasons)
        return {"ok": False, "reasons": reasons}

    def swap(self, ppt_path: str, *, allow_unsigned: bool = False, strict: bool = False) -> dict:
        """Verify -> envelope -> version -> stage -> atomic flip. Returns {ok, reasons} (or the
        active dict on success). Every outcome is one audit event; the active policy only changes
        on full success."""
        with self._lock:
            pending = self._recover()
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
                ok, reasons = pp.check_envelope(manifest, image, self.envelope)
                if not ok:
                    return self._reject(to_hash, manifest.get("version"), reasons, strict)
                version = manifest["version"]
                stored = self._stored_version()
                # The floor admits one exception: the very swap an interrupted commit had already
                # advanced the floor for, identified by both its version and its image hash.
                resuming = (pending is not None and pending.get("version") == version
                            and pending.get("to_hash") == to_hash)
                if version < stored or (version == stored and not resuming):
                    return self._reject(to_hash, version,
                                        [f"version:not-monotonic:{version}<={stored}"], strict)

            # stage a shadow: fully parse the image into the register-machine views before any flip
            try:
                staged = pp.read_ppt_header(image)
            except ValueError as error:
                return self._reject(to_hash, manifest.get("version"), [str(error)], strict)

            new_active = {"sha256": to_hash, "version": manifest.get("version"),
                          "key_id": manifest.get("key_id"),
                          "envelope_id": manifest.get("envelope_id"),
                          "unsigned": bool(manifest.get("unsigned")),
                          "overlay_of": manifest.get("overlay_of"),
                          "counts": staged, "image": image, "since": _now(),
                          "ppt_path": os.path.abspath(ppt_path)}
            # commit: intent, floor, evidence, then the flip; see the protocol note above
            self._write_pending(to_hash, manifest.get("version"))
            if manifest.get("version") is not None:
                self._persist_version(manifest["version"])
            self.audit.append("policy_host", "swap", {
                "from_hash": self._active["sha256"] if self._active else None,
                "to_hash": to_hash, "version": manifest.get("version"),
                "key_id": manifest.get("key_id"), "envelope_id": manifest.get("envelope_id"),
                "unsigned": bool(manifest.get("unsigned")), "overlay_of": manifest.get("overlay_of"),
                "result": "accepted"})
            self._prev, self._active = self._active, new_active
            self._clear_pending()
            return {"ok": True, **self.active()}

    def active(self) -> dict:
        if self._active is None:
            return {"active": None}
        active_policy = self._active
        return {"active": active_policy["sha256"], "version": active_policy["version"], "since": active_policy["since"],
                "unsigned": active_policy["unsigned"], "envelope_id": active_policy["envelope_id"],
                "overlay_of": active_policy.get("overlay_of")}

    def rollback(self) -> dict:
        """Restore the last-known-good policy (one deep). Audited; does NOT lower the version
        floor (anti-rollback still holds against replayed old packs)."""
        with self._lock:
            if self._prev is None:
                return {"ok": False, "reasons": ["rollback:no-previous"]}
            self._active, self._prev = self._prev, None
            self.audit.append("policy_host", "rollback", {
                "to_hash": self._active["sha256"], "version": self._active["version"],
                "result": "rolled_back"})
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
