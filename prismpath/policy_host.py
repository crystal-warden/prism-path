"""PolicyHost — the Attested + Audited-and-atomic half of the secure hot-swap
(spec-secure-hotswap §3.3-§3.4).

Holds the single active policy. `swap(pack)` runs the full pipeline — signature -> envelope ->
monotonic-version -> stage-and-parse a shadow -> single atomic reference flip — and writes every
attempt, accepted or rejected, to the Merkle-rooted audit log (`audit_log.py`, OTS-anchorable via
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

from prismpath import policy_pack as pp
from prismpath.audit_log import AuditLog


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

    # -- persisted monotonic version (anti-rollback floor) --
    def _stored_version(self) -> int:
        try:
            with open(self._version_path) as f:
                return int(f.read().strip() or "0")
        except (FileNotFoundError, ValueError):
            return 0

    def _persist_version(self, version: int) -> None:
        tmp = self._version_path + ".tmp"
        with open(tmp, "w") as f:
            f.write(str(version))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._version_path)

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
            image = None
            try:
                with open(ppt_path, "rb") as f:
                    image = f.read()
            except OSError as e:
                return self._reject(None, None, [f"image:unreadable:{e.errno}"], strict)

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
                if version <= self._stored_version():
                    return self._reject(to_hash, version,
                                        [f"version:not-monotonic:{version}<={self._stored_version()}"],
                                        strict)

            # stage a shadow: fully parse the image into the register-machine views before any flip
            try:
                staged = pp.read_ppt_header(image)
            except ValueError as e:
                return self._reject(to_hash, manifest.get("version"), [str(e)], strict)

            # atomic flip
            new_active = {"sha256": to_hash, "version": manifest.get("version"),
                          "key_id": manifest.get("key_id"),
                          "envelope_id": manifest.get("envelope_id"),
                          "unsigned": bool(manifest.get("unsigned")),
                          "counts": staged, "image": image, "since": _now(),
                          "ppt_path": os.path.abspath(ppt_path)}
            self._prev, self._active = self._active, new_active
            if manifest.get("version") is not None:
                self._persist_version(manifest["version"])

            self.audit.append("policy_host", "swap", {
                "from_hash": self._prev["sha256"] if self._prev else None,
                "to_hash": to_hash, "version": manifest.get("version"),
                "key_id": manifest.get("key_id"), "envelope_id": manifest.get("envelope_id"),
                "unsigned": bool(manifest.get("unsigned")), "result": "accepted"})
            return {"ok": True, **self.active()}

    def active(self) -> dict:
        if self._active is None:
            return {"active": None}
        a = self._active
        return {"active": a["sha256"], "version": a["version"], "since": a["since"],
                "unsigned": a["unsigned"], "envelope_id": a["envelope_id"]}

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
        a = self.active()
        self.audit.append("policy_host", "attestation",
                          {"active": a.get("active"), "version": a.get("version"), "ts": _now()})
        return a

    def anchor_attestations(self, out_dir: str, label: str) -> dict:
        """Anchor the audit trail's leaves to Bitcoin via OTS (delegates to ledger_ots)."""
        from prismpath import ledger_ots
        return ledger_ots.anchor(list(self.audit.leaves), out_dir, label)

    def history(self) -> List[dict]:
        """The swap/attestation timeline, oldest first — reconstructs 'policy X live [T1,T2]'."""
        return list(self.audit.events)
