# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Grants: what the owner of a resource signs to let a request through a rule that needs one.

A grant names what it allows, not who holds it. The gateway reads it as one more field of the request (`grant`:
none, valid, invalid or expired) and the policy decides what each is worth, so a grant held by a person, a
script or a model is the same grant.

    prismpath gateway grant --path-class admin --method-class read --ttl 3600

prints the header value a client sends as `X-PrismPath-Grant`. It is `<document>.<signature>`, both base64url
without padding. The document is canon/2:

    format          prismpath.grant/1
    grant_id        32 lower case hex digits, random
    key_id          SHA-256 of the authority public key that signed it (the gateway home's authority key)
    policy_sha256   SHA-256 of the policy image it was issued under; a grant does not carry over to another policy
    path_classes    the route classes it covers, sorted, at least one
    method_classes  the method classes it covers (read, write, delete, other), sorted, at least one
    not_before      Unix seconds
    expires         Unix seconds, after not_before, at most MAX_LIFETIME later

and the signature is Ed25519 over GRANT_DOMAIN followed by the document's bytes.

A request reads
  none     without the header;
  valid    with one header whose signature verifies under the gateway's authority key, issued under the policy the
           gateway runs, not revoked, `not_before <= now < expires`, covering the request's path and method class;
  expired  when the grant is all of that except that `now >= expires`;
  invalid  otherwise: more than one header, a value that is too long or not of the form, a document that is not
           canonical or not of the format, a signature that does not verify, another key or policy, a revoked
           grant, a grant not yet in force, or one that does not cover this request.

Revocation is the file `grants.revoked` in the gateway home, one grant id per line, read again whenever it
changes, so `prismpath gateway revoke ID` takes effect on the next request. A revocation list that cannot be read
makes every grant read invalid.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, Optional, Sequence, Tuple

from prismpath.kernel import canon2

FORMAT = "prismpath.grant/1"
GRANT_DOMAIN = b"prismpath.grant/1\x00"
MAX_VALUE = 4096
MAX_LIFETIME = 30 * 24 * 3600
REVOKED_FILE = "grants.revoked"
METHOD_CLASSES = ("delete", "other", "read", "write")
KEYS = ("expires", "format", "grant_id", "key_id", "method_classes", "not_before", "path_classes", "policy_sha256")

_B64 = re.compile(r"^[A-Za-z0-9_-]+$")
_ID = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CLASS = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


class GrantError(ValueError):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    if not _B64.match(text) or len(text) % 4 == 1:
        raise GrantError("not base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if _b64(raw) != text:
        raise GrantError("not the canonical base64url of its bytes")
    return raw


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _classes(values: Iterable[str], allowed: Optional[Sequence[str]], what: str) -> list:
    out = sorted(set(values))
    if not out:
        raise GrantError(f"a grant covers at least one {what}")
    for value in out:
        if not isinstance(value, str) or not _CLASS.match(value) or value in ("unknown", "other") and what == "path class":
            raise GrantError(f"{value!r} is not a {what} a grant can cover")
        if allowed is not None and value not in allowed:
            raise GrantError(f"{value!r} is not a {what} ({', '.join(allowed)})")
    return out


def document_ok(doc) -> bool:
    """Whether `doc` is a well formed grant document (the signature and the request are checked elsewhere)."""
    try:
        if not isinstance(doc, dict) or tuple(sorted(doc)) != KEYS or doc["format"] != FORMAT:
            return False
        if not _ID.match(str(doc["grant_id"])) or not _HEX64.match(str(doc["key_id"])) \
                or not _HEX64.match(str(doc["policy_sha256"])):
            return False
        for key in ("not_before", "expires"):
            if type(doc[key]) is not int or doc[key] < 0:
                return False
        if not doc["not_before"] < doc["expires"] <= doc["not_before"] + MAX_LIFETIME:
            return False
        for key, allowed, what in (("path_classes", None, "path class"), ("method_classes", METHOD_CLASSES, "method class")):
            values = doc[key]
            if not isinstance(values, list) or _classes(values, allowed, what) != values:
                return False
        return True
    except (GrantError, KeyError, TypeError):
        return False


def issue(home: Path, policy_sha256: str, path_classes: Sequence[str], method_classes: Sequence[str],
          ttl: int, now: Optional[int] = None, grant_id: Optional[str] = None) -> Tuple[str, Dict[str, object]]:
    """Sign a grant with the gateway home's authority key; (header value, document)."""
    from prismpath.agent import commands
    from prismpath.hotswap import policy_pack
    if type(ttl) is not int or not 0 < ttl <= MAX_LIFETIME:
        raise GrantError(f"a grant lasts from 1 second to {MAX_LIFETIME} seconds, not {ttl!r}")
    start = int(time.time()) if now is None else int(now)
    key_path, pub_path = commands._key_paths(Path(home), "authority")
    if not key_path.is_file() or not pub_path.is_file():
        raise GrantError(f"{home} has no authority key; run `prismpath gateway init` first")
    doc = {"format": FORMAT, "grant_id": grant_id or secrets.token_hex(16), "key_id": _sha256(pub_path.read_bytes()),
           "policy_sha256": policy_sha256, "path_classes": _classes(path_classes, None, "path class"),
           "method_classes": _classes(method_classes, METHOD_CLASSES, "method class"),
           "not_before": start, "expires": start + ttl}
    if not document_ok(doc):
        raise GrantError("the grant would not be well formed")
    body = canon2.dumps(doc)
    signature = policy_pack._load_private(str(key_path)).sign(GRANT_DOMAIN + body)
    return f"{_b64(body)}.{_b64(signature)}", doc


class Verifier:
    """Reads the grant header of a request against one gateway's authority key, policy and revocation list."""

    def __init__(self, authority_pub: bytes, policy_sha256: str, revoked_path: Optional[Path] = None, clock=time.time):
        from prismpath.hotswap import policy_pack
        _Priv, Pub, _ser, self._invalid = policy_pack._ed25519()
        self._key = Pub.from_public_bytes(authority_pub)
        self.key_id = _sha256(authority_pub)
        self.policy_sha256 = policy_sha256
        self.revoked_path = Path(revoked_path) if revoked_path else None
        self.clock = clock
        self._lock = threading.Lock()
        self._revoked_stamp: Optional[tuple] = None
        self._revoked: Optional[frozenset] = frozenset()

    def revoked(self) -> Optional[frozenset]:
        """The revoked grant ids, or None when the list exists but cannot be read."""
        if self.revoked_path is None:
            return frozenset()
        with self._lock:
            try:
                st = os.stat(self.revoked_path)
            except FileNotFoundError:
                self._revoked_stamp, self._revoked = None, frozenset()
                return self._revoked
            except OSError:
                return None
            stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
            if stamp != self._revoked_stamp:
                try:
                    lines = self.revoked_path.read_text(encoding="ascii").split("\n")
                    ids = [line.strip() for line in lines if line.strip()]
                    self._revoked = frozenset(ids) if all(_ID.match(i) for i in ids) else None
                except (OSError, UnicodeDecodeError):
                    self._revoked = None
                self._revoked_stamp = stamp
            return self._revoked

    def read(self, values: Sequence[str], path_class: str, method_class: str) -> Tuple[str, Optional[Dict[str, str]]]:
        """(state, record) of a request's grant header values; the record is `{"grant_id", "grant_sha256"}` of a
        grant whose signature verified (valid, expired, or refused for scope, time or revocation), else None."""
        if not values:
            return "none", None
        if len(values) != 1 or len(values[0]) > MAX_VALUE:
            return "invalid", None
        try:
            head, mark, tail = values[0].strip().partition(".")
            if not mark:
                return "invalid", None
            body, signature = _unb64(head), _unb64(tail)
            doc = canon2.loads(body)
            if canon2.dumps(doc) != body or not document_ok(doc) or doc["key_id"] != self.key_id:
                return "invalid", None
            self._key.verify(signature, GRANT_DOMAIN + body)
        except self._invalid:
            return "invalid", None
        except Exception:   # noqa: BLE001 - anything that cannot be read is invalid
            return "invalid", None
        record = {"grant_id": doc["grant_id"], "grant_sha256": _sha256(body)}
        revoked = self.revoked()
        if doc["policy_sha256"] != self.policy_sha256 or revoked is None or doc["grant_id"] in revoked:
            return "invalid", record
        if path_class not in doc["path_classes"] or method_class not in doc["method_classes"]:
            return "invalid", record
        now = int(self.clock())
        if now < doc["not_before"]:
            return "invalid", record
        if now >= doc["expires"]:
            return "expired", record
        return "valid", record


def revoke(home: Path, grant_id: str) -> bool:
    """Add `grant_id` to the home's revocation list; False when it was already there."""
    if not _ID.match(grant_id):
        raise GrantError(f"{grant_id!r} is not a grant id (32 lower case hex digits)")
    path = Path(home) / REVOKED_FILE
    existing = path.read_text(encoding="ascii").split() if path.exists() else []
    if grant_id in existing:
        return False
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (grant_id + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    return True
