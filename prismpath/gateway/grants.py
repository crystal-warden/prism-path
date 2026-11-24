# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Grants: what the owner of a resource signs to let a request through a rule that needs one.

A grant names what it allows, not who holds it. The gateway reads it as one more field of the request (`grant`:
none, valid, invalid or expired) and the policy decides what each is worth, so a grant held by a person, a
script or a model is the same grant.

    prismpath gateway grant --path-class admin --method-class read --ttl 3600

prints the header value a client sends as `X-PrismPath-Grant`. A grant is a distribution envelope
(spec-policy-distribution.md, section 13): artifact `grant`, target `gateway`, the gateway's stream, `seq` 1, the
policy it was issued under as `policy_sha256`, its lifetime as `not_before` and `expires` (at most MAX_LIFETIME),
and a `prismpath.dist-grant/1` body naming the route classes and method classes it covers. The header value is the
sealed envelope and the body, each base64url without padding, joined by a dot (GR1). Its id is the envelope id.

A request reads
  none     without the header;
  valid    with one header whose envelope verifies by the rules of GR2 (`verify.verify` with V2 to V7 and V9)
           against the gateway's trust store, issued under the policy the gateway runs, `not_before <= now <
           expires`, covering the request's path and method class;
  expired  when the grant is all of that except that `now >= expires`;
  invalid  otherwise: more than one header, a value that is too long or not of the form, an envelope or body the
           verifier refuses (a signature that does not verify, a key the store does not hold or has revoked, a
           revoked envelope id), another policy or stream, a grant not yet in force, or one that does not cover
           this request.

Revocation is the trust store's. A gateway home that follows a stream takes it from the signed `trust.revocation`
its PEP applied, where a grant is listed by its envelope id, and reads no other list (GR3). A home that holds its own
authority key holds the store in memory, that key alone, and lists in it the ids in `grants.revoked` in the home,
one per line, read again whenever the file changes, so `prismpath gateway revoke ID` takes effect on the next
request. A revocation list that cannot be read makes every grant read invalid.

The older form `prismpath.grant/1` (`<canon/2 document>.<signature>`, the signature Ed25519 over GRANT_DOMAIN and
the document) is still read for L3, in a home that holds its own authority key, as one branch on the first bytes
of the value. A home that follows a stream refuses it (L2).
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, Optional, Sequence, Tuple

from prismpath.distribution import envelope as env
from prismpath.distribution import kinds
from prismpath.distribution.kinds import Refused
from prismpath.kernel import canon2

FORMAT = "prismpath.grant/1"                       # the older form, read for L3
GRANT_FORMAT = kinds.GRANT_FORMAT
LOCAL_STREAM = "gateway"                           # the stream of a home that holds its own authority key
GRANT_DOMAIN = b"prismpath.grant/1\x00"
MAX_VALUE = 4096
MAX_LIFETIME = 30 * 24 * 3600
REVOKED_FILE = "grants.revoked"
METHOD_CLASSES = kinds.GRANT_METHOD_CLASSES
KEYS = ("expires", "format", "grant_id", "key_id", "method_classes", "not_before", "path_classes", "policy_sha256")

_B64 = re.compile(r"^[A-Za-z0-9_-]+$")
_ID = re.compile(r"^[0-9a-f]{32}$")                # an older grant's id
_REVOKED_ID = re.compile(r"^[0-9a-f]{32}(?:[0-9a-f]{32})?$")   # either form's id: an older one or an envelope id
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


def grant_body(path_classes: Sequence[str], method_classes: Sequence[str]) -> bytes:
    """The `prismpath.dist-grant/1` body of a grant covering these classes, or GrantError."""
    from prismpath import canon
    body = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": GRANT_FORMAT,
                               "method_classes": _classes(method_classes, METHOD_CLASSES, "method class"),
                               "path_classes": _classes(path_classes, None, "path class")})
    try:
        kinds.read_grant(body)
    except Refused as refused:
        raise GrantError(f"the grant would not be well formed ({refused})") from None
    return body


def issue(home: Path, policy_sha256: str, path_classes: Sequence[str], method_classes: Sequence[str],
          ttl: int, now: Optional[int] = None, stream: str = LOCAL_STREAM) -> Tuple[str, Dict[str, object]]:
    """Seal a grant envelope for the gateway on `stream` with the authority key in `home`; (header value, what it
    says). A home that follows a stream holds no authority key, so the owner issues its grants where the key is,
    naming the gateway's stream."""
    from prismpath.agent import commands
    from prismpath.hotswap import policy_pack
    if type(ttl) is not int or not 0 < ttl <= MAX_LIFETIME:
        raise GrantError(f"a grant lasts from 1 second to {MAX_LIFETIME} seconds, not {ttl!r}")
    if not kinds.is_hex64(policy_sha256):
        raise GrantError(f"{policy_sha256!r} is not a policy hash")
    if not kinds.is_stream(stream) or stream == env.TRUST_STREAM:
        raise GrantError(f"{stream!r} is not a gateway's stream")
    start = int(time.time()) if now is None else int(now)
    key_path, pub_path = commands._key_paths(Path(home), "authority")
    if not key_path.is_file() or not pub_path.is_file():
        raise GrantError(f"{home} has no authority key; a grant is issued where the authority key is "
                         f"(`prismpath gateway init` makes one)")
    body = grant_body(path_classes, method_classes)
    try:
        envelope_bytes = env.build("grant", body, stream=stream, seq=1, policy_sha256=policy_sha256,
                                   release=env.release_id([("grant", _sha256(body))]), targets=("gateway",),
                                   not_before=start, expires=start + ttl)
    except Refused as refused:
        raise GrantError(f"the grant would not be well formed ({refused})") from None
    sealed = env.seal(envelope_bytes, [policy_pack._load_private(str(key_path))])
    classes = kinds.read_grant(body)
    doc = {"format": GRANT_FORMAT, "grant_id": env.envelope_id(envelope_bytes), "key_id": _sha256(pub_path.read_bytes()),
           "policy_sha256": policy_sha256, "stream": stream, "path_classes": classes["path_classes"],
           "method_classes": classes["method_classes"], "not_before": start, "expires": start + ttl}
    return f"{_b64(sealed)}.{_b64(body)}", doc


class Verifier:
    """Reads the grant header of a request for one gateway: its trust store, its stream and the policy it runs.

    `Verifier(authority_pub, policy_sha256, revoked_path)` is a home that holds its own authority key: the store is
    that key alone with the ids in `revoked_path` listed, and the older form is read too (L3).
    `Verifier(None, policy_sha256, trust=store, stream=stream)` is a home that follows a stream: the store is the
    one its PEP keeps, revocation is that store's alone (GR3) and the older form is refused (L2)."""

    def __init__(self, authority_pub: Optional[bytes], policy_sha256: str, revoked_path: Optional[Path] = None,
                 clock=time.time, *, trust=None, stream: str = LOCAL_STREAM):
        from prismpath.hotswap import policy_pack
        _Priv, Pub, _ser, self._invalid = policy_pack._ed25519()
        if (authority_pub is None) == (trust is None):
            raise ValueError("a verifier reads under its home's authority key or under a trust store, one of them")
        self.legacy = trust is None
        self._key = Pub.from_public_bytes(authority_pub) if authority_pub is not None else None
        self._authority = bytes(authority_pub) if authority_pub is not None else None
        self.key_id = _sha256(authority_pub) if authority_pub is not None else None
        self.policy_sha256 = policy_sha256
        self.stream = stream
        self.revoked_path = Path(revoked_path) if revoked_path and self.legacy else None
        self.clock = clock
        self._trust = trust
        self._lock = threading.Lock()
        self._revoked_stamp: Optional[tuple] = None
        self._revoked: Optional[frozenset] = frozenset()
        self._local: Dict[frozenset, object] = {}

    def revoked(self) -> Optional[frozenset]:
        """The ids `grants.revoked` lists in a home that holds its authority key, or None when the list exists but
        cannot be read. A home that follows a stream has no such list."""
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
                    self._revoked = frozenset(ids) if all(_REVOKED_ID.match(i) for i in ids) else None
                except (OSError, UnicodeDecodeError):
                    self._revoked = None
                self._revoked_stamp = stamp
            return self._revoked

    def trust(self, revoked: Optional[frozenset] = None):
        """The trust store a grant envelope is verified under, or None when its revocation cannot be read."""
        from prismpath.distribution.trust import TrustStore
        if not self.legacy:
            return self._trust if self._trust.readable else None
        if revoked is None:
            return None
        listed = frozenset(i for i in revoked if len(i) == 64)
        with self._lock:
            store = self._local.get(listed)
            if store is None:
                store = TrustStore.with_keys([self._authority], revoked_envelopes=listed)
                self._local = {listed: store}
        return store

    def read(self, values: Sequence[str], path_class: str, method_class: str) -> Tuple[str, Optional[Dict[str, str]]]:
        """(state, record) of a request's grant header values; the record is `{"grant_id", "grant_sha256"}` of a
        grant whose signature verified (valid, expired, or refused for scope, time, policy or revocation), else
        None."""
        if not values:
            return "none", None
        if len(values) != 1 or len(values[0]) > MAX_VALUE:
            return "invalid", None
        try:
            head, mark, tail = values[0].strip().partition(".")
            if not mark:
                return "invalid", None
            first, second = _unb64(head), _unb64(tail)
        except Exception:   # noqa: BLE001 - anything that cannot be read is invalid
            return "invalid", None
        if first[:len(env.MAGIC)] == env.MAGIC:
            return self._read_envelope(first, second, path_class, method_class)
        if not self.legacy:
            return "invalid", None                  # L2: a home under distribution reads no older form
        return self._read_older(first, second, path_class, method_class)

    # ------------------------------------------------------------------ a grant envelope (GR1 to GR3)
    def _read_envelope(self, sealed: bytes, body: bytes, path_class: str,
                       method_class: str) -> Tuple[str, Optional[Dict[str, str]]]:
        from dataclasses import replace
        from prismpath.distribution.verify import GR2, PepView, verify
        revoked = self.revoked() if self.legacy else None
        trust = self.trust(revoked)
        try:
            pep = PepView(kind="gateway", stream=self.stream)
        except ValueError:
            return "invalid", None
        now = int(self.clock())
        if trust is None:                           # a revocation list that cannot be read revokes everything
            readable = self.trust(frozenset()) if self.legacy else None
            verdict = verify(sealed, body, trust=readable, pep=pep, now=now, rules=GR2) if readable else None
            return "invalid", self._record(sealed, verdict)
        verdict = verify(sealed, body, trust=trust, pep=pep, now=now, rules=GR2)
        record = self._record(sealed, verdict)
        time_now = max(now, trust.time_floor)
        if verdict.ok:
            return ("valid" if self._covers(verdict.envelope, body, path_class, method_class, time_now)
                    else "invalid"), record
        if verdict.cause == "dist:expired" and verdict.envelope is not None:
            # expired only when the grant is all a valid one is except for its time: read again just before it ended
            before = verdict.envelope.expires - 1
            again = verify(sealed, body, trust=replace(trust, time_floor=0), pep=pep, now=before, rules=GR2)
            if again.ok and self._covers(again.envelope, body, path_class, method_class, before):
                return "expired", record
        return "invalid", record

    @staticmethod
    def _record(sealed: bytes, verdict) -> Optional[Dict[str, str]]:
        """What the journal line keeps of a grant whose signatures counted (V3 passed and the envelope read)."""
        if verdict is None or verdict.envelope is None:
            return None
        return {"grant_id": verdict.envelope.envelope_id, "grant_sha256": _sha256(sealed)}

    def _covers(self, envelope, body: bytes, path_class: str, method_class: str, now: int) -> bool:
        """GR1 and the reading of section 13 beyond the verifier: the grant's form, `seq` 1, a lifetime of at most
        MAX_LIFETIME, the policy this gateway runs, in force at `now`, and the classes of this request."""
        try:
            classes = kinds.read_grant(body)
        except Refused:
            return False
        if envelope.seq != 1 or not envelope.expires or not envelope.not_before < envelope.expires \
                or envelope.expires - envelope.not_before > MAX_LIFETIME:
            return False
        if envelope.policy_sha256 != self.policy_sha256 or now < envelope.not_before:
            return False
        return path_class in classes["path_classes"] and method_class in classes["method_classes"]

    # ------------------------------------------------------------------ the older form (L3)
    def _read_older(self, body: bytes, signature: bytes, path_class: str,
                    method_class: str) -> Tuple[str, Optional[Dict[str, str]]]:
        try:
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
    """Add `grant_id` to the revocation list of a home that holds its authority key; False when it was already
    there. A home that follows a stream takes its revocations from the signed list alone (GR3)."""
    from prismpath.distribution.adapters import agent_home
    if agent_home.is_distributed(home):
        raise GrantError(f"{home} follows a stream, so a grant is revoked by its envelope id in a signed "
                         f"trust.revocation (`prismpath dist revoke`), not here")
    if not isinstance(grant_id, str) or not _REVOKED_ID.match(grant_id):
        raise GrantError(f"{grant_id!r} is not a grant id (64 lower case hex digits, or 32 for an older grant)")
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
