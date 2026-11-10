# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""canon: the shared byte level helpers every persisted or signed artifact is built from.

Two canonical JSON encodings exist in PrismPath and both are load bearing: the COMPACT form is what
signatures and Merkle leaves are computed over (policy packs, envelopes, the crypto registry, audit
log leaves), and the SPACED form (Python's default separators) is what attestation manifests, the
connector's content hashes, lock hashes, and composer item ids were frozen with. Neither can be
collapsed into the other without breaking a conformance corpus, a lock file on disk, a checkpoint
filename, or an anchored root, so each has its own name here and the frozen tests pin them.
Truncations, the `sha256:` prefix, and hex versus raw byte concatenation are likewise properties of
specific artifacts and stay at the call sites that own them; this module only removes copies that
were already byte identical.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Optional


class CanonicalError(ValueError):
    """A value that has no canonical JSON form: NaN, Infinity, -Infinity, or a string holding a lone
    surrogate. Canonical bytes are what signatures, Merkle leaves and content hashes are computed over,
    so a value that cannot be written the same way by every implementation is refused, never converted."""


class CanonicalReadError(CanonicalError, json.JSONDecodeError):
    """The reading side of `CanonicalError`: a document holds a NaN or Infinity token, a number beyond
    the double range (`1e400`), or a lone surrogate. It is also a `json.JSONDecodeError`, so every
    caller that already refuses an unparseable document refuses this one the same way."""

    def __init__(self, message: str):
        json.JSONDecodeError.__init__(self, message, "", 0)
        self.args = (message,)

    def __str__(self) -> str:
        return self.msg


def _surrogate_free(obj: Any) -> None:
    """Raise CanonicalError when any string or key inside `obj` holds a lone surrogate. Only called
    after `json.dumps` has accepted the object, so it cannot be circular."""
    stack = [obj]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if _LONE_SURROGATE.search(item):
                raise CanonicalError("string holds a lone surrogate, which has no UTF-8 or canonical JSON form")
        elif isinstance(item, dict):
            for key, value in item.items():
                if isinstance(key, str) and _LONE_SURROGATE.search(key):
                    raise CanonicalError("object key holds a lone surrogate, which has no UTF-8 or canonical JSON form")
                stack.append(value)
        elif isinstance(item, (list, tuple)):
            stack.extend(item)


_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def _dumps(obj: Any, separators: Optional[tuple], default: Optional[Any]) -> bytes:
    checked_default = default
    if default is not None:
        def checked_default(item):
            produced = default(item)
            _surrogate_free(produced)
            return produced
    try:
        text = json.dumps(obj, sort_keys=True, separators=separators, default=checked_default, allow_nan=False)
    except ValueError as error:
        if isinstance(error, CanonicalError):
            raise
        if "Out of range float" in str(error):
            raise CanonicalError("NaN, Infinity and -Infinity have no canonical JSON form") from error
        raise
    _surrogate_free(obj)
    return text.encode("utf-8")


def canonical_compact(obj: Any) -> bytes:
    """Sorted keys, no whitespace, ASCII escaped: the bytes signatures and leaves are computed over.
    Raises CanonicalError for NaN, Infinity, -Infinity and lone surrogates."""
    return _dumps(obj, (",", ":"), None)


def canonical_spaced(obj: Any, default: Optional[Any] = None) -> bytes:
    """Sorted keys with Python's default separators: the form manifests, connector hashes, lock
    hashes, and item ids were frozen with. `default` is passed through for the two sites that
    stringify non JSON items (composer item ids, ledger runner proof bytes). Refuses what
    `canonical_compact` refuses."""
    return _dumps(obj, None, default)


def dumps_strict(obj: Any, **kwargs: Any) -> str:
    """`json.dumps` for a document that is written to disk and later hashed, signed or verified:
    the same keyword arguments, but NaN, Infinity and lone surrogates raise CanonicalError."""
    kwargs["allow_nan"] = False
    try:
        text = json.dumps(obj, **kwargs)
    except ValueError as error:
        if "Out of range float" in str(error):
            raise CanonicalError("NaN, Infinity and -Infinity have no canonical JSON form") from error
        raise
    _surrogate_free(obj)
    return text


def _refuse_constant(token: str) -> Any:
    raise CanonicalReadError(f"{token} is not allowed: canonical JSON has no non finite numbers")


def _finite_float(text: str) -> float:
    number = float(text)
    if number in (float("inf"), float("-inf")):
        raise CanonicalReadError(f"number {text[:24]} is beyond the double range and is refused, not read as infinity")
    return number


def loads(text: Any, **kwargs: Any) -> Any:
    """`json.loads` for a document that is hashed, signed or verified: a NaN, Infinity or -Infinity
    token, a number beyond the double range, and a string holding a lone surrogate raise
    CanonicalReadError (a json.JSONDecodeError). Every ordinary document reads exactly as before."""
    kwargs.setdefault("parse_constant", _refuse_constant)
    kwargs.setdefault("parse_float", _finite_float)
    value = json.loads(text, **kwargs)
    try:
        _surrogate_free(value)
    except CanonicalError as error:
        raise CanonicalReadError(str(error)) from error
    return value


def load(handle: Any, **kwargs: Any) -> Any:
    """`loads` over an open file."""
    return loads(handle.read(), **kwargs)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_prefixed(data: bytes) -> str:
    """`sha256:<hex>`, the string form checkpoints, locks, and the connector persist."""
    return "sha256:" + sha256_hex(data)


def file_sha256_prefixed(path) -> str:
    """Content hash of a file as `sha256:<hex>`; raises OSError like open() does."""
    with open(path, "rb") as f:
        return sha256_prefixed(f.read())


def manifest_hash(m: dict) -> str:
    """The content address of an attestation manifest: sha256 over the spaced canonical form of every
    field except `manifest_hash` itself (ledger_airgap and the fixture generators share this)."""
    return sha256_hex(canonical_spaced({k: m[k] for k in m if k != "manifest_hash"}))


def atomic_write(path, data: str, encoding: str = "utf-8") -> None:
    """Write text so a reader sees the old file or the new one, never a torn one: parent directory
    created, temp file beside the target, flushed and fsynced, then os.replace."""
    path = os.fspath(path)
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding=encoding) as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def atomic_write_bytes(path, data: bytes) -> None:
    """`atomic_write` for bytes: the old file or the new one, never a torn one."""
    path = os.fspath(path)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def safe_name(name: str) -> str:
    """Filesystem safe and deliberately NOT injective (composer disambiguates with a hash when it
    matters): every character outside [A-Za-z0-9_.-] becomes `_`; empty becomes `flow`."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name) or "flow"
