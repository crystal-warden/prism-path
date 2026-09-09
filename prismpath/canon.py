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


def canonical_compact(obj: Any) -> bytes:
    """Sorted keys, no whitespace, ASCII escaped: the bytes signatures and leaves are computed over."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_spaced(obj: Any, default: Optional[Any] = None) -> bytes:
    """Sorted keys with Python's default separators: the form manifests, connector hashes, lock
    hashes, and item ids were frozen with. `default` is passed through for the two sites that
    stringify non JSON items (composer item ids, ledger runner proof bytes)."""
    if default is not None:
        return json.dumps(obj, sort_keys=True, default=default).encode("utf-8")
    return json.dumps(obj, sort_keys=True).encode("utf-8")


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


def safe_name(name: str) -> str:
    """Filesystem safe and deliberately NOT injective (composer disambiguates with a hash when it
    matters): every character outside [A-Za-z0-9_.-] becomes `_`; empty becomes `flow`."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name) or "flow"
