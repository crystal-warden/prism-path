# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The older signed forms and the writers that replaced them (spec-policy-distribution.md, section 17).

L1. A writer emits only distribution envelopes. Where nothing distributes the artifact, as in a home or a pack
directory that holds its own authority key, the envelope is sealed on the stream `local`, `seq` the writer's
version, and with a lifetime of `LOCAL_LIFETIME`. The older forms never expired, so a local envelope lasts long
enough that sealing one changes nothing a home did before. The body is the same bytes as before (L1), so an image
keeps its hash.

L3. A reader still accepts an older form where L2 does not refuse it, through the 0.3 series, as one branch on the
first bytes it reads, and writes a `legacy_form` audit event on every successful read. The event names the form,
the reader, the SHA-256 of the bytes the older form signed and the key id that signed them, and says from which
version the form is refused (`refused_from`). `record` appends it to an `AuditLog` a reader holds, and `record_at`
to the log file of a home that holds no open log, under a lock, since several hook processes may read at once.
"""
from __future__ import annotations

import os
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterable, Optional

EVENT = "legacy_form"
ACTOR = "distribution"
REFUSED_FROM = "0.4.0"                             # L3: from 0.4.0 every older form is `dist:legacy-refused`
LOCAL_STREAM = "local"                             # the stream of an envelope its owner seals for its own use
LOCAL_LIFETIME = 10 * 365 * 24 * 3600              # ten years: an older form never expired
AUDIT_FILE = "audit.log"                           # a home's own log, beside its keys

# The older forms of section 17, by format name. The cFS table's (`prismpath.cfs-table/1`) and the mesh's
# (`PPTM1`) readers are in the cFS app and the mesh firmware.
PACK = "ppt-pack/1"
CORE_IMAGE = "prismpath.core-image/1"
NET_DESTS = "prismpath.net_dests_pack/1"
GRANT = "prismpath.grant/1"
ZONES = "prismpath.zones.attestation/1"
CFS_TABLE = "prismpath.cfs-table/1"
MESH = "PPTM1"
FORMS = frozenset({PACK, CORE_IMAGE, NET_DESTS, GRANT, ZONES, CFS_TABLE, MESH})


def event(form: str, *, reader: str, sha256: str, key_id: Optional[str]) -> Dict[str, Any]:
    """The members of one `legacy_form` event."""
    if form not in FORMS:
        raise ValueError(f"{form!r} is not an older signed form")
    return {"form": form, "reader": reader, "sha256": sha256, "key_id": key_id, "refused_from": REFUSED_FROM}


def record(audit, form: str, *, reader: str, sha256: str, key_id: Optional[str]) -> dict:
    """Append the `legacy_form` event to `audit` (an `AuditLog`) and return it."""
    return audit.append(ACTOR, EVENT, event(form, reader=reader, sha256=sha256, key_id=key_id))


@contextmanager
def _locked(path: str):
    """An exclusive lock on `<path>.lock` where the platform has `fcntl`, so two processes append one after the
    other and each reads the log the other wrote."""
    try:
        import fcntl
    except ImportError:                             # pragma: no cover - Windows: one process at a time is assumed
        yield
        return
    fd = os.open(path + ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def record_at(path: str, form: str, *, reader: str, sha256: str, key_id: Optional[str],
              instance_key=None) -> dict:
    """Append the `legacy_form` event to the audit log at `path`, opened under the lock, and signed with
    `instance_key` when one is given, as the hosts sign theirs."""
    from prismpath.ledgers.audit_log import AuditLog
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with _locked(path):
        audit = AuditLog(path, instance_key=instance_key, sign_appends=instance_key is not None)
        return record(audit, form, reader=reader, sha256=sha256, key_id=key_id)


def events(audit) -> list:
    """The `legacy_form` events in `audit`, for a status line and the tests."""
    return [ev for ev in audit.events if ev.get("action") == EVENT]


def local_seal(artifact: str, body: bytes, signers: Iterable[Any], *, seq: int, targets: Iterable[str],
               meta: Optional[dict] = None, not_before: Optional[int] = None, expires: Optional[int] = None,
               stream: str = LOCAL_STREAM) -> bytes:
    """The sealed envelope of `body` for its owner's own use (L1): one artifact, its release the release of that
    one artifact, `policy_sha256` the body's own SHA-256, on `stream`. `Refused` for anything the format refuses."""
    from prismpath import canon
    from prismpath.distribution import envelope as env
    start = int(time.time()) if not_before is None else int(not_before)
    digest = canon.sha256_hex(bytes(body))
    envelope_bytes = env.build(artifact, body, stream=stream, seq=int(seq), policy_sha256=digest,
                               release=env.release_id([(artifact, digest)]), targets=tuple(targets),
                               not_before=start, expires=start + LOCAL_LIFETIME if expires is None else int(expires),
                               meta=meta)
    return env.seal(envelope_bytes, list(signers))
