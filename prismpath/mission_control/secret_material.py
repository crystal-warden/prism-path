# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Secret material the console never serves, by kind and by content.

Every route that returns a file's bytes (the editor's `GET /file` and the evidence readers under
`/evidence`) asks this module first, for the path asked for and for the real path it resolves to, so a
link with an innocent name cannot carry a key out, and again for the bytes it read, so a key copied under
an innocent name is refused too. Three rules, each a refusal reason:

    secret-kind     a private key file by its name (`*.key`, `instance.key`, `authority.key`, PKCS12 and
                    Java keystores, PuTTY keys, `id_rsa` and its kind without `.pub`), an `.env` like file
                    (`.env`, `.env.*`, `*.env`, `.envrc`, `.netrc`, `.pgpass`), or a file other than
                    a flow document named for secrets or credentials
    console-state   anything in the console's own state directory (the session token file above all)
                    but its audit log and that log's statements file, and the followed project when the
                    project is the default one inside it
    secret-content  a PEM private key block (any `-----BEGIN ... PRIVATE KEY-----` with key text after
                    it, also with its line feeds escaped as JSON writes them), a PuTTY key, or an
                    unencrypted Ed25519 PKCS8 key in DER

A public key (`*.pub`, a raw 32 bytes) and a certificate are not secret and read as before."""
from __future__ import annotations

import os
import re
from typing import Optional

from .config import SETTINGS

KIND, STATE, CONTENT = "secret-kind", "console-state", "secret-content"

MESSAGES = {
    KIND: "refused: the console never serves a private key, an .env like file or a credentials file",
    STATE: "refused: the console never serves its own state (the session token), only its audit log",
    CONTENT: "refused: the file holds private key material",
}

PRIVATE_KEY_SUFFIXES = (".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk", ".p8")
PRIVATE_KEY_NAMES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk")
ENV_NAMES = (".env", ".envrc", ".netrc", ".pgpass", ".npmrc", ".pypirc")
SECRET_STEMS = ("secret", "secrets", "credential", "credentials")

# A PEM private key block: the BEGIN line, then key text (base64) or an RFC 1421 header (an encrypted
# legacy key). A sentence that only names the marker is not a key. The line feed may be escaped (`\n`)
# when the block sits inside a JSON string.
_PEM_PRIVATE = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----[ \t]*(?:\r?\n|(?:\\r)?\\n)"
                          rb"(?:[A-Za-z0-9+/=]{16,}|[A-Za-z-]+: )")
_PUTTY = re.compile(rb"PuTTY-User-Key-File-[0-9]+: ")
# PKCS8 OneAsymmetricKey for Ed25519 (RFC 8410), unencrypted: SEQUENCE, version 0, the Ed25519 OID, and
# the 32 byte private key OCTET STRING header. X25519 (OID 1.3.101.110) and Ed448 share the shape.
_DER_PRIVATE = (bytes.fromhex("302e020100300506032b657004220420"),
                bytes.fromhex("302e020100300506032b656e04220420"),
                bytes.fromhex("3047020100300506032b6571043b0439"))


def kind_refusal(path: str) -> Optional[str]:
    """`secret-kind` when the file's name marks it as secret material, else None."""
    name = os.path.basename(os.path.normpath(path)).lower()
    if not name:
        return None
    if name.endswith(PRIVATE_KEY_SUFFIXES) or name in PRIVATE_KEY_NAMES:
        return KIND
    if name in ENV_NAMES or name.startswith(".env.") or name.endswith(".env"):
        return KIND
    stem = name.split(".", 1)[0]
    if stem in SECRET_STEMS and not name.endswith(".md"):     # a flow may be about credentials; its bytes
        return KIND                                           # are still judged by content_refusal
    return None


def _inside(path: str, base: str) -> bool:
    return path == base or path.startswith(base.rstrip(os.sep) + os.sep)


def state_refusal(real: str) -> Optional[str]:
    """`console-state` when the real path `real` lies in the console's state directory and is neither its
    audit log nor that log's statements file nor in a followed project kept inside it, else None."""
    state_dir = os.path.realpath(SETTINGS.state_dir)
    real = os.path.realpath(real)
    if not _inside(real, state_dir):
        return None
    from . import audit                                    # late: audit imports the ledgers
    from .state import current_project
    from prismpath.ledgers import root_statement
    log_path = os.path.realpath(audit.LOG.path)
    if real in (log_path, os.path.realpath(root_statement.statements_path_for(log_path))):
        return None
    followed = current_project()
    project = os.path.realpath(followed) if followed else ""
    if project and project != state_dir and _inside(project, state_dir) and _inside(real, project):
        return None
    return STATE


def path_refusal(*paths: str) -> Optional[str]:
    """The first refusal by kind or console state for any of `paths` (the path asked for and the real path
    it resolved to), else None."""
    for path in paths:
        reason = kind_refusal(path)
        if reason:
            return reason
    for path in paths:
        if os.path.isabs(path):
            reason = state_refusal(path)
            if reason:
                return reason
    return None


def content_refusal(data: bytes) -> Optional[str]:
    """`secret-content` when `data` holds private key material, else None."""
    if _PEM_PRIVATE.search(data) or _PUTTY.search(data):
        return CONTENT
    if any(marker in data for marker in _DER_PRIVATE):
        return CONTENT
    return None
