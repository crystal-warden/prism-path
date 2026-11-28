# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Keys behind the `Signer` port (`prismpath.ports.keys`): the one place PrismPath reads Ed25519.

Every signature PrismPath makes or checks goes through here. A private key is a PKCS8 PEM file read with no
password, or a signer daemon's socket named `unix:PATH` (`load_signer`). A public key is a file of its 32 raw
bytes (`load_public`). A signature is checked with `verify`, which answers True or False and never raises for a
signature or a key that does not verify. Nothing here writes a new key format: the files are the ones
`swap keygen` and `ledger keygen` have always written.

Two key generators are kept apart on purpose (`keygen`). An authority key is replaced when generated again under
its name, as `swap keygen` always did. An instance key is never replaced, because the statements an old instance
key signed verify only against it.

Ed25519 comes from `cryptography`, the `signing` extra. Without it every function that needs it raises
`MissingSigningExtra`, a `MissingExtra` and a `RuntimeError`, so the command line prints the install line alone.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any, Optional

from prismpath.extras import MissingExtra
from prismpath.ports.keys import ChainSigner, Signer

__all__ = ["Signer", "ChainSigner", "MissingSigningExtra", "FileKey", "require", "key_id_of", "fingerprint",
           "verify", "load_signer", "load_public", "public_key", "public_raw_of", "as_signer", "fixed_signer",
           "keygen", "DAEMON_PREFIX", "primitives", "load_private_key"]

INSTALL_MSG = "policy signing needs cryptography (the signing extra): pip install 'prismpath[signing]'"
DAEMON_PREFIX = "unix:"           # a signer source naming a signer daemon's socket


class MissingSigningExtra(MissingExtra, RuntimeError):
    """The signing extra is not installed. Also a RuntimeError, because callers have long caught the
    loud absence as one; the command line prints its install line alone."""


def _ed25519():
    """Import the Ed25519 primitives, loudly refusing if the optional dep is absent."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey)
        from cryptography.hazmat.primitives import serialization
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:                                   # pragma: no cover
        raise MissingSigningExtra("signing", "cryptography", INSTALL_MSG) from exc
    return Ed25519PrivateKey, Ed25519PublicKey, serialization, InvalidSignature


def primitives():
    """`(Ed25519PrivateKey, Ed25519PublicKey, serialization, InvalidSignature)` from `cryptography`, or
    `MissingSigningExtra`. Only the older names `policy_pack._ed25519` and `root_statement._ed25519` answer with it,
    for the integrations that still read them; code in the package calls the functions below."""
    return _ed25519()


def load_private_key(path: str):
    """The PEM private key at `path` as `cryptography` holds it. Only the older name `policy_pack._load_private`
    answers with it; code in the package calls `load_signer`."""
    return _load_private(path)


def require() -> None:
    """Raise `MissingSigningExtra` now when the signing extra is absent, so a check refuses before it reads anything
    rather than part way through."""
    _ed25519()


def key_id_of(public_raw: bytes) -> str:
    """sha256 hex of the raw 32 byte public key: the identity of a key in every manifest, envelope and list."""
    return hashlib.sha256(bytes(public_raw)).hexdigest()


def fingerprint(key_id: str) -> str:
    """The short form people read and compare: the first 16 hex characters of the key id."""
    return key_id[:16]


def _load_private(path: str):
    """The private key in the PEM file at `path`, as `cryptography` reads it."""
    _Priv, _Pub, ser, _Inv = _ed25519()
    with open(path, "rb") as handle:
        key = ser.load_pem_private_key(handle.read(), password=None)
    return key


def _raw_public_of_private(private_key) -> bytes:
    _Priv, _Pub, ser, _Inv = _ed25519()
    return private_key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)


# ------------------------------------------------------------------ adapters

class FileKey:
    """A signer holding its private key in this process: read from a PEM file (`load`), made from a seed
    (`fixed_signer`), or wrapped around a `cryptography` private key (`as_signer`). The public half is worked out
    when it is first asked for, so a key read for signing alone fails where it always did. It never renders its
    private half: `repr` shows the fingerprint."""

    def __init__(self, private_key, public_raw: Optional[bytes] = None, path: Optional[str] = None):
        self._private = private_key
        self._public_raw = None if public_raw is None else bytes(public_raw)
        self._key_id: Optional[str] = None
        self.path = path

    @classmethod
    def load(cls, path: str) -> "FileKey":
        return cls(_load_private(path), path=path)

    @property
    def public_raw(self) -> bytes:
        if self._public_raw is None:
            self._public_raw = _raw_public_of_private(self._private)
        return self._public_raw

    @property
    def key_id(self) -> str:
        if self._key_id is None:
            self._key_id = key_id_of(self.public_raw)
        return self._key_id

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.key_id)

    def sign(self, message: bytes) -> bytes:
        return self._private.sign(message)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(fingerprint={self.fingerprint!r})"


def fixed_signer(seed: bytes) -> FileKey:
    """The signer whose Ed25519 private key is the 32 byte `seed`: the fixed test key, for tests and the corpus
    generators, whose signatures are the same on every run."""
    Priv, _Pub, _ser, _Inv = _ed25519()
    return as_signer(Priv.from_private_bytes(bytes(seed)))


def as_signer(key: Any) -> Signer:
    """`key` as a signer: a signer as it is, or a `cryptography` Ed25519 private key wrapped as a `FileKey`."""
    if isinstance(key, Signer):
        return key
    return FileKey(key)


def public_raw_of(key: Any) -> bytes:
    """The 32 raw public bytes of a signer or of a `cryptography` Ed25519 private key."""
    return as_signer(key).public_raw


def load_signer(source: str, *, file_key: type = FileKey) -> Signer:
    """The signer `source` names: `unix:PATH` for a signer daemon answering on that socket
    (`prismpath.ledgers.signer_daemon.DaemonKey`), anything else the path of a PKCS8 PEM private key, loaded by
    `file_key.load`."""
    source = str(source)
    if source.startswith(DAEMON_PREFIX):
        from prismpath.ledgers import signer_daemon
        return signer_daemon.DaemonKey(source[len(DAEMON_PREFIX):])
    return file_key.load(source)


# ------------------------------------------------------------------ public keys and signatures

def public_key(public_raw: bytes):
    """The `cryptography` public key of 32 raw bytes. ValueError when they are not 32 bytes."""
    _Priv, Pub, _ser, _Inv = _ed25519()
    return Pub.from_public_bytes(bytes(public_raw))


def load_public(path: str) -> bytes:
    """A raw 32 byte Ed25519 public key file, as `keygen`, `swap keygen` and `ledger keygen` write it."""
    with open(path, "rb") as handle:
        raw = handle.read()
    if len(raw) != 32:
        raise ValueError(f"{path}: not a raw 32 byte Ed25519 public key ({len(raw)} bytes)")
    return raw


def verify(public_raw: bytes, signature: bytes, message: bytes) -> bool:
    """True when `signature` is an Ed25519 signature of `message` under the 32 raw public bytes `public_raw`.
    False for a signature that does not verify and for a public key that is not 32 bytes."""
    _Priv, Pub, _ser, InvalidSignature = _ed25519()
    try:
        Pub.from_public_bytes(bytes(public_raw)).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


# ------------------------------------------------------------------ generation

def keygen(out_dir: str, name: str, *, replace: bool) -> dict:
    """Generate an Ed25519 keypair: `<name>.key` (PKCS8 PEM, mode 0600) and `<name>.pub` (raw 32 bytes) in
    `out_dir`. Returns the two paths and the key id, never the private material.

    `replace` True is the authority key: a key already under the name is overwritten. `replace` False is the
    instance key: a key already under the name is refused with FileExistsError before anything is generated,
    because the statements an old key signed verify only against it, and the answer also carries the
    fingerprint."""
    Priv, _Pub, ser, _Inv = _ed25519()
    os.makedirs(out_dir, exist_ok=True)
    priv_path = os.path.join(out_dir, f"{name}.key")
    pub_path = os.path.join(out_dir, f"{name}.pub")
    if not replace:
        for path in (priv_path, pub_path):
            if os.path.exists(path):
                raise FileExistsError(17, "refusing to replace an existing key (statements it signed verify only "
                                          "against it); choose another --name or --out", path)
    private_key = Priv.generate()
    pem = private_key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if replace else os.O_EXCL)
    fd = os.open(priv_path, flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    public_raw = private_key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    with open(pub_path, "wb") as handle:
        handle.write(public_raw)
    key_id = key_id_of(public_raw)
    if replace:
        return {"private": priv_path, "public": pub_path, "key_id": key_id}
    return {"private": priv_path, "public": pub_path, "key_id": key_id, "fingerprint": fingerprint(key_id)}

