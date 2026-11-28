# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The `Signer` port: what holds a private Ed25519 key and signs with it.

A signer is named by its public half. `key_id` is the sha256 hex of the 32 raw public bytes, the identity every
manifest, envelope, trust store and revocation list uses, and `fingerprint` is its first 16 hex characters, the
form people compare. `sign` answers the 64 byte Ed25519 signature of a message. Ed25519 is deterministic, so two
signers holding one key sign every message with the same bytes, whichever adapter holds it.

The adapters are in `prismpath.onion.keys`: a key read from a PEM file, a fixed key from a seed for tests and
generators, and the signer daemon (`prismpath.ledgers.signer_daemon`), which holds the key in another process and
also answers `head`, the last statement it signed for a log. The functions that load, verify and generate keys
are there too.
"""
from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable


@runtime_checkable
class Signer(Protocol):
    key_id: str             # sha256 hex of the raw public key
    public_raw: bytes       # 32 bytes
    fingerprint: str        # first 16 hex of key_id

    def sign(self, message: bytes) -> bytes:
        """The 64 byte Ed25519 signature of `message`."""
        ...


@runtime_checkable
class ChainSigner(Signer, Protocol):
    def head(self, log: str) -> Optional[dict]:
        """The last statement the holder signed for `log`, or None."""
        ...
