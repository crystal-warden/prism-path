# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The keys behind the `Signer` port (`prismpath.onion.keys`): loading, signing, checking, generating, and the older
names that stay the same functions until the shims go."""
import hashlib
import os

import pytest

pytest.importorskip("cryptography")

from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.hotswap import policy_pack as pp  # noqa: E402
from prismpath.kernel import ppt_compile  # noqa: E402
from prismpath.ledgers import root_statement as rs, signer_daemon  # noqa: E402
from prismpath.onion import keys  # noqa: E402
from prismpath.ports import keys as port  # noqa: E402

SEED = hashlib.sha256(b"prismpath onion keys test").digest()


def test_a_pem_key_loads_as_a_signer_named_by_its_public_half(tmp_path):
    made = pp.keygen(str(tmp_path), "authority")
    signer = keys.load_signer(made["private"])
    public = open(made["public"], "rb").read()
    assert isinstance(signer, port.Signer) and isinstance(signer, keys.FileKey)
    assert signer.public_raw == public == keys.load_public(made["public"])
    assert signer.key_id == made["key_id"] == hashlib.sha256(public).hexdigest()
    assert signer.fingerprint == made["key_id"][:16] and "PRIVATE" not in repr(signer)
    signature = signer.sign(b"message")
    assert len(signature) == 64 and keys.verify(public, signature, b"message")


def test_verify_says_no_without_raising():
    signer = keys.fixed_signer(SEED)
    other = keys.fixed_signer(hashlib.sha256(SEED).digest())
    signature = signer.sign(b"message")
    assert not keys.verify(signer.public_raw, signature, b"messagE")
    assert not keys.verify(other.public_raw, signature, b"message")
    assert not keys.verify(signer.public_raw, signature[:63], b"message")
    assert not keys.verify(signer.public_raw[:31], signature, b"message")      # not a key: no, not an error


def test_the_fixed_key_signs_the_same_bytes_every_time():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    wrapped = keys.as_signer(Ed25519PrivateKey.from_private_bytes(SEED))
    assert keys.fixed_signer(SEED).sign(b"m") == keys.fixed_signer(SEED).sign(b"m") == wrapped.sign(b"m")
    assert keys.public_raw_of(Ed25519PrivateKey.from_private_bytes(SEED)) == keys.fixed_signer(SEED).public_raw
    held = keys.fixed_signer(SEED)
    assert keys.as_signer(held) is held


def test_a_sealed_envelope_is_the_same_from_a_signer_and_from_a_cryptography_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from prismpath.distribution import legacy
    body = ppt_compile.compile_predicate("when x >= 5").serialize()
    header = pp.read_ppt_header(body)
    meta = {"counts": {name: header[name] for name in ("atoms", "nodes", "edges", "prog_words", "max_steps",
                                                       "max_stack")},
            "fields": {"x": "int"}, "qualification": "test-env", "wcet_cycles": pp.wcet_cycles(body)}
    sealed = [legacy.local_seal("policy.ppt", body, [signer], seq=1, targets=("host",), meta=meta, not_before=0,
                                expires=10)
              for signer in (keys.fixed_signer(SEED), Ed25519PrivateKey.from_private_bytes(SEED))]
    assert sealed[0] == sealed[1]
    entries = env.unseal(sealed[0])[1]
    assert [kid for kid, _signature in entries] == [keys.fixed_signer(SEED).key_id]


def test_the_authority_keygen_replaces_and_the_instance_keygen_refuses(tmp_path):
    first = keys.keygen(str(tmp_path), "authority", replace=True)
    second = keys.keygen(str(tmp_path), "authority", replace=True)
    assert set(first) == {"private", "public", "key_id"} and first["key_id"] != second["key_id"]
    assert keys.load_signer(second["private"]).key_id == second["key_id"]
    assert oct(os.stat(second["private"]).st_mode & 0o777) == "0o600"
    made = keys.keygen(str(tmp_path), "instance", replace=False)
    assert set(made) == {"private", "public", "key_id", "fingerprint"}
    before = open(made["private"], "rb").read()
    with pytest.raises(FileExistsError):
        keys.keygen(str(tmp_path), "instance", replace=False)
    assert open(made["private"], "rb").read() == before
    assert rs.keygen(str(tmp_path / "other"))["role"] == "instance"


def test_the_instance_key_names_a_file_or_a_daemon(tmp_path, monkeypatch):
    made = rs.keygen(str(tmp_path))
    from_file = rs.key_from_env({rs.INSTANCE_KEY_ENV: made["private"]})
    assert isinstance(from_file, rs.InstanceKey) and from_file.key_id == made["key_id"]
    assert repr(from_file) == f"InstanceKey(fingerprint={made['fingerprint']!r})"
    assert rs.key_from_env({rs.INSTANCE_KEY_ENV: "  "}) is None

    asked = []

    class Stub:
        def __init__(self, socket_path):
            asked.append(socket_path)

    monkeypatch.setattr(signer_daemon, "DaemonKey", Stub)
    assert isinstance(rs.key_from_env({rs.INSTANCE_KEY_ENV: "unix:/run/signer.sock"}), Stub)
    assert isinstance(keys.load_signer("unix:/run/other.sock"), Stub)
    assert asked == ["/run/signer.sock", "/run/other.sock"]


def test_a_public_key_file_that_is_not_32_bytes_is_refused(tmp_path):
    path = tmp_path / "short.pub"
    path.write_bytes(b"\x00" * 31)
    with pytest.raises(ValueError):
        keys.load_public(str(path))
    with pytest.raises(ValueError):
        pp.load_public(str(path))


def test_the_older_names_are_the_same_functions():
    assert pp._ed25519 is keys.primitives and rs._ed25519 is keys.primitives
    assert pp._load_private is keys.load_private_key
    assert pp.MissingSigningExtra is keys.MissingSigningExtra
    assert issubclass(keys.MissingSigningExtra, RuntimeError) and issubclass(keys.MissingSigningExtra, ImportError)
    assert rs.load_public is keys.load_public and rs.key_id_of is keys.key_id_of


def test_the_pack_reader_takes_the_format_from_the_compiler():
    for name in ("HEADER", "ATOM", "NODE", "EDGE", "WORD", "MAGIC", "FORMAT_VERSION", "OPS", "TYPES", "PROG_OPCODES",
                 "FLAG_NODE_ATTR", "FLAG_COLORS", "FLAG_MIGRATE_BY_NAME", "FLAG_NODE_NAMES", "FLAG_STATEFUL"):
        assert getattr(pp, name) is getattr(ppt_compile, name), name
    assert pp.HEADER.size == 28
