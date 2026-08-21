# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Signed policy packs (spec-secure-hotswap §3.1-§3.2): the Authorized gate's negative matrix —
unsigned, tampered image, tampered manifest, wrong key, revoked key — and the Envelope-bounded
gate rejecting each violation class with a stable reason. Compiles a real flow through the real
`.ppt` compiler (read-only consumer); skips if `cryptography` or `prismpath-hw` are absent."""
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from prismpath import policy_pack as pp  # noqa: E402
from prismpath.parser import parse  # noqa: E402

_hw = Path(__file__).resolve().parent.parent.parent / "prismpath-hw"
if not (_hw / "ppt_compile.py").exists():
    pytest.skip("prismpath-hw/ppt_compile not present", allow_module_level=True)
sys.path.insert(0, str(_hw))
import ppt_compile as pc  # noqa: E402

FLOW = """# fixture

## start
-> hot: when temp >= 100
-> warm: when temp >= 50
-> cold: else

## hot
-> end

## warm
-> end

## cold
-> end

## end
"""
FIELDS = {"temp": "int"}


@pytest.fixture()
def pack(tmp_path):
    """keygen + compile + sign: a valid pack on disk."""
    keys = pp.keygen(str(tmp_path / "keys"))
    img = pc.compile_flow(parse(FLOW)).serialize()
    ppt = tmp_path / "fixture.ppt"
    ppt.write_bytes(img)
    manifest = pp.build_pack(str(ppt), FIELDS, version=1, envelope_id="env1",
                             priv_path=keys["private"], pub_path=keys["public"])
    return {"ppt": str(ppt), "keys": keys, "manifest": manifest, "tmp": tmp_path}


def _verify(p, **kw):
    return pp.verify_pack(p["ppt"], [p["keys"]["public"]], **kw)


# ------------------------------------------------------------- authorized

def test_happy_path_round_trip(pack):
    ok, reasons, manifest = _verify(pack)
    assert ok and reasons == []
    assert manifest["image_sha256"] == pp.sha256_hex(Path(pack["ppt"]).read_bytes())
    assert manifest["key_id"] == pack["keys"]["key_id"]
    assert manifest["format"] == "ppt-pack/1"


def test_unsigned_is_refused(pack):
    Path(pack["ppt"] + ".manifest.sig").unlink()
    ok, reasons, _ = _verify(pack)
    assert not ok and reasons == ["sig:missing"]


def test_tampered_image_one_byte(pack):
    raw = bytearray(Path(pack["ppt"]).read_bytes())
    raw[-1] ^= 0x01
    Path(pack["ppt"]).write_bytes(bytes(raw))
    ok, reasons, _ = _verify(pack)
    assert not ok and reasons == ["image:sha256-mismatch"]


def test_tampered_manifest(pack):
    man_path = Path(pack["ppt"] + ".manifest.json")
    man = json.loads(man_path.read_text())
    man["version"] = 999                       # try to skip the version gate
    man_path.write_text(json.dumps(man, indent=1, sort_keys=True))
    ok, reasons, _ = _verify(pack)
    assert not ok and reasons == ["sig:invalid"]


def test_wrong_key(pack, tmp_path):
    other = pp.keygen(str(tmp_path / "other"))
    ok, reasons, _ = pp.verify_pack(pack["ppt"], [other["public"]])
    assert not ok and reasons == ["sig:invalid"]


def test_revoked_key(pack):
    revoked = frozenset({pack["keys"]["key_id"]})
    ok, reasons, _ = _verify(pack, revoked=revoked)
    assert not ok and reasons == ["sig:revoked-key"]


def test_refusal_is_loud_without_cryptography(pack, monkeypatch):
    """Loud absence: no cryptography -> RuntimeError naming the install, never silent."""
    import builtins
    real_import = builtins.__import__

    def block(name, *a, **kw):
        if name.startswith("cryptography"):
            raise ImportError("blocked for test")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", block)
    with pytest.raises(RuntimeError, match="pip install cryptography"):
        pp.verify_pack(pack["ppt"], [pack["keys"]["public"]])


# ------------------------------------------------------------- image validation

def test_validate_real_image_clean(pack):
    ok, reasons = pp.validate_image(Path(pack["ppt"]).read_bytes())
    assert ok and reasons == []


def test_bad_magic_and_version():
    img = bytearray(pp.HEADER.size)
    pp.HEADER.pack_into(img, 0, 0xDEADBEEF, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    assert pp.validate_image(bytes(img)) == (False, ["image:bad-magic"])
    pp.HEADER.pack_into(img, 0, pp.MAGIC, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    assert pp.validate_image(bytes(img)) == (False, ["image:bad-version"])


def test_length_mismatch(pack):
    raw = Path(pack["ppt"]).read_bytes()
    ok, reasons = pp.validate_image(raw + b"\x00")
    assert not ok and reasons == ["image:length-mismatch"]


def test_unknown_opcode_injected(pack):
    """Flip a program word to an out-of-fragment opcode -> the load-time walk catches it."""
    raw = bytearray(Path(pack["ppt"]).read_bytes())
    h = pp.read_ppt_header(bytes(raw))
    prog_off = (pp.HEADER.size + pp.ATOM.size * h["atoms"]
                + pp.NODE.size * h["nodes"] + pp.EDGE.size * h["edges"])
    pp.WORD.pack_into(raw, prog_off, 0x9999)
    ok, reasons = pp.validate_image(bytes(raw))
    assert not ok and "image:unknown-opcode:word0" in reasons


# ------------------------------------------------------------- envelope

@pytest.fixture()
def envelope(pack):
    return pp.build_envelope("env1", FIELDS, None, pack["keys"]["private"],
                             pack["keys"]["public"], str(pack["tmp"] / "env"))


def test_envelope_in_bounds_passes(pack, envelope):
    ok, reasons = pp.check_envelope(pack["manifest"], Path(pack["ppt"]).read_bytes(), envelope)
    assert ok and reasons == []


def test_envelope_sig_round_trip(pack, envelope):
    base = str(pack["tmp"] / "env" / "env1.envelope")
    env, reasons = pp.load_envelope(base, [pack["keys"]["public"]])
    assert env == envelope and reasons == []
    env2, reasons2 = pp.load_envelope(base, [])
    assert env2 is None and reasons2 == ["envelope:sig-invalid"]


def test_envelope_rejects_unknown_field(pack, envelope):
    man = dict(pack["manifest"], fields={"temp": "int", "sneaky": "int"})
    ok, reasons = pp.check_envelope(man, Path(pack["ppt"]).read_bytes(), envelope)
    assert not ok and "envelope:unknown-field:sneaky" in reasons


def test_envelope_rejects_field_kind_mismatch(pack, envelope):
    man = dict(pack["manifest"], fields={"temp": "str"})
    ok, reasons = pp.check_envelope(man, Path(pack["ppt"]).read_bytes(), envelope)
    assert not ok and "envelope:field-kind-mismatch:temp" in reasons


def test_envelope_rejects_id_mismatch(pack, envelope):
    man = dict(pack["manifest"], envelope_id="other-env")
    ok, reasons = pp.check_envelope(man, Path(pack["ppt"]).read_bytes(), envelope)
    assert not ok and "envelope:id-mismatch" in reasons


@pytest.mark.parametrize("cap", ["atoms", "nodes", "edges", "prog_words", "max_steps", "max_stack"])
def test_envelope_rejects_each_cap_exceeded(pack, envelope, cap):
    tight = dict(envelope, caps={**envelope["caps"], cap: 0})
    ok, reasons = pp.check_envelope(pack["manifest"], Path(pack["ppt"]).read_bytes(), tight)
    assert not ok and f"envelope:cap-exceeded:{cap}" in reasons


# ---------------------------------------------------------------- packing profile (spiral sidecar)

def _spiral_pack(tmp_path, sidecar: bytes):
    """A pack that declares the spiral profile over an arbitrary sidecar blob."""
    import hashlib
    keys = pp.keygen(str(tmp_path / "skeys"))
    img = pc.compile_flow(parse(FLOW)).serialize()
    ppt = tmp_path / "spiral_fixture.ppt"
    ppt.write_bytes(img)
    (tmp_path / "spiral_fixture.ppt.spiral").write_bytes(sidecar)
    manifest = pp.build_pack(str(ppt), FIELDS, version=1, envelope_id="env1",
                             priv_path=keys["private"], pub_path=keys["public"],
                             packing={"profile": "spiral",
                                      "sidecar_sha256": hashlib.sha256(sidecar).hexdigest()})
    return str(ppt), keys, manifest


def test_packing_declared_and_verified(tmp_path):
    ppt, keys, manifest = _spiral_pack(tmp_path, b"sidecar-bytes-v1")
    assert manifest["packing"]["profile"] == "spiral"
    ok, reasons, _ = pp.verify_pack(ppt, [keys["public"]])
    assert ok and reasons == []


def test_packing_tampered_sidecar_fails(tmp_path):
    ppt, keys, _ = _spiral_pack(tmp_path, b"sidecar-bytes-v1")
    with open(ppt + ".spiral", "wb") as f:
        f.write(b"sidecar-bytes-v2")
    ok, reasons, _ = pp.verify_pack(ppt, [keys["public"]])
    assert not ok and "spiral:sidecar-hash-mismatch" in reasons


def test_packing_missing_sidecar_fails(tmp_path):
    ppt, keys, _ = _spiral_pack(tmp_path, b"sidecar-bytes-v1")
    import os as _os
    _os.remove(ppt + ".spiral")
    ok, reasons, _ = pp.verify_pack(ppt, [keys["public"]])
    assert not ok and "spiral:sidecar-missing" in reasons


def test_packing_unknown_profile_refused_at_build(tmp_path):
    keys = pp.keygen(str(tmp_path / "ukeys"))
    img = pc.compile_flow(parse(FLOW)).serialize()
    ppt = tmp_path / "u.ppt"
    ppt.write_bytes(img)
    with pytest.raises(ValueError, match="packing"):
        pp.build_pack(str(ppt), FIELDS, version=1, envelope_id="env1",
                      priv_path=keys["private"], pub_path=keys["public"],
                      packing={"profile": "hilbert", "sidecar_sha256": "00"})


def test_pack_without_packing_is_unaffected(pack):
    ok, reasons, manifest = pp.verify_pack(pack["ppt"], [pack["keys"]["public"]])
    assert ok and "packing" not in manifest
