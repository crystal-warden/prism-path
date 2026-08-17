# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze cross-language HOT-SWAP fixtures: a Python-signed pack + envelope + the full negative
matrix, every expected verdict computed by RUNNING the Python reference gates (verify_pack /
check_envelope) — so the Rust port is measured against what Python actually decides, reason
strings included.

    python prismpath/portable/gen_hotswap_fixtures.py   ->  conformance/hotswap.json

Ephemeral keys are generated fresh and FROZEN (pub raw + everything signed); private keys never
leave this generator. The image is compiled from a fixed predicate so bytes are deterministic.
"""
from __future__ import annotations

import base64
import json
import struct
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "prismpath-hw"))

from prismpath import policy_pack as pp    # noqa: E402
import ppt_compile as pc                    # noqa: E402

OUT = HERE / "conformance" / "hotswap.json"

b64 = lambda b: base64.b64encode(b).decode()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cw_hotswap_fx_") as td:
        td = Path(td)
        keys = pp.keygen(str(td / "keys"), "authority")
        wrong = pp.keygen(str(td / "keys"), "stranger")

        image = pc.compile_predicate("when x >= 5").serialize()
        ppt = td / "policy.ppt"
        ppt.write_bytes(image)

        fields = {"x": "int"}
        manifest = pp.build_pack(str(ppt), fields, 3, "test-env",
                                 keys["private"], keys["public"])
        sig = (td / "policy.ppt.manifest.sig").read_bytes()

        env = pp.build_envelope("test-env", {"x": "int", "y": "str"}, None,
                                keys["private"], keys["public"], str(td / "env"))
        env_sig = (td / "env" / "test-env.envelope.sig").read_bytes()

        # ---- negative variants, each with the verdict PYTHON actually returns ----
        cases = []

        def record(name, image_b, manifest_obj, sig_b, pubs, revoked, check_env=True):
            """Write the variant to disk, run the real gates, freeze verdicts."""
            d = td / f"case_{name}"
            d.mkdir()
            p = d / "policy.ppt"
            p.write_bytes(image_b)
            (d / "policy.ppt.manifest.json").write_text(json.dumps(manifest_obj, indent=1,
                                                                   sort_keys=True) + "\n")
            (d / "policy.ppt.manifest.sig").write_bytes(sig_b)
            ok, reasons, _m = pp.verify_pack(str(p), pubs, frozenset(revoked))
            entry = {"name": name, "image_b64": b64(image_b), "manifest": manifest_obj,
                     "sig_hex": sig_b.hex(),
                     "pubs": [Path(x).read_bytes().hex() for x in pubs],
                     "revoked": list(revoked),
                     "verify": {"ok": ok, "reasons": reasons}}
            if ok and check_env:
                eok, ereasons = pp.check_envelope(_m, image_b, env)
                entry["envelope_check"] = {"ok": eok, "reasons": ereasons}
            cases.append(entry)

        pub, wrong_pub = keys["public"], wrong["public"]

        # valid pack (verify ok + envelope ok)
        record("valid", image, manifest, sig, [pub], [])

        # tampered image: one byte flipped -> image:sha256-mismatch
        t_img = bytearray(image); t_img[-1] ^= 0xFF
        record("tampered_image", bytes(t_img), manifest, sig, [pub], [])

        # tampered manifest: version bumped after signing -> sig:invalid
        t_man = dict(manifest); t_man["version"] = 9
        record("tampered_manifest", image, t_man, sig, [pub], [])

        # wrong key list -> sig:invalid
        record("wrong_key", image, manifest, sig, [wrong_pub], [])

        # revoked signer -> sig:revoked-key
        record("revoked_key", image, manifest, sig, [pub], [keys["key_id"]])

        # out-of-envelope field: manifest fields {"z": int}, properly re-signed -> verify ok,
        # envelope check fails with envelope:unknown-field:z
        m_z = pp.build_manifest(image, {"z": "int"}, 4, "test-env", keys["key_id"])
        sig_z = pp._load_private(keys["private"]).sign(pp.canonical_bytes(m_z))
        record("bad_envelope_field", image, m_z, sig_z, [pub], [])

        # injected out-of-fragment opcode: patch a prog word to 0x9999, re-sign over the
        # TAMPERED image (bypassing build_pack's refusal) -> verify ok (sig+hash match), the
        # image-native opcode walk catches it at envelope check
        h = pp.read_ppt_header(image)
        prog_off = (pp.HEADER.size + pp.ATOM.size * h["atoms"] + pp.NODE.size * h["nodes"]
                    + pp.EDGE.size * h["edges"])
        bad_img = bytearray(image)
        struct.pack_into("<H", bad_img, prog_off, 0x9999)
        bad_img = bytes(bad_img)
        m_op = pp.build_manifest(bad_img, fields, 5, "test-env", keys["key_id"])
        sig_op = pp._load_private(keys["private"]).sign(pp.canonical_bytes(m_op))
        record("injected_opcode", bad_img, m_op, sig_op, [pub], [])

        doc = {
            "version": 1,
            "note": "Cross-language hot-swap fixtures. Every verdict (ok + stable reasons) was "
                    "produced by the Python reference gates; the Rust port must reproduce each "
                    "exactly. version_floor: swapping the valid pack (version 3) twice must "
                    "reject the second with version:not-monotonic:3<=3.",
            "envelope": env,
            "envelope_sig_hex": env_sig.hex(),
            "authority_pub_hex": Path(pub).read_bytes().hex(),
            "authority_key_id": keys["key_id"],
            "cases": cases,
        }
        OUT.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
        print(f"wrote {OUT}  ({len(cases)} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
