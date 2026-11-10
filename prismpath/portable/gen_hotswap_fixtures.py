# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze cross-language HOT-SWAP fixtures: a Python-signed pack + envelope + the full negative
matrix, every expected verdict computed by RUNNING the Python reference gates (verify_pack /
check_envelope) — so the Rust port is measured against what Python actually decides, reason
strings included.

    python prismpath/portable/gen_hotswap_fixtures.py   ->  conformance/hotswap.json

Ephemeral keys are generated fresh and FROZEN (pub raw + everything signed); private keys never
leave this generator. The image is compiled from a fixed predicate so bytes are deterministic.

Beyond the signed packs, the corpus freezes what Python decides about the image format itself:
header flags, the signed `safe_node`, the node attribute and name hash sections, the worst case
cycle bound (`wcet_cycles`) a manifest signs and a verifier recomputes, the spiral packing sidecar
checks, `overlay_of`, `flow_sha256` and the flow derived field dictionary. `images` replays
`validate_image` on bare images; the `cases` replay `verify_pack` and `check_envelope`.
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

from prismpath.hotswap import policy_pack as pp  # noqa: E402
import ppt_compile as pc                         # noqa: E402

OUT = HERE / "conformance" / "hotswap.json"

b64 = lambda raw_bytes: base64.b64encode(raw_bytes).decode()


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

        def record(name, image_b, manifest_obj, sig_b, pubs, revoked, check_env=True, sidecar=None,
                   envelope=None, manifest_raw=None):
            """Write the variant to disk, run the real gates, freeze verdicts."""
            case_dir = td / f"case_{name}"
            case_dir.mkdir()
            pack_path = case_dir / "policy.ppt"
            pack_path.write_bytes(image_b)
            if manifest_raw is not None:
                (case_dir / "policy.ppt.manifest.json").write_bytes(manifest_raw)
            else:
                (case_dir / "policy.ppt.manifest.json").write_text(json.dumps(manifest_obj, indent=1,
                                                                       sort_keys=True) + "\n")
            (case_dir / "policy.ppt.manifest.sig").write_bytes(sig_b)
            if sidecar is not None:
                (case_dir / "policy.ppt.spiral").write_bytes(sidecar)
            ok, reasons, _m = pp.verify_pack(str(pack_path), pubs, frozenset(revoked))
            entry = {"name": name, "image_b64": b64(image_b), "manifest": manifest_obj,
                     "sig_hex": sig_b.hex(),
                     "pubs": [Path(pub_path).read_bytes().hex() for pub_path in pubs],
                     "revoked": list(revoked),
                     "verify": {"ok": ok, "reasons": reasons}}
            if manifest_raw is not None:
                entry["manifest_raw_hex"] = manifest_raw.hex()   # the manifest file's own bytes; `manifest` is null
            if sidecar is not None:
                entry["sidecar_b64"] = b64(sidecar)
            if envelope is not None:
                entry["envelope"] = envelope
            if ok and check_env:
                eok, ereasons = pp.check_envelope(_m, image_b, envelope if envelope is not None else env)
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

        # a manifest file that cannot be parsed is `manifest:bad-format` with no manifest, never an
        # exception out of the gate: text that is not JSON, not UTF-8, NaN, Infinity, -Infinity, a number
        # beyond the double range, not an object, empty
        good_text = json.dumps(manifest, indent=1, sort_keys=True)
        for variant, raw in [
            ("manifest_not_json", b"{not json"), ("manifest_empty", b""), ("manifest_not_utf8", b"\xff\xfe{}"),
            ("manifest_nan", good_text.replace('"version": 3', '"version": NaN').encode()),
            ("manifest_infinity", good_text.replace('"version": 3', '"version": Infinity').encode()),
            ("manifest_negative_infinity", good_text.replace('"version": 3', '"version": -Infinity').encode()),
            ("manifest_number_beyond_the_double_range", good_text.replace('"version": 3', '"version": 1e400').encode()),
            ("manifest_array", b"[1, 2, 3]"), ("manifest_scalar", b"7"), ("manifest_null", b"null"),
            ("manifest_wrong_format_is_still_bad_format", good_text.replace("ppt-pack/1", "ppt-pack/9").encode()),
            # canon/2 has no float: a manifest that names canon/2 and holds one does not read
            ("manifest_canon2_with_a_float", good_text.replace('"version": 3', '"version": 3.5').encode()),
            ("manifest_unknown_encoding", good_text.replace('"canon/2"', '"canon/3"').encode()),
        ]:
            assert variant != "manifest_nan" or b"NaN" in raw
            record(variant, image, None, sig, [pub], [], manifest_raw=raw)

        # a legacy (canon/1, untagged) manifest signed over its canon/1 compact bytes, as packs were signed
        # before the migration: canon/1 is retired, so it is `manifest:bad-format` and never verifies
        legacy = {key: value for key, value in manifest.items() if key != "encoding"}
        legacy_bytes = json.dumps(legacy, sort_keys=True, separators=(",", ":")).encode("ascii")
        record("a_canon1_manifest_is_refused", image, legacy,
               pp._load_private(keys["private"]).sign(legacy_bytes), [pub], [])
        # the same legacy manifest given the canon/2 tag after signing: the signature does not cover it
        record("legacy_signature_over_a_retagged_manifest", image, manifest,
               pp._load_private(keys["private"]).sign(legacy_bytes), [pub], [])

        # out-of-envelope field: manifest fields {"z": int}, properly re-signed -> verify ok,
        # envelope check fails with envelope:unknown-field:z
        m_z = pp.build_manifest(image, {"z": "int"}, 4, "test-env", keys["key_id"])
        sig_z = pp._load_private(keys["private"]).sign(pp.signed_bytes(m_z))
        record("bad_envelope_field", image, m_z, sig_z, [pub], [])

        # injected out-of-fragment opcode: patch a prog word to 0x9999, re-sign over the
        # TAMPERED image (bypassing build_pack's refusal) -> verify ok (sig+hash match), the
        # image-native opcode walk catches it at envelope check
        header = pp.read_ppt_header(image)
        prog_off = (pp.HEADER.size + pp.ATOM.size * header["atoms"] + pp.NODE.size * header["nodes"]
                    + pp.EDGE.size * header["edges"])
        bad_img = bytearray(image)
        struct.pack_into("<H", bad_img, prog_off, 0x9999)
        bad_img = bytes(bad_img)
        m_op = pp.build_manifest(bad_img, fields, 5, "test-env", keys["key_id"])
        sig_op = pp._load_private(keys["private"]).sign(pp.signed_bytes(m_op))
        record("injected_opcode", bad_img, m_op, sig_op, [pub], [])


        # ---- image format facts: flags, safe_node, sections, WCET, packing, overlay, flow hash ----
        priv = pp._load_private(keys["private"])

        def signed(image_b, version, fields_=None, mutate=None):
            """A manifest built by the reference over `image_b` (bypassing build_pack's refusal of an
            invalid image) and signed, optionally edited by `mutate` before signing."""
            man = pp.build_manifest(image_b, fields_ or fields, version, "test-env", keys["key_id"])
            if mutate:
                mutate(man)
            try:
                return man, priv.sign(pp.signed_bytes(man))
            except pp.canon.CanonicalError:
                # a float has no canon/2 form, so no signature can cover this manifest as canon/2: the case
                # keeps its tag, is signed over the spelling a writer that ignored canon/2 would produce,
                # and is refused as `manifest:bad-format` when it is read
                return man, priv.sign(pp.canon.CANON2_DOMAIN + json.dumps(man, sort_keys=True,
                                                                         separators=(",", ":")).encode("ascii"))

        def with_flagword(image_b, flagword):
            raw = bytearray(image_b)
            struct.pack_into("<H", raw, 26, flagword)
            return bytes(raw)

        header = pp.read_ppt_header(image)
        n_nodes = header["nodes"]                                  # 2: node 1 is a real fail-safe target
        attr = lambda *values: b"".join(struct.pack("<H", value) for value in values)
        names = lambda *values: b"".join(struct.pack("<I", value) for value in values)
        version = [10]

        def image_case(name, image_b, caps=None):
            """A bare image, with the reference's validate_image verdict and header facts."""
            ok, reasons = pp.validate_image(image_b, caps)
            entry = {"name": name, "image_b64": b64(image_b), "validate": {"ok": ok, "reasons": reasons}}
            if caps is not None:
                entry["caps"] = caps
            try:
                entry["header"] = pp.read_ppt_header(image_b)
            except ValueError as exc:
                entry["header_error"] = str(exc)
            images.append(entry)

        def pack_case(name, image_b, mutate=None, **kwargs):
            version[0] += 1
            man, sig_b = signed(image_b, version[0], mutate=mutate)
            record(name, image_b, man, sig_b, [pub], [], **kwargs)

        images = []
        flag_images = {
            "safe_node_valid": with_flagword(image, 1 << 8),
            "safe_node_oob": with_flagword(image, 200 << 8),
            "safe_node_equals_node_count": with_flagword(image, n_nodes << 8),
            "safe_node_high_byte_max": with_flagword(image, 0xFF00),
            "flag_migrate_by_name": with_flagword(image, pp.FLAG_MIGRATE_BY_NAME | (1 << 8)),
            "flag_stateful": with_flagword(image, pp.FLAG_STATEFUL),
            "flags_unknown_bits": with_flagword(image, 0x00F0),
            "flag_node_attr_missing_section": with_flagword(image, pp.FLAG_NODE_ATTR),
            "flag_node_names_missing_section": with_flagword(image, pp.FLAG_NODE_NAMES),
            "flag_node_attr_ok": with_flagword(image, pp.FLAG_NODE_ATTR) + attr(0, 0x3F),
            "flag_node_attr_oob": with_flagword(image, pp.FLAG_NODE_ATTR) + attr(0x40, 0xFFFF),
            "flag_node_names_ok": with_flagword(image, pp.FLAG_NODE_NAMES) + names(0x811C9DC5, 0xFFFFFFFF),
            "flags_attr_and_names_ok": (with_flagword(image, pp.FLAG_NODE_ATTR | pp.FLAG_NODE_NAMES)
                                        + attr(1, 2) + names(7, 9)),
            "flags_attr_and_names_attr_oob": (with_flagword(image, pp.FLAG_NODE_ATTR | pp.FLAG_NODE_NAMES)
                                              + attr(2, 0x41) + names(7, 9)),
            "flags_attr_and_names_wrong_length": (with_flagword(image, pp.FLAG_NODE_ATTR | pp.FLAG_NODE_NAMES)
                                                  + attr(1, 2) + names(7)),
            "safe_node_oob_and_length_mismatch": with_flagword(image, (200 << 8) | pp.FLAG_NODE_ATTR),
            "safe_node_oob_and_attr_oob": with_flagword(image, (9 << 8) | pp.FLAG_NODE_ATTR) + attr(0x7F, 0),
            "trailing_byte": image + b"\x00",
            "truncated_header": image[:27],
            "bad_magic": b"XXXX" + image[4:],
            "bad_version": image[:4] + struct.pack("<H", 2) + image[6:],
        }
        for name, flagged in flag_images.items():
            image_case(name, flagged)
        image_case("valid_with_caps", image, {"atoms": 1, "nodes": 2, "edges": 1, "prog_words": 1,
                                              "max_steps": 25, "max_stack": 16})
        image_case("caps_exceeded", image, {"atoms": 0, "nodes": 1})
        image_case("empty_caps_check_nothing", image, {})
        image_case("caps_exceeded_after_safe_node_oob", flag_images["safe_node_oob"], {"nodes": 1})

        # signed packs over the same images: verify (signature, hash, counts, WCET) then the envelope gate
        # (verify_pack never walks the image, so a manifest over a short one still verifies when its
        # WCET is computable; the envelope gate is what refuses the length)
        for name in ("safe_node_valid", "safe_node_oob", "flag_migrate_by_name", "flag_stateful",
                     "flags_unknown_bits", "flag_node_attr_ok", "flag_node_attr_oob", "flag_node_names_ok",
                     "flags_attr_and_names_ok", "flag_node_attr_missing_section"):
            pack_case("pack_" + name, flag_images[name])

        # WCET: recorded wrong, recorded as an equal float, absent (a pack from before it existed)
        wcet = pp.wcet_cycles(image)
        pack_case("wcet_mismatch", image, mutate=lambda man: man.__setitem__("wcet_cycles", wcet + 1))
        pack_case("wcet_equal_float", image, mutate=lambda man: man.__setitem__("wcet_cycles", float(wcet)))
        pack_case("wcet_null", image, mutate=lambda man: man.__setitem__("wcet_cycles", None))
        pack_case("wcet_string", image, mutate=lambda man: man.__setitem__("wcet_cycles", str(wcet)))
        pack_case("wcet_absent", image, mutate=lambda man: man.pop("wcet_cycles"))
        pack_case("count_equal_float", image, mutate=lambda man: man["counts"].__setitem__("atoms", 1.0))
        pack_case("count_mismatch_bool", image, mutate=lambda man: man["counts"].__setitem__("nodes", True))

        # WCET is a max over nodes of the sum over their edges: a hand built two edge, long program image
        wide = bytearray(image) + b"\x00\x00" * 39               # 40 program words, all atom 0
        struct.pack_into("<H", wide, 16, 40)                       # prog_words in the header
        struct.pack_into("<HHH", wide, pp.HEADER.size + pp.ATOM.size + pp.NODE.size * 2, 1, 0, 40)
        wide = bytes(wide)
        image_case("long_program", wide)
        pack_case("pack_long_program", wide)

        # packing: the spiral sidecar the manifest declares
        sidecar = b"spiral-sidecar-bytes"
        pack_case("packing_ok", image, sidecar=sidecar,
                  mutate=lambda man: man.__setitem__("packing", {"profile": "spiral",
                                                                 "sidecar_sha256": pp.sha256_hex(sidecar)}))
        pack_case("packing_sidecar_missing", image,
                  mutate=lambda man: man.__setitem__("packing", {"profile": "spiral",
                                                                 "sidecar_sha256": pp.sha256_hex(sidecar)}))
        pack_case("packing_sidecar_hash_mismatch", image, sidecar=b"other bytes",
                  mutate=lambda man: man.__setitem__("packing", {"profile": "spiral",
                                                                 "sidecar_sha256": pp.sha256_hex(sidecar)}))
        pack_case("packing_unknown_profile", image, sidecar=sidecar,
                  mutate=lambda man: man.__setitem__("packing", {"profile": "zip",
                                                                 "sidecar_sha256": pp.sha256_hex(sidecar)}))
        pack_case("packing_no_profile", image, sidecar=sidecar,
                  mutate=lambda man: man.__setitem__("packing", {"sidecar_sha256": pp.sha256_hex(sidecar)}))
        pack_case("packing_no_hash", image, sidecar=sidecar,
                  mutate=lambda man: man.__setitem__("packing", {"profile": "spiral"}))

        # overlay_of and flow_sha256 ride the signed manifest, changing nothing about verification;
        # the flow derived field dictionary is bound as the manifest's fields
        flow_text = ("---\nname: fx_pack\nstart: s\nfield.error_rate: fixed scale=10000 unit=ratio "
                     "rounding=floor min=0 max=10000\nfield.label: category absent=allowed\n---\n"
                     "## s\n-> hit: when error_rate >= 0.85\n-> gone: when label == None\n-> miss: else\n"
                     "## hit\n## gone\n## miss\n")
        flow_fields = pp.field_dictionary_of(flow_text)
        flow_image = image          # the image is the signer's to assert as compiled from the flow
        version[0] += 1
        flow_ppt = td / "flow.ppt"
        flow_ppt.write_bytes(flow_image)
        flow_manifest = pp.build_pack(str(flow_ppt), {}, version[0], "test-env", keys["private"],
                                      keys["public"], overlay_of="baseline-2026-07", flow_text=flow_text)
        flow_sig = (td / "flow.ppt.manifest.sig").read_bytes()
        record("overlay_and_flow_sha256", flow_image, flow_manifest, flow_sig, [pub], [], check_env=False)
        flow_pack = {"flow_text": flow_text, "fields": flow_fields,
                     "flow_sha256": flow_manifest["flow_sha256"], "overlay_of": "baseline-2026-07"}

        # envelope variants: caps that the image exceeds, and an empty caps object (checks nothing)
        pack_case("envelope_caps_exceeded", image, envelope={**env, "caps": {"atoms": 0}})
        pack_case("envelope_empty_caps", image, envelope={**env, "caps": {}})

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
            "images": images,
            "flow_pack": flow_pack,
        }
        OUT.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
        print(f"wrote {OUT}  ({len(cases)} cases, {len(images)} images)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
