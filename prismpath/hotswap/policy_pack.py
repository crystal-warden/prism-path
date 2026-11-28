# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Signed policy packs — the Authorized + Envelope-bounded half of the secure hot-swap.

A pack is the byte-identical `.ppt` image plus a detached, signed manifest
(`docs/design/spec-secure-hotswap.md` §3.1). From 0.3.0 the writer, `seal_pack`, emits only a distribution
envelope (L1 of `docs/design/spec-policy-distribution.md`): `<ppt>.sealed`, a `policy.ppt` envelope for the
`host` kind whose `meta` carries what the manifest carried. `verify_pack` reads it, and still reads the older
`ppt-pack/1` manifest beside an image that has no `.sealed` (L3); the manifest it returns says which by its
`format`. `build_pack` writes the older form and is kept for the conformance fixtures and the tests' helpers. Nothing here modifies the image or the compiler:
this module is a read-only consumer of the `.ppt` format (SPEC §7 / TABLE_FORMAT.md), so every
certified image hash stays exactly what the FPGA/eBPF evidence rows cite.

Crypto is Ed25519 via the `cryptography` library, an optional extra (`pip install
prismpath[signing]`) with loud absence: verification unavailable -> refuse with the install
message, never fall through (the otel.py pattern). All checks return `(ok, [cause-name])`
tuples, every name a row in the cause registry (prismpath/kernel/causes.py), so tests and audit
rows pin exact failure classes. A parameterized check appends a `:<detail>` suffix to its
registered name; the registry row is the part before that suffix.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from prismpath import canon
from prismpath.onion import keys
# --- .ppt format facts, read from the compiler that writes them (kernel/ppt_compile.py / TABLE_FORMAT.md) ---
from prismpath.kernel.ppt_compile import (  # noqa: F401  (re-exported: the readers use policy_pack.HEADER and so on)
    ATOM, EDGE, FLAG_COLORS, FLAG_MIGRATE_BY_NAME, FLAG_NODE_ATTR, FLAG_NODE_NAMES, FLAG_STATEFUL, FORMAT_VERSION,
    HEADER, MAGIC, NODE, OPS, PROG_OPCODES, TYPES, WORD)

PACK_FORMAT = "ppt-pack/1"
SEALED = ".sealed"                # the `policy.ppt` envelope beside an image (L1)

# Default envelope caps = the eBPF loader's MAX_* constants (ppt_common.h) — the first place
# these bounds are enforced at build/load time rather than assumed.
DEFAULT_CAPS = {"atoms": 1024, "nodes": 256, "edges": 1024, "prog_words": 4096,
                "max_steps": 25, "max_stack": 16}

_INSTALL_MSG = keys.INSTALL_MSG
MissingSigningExtra = keys.MissingSigningExtra
# The older private names, kept as the same functions until the shims go: integrations and the certified caller
# (comparisons/groupa/ai_worker_governance_loop.py) read them. New code calls `prismpath.onion.keys`.
_ed25519 = keys.primitives
_load_private = keys.load_private_key


def canonical_bytes(obj) -> bytes:
    """The bytes a document is hashed over (`canon.document_bytes`): its canon/2 bytes. A document that does
    not name canon/2 (canon/1 is retired) raises EncodingError."""
    return canon.document_bytes(obj)


def signed_bytes(obj) -> bytes:
    """The bytes a signature over a manifest, an envelope, a flow authority manifest or a crypto registry
    covers (`canon.signed_message`): `canon.CANON2_DOMAIN` and the canon/2 bytes. A document that does not
    name canon/2 raises EncodingError."""
    return canon.signed_message(obj)


def write_signed_document(path: str, doc: dict) -> None:
    """A signed document as it is written to disk: its canon/2 bytes and a newline."""
    with open(path, "wb") as handle:
        handle.write(canon.canon2_bytes(doc) + b"\n")


sha256_hex = canon.sha256_hex


# ------------------------------------------------------------------ image parsing

def read_ppt_header(data: bytes) -> dict:
    """Parse the 28-byte header. Raises ValueError on wrong magic/version/truncation. The 12th word
    is split: low byte = flags (FLAG_NODE_ATTR et al.), high byte = safe_node (0 = undeclared)."""
    if len(data) < HEADER.size:
        raise ValueError("image:truncated-header")
    (magic, version, n_fields, n_interns, n_atoms, n_nodes, n_edges,
     prog_len, start, visits_idx, max_steps, max_stack, flagword) = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise ValueError("image:bad-magic")
    if version != FORMAT_VERSION:
        raise ValueError("image:bad-version")
    return {"fields": n_fields, "interns": n_interns, "atoms": n_atoms, "nodes": n_nodes,
            "edges": n_edges, "prog_words": prog_len, "start": start,
            "visits_idx": visits_idx, "max_steps": max_steps, "max_stack": max_stack,
            "flags": flagword & 0x00FF, "safe_node": (flagword >> 8) & 0xFF,
            "migrate_by_name": bool(flagword & FLAG_MIGRATE_BY_NAME),
            "stateful": bool(flagword & FLAG_STATEFUL)}


def validate_image(data: bytes, caps: Optional[dict] = None) -> Tuple[bool, List[str]]:
    """Image-native structural + fragment check: exact length, atom ops/types in the Level M
    fragment, program words resolve to atoms or boolean opcodes, node/edge indices in range,
    and (when caps given) every count within the envelope. The compiler guarantees fragment
    membership at build time; this re-verifies the shipped artifact at load time."""
    reasons: List[str] = []
    try:
        header = read_ppt_header(data)
    except ValueError as exc:
        return False, [str(exc)]

    if header["safe_node"] and header["safe_node"] >= header["nodes"]:
        reasons.append("image:safe-node-oob")    # signed fail-safe must name a real node

    need = (HEADER.size + ATOM.size * header["atoms"] + NODE.size * header["nodes"]
            + EDGE.size * header["edges"] + WORD.size * header["prog_words"])
    if header["flags"] & FLAG_NODE_ATTR:
        need += WORD.size * header["nodes"]      # one uint16 per-node attribute
    if header["flags"] & FLAG_NODE_NAMES:
        need += 4 * header["nodes"]      # one uint32 name-hash per node, after the node-attr section
    if len(data) != need:
        reasons.append("image:length-mismatch")
        return False, reasons

    if caps:
        for key, cap_key in (("atoms", "atoms"), ("nodes", "nodes"), ("edges", "edges"),
                             ("prog_words", "prog_words"), ("max_steps", "max_steps"),
                             ("max_stack", "max_stack")):
            if header[key] > caps.get(cap_key, DEFAULT_CAPS[cap_key]):
                reasons.append(f"image:caps-exceeded:{cap_key}")   # cause 16, the registered name

    off = HEADER.size
    for index in range(header["atoms"]):
        fidx, op, ty, _val = ATOM.unpack_from(data, off)
        off += ATOM.size
        if op not in OPS:
            reasons.append(f"image:unknown-op:atom{index}")
        if ty not in TYPES:
            reasons.append(f"image:unknown-type:atom{index}")
        if fidx >= header["fields"]:
            reasons.append(f"image:field-index-oob:atom{index}")
    off += NODE.size * header["nodes"]
    for index in range(header["edges"]):
        target, po, pc = EDGE.unpack_from(data, off)
        off += EDGE.size
        if target >= header["nodes"]:
            reasons.append(f"image:edge-target-oob:edge{index}")
        if po + pc > header["prog_words"]:
            reasons.append(f"image:edge-prog-oob:edge{index}")
    for index in range(header["prog_words"]):
        (word,) = WORD.unpack_from(data, off)
        off += WORD.size
        if word >= 0x8000 and word not in PROG_OPCODES:
            reasons.append(f"image:unknown-opcode:word{index}")
        if word < 0x8000 and word >= header["atoms"]:
            reasons.append(f"image:atom-index-oob:word{index}")
    if header["flags"] & FLAG_NODE_ATTR:
        for index in range(header["nodes"]):
            (attr_value,) = WORD.unpack_from(data, off)
            off += WORD.size
            if attr_value > 0x3F:        # fabric materialization envelope: 6-bit LED {LD5,LD4}
                reasons.append(f"image:node-attr-oob:node{index}")

    return (not reasons), reasons


def wcet_cycles(data: bytes) -> int:
    """Per-evaluate worst-case cycle bound = max over nodes of (sum over its edges of
    (2 + max(prog_words, 1))) + 2. Equals 2*E + P + 2 for compiler-emitted policies (every edge's
    program is at least one word); the max(., 1) term keeps the bound exact for hand-crafted images
    with zero-word edges, which still cost one S_RUN cycle each (the 3E+P adversarial case the
    formal work surfaced). The interpreter is a fixed FSM with no micro-architecture, so this is
    exact, not an over-approximation; calibrated + validated against the RTL in
    prismpath-hw/tb/wcet. At clock f, the time bound is wcet_cycles / f."""
    header = read_ppt_header(data)
    off = HEADER.size + ATOM.size * header["atoms"]
    node_recs = [NODE.unpack_from(data, off + index * NODE.size) for index in range(header["nodes"])]
    off += NODE.size * header["nodes"]
    edge_pcnt = [EDGE.unpack_from(data, off + index * EDGE.size)[2] for index in range(header["edges"])]
    worst = 0
    for eoff, ecnt in node_recs:                 # (edge_off, edge_cnt)
        worst = max(worst, sum(2 + max(pred_words, 1) for pred_words in edge_pcnt[eoff:eoff + ecnt]) + 2)
    return worst


# ------------------------------------------------------------------ keys

def keygen(out_dir: str, name: str = "authority") -> dict:
    """Generate an Ed25519 keypair. Private key PEM written 0600; returns paths + key_id
    (sha256 of the raw public bytes — the identity used in manifests and revocation lists). An authority key
    already under the name is replaced (`keys.keygen` with `replace`)."""
    return keys.keygen(out_dir, name, replace=True)


def load_public_raw(path: str) -> Tuple[bytes, str]:
    """A raw-32-byte Ed25519 public key file -> (raw, key_id), refused as `load_public` refuses it."""
    keys.require()                               # the loud absence comes before the file is read, as ever
    with open(path, "rb") as handle:
        raw = handle.read()
    keys.public_key(raw)                         # ValueError for a file that is not 32 raw bytes, as ever
    return raw, sha256_hex(raw)


def load_public(path: str) -> Tuple[object, str]:
    """Load a raw-32-byte Ed25519 public key file -> (key, key_id)."""
    raw, key_id = load_public_raw(path)
    return keys.public_key(raw), key_id


def load_revoked(path: Optional[str]) -> frozenset:
    """Revocation list: a JSON array of key_id hex strings. Missing path -> empty set."""
    if not path or not os.path.exists(path):
        return frozenset()
    with open(path) as handle:
        return frozenset(json.load(handle))


# ------------------------------------------------------------------ manifest / pack

def build_manifest(image: bytes, fields: Dict[str, str], version: int,
                   envelope_id: str, key_id: str) -> dict:
    header = read_ppt_header(image)
    return {
        "format": PACK_FORMAT,
        canon.ENCODING_KEY: canon.CANON2,
        "image_sha256": sha256_hex(image),
        "fields": dict(fields),
        "counts": {"atoms": header["atoms"], "nodes": header["nodes"], "edges": header["edges"],
                   "prog_words": header["prog_words"], "max_steps": header["max_steps"],
                   "max_stack": header["max_stack"]},
        "wcet_cycles": wcet_cycles(image),       # per-evaluate worst case, signed with the policy
        "version": int(version),
        "envelope_id": envelope_id,
        "key_id": key_id,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def field_dictionary_of(flow_text: str) -> Dict[str, str]:
    """The manifest field dictionary of a flow that defines its fields (SPEC section 4.5): each field
    name with its definition in canonical spelling. Signed into a pack, it binds the interpretation
    of every value the image compares, the scale, unit, rounding, range and absence, and the
    envelope gate compares it entry for entry, so a receiver declaring a different scale refuses the
    pack. A flow that breaks its definitions raises here, as it does at parse."""
    from prismpath.kernel.parser import parse
    graph = parse(flow_text)
    if not graph.fields:
        raise ValueError("the flow defines no fields, so there is no definition to bind; pass the field "
                         "dictionary explicitly")
    return {name: definition.canonical_text() for name, definition in sorted(graph.fields.items())}


def build_pack(ppt_path: str, fields: Dict[str, str], version: int, envelope_id: str,
               priv_path: str, pub_path: str, packing: Optional[dict] = None,
               overlay_of: Optional[str] = None, flow_text: Optional[str] = None) -> dict:
    """The older form (L3): sign a `.ppt` into a `ppt-pack/1` pack, writing `<ppt>.manifest.json` + `<ppt>.manifest.sig`
    beside the (untouched) image. Returns the manifest.

    `overlay_of` (optional) names the policy of record this pack temporarily overrides (an
    operator's short lived change). It rides the signed manifest, is carried into the host's
    active record, and `attest` prints it, so the owner of the baseline can see an overlay is in
    force. It changes nothing about verification or the version floor.

    `packing` (optional) declares a wire-packing profile whose baked artifact rides the pack,
    e.g. {"profile": "spiral", "sidecar_sha256": <hex of `<ppt>.spiral`>} — built by the
    telemetry adapter's `spiral_pack.write_sidecar`, which lint-gates the flow. The manifest
    signature then covers the declaration, and `verify_pack` re-hashes the sidecar at load.

    `flow_text` (optional) is the authored flow the image was compiled from. When the flow defines its
    fields, the field dictionary is derived from those definitions and an explicit `fields` must
    match it. The manifest also records `flow_sha256`, so the signature covers the authored text,
    decimal thresholds included, beside the image's canonical integers. The image is not recompiled
    here to check that it came from this flow; that correspondence is the signer's to assert."""
    flow_sha256 = None
    if flow_text is not None:
        derived = field_dictionary_of(flow_text)
        if fields and dict(fields) != derived:
            raise ValueError(f"the field dictionary {dict(fields)} differs from the flow's own definitions {derived}")
        fields = derived
        flow_sha256 = sha256_hex(flow_text.encode("utf-8"))
    with open(ppt_path, "rb") as handle:
        image = handle.read()
    ok, reasons = validate_image(image)
    if not ok:
        raise ValueError("refusing to sign an invalid image: " + ",".join(reasons))
    _pub, key_id = load_public(pub_path)
    manifest = build_manifest(image, fields, version, envelope_id, key_id)
    if packing is not None:
        if packing.get("profile") != "spiral" or not packing.get("sidecar_sha256"):
            raise ValueError("packing: only {'profile': 'spiral', 'sidecar_sha256': ...} is defined")
        manifest["packing"] = {"profile": "spiral",
                               "sidecar_sha256": packing["sidecar_sha256"]}
    if overlay_of:
        manifest["overlay_of"] = str(overlay_of)
    if flow_sha256 is not None:
        manifest["flow_sha256"] = flow_sha256
    sig = keys.load_signer(priv_path).sign(signed_bytes(manifest))
    write_signed_document(ppt_path + ".manifest.json", manifest)
    with open(ppt_path + ".manifest.sig", "wb") as handle:
        handle.write(sig)
    return manifest


def seal_pack(ppt_path: str, fields: Dict[str, str], version: int, envelope_id: str,
              priv_path: str, pub_path: str, packing: Optional[dict] = None,
              overlay_of: Optional[str] = None, flow_text: Optional[str] = None, *,
              stream: Optional[str] = None, not_before: Optional[int] = None,
              expires: Optional[int] = None) -> dict:
    """Seal a `.ppt` as a `policy.ppt` distribution envelope for the `host` kind (L1): writes `<ppt>.sealed` beside
    the untouched image and removes an older manifest and signature beside it. The arguments are `build_pack`'s and
    mean what they meant there: `version` is the envelope's `seq`, `envelope_id` the qualification envelope the
    pack is for (`meta.qualification`), and `fields`, the counts, `wcet_cycles`, `packing`, `overlay_of` and
    `flow_sha256` go in `meta`. The stream is `local` and the lifetime ten years unless `stream`, `not_before` and
    `expires` say otherwise. Returns what the envelope says, in the members of a manifest, with `format`
    `prismpath.dist/1`."""
    from prismpath.distribution import envelope as env
    from prismpath.distribution import legacy
    from prismpath.distribution.kinds import Refused
    flow_sha256 = None
    if flow_text is not None:
        derived = field_dictionary_of(flow_text)
        if fields and dict(fields) != derived:
            raise ValueError(f"the field dictionary {dict(fields)} differs from the flow's own definitions {derived}")
        fields = derived
        flow_sha256 = sha256_hex(flow_text.encode("utf-8"))
    with open(ppt_path, "rb") as handle:
        image = handle.read()
    ok, reasons = validate_image(image)
    if not ok:
        raise ValueError("refusing to sign an invalid image: " + ",".join(reasons))
    _pub, key_id = load_public(pub_path)
    priv = keys.load_signer(priv_path)
    if priv.key_id != key_id:
        raise ValueError(f"{priv_path} is not the private half of {pub_path}")
    header = read_ppt_header(image)
    meta = {"fields": dict(fields or {}), "qualification": envelope_id, "wcet_cycles": wcet_cycles(image),
            "counts": {name: header[name] for name in ("atoms", "nodes", "edges", "prog_words", "max_steps",
                                                       "max_stack")}}
    if packing is not None:
        if packing.get("profile") != "spiral" or not packing.get("sidecar_sha256"):
            raise ValueError("packing: only {'profile': 'spiral', 'sidecar_sha256': ...} is defined")
        meta["packing"] = {"profile": "spiral", "sidecar_sha256": packing["sidecar_sha256"]}
    if overlay_of:
        meta["overlay_of"] = str(overlay_of)
    if flow_sha256 is not None:
        meta["flow_sha256"] = flow_sha256
    try:
        sealed = legacy.local_seal("policy.ppt", image, [priv], seq=int(version), targets=("host",), meta=meta,
                                   not_before=not_before, expires=expires, stream=stream or legacy.LOCAL_STREAM)
    except Refused as refused:
        raise ValueError(f"the pack would not be a well formed envelope ({refused.cause}: {refused})") from None
    canon.atomic_write_bytes(ppt_path + SEALED, sealed)
    for older in (ppt_path + ".manifest.json", ppt_path + ".manifest.sig"):
        if os.path.exists(older):
            os.remove(older)
    return _sealed_manifest(env.read(env.unseal(sealed)[0]), key_id)


def _sealed_manifest(envelope, key_id: str) -> dict:
    """A `policy.ppt` envelope in the members of a manifest, so every reader of `verify_pack` reads either form."""
    meta = envelope.meta
    out = {"format": "prismpath.dist/1", "artifact": envelope.artifact,
           "image_sha256": envelope.body_sha256, "fields": dict(meta["fields"]), "counts": dict(meta["counts"]),
           "wcet_cycles": meta["wcet_cycles"], "version": envelope.seq, "envelope_id": meta["qualification"],
           "key_id": key_id, "stream": envelope.stream, "not_before": envelope.not_before,
           "expires": envelope.expires, "dist_envelope_id": envelope.envelope_id}
    for name in ("packing", "overlay_of", "flow_sha256"):
        if name in meta:
            out[name] = meta[name]
    return out


def _verify_sealed(ppt_path: str, pubkey_paths: List[str],
                   revoked: frozenset) -> Tuple[bool, List[str], Optional[dict]]:
    """`verify_pack` for `<ppt>.sealed`: a `policy.ppt` envelope for `host`, signed by a known key that is not
    revoked, in force now (V6), over this image, with its signed counts and packing as a manifest's."""
    import time
    from prismpath.distribution import envelope as env
    from prismpath.distribution.kinds import Refused
    from prismpath.distribution.verify import SKEW
    keys.require()
    try:
        with open(ppt_path + SEALED, "rb") as handle:
            envelope_bytes, entries = env.unseal(handle.read())
        envelope = env.read(envelope_bytes)
    except Refused as refused:
        return False, [refused.cause], None
    if envelope.artifact != "policy.ppt" or "host" not in envelope.targets:
        return False, ["dist:target-mismatch"], None
    message, signer_id = env.signed_message(envelope_bytes), None
    held = dict((key_id, public_raw) for public_raw, key_id in (load_public_raw(path) for path in pubkey_paths))
    for key_id, signature in entries:
        if key_id not in held:
            continue
        if keys.verify(held[key_id], signature, message):
            signer_id = key_id
            break
    if signer_id is None:
        return False, ["sig:invalid"], None
    manifest = _sealed_manifest(envelope, signer_id)
    if signer_id in revoked:
        return False, ["sig:revoked-key"], manifest
    now = int(time.time())
    if envelope.not_before - now > SKEW:
        return False, ["dist:not-yet-valid"], manifest
    if now >= envelope.expires:
        return False, ["dist:expired"], manifest
    with open(ppt_path, "rb") as handle:
        image = handle.read()
    if len(image) != envelope.body_size or sha256_hex(image) != envelope.body_sha256:
        return False, ["image:sha256-mismatch"], manifest
    reasons = check_counts(envelope.meta, image)
    if reasons:
        return False, reasons, manifest
    return _check_packing(ppt_path, manifest)


def _check_packing(ppt_path: str, manifest: dict) -> Tuple[bool, List[str], Optional[dict]]:
    if "packing" in manifest:
        pk = manifest["packing"]
        if pk.get("profile") != "spiral":
            return False, ["packing:unknown-profile"], manifest
        side_path = ppt_path + ".spiral"
        if not os.path.exists(side_path):
            return False, ["spiral:sidecar-missing"], manifest
        with open(side_path, "rb") as handle:
            if sha256_hex(handle.read()) != pk.get("sidecar_sha256"):
                return False, ["spiral:sidecar-hash-mismatch"], manifest
    return True, [], manifest


def read_sealed_manifest(ppt_path: str) -> Optional[dict]:
    """What `<ppt>.sealed` says, in the members of a manifest, read without checking its signature (for a view
    that shows an unchecked pack), or None when there is none or it does not read."""
    from prismpath.distribution import envelope as env
    from prismpath.distribution.kinds import Refused
    try:
        with open(ppt_path + SEALED, "rb") as handle:
            envelope_bytes, entries = env.unseal(handle.read(env.MAX_SEALED + 1))
        envelope = env.read(envelope_bytes)
    except (OSError, Refused):
        return None
    if envelope.artifact != "policy.ppt":
        return None
    return _sealed_manifest(envelope, entries[0][0])


def is_older(manifest: Optional[dict]) -> bool:
    """True for a manifest `verify_pack` read in the older `ppt-pack/1` form (L3)."""
    return isinstance(manifest, dict) and manifest.get("format") == PACK_FORMAT


def verify_pack(ppt_path: str, pubkey_paths: List[str],
                revoked: frozenset = frozenset()) -> Tuple[bool, List[str], Optional[dict]]:
    """The Authorized gate. Verifies: signature over the canonical manifest by a known,
    non-revoked key; manifest key_id matches the verifying key; image hash and header counts
    match the manifest. Returns (ok, stable-reasons, manifest-or-None): a manifest that cannot be parsed
    (not JSON, not UTF-8, NaN, Infinity or a number beyond the double range, or not an object) is
    `manifest:bad-format` with no manifest.

    An image with `<ppt>.sealed` beside it is read in that form alone (`_verify_sealed`), and the manifest returned
    has `format` `prismpath.dist/1`. Otherwise the older manifest is read, and a reader with an audit log writes
    the `legacy_form` event for it (`is_older`)."""
    keys.require()
    if os.path.exists(ppt_path + SEALED):
        return _verify_sealed(ppt_path, pubkey_paths, revoked)
    man_path, sig_path = ppt_path + ".manifest.json", ppt_path + ".manifest.sig"
    if not os.path.exists(man_path) or not os.path.exists(sig_path):
        return False, ["sig:missing"], None
    try:
        with open(man_path, encoding="utf-8", newline="") as handle:
            manifest = canon.loads_document(handle.read())
    except canon.NotCanonical:
        # canon/2 in a spelling other than its canonical bytes: refused with its own registered cause, never
        # respelled before the signature is checked
        return False, [canon.NotCanonical.CAUSE], None
    except ValueError:
        # The registry's `manifest:bad-format` is "manifest unparseable": text that is not JSON, not UTF-8,
        # or holds NaN, Infinity or a number beyond the double range (`CanonicalReadError`) is that refusal,
        # a stable reason, and not an exception out of a gate that returns reasons.
        return False, ["manifest:bad-format"], None
    with open(sig_path, "rb") as handle:
        sig = handle.read()
    if not isinstance(manifest, dict):
        return False, ["manifest:bad-format"], None
    if manifest.get("format") != PACK_FORMAT:
        return False, ["manifest:bad-format"], manifest

    try:
        payload = signed_bytes(manifest)
    except canon.CanonicalError:
        return False, ["manifest:bad-format"], manifest
    signer_id = None
    for path in pubkey_paths:
        public_raw, key_id = load_public_raw(path)
        if keys.verify(public_raw, sig, payload):
            signer_id = key_id
            break
    if signer_id is None:
        return False, ["sig:invalid"], manifest
    if signer_id in revoked:
        return False, ["sig:revoked-key"], manifest
    if manifest.get("key_id") != signer_id:
        return False, ["manifest:key-id-mismatch"], manifest

    with open(ppt_path, "rb") as handle:
        image = handle.read()
    if sha256_hex(image) != manifest.get("image_sha256"):
        return False, ["image:sha256-mismatch"], manifest
    if not isinstance(manifest.get("fields", {}), dict):
        return False, ["manifest:bad-format"], manifest
    reasons = check_counts(manifest, image)
    if reasons:
        return False, reasons, manifest
    return _check_packing(ppt_path, manifest)


def check_counts(signed: dict, image: bytes) -> List[str]:
    """The signed `counts` against the image header, then a signed `wcet_cycles` against the bound recomputed
    from the image, independently. [] when both hold. A pack's manifest and a distribution envelope's `meta`
    carry the same members and are checked here alike."""
    header = read_ppt_header(image)
    counts = signed.get("counts", {})
    if not isinstance(counts, dict):
        return ["manifest:bad-format"]
    for count_key in ("atoms", "nodes", "edges", "prog_words", "max_steps", "max_stack"):
        if counts.get(count_key) != header[count_key]:
            return [f"manifest:count-mismatch:{count_key}"]
    if "wcet_cycles" in signed and signed["wcet_cycles"] != wcet_cycles(image):
        return ["manifest:wcet-mismatch"]
    return []


# ------------------------------------------------------------------ envelope

def build_envelope(envelope_id: str, fields: Dict[str, str], caps: Optional[dict],
                   priv_path: str, pub_path: str, out_dir: str) -> dict:
    """Sign the qualified-once baseline: `<id>.envelope.json` + `.sig` in out_dir."""
    _pub, key_id = load_public(pub_path)
    env = {"envelope_id": envelope_id, "fields": dict(fields),
           "caps": {**DEFAULT_CAPS, **(caps or {})}, "require_level_m": True,
           "key_id": key_id, canon.ENCODING_KEY: canon.CANON2}
    sig = keys.load_signer(priv_path).sign(signed_bytes(env))
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, f"{envelope_id}.envelope")
    write_signed_document(base + ".json", env)
    with open(base + ".sig", "wb") as handle:
        handle.write(sig)
    return env


def load_envelope(base_path: str, pubkey_paths: List[str]) -> Tuple[Optional[dict], List[str]]:
    """Load + signature-verify an envelope (`base_path` without .json/.sig suffix)."""
    keys.require()
    for suffix in (".json", ".sig"):            # the files are <base>.json and <base>.sig; take either name
        if base_path.endswith(suffix):
            base_path = base_path[:-len(suffix)]
    try:
        with open(base_path + ".json", encoding="utf-8", newline="") as handle:
            env = canon.loads_document(handle.read())
        with open(base_path + ".sig", "rb") as handle:
            sig = handle.read()
    except FileNotFoundError:
        return None, ["envelope:missing"]
    except canon.NotCanonical:                   # canon/2, but not its canonical bytes
        return None, [canon.NotCanonical.CAUSE]
    except ValueError:                           # not canon/2: untagged (canon/1 is retired), another tag, or unreadable
        return None, ["envelope:sig-invalid"]
    try:
        payload = signed_bytes(env)
    except canon.CanonicalError:
        return None, ["envelope:sig-invalid"]
    for path in pubkey_paths:
        public_raw, _kid = load_public_raw(path)
        if keys.verify(public_raw, sig, payload):
            return env, []
    return None, ["envelope:sig-invalid"]


def check_envelope(manifest: dict, image: bytes, envelope: dict) -> Tuple[bool, List[str]]:
    """The Envelope-bounded gate: manifest targets this envelope, fields are a subset,
    and the image passes the capped structural/fragment walk."""
    if not isinstance(manifest.get("fields", {}), dict) or not isinstance(manifest.get("counts", {}), dict):
        return False, ["manifest:bad-format"]               # a signed member of another form is refused, never read
    reasons: List[str] = []
    if manifest.get("envelope_id") != envelope.get("envelope_id"):
        reasons.append("envelope:id-mismatch")
    env_fields = envelope.get("fields", {})
    for name, kind in manifest.get("fields", {}).items():
        if name not in env_fields:
            reasons.append(f"envelope:unknown-field:{name}")
        elif env_fields[name] != kind:
            reasons.append(f"envelope:field-kind-mismatch:{name}")
    ok, img_reasons = validate_image(image, caps=envelope.get("caps", DEFAULT_CAPS))
    reasons.extend(img_reasons)
    return (not reasons) and ok, reasons
