# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Signed policy packs — the Authorized + Envelope-bounded half of the secure hot-swap.

A pack is the byte-identical `.ppt` image plus a detached, signed manifest
(`docs/design/spec-secure-hotswap.md` §3.1). Nothing here modifies the image or the compiler:
this module is a read-only consumer of the `.ppt` format (SPEC §7 / TABLE_FORMAT.md), so every
certified image hash stays exactly what the FPGA/eBPF evidence rows cite.

Crypto is Ed25519 via the `cryptography` library, an optional extra (`pip install
prismpath[signing]`) with loud absence: verification unavailable -> refuse with the install
message, never fall through (the otel.py pattern). All verdicts are `(ok, [stable-reason])`
tuples so tests and audit rows pin exact failure classes.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

# --- .ppt format facts (read-only mirror of ppt_compile.py / TABLE_FORMAT.md) ---
MAGIC = 0x4D545050          # "PPTM"
FORMAT_VERSION = 1
HEADER = struct.Struct("<IHHHHHHHHHHHH")   # 28 bytes
ATOM = struct.Struct("<HBBi")               # fidx, op, ty, val
NODE = struct.Struct("<HH")
EDGE = struct.Struct("<HHH")
WORD = struct.Struct("<H")
OPS = frozenset(range(7))                   # ==, !=, <, <=, >, >=, truthy
TYPES = frozenset(range(4))                 # none, bool, int, str
PROG_OPCODES = frozenset({0x8000, 0x8001, 0x8002, 0x8003, 0x8004})  # NOT AND OR TRUE FALSE
# The 12th header word (offset 26) is split: low byte = flags, high byte = the optional signed
# safe_node (a fail-safe node index; 0 = undeclared -> reader falls back to the last-node convention).
# Flags bit 0 => a per-node ATTRIBUTE section (nodes x uint16) is appended after the program and signed
# with the image. The format gives the attribute no meaning; the substrate MATERIALIZES it (an LED
# color in the fabric, an skb mark / XDP verdict / traffic-class in the kernel, a UI label in
# software). LED color is one materialization, hence the back-compat alias.
FLAG_NODE_ATTR = 0x0001
FLAG_COLORS = FLAG_NODE_ATTR   # back-compat alias: the fabric's LED-color materialization
FLAG_MIGRATE_BY_NAME = 0x0002  # flags bit1: resident-selector hot-swap migration mode — set = by-name
                               # (re-resolve the current node by name), clear = reset-to (the fail-safe).
                               # Meaningful only when safe_node is declared; signed with the image.

PACK_FORMAT = "ppt-pack/1"

# Default envelope caps = the eBPF loader's MAX_* constants (ppt_common.h) — the first place
# these bounds are enforced at build/load time rather than assumed.
DEFAULT_CAPS = {"atoms": 1024, "nodes": 256, "edges": 1024, "prog_words": 4096,
                "max_steps": 25, "max_stack": 16}

_INSTALL_MSG = "policy signing needs `pip install cryptography` (the `signing` extra)"


def _ed25519():
    """Import the Ed25519 primitives, loudly refusing if the optional dep is absent."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey)
        from cryptography.hazmat.primitives import serialization
        from cryptography.exceptions import InvalidSignature
    except ImportError as e:                                   # pragma: no cover
        raise RuntimeError(_INSTALL_MSG) from e
    return Ed25519PrivateKey, Ed25519PublicKey, serialization, InvalidSignature


def canonical_bytes(obj) -> bytes:
    """The one canonical JSON encoding signatures are computed over."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
            "migrate_by_name": bool(flagword & FLAG_MIGRATE_BY_NAME)}


def validate_image(data: bytes, caps: Optional[dict] = None) -> Tuple[bool, List[str]]:
    """Image-native structural + fragment check: exact length, atom ops/types in the Level M
    fragment, program words resolve to atoms or boolean opcodes, node/edge indices in range,
    and (when caps given) every count within the envelope. The compiler guarantees fragment
    membership at build time; this re-verifies the shipped artifact at load time."""
    reasons: List[str] = []
    try:
        h = read_ppt_header(data)
    except ValueError as e:
        return False, [str(e)]

    if h["safe_node"] and h["safe_node"] >= h["nodes"]:
        reasons.append("image:safe-node-oob")    # signed fail-safe must name a real node

    need = (HEADER.size + ATOM.size * h["atoms"] + NODE.size * h["nodes"]
            + EDGE.size * h["edges"] + WORD.size * h["prog_words"])
    if h["flags"] & FLAG_NODE_ATTR:
        need += WORD.size * h["nodes"]           # one uint16 per-node attribute, appended last
    if len(data) != need:
        reasons.append("image:length-mismatch")
        return False, reasons

    if caps:
        for key, cap_key in (("atoms", "atoms"), ("nodes", "nodes"), ("edges", "edges"),
                             ("prog_words", "prog_words"), ("max_steps", "max_steps"),
                             ("max_stack", "max_stack")):
            if h[key] > caps.get(cap_key, DEFAULT_CAPS[cap_key]):
                reasons.append(f"envelope:cap-exceeded:{cap_key}")

    off = HEADER.size
    for i in range(h["atoms"]):
        fidx, op, ty, _val = ATOM.unpack_from(data, off)
        off += ATOM.size
        if op not in OPS:
            reasons.append(f"image:unknown-op:atom{i}")
        if ty not in TYPES:
            reasons.append(f"image:unknown-type:atom{i}")
        if fidx >= h["fields"]:
            reasons.append(f"image:field-index-oob:atom{i}")
    off += NODE.size * h["nodes"]
    for i in range(h["edges"]):
        target, po, pc = EDGE.unpack_from(data, off)
        off += EDGE.size
        if target >= h["nodes"]:
            reasons.append(f"image:edge-target-oob:edge{i}")
        if po + pc > h["prog_words"]:
            reasons.append(f"image:edge-prog-oob:edge{i}")
    for i in range(h["prog_words"]):
        (w,) = WORD.unpack_from(data, off)
        off += WORD.size
        if w >= 0x8000 and w not in PROG_OPCODES:
            reasons.append(f"image:unknown-opcode:word{i}")
        if w < 0x8000 and w >= h["atoms"]:
            reasons.append(f"image:atom-index-oob:word{i}")
    if h["flags"] & FLAG_NODE_ATTR:
        for i in range(h["nodes"]):
            (c,) = WORD.unpack_from(data, off)
            off += WORD.size
            if c > 0x3F:                          # fabric materialization envelope: 6-bit LED {LD5,LD4}
                reasons.append(f"image:node-attr-oob:node{i}")

    return (not reasons), reasons


def wcet_cycles(data: bytes) -> int:
    """Per-evaluate worst-case cycle bound = max over nodes of (sum over its edges of
    (2 + max(prog_words, 1))) + 2. Equals 2*E + P + 2 for compiler-emitted policies (every edge's
    program is at least one word); the max(., 1) term keeps the bound exact for hand-crafted images
    with zero-word edges, which still cost one S_RUN cycle each (the 3E+P adversarial case the
    formal work surfaced). The interpreter is a fixed FSM with no micro-architecture, so this is
    exact, not an over-approximation; calibrated + validated against the RTL in
    prismpath-hw/tb/wcet. At clock f, the time bound is wcet_cycles / f."""
    h = read_ppt_header(data)
    off = HEADER.size + ATOM.size * h["atoms"]
    node_recs = [NODE.unpack_from(data, off + i * NODE.size) for i in range(h["nodes"])]
    off += NODE.size * h["nodes"]
    edge_pcnt = [EDGE.unpack_from(data, off + i * EDGE.size)[2] for i in range(h["edges"])]
    worst = 0
    for eoff, ecnt in node_recs:                 # (edge_off, edge_cnt)
        worst = max(worst, sum(2 + max(p, 1) for p in edge_pcnt[eoff:eoff + ecnt]) + 2)
    return worst


# ------------------------------------------------------------------ keys

def keygen(out_dir: str, name: str = "authority") -> dict:
    """Generate an Ed25519 keypair. Private key PEM written 0600; returns paths + key_id
    (sha256 of the raw public bytes — the identity used in manifests and revocation lists)."""
    Priv, _Pub, ser, _Inv = _ed25519()
    os.makedirs(out_dir, exist_ok=True)
    priv = Priv.generate()
    priv_path = os.path.join(out_dir, f"{name}.key")
    pub_path = os.path.join(out_dir, f"{name}.pub")
    pem = priv.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    raw = priv.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    with open(pub_path, "wb") as f:
        f.write(raw)
    return {"private": priv_path, "public": pub_path, "key_id": sha256_hex(raw)}


def _load_private(path: str):
    Priv, _Pub, ser, _Inv = _ed25519()
    with open(path, "rb") as f:
        key = ser.load_pem_private_key(f.read(), password=None)
    return key


def load_public(path: str) -> Tuple[object, str]:
    """Load a raw-32-byte Ed25519 public key file -> (key, key_id)."""
    _Priv, Pub, _ser, _Inv = _ed25519()
    with open(path, "rb") as f:
        raw = f.read()
    return Pub.from_public_bytes(raw), sha256_hex(raw)


def load_revoked(path: Optional[str]) -> frozenset:
    """Revocation list: a JSON array of key_id hex strings. Missing path -> empty set."""
    if not path or not os.path.exists(path):
        return frozenset()
    with open(path) as f:
        return frozenset(json.load(f))


# ------------------------------------------------------------------ manifest / pack

def build_manifest(image: bytes, fields: Dict[str, str], version: int,
                   envelope_id: str, key_id: str) -> dict:
    h = read_ppt_header(image)
    return {
        "format": PACK_FORMAT,
        "image_sha256": sha256_hex(image),
        "fields": dict(fields),
        "counts": {"atoms": h["atoms"], "nodes": h["nodes"], "edges": h["edges"],
                   "prog_words": h["prog_words"], "max_steps": h["max_steps"],
                   "max_stack": h["max_stack"]},
        "wcet_cycles": wcet_cycles(image),       # per-evaluate worst case, signed with the policy
        "version": int(version),
        "envelope_id": envelope_id,
        "key_id": key_id,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def build_pack(ppt_path: str, fields: Dict[str, str], version: int, envelope_id: str,
               priv_path: str, pub_path: str, packing: Optional[dict] = None) -> dict:
    """Sign a `.ppt` into a pack: writes `<ppt>.manifest.json` + `<ppt>.manifest.sig`
    beside the (untouched) image. Returns the manifest.

    `packing` (optional) declares a wire-packing profile whose baked artifact rides the pack,
    e.g. {"profile": "spiral", "sidecar_sha256": <hex of `<ppt>.spiral`>} — built by the
    telemetry adapter's `spiral_pack.write_sidecar`, which lint-gates the flow. The manifest
    signature then covers the declaration, and `verify_pack` re-hashes the sidecar at load."""
    with open(ppt_path, "rb") as f:
        image = f.read()
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
    priv = _load_private(priv_path)
    sig = priv.sign(canonical_bytes(manifest))
    with open(ppt_path + ".manifest.json", "w") as f:
        json.dump(manifest, f, indent=1, sort_keys=True)
        f.write("\n")
    with open(ppt_path + ".manifest.sig", "wb") as f:
        f.write(sig)
    return manifest


def verify_pack(ppt_path: str, pubkey_paths: List[str],
                revoked: frozenset = frozenset()) -> Tuple[bool, List[str], Optional[dict]]:
    """The Authorized gate. Verifies: signature over the canonical manifest by a known,
    non-revoked key; manifest key_id matches the verifying key; image hash and header counts
    match the manifest. Returns (ok, stable-reasons, manifest-or-None)."""
    _Priv, _Pub, _ser, InvalidSignature = _ed25519()
    man_path, sig_path = ppt_path + ".manifest.json", ppt_path + ".manifest.sig"
    if not os.path.exists(man_path) or not os.path.exists(sig_path):
        return False, ["sig:missing"], None
    with open(man_path) as f:
        manifest = json.load(f)
    with open(sig_path, "rb") as f:
        sig = f.read()
    if manifest.get("format") != PACK_FORMAT:
        return False, ["manifest:bad-format"], manifest

    payload = canonical_bytes(manifest)
    signer_id = None
    for path in pubkey_paths:
        pub, key_id = load_public(path)
        try:
            pub.verify(sig, payload)
            signer_id = key_id
            break
        except InvalidSignature:
            continue
    if signer_id is None:
        return False, ["sig:invalid"], manifest
    if signer_id in revoked:
        return False, ["sig:revoked-key"], manifest
    if manifest.get("key_id") != signer_id:
        return False, ["manifest:key-id-mismatch"], manifest

    with open(ppt_path, "rb") as f:
        image = f.read()
    if sha256_hex(image) != manifest.get("image_sha256"):
        return False, ["image:sha256-mismatch"], manifest
    h = read_ppt_header(image)
    counts = manifest.get("counts", {})
    for k in ("atoms", "nodes", "edges", "prog_words", "max_steps", "max_stack"):
        if counts.get(k) != h[k]:
            return False, [f"manifest:count-mismatch:{k}"], manifest
    if "wcet_cycles" in manifest and manifest["wcet_cycles"] != wcet_cycles(image):
        return False, ["manifest:wcet-mismatch"], manifest   # recomputed from the image, independently
    if "packing" in manifest:
        pk = manifest["packing"]
        if pk.get("profile") != "spiral":
            return False, ["packing:unknown-profile"], manifest
        side_path = ppt_path + ".spiral"
        if not os.path.exists(side_path):
            return False, ["spiral:sidecar-missing"], manifest
        with open(side_path, "rb") as f:
            if sha256_hex(f.read()) != pk.get("sidecar_sha256"):
                return False, ["spiral:sidecar-hash-mismatch"], manifest
    return True, [], manifest


# ------------------------------------------------------------------ envelope

def build_envelope(envelope_id: str, fields: Dict[str, str], caps: Optional[dict],
                   priv_path: str, pub_path: str, out_dir: str) -> dict:
    """Sign the qualified-once baseline: `<id>.envelope.json` + `.sig` in out_dir."""
    _pub, key_id = load_public(pub_path)
    env = {"envelope_id": envelope_id, "fields": dict(fields),
           "caps": {**DEFAULT_CAPS, **(caps or {})}, "require_level_m": True,
           "key_id": key_id}
    sig = _load_private(priv_path).sign(canonical_bytes(env))
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, f"{envelope_id}.envelope")
    with open(base + ".json", "w") as f:
        json.dump(env, f, indent=1, sort_keys=True)
        f.write("\n")
    with open(base + ".sig", "wb") as f:
        f.write(sig)
    return env


def load_envelope(base_path: str, pubkey_paths: List[str]) -> Tuple[Optional[dict], List[str]]:
    """Load + signature-verify an envelope (`base_path` without .json/.sig suffix)."""
    _Priv, _Pub, _ser, InvalidSignature = _ed25519()
    try:
        with open(base_path + ".json") as f:
            env = json.load(f)
        with open(base_path + ".sig", "rb") as f:
            sig = f.read()
    except FileNotFoundError:
        return None, ["envelope:missing"]
    payload = canonical_bytes(env)
    for path in pubkey_paths:
        pub, _kid = load_public(path)
        try:
            pub.verify(sig, payload)
            return env, []
        except InvalidSignature:
            continue
    return None, ["envelope:sig-invalid"]


def check_envelope(manifest: dict, image: bytes, envelope: dict) -> Tuple[bool, List[str]]:
    """The Envelope-bounded gate: manifest targets this envelope, fields are a subset,
    and the image passes the capped structural/fragment walk."""
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
