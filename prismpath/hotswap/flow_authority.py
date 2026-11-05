# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Flow manifests: the policy authority's signature on an ordinary Markdown flow.

A signed pack (`policy_pack`) authorizes a compiled `.ppt` image, and an image exists only for a Level
M flow compiled for a table substrate. A flow with semantic edges, which is what `prismpath run`
executes, has no image, so until now nothing let the authority say "this flow, at this version, may
run". A **flow manifest** does. It is a detached JSON document beside the flow, `flow.md.manifest.json`
with its Ed25519 signature in `flow.md.manifest.sig`, the same two file shape a pack manifest has:

    {"format": "prismpath-flow-manifest/1", "flow": "<the flow's name>",
     "flow_sha256": "<sha256 of the flow document>", "version": 3,
     "fields": {"amount": "fixed scale 2 ..."},       # only when the flow defines its fields
     "key_id": "<sha256 of the authority public key>", "created": "2026-11-04T12:00:00+00:00"}

The signature covers the canonical compact JSON of the manifest (`policy_pack.canonical_bytes`), as a
pack manifest's does; the `format` field keeps the two from ever being the same bytes. The flow's hash
is the sha256 of its UTF-8 text with line endings read as LF, the same hash `swap pack --flow` records
in a pack manifest, so a checkout that turns LF into CRLF does not unauthorize a flow and a change to
any character does.

`verify_flow` refuses with registry causes (`prismpath/kernel/causes.py`): `sig:missing` when there is
no manifest, `manifest:bad-format`, `sig:invalid` when no trusted authority key verifies it,
`sig:revoked-key`, `manifest:key-id-mismatch`, `flow:sha256-mismatch` when the flow changed after
signing, and `flow:version-replay` when the version is below one already accepted, or equal to it with
other content. The accepted versions are a floor kept by the deployment (`VersionFloor`), not beside
the flow, because whoever can replace the flow can replace what sits next to it.

The authority key is the key `swap keygen` writes. The instance key (`prismpath ledger keygen`) attests
what a deployment recorded and must never authorize a flow; `run` refuses the pair when they are the
same key.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from prismpath import canon
from prismpath.hotswap import policy_pack as pp

FLOW_MANIFEST_FORMAT = "prismpath-flow-manifest/1"
REQUIRE_ENV = "PRISMPATH_REQUIRE_AUTHORIZATION"
AUTHORITY_PUB_ENV = "PRISMPATH_AUTHORITY_PUB"
STATE_DIR_ENV = "PRISMPATH_STATE_DIR"
DEFAULT_STATE_DIR = ".prismpath"
FLOOR_FILE = "flow_versions.json"
UNAUTHORIZED = "unauthorized"


def manifest_paths(flow_path: str) -> Tuple[str, str]:
    return flow_path + ".manifest.json", flow_path + ".manifest.sig"


def flow_sha256(flow_path: str) -> str:
    """sha256 of the flow document's UTF-8 text with line endings read as LF."""
    with open(flow_path, encoding="utf-8") as handle:
        return canon.sha256_hex(handle.read().encode("utf-8"))


def manifest_sha256(manifest: dict) -> str:
    """The flow manifest's content address: sha256 of the canonical bytes its signature covers."""
    return canon.sha256_hex(pp.canonical_bytes(manifest))


def sign_flow(flow_path: str, version: int, priv_path: str, pub_path: str) -> dict:
    """Write `<flow>.manifest.json` and `<flow>.manifest.sig`, signed by the authority key. Returns the
    manifest. A flow that defines its fields signs their canonical definitions too, so the authorization
    names the scale and unit of every value the flow routes on."""
    from prismpath.kernel.parser import parse
    with open(flow_path, encoding="utf-8") as handle:
        text = handle.read()
    graph = parse(text)
    if int(version) < 1:
        raise ValueError("the version must be a positive integer, and each new authorization a higher one")
    _Priv, _Pub, ser, _Inv = pp._ed25519()
    _pub, key_id = pp.load_public(pub_path)
    private_key = pp._load_private(priv_path)
    derived = private_key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    if canon.sha256_hex(derived) != key_id:
        raise ValueError(f"{priv_path} is not the private half of {pub_path}")
    manifest = {"format": FLOW_MANIFEST_FORMAT, "flow": graph.name, "flow_sha256": canon.sha256_hex(text.encode("utf-8")),
                "version": int(version), "key_id": key_id,
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    if graph.fields:
        manifest["fields"] = {name: definition.canonical_text() for name, definition in sorted(graph.fields.items())}
    signature = private_key.sign(pp.canonical_bytes(manifest))
    json_path, sig_path = manifest_paths(flow_path)
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=1, sort_keys=True)
        handle.write("\n")
    with open(sig_path, "wb") as handle:
        handle.write(signature)
    return manifest


def read_manifest(flow_path: str) -> Optional[dict]:
    """The manifest beside the flow, unverified, or None when there is none or it is not JSON."""
    json_path, _sig_path = manifest_paths(flow_path)
    try:
        with open(json_path, encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (FileNotFoundError, ValueError):
        return None
    return manifest if isinstance(manifest, dict) else None


def verify_flow(flow_path: str, pubkey_paths: List[str], revoked: frozenset = frozenset(),
                floor: Optional["VersionFloor"] = None) -> Tuple[bool, List[str], Optional[dict]]:
    """The authorization check, in the order a reader would ask: is there a signature, does a trusted
    and unrevoked authority key make it, does the manifest name that key, is the flow the one signed,
    and is the version at or above the one already accepted. Returns (ok, causes, manifest)."""
    _Priv, _Pub, _ser, InvalidSignature = pp._ed25519()
    json_path, sig_path = manifest_paths(flow_path)
    if not os.path.exists(json_path) or not os.path.exists(sig_path):
        return False, ["sig:missing"], None
    try:
        with open(json_path, encoding="utf-8") as handle:
            manifest = json.load(handle)
    except ValueError:
        return False, ["manifest:bad-format"], None
    with open(sig_path, "rb") as handle:
        signature = handle.read()
    if not isinstance(manifest, dict) or manifest.get("format") != FLOW_MANIFEST_FORMAT \
            or not isinstance(manifest.get("version"), int):
        return False, ["manifest:bad-format"], manifest if isinstance(manifest, dict) else None
    payload = pp.canonical_bytes(manifest)
    signer_id = None
    for path in pubkey_paths:
        public_key, key_id = pp.load_public(path)
        try:
            public_key.verify(signature, payload)
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
    if flow_sha256(flow_path) != manifest.get("flow_sha256"):
        return False, ["flow:sha256-mismatch"], manifest
    if floor is not None and not floor.admits(manifest):
        return False, ["flow:version-replay"], manifest
    return True, [], manifest


def authorization_of(manifest: Optional[dict], ok: bool):
    """What a root statement and a receipt record as the authorization in force: the manifest hash,
    the authority key id and the version when it verified, and "unauthorized" otherwise."""
    if not ok or manifest is None:
        return UNAUTHORIZED
    return {"manifest_sha256": manifest_sha256(manifest), "key_id": manifest["key_id"],
            "version": manifest["version"]}


class VersionFloor:
    """The highest version accepted for each flow name, and the flow hash accepted at it, in one JSON
    file in the deployment's state directory. A version below the floor is refused; the same version is
    admitted again only with the same flow, so a run can repeat and a second flow at the same version
    cannot slip in."""

    def __init__(self, path: str):
        self.path = path
        self.entries: Dict[str, dict] = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as handle:
                loaded = json.load(handle)
            if not isinstance(loaded, dict):
                raise ValueError(f"{path}: the version floor is not a JSON object")
            self.entries = loaded

    @classmethod
    def in_state_dir(cls, state_dir: str) -> "VersionFloor":
        return cls(os.path.join(state_dir, FLOOR_FILE))

    def admits(self, manifest: dict) -> bool:
        entry = self.entries.get(str(manifest.get("flow")))
        if entry is None:
            return True
        version = manifest["version"]
        if version > entry["version"]:
            return True
        return version == entry["version"] and manifest.get("flow_sha256") == entry["flow_sha256"]

    def accept(self, manifest: dict) -> None:
        """Raise the floor to this manifest's version, durably, before the flow runs."""
        name = str(manifest.get("flow"))
        entry = self.entries.get(name)
        if entry is not None and entry["version"] >= manifest["version"]:
            return
        self.entries[name] = {"version": manifest["version"], "flow_sha256": manifest["flow_sha256"],
                              "manifest_sha256": manifest_sha256(manifest)}
        canon.atomic_write(self.path, json.dumps(self.entries, indent=1, sort_keys=True) + "\n")
