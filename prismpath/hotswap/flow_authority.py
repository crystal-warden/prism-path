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

`authorize_flow` is the check as a library call, for every place that loads a flow to make decisions:
`run` and `resume` on the command line, `compose`, the timeout scheduler, a Mission Control sprint that
runs `flows/sprint_loop.md`, and a program that calls `checkpoint.run_durable`, `checkpoint.resume`,
`ledger_runner.run_ledgered_loop` or `engine.run` itself. It reads the same three settings the command
line does (`PRISMPATH_REQUIRE_AUTHORIZATION`, `PRISMPATH_AUTHORITY_PUB`, `PRISMPATH_STATE_DIR`), or an
`AuthorizationPolicy` that names them. A program that builds a `Graph` and calls `engine.run` has no path
to check, so it calls `authorize_flow(path)` before `parse_file(path)`; `load_authorized` does both.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from prismpath import canon
from prismpath.hotswap import policy_pack as pp

FLOW_MANIFEST_FORMAT = "prismpath-flow-manifest/1"
REQUIRE_ENV = "PRISMPATH_REQUIRE_AUTHORIZATION"
AUTHORITY_PUB_ENV = "PRISMPATH_AUTHORITY_PUB"
STATE_DIR_ENV = "PRISMPATH_STATE_DIR"
DEFAULT_STATE_DIR = ".prismpath"
FLOOR_FILE = "flow_versions.json"
UNAUTHORIZED = "unauthorized"

# What `authorize_flow` found. `none`: no manifest beside the flow and authorization not required, so
# nothing was asked. `unchecked`: a manifest is present and no authority key was given, so it was not
# verified. `verified` and `failed` are the two answers to a check that ran.
NONE, UNCHECKED, VERIFIED, FAILED = "none", "unchecked", "verified", "failed"


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


# ------------------------------------------------------------------ the check, for any caller

class AuthorizationConfigError(ValueError):
    """Authorization is required and cannot be checked: no authority public key was given, or the
    instance key and an authority key are the same key. A configuration the operator fixes, not a flow
    that was refused."""


class FlowNotAuthorized(Exception):
    """Authorization is required and the flow does not have it. `causes` are registry names
    (`sig:missing`, `flow:sha256-mismatch`, ...); `manifest` is the manifest that was read, if any."""

    def __init__(self, flow_path: str, causes: Sequence[str], manifest: Optional[dict] = None):
        super().__init__(f"{flow_path}: the flow is not authorized: {', '.join(causes)}")
        self.flow_path = flow_path
        self.causes = list(causes)
        self.manifest = manifest


@dataclass
class Authorization:
    """What a check found: `status` (none, unchecked, verified or failed), the registry causes when it
    failed, and the manifest read. `record` is what a receipt and a root statement carry as the
    authorization in force."""
    flow_path: str
    status: str
    required: bool = False
    reasons: List[str] = field(default_factory=list)
    manifest: Optional[dict] = None

    @property
    def ok(self) -> bool:
        return self.status == VERIFIED

    @property
    def record(self):
        return authorization_of(self.manifest, self.ok)


@dataclass(frozen=True)
class AuthorizationPolicy:
    """Where a check gets its settings. Every field left as None is read from the environment when the
    check runs: `required` from PRISMPATH_REQUIRE_AUTHORIZATION, `authority_pubs` from
    PRISMPATH_AUTHORITY_PUB (paths separated by the platform path separator), `state_dir` from
    PRISMPATH_STATE_DIR, else `.prismpath`. `revoked` is a revocation list path or a set of key ids."""
    required: Optional[bool] = None
    authority_pubs: Optional[Sequence[str]] = None
    revoked: Union[None, str, Iterable[str]] = None
    state_dir: Optional[str] = None

    def is_required(self) -> bool:
        if self.required is not None:
            return bool(self.required)
        return os.environ.get(REQUIRE_ENV, "").strip().lower() in ("1", "true", "yes")

    def pubs(self) -> List[str]:
        if self.authority_pubs:
            return list(self.authority_pubs)
        return [path for path in os.environ.get(AUTHORITY_PUB_ENV, "").split(os.pathsep) if path.strip()]

    def state(self) -> str:
        return self.state_dir or os.environ.get(STATE_DIR_ENV, "").strip() or DEFAULT_STATE_DIR

    def revoked_ids(self) -> frozenset:
        if self.revoked is None or isinstance(self.revoked, str):
            return pp.load_revoked(self.revoked)
        return frozenset(self.revoked)


def authorize_flow(flow_path: str, policy: Optional[AuthorizationPolicy] = None, instance_key=None) -> Authorization:
    """Decide whether this flow may make decisions. Returns an `Authorization`; raises `FlowNotAuthorized`
    when authorization is required and the flow does not have it, and `AuthorizationConfigError` when it
    is required and cannot be checked. When it is not required, a flow manifest that is present is still
    verified (given authority keys) and the result returned, never ignored; nothing here prints.

    `instance_key` is the key the caller signs its receipts with, if it signs: an instance key never
    authorizes a flow, so it is refused as an authority key and as the signer of a manifest."""
    policy = policy or AuthorizationPolicy()
    required = policy.is_required()
    manifest_present = any(os.path.exists(path) for path in manifest_paths(flow_path))
    if not required and not manifest_present:
        return Authorization(flow_path, NONE)
    pubs = policy.pubs()
    if required and not pubs:
        raise AuthorizationConfigError(
            "authorization is required and no trusted authority key was given: pass --authority-pub PUB or "
            f"set {AUTHORITY_PUB_ENV}")
    if not pubs:
        return Authorization(flow_path, UNCHECKED, required, [], read_manifest(flow_path))
    if instance_key is not None:
        from prismpath.ledgers import root_statement
        authority_ids = []
        for path in pubs:
            with open(path, "rb") as handle:
                authority_ids.append(pp.sha256_hex(handle.read()))
        try:
            root_statement.check_separation(instance_key, authority_ids)
        except ValueError as same_key:
            raise AuthorizationConfigError(str(same_key)) from same_key
    floor = VersionFloor.in_state_dir(policy.state())
    ok, reasons, manifest = verify_flow(flow_path, pubs, policy.revoked_ids(), floor=floor)
    if ok and instance_key is not None and manifest.get("key_id") == instance_key.key_id:
        ok, reasons = False, ["sig:invalid"]            # an instance key never authorizes a flow
    if not ok:
        if required:
            raise FlowNotAuthorized(flow_path, reasons, manifest)
        return Authorization(flow_path, FAILED, required, reasons, manifest)
    if required:
        floor.accept(manifest)
    return Authorization(flow_path, VERIFIED, required, [], manifest)


def load_authorized(flow_path: str, policy: Optional[AuthorizationPolicy] = None, instance_key=None):
    """`authorize_flow`, then `parse_file`: the flow's graph and the authorization it was loaded under.
    For a program that runs `engine.run` itself and would otherwise load the flow unchecked."""
    from prismpath.kernel.parser import parse_file
    authorization = authorize_flow(flow_path, policy, instance_key)
    return parse_file(flow_path), authorization
