# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A stdio MCP server that lets a model read a Facet stream through the signed policy that defines its codebook.

    python -m prismpath.telemetry.facet_mcp --registry DIR --authority-pub PUB [--authority-pub PUB ...]
                                            [--revoked LIST] [--pin POLICY_SHA256]

Three tools:

    facet_describe(policy_hash)                      the codebook in words, each cell with its index
    facet_decode(stream_hex, policy_hash, ...)       each reading as cell indices and the policy's decision
    facet_summary(stream_hex, policy_hash, ...)      the decision distribution, the cells that appear, the exceptions

A Facet stream has no header, no field tags and no codebook (PROTOCOL.md 2.1), so the policy hash is the only
thing that says which codebook applies. The server finds a policy by that hash in a registry directory and
reads it only when the authority signed it:

  * a flow `NAME.md` with its flow manifest `NAME.md.manifest.json` and `.sig` (`hotswap.flow_authority`,
    checked by `verify_flow`, with its refusal causes);
  * a core image `NAME.core.json` with an image attestation `NAME.core.json.attest`, the same Ed25519 over
    `core_evidence.IMAGE_DOMAIN` and the image's canon/2 bytes that a core run records per case (`sign_image`
    writes one, `verify_image` checks it).

A policy with no signature, a signature no `--authority-pub` key makes, a revoked key, or content changed after
signing is not served, and the refusal names the registry cause. A hash that no signed policy has is refused as
unknown. `--pin` binds the session to one policy (the out of band binding), so a call that names another signed
policy's hash is refused too.

Integrity. The stream carries no check of its own, and a bit flip that still decodes to valid symbols decodes.
That is the epoch's Merkle root's job (`telemetry.epochs`, `selfheal.commit`, an RFC 6962 tree over the epoch's
blocks, `ledger_ots`). `facet_decode` and `facet_summary` take the epoch's root, either with `block_bits` (the
stream is the epoch: its transmitted bits, padding included, are cut into blocks of that many bits and the root
recomputed) or with `epoch_blocks` (the epoch's blocks as bit strings, which must hash to the root and be the
bits of the stream). A root that does not match is refused. Every answer carries `integrity`, `checked` or
`unchecked`, and with no root it says in words that nothing was checked. A server cannot make an unsealed stream
trustworthy; it can say that it did not look.

Protocol. Newline delimited JSON-RPC on standard input and output, handled with `agent.mcp_proxy`'s strict line
parser and message helpers (a repeated key is refused, a batch is answered as a batch). Both eras answer:
`initialize` (2025-11-25 and earlier) and `server/discover` (2026-07-28, results carry `resultType`). No
dependency beyond the package and the `signing` extra (`cryptography`) that verifying a signature needs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from typing import Any, BinaryIO, Dict, List, Optional, Sequence, Tuple

from prismpath.agent import mcp_proxy as mp
from prismpath.hotswap import flow_authority
from prismpath.hotswap import policy_pack as pp
from prismpath.kernel import canon2, core_render
from prismpath.kernel.parser import parse
from prismpath.ledgers import core_evidence
from prismpath.onion import keys
from prismpath.telemetry import packed, quantizer, selfheal, wire
from prismpath.telemetry import zeckendorf as zeck

FORMAT = "facet/1"
SERVER_NAME = "prismpath-facet"
SERVER_VERSION = "0.1.0"
ATTEST_SUFFIX = ".attest"
ATTEST_FORMAT = "prismpath.facet-image-attestation/1"
DEFAULT_LIMIT = 100
NO_EDGE = "(no edge matched)"   # the summary's name for a reading no edge of the decision node routes
UNCHECKED_NOTE = ("no epoch Merkle root was given, so nothing shows this is the stream the sender sealed; a bit "
                  "flip that still decodes to valid symbols would be read as fact")


class Refused(Exception):
    """A refusal reported to the caller as an error, never a best effort decode."""


# ------------------------------------------------------------------ cells in words
def _label(part, cell: dict) -> str:
    if cell.get("absent"):
        return "absent (field not sent)"
    if part.kind == "boolean":
        return "true" if cell["rep"] else "false"
    if part.kind == "categorical":
        c = cell["const"]
        return "any other value" if c == quantizer.OTHER_CELL else f"the string {c!r}"
    lo, hi = cell["lo"], cell["hi"]
    if lo is None:
        return f"{hi} or less"
    if hi is None:
        return f"{lo} or more"
    return f"exactly {lo}" if lo == hi else f"{lo} to {hi}"


# ------------------------------------------------------------------ one policy
class Policy:
    def __init__(self, path: str, decision_node: Optional[str] = None):
        raw = open(path, encoding="utf-8").read()
        self.path = path
        self.sha256 = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        self.text = core_render.render(json.loads(raw)) if path.endswith(".core.json") else raw
        self.graph = parse(self.text)
        self.parts = quantizer.build_partitions(self.graph)
        self.order = sorted(self.parts)
        nodes = wire.decision_nodes(self.graph)
        self.node = decision_node or max(nodes, key=lambda n: len(self.graph.nodes[n].edges))
        edges = self.graph.nodes[self.node].edges
        self.targets = sorted({t for t, _ in edges})
        # the default decision is the target of the last edge that always holds, when the node has one
        self.default = next((t for t, cond in reversed(edges) if cond.strip().lower() in core_render.ALWAYS), None)
        self.signed_by: Optional[str] = None
        self.version: Optional[int] = None

    def decision(self, reading: Dict[str, Any]) -> Optional[str]:
        return wire.route_node(self.graph, self.node, reading)

    def encode(self, readings: List[Dict[str, Any]]) -> bytes:
        return packed.pack("".join(wire.encode_reading(self.parts, r) for r in readings))

    def symbols(self, data: bytes) -> List[Dict[str, int]]:
        """Bytes -> one {field: cell index} per reading, or Refused."""
        ints, tail = zeck.decode_stream_tail(packed.unpack(data))
        n = len(self.order)
        if "1" in tail:
            raise Refused("codebook mismatch: the stream ends inside a code word that is not zero padding")
        if not ints or len(ints) % n:
            raise Refused(f"codebook mismatch: {len(ints)} symbols is not a whole number of readings "
                          f"of {n} fields")
        rows = []
        for i in range(0, len(ints), n):
            row = {}
            for f, v in zip(self.order, ints[i:i + n]):
                if not 1 <= v <= self.parts[f].n:
                    raise Refused(f"codebook mismatch: symbol {v} is outside field {f!r}, "
                                  f"which has {self.parts[f].n} cells")
                row[f] = v - 1
            rows.append(row)
        return rows


# ------------------------------------------------------------------ signing and verifying a core image
def image_bytes(path: str) -> bytes:
    """The image's canon/2 bytes, which is what is signed: the file without its final newline. A file that is
    not exactly one canon/2 document raises Refused."""
    with open(path, "rb") as handle:
        raw = handle.read()
    body = raw[:-1] if raw.endswith(b"\n") else raw
    try:
        if canon2.dumps(canon2.loads(body)) != body:
            raise Refused("document:not-canonical")
    except canon2.Canon2Error:
        raise Refused("document:not-canonical")
    return body


def sign_image(path: str, priv_path: str, pub_path: str) -> dict:
    """Write `<image>.attest`, the authority's signature on a core image."""
    body = image_bytes(path)
    _pub, key_id = pp.load_public(pub_path)
    signer = keys.load_signer(priv_path)
    attestation = {"format": ATTEST_FORMAT, "image_sha256": hashlib.sha256(body).hexdigest(), "key_id": key_id,
                   "sig": signer.sign(core_evidence.IMAGE_DOMAIN + body).hex()}
    with open(path + ATTEST_SUFFIX, "wb") as handle:
        handle.write(canon2.dumps(attestation) + b"\n")
    return attestation


def verify_image(path: str, pubkey_paths: List[str], revoked: frozenset = frozenset()
                 ) -> Tuple[bool, List[str], Optional[dict]]:
    """(ok, causes, attestation) in the order flow_authority.verify_flow asks: signature present, a trusted key
    made it, the key is not revoked, the image is the one signed."""
    keys.require()
    try:
        with open(path + ATTEST_SUFFIX, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return False, ["sig:missing"], None
    try:
        attestation = canon2.loads(raw[:-1] if raw.endswith(b"\n") else raw)
    except canon2.Canon2Error:
        return False, ["manifest:bad-format"], None
    if not isinstance(attestation, dict) or attestation.get("format") != ATTEST_FORMAT \
            or not isinstance(attestation.get("sig"), str):
        return False, ["manifest:bad-format"], None
    try:
        body = image_bytes(path)
        signature = bytes.fromhex(attestation["sig"])
    except (Refused, ValueError):
        return False, ["manifest:bad-format"], attestation
    signer = None
    for pub in pubkey_paths:
        public_raw, key_id = pp.load_public_raw(pub)
        if keys.verify(public_raw, signature, core_evidence.IMAGE_DOMAIN + body):
            signer = key_id
            break
    if signer is None:
        return False, ["sig:invalid"], attestation
    if signer in revoked:
        return False, ["sig:revoked-key"], attestation
    if attestation.get("key_id") != signer:
        return False, ["manifest:key-id-mismatch"], attestation
    if attestation.get("image_sha256") != hashlib.sha256(body).hexdigest():
        return False, ["flow:sha256-mismatch"], attestation
    return True, [], attestation


# ------------------------------------------------------------------ the registry
class Registry:
    """The signed policies in a directory, by sha256. Each lookup re-reads what changed on disk, so a policy
    edited or un-signed after the server started is no longer served."""

    def __init__(self, directory: str, authority_pubs: Sequence[str], revoked: frozenset = frozenset()):
        if not authority_pubs:
            raise ValueError("a registry needs at least one trusted authority public key (--authority-pub)")
        self.directory = directory
        self.pubs = list(authority_pubs)
        self.revoked = revoked
        self._cache: Dict[str, Tuple[tuple, Any]] = {}
        self.scan()

    def _candidates(self) -> List[str]:
        out = []
        for root, _dirs, files in os.walk(self.directory):
            for name in sorted(files):
                if name.endswith(".md") or name.endswith(".core.json"):
                    out.append(os.path.join(root, name))
        return sorted(out)

    @staticmethod
    def _stamp(path: str) -> tuple:
        stamp = []
        suffixes = (".manifest.json", ".manifest.sig") if path.endswith(".md") else (ATTEST_SUFFIX,)
        for p in [path] + [path + s for s in suffixes]:
            try:
                st = os.stat(p)
                stamp.append((st.st_mtime_ns, st.st_size))
            except FileNotFoundError:
                stamp.append(None)
        return tuple(stamp)

    def _load(self, path: str):
        """(Policy, None) when signed and good, (None, causes) when refused."""
        if path.endswith(".md"):
            ok, causes, manifest = flow_authority.verify_flow(path, self.pubs, self.revoked)
            who, version = (manifest or {}).get("key_id"), (manifest or {}).get("version")
        else:
            ok, causes, manifest = verify_image(path, self.pubs, self.revoked)
            who, version = (manifest or {}).get("key_id"), None
        if not ok:
            return None, causes
        try:
            policy = Policy(path)
        except Exception as exc:   # noqa: BLE001 - a signed file the codec cannot carry is refused, not served
            return None, [f"policy:unreadable:{type(exc).__name__}"]
        policy.signed_by, policy.version = who, version
        return policy, None

    def scan(self) -> Tuple[Dict[str, Policy], Dict[str, List[str]]]:
        """(signed policies by hash, refused paths with their causes)."""
        good: Dict[str, Policy] = {}
        refused: Dict[str, List[str]] = {}
        seen = set()
        for path in self._candidates():
            seen.add(path)
            stamp = self._stamp(path)
            cached = self._cache.get(path)
            if cached is None or cached[0] != stamp:
                cached = (stamp, self._load(path))
                self._cache[path] = cached
            policy, causes = cached[1]
            if policy is not None:
                good[policy.sha256] = policy
            else:
                refused[path] = causes
        for gone in set(self._cache) - seen:
            del self._cache[gone]
        return good, refused

    def get(self, policy_hash: str) -> Policy:
        good, refused = self.scan()
        if policy_hash in good:
            return good[policy_hash]
        for path, causes in refused.items():
            try:
                with open(path, encoding="utf-8") as handle:
                    if hashlib.sha256(handle.read().encode("utf-8")).hexdigest() == policy_hash:
                        raise Refused(f"unsigned or unauthorized policy: {os.path.basename(path)} has this hash "
                                      f"but is refused ({', '.join(causes)}); not served")
            except (OSError, UnicodeDecodeError):
                continue
        raise Refused(f"unknown policy: no signed policy in the registry has hash {str(policy_hash)[:12]}...")


# ------------------------------------------------------------------ integrity
def check_integrity(data: bytes, epoch_root: Optional[str], block_bits: Optional[int],
                    epoch_blocks: Optional[List[str]]) -> Dict[str, Any]:
    """Whether the stream is the epoch the Merkle root commits to. Returns the `integrity` fields to put in the
    answer; raises Refused on a root mismatch or on arguments that cannot be checked."""
    if epoch_root is None:
        if block_bits is not None or epoch_blocks is not None:
            raise Refused("epoch_blocks and block_bits need epoch_root; give the root or neither")
        return {"integrity": "unchecked", "integrity_note": UNCHECKED_NOTE}
    root = str(epoch_root).strip().lower()
    if len(root) != 64 or any(c not in "0123456789abcdef" for c in root):
        raise Refused("epoch_root is not a 64 digit hex sha256 root")
    bits = packed.unpack(data)
    if epoch_blocks is not None:
        if block_bits is not None:
            raise Refused("give epoch_blocks or block_bits, not both")
        if (not isinstance(epoch_blocks, list) or not epoch_blocks
                or any(not isinstance(b, str) or set(b) - {"0", "1"} for b in epoch_blocks)):
            raise Refused("epoch_blocks must be a non empty list of bit strings of 0 and 1")
        got = selfheal.commit(list(epoch_blocks))[0]
        joined = "".join(epoch_blocks)
        if got != root:
            raise Refused(f"integrity failure: the blocks hash to {got[:16]}..., not the epoch root "
                          f"{root[:16]}...; refusing to decode")
        if not bits.startswith(joined) or "1" in bits[len(joined):]:
            raise Refused("integrity failure: the stream is not the bits of the epoch's blocks; refusing to decode")
        return {"integrity": "checked", "epoch_root": root, "integrity_basis": f"{len(epoch_blocks)} blocks"}
    if block_bits is None:
        raise Refused("epoch_root needs block_bits (the epoch's block size) or epoch_blocks")
    if not isinstance(block_bits, int) or isinstance(block_bits, bool) or block_bits <= 0:
        raise Refused("block_bits must be a positive integer")
    blocks = selfheal.chunk(bits, block_bits)
    got = selfheal.commit(blocks)[0]
    if got != root:
        raise Refused(f"integrity failure: the stream's Merkle root is {got[:16]}..., not the epoch root "
                      f"{root[:16]}...; the stream is not the epoch that was sealed; refusing to decode")
    return {"integrity": "checked", "epoch_root": root, "integrity_basis": f"{len(blocks)} blocks of {block_bits} bits"}


# ------------------------------------------------------------------ the tools
INTEGRITY_PROPS = {
    "epoch_root": {"type": "string", "description": "The epoch's Merkle root (RFC 6962 over sha256 of each block's "
                                                    "bit string), 64 hex digits. Without it the answer says "
                                                    "integrity is unchecked."},
    "block_bits": {"type": "integer", "description": "With epoch_root: the epoch's block size in bits. The stream "
                                                      "(its transmitted bits, padding included) is cut into blocks "
                                                      "of this size and the root recomputed."},
    "epoch_blocks": {"type": "array", "items": {"type": "string"},
                     "description": "With epoch_root, instead of block_bits: the epoch's blocks as bit strings."},
}
TOOLS = [
    {"name": "facet_describe",
     "description": "Describe the codebook of a signed Facet policy in words: each field's cells, each with its "
                    "index, in canonical field order. Needs the policy sha256 from the binding.",
     "inputSchema": {"type": "object", "properties": {"policy_hash": {"type": "string"}},
                     "required": ["policy_hash"]}},
    {"name": "facet_decode",
     "description": "Decode a Facet stream (hex) under a signed policy. Each reading comes back with the 0-based "
                    "cell index of every field in canonical field order, and the decision the policy makes. "
                    "format 'compact' returns only the index list and decision per reading. Refuses an unknown or "
                    "unsigned policy hash, a stream that does not fit the codebook, and a stream whose Merkle root "
                    "does not match epoch_root. Reports integrity as checked or unchecked.",
     "inputSchema": {"type": "object",
                     "properties": {"stream_hex": {"type": "string"}, "policy_hash": {"type": "string"},
                                    "format": {"type": "string", "enum": ["full", "compact"]}, **INTEGRITY_PROPS},
                     "required": ["stream_hex", "policy_hash"]}},
    {"name": "facet_summary",
     "description": "Summarize a Facet stream under a signed policy without transcribing it: the decision "
                    "distribution, which cells appear in each field and how often, and the exception readings "
                    "(those with the named decision, or every decision other than the policy's default). Same "
                    "refusals and integrity report as facet_decode.",
     "inputSchema": {"type": "object",
                     "properties": {"stream_hex": {"type": "string"}, "policy_hash": {"type": "string"},
                                    "decision": {"type": "string", "description": "Exceptions are the readings "
                                                 "with this decision. Omit for every non-default decision."},
                                    "limit": {"type": "integer", "description": f"At most this many exceptions "
                                              f"listed (default {DEFAULT_LIMIT}); the total is always reported."},
                                    **INTEGRITY_PROPS},
                     "required": ["stream_hex", "policy_hash"]}},
]


class FacetServer:
    """The tools over a registry. `pinned_hash`, when given, is the policy the session is bound to."""

    def __init__(self, registry: Registry, pinned_hash: Optional[str] = None, epoch: int = 1):
        self.registry, self.pinned, self.epoch = registry, pinned_hash, epoch

    def binding(self) -> Dict[str, Any]:
        return {"format": FORMAT, "policy_sha256": self.pinned, "epoch": self.epoch}

    def _policy(self, policy_hash: str) -> Policy:
        if self.pinned is not None and policy_hash != self.pinned:
            raise Refused(f"policy hash mismatch: this session is bound to {self.pinned[:12]}..., "
                          f"not {str(policy_hash)[:12]}...; refusing to decode")
        return self.registry.get(policy_hash)

    @staticmethod
    def _bytes(stream_hex: str) -> bytes:
        try:
            return bytes.fromhex("".join(str(stream_hex).split()))
        except ValueError:
            raise Refused("stream_hex is not valid hexadecimal")

    def _read(self, stream_hex, policy_hash, epoch_root, block_bits, epoch_blocks):
        p = self._policy(policy_hash)
        data = self._bytes(stream_hex)
        integrity = check_integrity(data, epoch_root, block_bits, epoch_blocks)
        rows = p.symbols(data)
        readings = []
        for i, syms in enumerate(rows):
            rep = quantizer.reconstruct(p.parts, syms)
            readings.append((i, [syms[f] for f in p.order], p.decision(rep)))
        return p, integrity, readings

    def facet_describe(self, policy_hash: str) -> Dict[str, Any]:
        p = self._policy(policy_hash)
        fields = []
        for f in p.order:
            part = p.parts[f]
            fields.append({"field": f, "kind": part.kind,
                           "cells": [{"index": i, "meaning": _label(part, c)} for i, c in enumerate(part.cells)]})
        return {"format": FORMAT, "policy_sha256": p.sha256, "signed": True, "signed_by_key_id": p.signed_by,
                "field_order": p.order, "fields": fields, "decision_node": p.node,
                "possible_decisions": p.targets, "default_decision": p.default,
                "wire": "per reading, one Fibonacci code per field in field_order carrying cell index + 1"}

    def facet_decode(self, stream_hex: str, policy_hash: str, format: str = "full", epoch_root: Optional[str] = None,
                     block_bits: Optional[int] = None, epoch_blocks: Optional[List[str]] = None) -> Dict[str, Any]:
        if format not in ("full", "compact"):
            raise Refused("format must be 'full' or 'compact'")
        p, integrity, readings = self._read(stream_hex, policy_hash, epoch_root, block_bits, epoch_blocks)
        out: Dict[str, Any] = {"format": FORMAT, "policy_sha256": p.sha256, **integrity,
                               "field_order": p.order, "reading_count": len(readings)}
        if format == "compact":
            out["readings"] = [{"cells": cells, "decision": d} for _i, cells, d in readings]
        else:
            out["readings"] = [
                {"reading": i,
                 "cells": [{"field": f, "index": c, "meaning": _label(p.parts[f], p.parts[f].cells[c])}
                           for f, c in zip(p.order, cells)],
                 "decision": d} for i, cells, d in readings]
        return out

    def facet_summary(self, stream_hex: str, policy_hash: str, decision: Optional[str] = None,
                      limit: int = DEFAULT_LIMIT, epoch_root: Optional[str] = None, block_bits: Optional[int] = None,
                      epoch_blocks: Optional[List[str]] = None) -> Dict[str, Any]:
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise Refused("limit must be a non negative integer")
        p, integrity, readings = self._read(stream_hex, policy_hash, epoch_root, block_bits, epoch_blocks)
        if decision is not None and decision not in p.targets:
            raise Refused(f"{decision!r} is not a decision this policy makes; it makes {p.targets}")
        dist: Dict[str, int] = {}
        for _i, _c, d in readings:
            dist[NO_EDGE if d is None else d] = dist.get(NO_EDGE if d is None else d, 0) + 1
        present: Dict[str, Dict[str, int]] = {f: {} for f in p.order}
        for _i, cells, _d in readings:
            for f, c in zip(p.order, cells):
                present[f][str(c)] = present[f].get(str(c), 0) + 1
        if decision is not None:
            rule = f"readings whose decision is {decision!r}"
            picked = [r for r in readings if r[2] == decision]
        elif p.default is not None:
            rule = f"every reading whose decision is not the policy's default, {p.default!r}"
            picked = [r for r in readings if r[2] != p.default]
        else:
            base = max(sorted(dist), key=lambda k: dist[k])
            rule = f"every reading whose decision is not {base!r}, the most frequent here (the policy has no default edge)"
            picked = [r for r in readings if (NO_EDGE if r[2] is None else r[2]) != base]
        return {"format": FORMAT, "policy_sha256": p.sha256, **integrity, "field_order": p.order,
                "reading_count": len(readings),
                "decision_distribution": {k: dist[k] for k in sorted(dist)},
                "cells_present": {f: {k: present[f][k] for k in sorted(present[f], key=int)} for f in p.order},
                "exception_rule": rule, "exceptions_total": len(picked),
                "exceptions_listed": min(limit, len(picked)),
                "exceptions": [{"reading": i, "cells": cells, "decision": d} for i, cells, d in picked[:limit]]}

    def dispatch(self, name: str, args: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
        """(result object, is_error). A refusal is a result the model reads, not a protocol error."""
        try:
            fn = {"facet_describe": self.facet_describe, "facet_decode": self.facet_decode,
                  "facet_summary": self.facet_summary}[name]
            return fn(**args), False
        except Refused as exc:
            return {"error": "refused", "reason": str(exc)}, True
        except (KeyError, TypeError) as exc:
            return {"error": "bad call", "reason": f"{type(exc).__name__}: {exc}"}, True

    def call(self, name: str, args: Dict[str, Any]) -> str:
        """The JSON text a model sees for one tool call."""
        return json.dumps(self.dispatch(name, args)[0], separators=(",", ":"))


# ------------------------------------------------------------------ MCP over stdio
def _wants_result_type(request: Dict[str, Any]) -> bool:
    params = request.get("params")
    meta = params.get("_meta") if isinstance(params, dict) else None
    return isinstance(meta, dict) and mp.META_VERSION in meta


def _reply(request: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    if _wants_result_type(request):
        result = {"resultType": "complete", **result}
    return {"jsonrpc": "2.0", "id": request.get("id"), "result": result}


def _error(request: Dict[str, Any], code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request.get("id"), "error": {"code": code, "message": message}}


def answer(server: FacetServer, request: Any) -> Optional[Dict[str, Any]]:
    """The reply to one JSON-RPC message, or None for a notification (no id) and for a response."""
    if not isinstance(request, dict) or not isinstance(request.get("method"), str):
        return None if isinstance(request, dict) and "method" not in request and "id" in request \
            else mp.rpc_error(mp.INVALID_REQUEST, "the message is not a JSON-RPC request")
    if "id" not in request:
        return None
    method, params = request["method"], request.get("params")
    params = params if isinstance(params, dict) else {}
    info = {"name": SERVER_NAME, "version": SERVER_VERSION}
    if method == "initialize":
        return _reply(request, {"protocolVersion": params.get("protocolVersion", "2025-11-25"),
                                "capabilities": {"tools": {}}, "serverInfo": info})
    if method == "server/discover":
        return _reply(request, {"supportedVersions": [mp.PROTOCOL_VERSION], "capabilities": {"tools": {}},
                                "serverInfo": info})
    if method == "ping":
        return _reply(request, {})
    if method == "tools/list":
        return _reply(request, {"tools": TOOLS})
    if method == "tools/call":
        name, args = params.get("name"), params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(args, dict):
            return _error(request, -32602, "tools/call needs a tool name and an arguments object")
        if name not in {t["name"] for t in TOOLS}:
            return _error(request, -32602, f"unknown tool {name!r}")
        result, is_error = server.dispatch(name, args)
        return _reply(request, {"content": [{"type": "text", "text": json.dumps(result, separators=(",", ":"))}],
                                "isError": is_error})
    return _error(request, -32601, f"no method {method}")


def serve(server: FacetServer, source: BinaryIO, sink: BinaryIO) -> None:
    def send(message: Any) -> None:
        sink.write(mp._encode(message))
        sink.flush()

    for line in iter(source.readline, b""):
        if not line.strip():
            continue
        try:
            message = mp.parse_message(line.rstrip(b"\r\n"))
        except mp._Repeated:
            send(mp.rpc_error(mp.INVALID_REQUEST, "a message with a repeated key is not accepted"))
            continue
        except ValueError:
            send(mp.rpc_error(mp.PARSE_ERROR, "the line is not one JSON value in UTF-8"))
            continue
        if isinstance(message, list) and message:
            replies = [r for r in (answer(server, m) for m in message) if r is not None]
            if replies:
                send(replies)
            continue
        reply = answer(server, message)
        if reply is not None:
            send(reply)


def build(registry: str, authority_pubs: Sequence[str], revoked: Optional[str] = None,
          pin: Optional[str] = None) -> FacetServer:
    return FacetServer(Registry(registry, authority_pubs, pp.load_revoked(revoked)), pin)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m prismpath.telemetry.facet_mcp",
                                     description="An MCP server that decodes Facet streams under signed policies.")
    parser.add_argument("--registry", required=True, help="a directory of signed flows and core images")
    parser.add_argument("--authority-pub", action="append", default=None, metavar="PUB",
                        help="a trusted authority public key (repeat for a rotation); default: "
                             f"{flow_authority.AUTHORITY_PUB_ENV}")
    parser.add_argument("--revoked", default=None, help="revocation list JSON of key ids")
    parser.add_argument("--pin", default=None, metavar="SHA256", help="bind the session to this policy hash")
    args = parser.parse_args(argv)
    pubs = args.authority_pub or [p for p in os.environ.get(flow_authority.AUTHORITY_PUB_ENV, "").split(os.pathsep)
                                  if p.strip()]
    if not pubs:
        parser.error(f"name a trusted authority key: --authority-pub PUB or set {flow_authority.AUTHORITY_PUB_ENV}")
    if not os.path.isdir(args.registry):
        parser.error(f"{args.registry} is not a directory")
    server = build(args.registry, pubs, args.revoked, args.pin)
    good, refused = server.registry.scan()
    sys.stderr.write(f"prismpath facet mcp: {len(good)} signed policies served, {len(refused)} refused\n")
    for path, causes in sorted(refused.items()):
        sys.stderr.write(f"  refused {path}: {', '.join(causes)}\n")
    serve(server, sys.stdin.buffer, sys.stdout.buffer)
    return 0


if __name__ == "__main__":
    sys.exit(main())
