# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Two tools a model can call to read a Facet stream, built on the existing codec.

    facet_describe(policy_hash)                  the codebook in words, fields in canonical order
    facet_decode(stream_hex, policy_hash)        each reading as named cells plus the policy's decision

A Facet stream has no header, no field tags and no codebook (PROTOCOL.md 2.1), so the policy hash is the
only thing that says which codebook applies. The server below is the receiver: it holds the hash it is
pinned to for the session (the out of band binding) and refuses any call that names a different one. It
also refuses a stream that does not fit the codebook (I3): a symbol count that is not a whole number of
readings, a bit run left over that is not zero padding, or a symbol outside its field's cells.

What it cannot catch is a bit flip that still decodes to valid symbols. The stream carries no integrity
check of its own. That is the epoch's Merkle root (PROTOCOL.md 2.4), which this module does not touch.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from prismpath.kernel import core_render
from prismpath.kernel.parser import parse
from prismpath.telemetry import packed, quantizer, wire
from prismpath.telemetry import zeckendorf as zeck

FORMAT = "facet/1"


class Refused(Exception):
    """A refusal the tool reports to the model as an error, never a best effort decode."""


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
        self.node = decision_node or max(
            nodes, key=lambda n: len(self.graph.nodes[n].edges))
        self.targets = sorted({t for t, _ in self.graph.nodes[self.node].edges})

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


class FacetServer:
    """The receiver. `pinned_hash` is the policy the session is bound to (the out of band binding)."""

    def __init__(self, policies: List[Policy], pinned_hash: str, epoch: int = 1):
        self.by_hash = {p.sha256: p for p in policies}
        self.pinned = pinned_hash
        self.epoch = epoch

    def binding(self) -> Dict[str, Any]:
        return {"format": FORMAT, "policy_sha256": self.pinned, "epoch": self.epoch}

    def _policy(self, policy_hash: str) -> Policy:
        if policy_hash != self.pinned:
            raise Refused(f"policy hash mismatch: this session is bound to {self.pinned[:12]}..., "
                          f"not {str(policy_hash)[:12]}...; refusing to decode")
        return self.by_hash[policy_hash]

    def facet_describe(self, policy_hash: str) -> Dict[str, Any]:
        p = self._policy(policy_hash)
        fields = []
        for f in p.order:
            part = p.parts[f]
            fields.append({"field": f, "kind": part.kind,
                           "cells": [{"index": i, "meaning": _label(part, c)} for i, c in enumerate(part.cells)]})
        return {"format": FORMAT, "policy_sha256": p.sha256, "field_order": p.order, "fields": fields,
                "decision_node": p.node, "possible_decisions": p.targets,
                "wire": "per reading, one Fibonacci code per field in field_order carrying cell index + 1"}

    def facet_decode(self, stream_hex: str, policy_hash: str) -> Dict[str, Any]:
        p = self._policy(policy_hash)
        try:
            data = bytes.fromhex("".join(str(stream_hex).split()))
        except ValueError:
            raise Refused("stream_hex is not valid hexadecimal")
        out = []
        for i, syms in enumerate(p.symbols(data)):
            rep = quantizer.reconstruct(p.parts, syms)
            cells = {f: _label(p.parts[f], p.parts[f].cells[s]) for f, s in syms.items()}
            out.append({"reading": i, "cells": cells, "decision": p.decision(rep)})
        return {"format": FORMAT, "policy_sha256": p.sha256, "readings": out}

    def call(self, name: str, args: Dict[str, Any]) -> str:
        """Dispatch a model's tool call and return the JSON text it sees. Refusals come back as an error."""
        try:
            fn = {"facet_describe": self.facet_describe, "facet_decode": self.facet_decode}[name]
            return json.dumps(fn(**args), separators=(",", ":"))
        except Refused as e:
            return json.dumps({"error": "refused", "reason": str(e)}, separators=(",", ":"))
        except (KeyError, TypeError) as e:
            return json.dumps({"error": "bad call", "reason": f"{type(e).__name__}: {e}"}, separators=(",", ":"))


TOOL_SPECS = [
    {"type": "function", "function": {
        "name": "facet_describe",
        "description": "Describe the codebook of a Facet policy in words: each field's cells as ranges or constants, "
                       "in canonical order. Needs the policy sha256 from the binding.",
        "parameters": {"type": "object", "properties": {"policy_hash": {"type": "string"}},
                       "required": ["policy_hash"]}}},
    {"type": "function", "function": {
        "name": "facet_decode",
        "description": "Decode a Facet stream (hex) under a policy. Returns each reading as named cells plus the "
                       "decision the policy makes. Refuses a policy hash that is not the session's binding and a "
                       "stream that does not fit the codebook.",
        "parameters": {"type": "object", "properties": {"stream_hex": {"type": "string"},
                                                        "policy_hash": {"type": "string"}},
                       "required": ["stream_hex", "policy_hash"]}}},
]
