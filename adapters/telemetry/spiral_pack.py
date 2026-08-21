# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The spiral profile's BAKED materialization: serialize a flow's derived spiral layouts into a
signed sidecar (`<pack>.spiral`) that small targets consume as data.

One profile, two materializations. Capable endpoints DERIVE the layout from the signed policy
(`spiral.SpiralLayout`); small instruction sets receive this sidecar inside the pack they already
verify — band bases/widths and route map for the decision-lossless tier, per-field partitions to
quantize raw readings, and the cell->index map for Gray refinement. The two materializations are
bound by byte-equality fixtures: derived and baked must describe the identical layout.

Fail-closed at build: the builder runs the static lint and REFUSES a flow that does not declare
`packing: spiral` or that violates the profile's authoring rules — a convention-violating flow
cannot become a baked pack. (The verifier's hash check is in `prismpath.policy_pack`; the semantic
re-derivation lives here, where the adapter may import both halves.)

Sidecar v1 bakes numeric and boolean fields only (the mesh's world). Categorical fields need the
intern table and are refused, not approximated.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Dict, List, Optional

from prismpath import analysis

import spiral as sp

MAGIC = 0x4C535050            # "PPSL"
VERSION = 1
_KINDS = {"numeric": 0, "boolean": 1}


def _lint_gate(graph) -> None:
    if graph.meta.get("packing", "").strip().lower() != "spiral":
        raise ValueError("refusing to bake: flow does not declare `packing: spiral`")
    errs = [f for f in analysis.analyze(graph) if f.severity == "error"]
    if errs:
        raise ValueError("refusing to bake: lint errors: " +
                         "; ".join(f"{f.code}@{f.node}" for f in errs))


def _packable_nodes(graph) -> List[str]:
    """Deterministic default node set: document order, every node whose spiral layout is
    derivable (routes on at least one decision-relevant field)."""
    out = []
    for name in graph.nodes:
        try:
            sp.SpiralLayout(graph, name)
        except ValueError:
            continue
        out.append(name)
    return out


def serialize_layouts(graph, nodes: Optional[List[str]] = None) -> bytes:
    """Derive every packed node's layout and emit the deterministic v1 sidecar bytes."""
    _lint_gate(graph)
    names = nodes if nodes is not None else _packable_nodes(graph)
    if not names:
        raise ValueError("refusing to bake: no packable nodes (no decision-relevant fields)")
    out = bytearray(struct.pack("<IHH", MAGIC, VERSION, len(names)))
    for name in names:
        L = sp.SpiralLayout(graph, name)
        nb = name.encode()
        out += struct.pack("<B", len(nb)) + nb
        out += struct.pack("<BB", len(L.fields), 0)
        for f in L.fields:
            part = L.parts[f]
            if part.kind not in _KINDS:
                raise ValueError(f"refusing to bake: field {f!r} is {part.kind} — "
                                 f"sidecar v1 bakes numeric/boolean fields only")
            fb = f.encode()
            out += struct.pack("<B", len(fb)) + fb
            out += struct.pack("<BH", _KINDS[part.kind], part.n)
            if part.kind == "numeric":
                for c in part.cells:
                    flags = (1 if c["lo"] is None else 0) | (2 if c["hi"] is None else 0)
                    out += struct.pack("<Biii", flags,
                                       0 if c["lo"] is None else int(c["lo"]),
                                       0 if c["hi"] is None else int(c["hi"]),
                                       int(c["rep"]))
        out += struct.pack("<H", len(L.routes))
        for i, r in enumerate(L.routes):
            rb = (r or "").encode()
            out += struct.pack("<IIB", L.band_base[i], L.band_width[i], len(rb)) + rb
        # cell -> n map in plain counting (row-major) order over the radices: the device computes
        # a linear cell index from its symbols and looks n up in O(1).
        out += struct.pack("<I", L.size)
        idx = [0] * L.size
        for cell, n in L.n_of.items():
            lin = 0
            for s, r in zip(cell, L.radices):
                lin = lin * r + s
            idx[lin] = n
        out += struct.pack(f"<{L.size}I", *idx)
    return bytes(out)


def parse_sidecar(data: bytes) -> Dict:
    """Decode v1 sidecar bytes into plain structures (the referee's and the tests' view)."""
    magic, version, n_nodes = struct.unpack_from("<IHH", data, 0)
    if magic != MAGIC:
        raise ValueError("sidecar: bad magic")
    if version != VERSION:
        raise ValueError(f"sidecar: unsupported version {version}")
    off = 8
    nodes: Dict[str, Dict] = {}
    for _ in range(n_nodes):
        (nl,) = struct.unpack_from("<B", data, off); off += 1
        name = data[off:off + nl].decode(); off += nl
        k, _pad = struct.unpack_from("<BB", data, off); off += 2
        fields = []
        for _ in range(k):
            (fl,) = struct.unpack_from("<B", data, off); off += 1
            fname = data[off:off + fl].decode(); off += fl
            kind, ncells = struct.unpack_from("<BH", data, off); off += 3
            cells = []
            if kind == 0:
                for _ in range(ncells):
                    flags, lo, hi, rep = struct.unpack_from("<Biii", data, off); off += 13
                    cells.append({"lo": None if flags & 1 else lo,
                                  "hi": None if flags & 2 else hi, "rep": rep})
            fields.append({"field": fname, "kind": "numeric" if kind == 0 else "boolean",
                           "n": ncells, "cells": cells})
        (n_bands,) = struct.unpack_from("<H", data, off); off += 2
        bands = []
        for _ in range(n_bands):
            base, width, rl = struct.unpack_from("<IIB", data, off); off += 9
            route = data[off:off + rl].decode() or None; off += rl
            bands.append({"base": base, "width": width, "route": route})
        (size,) = struct.unpack_from("<I", data, off); off += 4
        cell_n = list(struct.unpack_from(f"<{size}I", data, off)); off += 4 * size
        nodes[name] = {"fields": fields, "bands": bands, "size": size, "cell_n": cell_n}
    return {"version": VERSION, "nodes": nodes}


def write_sidecar(graph, ppt_path: str, nodes: Optional[List[str]] = None) -> Dict:
    """Bake `<ppt_path>.spiral` beside the pack; returns {path, sha256, nodes} for the manifest."""
    blob = serialize_layouts(graph, nodes)
    path = ppt_path + ".spiral"
    with open(path, "wb") as f:
        f.write(blob)
    return {"path": path, "sha256": hashlib.sha256(blob).hexdigest(),
            "nodes": sorted(parse_sidecar(blob)["nodes"])}


def verify_derived_equals_baked(graph, data: bytes) -> List[str]:
    """The semantic referee: re-derive every baked node's layout from the graph and compare to the
    sidecar, field by field. Returns a list of mismatch descriptions (empty = byte-equal layouts)."""
    got = parse_sidecar(data)
    errs: List[str] = []
    for name, rec in got["nodes"].items():
        L = sp.SpiralLayout(graph, name)
        if [f["field"] for f in rec["fields"]] != L.fields:
            errs.append(f"{name}: field set/order differs"); continue
        for f, part in zip(rec["fields"], (L.parts[x] for x in L.fields)):
            want = ([{"lo": c["lo"], "hi": c["hi"], "rep": c["rep"]} for c in part.cells]
                    if part.kind == "numeric" else [])
            if f["kind"] != part.kind or f["n"] != part.n or f["cells"] != want:
                errs.append(f"{name}/{f['field']}: partition differs")
        want_bands = [{"base": L.band_base[i], "width": L.band_width[i], "route": r}
                      for i, r in enumerate(L.routes)]
        if rec["bands"] != want_bands:
            errs.append(f"{name}: bands differ")
        if rec["size"] != L.size:
            errs.append(f"{name}: size differs")
        else:
            for cell, n in L.n_of.items():
                lin = 0
                for s, r in zip(cell, L.radices):
                    lin = lin * r + s
                if rec["cell_n"][lin] != n:
                    errs.append(f"{name}: cell map differs at {cell}"); break
    return errs
