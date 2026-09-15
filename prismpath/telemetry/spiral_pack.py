# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The spiral profile's BAKED materialization: serialize a flow's derived spiral layouts into a
signed sidecar (`<pack>.spiral`) that small targets consume as data.

One profile, two materializations. Capable endpoints DERIVE the layout from the signed policy
(`spiral.SpiralLayout`); small instruction sets receive this sidecar inside the pack they already
verify  -  band bases/widths and route map for the decision-lossless tier, per-field partitions to
quantize raw readings, and the cell->index map for Gray refinement. The two materializations are
bound by byte-equality fixtures: derived and baked must describe the identical layout.

Fail-closed at build: the builder runs the static lint and REFUSES a flow that does not declare
`packing: spiral` or that violates the profile's authoring rules  -  a convention-violating flow
cannot become a baked pack. (The verifier's hash check is in `prismpath.policy_pack`; the semantic
re-derivation lives here, where the adapter may import both halves.)

Sidecar v1 bakes numeric and boolean fields only (the mesh's world). Categorical fields need the
intern table and are refused, not approximated.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Dict, List, Optional

from prismpath.kernel import analysis
from prismpath.telemetry import spiral

MAGIC = 0x4C535050  # "PPSL"
VERSION = 1
_KINDS = {"numeric": 0, "boolean": 1}


def _lint_gate(graph) -> None:
    if graph.meta.get("packing", "").strip().lower() != "spiral":
        raise ValueError("refusing to bake: flow does not declare `packing: spiral`")
    errs = [finding for finding in analysis.analyze(graph) if finding.severity == "error"]
    if errs:
        raise ValueError("refusing to bake: lint errors: "
                         + "; ".join(f"{finding.code}@{finding.node}" for finding in errs))


def _packable_nodes(graph) -> List[str]:
    """Deterministic default node set: document order, every node whose spiral layout is
    derivable (routes on at least one decision-relevant field)."""
    out = []
    for name in graph.nodes:
        try:
            spiral.SpiralLayout(graph, name)
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
        layout = spiral.SpiralLayout(graph, name)
        nb = name.encode()
        out += struct.pack("<B", len(nb)) + nb
        out += struct.pack("<BB", len(layout.fields), 0)
        for field in layout.fields:
            part = layout.parts[field]
            if part.kind not in _KINDS:
                raise ValueError(
                    f"refusing to bake: field {field!r} is {part.kind}  -  "
                    f"sidecar v1 bakes numeric/boolean fields only"
                )
            fb = field.encode()
            out += struct.pack("<B", len(fb)) + fb
            out += struct.pack("<BH", _KINDS[part.kind], part.n)
            if part.kind == "numeric":
                for cell in part.cells:
                    flags = (1 if cell["lo"] is None else 0) | (2 if cell["hi"] is None else 0)
                    out += struct.pack(
                        "<Biii",
                        flags,
                        0 if cell["lo"] is None else int(cell["lo"]),
                        0 if cell["hi"] is None else int(cell["hi"]),
                        int(cell["rep"]),
                    )
        out += struct.pack("<H", len(layout.routes))
        for band, r in enumerate(layout.routes):
            rb = (r or "").encode()
            out += struct.pack("<IIB", layout.band_base[band], layout.band_width[band], len(rb)) + rb
        # cell -> n map in plain counting (row-major) order over the radices: the device computes
        # a linear cell index from its symbols and looks n up in O(1).
        out += struct.pack("<I", layout.size)
        idx = [0] * layout.size
        for cell, spiral_index in layout.n_of.items():
            lin = 0
            for symbol, r in zip(cell, layout.radices):
                lin = lin * r + symbol
            idx[lin] = spiral_index
        out += struct.pack(f"<{layout.size}I", *idx)
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
        (nl,) = struct.unpack_from("<B", data, off)
        off += 1
        name = data[off : off + nl].decode()
        off += nl
        field_count, _pad = struct.unpack_from("<BB", data, off)
        off += 2
        fields = []
        for _ in range(field_count):
            (fl,) = struct.unpack_from("<B", data, off)
            off += 1
            fname = data[off : off + fl].decode()
            off += fl
            kind, ncells = struct.unpack_from("<BH", data, off)
            off += 3
            cells = []
            if kind == 0:
                for _ in range(ncells):
                    flags, lo, hi, rep = struct.unpack_from("<Biii", data, off)
                    off += 13
                    cells.append(
                        {"lo": None if flags & 1 else lo, "hi": None if flags & 2 else hi, "rep": rep}
                    )
            fields.append(
                {"field": fname, "kind": "numeric" if kind == 0 else "boolean", "n": ncells, "cells": cells}
            )
        (n_bands,) = struct.unpack_from("<H", data, off)
        off += 2
        bands = []
        for _ in range(n_bands):
            base, width, rl = struct.unpack_from("<IIB", data, off)
            off += 9
            route = data[off : off + rl].decode() or None
            off += rl
            bands.append({"base": base, "width": width, "route": route})
        (size,) = struct.unpack_from("<I", data, off)
        off += 4
        cell_n = list(struct.unpack_from(f"<{size}I", data, off))
        off += 4 * size
        nodes[name] = {"fields": fields, "bands": bands, "size": size, "cell_n": cell_n}
    return {"version": VERSION, "nodes": nodes}


def write_sidecar(graph, ppt_path: str, nodes: Optional[List[str]] = None) -> Dict:
    """Bake `<ppt_path>.spiral` beside the pack; returns {path, sha256, nodes} for the manifest."""
    blob = serialize_layouts(graph, nodes)
    path = ppt_path + ".spiral"
    with open(path, "wb") as sidecar_file:
        sidecar_file.write(blob)
    return {
        "path": path,
        "sha256": hashlib.sha256(blob).hexdigest(),
        "nodes": sorted(parse_sidecar(blob)["nodes"]),
    }


def verify_derived_equals_baked(graph, data: bytes) -> List[str]:
    """The semantic referee: re-derive every baked node's layout from the graph and compare to the
    sidecar, field by field. Returns a list of mismatch descriptions (empty = byte-equal layouts)."""
    got = parse_sidecar(data)
    errs: List[str] = []
    for name, rec in got["nodes"].items():
        layout = spiral.SpiralLayout(graph, name)
        if [baked_field["field"] for baked_field in rec["fields"]] != layout.fields:
            errs.append(f"{name}: field set/order differs")
            continue
        for baked_field, part in zip(rec["fields"], (layout.parts[field] for field in layout.fields)):
            want = (
                [{"lo": cell["lo"], "hi": cell["hi"], "rep": cell["rep"]} for cell in part.cells]
                if part.kind == "numeric"
                else []
            )
            if baked_field["kind"] != part.kind or baked_field["n"] != part.n or baked_field["cells"] != want:
                errs.append(f"{name}/{baked_field['field']}: partition differs")
        want_bands = [
            {"base": layout.band_base[band], "width": layout.band_width[band], "route": route}
            for band, route in enumerate(layout.routes)
        ]
        if rec["bands"] != want_bands:
            errs.append(f"{name}: bands differ")
        if rec["size"] != layout.size:
            errs.append(f"{name}: size differs")
        else:
            for cell, spiral_index in layout.n_of.items():
                lin = 0
                for symbol, radix in zip(cell, layout.radices):
                    lin = lin * radix + symbol
                if rec["cell_n"][lin] != spiral_index:
                    errs.append(f"{name}: cell map differs at {cell}")
                    break
    return errs
