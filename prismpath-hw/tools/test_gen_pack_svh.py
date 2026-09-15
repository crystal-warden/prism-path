# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Gate for gen_pack_svh.py: the emitted SVH must equal the PS write sequence derived
independently through ppt_pynq.PptImage (the parser the board actually uses)."""

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HW = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HW.parents[0]))                       # prismpath repo
sys.path.insert(0, str(HW / "pynq"))

import gen_pack_svh as pack_generator                         # noqa: E402
from ppt_pynq import PptImage                                # noqa: E402

MANIFEST = json.load(open(HERE / "finale_pack.json"))
# manifest paths are relative to the manifest file; resolve so the test is cwd-independent
for _pol in MANIFEST["policies"]:
    for _k in ("ppt", "json"):
        if not Path(_pol[_k]).is_absolute():
            _pol[_k] = str((HERE / _pol[_k]).resolve())
if not Path(MANIFEST["ctrl_table"]).is_absolute():
    MANIFEST["ctrl_table"] = str((HERE / MANIFEST["ctrl_table"]).resolve())


def golden_from_pptimage(ppt: str, jsn: str, colors_on: bool, pol: dict | None = None):
    """The PS sequence, built from PptImage (independent parse) following load_image order."""
    img = PptImage(ppt, jsn)
    writes = [(0x20, 1), (0x00, 0), (0x04, img.visits_idx)]
    for atom_index, (field_index, op, ty, val) in enumerate(img.atoms):
        writes += [(0x00, (1 << 16) | atom_index), (0x04, ((ty << 24) | (op << 16) | field_index) & 0xFFFFFFFF)]
        writes += [(0x00, (2 << 16) | atom_index), (0x04, val & 0xFFFFFFFF)]
    for node_index, (eoff, ecnt) in enumerate(img.node_recs):
        writes += [(0x00, (3 << 16) | node_index), (0x04, ((ecnt << 16) | eoff) & 0xFFFFFFFF)]
    for edge_index, (target, poff, pcnt) in enumerate(img.edges):
        writes += [(0x00, (4 << 16) | edge_index), (0x04, ((poff << 16) | target) & 0xFFFFFFFF)]
        writes += [(0x00, (5 << 16) | edge_index), (0x04, pcnt)]
    for prog_index, word in enumerate(img.prog):
        writes += [(0x00, (6 << 16) | prog_index), (0x04, word)]
    if colors_on:
        data = open(ppt, "rb").read()
        colors = pack_generator.image_colors(data)
        if colors is not None:
            for node_index, color in enumerate(colors):
                writes += [(0x00, (7 << 16) | node_index), (0x04, color)]
    if pol is not None:
        # the arm/disarm tail, derived independently from the SIGNED header (stateful+safe) and
        # the debug view's field index — the mode must ride the pack, never be inherited
        header = pack_generator.policy_pack.read_ppt_header(open(ppt, "rb").read())
        if pol.get("arm_field"):
            fidx = json.load(open(jsn))["fields"][pol["arm_field"]]
            writes.append((0x28, ((header["safe_node"] & 0xFF) << 24) | ((fidx & 0xFF) << 16)
                     | ((img.start & 0xFF) << 8) | (2 if header["stateful"] else 0) | 1))
        elif pol.get("disarm"):
            writes.append((0x28, 0))
    return writes


def parse_svh(path: Path):
    text = path.read_text()
    writes = [(int(write_match.group(1), 16), int(write_match.group(2), 16))
              for write_match in re.finditer(r"\{8'h([0-9A-Fa-f]{2}), 32'h([0-9A-Fa-f]{8})\}", text)]
    starts = [int(field) for field in re.search(r"POL_START.*?'\{([^}]*)\}", text).group(1).split(",")]
    lens = [int(field) for field in re.search(r"POL_LEN.*?'\{([^}]*)\}", text).group(1).split(",")]
    return writes, starts, lens


def test_pack_svh_matches_pptimage_golden():
    svh = HW / "rtl" / "ppt_pack.svh"
    writes, starts, lens = parse_svh(svh)
    assert len(writes) == sum(lens)
    for idx, pol in enumerate(MANIFEST["policies"]):
        golden = golden_from_pptimage(pol["ppt"], pol["json"], pol.get("colors", True), pol)
        got = writes[starts[idx]: starts[idx] + lens[idx]]
        assert got == golden, f"policy {idx}: emitted writes diverge from the PptImage golden"


def test_ctrl_svh_matches_spec():
    text = (HW / "rtl" / "ppt_ctrl_pack.svh").read_text()
    rows = re.findall(r"\{3'd(\d), 8'h([0-9A-Fa-f]{2})\}", text)
    spec = json.load(open(MANIFEST["ctrl_table"]))
    by_idx = {(entry["profile"], entry["btn"]): entry for entry in spec["entries"]}
    assert len(rows) == 2 * spec["nbtn"]
    for row_index, (code, arg) in enumerate(rows):
        prof, btn = divmod(row_index, spec["nbtn"])
        entry = by_idx[(prof, btn)]
        assert int(code) == pack_generator.ACT[entry["act"]] and int(arg, 16) == (entry.get("arg", 0) & 0xFF)
