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

import gen_pack_svh as g                                     # noqa: E402
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
    w = [(0x20, 1), (0x00, 0), (0x04, img.visits_idx)]
    for i, (f, op, ty, val) in enumerate(img.atoms):
        w += [(0x00, (1 << 16) | i), (0x04, ((ty << 24) | (op << 16) | f) & 0xFFFFFFFF)]
        w += [(0x00, (2 << 16) | i), (0x04, val & 0xFFFFFFFF)]
    for ni, (eoff, ecnt) in enumerate(img.node_recs):
        w += [(0x00, (3 << 16) | ni), (0x04, ((ecnt << 16) | eoff) & 0xFFFFFFFF)]
    for ei, (tgt, poff, pcnt) in enumerate(img.edges):
        w += [(0x00, (4 << 16) | ei), (0x04, ((poff << 16) | tgt) & 0xFFFFFFFF)]
        w += [(0x00, (5 << 16) | ei), (0x04, pcnt)]
    for pi, word in enumerate(img.prog):
        w += [(0x00, (6 << 16) | pi), (0x04, word)]
    if colors_on:
        data = open(ppt, "rb").read()
        colors = g.image_colors(data)
        if colors is not None:
            for ni, c in enumerate(colors):
                w += [(0x00, (7 << 16) | ni), (0x04, c)]
    if pol is not None:
        # the arm/disarm tail, derived independently from the SIGNED header (stateful+safe) and
        # the debug view's field index — the mode must ride the pack, never be inherited
        h = g.policy_pack.read_ppt_header(open(ppt, "rb").read())
        if pol.get("arm_field"):
            fidx = json.load(open(jsn))["fields"][pol["arm_field"]]
            w.append((0x28, ((h["safe_node"] & 0xFF) << 24) | ((fidx & 0xFF) << 16)
                     | ((img.start & 0xFF) << 8) | (2 if h["stateful"] else 0) | 1))
        elif pol.get("disarm"):
            w.append((0x28, 0))
    return w


def parse_svh(path: Path):
    text = path.read_text()
    writes = [(int(m.group(1), 16), int(m.group(2), 16))
              for m in re.finditer(r"\{8'h([0-9A-Fa-f]{2}), 32'h([0-9A-Fa-f]{8})\}", text)]
    starts = [int(x) for x in re.search(r"POL_START.*?'\{([^}]*)\}", text).group(1).split(",")]
    lens = [int(x) for x in re.search(r"POL_LEN.*?'\{([^}]*)\}", text).group(1).split(",")]
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
    by_idx = {(e["profile"], e["btn"]): e for e in spec["entries"]}
    assert len(rows) == 2 * spec["nbtn"]
    for i, (code, arg) in enumerate(rows):
        prof, btn = divmod(i, spec["nbtn"])
        e = by_idx[(prof, btn)]
        assert int(code) == g.ACT[e["act"]] and int(arg, 16) == (e.get("arg", 0) & 0xFF)
