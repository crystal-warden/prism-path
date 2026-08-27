#!/usr/bin/env python3
"""gen_pack_svh.py — arc task #4: bake signed policies into the fabric loader's ROM.

Emits `ppt_pack.svh` (and `ppt_ctrl_pack.svh`) from real .ppt images, replacing the mock ROMs in
ppt_pack_loader.sv / ppt_ctrl_interp.sv. The write list per policy is BYTE-IDENTICAL to what the PS
issues in ppt_pynq.load_image + dp_load's color loop: soft-reset, then sel0 visits, sel1/2 atoms,
sel3 nodes, sel4/5 edges, sel6 prog, sel7 colors (when the image carries them), each as the
{0x00 sel|addr, 0x04 data} register pair, optionally ending with the 0x28 AUTO_CTRL arm.

Manifest JSON drives it (the pack definition is itself an artifact):

    {
      "policies": [
        {"ppt": "path.ppt", "json": "path.json", "colors": true,
         "arm_field": "pot", "pubkeys": ["authority.pub"]},
        ...
      ],
      "ctrl_table": "ctrl_table.json"          // optional; emits ppt_ctrl_pack.svh
    }

Signature policy: a policy with "pubkeys" is verified via prismpath.policy_pack.verify_pack and the
generator REFUSES to emit on failure. A policy without "pubkeys" is emitted with an UNSIGNED
provenance note (useful for bench work; not for the demo's signed finale).

    python3 tools/gen_pack_svh.py <manifest.json> -o rtl/
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]          # .../prismpath
sys.path.insert(0, str(REPO))
from prismpath import policy_pack                    # noqa: E402

R_SEL_ADDR, R_DATA, R_SOFT_RST, R_AUTO_CTRL = 0x00, 0x04, 0x20, 0x28


def parse_ppt(data: bytes) -> dict:
    """Binary section of a PPT v1 image (mirrors ppt_pynq.PptImage; the pytest gate cross-checks
    this parse against PptImage itself so the two cannot drift silently)."""
    (magic, version, n_fields, n_interns, n_atoms, n_nodes,
     n_edges, prog_len, start, visits_idx, _max_steps,
     _max_stack, _pad) = struct.unpack_from("<IHHHHHHHHHHHH", data, 0)
    assert magic == 0x4D545050 and version == 1, "not a PPT v1 image"
    off = 28
    atoms = []
    for _ in range(n_atoms):
        f, op, ty, val = struct.unpack_from("<HBBi", data, off)
        atoms.append((f, op, ty, val))
        off += 8
    node_recs = []
    for _ in range(n_nodes):
        node_recs.append(struct.unpack_from("<HH", data, off))
        off += 4
    edges = []
    for _ in range(n_edges):
        edges.append(struct.unpack_from("<HHH", data, off))
        off += 6
    prog = list(struct.unpack_from(f"<{prog_len}H", data, off))
    return {"start": start, "visits_idx": visits_idx, "atoms": atoms,
            "node_recs": node_recs, "edges": edges, "prog": prog, "n_nodes": n_nodes}


def image_colors(data: bytes) -> list[int] | None:
    h = policy_pack.read_ppt_header(data)
    if not (h["flags"] & policy_pack.FLAG_COLORS):
        return None
    n = h["nodes"]
    return list(struct.unpack_from(f"<{n}H", data, len(data) - 2 * n))


def load_writes(sel: int, addr: int, data: int) -> list[tuple[int, int]]:
    return [(R_SEL_ADDR, ((sel & 0xFFFF) << 16) | (addr & 0xFFFF)), (R_DATA, data & 0xFFFFFFFF)]


def policy_writes(img: dict, colors: list[int] | None,
                  arm: tuple[int, int, bool, int] | None,
                  disarm: bool = False) -> list[tuple[int, int]]:
    """The full PS-identical load sequence for one policy."""
    w: list[tuple[int, int]] = [(R_SOFT_RST, 1)]
    w += load_writes(0, 0, img["visits_idx"])
    for i, (f, op, ty, val) in enumerate(img["atoms"]):
        w += load_writes(1, i, ((ty & 0xFF) << 24) | ((op & 0xFF) << 16) | (f & 0xFFFF))
        w += load_writes(2, i, val)
    for ni, (eoff, ecnt) in enumerate(img["node_recs"]):
        w += load_writes(3, ni, ((ecnt & 0xFFFF) << 16) | (eoff & 0xFFFF))
    for ei, (tgt, poff, pcnt) in enumerate(img["edges"]):
        w += load_writes(4, ei, ((poff & 0xFFFF) << 16) | (tgt & 0xFFFF))
        w += load_writes(5, ei, pcnt)
    for pi, word in enumerate(img["prog"]):
        w += load_writes(6, pi, word)
    if colors is not None:
        for ni, c in enumerate(colors):
            w += load_writes(7, ni, c)
    if arm is not None:
        fidx, start, stateful, safe = arm
        # [31:24] safe_node, [23:16] pot_fidx, [15:8] start, [1] stateful, [0] enable — the
        # stateful/safe bits come from the SIGNED image header (FLAG_STATEFUL + safe byte), so the
        # resident-FSM mode rides the signed replay and a manifest cannot contradict the pack.
        w.append((R_AUTO_CTRL, ((safe & 0xFF) << 24) | ((fidx & 0xFF) << 16)
                  | ((start & 0xFF) << 8) | ((2 if stateful else 0)) | 1))
    elif disarm:
        # a pack that is not auto-armed DECLARES that too: swap-in drops to PS mode instead of
        # inheriting the previous policy's arm word (mode inherited = mode negotiated — the hole
        # the stateful bit must never fall into)
        w.append((R_AUTO_CTRL, 0))
    return w


_MANIFEST_DIR = Path('.')     # set by main() to the manifest file's parent


def _rel(p: str) -> str:
    """A manifest path, resolved relative to the manifest file (absolute passes through)."""
    q = Path(p)
    return str(q if q.is_absolute() else (_MANIFEST_DIR / q))


def emit_pack_svh(policies: list[dict], out: Path) -> None:
    all_writes: list[tuple[int, int]] = []
    starts, lens, notes = [], [], []
    for p in policies:
        data = Path(_rel(p["ppt"])).read_bytes()
        img = parse_ppt(data)
        colors = image_colors(data) if p.get("colors", True) else None
        arm = None
        if p.get("arm_field"):
            dbg = json.load(open(_rel(p["json"])))
            h = policy_pack.read_ppt_header(data)
            arm = (dbg["fields"][p["arm_field"]], img["start"], h["stateful"], h["safe_node"])
        disarm = bool(p.get("disarm"))
        verified = "UNSIGNED"
        if p.get("pubkeys"):
            ok, reasons, man = policy_pack.verify_pack(_rel(p["ppt"]), [_rel(k) for k in p["pubkeys"]])
            if not ok:
                raise SystemExit(f"REFUSED: {p['ppt']} failed verification: {reasons}")
            verified = f"verified envelope={man['envelope_id']} v{man['version']} key={man['key_id'][:8]}"
        w = policy_writes(img, colors, arm, disarm)
        starts.append(len(all_writes))
        lens.append(len(w))
        all_writes += w
        notes.append(f"//   [{len(starts)-1}] {Path(_rel(p['ppt'])).name}  sha256={hashlib.sha256(data).hexdigest()[:16]}"
                     f"  writes={len(w)}  colors={'y' if colors else 'n'}  arm={'y' if arm else 'n'}  {verified}")
    npol, nw = len(policies), len(all_writes)
    lines = [
        "// ppt_pack.svh - GENERATED by tools/gen_pack_svh.py; do not hand-edit.",
        "// Byte-identical replay of the PS load sequence (ppt_pynq.load_image + dp_load colors).",
        *notes,
        f"localparam int NPOL = {npol};",
        f"localparam int NW   = {nw};",
        f"localparam logic [39:0] WRITES [0:NW-1] = '{{",
    ]
    body = [f"    {{8'h{r:02X}, 32'h{v:08X}}}" for r, v in all_writes]
    lines.append(",\n".join(body))
    lines.append("};")
    lines.append("localparam int POL_START [0:NPOL-1] = '{" + ", ".join(map(str, starts)) + "};")
    lines.append("localparam int POL_LEN   [0:NPOL-1] = '{" + ", ".join(map(str, lens)) + "};")
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote {out}  ({npol} policies, {nw} writes)")


ACT = {"NOP": 0, "SWAP": 1, "META": 2, "COLOR": 3, "MUTE": 4, "DECIN": 5}


def emit_ctrl_svh(spec_path: str, out: Path) -> None:
    spec = json.load(open(spec_path))
    nbtn = spec["nbtn"]
    entries = spec["entries"]                       # [{profile, btn, act, arg}]
    tbl = {(e["profile"], e["btn"]): (ACT[e["act"]], e.get("arg", 0)) for e in entries}
    lines = [
        "// ppt_ctrl_pack.svh - GENERATED by tools/gen_pack_svh.py from " + Path(spec_path).name + "; do not hand-edit.",
        f"localparam int NENT = {2 * nbtn};",
        f"localparam logic [10:0] CTRL_TBL [0:NENT-1] = '{{",
    ]
    rows = []
    for prof in (0, 1):
        for b in range(nbtn):
            code, arg = tbl.get((prof, b), (0, 0))
            last = (prof == 1 and b == nbtn - 1)
            rows.append(f"    {{3'd{code}, 8'h{arg & 0xFF:02X}}}{' ' if last else ','}  // P{prof} BTN{b}")
    lines.extend(rows)
    lines.append("};")
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote {out}  ({2*nbtn} entries)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest")
    ap.add_argument("-o", "--outdir", default=str(Path(__file__).resolve().parents[1] / "rtl"))
    a = ap.parse_args()
    global _MANIFEST_DIR
    _MANIFEST_DIR = Path(a.manifest).resolve().parent
    man = json.load(open(a.manifest))
    outdir = Path(a.outdir)
    emit_pack_svh(man["policies"], outdir / "ppt_pack.svh")
    if man.get("ctrl_table"):
        emit_ctrl_svh(_rel(man["ctrl_table"]), outdir / "ppt_ctrl_pack.svh")
    return 0


if __name__ == "__main__":
    sys.exit(main())
