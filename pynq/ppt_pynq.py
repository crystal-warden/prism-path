#!/usr/bin/env python3
"""ppt_pynq.py — board-side driver + field server for the PPT overlay (runs ON the Arty
under PYNQ; Python 3, needs only `pynq`).

The register protocol here is byte-for-byte what tb/axi/test_ppt_axi.py certified in
simulation. `make deploy` is: recompile the .ppt on the dev box, scp it here, call
load_image() — BRAM contents change, the bitstream never does.

Usage on the board:
    sudo python3 ppt_pynq.py ppt_overlay.bit incident_severity.ppt incident_severity.json
        [--port 9317]

Then point the Mac bridge at this board's IP: the server accepts the same NDJSON field
stream route_live.py did, but the routing decision comes from the fabric.
"""
from __future__ import annotations

import json
import socket
import struct
import sys
import time

R_LOAD_SEL_ADDR = 0x00
R_LOAD_DATA     = 0x04
R_FLD_IDX_TYPE  = 0x08
R_FLD_VAL       = 0x0C
R_BUMP          = 0x10
R_CTRL          = 0x14
R_STATUS        = 0x18
R_RESULT        = 0x1C
R_SOFT_RST      = 0x20
R_MAGIC         = 0x24
MAGIC           = 0x50505431          # "PPT1"

TY_NONE, TY_BOOL, TY_INT, TY_STR = 0, 1, 2, 3


class PptImage:
    """Parse a PPT v1 binary image (TABLE_FORMAT.md) + its JSON debug view (field names,
    intern table) — no prismpath dependency on the board."""

    def __init__(self, ppt_path: str, json_path: str):
        b = open(ppt_path, "rb").read()
        (magic, version, self.n_fields, self.n_interns, self.n_atoms, self.n_nodes,
         self.n_edges, self.prog_len, self.start, self.visits_idx, self.max_steps,
         self.max_stack, _pad) = struct.unpack_from("<IHHHHHHHHHHHH", b, 0)
        assert magic == 0x4D545050 and version == 1, "not a PPT v1 image"
        off = 28
        self.atoms = []
        for _ in range(self.n_atoms):
            f, op, ty, val = struct.unpack_from("<HBBi", b, off)
            self.atoms.append((f, op, ty, val))
            off += 8
        self.node_recs = []
        for _ in range(self.n_nodes):
            self.node_recs.append(struct.unpack_from("<HH", b, off))
            off += 4
        self.edges = []
        for _ in range(self.n_edges):
            self.edges.append(struct.unpack_from("<HHH", b, off))
            off += 6
        self.prog = list(struct.unpack_from(f"<{self.prog_len}H", b, off))
        dbg = json.load(open(json_path))
        self.fields = dbg["fields"]                       # name -> idx
        self.intern = dict(dbg["intern"])                 # str -> id
        self.node_names = [n["name"] for n in dbg["nodes"]]

    def encode(self, v):
        if v is None:
            return TY_NONE, 0
        if isinstance(v, bool):
            return TY_BOOL, int(v)
        if isinstance(v, int) and -2**31 <= v < 2**31:
            return TY_INT, v
        if isinstance(v, str):
            if v not in self.intern:
                self.intern[v] = len(self.intern)
            return TY_STR, self.intern[v]
        return TY_NONE, 0                                 # out-of-domain -> missing


class PptOverlay:
    def __init__(self, bit_path: str):
        from pynq import Overlay
        self.ol = Overlay(bit_path)
        ip = next(k for k in self.ol.ip_dict if "ppt" in k.lower())
        self.mmio = self.ol.ip_dict[ip]  # noqa: F841 — keep dict entry for debugging
        self.io = getattr(self.ol, ip).mmio if hasattr(getattr(self.ol, ip), "mmio") \
            else __import__("pynq").MMIO(self.ol.ip_dict[ip]["phys_addr"], 0x100)
        got = self.io.read(R_MAGIC)
        assert got == MAGIC, f"overlay magic mismatch: {got:#x}"

    def _load(self, sel: int, addr: int, data: int):
        self.io.write(R_LOAD_SEL_ADDR, (sel << 16) | addr)
        self.io.write(R_LOAD_DATA, data & 0xFFFFFFFF)

    def load_image(self, img: PptImage):
        self.io.write(R_SOFT_RST, 1)
        self._load(0, 0, img.visits_idx)
        for i, (f, op, ty, val) in enumerate(img.atoms):
            self._load(1, i, (ty << 24) | (op << 16) | f)
            self._load(2, i, val & 0xFFFFFFFF)
        for ni, (eoff, ecnt) in enumerate(img.node_recs):
            self._load(3, ni, (ecnt << 16) | eoff)
        for ei, (tgt, poff, pcnt) in enumerate(img.edges):
            self._load(4, ei, (poff << 16) | tgt)
            self._load(5, ei, pcnt)
        for pi, w in enumerate(img.prog):
            self._load(6, pi, w)

    def write_fields(self, img: PptImage, ctx: dict):
        for name, idx in img.fields.items():
            ty, val = img.encode(ctx.get(name))
            self.io.write(R_FLD_IDX_TYPE, (ty << 16) | idx)
            self.io.write(R_FLD_VAL, val & 0xFFFFFFFF)

    def evaluate(self, node: int, use_visits: bool = False):
        self.io.write(R_CTRL, (int(use_visits) << 16) | node)
        for _ in range(1000):
            s = self.io.read(R_STATUS)
            if s & 0b010:
                break
        else:
            raise TimeoutError("fabric evaluate never done")
        result = self.io.read(R_RESULT)                   # clears the done latch
        if not (s & 0b100):
            return None
        return (result >> 16) & 0xFFFF, result & 0xFFFF   # (edge, target)


def watch_and_reload(ol: PptOverlay, holder: dict, lock, ppt_path: str, json_path: str):
    """Hot reload — the demo's spine: a new .ppt landing on disk becomes new BRAM contents
    in milliseconds, mid-stream, bitstream untouched. `make deploy` scps the files; this
    thread notices."""
    import os
    import threading  # noqa: F401
    last_mtime = os.path.getmtime(ppt_path)
    while True:
        time.sleep(0.5)
        try:
            m = os.path.getmtime(ppt_path)
        except OSError:
            continue
        if m != last_mtime:
            last_mtime = m
            t0 = time.perf_counter_ns()
            new_img = PptImage(ppt_path, json_path)
            with lock:
                ol.load_image(new_img)
                holder["img"] = new_img
            dt_ms = (time.perf_counter_ns() - t0) / 1e6
            print(f"*** TABLE RELOADED in {dt_ms:.1f}ms — same circuit, new policy ***")


def serve(ol: PptOverlay, holder: dict, lock, port: int):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    print(f"fabric router up — listening on :{port}")
    log = open("fabric_route_log.ndjson", "a")
    while True:
        conn, addr = srv.accept()
        print(f"bridge connected from {addr[0]}")
        last = None
        n = 0
        for line in conn.makefile("r"):
            line = line.strip()
            if not line:
                continue
            sample = json.loads(line)
            with lock:
                img = holder["img"]
                ol.write_fields(img, sample)
                t0 = time.perf_counter_ns()
                res = ol.evaluate(img.start)
                dt_us = (time.perf_counter_ns() - t0) / 1000
            decision = img.node_names[res[1]] if res else "<stuck>"
            n += 1
            log.write(json.dumps({"decision": decision, "us": round(dt_us, 1),
                                  **sample}) + "\n")
            log.flush()
            if decision != last:
                print(f"#{n:6d} -> {decision:12s} ({dt_us:.0f}us round-trip) "
                      f"rate={sample.get('error_rate')} risk={sample.get('data_at_risk')}")
                last = decision
        print(f"bridge disconnected after {n} samples")


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("bitfile")
    ap.add_argument("ppt")
    ap.add_argument("json")
    ap.add_argument("--port", type=int, default=9317)
    args = ap.parse_args()
    import threading
    img = PptImage(args.ppt, args.json)
    ol = PptOverlay(args.bitfile)
    ol.load_image(img)
    print(f"image loaded: {img.n_atoms} atoms, {img.n_nodes} nodes, "
          f"{img.n_edges} edges, {img.prog_len} prog words")
    holder = {"img": img}
    lock = threading.Lock()
    threading.Thread(target=watch_and_reload, args=(ol, holder, lock, args.ppt, args.json),
                     daemon=True).start()
    serve(ol, holder, lock, args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
