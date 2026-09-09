#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""gen_hyst_corpus.py — freeze the hyst_band sequence corpus (the fabric resident-FSM oracle).

The stateful selector discipline applied to a continuous level: a stream of pot samples is one
evaluate per sample from the RESIDENT node (each evaluate is a single step: scan the current
node's ordered edges, first match wins, the target becomes the resident node). The reference
trail is computed twice — a Python stepper over the compiled image's debug view, and the
certified C target (`build/interp eval`, unmodified, one invocation per step, the resident node
carried in regs.bin's leading word) — and both must agree at every step before the corpus
freezes. The frozen JSON is the one oracle the RTL simulation and the on-board re-cert replay.

Streams: boundary sweeps both directions, parked-on-the-line jitter at both thresholds from both
sides (the measured 663..670 dither that motivated the policy), deadband entry/exit walks that
prove enter-at-+H / leave-at--H, full-range jumps (the two-step traversal through mid is part of
the frozen trail), seeded random walks, and a dwell-biased stress stream. Deterministic: fixed
seeds, no wall clock.
"""
from __future__ import annotations

import hashlib
import json
import random
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FLOWS = HERE / "demo" / "flows"
INTERP = HERE / "build" / "interp"

import ppt_compile as pc                                    # noqa: E402
from prismpath.kernel.parser import parse_file                     # noqa: E402

T_LO_IN, T_LO_OUT = 681, 649        # mid entered from below at +H, left at -H (T_lo=665, H=16)
T_HI_IN, T_HI_OUT = 1647, 1615      # high entered at +H, left at -H (T_hi=1631, H=16)


# ---------------------------------------------------------------- python stepper (reference 1)
class Stepper:
    def __init__(self, dbg: dict):
        self.atoms = dbg["atoms"]
        self.nodes = dbg["nodes"]
        self.start = dbg["start"]

    def _atom(self, i: int, pot: int) -> bool:
        a = self.atoms[i]
        assert a["field"] == "pot" and a["op"] == ">=" and a["type"] == "int"
        return pot >= a["val"]

    def _prog(self, prog: list[str], pot: int) -> bool:
        st: list[bool] = []
        for w in prog:
            if w.startswith("ATOM"):
                st.append(self._atom(int(w.split()[1]), pot))
            elif w == "TRUE":
                st.append(True)
            elif w == "FALSE":
                st.append(False)
            elif w == "NOT":
                st.append(not st.pop())
            elif w in ("AND", "OR"):
                b, a = st.pop(), st.pop()
                st.append((a and b) if w == "AND" else (a or b))
            else:
                raise AssertionError(w)
        assert len(st) == 1
        return st[0]

    def step(self, cur: int, pot: int) -> int:
        for e in self.nodes[cur]["edges"]:
            if self._prog(e["program"], pot):
                return e["target"]
        raise AssertionError(f"no matching edge: node={cur} pot={pot}")


# ---------------------------------------------------------------- C target (reference 2)
def c_step(img, ppt: Path, cur: int, pot: int, tmp: Path) -> int:
    tmp.write_bytes(pc.encode_regs(img, {"pot": pot}, node_idx=cur))
    out = subprocess.run([str(INTERP), "eval", str(ppt), str(tmp)],
                         capture_output=True, text=True, check=True).stdout.split()
    assert out[0] == "match", f"C target: no match at node={cur} pot={pot}: {out}"
    return int(out[2])


# ---------------------------------------------------------------- streams
def streams() -> list[tuple[str, list[int]]]:
    rng = random.Random(20260826)
    out: list[tuple[str, list[int]]] = []

    out.append(("sweep_up", list(range(0, 4096, 37))))
    out.append(("sweep_down", list(range(4095, -1, -37))))

    park = [rng.randint(663, 670) for _ in range(200)]
    out.append(("park_665_from_below", [300, 500] + park))          # LOW throughout: entry needs 681
    out.append(("park_665_from_above", [300, 700] + park))          # enters MID at 700, holds: exit needs <649
    jit_hi = [rng.randint(1623, 1639) for _ in range(200)]
    out.append(("park_1631_from_below", [300, 1000] + jit_hi))      # MID throughout: entry needs 1647
    # two warm-up samples at 1700: the resident FSM climbs one band per evaluate (low->mid->high),
    # THEN the jitter must hold HIGH (exit needs <1615)
    out.append(("park_1631_from_above", [300, 1700, 1700] + jit_hi))

    out.append(("deadband_walk", [600, 660, 680, 681, 670, 650, 649, 648, 660, 680, 681, 700]))
    out.append(("deadband_walk_high", [1000, 1640, 1646, 1647, 1620, 1616, 1615, 1614, 1600, 1646, 1647]))
    out.append(("jump_low_high", [100, 4000, 4000, 4000, 100, 100, 100]))
    out.append(("clamp_ends", [0, 0, 4095, 4095, 4095, 0, 0]))

    for k in range(30):
        r = random.Random(1000 + k)
        v = r.randint(0, 4095)
        pots = []
        for _ in range(100):
            v = max(0, min(4095, v + r.randint(-120, 120)))
            pots.append(v)
        out.append((f"walk_{k:02d}", pots))

    r = random.Random(777)
    dwell = []
    for _ in range(500):
        zone = r.random()
        if zone < 0.4:
            dwell.append(r.randint(T_LO_OUT - 12, T_LO_IN + 12))
        elif zone < 0.8:
            dwell.append(r.randint(T_HI_OUT - 12, T_HI_IN + 12))
        else:
            dwell.append(r.randint(0, 4095))
    out.append(("stress_dwell", dwell))
    return out


def main() -> int:
    md = FLOWS / "hyst_band.md"
    ppt = FLOWS / "hyst_band.ppt"
    img = pc.compile_flow(parse_file(str(md)))
    blob = img.serialize()
    assert blob == ppt.read_bytes(), "hyst_band.ppt is stale vs the .md — recompile first"
    dbg = img.debug()
    stepper = Stepper(dbg)
    names = [n["name"] for n in dbg["nodes"]]
    tmp = HERE / "build" / "hyst_regs.tmp"

    frozen = []
    total = 0
    n_nodes = len(names)
    for name, pots in streams():
        cur_py = cur_c = settled = dbg["start"]
        trail = []
        trail_settled = []          # the free-running fabric's fixpoint per held sample: iterate the
        for pot in pots:            # SAME certified step until stable (<= n_nodes, hysteresis absorbs)
            cur_py = stepper.step(cur_py, pot)
            cur_c = c_step(img, ppt, cur_c, pot, tmp)
            assert cur_py == cur_c, f"{name}: python={cur_py} C={cur_c} at pot={pot}"
            trail.append(cur_py)
            for _ in range(n_nodes + 1):
                nxt = stepper.step(settled, pot)
                assert nxt == c_step(img, ppt, settled, pot, tmp), \
                    f"{name}: settled-step disagreement at pot={pot}"
                if nxt == settled:
                    break
                settled = nxt
            else:
                raise AssertionError(f"{name}: no fixpoint at pot={pot} (cycle under constant input)")
            trail_settled.append(settled)
        frozen.append({"name": name, "start": dbg["start"], "pots": pots,
                       "trail": trail, "trail_settled": trail_settled})
        total += len(pots)
        print(f"  {name:24s} {len(pots):4d} events  end={names[trail[-1]]}"
              f"  settled_end={names[trail_settled[-1]]}")

    # the parked streams are the point: assert each frozen trail holds steady on the NAMED band
    by = {s["name"]: s for s in frozen}
    LOW, MID, HIGH = names.index("low"), names.index("mid"), names.index("high")
    assert set(by["park_665_from_below"]["trail"][1:]) == {LOW}, "665 from below must hold LOW"
    assert set(by["park_665_from_above"]["trail"][1:]) == {MID}, "665 from above must hold MID"
    assert set(by["park_1631_from_below"]["trail"][1:]) == {MID}, "1631 from below must hold MID"
    assert set(by["park_1631_from_above"]["trail"][2:]) == {HIGH}, "1631 from above must hold HIGH"

    doc = {"policy": "hyst_band", "image_sha256": hashlib.sha256(blob).hexdigest(),
           "node_names": names, "streams": frozen}
    out = FLOWS / "hyst_corpus.json"
    out.write_text(json.dumps(doc, indent=1) + "\n")
    print(f"FROZEN: {out.name}  {len(frozen)} streams, {total} events, "
          f"both references agree at every step")
    print(f"corpus sha256: {hashlib.sha256(out.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
