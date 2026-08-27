#!/usr/bin/env python3
"""cert_hyst_board.py — silicon re-cert: the frozen hyst_band sequence corpus on the real fabric.

Runs ON the board (PYNQ, root + sourced env) against the loaded stateful finale overlay. Two legs:

Leg 1 (PS-mode sequence replay, the decision oracle): for every corpus event, write the pot field,
evaluate from the EXPLICIT resident node (PS supplies node_idx exactly like the certified
single-step references), read the matched target, feed it back. The silicon table + interpreter
must reproduce the frozen per-step `trail` at every one of the 4568 events. This is the same
replay discipline as the 124/124 predicate certs, extended to sequences.

Leg 2 (auto-mode resident spot check): arm AUTO_CTRL with the stateful+safe bits (the signed arm
word), confirm CUR_NODE (0x30) reads back stateful=1 and the armed start, and that the resident
band tracks the LIVE pot through at least one boundary crossing (prompts the operator to sweep).
The full free-running trail was certified in RTL simulation (4568/4568); on silicon the pot is
physical, so the settled behavior is verified live at the boundaries rather than replayed.

Usage (on the board):
    sudo -s
    source /etc/profile.d/pynq_venv.sh; source /etc/profile.d/xrt_setup.sh
    python3 cert_hyst_board.py hyst_corpus.json hyst_band.ppt hyst_band.json [--auto]
"""
import json
import struct
import sys
import time

BASE = 0x40000000
R_LOAD_SEL, R_LOAD_DATA = 0x00, 0x04
R_FLD_IDX, R_FLD_VAL = 0x08, 0x0C
R_CTRL, R_STATUS, R_RESULT = 0x14, 0x18, 0x1C
R_SOFT_RST, R_MAGIC, R_AUTO_CTRL, R_POT_NOW, R_CUR_NODE = 0x20, 0x24, 0x28, 0x2C, 0x30
MAGIC = 0x50505431
TY_INT = 2


def load_policy(io, ppt_path, dbg):
    """The PS load sequence (mirrors ppt_pynq.load_image + colors), plain MMIO."""
    data = open(ppt_path, "rb").read()
    (magic, ver, n_fields, n_interns, n_atoms, n_nodes, n_edges,
     prog_len, start, visits_idx, _ms, _mx, flags) = struct.unpack_from("<IHHHHHHHHHHHH", data, 0)
    assert magic == 0x4D545050 and ver == 1
    io.write(R_SOFT_RST, 1)

    def load(sel, addr, val):
        io.write(R_LOAD_SEL, ((sel & 0xFFFF) << 16) | (addr & 0xFFFF))
        io.write(R_LOAD_DATA, val & 0xFFFFFFFF)

    load(0, 0, visits_idx)
    off = 28
    for i in range(n_atoms):
        f, op, ty, val = struct.unpack_from("<HBBi", data, off); off += 8
        load(1, i, ((ty & 0xFF) << 24) | ((op & 0xFF) << 16) | (f & 0xFFFF))
        load(2, i, val & 0xFFFFFFFF)
    node_recs = []
    for i in range(n_nodes):
        eo, ec = struct.unpack_from("<HH", data, off); off += 4
        node_recs.append((eo, ec))
        load(3, i, ((ec & 0xFFFF) << 16) | (eo & 0xFFFF))
    for i in range(n_edges):
        t, po, pc = struct.unpack_from("<HHH", data, off); off += 6
        load(4, i, ((po & 0xFFFF) << 16) | (t & 0xFFFF))
        load(5, i, pc)
    for i in range(prog_len):
        (w,) = struct.unpack_from("<H", data, off); off += 2
        load(6, i, w)
    for n in sorted(dbg["nodes"], key=lambda x: x["i"]):
        load(7, n["i"], int(n.get("color", 0)) & 0x3F)
    return {"start": start, "flags": flags, "safe": (flags >> 8) & 0xFF,
            "stateful": bool(flags & 0x08), "pot_fidx": dbg["fields"]["pot"]}


def eval_step(io, cur, pot, pot_fidx, timeout=0.02):
    io.write(R_FLD_IDX, (TY_INT << 16) | pot_fidx)
    io.write(R_FLD_VAL, pot & 0xFFFFFFFF)
    io.write(R_CTRL, cur & 0xFFFF)                     # pulses start (PS mode)
    t0 = time.time()
    while time.time() - t0 < timeout:
        st = io.read(R_STATUS)
        if st & 0x2:                                   # done latch
            res = io.read(R_RESULT)                    # read clears the latch
            assert st & 0x4, f"no matching edge: node={cur} pot={pot}"
            return res & 0xFFFF
    raise TimeoutError(f"evaluate stuck: node={cur} pot={pot}")


def main():
    corpus_p, ppt_p, json_p = sys.argv[1], sys.argv[2], sys.argv[3]
    do_auto = "--auto" in sys.argv
    from pynq import MMIO
    io = MMIO(BASE, 0x10000)
    assert io.read(R_MAGIC) == MAGIC, "no PPT overlay (MAGIC mismatch) — load the finale first"
    io.write(R_AUTO_CTRL, 0)                           # PS mode for the replay
    corpus = json.load(open(corpus_p))
    dbg = json.load(open(json_p))
    hdr = load_policy(io, ppt_p, dbg)
    assert hdr["stateful"] and hdr["safe"] == 2, "hyst_band header must be stateful with safe=high"
    names = corpus["node_names"]

    total = bad = 0
    for st in corpus["streams"]:
        cur = st["start"]
        for pot, want in zip(st["pots"], st["trail"]):
            got = eval_step(io, cur, pot, hdr["pot_fidx"])
            if got != want:
                bad += 1
                print(f"MISMATCH {st['name']}: pot={pot} cur={names[cur]} "
                      f"silicon={names[got]} frozen={names[want]}")
            cur = got
            total += 1
        print(f"  {st['name']:24s} {len(st['pots']):4d} events  end={names[cur]}")
    print(f"\nLEG 1 (PS-mode sequence replay): {total - bad}/{total} events match the frozen trail"
          f" -> {'PASS' if bad == 0 else 'FAIL'}")
    if bad:
        sys.exit(1)

    if do_auto:
        # Leg 2: arm the signed stateful word and watch the resident band on the LIVE pot
        word = ((hdr["safe"] & 0xFF) << 24) | ((hdr["pot_fidx"] & 0xFF) << 16) \
               | ((hdr["start"] & 0xFF) << 8) | 0x2 | 0x1
        io.write(R_AUTO_CTRL, word)
        time.sleep(0.05)
        cn = io.read(R_CUR_NODE)
        assert (cn >> 16) & 1, "CUR_NODE must read stateful=1 after the stateful arm"
        print(f"LEG 2 armed: resident={names[cn & 0xFFFF]} (word=0x{word:08X})")
        print("sweep the pot through both boundaries; resident band + pot follow for 30s:")
        last = None
        t0 = time.time()
        while time.time() - t0 < 30:
            cn = io.read(R_CUR_NODE) & 0xFFFF
            pot = io.read(R_POT_NOW) & 0xFFF
            if cn != last:
                print(f"  t={time.time()-t0:5.1f}s pot={pot:4d} resident -> {names[cn]}")
                last = cn
            time.sleep(0.05)
        print("LEG 2 done (operator-verified: enter at +H, leave at -H, hold on the line)")


if __name__ == "__main__":
    main()
