#!/usr/bin/env python3
"""Build the eBPF in-kernel conformance corpus from the FROZEN predicate vectors — the same
`prismpath/portable/conformance/predicates.json` every kernel certifies against.

Each in-fragment predicate compiles to its own PPT table (SubsetError => outside the Level M
match-action fragment => excluded, with the reason counted — not hidden behind "declared subset").
For each kept vector we emit a table-per-vector record and cross-check the expected verdict against
interp.c so a mismatch is caught before the kernel run. The loader's `certify` mode then runs every
record through the actual XDP program via BPF_PROG_TEST_RUN.

Record format (LE): <s32 expected_target><u32 tbl_len><tbl bytes><u32 pkt_len><pkt bytes>
Usage: cert_corpus.py <out.packets.bin>
"""
import collections
import json
import socket
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "prismpath-hw"))
sys.path.insert(0, str(REPO))
import ppt_compile as pc                                  # noqa: E402

PPT_MAGIC = 0x4D545050
INTERP = HERE / "interp"
CONF = REPO / "prismpath" / "portable" / "conformance"


def frame_packet(node_idx, n_fields, regs_bytes):
    payload = struct.pack("<III", PPT_MAGIC, node_idx, n_fields) + regs_bytes
    eth = struct.pack("!6s6sH", b"\xff" * 6, b"\x02" * 6, 0x0800)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 8 + len(payload), 0x1234, 0, 64, 17, 0,
                     socket.inet_aton("192.168.1.1"), socket.inet_aton("192.168.1.2"))
    udp = struct.pack("!HHHH", 12345, 9999, 8 + len(payload), 0)
    return eth + ip + udp + payload


def interp_target(ppt_bytes, regs_payload, tmp):
    (tmp / "c.ppt").write_bytes(ppt_bytes)
    (tmp / "c.bin").write_bytes(regs_payload)
    out = subprocess.run([str(INTERP), "eval", str(tmp / "c.ppt"), str(tmp / "c.bin")],
                         capture_output=True, text=True).stdout.strip()
    if out.startswith("match"):
        return int(out.split()[2]), True
    return -1, False


def main():
    out_path = Path(sys.argv[1])
    tmp = HERE / "scratch"; tmp.mkdir(exist_ok=True)
    cases = json.loads((CONF / "predicates.json").read_text())["cases"]

    records = bytearray()
    kept = 0
    excl = collections.Counter()
    ref_disagree = 0
    for c in cases:
        cond, ctx, expect = c["cond"], c["ctx"], c["expect"]
        try:
            img = pc.compile_predicate(cond)
        except pc.SubsetError as e:
            excl[e.reason] += 1
            continue
        except Exception as e:
            excl[f"other:{type(e).__name__}"] += 1
            continue
        # Canonical declared-subset filter (identical to prismpath-hw/run_vectors cert_predicates):
        # in-subset iff the condition is in-fragment (compiled above) AND the fields it READS are
        # representable on the i32 table machine. encode_regs only touches read fields, so a non-scalar
        # value in an UNREAD ctx field is irrelevant — checking all ctx values was an over-strict bug.
        try:
            regs_payload = pc.encode_regs(img, ctx, node_idx=0)     # <I node_idx> + regs
        except pc.SubsetError as e:
            excl[e.reason] += 1
            continue

        tbl = img.serialize()
        regs_bytes = regs_payload[4:]
        n_fields = len(img.fields)
        pkt = frame_packet(0, n_fields, regs_bytes)

        exp_target, matched = interp_target(tbl, regs_payload, tmp)
        if isinstance(expect, bool) and matched != expect:
            ref_disagree += 1                                    # C reference vs recorded expect
        records += struct.pack("<iI", exp_target, len(tbl)) + tbl + struct.pack("<I", len(pkt)) + pkt
        kept += 1

    out_path.write_bytes(records)
    total = len(cases)
    EXPECTED_SUBSET = 114   # the declared subset shared with the FPGA C-target; see test_conformance_drift
    print(f"PREDICATE CORPUS: {total} frozen vectors")
    print(f"  in declared subset (in-fragment condition + read fields i32-representable): {kept}")
    if kept != EXPECTED_SUBSET:
        print(f"  *** WARNING: subset drifted from {EXPECTED_SUBSET} — reconcile FPGA/eBPF evidence "
              f"(#72/#77) + the drift guard before trusting this run")
    print(f"  excluded: {sum(excl.values())}")
    for r, n in excl.most_common():
        print(f"     {n:4}  {r}")
    print(f"  interp.c reference vs recorded expect: {kept - ref_disagree}/{kept} agree"
          + ("" if ref_disagree == 0 else f"  ({ref_disagree} DISAGREE)"))
    print(f"\nwrote {out_path} — {kept} table-per-vector records")
    return 0 if ref_disagree == 0 and kept > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
