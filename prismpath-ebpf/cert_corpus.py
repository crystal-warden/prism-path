#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Build the eBPF in-kernel conformance corpus from the FROZEN predicate vectors — the same
`prismpath/portable/conformance/predicates.json` every kernel certifies against.

Each in-fragment predicate compiles to its own PPT table (SubsetError => outside the Level M
match-action fragment => excluded, with the reason counted — not hidden behind "declared subset").
For each kept vector we emit a table-per-vector record and cross-check the expected verdict against
interp.c so a mismatch is caught before the kernel run. The loader's `certify` mode then runs every
record through the actual XDP program via BPF_PROG_TEST_RUN.

Record format (LE): <s32 expected_target><u32 tbl_len><tbl bytes><u32 pkt_len><pkt bytes>
Usage: cert_corpus.py <out.packets.bin>
       cert_corpus.py --boundary <out.packets.bin>

`--boundary` writes the other corpus, the evaluator's own bounds rather than the frozen vectors: an
operand stack at the depth the source language can reach and at STACK_MAX, programs of 33, 2,000 and
4,000 words, and a node of 200 edges with the match on the last. Each record's expectation is an
RPN evaluation written here, independent of both the kernel and interp.c, and interp.c is the second
referee as above. The in kernel job loads the program under the verifier and runs these records, so a
change to the evaluator that the verifier refuses, or that misroutes at a bound, fails there.
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
from ebpf_table_limits import table_refusals             # noqa: E402
import declared_subset                                    # noqa: E402

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


def rpn(img, prog, ctx):
    """One edge program evaluated on its own stack, the semantics of interp.c written independently."""
    names = {index: name for name, index in img.fields.items()}
    stack = []
    for word in prog:
        if word < 0x8000:
            field, op, _ty, val = img.atoms[word]
            reading = ctx[names[field]]
            stack.append({pc.OP_EQ: reading == val, pc.OP_NE: reading != val, pc.OP_LT: reading < val,
                          pc.OP_LE: reading <= val, pc.OP_GT: reading > val, pc.OP_GE: reading >= val}[op])
        elif word == pc.OPC_NOT:
            stack.append(not stack.pop())
        elif word in (pc.OPC_AND, pc.OPC_OR):
            right, left = stack.pop(), stack.pop()
            stack.append((left and right) if word == pc.OPC_AND else (left or right))
        else:
            stack.append(word == pc.OPC_TRUE)
    return stack[0]


def boundary_images():
    """[(name, image, ctx, expected target)] at and past the evaluator's old bounds, all within the new."""
    out = []

    def single(name, prog_of, edges=1, xs=(0, 1, 2, 7, 63)):
        for x in xs:
            img = pc.TableImage(max_steps=1)
            field = img.field("x")
            prog = prog_of(img, field)
            ctx = {"x": x}
            img.nodes = [("p", [(1, name, prog)]), ("t", [])]
            img.start = 0
            out.append((f"{name} x={x}", img, ctx, 1 if rpn(img, prog, ctx) else -1))

    def chain(depth):
        """depth pushes, then depth - 1 operators alternating AND and OR: the stack reaches depth."""
        def build(img, field):
            prog = [img.atom(field, pc.OP_NE, pc.TY_INT, k) for k in range(depth)]
            prog += [pc.OPC_AND if k % 2 else pc.OPC_OR for k in range(depth - 1)]
            return prog
        return build

    def listed(count, negate, words=0):
        """x in [0..count), `words` long by repeating the first atom (a program may reuse an atom)."""
        def build(img, field):
            prog = []
            for k in range(count):
                prog.append(img.atom(field, pc.OP_EQ, pc.TY_INT, k))
                if k:
                    prog.append(pc.OPC_OR)
            while len(prog) + 2 <= words - negate:
                prog += [0, pc.OPC_OR]
            return prog + ([pc.OPC_NOT] if negate else [])
        return build

    single("depth 25", chain(25))
    single("depth 63", chain(63))
    single("depth 64 (STACK_MAX)", chain(64))
    single("33 member list", listed(33, False), xs=(0, 32, 33, 99))
    single("not in a 33 member list", listed(33, True), xs=(0, 32, 33, 99))
    single("not in a 1000 member list", listed(1000, True), xs=(0, 999, 1000, 5000))
    single("4000 word program", listed(1000, True, 4000), xs=(0, 999, 1000, 5000))
    for x in (0, 150, 199, 400):
        img = pc.TableImage(max_steps=1)
        field = img.field("x")
        edges, expected = [], -1
        for k in range(200):
            prog = [img.atom(field, pc.OP_EQ, pc.TY_INT, k)]
            edges.append((k + 1, f"x == {k}", prog))
            if expected < 0 and x == k:
                expected = k + 1
        img.nodes = [("p", edges)] + [(f"t{k}", []) for k in range(200)]
        img.start = 0
        out.append((f"200 edges x={x}", img, {"x": x}, expected))
    return out


def boundary(out_path):
    tmp = HERE / "scratch"; tmp.mkdir(exist_ok=True)
    records, disagree = bytearray(), 0
    for name, img, ctx, expected in boundary_images():
        tbl = img.serialize()
        refused = table_refusals(tbl)
        if refused:
            raise SystemExit(f"{name}: a boundary table is outside the evaluator's limits: {refused}")
        regs_payload = pc.encode_regs(img, ctx, node_idx=0)
        pkt = frame_packet(0, len(img.fields), regs_payload[4:])
        target, matched = interp_target(tbl, regs_payload, tmp)
        if target != expected:
            disagree += 1
            print(f"  DISAGREE {name}: interp.c {target}, expected {expected}")
        records += struct.pack("<iI", expected, len(tbl)) + tbl + struct.pack("<I", len(pkt)) + pkt
    out_path.write_bytes(records)
    count = len(boundary_images())
    print(f"BOUNDARY CORPUS: {count} records, interp.c reference vs independent RPN: {count - disagree}/{count} agree")
    print(f"wrote {out_path}")
    return 0 if disagree == 0 else 1


def main():
    if sys.argv[1] == "--boundary":
        return boundary(Path(sys.argv[2]))
    out_path = Path(sys.argv[1])
    tmp = HERE / "scratch"; tmp.mkdir(exist_ok=True)
    cases = json.loads((CONF / "predicates.json").read_text())["cases"]

    records = bytearray()
    kept = 0
    kept_ids = []
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
        # A table the kernel would clamp is outside the eBPF target's subset, so it is excluded and
        # counted here, never certified against a reference that clamps the same way.
        if table_refusals(tbl):
            excl["ebpf-limits"] += 1
            continue
        regs_bytes = regs_payload[4:]
        n_fields = len(img.fields)
        pkt = frame_packet(0, n_fields, regs_bytes)

        # The kernel is held to the frozen expectation itself: a match is edge 0's target and no match
        # is -1. The C reference interpreter is a second referee that must agree with the same record.
        frozen_target = img.nodes[0][1][0][0] if expect is True else -1
        interp_target_index, matched = interp_target(tbl, regs_payload, tmp)
        if not isinstance(expect, bool) or matched != expect or interp_target_index != frozen_target:
            ref_disagree += 1                                    # C reference vs recorded expect
        records += struct.pack("<iI", frozen_target, len(tbl)) + tbl + struct.pack("<I", len(pkt)) + pkt
        kept += 1
        kept_ids.append(declared_subset.case_id(c))

    out_path.write_bytes(records)
    total = len(cases)
    print(f"PREDICATE CORPUS: {total} frozen vectors")
    print(f"  in declared subset (in-fragment condition + read fields i32-representable): {kept}")
    # refuse, not warn: a smaller subset would certify less and still report every record passing
    declared_subset.require_frozen(kept_ids, "cert_corpus")
    print(f"  excluded: {sum(excl.values())}")
    for r, n in excl.most_common():
        print(f"     {n:4}  {r}")
    print(f"  interp.c reference vs recorded expect: {kept - ref_disagree}/{kept} agree"
          + ("" if ref_disagree == 0 else f"  ({ref_disagree} DISAGREE)"))
    print(f"\nwrote {out_path} — {kept} table-per-vector records")
    return 0 if ref_disagree == 0 and kept > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
