#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Refuse a PPT table the eBPF evaluator cannot run faithfully, before it is written or signed.

The in kernel evaluator runs every loop under a fixed bound so the verifier accepts it. It reads at most
MAX_EDGES_PER_NODE edges of a node and MAX_PROG_PER_EDGE words of an edge program, and its operand stack
holds STACK_MAX entries. Past any of those bounds it clamps instead of failing: a push past the stack is
dropped, and the rest of a long program or a node's later edges are never read. The shared compiler
emits such tables, because the C and FPGA targets allow more, so `when x not in [0..32]` compiles to 66
words and decided the inverse of the authored policy in the kernel, and `when a and (b and (c and (d and
e)))` reaches depth 5 and ignored `e` (October 2026 reading boundary audit). The image loader refuses the
same tables at load (ppt_image.c, parse_image_buf), and this module refuses them where the eBPF tooling
builds one.

The bounds are read from ppt_common.h, the header the evaluator is compiled from, so this check and the
kernel cannot disagree about them. Every program is also checked to be well formed, because the
evaluator treats a missing operand as a no op where the C reference would read past its stack.

    python ebpf_table_limits.py TABLE.ppt [TABLE.ppt ...]     exit 1 if any table is refused
"""
import re
import struct
import sys
from pathlib import Path
from typing import Dict, List

HERE = Path(__file__).resolve().parent
HEADER = HERE / "ppt_common.h"
TABLE_HEADER = struct.Struct("<IHHHHHHHHHHHH")
LIMIT_NAMES = ("MAX_ATOMS", "MAX_NODES", "MAX_EDGES", "MAX_PROG_WORDS", "MAX_FIELDS_PER_PKT",
               "MAX_EDGES_PER_NODE", "MAX_PROG_PER_EDGE", "STACK_MAX", "OPC_NOT", "OPC_AND", "OPC_OR",
               "OPC_TRUE", "OPC_FALSE", "PPT_MAGIC")


def header_constants(header: Path = HEADER) -> Dict[str, int]:
    """The evaluator's bounds and opcodes, read from the `#define` lines of ppt_common.h."""
    found: Dict[str, int] = {}
    for name, value in re.findall(r"^#define\s+(\w+)\s+(0x[0-9A-Fa-f]+|\d+)u?\b", header.read_text(), re.M):
        found[name] = int(value, 0)
    missing = [name for name in LIMIT_NAMES if name not in found]
    if missing:
        raise RuntimeError(f"{header} no longer defines {', '.join(missing)}")
    return found


def table_refusals(table: bytes, limits: Dict[str, int] = None) -> List[str]:
    """Every reason the eBPF evaluator could not run this table as written; empty when it can."""
    limits = limits or header_constants()
    if len(table) < TABLE_HEADER.size:
        return [f"table is {len(table)} bytes, shorter than its {TABLE_HEADER.size} byte header"]
    (magic, version, n_fields, _n_interns, n_atoms, n_nodes, n_edges, prog_len,
     _start, _visits, _max_steps, _max_stack, _flags) = TABLE_HEADER.unpack_from(table, 0)
    if magic != limits["PPT_MAGIC"] or version != 1:
        return ["not a PPT v1 table"]
    refusals: List[str] = []
    for count, bound in ((n_atoms, "MAX_ATOMS"), (n_nodes, "MAX_NODES"), (n_edges, "MAX_EDGES"),
                         (prog_len, "MAX_PROG_WORDS"), (n_fields, "MAX_FIELDS_PER_PKT")):
        if count > limits[bound]:
            refusals.append(f"{count} exceeds {bound} {limits[bound]}")
    need = TABLE_HEADER.size + 8 * n_atoms + 4 * n_nodes + 6 * n_edges + 2 * prog_len
    if len(table) < need:
        return refusals + [f"table is {len(table)} bytes, its sections need {need}"]
    cursor = TABLE_HEADER.size + 8 * n_atoms
    nodes = [struct.unpack_from("<HH", table, cursor + 4 * index) for index in range(n_nodes)]
    cursor += 4 * n_nodes
    edges = [struct.unpack_from("<HHH", table, cursor + 6 * index) for index in range(n_edges)]
    cursor += 6 * n_edges
    prog = list(struct.unpack_from(f"<{prog_len}H", table, cursor))

    for node_index, (edge_off, edge_cnt) in enumerate(nodes):
        if edge_cnt > limits["MAX_EDGES_PER_NODE"]:
            refusals.append(f"node {node_index} has {edge_cnt} edges, past MAX_EDGES_PER_NODE "
                            f"{limits['MAX_EDGES_PER_NODE']}, so the kernel would never read the rest")
        if edge_off + edge_cnt > n_edges:
            refusals.append(f"node {node_index} edges {edge_off}+{edge_cnt} run past the {n_edges} edges")
    for edge_index, (_target, prog_off, prog_cnt) in enumerate(edges):
        where = f"edge {edge_index}"
        if prog_cnt > limits["MAX_PROG_PER_EDGE"]:
            refusals.append(f"{where} program is {prog_cnt} words, past MAX_PROG_PER_EDGE "
                            f"{limits['MAX_PROG_PER_EDGE']}, so the kernel would cut it short")
        if prog_off + prog_cnt > prog_len:
            refusals.append(f"{where} program {prog_off}+{prog_cnt} runs past the {prog_len} words")
            continue
        refusals += program_refusals(where, prog[prog_off:prog_off + prog_cnt], n_atoms, limits)
    return refusals


def program_refusals(where: str, words: List[int], n_atoms: int, limits: Dict[str, int]) -> List[str]:
    """Run one edge program's stack effect: every operator has its operands, the depth never passes
    STACK_MAX, and exactly one result is left. The shared compiler already demands the last two of
    its own output; this repeats them on the bytes the kernel will actually be given."""
    depth, peak = 0, 0
    for word in words:
        if word < 0x8000:
            if word >= n_atoms:
                return [f"{where} reads atom {word}, past the {n_atoms} atoms"]
            depth += 1
        elif word in (limits["OPC_TRUE"], limits["OPC_FALSE"]):
            depth += 1
        elif word == limits["OPC_NOT"]:
            if depth < 1:
                return [f"{where} negates an empty stack"]
        elif word in (limits["OPC_AND"], limits["OPC_OR"]):
            if depth < 2:
                return [f"{where} combines fewer than two operands"]
            depth -= 1
        else:
            return [f"{where} holds unknown opcode {word:#06x}"]
        peak = max(peak, depth)
    refusals = []
    if peak > limits["STACK_MAX"]:
        refusals.append(f"{where} needs stack depth {peak}, past STACK_MAX {limits['STACK_MAX']}, so the "
                        f"kernel would drop operands")
    if depth != 1:
        refusals.append(f"{where} leaves {depth} results, not one")
    return refusals


def require_within_limits(table: bytes, what: str = "table") -> bytes:
    """Return the table unchanged, or raise naming every reason the eBPF evaluator would misread it."""
    refusals = table_refusals(table)
    if refusals:
        raise ValueError(f"{what} is outside the eBPF evaluator's limits: " + "; ".join(refusals))
    return table


def main(argv: List[str]) -> int:
    if not argv:
        print(__doc__.strip().splitlines()[-1].strip())
        return 2
    refused = 0
    for path in argv:
        refusals = table_refusals(Path(path).read_bytes())
        if refusals:
            refused += 1
            print(f"REFUSED {path}")
            for reason in refusals:
                print(f"  {reason}")
        else:
            print(f"ok      {path}")
    return 1 if refused else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
