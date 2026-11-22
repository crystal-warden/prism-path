# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The `mesh` adapter: a model of one ESP32 node (`prismpath-hw/mesh/main/ppt_mesh.c`) as a distribution target
(spec-policy-distribution.md, section 3), so the Python reference runs the same machine, hold included, as the
C core the firmware carries.

A node holds one `.ppt` table of at most 640 bytes and decides with the embedded PPT evaluator
(`prismpath-hw/ppt_eval.h`). `evaluate` is that evaluator in Python, step for step: the first edge of a node
whose program is true wins, atoms compare the register file the table indexes, and a program word past the
atom range is one of the five boolean opcodes. A node ignores `meta` and runs its own table parser, so its
check of a `policy.ppt` is the image check alone (`kinds.check_mesh_table`).
"""
from __future__ import annotations

import struct
from typing import List, Optional, Tuple

from prismpath.distribution.adapters import Adapter
from prismpath.hotswap import policy_pack

TY_NONE, TY_BOOL, TY_INT, TY_STR = range(4)
OP_EQ, OP_NE, OP_LT, OP_LE, OP_GT, OP_GE, OP_TRUTHY = range(7)
OPC_NOT, OPC_AND, OPC_OR, OPC_TRUE, OPC_FALSE = range(0x8000, 0x8005)
STACK_MAX = 64                                     # ppt_mesh.c


class EvalError(ValueError):
    """A program word that is no opcode, or an operand stack past its bound."""


def _registers(regs: bytes) -> List[Tuple[int, int]]:
    """The register file after its 4 byte node prefix: (type, value) per field."""
    body = bytes(regs)[4:]
    return [struct.unpack_from("<ii", body, offset) for offset in range(0, len(body) - len(body) % 8, 8)]


def _atom(image: bytes, offset: int, registers: List[Tuple[int, int]]) -> bool:
    field, op, aty, aval = policy_pack.ATOM.unpack_from(image, offset)
    rty, rval = registers[field] if field < len(registers) else (TY_NONE, 0)
    lnum, rnum = rty in (TY_BOOL, TY_INT), aty in (TY_BOOL, TY_INT)
    if op in (OP_EQ, OP_NE):
        if lnum and rnum or rty == TY_STR and aty == TY_STR:
            equal = rval == aval
        else:
            equal = rty == TY_NONE and aty == TY_NONE
        return equal if op == OP_EQ else not equal
    if op in (OP_LT, OP_LE, OP_GT, OP_GE):
        if not (lnum and rnum):
            return False                                           # totality: a non numeric operand is unsatisfied
        return {OP_LT: rval < aval, OP_LE: rval <= aval, OP_GT: rval > aval, OP_GE: rval >= aval}[op]
    if op == OP_TRUTHY:
        return rty != TY_NONE and rval != 0
    return False


def evaluate(image: bytes, regs: bytes, node: int) -> Optional[Tuple[int, int]]:
    """(edge index, target node) of the first edge of `node` whose program holds, or None when none does
    (`ppt_eval.h` `evaluate`). `image` is a table `policy_pack.validate_image` accepts."""
    header = policy_pack.read_ppt_header(image)
    atoms = policy_pack.HEADER.size
    nodes = atoms + policy_pack.ATOM.size * header["atoms"]
    edges = nodes + policy_pack.NODE.size * header["nodes"]
    words = edges + policy_pack.EDGE.size * header["edges"]
    registers = _registers(regs)
    edge_offset, edge_count = policy_pack.NODE.unpack_from(image, nodes + policy_pack.NODE.size * node)
    for index in range(edge_count):
        target, program_offset, program_count = policy_pack.EDGE.unpack_from(
            image, edges + policy_pack.EDGE.size * (edge_offset + index))
        stack: List[bool] = []
        for position in range(program_count):
            (word,) = policy_pack.WORD.unpack_from(image, words + policy_pack.WORD.size * (program_offset + position))
            if word < 0x8000 or word in (OPC_TRUE, OPC_FALSE):
                if len(stack) >= STACK_MAX:
                    raise EvalError("the operand stack is past its bound")
                stack.append(word == OPC_TRUE if word >= 0x8000 else _atom(image, atoms + policy_pack.ATOM.size * word,
                                                                             registers))
            elif word == OPC_NOT:
                stack[-1] = not stack[-1]
            elif word in (OPC_AND, OPC_OR):
                right = stack.pop()
                stack[-1] = (stack[-1] and right) if word == OPC_AND else (stack[-1] or right)
            else:
                raise EvalError(f"program word {word:#06x} is no opcode")
        if stack and stack[0]:
            return index, target
    return None


class MeshAdapter(Adapter):
    """One modelled mesh node. `activate` holds the committed table and `deactivate` drops it, so the node
    decides nothing. `decide(regs)` is the next node from the table's start node, None when no edge holds."""
    kind = "mesh"

    def __init__(self):
        self.table: Optional[bytes] = None

    def activate(self, release) -> None:
        self.table = release.bodies["policy.ppt"]

    def deactivate(self, cause: str) -> None:
        self.table = None

    def decide(self, regs: bytes) -> Optional[int]:
        if self.table is None:
            raise RuntimeError("a node with no table decides nothing")
        start = policy_pack.read_ppt_header(self.table)["start"]
        step = evaluate(self.table, regs, start)
        return None if step is None else step[1]
