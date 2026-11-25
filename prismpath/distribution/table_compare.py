# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The table comparator of policy distribution (spec-policy-distribution.md, section 9.4, W8), for the `policy.ppt`
table of a `host` or a `mesh` target. It runs at the sealing tool and the controller and never in a PEP or the C
core. A PEP still holds a table to W2's byte rule, so a PEP alone stays as conservative as it was.

A table is a priority encoder per node: the first edge whose program holds wins, and no edge holding decides
nothing. The comparator gives the table one meaning beyond identity, the one the format and every substrate
already share: a run that reaches no terminal node (`stuck`, or `max_steps`) decides nothing, and a substrate
that decides nothing refuses (X3). On a mesh node no edge holding at the start is the deny verdict.

The staged table is not larger than the active one when the two share a frame (the header words, the terminal
nodes, the attribute and name sections and, when both are given, the signed field dictionary of `meta`), the
staged `max_steps` is not above the active one, and on every node and every register file the staged table takes
the same edge to the same node as the active one or takes none. A table that declares the stateful profile, or
whose nodes carry attributes a substrate materializes, is held to the same edge on every reading, since there a
step that takes no edge may keep a node that decides. Under that rule every run of the staged table follows the
active one's and either ends where it ends or ends deciding nothing.

The register files walked are every value each register can hold, `NONE`, `BOOL`, `INT` over all of i32 and `STR`
over every intern id, cut into classes by the atoms of the node being walked: an atom tests one register against
one constant, so the values between two constants (and the constants themselves, their neighbours, zero and the
ends of i32) are all the classes there are, and one value of each class is walked. That walk is exhaustive at the
register level, a superset of the engineer's reading domain, so it never misses a widening the reading domain
holds and may count as larger a change that differs only outside it. A node whose product of classes passes
`NODE_BOUND`, or a table whose walk passes `TOTAL_BOUND`, is not walked and the answer is `CANNOT_DECIDE`,
which every caller counts as larger.

The comparison is at the register file, the level the byte rule holds a table to. The encoding of a reading into
registers, the field order and the string intern ids of the debug view, is the substrate's and is not in the
signed image, so two byte identical tables compiled from different flows can mean different strings. That is a
property of the format the byte rule shares, and nothing here adds to it or removes it.
"""
from __future__ import annotations

import itertools
import struct
from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from prismpath.distribution.adapters import CANNOT_DECIDE, LARGER, NOT_LARGER
from prismpath.hotswap import policy_pack

NODE_BOUND = 1 << 16                      # register files walked on one node
TOTAL_BOUND = 1 << 20                     # register files walked on one table pair, all nodes
I32_MIN, I32_MAX = -(1 << 31), (1 << 31) - 1
TY_NONE, TY_BOOL, TY_INT, TY_STR = range(4)
TYPE_NAMES = ("none", "bool", "int", "str")
OP_EQ, OP_NE, OP_LT, OP_LE, OP_GT, OP_GE, OP_TRUTHY = range(7)
OPC_NOT, OPC_AND, OPC_OR, OPC_TRUE, OPC_FALSE = range(0x8000, 0x8005)

RENEWAL, FRAME, STEP, BOUND, UNREADABLE, NARROWER = "renewal", "frame", "step", "bound", "unreadable", "narrower"


@dataclass(frozen=True)
class Comparison:
    """What W8 found. `answer` is `LARGER`, `NOT_LARGER` or `CANNOT_DECIDE`. `reason` is `renewal` (the same
    bytes), `narrower` (not larger by the walk), `frame` (the two do not share a frame), `step` (a register file
    the staged table steps on more permissively), `bound` (the walk passed its bound) or `unreadable`. `witness`
    says where: for `step` the node, the register file and what each table does there, for `frame` the member
    and its two values."""
    answer: str
    reason: str
    witness: Optional[dict] = None

    def document(self) -> dict:
        return {"answer": self.answer, "reason": self.reason, "witness": self.witness}


@dataclass
class _Table:
    header: dict
    atoms: List[Tuple[int, int, int, int]]
    nodes: List[List[Tuple[int, Tuple[int, ...]]]]          # per node, its edges as (target, program words)
    attrs: Optional[Tuple[int, ...]] = None
    names: Optional[Tuple[int, ...]] = None


def _read(image: bytes) -> Optional[_Table]:
    ok, _reasons = policy_pack.validate_image(image)
    if not ok:
        return None
    header = policy_pack.read_ppt_header(image)
    offset = policy_pack.HEADER.size
    atoms = []
    for _ in range(header["atoms"]):
        atoms.append(policy_pack.ATOM.unpack_from(image, offset))
        offset += policy_pack.ATOM.size
    node_records = []
    for _ in range(header["nodes"]):
        node_records.append(policy_pack.NODE.unpack_from(image, offset))
        offset += policy_pack.NODE.size
    edges = []
    for _ in range(header["edges"]):
        edges.append(policy_pack.EDGE.unpack_from(image, offset))
        offset += policy_pack.EDGE.size
    words = struct.unpack_from(f"<{header['prog_words']}H", image, offset)
    offset += 2 * header["prog_words"]
    nodes = []
    for edge_offset, edge_count in node_records:
        if edge_offset + edge_count > len(edges):
            return None                                        # a node past the edge section is no table to compare
        nodes.append([(target, tuple(words[start:start + count]))
                      for target, start, count in edges[edge_offset:edge_offset + edge_count]])
    attrs = names = None
    if header["flags"] & policy_pack.FLAG_NODE_ATTR:
        attrs = struct.unpack_from(f"<{header['nodes']}H", image, offset)
        offset += 2 * header["nodes"]
    if header["flags"] & policy_pack.FLAG_NODE_NAMES:
        names = struct.unpack_from(f"<{header['nodes']}I", image, offset)
    return _Table(header, atoms, nodes, attrs, names)


def _atom(atom: Tuple[int, int, int, int], value: Tuple[int, int]) -> bool:
    """One atom against one register (TABLE_FORMAT.md, and `adapters.mesh._atom` step for step)."""
    _field, op, aty, aval = atom
    rty, rval = value
    lnum, rnum = rty in (TY_BOOL, TY_INT), aty in (TY_BOOL, TY_INT)
    if op in (OP_EQ, OP_NE):
        if lnum and rnum or rty == TY_STR and aty == TY_STR:
            equal = rval == aval
        else:
            equal = rty == TY_NONE and aty == TY_NONE
        return equal if op == OP_EQ else not equal
    if op in (OP_LT, OP_LE, OP_GT, OP_GE):
        if not (lnum and rnum):
            return False
        return {OP_LT: rval < aval, OP_LE: rval <= aval, OP_GT: rval > aval, OP_GE: rval >= aval}[op]
    if op == OP_TRUTHY:
        return rty != TY_NONE and rval != 0
    return False


def _program(table: _Table, words: Sequence[int], registers: Mapping[int, Tuple[int, int]]) -> bool:
    stack: List[bool] = []
    for word in words:
        if word < 0x8000:
            atom = table.atoms[word]
            stack.append(_atom(atom, registers.get(atom[0], (TY_NONE, 0))))
        elif word in (OPC_TRUE, OPC_FALSE):
            stack.append(word == OPC_TRUE)
        elif word == OPC_NOT:
            if not stack:
                raise ValueError("NOT on an empty stack")
            stack[-1] = not stack[-1]
        else:
            if len(stack) < 2:
                raise ValueError("a binary opcode on a short stack")
            right = stack.pop()
            stack[-1] = (stack[-1] and right) if word == OPC_AND else (stack[-1] or right)
    return bool(stack) and stack[0]


def _step(table: _Table, node: int, registers: Mapping[int, Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    """(edge index, target) of the first edge of `node` whose program holds, or None when none does."""
    for index, (target, words) in enumerate(table.nodes[node]):
        if _program(table, words, registers):
            return index, target
    return None


def _clip(value: int) -> Optional[int]:
    return value if I32_MIN <= value <= I32_MAX else None


def _classes(atoms: Sequence[Tuple[int, int, int, int]], interns: int) -> List[Tuple[int, int]]:
    """One register value of each class the atoms on one register cut its values into."""
    numbers = {0, 1, -1, I32_MIN, I32_MAX}
    strings = {0}
    for _field, _op, aty, aval in atoms:
        if aty in (TY_BOOL, TY_INT):
            numbers.update(one for one in (_clip(aval - 1), aval, _clip(aval + 1)) if one is not None)
        elif aty == TY_STR:
            strings.add(aval)
    fresh = max(strings | {interns}) + 1                          # an id no atom names, as an unknown runtime string
    if fresh <= I32_MAX:
        strings.add(fresh)
    values = [(TY_NONE, 0), (TY_BOOL, 0), (TY_BOOL, 1)]
    values += [(TY_INT, number) for number in sorted(numbers)]
    values += [(TY_STR, one) for one in sorted(strings)]
    return values


def _frame(old: _Table, new: _Table, old_fields, new_fields) -> Optional[dict]:
    """The first member the two tables must share and do not, as a witness, else None."""
    for member in ("fields", "interns", "nodes", "start", "visits_idx", "flags", "safe_node"):
        if old.header[member] != new.header[member]:
            return {"member": member, "active": old.header[member], "staged": new.header[member]}
    exact = old.header["stateful"] or old.attrs is not None
    if new.header["max_steps"] > old.header["max_steps"] or exact and new.header["max_steps"] != old.header["max_steps"]:
        return {"member": "max_steps", "active": old.header["max_steps"], "staged": new.header["max_steps"]}
    terminals = [index for index, edges in enumerate(old.nodes) if not edges]
    staged_terminals = [index for index, edges in enumerate(new.nodes) if not edges]
    if terminals != staged_terminals:
        return {"member": "terminals", "active": terminals, "staged": staged_terminals}
    if old.attrs != new.attrs:
        return {"member": "attrs", "active": list(old.attrs or ()), "staged": list(new.attrs or ())}
    if old.names != new.names:
        return {"member": "names", "active": list(old.names or ()), "staged": list(new.names or ())}
    if old_fields != new_fields:
        return {"member": "meta.fields", "active": old_fields, "staged": new_fields}
    return None


def _shown(step: Optional[Tuple[int, int]]) -> Optional[dict]:
    return None if step is None else {"edge": step[0], "target": step[1]}


def compare_tables(active: bytes, staged: bytes, *, active_fields: Optional[Mapping[str, str]] = None,
                   staged_fields: Optional[Mapping[str, str]] = None, node_bound: int = NODE_BOUND,
                   total_bound: int = TOTAL_BOUND) -> Comparison:
    """W8: whether the `staged` table allows more than the `active` one, with a witness when it does.
    `active_fields` and `staged_fields` are the signed field dictionaries of the two envelopes' `meta`, where
    the kind reads `meta`; tables whose dictionaries differ do not share a frame."""
    if bytes(active) == bytes(staged) and dict(active_fields or {}) == dict(staged_fields or {}):
        return Comparison(NOT_LARGER, RENEWAL)
    old, new = _read(active), _read(staged)
    if old is None or new is None:
        return Comparison(CANNOT_DECIDE, UNREADABLE)
    framed = _frame(old, new, None if active_fields is None else dict(active_fields),
                    None if staged_fields is None else dict(staged_fields))
    if framed is not None:
        return Comparison(LARGER, FRAME, framed)
    exact = old.header["stateful"] or old.attrs is not None
    walked = 0
    try:
        for node in range(len(old.nodes)):
            atoms = [old.atoms[word] for _target, words in old.nodes[node] for word in words if word < 0x8000]
            atoms += [new.atoms[word] for _target, words in new.nodes[node] for word in words if word < 0x8000]
            registers = sorted({atom[0] for atom in atoms})
            groups = [_classes([atom for atom in atoms if atom[0] == register], old.header["interns"])
                      for register in registers]
            size = 1
            for group in groups:
                size *= len(group)
            walked += size
            if size > node_bound or walked > total_bound:
                return Comparison(CANNOT_DECIDE, BOUND, {"node": node, "registers": registers, "readings": size})
            for values in itertools.product(*groups):
                reading = dict(zip(registers, values))
                before, after = _step(old, node, reading), _step(new, node, reading)
                if after == before or after is None and not exact:
                    continue
                return Comparison(LARGER, STEP, {
                    "node": node, "registers": {str(register): [TYPE_NAMES[value[0]], value[1]]
                                                for register, value in reading.items()},
                    "active": _shown(before), "staged": _shown(after)})
    except (ValueError, IndexError):
        return Comparison(CANNOT_DECIDE, UNREADABLE)
    return Comparison(NOT_LARGER, NARROWER)


def table_fields(envelope) -> Optional[Dict[str, str]]:
    """The signed field dictionary of a `policy.ppt` envelope's `meta`, None when it carries none."""
    meta = getattr(envelope, "meta", None) or {}
    fields = meta.get("fields")
    return dict(fields) if isinstance(fields, dict) else None
