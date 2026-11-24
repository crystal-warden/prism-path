# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The table comparator of W8 (spec-policy-distribution.md, section 9.4), which the sealing tool and the
controller run on a `host` or a `mesh` table and no PEP does.

The cases name the conformance case of section 20 they cover. The property tests hold the comparator to the
mesh evaluator of `prismpath.distribution.adapters.mesh`, which is written apart from it: over seeded random
table pairs, no pair the comparator calls not larger has a register file on which the staged table steps or runs
more permissively than the active one, and every witness it gives reproduces. A seeded sample runs on every
push, and the checkpoint run takes many more pairs."""
import random
import struct

import pytest

from prismpath.distribution import table_compare, widening
from prismpath.distribution.adapters import CANNOT_DECIDE, LARGER, NOT_LARGER
from prismpath.distribution.adapters import mesh as mesh_eval
from prismpath.kernel import ppt_compile
from prismpath.kernel.ppt_compile import (OP_EQ, OP_GE, OP_GT, OP_LE, OP_LT, OP_NE, OP_TRUTHY, OPC_AND, OPC_FALSE,
                                          OPC_NOT, OPC_OR, OPC_TRUE, TY_BOOL, TY_INT, TY_NONE, TY_STR)
from prismpath.tests import _dist

I32_MIN, I32_MAX = -(1 << 31), (1 << 31) - 1


def _predicate(cond: str, max_steps: int = 1) -> bytes:
    image = ppt_compile.compile_predicate(cond)
    image.max_steps = max_steps
    return image.serialize()


def _table(nodes, *, fields=("a", "b"), interns=("s1", "s2", "s3"), max_steps=4, stateful=False, colors=None,
           start=0) -> bytes:
    """A table from `nodes`, each a list of (target, program) where a program is a list of atoms as
    (field, op, type, value) and opcodes. The field and intern dictionaries are fixed, so two tables built here
    share a frame unless a test changes one."""
    image = ppt_compile.TableImage(max_steps)
    image.fields = {name: index for index, name in enumerate(fields)}
    image.intern = {"": 0, **{name: index + 1 for index, name in enumerate(interns)}}
    built = []
    for index, edges in enumerate(nodes):
        compiled = []
        for target, program in edges:
            words = [word if isinstance(word, int) else image.atom(*word) for word in program]
            compiled.append((target, "", words))
        built.append((f"n{index}", compiled))
    image.nodes = built
    image.start = start
    if stateful:
        image.stateful, image.safe_node = True, len(nodes) - 1
    if colors:
        image.node_colors = list(colors)
    return image.serialize()


def _compare(active, staged, **args):
    return table_compare.compare_tables(active, staged, **args)


# ------------------------------------------------------------------ the cases

def test_case_289_the_table_comparator_finds_a_reading_that_moves_and_only_then():
    """case_289: W8. A mesh table that raises its threshold and one that drops an edge are not larger, one that
    lowers its threshold is larger with a witness reading the active table refuses, one that moves an edge to
    another node is larger, one with a higher `max_steps` is larger by its frame, a stateful table that drops an
    edge is larger, and a table whose walk passes the bound cannot be decided, which every caller counts as larger."""
    old, raised, lowered = _dist.image(5), _dist.image(7), _dist.image(3)
    assert _compare(old, old).document() == {"answer": NOT_LARGER, "reason": "renewal", "witness": None}
    assert _compare(old, raised).answer == NOT_LARGER

    found = _compare(old, lowered)
    assert (found.answer, found.reason) == (LARGER, "step")
    reading = found.witness["registers"]["0"]
    assert reading[0] in ("int", "bool") and 3 <= reading[1] < 5
    assert found.witness["active"] is None and found.witness["staged"] == {"edge": 0, "target": 1}
    regs = struct.pack("<I", 0) + struct.pack("<ii", {"int": TY_INT, "bool": TY_BOOL}[reading[0]], reading[1])
    assert mesh_eval.evaluate(old, regs, 0) is None and mesh_eval.evaluate(lowered, regs, 0) == (0, 1)

    a_eq_1 = (0, OP_EQ, TY_INT, 1)
    b_eq_s1 = (1, OP_EQ, TY_STR, 1)
    two = _table([[(1, [a_eq_1]), (2, [b_eq_s1])], [], []])
    one = _table([[(1, [a_eq_1]), (2, [OPC_FALSE])], [], []])
    assert _compare(two, one).answer == NOT_LARGER                       # the second edge takes no reading now
    assert _compare(one, two).answer == LARGER
    moved = _table([[(2, [a_eq_1]), (2, [b_eq_s1])], [], []])
    assert (_compare(two, moved).answer, _compare(two, moved).reason) == (LARGER, "step")

    longer = _table([[(1, [a_eq_1])], [(0, [OPC_TRUE])], []], max_steps=6)
    shorter = _table([[(1, [a_eq_1])], [(0, [OPC_TRUE])], []], max_steps=3)
    assert _compare(shorter, longer).witness == {"member": "max_steps", "active": 3, "staged": 6}
    assert _compare(longer, shorter).answer == NOT_LARGER

    resident = _table([[(1, [a_eq_1]), (2, [b_eq_s1])], [(2, [OPC_TRUE])], []], stateful=True)
    dropped = _table([[(1, [a_eq_1]), (2, [OPC_FALSE])], [(2, [OPC_TRUE])], []], stateful=True)
    assert (_compare(resident, dropped).answer, _compare(resident, dropped).reason) == (LARGER, "step")

    wide = [(field, OP_GE, TY_INT, value) for field in range(6) for value in range(6)]
    program = [wide[0]] + [word for atom in wide[1:] for word in (atom, OPC_AND)]
    many = _table([[(1, program)], []], fields=tuple("abcdef"))
    fewer = _table([[(1, program + [(0, OP_EQ, TY_INT, 9), OPC_AND])], []], fields=tuple("abcdef"))
    found = _compare(many, fewer)
    assert (found.answer, found.reason) == (CANNOT_DECIDE, "bound") and found.witness["readings"] > 1 << 16


def test_the_frame_holds_the_header_the_terminals_the_sections_and_the_field_dictionary():
    """case_289: W8, the frame half. Two tables that do not share a frame are larger, with the member as the
    witness, and a field dictionary in `meta` that differs is one."""
    base = _table([[(1, [(0, OP_EQ, TY_INT, 1)])], [], []])
    cases = {
        "fields": _table([[(1, [(0, OP_EQ, TY_INT, 1)])], [], []], fields=("a", "b", "c")),
        "interns": _table([[(1, [(0, OP_EQ, TY_INT, 1)])], [], []], interns=("s1",)),
        "nodes": _table([[(1, [(0, OP_EQ, TY_INT, 1)])], [], [], []]),
        "start": _table([[(1, [(0, OP_EQ, TY_INT, 1)])], [], []], start=1),
        "terminals": _table([[(1, [(0, OP_EQ, TY_INT, 1)])], [(2, [OPC_FALSE])], []]),
        "flags": _table([[(1, [(0, OP_EQ, TY_INT, 1)])], [], []], colors=[1, 2, 3]),
    }
    for member, staged in cases.items():
        found = _compare(base, staged)
        assert (found.answer, found.reason, found.witness["member"]) == (LARGER, "frame", member), member
    coloured = _table([[(1, [(0, OP_EQ, TY_INT, 1)])], [], []], colors=[1, 2, 3])
    recoloured = _table([[(1, [(0, OP_EQ, TY_INT, 1)])], [], []], colors=[1, 3, 3])
    assert _compare(coloured, recoloured).witness["member"] == "attrs"
    narrowed = _table([[(1, [(0, OP_EQ, TY_INT, 1), (1, OP_TRUTHY, TY_NONE, 0), OPC_AND])], [], []], colors=[1, 2, 3])
    assert _compare(coloured, narrowed).reason == "step"                  # a node that decides by its colour: exact
    fields = {"a": "int 0..9", "b": "category"}
    assert _compare(base, base, active_fields=fields, staged_fields=dict(fields, a="int 0..99")).witness["member"] \
        == "meta.fields"
    assert _compare(base, base, active_fields=fields, staged_fields=None).answer == LARGER
    assert _compare(base, b"PPTM").reason == "unreadable"


def test_the_classes_cover_strings_the_atoms_never_name_and_the_ends_of_i32():
    """A string no atom names reads as a fresh id, and the ends of i32 are walked."""
    names_s1 = _table([[(1, [(0, OP_NE, TY_STR, 1)])], []])
    names_s2 = _table([[(1, [(0, OP_NE, TY_STR, 1), (0, OP_NE, TY_STR, 2), OPC_AND])], []])
    assert _compare(names_s1, names_s2).answer == NOT_LARGER
    found = _compare(names_s2, names_s1)
    assert found.witness["registers"]["0"] == ["str", 2]
    top = _table([[(1, [(0, OP_GE, TY_INT, I32_MAX)])], []])
    never = _table([[(1, [OPC_FALSE])], []])
    assert _compare(never, top).witness["registers"]["0"][1] == I32_MAX


def test_the_byte_rule_is_unchanged_where_a_pep_compares():
    """W2 stays what a PEP computes: `compare_artifact` of a `policy.ppt` is still the byte rule, so a narrower
    table is larger there and not larger by W8."""
    old, raised = _dist.image(5), _dist.image(7)
    assert widening.compare_artifact("policy.ppt", old, raised) == LARGER
    assert _compare(old, raised).answer == NOT_LARGER


# ------------------------------------------------------------------ the property: never a widening called not larger

# Every class the random atoms below can cut a register into has a value here: their constants stay within -3 to
# 5 and their string ids within -1 to 4, so the integers -5 to 7 and the ids -2 to 6 hold a neighbour of each.
_DOMAIN = ([(TY_NONE, 0), (TY_NONE, 7), (TY_BOOL, 0), (TY_BOOL, 1)] + [(TY_INT, value) for value in range(-5, 8)]
           + [(TY_INT, I32_MIN), (TY_INT, I32_MAX)] + [(TY_STR, value) for value in range(-2, 7)])
_READINGS = [(first, second) for first in _DOMAIN for second in _DOMAIN]
_REGS = [struct.pack("<I", 0) + struct.pack("<ii", *first) + struct.pack("<ii", *second) for first, second in _READINGS]


def _atom(rng):
    kind = rng.choice((TY_NONE, TY_BOOL, TY_INT, TY_INT, TY_STR))
    value = {TY_NONE: 0, TY_BOOL: rng.randint(0, 1), TY_INT: rng.randint(-2, 4), TY_STR: rng.randint(0, 3)}[kind]
    return (rng.randint(0, 1), rng.choice((OP_EQ, OP_NE, OP_LT, OP_LE, OP_GT, OP_GE, OP_TRUTHY)), kind, value)


def _program(rng, depth=0):
    roll = rng.random()
    if depth >= 2 or roll < 0.45:
        return [_atom(rng)]
    if roll < 0.55:
        return _program(rng, depth + 1) + [OPC_NOT]
    if roll < 0.6:
        return [rng.choice((OPC_TRUE, OPC_FALSE))]
    return _program(rng, depth + 1) + _program(rng, depth + 1) + [rng.choice((OPC_AND, OPC_OR))]


def _shape(rng):
    """Three nodes: two that route and a terminal one, so random pairs keep a frame."""
    return [[(rng.choice((1, 2)) if node == 0 else rng.choice((0, 2)), _program(rng))
             for _ in range(rng.randint(1, 3))] for node in range(2)] + [[]]


def _mutate(rng, shape):
    shape = [[(target, list(program)) for target, program in edges] for edges in shape]
    node = rng.randint(0, 1)
    edges = shape[node]
    index = rng.randrange(len(edges))
    target, program = edges[index]
    choice = rng.randrange(9)
    if choice == 0:
        edges[index] = (target, program + _program(rng) + [OPC_AND])             # narrower
    elif choice == 1:
        edges[index] = (target, program + _program(rng) + [OPC_OR])              # wider
    elif choice == 2 and len(edges) > 1:
        del edges[index]
    elif choice == 3:
        edges[index] = (target, [OPC_FALSE])
    elif choice == 4 and len(edges) > 1:
        other = rng.randrange(len(edges))
        edges[index], edges[other] = edges[other], edges[index]
    elif choice == 5:
        edges[index] = ((target + 1) % 3 if node == 0 else rng.choice((0, 2)), program)
    elif choice == 6:
        atoms = [position for position, word in enumerate(program) if isinstance(word, tuple)]
        position = rng.choice(atoms) if atoms else None
        if position is not None:
            field, op, kind, value = program[position]
            program[position] = (field, op, kind, value + rng.choice((-1, 1)) if kind != TY_NONE else value)
    elif choice == 7:
        edges[index] = (target, program + [OPC_NOT])
    else:
        return _shape(rng)
    return shape


def _steps(image):
    """Per node with edges, the mesh evaluator's step on every register file of the domain."""
    return {node: [mesh_eval.evaluate(image, regs, node) for regs in _REGS] for node in (0, 1)}


def _run(steps, reading, max_steps):
    """The stateless run loop of TABLE_FORMAT.md from node 0: terminal, stuck or max_steps, and the end node."""
    node = 0
    for _ in range(max_steps):
        if node == 2:
            return "terminal", node
        step = steps[node][reading]
        if step is None:
            return "stuck", node
        node = step[1]
    return ("terminal", node) if node == 2 else ("max_steps", node)


def _check_pairs(seed: int, pairs: int):
    rng = random.Random(seed)
    tallies = {NOT_LARGER: 0, LARGER: 0, CANNOT_DECIDE: 0, "real": 0}
    for _ in range(pairs):
        stateful = rng.random() < 0.2
        old_shape = _shape(rng)
        new_shape = _mutate(rng, old_shape)
        try:
            old = _table(old_shape, stateful=stateful)
            new = _table(new_shape, stateful=stateful)
        except ValueError:
            continue                                                   # a program the compiler would never emit
        found = _compare(old, new)
        tallies[found.answer] += 1
        before, after = _steps(old), _steps(new)
        moved = [(node, reading) for node in (0, 1) for reading in range(len(_REGS))
                 if after[node][reading] != before[node][reading]
                 and (stateful or after[node][reading] is not None)]
        runs_wider = [reading for reading in range(len(_REGS))
                      if _run(after, reading, 4)[0] == "terminal" and _run(after, reading, 4) != _run(before, reading, 4)]
        real = bool(moved) or bool(runs_wider)
        tallies["real"] += real
        if found.answer == NOT_LARGER:
            assert not real, (seed, old_shape, new_shape, moved[:3], runs_wider[:3])
        if real:
            assert found.answer == LARGER and found.reason == "step", (old_shape, new_shape, found)
        if found.reason == "step":                                     # every witness reproduces
            node, witness = found.witness["node"], found.witness["registers"]
            values = [(TY_NONE, 0), (TY_NONE, 0)]
            for register, (kind, value) in witness.items():
                values[int(register)] = (table_compare.TYPE_NAMES.index(kind), value)
            regs = struct.pack("<I", 0) + b"".join(struct.pack("<ii", *value) for value in values)
            shown = (lambda step: None if step is None else {"edge": step[0], "target": step[1]})
            assert shown(mesh_eval.evaluate(old, regs, node)) == found.witness["active"]
            assert shown(mesh_eval.evaluate(new, regs, node)) == found.witness["staged"]
            assert found.witness["staged"] != found.witness["active"]
            assert real, (old_shape, new_shape, found)                 # the domain holds every class here
    return tallies


def test_the_comparator_never_calls_a_widening_not_larger_on_a_seeded_sample():
    tallies = _check_pairs(seed=7, pairs=400)
    assert tallies[NOT_LARGER] >= 80 and tallies[LARGER] >= 80 and tallies[CANNOT_DECIDE] == 0, tallies


@pytest.mark.checkpoint
def test_the_comparator_never_calls_a_widening_not_larger_on_many_pairs():
    tallies = {}
    for seed in range(20):
        for answer, count in _check_pairs(seed=1000 + seed, pairs=1000).items():
            tallies[answer] = tallies.get(answer, 0) + count
    assert tallies[NOT_LARGER] >= 4000 and tallies[LARGER] >= 4000, tallies
