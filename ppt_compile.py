#!/usr/bin/env python3
"""ppt_compile.py — compile PrismPath Level M conditions/flows to PPT v1 table images.

`compile --target table`, off-repo edition: uses the repo's own classifier
(prismpath.model_check.is_level_m) as the fragment authority, so this compiler can never
disagree with `prismpath verify --level-m` about what is compilable. See TABLE_FORMAT.md.

CLI:  python3 ppt_compile.py <flow.md> [-o image.bin] [--json debug.json] [--max-steps N]
"""
from __future__ import annotations

import ast
import json
import os
import struct
import sys
from pathlib import Path

_REPO = os.environ.get("PRISMPATH_REPO",
                       str(Path(__file__).resolve().parent.parent / "prismpath"))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from prismpath import predicates                     # noqa: E402
from prismpath.analysis import _reachable            # noqa: E402
from prismpath.model_check import _classify          # noqa: E402

TY_NONE, TY_BOOL, TY_INT, TY_STR = 0, 1, 2, 3
OP_EQ, OP_NE, OP_LT, OP_LE, OP_GT, OP_GE, OP_TRUTHY = range(7)
OPC_NOT, OPC_AND, OPC_OR, OPC_TRUE, OPC_FALSE = 0x8000, 0x8001, 0x8002, 0x8003, 0x8004
I32_MIN, I32_MAX = -(2 ** 31), 2 ** 31 - 1
MAGIC = 0x4D545050          # "PPTM"
VISITS_NONE = 0xFFFF

_OP_NAME = {OP_EQ: "==", OP_NE: "!=", OP_LT: "<", OP_LE: "<=", OP_GT: ">", OP_GE: ">=",
            OP_TRUTHY: "truthy"}
_TY_NAME = {TY_NONE: "none", TY_BOOL: "bool", TY_INT: "int", TY_STR: "str"}
_AST_OP = {ast.Eq: OP_EQ, ast.NotEq: OP_NE, ast.Lt: OP_LT, ast.LtE: OP_LE,
           ast.Gt: OP_GT, ast.GtE: OP_GE}
_FLIP = {OP_LT: OP_GT, OP_LE: OP_GE, OP_GT: OP_LT, OP_GE: OP_LE, OP_EQ: OP_EQ, OP_NE: OP_NE}


class SubsetError(ValueError):
    """The condition/flow/value is outside the declared v0 subset. `reason` is a stable code
    the harness aggregates in its exclusion report."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        super().__init__(f"{reason}{': ' + detail if detail else ''}")


def encode_scalar(v, intern: dict) -> tuple:
    """A Python scalar -> (type, i32). Mutates `intern` (str -> id; '' is id 0)."""
    if v is None:
        return TY_NONE, 0
    if isinstance(v, bool):
        return TY_BOOL, int(v)
    if isinstance(v, int):
        if not I32_MIN <= v <= I32_MAX:
            raise SubsetError("int-out-of-i32", repr(v))
        return TY_INT, v
    if isinstance(v, float):
        raise SubsetError("float-value", repr(v))
    if isinstance(v, str):
        if v not in intern:
            intern[v] = len(intern)
        return TY_STR, intern[v]
    raise SubsetError("non-scalar-value", type(v).__name__)


def _desugar_chains(node):
    """`a < b < c` -> `a < b and b < c`, recursively. Exact under the engine's semantics:
    operands are pure (names/constants, evaluated identically each time), every pairwise
    comparison is total, and BoolOp evaluates all operands — so the desugared form cannot
    diverge from Python's chain evaluation on any context."""
    if isinstance(node, ast.BoolOp):
        return ast.BoolOp(op=node.op, values=[_desugar_chains(v) for v in node.values])
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return ast.UnaryOp(op=node.op, operand=_desugar_chains(node.operand))
    if isinstance(node, ast.Compare) and len(node.ops) > 1:
        operands = [node.left] + list(node.comparators)
        return ast.BoolOp(op=ast.And(), values=[
            ast.Compare(left=operands[i], ops=[node.ops[i]], comparators=[operands[i + 1]])
            for i in range(len(node.ops))])
    return node


class TableImage:
    def __init__(self, max_steps: int = 25):
        self.max_steps = max_steps
        self.fields: dict = {}                 # name -> register index
        self.intern: dict = {"": 0}            # string -> id
        self.atoms: list = []                  # (field_idx, op, ty, val)
        self._atom_ix: dict = {}
        self.nodes: list = []                  # (name, [(target_idx, condition, program)])
        self.start = 0
        self.skipped_tiers: list = []          # host-side (error/event) edges, debug view only

    # ---------------------------------------------------------------- construction
    def field(self, name: str) -> int:
        return self.fields.setdefault(name, len(self.fields))

    def atom(self, fidx: int, op: int, ty: int, val: int) -> int:
        key = (fidx, op, ty, val)
        if key not in self._atom_ix:
            self._atom_ix[key] = len(self.atoms)
            self.atoms.append(key)
        return self._atom_ix[key]

    def _prog_expr(self, node) -> list:
        if isinstance(node, ast.Name):
            return [self.atom(self.field(node.id), OP_TRUTHY, TY_NONE, 0)]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return self._prog_expr(node.operand) + [OPC_NOT]
        if isinstance(node, ast.BoolOp):
            opc = OPC_AND if isinstance(node.op, ast.And) else OPC_OR
            prog: list = []
            for i, v in enumerate(node.values):
                prog += self._prog_expr(v)
                if i:
                    prog.append(opc)
            return prog
        if isinstance(node, ast.Compare):
            left, op, right = node.left, node.ops[0], node.comparators[0]
            if isinstance(op, (ast.In, ast.NotIn)):
                fidx = self.field(left.id)
                if not right.elts:
                    prog = [OPC_FALSE]
                else:
                    prog = []
                    for i, e in enumerate(right.elts):
                        ty, val = encode_scalar(e.value, self.intern)
                        prog.append(self.atom(fidx, OP_EQ, ty, val))
                        if i:
                            prog.append(OPC_OR)
                if isinstance(op, ast.NotIn):
                    prog.append(OPC_NOT)
                return prog
            opc = _AST_OP.get(type(op))
            if opc is None:
                # the repo classifier accepts `is`/`is not` (soundness gap, flagged upstream);
                # the evaluator rejects them, so they are outside the fragment here too
                raise SubsetError(f"not-level-m:disallowed-op-{type(op).__name__}")
            if isinstance(left, ast.Name):
                fidx = self.field(left.id)
                ty, val = encode_scalar(right.value, self.intern)
            else:                               # constant OP field -> flip orientation
                fidx = self.field(right.id)
                ty, val = encode_scalar(left.value, self.intern)
                opc = _FLIP[opc]
            return [self.atom(fidx, opc, ty, val)]
        raise SubsetError("not-level-m", type(node).__name__)   # unreachable post-classifier

    def compile_condition(self, cond: str) -> list:
        if not predicates.is_deterministic(cond):
            raise SubsetError("non-deterministic-edge", cond)
        expr = predicates._expr_of(cond)
        if expr.lower() in predicates.ALWAYS:
            return [OPC_TRUE]
        if expr.lower() in predicates.NEVER:
            return [OPC_FALSE]
        # the evaluator's own static gate first (rejects `is`, calls, unparseable — everything
        # the corpus records as "ERROR"), so check/eval/compile accept the same language
        if predicates.check_predicate(cond):
            raise SubsetError("not-level-m:disallowed-or-unparseable")
        tree = _desugar_chains(ast.parse(expr, mode="eval").body)
        # fragment membership judged by the repo classifier — applied AFTER the mechanical
        # chain desugar the SPEC says tooling SHOULD perform (§4.3)
        reason = _classify(tree)
        if reason is not None:
            raise SubsetError(f"not-level-m:{reason}")
        return self._prog_expr(tree)

    # ---------------------------------------------------------------- serialization
    @staticmethod
    def _stack_depth(prog: list) -> int:
        depth = peak = 0
        for w in prog:
            if w < 0x8000 or w in (OPC_TRUE, OPC_FALSE):
                depth += 1
            elif w in (OPC_AND, OPC_OR):
                depth -= 1
            peak = max(peak, depth)
        assert depth == 1, f"malformed program (final depth {depth})"
        return peak

    def serialize(self) -> bytes:
        prog_blob: list = []
        edges: list = []                        # (target, off, cnt)
        node_recs: list = []                    # (edge_off, edge_cnt)
        max_stack = 1
        for _name, nedges in self.nodes:
            node_recs.append((len(edges), len(nedges)))
            for target, _cond, prog in nedges:
                edges.append((target, len(prog_blob), len(prog)))
                prog_blob.extend(prog)
                max_stack = max(max_stack, self._stack_depth(prog))
        visits_idx = self.fields.get("visits", VISITS_NONE)
        out = struct.pack("<IHHHHHHHHHHHH", MAGIC, 1,
                          len(self.fields), len(self.intern), len(self.atoms),
                          len(self.nodes), len(edges), len(prog_blob),
                          self.start, visits_idx, self.max_steps, max_stack, 0)
        for fidx, op, ty, val in self.atoms:
            out += struct.pack("<HBBi", fidx, op, ty, val)
        for eo, ec in node_recs:
            out += struct.pack("<HH", eo, ec)
        for t, po, pc in edges:
            out += struct.pack("<HHH", t, po, pc)
        for w in prog_blob:
            out += struct.pack("<H", w)
        return out

    def debug(self) -> dict:
        def dis(prog):
            names = {OPC_NOT: "NOT", OPC_AND: "AND", OPC_OR: "OR",
                     OPC_TRUE: "TRUE", OPC_FALSE: "FALSE"}
            return [f"ATOM {w}" if w < 0x8000 else names[w] for w in prog]
        inv_f = {v: k for k, v in self.fields.items()}
        return {
            "format": "PPT", "version": 1, "max_steps": self.max_steps,
            "fields": self.fields,
            "intern": self.intern,
            "atoms": [{"i": i, "field": inv_f[f], "op": _OP_NAME[op],
                       "type": _TY_NAME[ty], "val": val}
                      for i, (f, op, ty, val) in enumerate(self.atoms)],
            "start": self.start,
            "nodes": [{"i": i, "name": name,
                       "edges": [{"target": t, "condition": c, "program": dis(p)}
                                 for t, c, p in nedges]}
                      for i, (name, nedges) in enumerate(self.nodes)],
            "host_side_edges": [{"node": n, "target": t, "condition": c}
                                for n, t, c in self.skipped_tiers],
        }


# -------------------------------------------------------------------- entry points

def compile_flow(graph, max_steps: int = 25) -> TableImage:
    """A parsed prismpath Graph -> image of its REACHABLE deterministic tier (SPEC §7 computes
    portability over reachable edges; the engine cannot visit an unreachable node, so dropping
    them is exact). Every reachable deterministic edge must be Level M; error/event edges are
    skipped (the host's tiers — the fabric is never consulted for them); a reachable semantic
    edge is outside v0 entirely (the engine would release the semantic tier where the table
    says stuck)."""
    img = TableImage(max_steps)
    reach = _reachable(graph)
    names = [n for n in graph.nodes if n in reach]      # document order, reachable only
    idx = {n: i for i, n in enumerate(names)}
    if graph.start not in idx:
        raise SubsetError("bad-start", graph.start)
    skipped = []
    for name in names:
        nedges = []
        for target, cond in graph.nodes[name].edges:
            if predicates.is_error(cond) or predicates.is_event(cond):
                skipped.append((name, target, cond))
                continue
            if predicates.is_semantic(cond):
                raise SubsetError("semantic-edge", cond)
            if target not in idx:
                raise SubsetError("dangling-target", target)
            nedges.append((idx[target], cond, img.compile_condition(cond)))
        img.nodes.append((name, nedges))
    img.start = idx[graph.start]
    img.skipped_tiers = skipped
    return img


def compile_predicate(cond: str) -> TableImage:
    """One condition -> a 2-node image: node 0 has the single conditional edge to terminal
    node 1. evaluate(node 0) matching edge 0 = true; no match = false."""
    img = TableImage(max_steps=1)
    prog = img.compile_condition(cond)
    img.nodes = [("p", [(1, cond, prog)]), ("t", [])]
    img.start = 0
    return img


def encode_regs(img: TableImage, ctx: dict, node_idx: int = 0) -> bytes:
    """A predicate-vector ctx -> regs.bin. Only fields the image reads are encoded; runtime
    strings extend a copy of the compile-time intern map (fresh ids compare unequal to every
    authored constant, truthy iff non-empty — exactly the runtime contract)."""
    intern = dict(img.intern)
    out = struct.pack("<I", node_idx)
    by_idx = sorted(img.fields.items(), key=lambda kv: kv[1])
    for _name, _i in by_idx:
        ty, val = encode_scalar(ctx.get(_name), intern)
        out += struct.pack("<ii", ty, val)
    return out


def encode_script(img: TableImage, script: dict) -> bytes:
    """flows.json script -> script.bin (see TABLE_FORMAT.md). Mirrors engine._normalize and
    the scripted-agent protocol: unscripted node -> {'text': node_name}; bare value -> its
    str(); only fields the image reads are encoded; suspending/raising outcomes are outside
    the subset."""
    intern = dict(img.intern)
    by_idx = sorted(img.fields.items(), key=lambda kv: kv[1])
    out = struct.pack("<I", len(img.nodes))
    for name, _edges in img.nodes:
        seq = script.get(name)
        if seq is None:
            seq = [{"text": name}]
        out += struct.pack("<I", len(seq))
        for outcome in seq:
            if isinstance(outcome, dict):
                if "__raise__" in outcome:
                    raise SubsetError("script-raises")
                fields = outcome
            else:
                fields = {"text": str(outcome)}
            if fields.get("needs_human") or fields.get("wait") or \
                    fields.get("spawn") is not None:
                raise SubsetError("script-suspends")
            for _name, _i in by_idx:
                ty, val = encode_scalar(fields.get(_name), intern)
                out += struct.pack("<ii", ty, val)
    return out


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("flow_md")
    ap.add_argument("-o", "--out", default=None)
    ap.add_argument("--json", dest="json_out", default=None)
    ap.add_argument("--max-steps", type=int, default=25)
    args = ap.parse_args()

    from prismpath.parser import parse_file
    graph = parse_file(args.flow_md)
    try:
        img = compile_flow(graph, args.max_steps)
    except SubsetError as e:
        print(f"NOT TABLE-COMPILABLE: {e}")
        return 1
    blob = img.serialize()
    out = args.out or (Path(args.flow_md).stem + ".ppt")
    Path(out).write_bytes(blob)
    dbg = img.debug()
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(dbg, indent=1) + "\n")
    print(f"{out}: {len(blob)}B  fields={len(img.fields)} interns={len(img.intern)} "
          f"atoms={len(img.atoms)} nodes={len(img.nodes)} "
          f"edges={sum(len(e) for _, e in img.nodes)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
