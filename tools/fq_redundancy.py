# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""How much finer is Figueroa quantization than it needs to be? (docs/research/paper-facet-figueroa-quantization.md 2.3)

    python tools/fq_redundancy.py [out.json]      # from the repository root


For each shipped flow, compare three partitions of the reading space, each sufficient for the decision
(the route chosen at every decision node):

  FQ           the product of FQ's per-field cells (what the quantizer ships);
  product*     the coarsest sufficient partition that is still a product of per-field partitions;
  decision     the decision classes themselves (the minimal sufficient statistic, not a product).

Method: a reduced ordered multi-valued decision diagram over FQ's cells, one level per field, built by
partial evaluation with the engine's own comparison semantics. Reduced diagrams are canonical, so two
cells of a field are interchangeable in every context exactly when their cofactors are the same node.
product* keeps one block per distinct cofactor; "redundant cuts" counts adjacent numeric cells whose
cofactors are equal, i.e. cut points that never change any decision. Every diagram is checked against
the real engine (wire.route_node) on random readings and on every FQ cell when the grid is small.
"""
import ast
import glob
import json
import math
import random
import sys

sys.setrecursionlimit(100000)
from prismpath.kernel import core_render, predicates
from prismpath.kernel.parser import parse
from prismpath.telemetry import quantizer, wire

UNK = object()


def pev(node, ctx):
    """Partial evaluation: (True, value) when known under the assigned fields, else (False, simplified AST)."""
    if isinstance(node, ast.Constant):
        return True, node.value
    if isinstance(node, ast.Name):
        if node.id in ctx:
            return True, ctx[node.id]
        return False, node
    if isinstance(node, (ast.List, ast.Tuple)):
        vals = [pev(e, ctx) for e in node.elts]
        if all(k for k, _ in vals):
            return True, [v for _, v in vals]
        return False, node
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        k, v = pev(node.operand, ctx)
        return (True, not v) if k else (False, ast.UnaryOp(op=ast.Not(), operand=v))
    if isinstance(node, ast.BoolOp):
        is_and = isinstance(node.op, ast.And)
        rest = []
        for operand in node.values:
            k, v = pev(operand, ctx)
            if k:
                if is_and and not v:
                    return True, False
                if not is_and and v:
                    return True, True
            else:
                rest.append(v)
        if not rest:
            return True, is_and           # every operand known: all() of truthy / any() of falsy
        if len(rest) == 1:
            return False, ast.UnaryOp(op=ast.Not(), operand=ast.UnaryOp(op=ast.Not(), operand=rest[0]))
        return False, ast.BoolOp(op=node.op, values=rest)
    if isinstance(node, ast.Compare):
        operands = [pev(node.left, ctx)] + [pev(c, ctx) for c in node.comparators]
        for i, op in enumerate(node.ops):
            (kl, vl), (kr, vr) = operands[i], operands[i + 1]
            if kl and kr and not predicates._compare(op, vl, vr):
                return True, False
        if all(k for k, _ in operands):
            return True, True
        sub = [ast.Constant(v) if k and not isinstance(v, list) else
               (ast.List(elts=[ast.Constant(x) for x in v], ctx=ast.Load()) if k else v) for k, v in operands]
        return False, ast.Compare(left=sub[0], ops=node.ops, comparators=sub[1:])
    raise ValueError(f"unsupported {type(node).__name__}")


def rules_of(graph):
    """Per decision node: its deterministic edges in order, as (target, ast or True/False)."""
    out = []
    for name in wire.decision_nodes(graph):
        rules = []
        for target, cond in graph.nodes[name].edges:
            if not predicates.is_deterministic(cond):
                continue
            expr = predicates._expr_of(cond)
            if expr.lower() in predicates.ALWAYS:
                rules.append((target, True))
            elif expr.lower() in predicates.NEVER:
                rules.append((target, False))
            else:
                tree = ast.parse(expr, mode="eval")
                predicates.fold_unary_signs(tree)
                rules.append((target, tree.body))
        out.append((name, rules))
    return out


def residual(node_rules, ctx):
    """The decision still open under ctx: per node, the rules not yet decided, ending at a known match."""
    res = []
    for _name, rules in node_rules:
        keep = []
        for target, cond in rules:
            if cond is True or cond is False:
                k, v = True, cond
            else:
                k, v = pev(cond, ctx)
            if k:
                if bool(v):
                    keep.append((target, None))
                    break
                continue
            keep.append((target, ast.dump(v)))
        res.append(tuple(keep))
    return tuple(res)


def is_terminal(res):
    return all(not rules or rules[0][1] is None for rules in res)


def terminal_value(res):
    return tuple(rules[0][0] if rules else None for rules in res)


class MDD:
    def __init__(self):
        self.unique = {}
        self.nodes = []        # id -> ("T", value) | ("N", level, children)
        self.restrict_memo = {}

    def term(self, value):
        return self._mk(("T", value))

    def mk(self, level, children):
        children = tuple(children)
        if all(c == children[0] for c in children):
            return children[0]
        return self._mk(("N", level, children))

    def _mk(self, key):
        if key not in self.unique:
            self.unique[key] = len(self.nodes)
            self.nodes.append(key)
        return self.unique[key]

    def restrict(self, node, level, sym):
        key = (node, level, sym)
        if key in self.restrict_memo:
            return self.restrict_memo[key]
        n = self.nodes[node]
        if n[0] == "T" or n[1] > level:
            out = node
        elif n[1] == level:
            out = n[2][sym]
        else:
            out = self.mk(n[1], [self.restrict(c, level, sym) for c in n[2]])
        self.restrict_memo[key] = out
        return out

    def terminals(self, node, seen=None):
        seen = set() if seen is None else seen
        acc = set()
        stack = [node]
        while stack:
            x = stack.pop()
            if x in seen:
                continue
            seen.add(x)
            n = self.nodes[x]
            if n[0] == "T":
                acc.add(n[1])
            else:
                stack.extend(n[2])
        return acc


def build(node_rules, order, parts):
    mdd = MDD()
    memo = {}

    def go(level, ctx):
        res = residual(node_rules, ctx)
        if is_terminal(res):
            return mdd.term(terminal_value(res))
        key = (level, res)
        if key in memo:
            return memo[key]
        field = order[level]
        part = parts[field]
        kids = []
        for sym in range(part.n):
            ctx2 = dict(ctx)
            ctx2[field] = part.representative(sym)
            kids.append(go(level + 1, ctx2))
        out = mdd.mk(level, kids)
        memo[key] = out
        return out

    return mdd, go(0, {})


def evaluate(mdd, root, symbols_by_level):
    x = root
    while mdd.nodes[x][0] == "N":
        x = mdd.nodes[x][2][symbols_by_level[mdd.nodes[x][1]]]
    return mdd.nodes[x][1]


def measure(name, graph, rng):
    parts = quantizer.build_partitions(graph)
    node_rules = rules_of(graph)
    if not node_rules or not parts:
        return None
    order = wire._order(parts)
    mdd, root = build(node_rules, order, parts)
    # check against the engine
    grid = math.prod(parts[f].n for f in order)
    def engine(syms):
        reading = {f: parts[f].representative(s) for f, s in zip(order, syms)}
        return tuple(wire.route_node(graph, n, reading) for n, _ in node_rules)
    checks = 0
    if grid <= 20000:
        import itertools
        for syms in itertools.product(*[range(parts[f].n) for f in order]):
            assert evaluate(mdd, root, syms) == engine(syms), (name, syms)
            checks += 1
    for _ in range(3000):
        syms = [rng.randrange(parts[f].n) for f in order]
        assert evaluate(mdd, root, syms) == engine(syms), (name, syms)
        checks += 1
    fields = []
    for level, f in enumerate(order):
        part = parts[f]
        cof = [mdd.restrict(root, level, s) for s in range(part.n)]
        classes = len(set(cof))
        adjacent_dupes = sum(1 for a, b in zip(cof, cof[1:]) if a == b) if part.kind == "numeric" else 0
        fields.append({"field": f, "kind": part.kind, "fq": part.n, "product_star": classes,
                       "redundant_cuts": adjacent_dupes, "unused": classes == 1})
    fq = math.prod(x["fq"] for x in fields)
    ps = math.prod(x["product_star"] for x in fields)
    dec = len(mdd.terminals(root))
    return {"name": name, "fields": len(fields), "fq_cells": fq, "product_star_cells": ps,
            "decision_classes": dec, "fq_bits": sum(math.ceil(math.log2(x["fq"])) if x["fq"] > 1 else 0 for x in fields),
            "ps_bits": sum(math.ceil(math.log2(x["product_star"])) if x["product_star"] > 1 else 0 for x in fields),
            "min_bits": math.ceil(math.log2(dec)) if dec > 1 else 0,
            "mdd_nodes": len(mdd.nodes), "checks": checks, "per_field": fields}


def main():
    rng = random.Random(20261115)
    sources = []
    for path in sorted(glob.glob("prismpath/flows/*.md") + glob.glob("prismpath/examples/**/*.md", recursive=True)):
        if path.endswith(("README.md", ".tests.md")):
            continue
        sources.append((path, open(path, encoding="utf-8").read()))
    for case in json.load(open("prismpath/telemetry/conformance/decisions.json"))["cases"]:
        sources.append((f"decisions.json:{case['name']}", case["flow"]))
    for path in sorted(glob.glob("integrations/governed_*/policy/*.core.json")):
        sources.append((path, core_render.render(json.load(open(path)))))
    results, skipped = [], []
    for name, text in sources:
        try:
            graph = parse(text)
            r = measure(name, graph, rng)
        except Exception as error:  # noqa: BLE001
            skipped.append((name, f"{type(error).__name__}: {str(error)[:120]}"))
            continue
        if r is None:
            skipped.append((name, "no deterministic decision"))
        else:
            results.append(r)
    if len(sys.argv) > 1:
        json.dump({"results": results, "skipped": skipped}, open(sys.argv[1], "w"), indent=1)
    print(f"{'policy':58} {'fld':>3} {'FQ cells':>12} {'product*':>10} {'decis':>5} {'bits FQ/p*/min':>15} {'cuts':>4} {'checks':>6}")
    for r in results:
        cuts = sum(f["redundant_cuts"] for f in r["per_field"])
        print(f"{r['name'][-58:]:58} {r['fields']:>3} {r['fq_cells']:>12,} {r['product_star_cells']:>10,} "
              f"{r['decision_classes']:>5} {r['fq_bits']:>5}/{r['ps_bits']:>3}/{r['min_bits']:>3} {cuts:>4} {r['checks']:>6}")
    print(f"\nskipped {len(skipped)}:")
    for name, why in skipped:
        print(f"  {name}: {why}")


if __name__ == "__main__":
    main()
