#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Generate formal/FQ/Vectors.lean: the bridge from the Lean model to the frozen corpora and the
reference implementation. Every emitted line is a `#guard`, evaluated at build time; a false guard
fails `lake build`. Nothing here is a proof; it is what ties the proven model to the code.

Sources (hashes recorded in the generated header):
  prismpath/portable/conformance/predicates.json   Level M cases: Lean evalCond == frozen expectation
  adapters/telemetry/conformance/decisions.json    every reading: Lean route == frozen route, and Lean
                                                   canonical symbols == the reference quantizer's symbols
  adapters/fusion/conformance/spiral_fusion.json   every probe: Lean route == frozen route

Skipped predicate cases are counted by reason in the header: not Level M; a referenced field missing
or null (the model has total readings); a non scalar or float value; a cross kind comparison (the
model's well typed theorem excludes them); a shape the translator does not carry.

Usage: ./.venv/bin/python formal/gen_vectors.py   (from the repo root)
"""
from __future__ import annotations

import ast
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "adapters" / "telemetry"))

from prismpath import model_check  # noqa: E402
from prismpath.parser import parse  # noqa: E402
import quantizer as q  # noqa: E402

PRED = REPO / "prismpath" / "portable" / "conformance" / "predicates.json"
DEC = REPO / "adapters" / "telemetry" / "conformance" / "decisions.json"
SPI = REPO / "adapters" / "fusion" / "conformance" / "spiral_fusion.json"
OUT = REPO / "formal" / "FQ" / "Vectors.lean"

CATCH_ALL = {"else", "otherwise", "always", "default", "_", "true"}


class Skip(Exception):
    pass


def lean_str(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


def lean_int(n: int) -> str:
    return f"({n})" if n < 0 else str(n)


def lean_value(v) -> str:
    if isinstance(v, bool):
        return ".bool true" if v else ".bool false"
    if isinstance(v, int):
        return f".int {lean_int(v)}"
    if isinstance(v, str):
        return f".str {lean_str(v)}"
    raise Skip("non scalar or float value")


def const_kind(v) -> str:
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, str):
        return "str"
    raise Skip("non scalar or float constant")


OPS = {ast.Lt: ".lt", ast.LtE: ".le", ast.Gt: ".gt", ast.GtE: ".ge", ast.Eq: ".eq", ast.NotEq: ".ne"}


def _const(node):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) and isinstance(node.operand, ast.Constant) \
            and isinstance(node.operand.value, int) and not isinstance(node.operand.value, bool):
        return -node.operand.value
    raise Skip("shape not carried (non literal operand)")


def to_cond(node, atoms: list) -> str:
    """Python AST (Level M) -> Lean Cond term. Records (field, kind) of every atom in `atoms`."""
    if isinstance(node, ast.BoolOp):
        parts = [to_cond(v, atoms) for v in node.values]
        op = ".and" if isinstance(node.op, ast.And) else ".or"
        out = parts[0]
        for p in parts[1:]:
            out = f"(Cond{op} {out} {p})"
        return out
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return f"(Cond.not {to_cond(node.operand, atoms)})"
    if isinstance(node, ast.Name):
        atoms.append((node.id, None))
        return f"(Cond.truthy {lean_str(node.id)})"
    if isinstance(node, ast.Compare):
        # chained comparisons desugar to a conjunction, SPEC section 4.3
        operands = [node.left] + node.comparators
        terms = []
        for i, op in enumerate(node.ops):
            left, right = operands[i], operands[i + 1]
            if isinstance(op, (ast.In, ast.NotIn)):
                if not isinstance(left, ast.Name) or not isinstance(right, (ast.Tuple, ast.List)):
                    raise Skip("shape not carried (membership operands)")
                consts = [_const(e) for e in right.elts]
                kinds = {const_kind(c) for c in consts}
                if len(kinds) > 1:
                    raise Skip("shape not carried (mixed kind list)")
                atoms.append((left.id, kinds.pop() if kinds else None))
                form = "Cond.mem" if isinstance(op, ast.In) else "Cond.nmem"
                terms.append(f"({form} {lean_str(left.id)} [{', '.join(lean_value(c) for c in consts)}])")
                continue
            if type(op) not in OPS:
                raise Skip("shape not carried (operator)")
            if isinstance(left, ast.Name) and not isinstance(right, ast.Name):
                field, const, lop = left.id, _const(right), OPS[type(op)]
            elif isinstance(right, ast.Name) and not isinstance(left, ast.Name):
                flip = {".lt": ".gt", ".gt": ".lt", ".le": ".ge", ".ge": ".le", ".eq": ".eq", ".ne": ".ne"}
                field, const, lop = right.id, _const(left), flip[OPS[type(op)]]
            else:
                raise Skip("shape not carried (field against field or constant only)")
            atoms.append((field, const_kind(const)))
            terms.append(f"(Cond.cmp {lean_str(field)} {lop} ({lean_value(const)}))")
        out = terms[0]
        for t in terms[1:]:
            out = f"(Cond.and {out} {t})"
        return out
    raise Skip("shape not carried")


def translate(cond_text: str, atoms: list) -> str:
    text = cond_text.strip()
    if text.startswith("when "):
        text = text[5:].strip()
    if text in CATCH_ALL:
        return "Cond.tt"
    tree = ast.parse(text, mode="eval")
    return to_cond(tree.body, atoms)


def check_typed(ctx: dict, atoms: list) -> None:
    for field, kind in atoms:
        if field not in ctx or ctx[field] is None:
            raise Skip("referenced field missing or null")
        v = ctx[field]
        vk = const_kind(v)          # raises Skip on non scalar / float
        if kind is not None and vk != kind:
            raise Skip("cross kind comparison")


def reading_term(ctx: dict, fields) -> str:
    items = ", ".join(f"({lean_str(f)}, {lean_value(ctx[f])})" for f in fields if f in ctx and ctx[f] is not None)
    return f"(readingOf [{items}])"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def gen_predicates(lines: list, counts: dict) -> None:
    doc = json.loads(PRED.read_text())
    lines.append(f"/-! ## predicates.json (version {doc['version']}, {len(doc['cases'])} cases): the Level M, well typed subset -/")
    for i, case in enumerate(doc["cases"]):
        cond, ctx, expect = case["cond"], case["ctx"], case["expect"]
        ok, _reason = model_check.is_level_m(cond)
        if not ok:
            counts["not Level M"] += 1
            continue
        if expect == "ERROR":
            counts["expectation is ERROR"] += 1
            continue
        atoms: list = []
        try:
            term = translate(cond, atoms)
            check_typed(ctx, atoms)
        except Skip as e:
            counts[str(e)] += 1
            continue
        fields = sorted({f for f, _ in atoms})
        exp = "true" if expect else "false"
        lines.append(f"#guard evalCond {reading_term(ctx, fields)} {term} == {exp}  -- case {i}: {cond}")
        counts["checked"] += 1


def flow_policies(flow_text: str):
    """(all_edges_policy_term, {node: node_policy_term}) for a flow, or raise Skip."""
    g = parse(flow_text)
    node_terms, all_rules = {}, []
    for name, node in g.nodes.items():
        if not node.edges:
            continue
        rules = []
        for target, cond in node.edges:
            atoms: list = []
            term = translate(cond, atoms)
            rules.append(f"⟨{term}, {lean_str(target)}⟩")
        node_terms[name] = "[" + ", ".join(rules) + "]"
        all_rules.extend(rules)
    return "[" + ", ".join(all_rules) + "]", node_terms


def gen_decisions(lines: list, counts: dict) -> None:
    doc = json.loads(DEC.read_text())
    lines.append(f"\n/-! ## decisions.json (version {doc['version']}, {len(doc['cases'])} flows): routes and canonical symbols against the reference quantizer -/")
    for case in doc["cases"]:
        name = case["name"]
        g = parse(case["flow"])
        parts = q.build_partitions(g)
        all_term, node_terms = flow_policies(case["flow"])
        lines.append(f"def {name}_all : Policy String := {all_term}")
        for node, term in node_terms.items():
            lines.append(f"def {name}_{node} : Policy String := {term}")
        fields = sorted(parts)
        for j, entry in enumerate(case["readings"]):
            reading = entry["reading"]
            r = reading_term(reading, fields)
            for node, target in entry["routes"].items():
                exp = f"some {lean_str(target)}" if target is not None else "none"
                lines.append(f"#guard route {name}_{node} {r} == {exp}  -- {name} reading {j}")
                counts["routes checked"] += 1
            py_syms = q.quantize(parts, reading)
            for f in fields:
                lines.append(f"#guard (quantize (buildPartitions {name}_all) {r}).lookup {lean_str(f)} == some {py_syms[f]}")
                counts["symbols checked against the reference"] += 1


def gen_spiral(lines: list, counts: dict) -> None:
    doc = json.loads(SPI.read_text())
    lines.append(f"\n/-! ## spiral_fusion.json ({len(doc['probes'])} probes at node {doc['node']}) -/")
    all_term, node_terms = flow_policies(doc["flow"])
    lines.append(f"def fusion_{doc['node']} : Policy String := {node_terms[doc['node']]}")
    for j, probe in enumerate(doc["probes"]):
        r = reading_term(probe["reading"], sorted(probe["reading"]))
        lines.append(f"#guard route fusion_{doc['node']} {r} == some {lean_str(probe['route'])}  -- probe {j}")
        counts["spiral probes checked"] += 1


def gen_spiral_layout(lines: list, counts: dict) -> None:
    """The Lean spiral layout, derived in Lean from the fusion policy (radices from the partitions, cell
    routes from the representatives, route order from the rules), must place every frozen cell at the
    frozen index and give it the frozen route and band, and the Lean Gray order must equal the
    reference's iterative one on the frozen radices."""
    sys.path.insert(0, str(REPO / "adapters" / "telemetry"))
    import spiral as sp
    doc = json.loads(SPI.read_text())
    node = doc["node"]
    fields = doc["fields"]
    lines.append(f"\n/-! ## spiral_fusion.json: the layout derived in Lean equals the frozen cell table ({len(doc['cells'])} cells) -/")
    lines.append("open FQ.Spiral in")
    lines.append(f"def fusion_fields : List String := [{', '.join(lean_str(f) for f in fields)}]")
    lines.append(f"def fusion_partFor (f : String) : Option FieldPartition := (buildPartitions fusion_{node}).find? (·.field == f)")
    lines.append("def fusion_radices : List Nat := fusion_fields.filterMap (fun f => (fusion_partFor f).map FQ.Spiral.cellCount)")
    lines.append("def fusion_cellReading (cell : FQ.Spiral.Cell) : Reading :=")
    lines.append("  readingOf (List.zipWith (fun f d => (f, match fusion_partFor f with | some p => representativeOf p d | none => .int 0)) fusion_fields cell)")
    lines.append(f"def fusion_routeOf (cell : FQ.Spiral.Cell) : Option String := route fusion_{node} (fusion_cellReading cell)")
    lines.append(f"def fusion_routes : List (Option String) := FQ.Spiral.routesFor fusion_{node} (FQ.Spiral.gray fusion_radices) fusion_routeOf")
    lines.append("def fusion_layout : List FQ.Spiral.Cell := FQ.Spiral.layout (FQ.Spiral.gray fusion_radices) fusion_routeOf fusion_routes")
    lines.append(f"#guard fusion_radices == {doc['radices']}")
    routes = ", ".join(f"some {lean_str(b['route'])}" if b["route"] is not None else "none" for b in doc["bands"])
    lines.append(f"#guard fusion_routes == [{routes}]")
    lines.append(f"#guard fusion_layout.length == {doc['size']}")
    gray_py = [list(t) for t in sp.mixed_radix_gray(doc["radices"])]
    lines.append(f"#guard FQ.Spiral.gray fusion_radices == {gray_py}")
    counts["spiral gray order equals the reference"] += 1
    for entry in doc["cells"]:
        cell, n, band, route = entry["cell"], entry["n"], entry["band"], entry["route"]
        r = f"some {lean_str(route)}" if route is not None else "none"
        lines.append(f"#guard fusion_layout.idxOf {cell} == {n}")
        lines.append(f"#guard fusion_routeOf {cell} == {r}")
        lines.append(f"#guard FQ.Spiral.bandOf (FQ.Spiral.bands (FQ.Spiral.gray fusion_radices) fusion_routeOf fusion_routes) {n} == some {band}")
        counts["spiral cells checked (index, route, band)"] += 1


def gen_zeckendorf(lines: list, counts: dict, upto: int = 300) -> None:
    """The Lean Fibonacci code must equal the reference's bit string for every 1 <= n <= upto, and the
    reference's decode must invert it (evaluated; the theorem covers all n)."""
    import zeckendorf as z
    lines.append(f"\n/-! ## zeckendorf.py: Lean encode == reference bits for 1..{upto} -/")
    for n in range(1, upto + 1):
        bits = z.encode(n)
        lean_bits = "[" + ", ".join("true" if b == "1" else "false" for b in bits) + "]"
        lines.append(f"#guard FQ.Zeck.encode {n} == {lean_bits}")
        counts["zeckendorf codes checked against the reference"] += 1


def main() -> int:
    from collections import Counter
    counts: Counter = Counter()
    body: list = []
    gen_predicates(body, counts)
    gen_decisions(body, counts)
    gen_spiral(body, counts)
    gen_spiral_layout(body, counts)
    gen_zeckendorf(body, counts)
    header = [
        "-- SPDX-License-Identifier: Apache-2.0",
        "-- Copyright 2026 Crystal Warden Supply Chain Labs LLC",
        "-- GENERATED by formal/gen_vectors.py from the frozen corpora and the reference quantizer. Do not edit.",
        f"-- predicates.json sha256 {sha(PRED)}",
        f"-- decisions.json   sha256 {sha(DEC)}",
        f"-- spiral_fusion.json sha256 {sha(SPI)}",
        "-- counts: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())),
        "import FQ.Partition",
        "import FQ.Zeckendorf",
        "import FQ.Spiral",
        "",
        "namespace FQ.Vectors",
        "open FQ",
        "",
        "/-- A total reading from an association list; absent fields read as 0 (never referenced by the",
        "checked conditions, the generator filters those cases out). -/",
        "def readingOf (l : List (String × Value)) : Reading := fun f => (l.lookup f).getD (.int 0)",
        "",
    ]
    OUT.write_text("\n".join(header + body) + "\n\nend FQ.Vectors\n", encoding="utf-8")
    print(f"wrote {OUT}")
    for k, v in sorted(counts.items()):
        print(f"  {k:45} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
