#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Generate formal/FQ/Vectors.lean: the bridge from the Lean model to the frozen corpora and the
reference implementation. Every emitted line is a `#guard`, evaluated at build time; a false guard
fails `lake build`. Nothing here is a proof; it is what ties the proven model to the code.

Sources (hashes recorded in the generated header):
  prismpath/portable/conformance/predicates.json   Level M cases: Lean evalCond == frozen expectation
  prismpath/telemetry/conformance/decisions.json    every reading: Lean route == frozen route, and Lean
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
from prismpath import model_check  # noqa: E402
from prismpath.kernel.parser import parse  # noqa: E402
from prismpath.telemetry import quantizer as quantizer  # noqa: E402

PRED = REPO / "prismpath" / "portable" / "conformance" / "predicates.json"
DEC = REPO / "prismpath" / "telemetry" / "conformance" / "decisions.json"
SPI = REPO / "adapters" / "fusion" / "conformance" / "spiral_fusion.json"
INP = REPO / "prismpath" / "telemetry" / "conformance" / "inputs.json"
FDEF = REPO / "prismpath" / "portable" / "conformance" / "field_definitions.json"
OUT = REPO / "formal" / "FQ" / "Vectors.lean"

CATCH_ALL = {"else", "otherwise", "always", "default", "_", "true"}


class Skip(Exception):
    pass


def lean_str(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)


def lean_int(number: int) -> str:
    return f"({number})" if number < 0 else str(number)


def lean_value(value) -> str:
    if isinstance(value, bool):
        return ".bool true" if value else ".bool false"
    if isinstance(value, int):
        return f".int {lean_int(value)}"
    if isinstance(value, str):
        return f".str {lean_str(value)}"
    raise Skip("non scalar or float value")


def const_kind(value) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, str):
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
        parts = [to_cond(operand, atoms) for operand in node.values]
        op = ".and" if isinstance(node.op, ast.And) else ".or"
        out = parts[0]
        for part in parts[1:]:
            out = f"(Cond{op} {out} {part})"
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
        for index, op in enumerate(node.ops):
            left, right = operands[index], operands[index + 1]
            if isinstance(op, (ast.In, ast.NotIn)):
                if not isinstance(left, ast.Name) or not isinstance(right, (ast.Tuple, ast.List)):
                    raise Skip("shape not carried (membership operands)")
                consts = [_const(element) for element in right.elts]
                kinds = {const_kind(constant) for constant in consts}
                if len(kinds) > 1:
                    raise Skip("shape not carried (mixed kind list)")
                atoms.append((left.id, kinds.pop() if kinds else None))
                form = "Cond.mem" if isinstance(op, ast.In) else "Cond.nmem"
                terms.append(f"({form} {lean_str(left.id)} [{', '.join(lean_value(constant) for constant in consts)}])")
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
        for term in terms[1:]:
            out = f"(Cond.and {out} {term})"
        return out
    raise Skip("shape not carried")


def translate(cond_text: str, atoms: list) -> str:
    # The `when` prefix and the catch-all words are case insensitive to the kernel
    # (kernel/predicates.py:141 and 153), so they have to be here too. Matching case sensitively
    # sent a condition spelled "When x > 3" straight to ast.parse, which raises SyntaxError rather
    # than Skip and so killed the generator instead of counting a skipped case.
    text = cond_text.strip()
    if text.lower().startswith("when "):
        text = text[5:].strip()
    if text.lower() in CATCH_ALL:
        return "Cond.tt"
    tree = ast.parse(text, mode="eval")
    return to_cond(tree.body, atoms)


def check_typed(ctx: dict, atoms: list) -> None:
    for field, kind in atoms:
        if field not in ctx or ctx[field] is None:
            raise Skip("referenced field missing or null")
        value = ctx[field]
        value_kind = const_kind(value)          # raises Skip on non scalar / float
        if kind is not None and value_kind != kind:
            raise Skip("cross kind comparison")


def reading_term(ctx: dict, fields) -> str:
    items = ", ".join(f"({lean_str(field)}, {lean_value(ctx[field])})" for field in fields if field in ctx and ctx[field] is not None)
    return f"(readingOf [{items}])"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def gen_predicates(lines: list, counts: dict) -> None:
    doc = json.loads(PRED.read_text())
    lines.append(f"/-! ## predicates.json (version {doc['version']}, {len(doc['cases'])} cases): the Level M, well typed subset -/")
    for case_index, case in enumerate(doc["cases"]):
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
        except Skip as skipped:
            counts[str(skipped)] += 1
            continue
        fields = sorted({field for field, _ in atoms})
        exp = "true" if expect else "false"
        lines.append(f"#guard evalCond {reading_term(ctx, fields)} {term} == {exp}  -- case {case_index}: {cond}")
        counts["checked"] += 1


def flow_policies(flow_text: str):
    """(all_edges_policy_term, {node: node_policy_term}) for a flow, or raise Skip."""
    flow = parse(flow_text)
    node_terms, all_rules = {}, []
    for name, node in flow.nodes.items():
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
        flow = parse(case["flow"])
        parts = quantizer.build_partitions(flow)
        all_term, node_terms = flow_policies(case["flow"])
        lines.append(f"def {name}_all : Policy String := {all_term}")
        for node, term in node_terms.items():
            lines.append(f"def {name}_{node} : Policy String := {term}")
        fields = sorted(parts)
        for reading_index, entry in enumerate(case["readings"]):
            reading = entry["reading"]
            # The model's readings are total, and readingOf fills a gap with 0. A reading missing a
            # decision field is a different reading to the reference, which reads it as null, so it
            # is never bridged: a guard that happened to agree would tie Lean to a reading the
            # reference never saw. Absence enters the model in the formalization's next step.
            if any(field not in reading or reading[field] is None for field in fields):
                counts["readings skipped: a decision field missing or null"] += 1
                continue
            reading_lean = reading_term(reading, fields)
            for node, target in entry["routes"].items():
                exp = f"some {lean_str(target)}" if target is not None else "none"
                lines.append(f"#guard route {name}_{node} {reading_lean} == {exp}  -- {name} reading {reading_index}")
                counts["routes checked"] += 1
            py_syms = quantizer.quantize(parts, reading)
            for field in fields:
                lines.append(f"#guard (quantize (buildPartitions {name}_all) {reading_lean}).lookup {lean_str(field)} == some {py_syms[field]}")
                counts["symbols checked against the reference"] += 1


def gen_spiral(lines: list, counts: dict) -> None:
    doc = json.loads(SPI.read_text())
    lines.append(f"\n/-! ## spiral_fusion.json ({len(doc['probes'])} probes at node {doc['node']}) -/")
    all_term, node_terms = flow_policies(doc["flow"])
    lines.append(f"def fusion_{doc['node']} : Policy String := {node_terms[doc['node']]}")
    for probe_index, probe in enumerate(doc["probes"]):
        reading_lean = reading_term(probe["reading"], sorted(probe["reading"]))
        lines.append(f"#guard route fusion_{doc['node']} {reading_lean} == some {lean_str(probe['route'])}  -- probe {probe_index}")
        counts["spiral probes checked"] += 1


def gen_spiral_layout(lines: list, counts: dict) -> None:
    """The Lean spiral layout, derived in Lean from the fusion policy (radices from the partitions, cell
    routes from the representatives, route order from the rules), must place every frozen cell at the
    frozen index and give it the frozen route and band, and the Lean Gray order must equal the
    reference's iterative one on the frozen radices."""
    sys.path.insert(0, str(REPO / "prismpath" / "telemetry"))
    import spiral as spiral_reference
    doc = json.loads(SPI.read_text())
    node = doc["node"]
    fields = doc["fields"]
    lines.append(f"\n/-! ## spiral_fusion.json: the layout derived in Lean equals the frozen cell table ({len(doc['cells'])} cells) -/")
    lines.append("open FQ.Spiral in")
    lines.append(f"def fusion_fields : List String := [{', '.join(lean_str(field) for field in fields)}]")
    lines.append(f"def fusion_partFor (f : String) : Option FieldPartition := (buildPartitions fusion_{node}).find? (·.field == f)")
    lines.append("def fusion_radices : List Nat := fusion_fields.filterMap (fun f => (fusion_partFor f).map FQ.Spiral.cellCount)")
    lines.append("def fusion_cellReading (cell : FQ.Spiral.Cell) : Reading :=")
    lines.append("  readingOf (List.zipWith (fun f d => (f, match fusion_partFor f with | some p => representativeOf p d | none => .int 0)) fusion_fields cell)")
    lines.append(f"def fusion_routeOf (cell : FQ.Spiral.Cell) : Option String := route fusion_{node} (fusion_cellReading cell)")
    lines.append(f"def fusion_routes : List (Option String) := FQ.Spiral.routesFor fusion_{node} (FQ.Spiral.gray fusion_radices) fusion_routeOf")
    lines.append("def fusion_layout : List FQ.Spiral.Cell := FQ.Spiral.layout (FQ.Spiral.gray fusion_radices) fusion_routeOf fusion_routes")
    lines.append(f"#guard fusion_radices == {doc['radices']}")
    routes = ", ".join(f"some {lean_str(band['route'])}" if band["route"] is not None else "none" for band in doc["bands"])
    lines.append(f"#guard fusion_routes == [{routes}]")
    lines.append(f"#guard fusion_layout.length == {doc['size']}")
    gray_py = [list(digits) for digits in spiral_reference.mixed_radix_gray(doc["radices"])]
    lines.append(f"#guard FQ.Spiral.gray fusion_radices == {gray_py}")
    counts["spiral gray order equals the reference"] += 1
    for entry in doc["cells"]:
        cell, cell_index, band, route = entry["cell"], entry["n"], entry["band"], entry["route"]
        route_lean = f"some {lean_str(route)}" if route is not None else "none"
        lines.append(f"#guard fusion_layout.idxOf {cell} == {cell_index}")
        lines.append(f"#guard fusion_routeOf {cell} == {route_lean}")
        lines.append(f"#guard FQ.Spiral.bandOf (FQ.Spiral.bands (FQ.Spiral.gray fusion_radices) fusion_routeOf fusion_routes) {cell_index} == some {band}")
        counts["spiral cells checked (index, route, band)"] += 1


def gen_zeckendorf(lines: list, counts: dict, upto: int = 300) -> None:
    """The Lean Fibonacci code must equal the reference's bit string for every 1 <= n <= upto, and the
    reference's decode must invert it (evaluated; the theorem covers all n)."""
    import zeckendorf as zeckendorf_reference
    lines.append(f"\n/-! ## zeckendorf.py: Lean encode == reference bits for 1..{upto} -/")
    for number in range(1, upto + 1):
        bits = zeckendorf_reference.encode(number)
        lean_bits = "[" + ", ".join("true" if bit == "1" else "false" for bit in bits) + "]"
        lines.append(f"#guard FQ.Zeck.encode {number} == {lean_bits}")
        counts["zeckendorf codes checked against the reference"] += 1


def lean_rat(value) -> str:
    """The exact rational of an int, a float (a binary double is a dyadic rational) or a Fraction."""
    from fractions import Fraction
    frac = Fraction(value)
    if frac.denominator == 1:
        return f"({frac.numerator} : ℚ)"
    return f"(({frac.numerator} : ℚ) / {frac.denominator})"


def lean_raw(value) -> str:
    """A JSON value as the model's raw value (FQ.Contract)."""
    if value is None:
        return ".null"
    if isinstance(value, bool):
        return ".bool true" if value else ".bool false"
    if isinstance(value, (int, float)):
        return f".num {lean_rat(value)}"
    if isinstance(value, str):
        return f".str {lean_str(value)}"
    return f".other {'true' if value else 'false'}"


LEAN_KIND = {"numeric": ".numeric", "boolean": ".boolean", "categorical": ".categorical"}


def gen_acceptance(lines: list, counts: dict) -> None:
    """Every case of the frozen acceptance corpus: the model's `accept` (FQ.Contract, the function the
    strict contract is proven over) refuses what the corpus refuses, accepts what it accepts to the same
    value, and the accepted value lands in the frozen cell."""
    doc = json.loads(INP.read_text())
    parts = quantizer.build_partitions(parse(doc["flow"]))
    all_term, _node_terms = flow_policies(doc["flow"])
    lines.append(f"\n/-! ## inputs.json (version {doc['version']}, {len(doc['cases'])} cases): the acceptance function -/")
    lines.append(f"def inputs_all : Policy String := {all_term}")
    for case_index, case in enumerate(doc["cases"]):
        field = case["field"]
        kind = parts[field].kind
        raw = lean_raw(case["input"])
        label = f"inputs case {case_index}: {field}={json.dumps(case['input'])}"
        if "refuse" in case["expect"]:
            lines.append(f"#guard accept {LEAN_KIND[kind]} ({raw}) == none  -- {label} refused {case['expect']['refuse']}")
            counts["acceptance refusals checked"] += 1
            continue
        _reason, converted = quantizer.accept_value(kind, case["input"])
        value = lean_value(converted)
        lines.append(f"#guard accept {LEAN_KIND[kind]} ({raw}) == some ({value})  -- {label}")
        lines.append(f"#guard ((buildPartitions inputs_all).find? (·.field == {lean_str(field)})).map "
                     f"(fun q => symbolOf q ({value})) == some {case['expect']['symbol']}  -- {label}")
        counts["acceptances checked, value and cell"] += 1


def gen_conversion(lines: list, counts: dict) -> None:
    """Every fixed field case of the frozen conversion vectors the model covers: the model's `convert`
    (FQ.Conversion, the function the conversion lemma is proven over) gives the canonical integer the
    reference gives, puts an out of range value outside the range, and refuses an off grid value under
    exact rounding. Cases the model leaves to the implementation (text that does not parse, a binary
    double with a fraction, a wrong type, absence) are counted, not bridged."""
    from fractions import Fraction
    from prismpath.kernel import field_definitions
    doc = json.loads(FDEF.read_text())
    lines.append(f"\n/-! ## field_definitions.json (version {doc['version']}): the shared conversion on fixed fields -/")
    rounding_term = {"floor": ".floor", "ceiling": ".ceiling", "exact": ".exact"}
    for case_index, case in enumerate(doc["conversion"]):
        definition = field_definitions.parse_definition("value", case["definition"])
        raw = case["raw"]
        if definition.kind != field_definitions.KIND_FIXED:
            counts["conversion cases skipped: not a fixed field"] += 1
            continue
        if isinstance(raw, str):
            exact = field_definitions.decimal_fraction(raw)
        elif isinstance(raw, int) and not isinstance(raw, bool):
            exact = Fraction(raw)
        elif isinstance(raw, float) and raw.is_integer():
            exact = Fraction(raw)
        else:
            exact = None
        if exact is None or case.get("refused") in ("unparseable_string", "binary_float", "wrong_type", "missing"):
            counts["conversion cases skipped: outside the model (parse, type, absence)"] += 1
            continue
        call = f"FQ.Conversion.convert {rounding_term[definition.rounding]} {definition.scale} {lean_rat(exact)}"
        label = f"conversion case {case_index}: {case['definition']} {json.dumps(raw)}"
        if "canonical" in case:
            lines.append(f"#guard {call} == some {lean_int(case['canonical'])}  -- {label}")
        elif case["refused"] == "off_grid":
            lines.append(f"#guard {call} == none  -- {label} off grid")
        elif case["refused"] == "out_of_range":
            lines.append(f"#guard ({call}).map (fun n => decide ({lean_int(definition.minimum)} ≤ n ∧ n ≤ "
                         f"{lean_int(definition.maximum)})) != some true  -- {label} out of range")
        else:
            raise AssertionError(f"unhandled conversion refusal {case['refused']!r}")
        counts["conversions checked"] += 1


def main() -> int:
    from collections import Counter
    counts: Counter = Counter()
    body: list = []
    gen_predicates(body, counts)
    gen_decisions(body, counts)
    gen_spiral(body, counts)
    gen_spiral_layout(body, counts)
    gen_zeckendorf(body, counts)
    gen_acceptance(body, counts)
    gen_conversion(body, counts)
    header = [
        "-- SPDX-License-Identifier: Apache-2.0",
        "-- Copyright 2026 Crystal Warden Supply Chain Labs LLC",
        "-- GENERATED by formal/gen_vectors.py from the frozen corpora and the reference quantizer. Do not edit.",
        f"-- predicates.json sha256 {sha(PRED)}",
        f"-- decisions.json   sha256 {sha(DEC)}",
        f"-- spiral_fusion.json sha256 {sha(SPI)}",
        f"-- inputs.json sha256 {sha(INP)}",
        f"-- field_definitions.json sha256 {sha(FDEF)}",
        "-- counts: " + ", ".join(f"{name} {count}" for name, count in sorted(counts.items())),
        "import FQ.Partition",
        "import FQ.Zeckendorf",
        "import FQ.Spiral",
        "import FQ.Contract",
        "import FQ.Conversion",
        "",
        "namespace FQ.Vectors",
        "open FQ",
        "",
        "/-- A total reading from an association list; a field not listed reads as 0. No guard relies on",
        "that default: the generator skips, with a counted reason, every predicate case whose condition",
        "references a missing or null field and every corpus reading missing a decision field, because",
        "the reference reads absence as null and the model has no null yet. -/",
        "def readingOf (l : List (String × Value)) : Reading := fun f => (l.lookup f).getD (.int 0)",
        "",
    ]
    # Refusing to write an empty run is the point: the corpora are read by path, so a rename or a
    # moved repo used to produce a Vectors.lean with a header, no guards and exit 0, which reads
    # downstream as a clean build of a bridge that is no longer checking anything.
    guards = sum(1 for line in body if line.startswith("#guard"))
    if guards == 0:
        print("gen_vectors: no #guard emitted, so FQ/Vectors.lean was NOT rewritten", file=sys.stderr)
        return 1
    OUT.write_text("\n".join(header + body) + "\n\nend FQ.Vectors\n", encoding="utf-8")
    print(f"wrote {OUT}")
    for name, count in sorted(counts.items()):
        print(f"  {name:45} {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
