# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Level M, the match action fragment (SPEC section 4.3 and section 7): the classifier that says
whether a deterministic `when` condition is table encodable, the per edge report, and the per flow
verdict. This is the definition every compiler and interpreter target follows (prismpath-hw's
ppt_compile imports the chain desugar from here through model_check), so it sits below the analyzer
and the model checker and imports only the parser and the predicates."""
from __future__ import annotations

import ast
from typing import List, Optional, Tuple

from prismpath.kernel import predicates
from prismpath.kernel.parser import reachable as _reachable
from prismpath.kernel.predicates import expr_ast as _parse


# reason codes for non-membership (stable, machine-readable)
_R_CHAINED = "chained-comparison"
_R_FIELD_VS_FIELD = "field-vs-field"
_R_SUBSTRING = "substring-in"
_R_NONLITERAL = "non-literal-collection"
_R_STRING_ORDER = "string-ordering"
_R_CONSTANT = "constant-only"
_R_NESTED = "nested-container"
_R_SYNTAX = "disallowed-or-unparseable"

_ORDER_OPS = (ast.Lt, ast.LtE, ast.Gt, ast.GtE)
_EQ_OPS = (ast.Eq, ast.NotEq)


def _scalar_const(node) -> bool:
    # float is EXCLUDED: the Level M / hardware match-action fragment is an i32 value domain, so a float
    # constant is not table-representable (the PPT compiler delegates here and so rejects it too, as
    # `not-level-m:disallowed-or-unparseable`). bool is a subclass of int, so `isinstance(True, int)` is
    # True — booleans stay in-fragment.
    return isinstance(node, ast.Constant) and (
        node.value is None or (isinstance(node.value, (bool, int, str))
                               and not isinstance(node.value, float)))


def _atom_reason(node) -> Optional[str]:
    """None if `node` is a Level M atom; else the reason code it is not."""
    if isinstance(node, ast.Name):
        return None                                        # bare field (scalar truthiness)
    if isinstance(node, ast.Constant):
        return _R_CONSTANT                                 # `when True` — no field, not a row
    if isinstance(node, ast.Compare):
        if len(node.ops) != 1:
            return _R_CHAINED                              # defensive: is_level_m desugars chains
            #                                                first (SPEC §4.3), so this is unreachable
            #                                                on that path — kept so a raw _classify
            #                                                call can't silently read only ops[0].
        left, op, right = node.left, node.ops[0], node.comparators[0]
        if not isinstance(op, _ORDER_OPS + _EQ_OPS + (ast.In, ast.NotIn)):
            return _R_SYNTAX                               # `is`/`is not` — eval rejects them too
        # membership: field in/not in [scalar literals]
        if isinstance(op, (ast.In, ast.NotIn)):
            if not isinstance(left, ast.Name):
                return _R_FIELD_VS_FIELD if not isinstance(left, ast.Constant) else _R_CONSTANT
            if isinstance(right, ast.Constant) and isinstance(right.value, str):
                return _R_SUBSTRING                        # string RHS = substring test
            if isinstance(right, (ast.List, ast.Tuple)):
                for e in right.elts:
                    if isinstance(e, (ast.List, ast.Tuple)):
                        return _R_NESTED
                    if not _scalar_const(e):
                        return _R_NONLITERAL
                return None
            return _R_NONLITERAL                           # membership in a runtime collection
        # comparison: field OP constant (either orientation)
        if isinstance(left, ast.Name) and _scalar_const(right):
            var_c = right
        elif isinstance(right, ast.Name) and _scalar_const(left):
            var_c = left
        elif isinstance(left, ast.Name) and isinstance(right, ast.Name):
            return _R_FIELD_VS_FIELD
        else:
            return _R_CONSTANT if (_scalar_const(left) and _scalar_const(right)) else _R_SYNTAX
        if isinstance(op, _ORDER_OPS) and isinstance(var_c.value, str):
            return _R_STRING_ORDER                         # string *ordering* is excluded
        return None
    return _R_SYNTAX


def _desugar_chains(node):
    """`a < b < c` -> `a < b and b < c`, recursively (SPEC §4.3: tooling SHOULD desugar chained
    comparisons before classifying/compiling). Exact under the engine's semantics: operands are pure
    (names/constants, evaluated identically each time), every pairwise comparison is total, and BoolOp
    evaluates all operands — so the desugared form cannot diverge from Python's chain evaluation on any
    context. This is the ONE desugar both the classifier (`is_level_m`) and the PPT compiler
    (`prismpath-hw/ppt_compile`, which imports this) use, so they can never disagree about chains."""
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


def _classify(node) -> Optional[str]:
    """None if the whole expression is a boolean combination of Level M atoms; else a reason."""
    if isinstance(node, ast.BoolOp):
        for v in node.values:
            r = _classify(v)
            if r is not None:
                return r
        return None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _classify(node.operand)
    return _atom_reason(node)


def is_level_m(cond: str) -> Tuple[bool, Optional[str]]:
    """Is a deterministic condition in the match-action fragment? Keyword catch-alls
    (`always`/`else`/`false`…) are trivially table-encodable (the default / disabled row) and
    count as in-fragment. Non-deterministic conditions are (False, tier-name)."""
    if not predicates.is_deterministic(cond):
        if predicates.is_error(cond):
            expr = predicates.error_expr(cond)             # '' | 'when <expr>'
            if not expr:
                return True, None                          # bare `on error` — a table default row
            if not expr.lower().startswith("when "):
                expr = "when " + expr
            return is_level_m(expr)
        return False, "not-deterministic"
    expr = predicates._expr_of(cond)
    if expr.lower() in predicates.ALWAYS or expr.lower() in predicates.NEVER:
        return True, None
    node = _parse(cond)
    if node is None:
        return False, _R_SYNTAX
    node = _desugar_chains(node)             # SPEC §4.3: chained comparisons normalize into the fragment
    reason = _classify(node)
    return (reason is None), reason


def level_m_report(graph) -> List[dict]:
    """Per-edge fragment membership for every reachable deterministic edge (SPEC §4.3: tooling
    SHOULD report this). Rows: {node, target, condition, level_m, reason}."""
    out = []
    reach = _reachable(graph)
    for name in sorted(reach):
        node = graph.nodes.get(name)
        if node is None:
            continue
        for t, c in node.edges:
            if not predicates.is_deterministic(c):
                continue
            ok, reason = is_level_m(c)
            out.append({"node": name, "target": t, "condition": c,
                        "level_m": ok, "reason": reason})
    return out


def flow_level_m(graph) -> Tuple[bool, List[dict]]:
    """SPEC §7: within P0, Level M marks flows whose deterministic edges are ALL in the
    fragment. Returns (all_in_fragment, non-member rows)."""
    rows = level_m_report(graph)
    bad = [r for r in rows if not r["level_m"]]
    return (not bad), bad
