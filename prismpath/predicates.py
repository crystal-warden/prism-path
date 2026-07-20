"""Deterministic edge predicates — the layer that fixes negation/logic at the source.

An edge condition that starts with `when ` (or is a bare `always`/`else`/`false`) is
DETERMINISTIC: its expression is evaluated against the agent's structured outcome (+ a
`visits` counter), not embedded. Logic where logic exists; semantic routing where it doesn't.

Safe evaluator: only names, constants, and/or/not, and comparisons — no calls, attributes,
or subscripts (no arbitrary code execution). Two robustness guarantees back the safety claim:

  * `check_predicate(cond)` statically rejects unsafe or unparseable predicates WITHOUT
    evaluating them — wired into `Graph.validate()` / lint, so a bad predicate is a compile-time
    problem, not a runtime surprise.
  * `eval_condition(cond, ctx)` never raises an *arbitrary* exception: disallowed syntax and
    parse errors become `PredicateError` (a `ValueError` subclass), and a comparison against a
    missing field or a type-mismatched value is simply *unsatisfied* (matching the documented
    "unknown name -> None (falsy)" intuition) rather than a crash. This keeps a running flow
    alive; see fuzz_predicates.py for the stress test behind these guarantees.
"""
from __future__ import annotations

import ast
import operator
from typing import Any, Dict, List

ALWAYS = {"always", "true", "else", "otherwise", "default", "_"}
NEVER = {"false", "never"}

# Bound on predicate expression nesting — predicates are tiny by design; this is a generous
# ceiling that makes deep-nesting inputs a defined rejection instead of a RecursionError.
_MAX_DEPTH = 50

_CMP = {
    ast.Eq: operator.eq, ast.NotEq: operator.ne,
    ast.Lt: operator.lt, ast.LtE: operator.le,
    ast.Gt: operator.gt, ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b, ast.NotIn: lambda a, b: a not in b,
}

# The complete set of AST node types the predicate grammar is allowed to contain. Anything else
# (Call, Attribute, Subscript, Lambda, comprehensions, f-strings, walrus, arithmetic, `is`, …)
# is rejected — statically by check_predicate and at eval time by _ev.
_ALLOWED_NODES = (
    ast.Expression, ast.Constant, ast.Name, ast.Load,
    ast.BoolOp, ast.And, ast.Or,
    ast.UnaryOp, ast.Not,
    ast.Compare, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn,
    ast.List, ast.Tuple,
)


class PredicateError(ValueError):
    """A predicate is unsafe (disallowed syntax) or unparseable. Subclasses ValueError so
    existing callers that catch ValueError keep working."""


def is_deterministic(condition: str) -> bool:
    c = condition.strip().lower()
    return c.startswith("when ") or c in ALWAYS or c in NEVER


def is_error(condition: str) -> bool:
    """An error-handler edge: `on error` (any error) or `on error when <expr>` (over the error
    context: error, error_type, error_message, error_count). Only fires when the worker raises."""
    return condition.strip().lower().startswith("on error")


def is_event(condition: str) -> bool:
    """A wait-for-event edge: `on event <name>` (an external signal/webhook) or `on timeout`. Only
    fires when the run is resumed with that event after the worker returned `{"wait": …}`."""
    c = condition.strip().lower()
    return c.startswith("on event") or c.startswith("on timeout")


def event_name(condition: str) -> str:
    """The event a `on event <name>` edge awaits; '__timeout__' for an `on timeout` edge."""
    c = condition.strip()
    if c.lower().startswith("on timeout"):
        return "__timeout__"
    return c[len("on event"):].strip()


def is_semantic(condition: str) -> bool:
    """A natural-language (embedding/LLM-routed) edge — not a `when` predicate, error, or event edge."""
    return not is_deterministic(condition) and not is_error(condition) and not is_event(condition)


def spawn_join_event(join: str) -> str:
    """The event NAME a fan-out `@spawn(join=…)` policy resolves to — the single source of truth so the
    composer (which DELIVERS the event) and the static analyzer (which REQUIRES the matching
    `on event <name>` edge) can never drift: `all_done` | `any` | `quorum`."""
    j = (join or "all_done").strip().lower()
    if j.startswith("quorum"):
        return "quorum"
    if j == "any":
        return "any"
    return "all_done"


def error_expr(condition: str) -> str:
    """The predicate part of an error edge: '' for bare `on error`, else the `when …` clause."""
    return condition.strip()[len("on error"):].strip()


def _expr_of(condition: str) -> str:
    c = condition.strip()
    return c[5:].strip() if c.lower().startswith("when ") else c


def check_predicate(condition: str) -> List[str]:
    """Static safety check for a deterministic condition. Returns a list of human-readable
    problems ([] means safe AND parseable). Does NOT evaluate — pure structural analysis, so it
    is safe to run over untrusted flows at author/validate time.

    Non-deterministic (semantic) conditions and the bare `always`/`false` keywords return []."""
    if not is_deterministic(condition):
        return []
    expr = _expr_of(condition)
    if expr.lower() in ALWAYS or expr.lower() in NEVER:
        return []
    if not expr:
        return [f"empty `when` predicate in {condition!r}"]
    try:
        tree = ast.parse(expr, mode="eval")
    except (SyntaxError, ValueError) as e:  # ValueError: e.g. null bytes
        return [f"unparseable predicate {condition!r}: {e}"]
    problems: List[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            problems.append(
                f"predicate {condition!r} uses disallowed syntax "
                f"({type(node).__name__}) — only names, literals, and/or/not, and comparisons "
                f"are permitted")
    if _depth(tree.body) > _MAX_DEPTH:
        problems.append(f"predicate {condition!r} is nested too deeply (> {_MAX_DEPTH})")
    # de-dup while preserving order (walk can flag the same disallowed kind repeatedly)
    seen, out = set(), []
    for p in problems:
        if p not in seen:
            seen.add(p); out.append(p)
    return out


def _depth(node, d: int = 0) -> int:
    children = list(ast.iter_child_nodes(node))
    return d if not children else max(_depth(c, d + 1) for c in children)


def eval_condition(condition: str, ctx: Dict[str, Any]) -> bool:
    expr = _expr_of(condition)
    low = expr.lower()
    if low in ALWAYS:
        return True
    if low in NEVER:
        return False
    try:
        tree = ast.parse(expr, mode="eval")
    except (SyntaxError, ValueError) as e:
        raise PredicateError(f"unparseable predicate {condition!r}: {e}") from e
    # Enforce the sandbox STATICALLY before evaluating, exactly like check_predicate: without this,
    # a lazily-short-circuited chain (`2 < 1 < f(x)`) never visits the disallowed Call and quietly
    # evaluates on one engine while erroring on another (found by differential fuzzing). eval and
    # check must accept the same language, always.
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            raise PredicateError(
                f"predicate {condition!r} uses disallowed syntax ({type(node).__name__})")
    return bool(_ev(tree.body, ctx, 0))


def _compare(op, left, right) -> bool:
    """One pairwise comparison, made total: a missing field (None) or a type-mismatched pair
    makes an ordering/membership test *unsatisfied* rather than raising. `==`/`!=` are already
    total in Python and keep exact semantics."""
    fn = _CMP.get(type(op))
    if fn is None:
        raise PredicateError(f"comparison operator {type(op).__name__} not allowed")
    try:
        return bool(fn(left, right))
    except Exception:   # noqa: BLE001 - a predicate must never crash a run
        # `<,<=,>,>=` on incompatible/missing operands, `in`/`not in` on a non-iterable, a value
        # whose __lt__ raises, an ambiguous array truth value — all treated as *unsatisfied*
        # (its negation `not in` therefore satisfied), matching "unknown -> falsy".
        return isinstance(op, ast.NotIn)


def _ev(node, ctx, depth: int):
    if depth > _MAX_DEPTH:
        raise PredicateError("predicate nested too deeply")
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return ctx.get(node.id)            # unknown name -> None (falsy)
    if isinstance(node, ast.BoolOp):
        vals = [_ev(v, ctx, depth + 1) for v in node.values]
        return all(vals) if isinstance(node.op, ast.And) else any(vals)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _ev(node.operand, ctx, depth + 1)
    if isinstance(node, ast.Compare):
        left = _ev(node.left, ctx, depth + 1)
        for op, comp in zip(node.ops, node.comparators):
            right = _ev(comp, ctx, depth + 1)
            if not _compare(op, left, right):
                return False
            left = right
        return True
    if isinstance(node, (ast.List, ast.Tuple)):   # literal collection, e.g. `x in [1,2,3]`
        return [_ev(e, ctx, depth + 1) for e in node.elts]
    raise PredicateError(f"unsupported predicate syntax near: {type(node).__name__}")
