"""analysis.py — static analysis over the flow graph ("your flow compiles").

Because the flow *is* the graph (a Markdown file, not code smeared across Python), the whole
control structure is inspectable without running anything. This module is that inspection: a set
of **decidable** checks — no model, no embeddings, no execution — that catch the structural
mistakes an author actually makes. It is the guarantee LangGraph structurally cannot give,
because its graph only exists at runtime.

Each check yields `Finding`s at one of two severities:
  * **error**   — the flow is broken (won't run correctly): undefined targets, no reachable
                  terminal, an unsafe/unparseable predicate. `validate` exits non-zero on these.
  * **warning** — a likely authoring mistake that still "runs": unreachable nodes, a
                  deterministic-only node that isn't provably exhaustive (can get stuck), an edge
                  shadowed by an earlier catch-all, an unbounded cycle, an always-false edge, or
                  duplicate semantic conditions. Advisory — surfaced, not fatal.

The predicate reasoning is deliberately confined to the tiny decidable fragment the `when`
language allows (comparisons of a variable against literals, joined by and/or/not); anything
outside that fragment is left un-analyzed rather than guessed at, so there are **no false
positives** on real flows.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List, Optional

from prismpath import predicates


@dataclass
class Finding:
    severity: str            # "error" | "warning"
    code: str                # stable machine code, e.g. "unreachable-node"
    node: Optional[str]      # the node it concerns (or None for whole-graph)
    message: str

    def as_dict(self) -> dict:
        return {"severity": self.severity, "code": self.code,
                "node": self.node, "message": self.message}

    def __str__(self) -> str:
        mark = "✗" if self.severity == "error" else "⚠"
        where = f"[{self.node}] " if self.node else ""
        return f"  {mark} {where}{self.message}  ({self.code})"


# --------------------------------------------------------------------------------------
# Predicate-fragment helpers (the decidable core). All operate on a deterministic condition
# string; they return conservative answers — "unknown" collapses to "no finding".
# --------------------------------------------------------------------------------------

def _parse(cond: str):
    """Return the AST expression for a deterministic `when` condition, or None (keyword
    catch-alls / unparseable / not-deterministic)."""
    if not predicates.is_deterministic(cond):
        return None
    expr = predicates._expr_of(cond)
    if expr.lower() in predicates.ALWAYS or expr.lower() in predicates.NEVER:
        return None
    try:
        return ast.parse(expr, mode="eval").body
    except (SyntaxError, ValueError):
        return None


def _is_always_true(cond: str) -> bool:
    """True only when the condition ALWAYS matches: a catch-all keyword, or a truthy constant."""
    if not predicates.is_deterministic(cond):
        return False
    expr = predicates._expr_of(cond).lower()
    if expr in predicates.ALWAYS:
        return True
    node = _parse(cond)
    return isinstance(node, ast.Constant) and bool(node.value)


def _references_visits(cond: str) -> bool:
    node = _parse(cond)
    if node is None:
        return False
    return any(isinstance(n, ast.Name) and n.id == "visits" for n in ast.walk(node))


def _negates(a: str, b: str) -> bool:
    """True if deterministic conditions `a` and `b` are exact logical negations — the common
    `X` / `not X` (and comparison-operator) pairs that make a two-way branch exhaustive."""
    na, nb = _parse(a), _parse(b)
    if na is None or nb is None:
        return False

    def _not_of(x, y):   # is x == `not (y)` ?
        return isinstance(x, ast.UnaryOp) and isinstance(x.op, ast.Not) \
            and ast.dump(x.operand) == ast.dump(y)

    if _not_of(na, nb) or _not_of(nb, na):
        return True
    # comparison-operator negation: `p == q` vs `p != q`, `p < q` vs `p >= q`, etc.
    _OPP = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.GtE, ast.GtE: ast.Lt,
            ast.Gt: ast.LtE, ast.LtE: ast.Gt}
    if (isinstance(na, ast.Compare) and isinstance(nb, ast.Compare)
            and len(na.ops) == 1 and len(nb.ops) == 1
            and ast.dump(na.left) == ast.dump(nb.left)
            and ast.dump(na.comparators[0]) == ast.dump(nb.comparators[0])
            and _OPP.get(type(na.ops[0])) is type(nb.ops[0])):
        return True
    return False


def _as_simple_compare(node):
    """`var OP literal` or `literal OP var` -> (var, op_type, number) for a single numeric
    comparison, else None."""
    if not (isinstance(node, ast.Compare) and len(node.ops) == 1):
        return None
    left, op, right = node.left, node.ops[0], node.comparators[0]
    if isinstance(left, ast.Name) and isinstance(right, ast.Constant) \
            and isinstance(right.value, (int, float)) and not isinstance(right.value, bool):
        return left.id, type(op), right.value
    if isinstance(right, ast.Name) and isinstance(left, ast.Constant) \
            and isinstance(left.value, (int, float)) and not isinstance(left.value, bool):
        flip = {ast.Lt: ast.Gt, ast.Gt: ast.Lt, ast.LtE: ast.GtE, ast.GtE: ast.LtE,
                ast.Eq: ast.Eq, ast.NotEq: ast.NotEq}
        return right.id, flip[type(op)], left.value
    return None


def _flatten_and(node) -> Optional[list]:
    """Flatten a pure conjunction into a list of conjuncts; None if any OR is present (we only
    prove UNSAT over conjunctions — a disjunction can rescue satisfiability)."""
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        return None
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        out = []
        for v in node.values:
            sub = _flatten_and(v)
            if sub is None:
                return None
            out.extend(sub)
        return out
    return [node]


def _is_always_false(cond: str) -> bool:
    """True when the condition can NEVER match: a falsy constant, or a conjunction with a
    single-variable interval contradiction (e.g. `visits < 4 and visits > 10`). The literal
    `false`/`never` keyword is a deliberate edge-disable and is NOT reported here."""
    node = _parse(cond)
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return not bool(node.value)
    conj = _flatten_and(node)
    if conj is None:
        return False
    lo: Dict[str, tuple] = {}   # var -> (value, inclusive)  tightest lower bound
    hi: Dict[str, tuple] = {}   # var -> (value, inclusive)  tightest upper bound
    for c in conj:
        parsed = _as_simple_compare(c)
        if parsed is None:
            continue
        var, op, num = parsed
        def tighten_lo(v, inc):
            cur = lo.get(var)
            if cur is None or v > cur[0] or (v == cur[0] and cur[1] and not inc):
                lo[var] = (v, inc)
        def tighten_hi(v, inc):
            cur = hi.get(var)
            if cur is None or v < cur[0] or (v == cur[0] and cur[1] and not inc):
                hi[var] = (v, inc)
        if op is ast.Gt:
            tighten_lo(num, False)
        elif op is ast.GtE:
            tighten_lo(num, True)
        elif op is ast.Lt:
            tighten_hi(num, False)
        elif op is ast.LtE:
            tighten_hi(num, True)
        elif op is ast.Eq:
            tighten_lo(num, True); tighten_hi(num, True)
        # `!=` doesn't tighten an interval (it punches a hole) -> ignored for UNSAT
    for var in set(lo) & set(hi):
        (lv, li), (hv, hi_inc) = lo[var], hi[var]
        if lv > hv or (lv == hv and not (li and hi_inc)):
            return True
    return False


# --------------------------------------------------------------------------------------
# Graph helpers
# --------------------------------------------------------------------------------------

def _reachable(graph) -> set:
    seen, stack = set(), [graph.start]
    while stack:
        cur = stack.pop()
        if cur in seen or cur not in graph.nodes:
            continue
        seen.add(cur)
        for tgt, _ in graph.nodes[cur].edges:
            if tgt in graph.nodes and tgt not in seen:
                stack.append(tgt)
    return seen


def _upstream_nodes(graph, node_name: str) -> set:
    """Returns the set of all node names that have a path to node_name and are reachable from start."""
    rev_adj = {}
    for name, n in graph.nodes.items():
        for tgt, _ in n.edges:
            rev_adj.setdefault(tgt, set()).add(name)
            
    seen = set()
    stack = [node_name]
    while stack:
        cur = stack.pop()
        for parent in rev_adj.get(cur, []):
            if parent not in seen:
                seen.add(parent)
                stack.append(parent)
    reach = _reachable(graph)
    return seen & reach



def _sccs(graph) -> List[set]:
    """Tarjan's strongly-connected components over the node graph."""
    import sys
    index = {}
    low = {}
    onstack = {}
    stack: List[str] = []
    out: List[set] = []
    counter = [0]
    # the recursion is one frame per node on a chain; raise the limit for very large flows so a
    # long path can't overflow the stack (restored in the finally below).
    _old_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(max(_old_limit, len(graph.nodes) * 4 + 100))

    def strong(v):
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v); onstack[v] = True
        for tgt, _ in graph.nodes[v].edges:
            if tgt not in graph.nodes:
                continue
            if tgt not in index:
                strong(tgt)
                low[v] = min(low[v], low[tgt])
            elif onstack.get(tgt):
                low[v] = min(low[v], index[tgt])
        if low[v] == index[v]:
            comp = set()
            while True:
                w = stack.pop(); onstack[w] = False
                comp.add(w)
                if w == v:
                    break
            out.append(comp)

    try:
        for v in graph.nodes:
            if v not in index:
                strong(v)
    finally:
        sys.setrecursionlimit(_old_limit)
    return out


def _has_self_loop(graph, node: str) -> bool:
    return any(tgt == node for tgt, _ in graph.nodes[node].edges)


# --------------------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------------------

def _check_structure(graph) -> List[Finding]:
    """Errors: undefined start, undefined edge targets, unsafe/unparseable predicates."""
    out: List[Finding] = []
    if graph.start not in graph.nodes:
        out.append(Finding("error", "undefined-start", None,
                           f"start node '{graph.start}' is not defined"))
    for name, n in graph.nodes.items():
        for tgt, cond in n.edges:
            if tgt not in graph.nodes:
                out.append(Finding("error", "undefined-target", name,
                                   f"edge -> '{tgt}' points at an undefined node"))
            for problem in predicates.check_predicate(cond):
                out.append(Finding("error", "unsafe-predicate", name, problem))
    return out


def _check_reachability(graph) -> List[Finding]:
    if graph.start not in graph.nodes:
        return []
    reach = _reachable(graph)
    out = [Finding("warning", "unreachable-node", name,
                   "node is unreachable from the start node")
           for name in graph.nodes if name not in reach]
    if not any(graph.nodes[name].terminal for name in reach):
        out.append(Finding("error", "no-terminal", None,
                           "no terminal node is reachable from the start — the flow can only "
                           "end at max_steps"))
    return out


def _check_stuck(graph) -> List[Finding]:
    """A node whose edges are ALL deterministic and not provably exhaustive can halt as
    `stuck` at runtime. A complementary `X`/`not X` pair, or a catch-all, makes it total."""
    out: List[Finding] = []
    for name, n in graph.nodes.items():
        if n.terminal:
            continue
        det = [(t, c) for t, c in n.edges if predicates.is_deterministic(c)]
        sem = [(t, c) for t, c in n.edges if predicates.is_semantic(c)]
        if sem or not det:
            continue  # a semantic edge always routes; a no-edge node is terminal
        if any(_is_always_true(c) for _, c in det):
            continue
        conds = [c for _, c in det]
        exhaustive = any(_negates(conds[i], conds[j])
                         for i in range(len(conds)) for j in range(i + 1, len(conds)))
        if not exhaustive:
            out.append(Finding("warning", "possible-stuck", name,
                               "deterministic-only node whose conditions are not provably "
                               "exhaustive — add an `else`/`always` edge (or a complementary "
                               "`when not …`) so it can't halt as stuck"))
    return out


def _check_shadowing(graph) -> List[Finding]:
    """Deterministic edges run first, in document order, first-true-wins. An always-true
    deterministic edge makes every later deterministic edge — and ALL semantic edges — dead."""
    out: List[Finding] = []
    for name, n in graph.nodes.items():
        det = [(i, t, c) for i, (t, c) in enumerate(n.edges) if predicates.is_deterministic(c)]
        first_true = next((i for (i, _t, c) in det if _is_always_true(c)), None)
        if first_true is None:
            continue
        for i, (t, c) in enumerate(n.edges):
            if i == first_true:
                continue
            # error/event edges route on their OWN tiers (a raise / a delivered event), so a
            # deterministic catch-all never shadows them — only when-predicates and semantic
            # edges compete with it.
            if predicates.is_error(c) or predicates.is_event(c):
                continue
            is_det = predicates.is_deterministic(c)
            if is_det and i > first_true:
                out.append(Finding("warning", "shadowed-edge", name,
                                   f"edge -> '{t}' is unreachable: an earlier catch-all edge "
                                   f"always matches first"))
            elif not is_det:
                out.append(Finding("warning", "shadowed-edge", name,
                                   f"semantic edge -> '{t}' is unreachable: a deterministic "
                                   f"catch-all on this node always matches first"))
    return out


def _check_error_shadowing(graph) -> List[Finding]:
    """Error edges are tried in document order, first-match-wins (the engine wraps the agent call and
    takes the first `on error` whose `when` holds). A BARE `on error` (no `when`) matches every
    exception, so any later conditional `on error [when …]` on the same node is dead — the same
    first-match hazard as a deterministic catch-all, in the error tier."""
    out: List[Finding] = []
    for name, n in graph.nodes.items():
        err = [(i, t, c) for i, (t, c) in enumerate(n.edges) if predicates.is_error(c)]
        first_bare = next((i for (i, _t, c) in err if not predicates.error_expr(c)), None)
        if first_bare is None:
            continue
        for i, t, c in err:
            if i > first_bare:
                out.append(Finding("warning", "shadowed-error-edge", name,
                                   f"error edge -> '{t}' is unreachable: an earlier unconditional "
                                   f"`on error` always matches first — order `on error when …` edges "
                                   f"before the bare `on error` catch-all"))
    return out


def _check_event_shadowing(graph) -> List[Finding]:
    """Event edges resume on a delivered signal, first-match-wins by event name (the engine's
    `eventTarget` returns the first `on event <name>` edge). Two edges on one node awaiting the SAME
    event make the second unreachable — the same first-match hazard as a deterministic catch-all or a
    bare `on error`, in the event tier. (Surfaced by the Journeyman cross-kernel comparison.)"""
    out: List[Finding] = []
    for name, n in graph.nodes.items():
        seen: Dict[str, str] = {}
        for t, c in n.edges:
            if not predicates.is_event(c):
                continue
            ev = predicates.event_name(c)
            if ev in seen:
                out.append(Finding("warning", "shadowed-event-edge", name,
                                   f"event edge -> '{t}' is unreachable: an earlier edge on this "
                                   f"node already awaits '{ev}' (first-match-wins)"))
            else:
                seen[ev] = t
    return out


def _check_cycles(graph) -> List[Finding]:
    """A cycle with no `visits`-based cap on any node in it is bounded only by max_steps."""
    out: List[Finding] = []
    for comp in _sccs(graph):
        is_cycle = len(comp) > 1 or any(_has_self_loop(graph, v) for v in comp)
        if not is_cycle:
            continue
        capped = any(_references_visits(c)
                     for v in comp for _, c in graph.nodes[v].edges)
        if not capped:
            members = ", ".join(sorted(comp))
            out.append(Finding("warning", "unbounded-cycle", sorted(comp)[0],
                               f"cycle ({members}) has no `visits`-based cap — it is bounded "
                               f"only by max_steps; add e.g. `-> give_up: when visits > N`"))
    return out


def _check_dead_and_dup(graph) -> List[Finding]:
    out: List[Finding] = []
    for name, n in graph.nodes.items():
        for t, c in n.edges:
            if _is_always_false(c):
                out.append(Finding("warning", "always-false-edge", name,
                                   f"edge -> '{t}' has a condition that is always false "
                                   f"(dead edge): {c!r}"))
        sem = [c for t, c in n.edges if predicates.is_semantic(c)]
        seen = set()
        for c in sem:
            key = c.strip().lower()
            if key in seen:
                out.append(Finding("warning", "duplicate-condition", name,
                                   f"duplicate semantic condition {c!r} — the two edges are a "
                                   f"guaranteed near-tie for the router"))
            seen.add(key)
    return out


ERROR_CODES = {"undefined-start", "undefined-target", "unsafe-predicate", "no-terminal"}


def _check_provenance(graph) -> List[Finding]:
    """Field provenance (opt-in, per `@emits`): every field a node's `when` edges READ must be a field
    the node DECLARES its worker emits, OR declared by an upstream node. A field read but never declared
    means the worker won't produce it and it is not in the state, so those edges fall through."""
    from prismpath import contract
    out: List[Finding] = []
    contracts = contract.derive_contract(graph)
    for name, node in graph.nodes.items():
        node_declared = contract.declared_emits(node)
        if node_declared is None:
            continue
        
        # Collect upstream declared fields
        upstream = _upstream_nodes(graph, name)
        upstream_declared = set()
        for u in upstream:
            unode = graph.nodes[u]
            udec = contract.declared_emits(unode)
            if udec:
                upstream_declared.update(udec)
                
        for f in sorted(set(contracts.get(name, {})) - node_declared - upstream_declared):
            out.append(Finding("warning", "undeclared-field", name,
                               f"a `when` edge reads field {f!r}, but neither this node's `@emits` "
                               f"nor any upstream node's `@emits` declares it"))
    return out



# declared @emits type token -> the derived-contract type family it must agree with
_EMIT_TYPE_FAMILY = {
    "bool": "boolean", "boolean": "boolean",
    "str": "string", "string": "string", "text": "string",
    "int": "number", "float": "number", "num": "number", "number": "number",
}


def _derived_family(spec: dict) -> Optional[str]:
    """Collapse a derived FieldSpec to a type family comparable with a declared token. An enum's
    family is that of its value literals; mixed/unknown collapses to None (no finding — the
    analyzer never guesses)."""
    t = spec.get("type")
    if t in ("boolean", "number", "string"):
        return t
    if t == "enum":
        vals = spec.get("values") or []
        if vals and all(isinstance(v, str) for v in vals):
            return "string"
        if vals and all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in vals):
            return "number"
    return None


def _check_emits_types(graph) -> List[Finding]:
    """Cross-check a TYPED `@emits(x=bool, ...)` declaration against the type the node's own `when`
    predicates INFER for the field (contract.derive_contract). A declaration that contradicts how the
    edges actually read the field means one of them is wrong — and the type_gate would enforce the
    inferred one, so surface the drift at author time. Untyped (bare) tokens and unrecognized type
    words are skipped: no false positives."""
    from prismpath import contract
    out: List[Finding] = []
    contracts = contract.derive_contract(graph)
    for name, node in graph.nodes.items():
        emits = node.annotations.get("emits") or {}
        derived = contracts.get(name, {})
        for field_name, token in sorted(emits.items()):
            if not token:
                continue                                   # bare @emits(x) — untyped, nothing to check
            want = _EMIT_TYPE_FAMILY.get(str(token).strip().lower())
            if want is None:
                continue                                   # unrecognized type word — don't guess
            spec = derived.get(field_name)
            if not spec:
                continue                                   # field not read by any predicate
            have = _derived_family(spec)
            if have is not None and have != want:
                out.append(Finding("warning", "emits-type-mismatch", name,
                                   f"`@emits({field_name}={token})` declares {want}, but this node's "
                                   f"`when` edges read {field_name!r} as {have} — the declaration and "
                                   f"the predicates disagree (the type_gate enforces the inferred "
                                   f"{have})"))
                                   
        # Upstream type checks (Task 3)
        upstream = _upstream_nodes(graph, name)
        upstream_emits = {}
        for u in upstream:
            unode = graph.nodes[u]
            uemits = unode.annotations.get("emits") or {}
            for f, token in uemits.items():
                if token:
                    want = _EMIT_TYPE_FAMILY.get(str(token).strip().lower())
                    if want:
                        # Store type family and node name that declared it
                        upstream_emits[f] = (want, u)
                        
        for field_name, spec in derived.items():
            if field_name not in emits and field_name in upstream_emits:
                want, u_node = upstream_emits[field_name]
                have = _derived_family(spec)
                if have is not None and have != want:
                    out.append(Finding("warning", "upstream-type-mismatch", name,
                                       f"a `when` edge reads field {field_name!r} as {have}, but upstream node "
                                       f"'{u_node}' declares it as {want} via `@emits` — the downstream "
                                       f"usage and upstream declaration disagree"))
    return out



def _check_field_only(graph) -> List[Finding]:
    """Field-only nodes (`@field_only`) route ONLY on declared structured fields, never on the worker's
    raw outcome text — the security property that keeps attacker-influenced free text out of routing. A
    semantic edge on such a node routes on raw text and is a violation; and its `when` fields must all be
    declared (an undeclared field would fall through to nothing)."""
    from prismpath import contract
    out: List[Finding] = []
    for name, node in graph.nodes.items():
        if "field_only" not in node.annotations:
            continue
        for t, c in node.edges:
            if predicates.is_semantic(c):
                out.append(Finding("error", "field-only-violation", name,
                                   f"`@field_only` node routes on RAW TEXT via a semantic edge -> "
                                   f"{t!r} ({c!r}); field-only nodes may route only on declared "
                                   f"structured fields (`when`/error/event edges)"))
        if contract.declared_emits(node) is None:
            out.append(Finding("error", "field-only-violation", name,
                               "`@field_only` node has no `@emits` declaration — nothing constrains "
                               "what the worker may emit, so 'field-only' cannot be enforced"))
    return out


def _check_spawn(graph) -> List[Finding]:
    """Fan-out / sub-flow composition checks decidable from THIS graph alone (roadmap item #4). A node
    that declares `@spawn(...)` will suspend awaiting its join event, so it MUST have the matching
    `on event <join>` edge or it deadlocks forever — the highest-value cross-nothing check (a missing
    join edge is the classic fan-out deadlock). The cross-FILE checks (does the child flow exist / have
    a terminal / satisfy `@expect`) need I/O and live in `analyze_composition`."""
    out: List[Finding] = []
    for name, node in graph.nodes.items():
        spawn = node.annotations.get("spawn")
        if spawn is None:
            continue
        if not spawn.get("child"):
            out.append(Finding("error", "spawn-no-child", name,
                               "`@spawn` requires `child=<flow.md>` naming the sub-flow to run per item"))
        want = predicates.spawn_join_event(spawn.get("join") or "all_done")
        have = {predicates.event_name(c) for _, c in node.edges if predicates.is_event(c)}
        if want not in have:
            out.append(Finding("error", "spawn-no-join-edge", name,
                               f"`@spawn` declares join={spawn.get('join') or 'all_done'!r} but the node "
                               f"has no `on event {want}` edge — it would suspend forever; add "
                               f"`-> <next>: on event {want}`"))
    return out


def analyze(graph) -> List[Finding]:
    """Run every decidable, IN-GRAPH check and return all findings (errors first, then warnings).
    Cross-flow-boundary composition checks (which read child flow FILES) are in `analyze_composition`,
    which the CLI runs additionally when it has the flow's path."""
    findings: List[Finding] = []
    findings += _check_structure(graph)
    findings += _check_reachability(graph)
    findings += _check_stuck(graph)
    findings += _check_shadowing(graph)
    findings += _check_event_shadowing(graph)
    findings += _check_error_shadowing(graph)
    findings += _check_provenance(graph)
    findings += _check_emits_types(graph)
    findings += _check_field_only(graph)
    findings += _check_spawn(graph)
    findings += _check_cycles(graph)
    findings += _check_dead_and_dup(graph)
    findings.sort(key=lambda f: (f.severity != "error", f.code, f.node or ""))
    return findings


def _has_reachable_terminal(graph) -> bool:
    reach = _reachable(graph)
    return any(graph.nodes[n].terminal for n in reach if n in graph.nodes)


def _child_emitted_fields(graph) -> set:
    """The fields a child flow DECLARES it emits (union of every node's `@emits(...)`). Empty if the
    child never declares — in which case the `@expect` cross-check stays silent (no false positives)."""
    out: set = set()
    for node in graph.nodes.values():
        emits = node.annotations.get("emits")
        if emits:
            out |= set(emits.keys())
    return out


def _child_emitted_types(graph) -> Dict[str, str]:
    """Returns a dict of {field_name: type_family} declared in the child flow's nodes."""
    out = {}
    for node in graph.nodes.values():
        emits = node.annotations.get("emits") or {}
        for f, t in emits.items():
            if t:
                family = _EMIT_TYPE_FAMILY.get(str(t).strip().lower())
                if family:
                    out[f] = family
    return out


def analyze_composition(graph, flow_path) -> List[Finding]:
    """Cross-FLOW-BOUNDARY checks for `@spawn` nodes (roadmap item #4, hard part 2). Unlike the pure
    `analyze()`, these do I/O — they resolve the child flow path (relative to `flow_path`'s dir), parse
    it, and reason across the two documents:
      * spawn-missing-child / spawn-child-unparseable — the referenced sub-flow must exist and parse;
      * spawn-child-no-terminal — the child must be able to REACH a terminal, else its runs never
        finish and the parent's join event never fires (a cross-file deadlock);
      * spawn-expect-unmet (warning) — a parent `@expect(fields)` must be covered by the child's
        `@emits` declarations, so the composition contract is checkable across the boundary.
    Composition is the stress test of the data-not-code thesis: the whole call tree is inspectable
    statically, no run required."""
    import os
    from prismpath.parser import parse_file
    out: List[Finding] = []
    base = os.path.dirname(os.path.abspath(os.fspath(flow_path)))
    for name, node in graph.nodes.items():
        spawn = node.annotations.get("spawn")
        if spawn is None or not spawn.get("child"):
            continue
        child = spawn["child"]
        cpath = child if os.path.isabs(child) else os.path.normpath(os.path.join(base, child))
        if not os.path.exists(cpath):
            out.append(Finding("error", "spawn-missing-child", name,
                               f"`@spawn(child={child!r})` does not resolve to a file ({cpath})"))
            continue
        try:
            child_graph = parse_file(cpath)
        except Exception as e:                        # noqa: BLE001
            out.append(Finding("error", "spawn-child-unparseable", name,
                               f"child flow {child!r} failed to parse: {e}"))
            continue
        if not _has_reachable_terminal(child_graph):
            out.append(Finding("error", "spawn-child-no-terminal", name,
                               f"child flow {child!r} has no reachable terminal node — its runs never "
                               f"finish, so the join event never fires"))
        expect = node.annotations.get("expect")
        emitted = _child_emitted_fields(child_graph)
        if expect and emitted:                        # only check when the child declares its outputs
            missing = [f for f in expect if f not in emitted]
            if missing:
                out.append(Finding("warning", "spawn-expect-unmet", name,
                                   f"`@expect{tuple(expect)}` but child {child!r} never `@emits` "
                                   f"{missing} — the composition contract is unmet (fix the field name "
                                   f"or declare it in the child)"))
            
            # Cross-check types (Task 3)
            child_types = _child_emitted_types(child_graph)
            for f, token in expect.items():
                if token and f in child_types:
                    want = _EMIT_TYPE_FAMILY.get(str(token).strip().lower())
                    have = child_types[f]
                    if want and have and want != have:
                        out.append(Finding("warning", "spawn-expect-type-mismatch", name,
                                           f"`@expect({f}={token})` expects {want}, but child {child!r} "
                                           f"declares {f!r} as {have} via `@emits` — the parent and child "
                                           f"types disagree"))
    return out



# --------------------------------------------------------------------------------------
# Portability (roadmap item #5): the ML-free subset. A flow is PORTABLE iff every edge on
# every REACHABLE node is decidable without a model — a `when` predicate, an error edge, or
# an event edge. Semantic (natural-language) edges need the embedder/LLM tier, so they are
# exactly the portability violations. A portable flow runs on the reference port
# (portable/prismpath.mjs — browser/edge/appliance) with routing identical to this engine.
# --------------------------------------------------------------------------------------

def portability(graph) -> List[Finding]:
    """Findings for every semantic edge on a reachable node (`not-portable-edge`, severity
    "warning" — a semantic edge is perfectly legal in the full engine; it only excludes the
    flow from the ML-free subset). Empty list == the flow is portable."""
    out: List[Finding] = []
    reach = _reachable(graph)
    for name in sorted(reach):
        node = graph.nodes.get(name)
        if node is None:
            continue
        for t, c in node.edges:
            if predicates.is_semantic(c):
                out.append(Finding("warning", "not-portable-edge", name,
                                   f"semantic edge -> {t!r} ({c!r}) needs the embedding/LLM tier; "
                                   f"rewrite as a `when <field …>` predicate (see @emits/@field_only) "
                                   f"to keep the flow in the ML-free portable subset"))
    return out


def portability_tree(graph, flow_path, _seen=None) -> List[Finding]:
    """`portability` across the WHOLE composition tree: this flow plus, recursively, every
    `@spawn` child (a portable parent spawning a non-portable child is not portable). Missing/
    unparseable children are already errors in `analyze_composition`, so here they're skipped;
    cyclic compositions are visited once (guarded), not looped."""
    import os
    from prismpath.parser import parse_file
    _seen = _seen or set()
    ap = os.path.abspath(os.fspath(flow_path))
    if ap in _seen:
        return []
    _seen = _seen | {ap}
    out = list(portability(graph))
    base = os.path.dirname(ap)
    for name, node in graph.nodes.items():
        spawn = node.annotations.get("spawn")
        if spawn is None or not spawn.get("child"):
            continue
        child = spawn["child"]
        cpath = child if os.path.isabs(child) else os.path.normpath(os.path.join(base, child))
        try:
            child_graph = parse_file(cpath)
        except Exception:                             # noqa: BLE001 - analyze_composition owns this error
            continue
        for f in portability_tree(child_graph, cpath, _seen):
            out.append(Finding(f.severity, f.code, f"{child}:{f.node}" if f.node else child, f.message))
    return out


def portability_tier(graph, flow_path) -> dict:
    """Stratify portability into the three deployment TIERS (a lint-computable flow property):

      * **P0** — every reachable edge is decidable (when/error/event). Zero ML: runs on the
        reference port (portable/prismpath.mjs) anywhere JavaScript runs.
      * **P1** — reachable semantic edges exist, but EVERY one of them is pinned in the flow's
        routing lockfile: the condition side is committed vectors, so routing needs only an
        OUTCOME-side embedder at runtime (an ONNX-able, ~35MB dependency) — portable to any
        appliance/edge host that can run a small encoder. Escalation stays optional.
      * **P2** — reachable semantic edges not fully covered by a lock: needs the full stack
        (live condition embedding and/or LLM escalation).

    Returns {tier, semantic_edges: [(node, target, condition)], unlocked: [condition, ...],
    lock: path|None}. Decidable from the document + its sidecar lock — no model, no execution."""
    reach = _reachable(graph)
    semantic = []
    for name in sorted(reach):
        node = graph.nodes.get(name)
        if node is None:
            continue
        for t, c in node.edges:
            if predicates.is_semantic(c):
                semantic.append((name, t, c))
    if not semantic:
        return {"tier": "P0", "semantic_edges": [], "unlocked": [], "lock": None}
    import os
    from prismpath import lockfile as _lf
    lp = _lf.lock_path(flow_path)
    locked_conds = set()
    lock_found = None
    if os.path.exists(lp):
        try:
            locked_conds = set(_lf.load_lock(lp).get("conditions", {}))
            lock_found = lp
        except Exception:                             # noqa: BLE001 - unreadable lock == no lock
            pass
    unlocked = sorted({c for _, _, c in semantic if c not in locked_conds})
    tier = "P1" if lock_found and not unlocked else "P2"
    return {"tier": tier, "semantic_edges": semantic, "unlocked": unlocked, "lock": lock_found}


def portability_tier_tree(graph, flow_path, _seen=None) -> dict:
    """The tier of a WHOLE composition tree: the max (worst) tier across this flow and,
    recursively, every `@spawn` child — a P0 parent spawning a P2 child deploys as P2. Returns
    {tier, flows: {path_or_ref: per-flow tier dict}}. Cycle-guarded like portability_tree."""
    import os
    from prismpath.parser import parse_file
    order = {"P0": 0, "P1": 1, "P2": 2}
    _seen = _seen or set()
    ap = os.path.abspath(os.fspath(flow_path))
    if ap in _seen:
        return {"tier": "P0", "flows": {}}
    _seen = _seen | {ap}
    mine = portability_tier(graph, flow_path)
    flows = {os.fspath(flow_path): mine}
    worst = mine["tier"]
    for name, node in graph.nodes.items():
        spawn = node.annotations.get("spawn")
        if spawn is None or not spawn.get("child"):
            continue
        child = spawn["child"]
        cpath = child if os.path.isabs(child) else os.path.normpath(os.path.join(os.path.dirname(ap), child))
        try:
            child_graph = parse_file(cpath)
        except Exception:                             # noqa: BLE001 - analyze_composition owns this error
            continue
        sub = portability_tier_tree(child_graph, cpath, _seen)
        flows.update(sub["flows"])
        if order[sub["tier"]] > order[worst]:
            worst = sub["tier"]
    return {"tier": worst, "flows": flows}
