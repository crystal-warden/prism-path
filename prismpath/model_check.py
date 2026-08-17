# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""model_check.py — Level M fragment classification + bounded model checking (`prismpath verify`).

Two capabilities over the decidable heart of a flow (SPEC §4.3, §7):

1. **Level M membership** — per-edge classification into the match-action fragment: boolean
   combinations of `field OP constant`, `field in [scalar literals]`, and bare-`field` atoms.
   A P0 flow whose deterministic edges are all in the fragment compiles to table-driven
   targets; SPEC §4.3 says linters SHOULD report membership, and this module is that report.

2. **Reachability / invariant checking** — "can node X ever be reached (under assumption Y)?",
   answered by explicit-state search where the *worker is adversarial*: at every node it may
   emit any fields. Routing follows the engine exactly — deterministic edges first, in document
   order, first true wins (an edge is takeable iff `assume ∧ pred_i ∧ ¬pred_1..i-1` is
   satisfiable); semantic edges only when no deterministic edge can match.

   Satisfiability is decided by **candidate enumeration against the real evaluator**
   (`predicates.eval_condition`), so the semantics can never drift from the engine: for Level M
   predicates the candidate partition is exhaustive and verdicts are exact; anything outside the
   fragment is *over-approximated* (treated as possibly-takeable), which keeps UNREACHABLE
   verdicts sound. Witness paths are labeled `certain` (every hop proven with a concrete
   example outcome) or `may` (some hop crosses an over-approximated edge — a semantic edge, an
   error raise, or an event resume).

   `visits` counters are modeled exactly, with saturation at (largest compared constant + 2),
   which makes the state space finite: when the search exhausts it, UNREACHABLE holds for **all**
   bounds, not just the explored depth. Human `choose=` overrides are out of scope — they bypass
   routing by design and are recorded as overrides, not decisions this checker predicts.
"""
from __future__ import annotations

import ast
import itertools
import json
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from prismpath import predicates
from prismpath.analysis import _parse, _reachable

# ------------------------------------------------------------------ Level M classification

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


def capability_report(graph) -> dict:
    """Which targets a flow compiles to, and — for the ones it doesn't — the edges that push it out.
    Composes flow_level_m with a reachable-semantic-edge scan: a portable, verifiable answer to
    "where does this flow run?", turning "runs everywhere" into a per-flow, machine-checked matrix."""
    reach = _reachable(graph)
    semantic = []
    for name in sorted(reach):
        node = graph.nodes.get(name)
        if node is None:
            continue
        for t, c in node.edges:
            if predicates.is_semantic(c):
                semantic.append({"node": name, "target": t, "condition": c})
    p0 = not semantic
    lm_ok, lm_bad = flow_level_m(graph)
    hw_ok = p0 and lm_ok
    targets = {
        "python": {"status": "yes", "reason": None, "blocking_edges": []},
        "portable": {                                   # JS / Rust / Go portable kernels
            "status": "yes" if p0 else "needs-lockfile",
            "reason": None if p0 else
                f"{len(semantic)} reachable semantic edge(s) — P0 runs unconditionally; lock them for P1",
            "blocking_edges": [] if p0 else semantic,
        },
        "level_m_hardware": {                           # FPGA C-table (and the future eBPF target)
            "status": "yes" if hw_ok else "no",
            "reason": None if hw_ok else (
                f"{len(semantic)} reachable semantic edge(s) — not deterministic" if not p0
                else f"{len(lm_bad)} deterministic edge(s) outside the match-action fragment"),
            "blocking_edges": semantic if not p0 else ([] if hw_ok else lm_bad),
        },
    }
    return {"tier": "P0" if p0 else "P1/P2", "level_m": lm_ok, "targets": targets}


# ------------------------------------------------------------------ satisfiability core

_FRESH_STR = "\x00fresh"          # a string equal to no authored literal


def _constants(node) -> list:
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Constant):
            out.append(n.value)
    return out


def _fields_of(node) -> set:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _candidates(consts: list) -> list:
    """A finite candidate set that hits every truth-region a Level M atom set can carve out of
    one field's value space: each mentioned constant, numeric neighbours + midpoints (for strict
    /non-strict interval boundaries), the falsy/truthy poles, a fresh string, and None (the
    missing-field case — central to the totality rule)."""
    nums = sorted({c for c in consts if isinstance(c, (int, float)) and not isinstance(c, bool)})
    cands: list = [None, True, False, 0, 1, "", _FRESH_STR]
    for c in consts:
        cands.append(c)
    for n in nums:
        cands.extend([n - 1, n + 1])
    for a, b in zip(nums, nums[1:]):
        cands.append((a + b) / 2)
    # dedupe preserving order (values may repeat; bool/int collisions are fine — both present)
    seen, out = set(), []
    for v in cands:
        k = (type(v).__name__, v if not isinstance(v, float) or v == v else "nan")
        if k not in seen:
            seen.add(k)
            out.append(v)
    return out


_PRODUCT_CAP = 50_000


@dataclass
class _NodeSat:
    """Precomputed satisfiability machinery for one node's deterministic edges (+ assume)."""
    det: List[Tuple[int, str, str]]        # (edge_index, target, condition) in document order
    fields: List[str]
    cands: list
    complete: bool                          # candidate partition exhaustive for these predicates?

    def contexts(self, visits: int):
        if not self.fields:
            yield {"visits": visits}
            return
        total = 1
        for _ in self.fields:
            total *= len(self.cands)
            if total > _PRODUCT_CAP:
                return                      # caller treats as incomplete
        for combo in itertools.product(self.cands, repeat=len(self.fields)):
            ctx = dict(zip(self.fields, combo))
            ctx["visits"] = visits
            yield ctx


def _node_sat(graph, name: str, assume: Optional[str]) -> _NodeSat:
    node = graph.nodes[name]
    det = [(i, t, c) for i, (t, c) in enumerate(node.edges) if predicates.is_deterministic(c)]
    consts: list = []
    fields: set = set()
    complete = True
    exprs = [c for _, _, c in det] + ([assume] if assume else [])
    for cond in exprs:
        tree = _parse(cond)
        if tree is None:
            continue                        # keyword catch-alls carry no fields/constants
        consts.extend(_constants(tree))
        fields |= _fields_of(tree)
        ok, _ = is_level_m(cond)
        if not ok:
            complete = False                # partition may miss regions -> over-approximate
    fields.discard("visits")                # modeled concretely by the search
    cands = _candidates(consts)
    n_fields = sorted(fields)
    total = 1
    for _ in n_fields:
        total *= len(cands)
    if total > _PRODUCT_CAP:
        complete = False
    return _NodeSat(det=det, fields=n_fields, cands=cands, complete=complete)


def _edge_outcomes(sat: _NodeSat, assume: Optional[str], visits: int):
    """For one node entry: which deterministic edges are takeable (with a concrete witness ctx),
    and can the deterministic tier fail entirely (releasing semantic edges)?

    Returns (takeable: {edge_idx: example_ctx}, none_match_example: ctx|None|False).
    `none_match_example` is False when *provably* some deterministic edge always matches."""
    takeable: Dict[int, dict] = {}
    none_match: object = None
    saw_ctx = False
    for ctx in sat.contexts(visits):
        saw_ctx = True
        if assume is not None:
            try:
                if not predicates.eval_condition(assume, ctx):
                    continue
            except predicates.PredicateError:
                continue
        matched = None
        for idx, _t, cond in sat.det:
            try:
                hit = predicates.eval_condition(cond, ctx)
            except predicates.PredicateError:
                hit = False                 # unsafe predicate never matches (engine parity)
            if hit:
                matched = idx
                break
        if matched is None:
            if none_match is None:
                none_match = {k: v for k, v in ctx.items() if k != "visits"}
        elif matched not in takeable:
            takeable[matched] = {k: v for k, v in ctx.items() if k != "visits"}
    if not saw_ctx:                          # product cap tripped — nothing enumerated
        return {}, None
    if sat.complete and none_match is None:
        none_match = False
    return takeable, none_match


# ------------------------------------------------------------------ the reachability search

CERTAIN, MAY = "certain", "may"


@dataclass
class Step:
    node: str
    target: str
    condition: str
    via: str                                 # deterministic | semantic | error | event
    certainty: str                           # certain | may
    example: Optional[dict] = None           # a concrete outcome that takes the edge


@dataclass
class ReachResult:
    node: str
    reachable: str                           # "yes" | "may" | "no"
    proven: bool                             # "no" verdicts: state space exhausted (all bounds)
    depth: Optional[int]
    witness: List[Step] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"node": self.node, "reachable": self.reachable, "proven": self.proven,
                "depth": self.depth,
                "witness": [{"node": s.node, "target": s.target, "condition": s.condition,
                             "via": s.via, "certainty": s.certainty, "example": s.example}
                            for s in self.witness]}


def _visit_caps(graph) -> Dict[str, int]:
    """Saturation cap per node whose predicates read `visits`: largest compared constant + 2
    (so both strict and non-strict boundaries stay distinguishable). Nodes that never compare
    visits are not tracked at all."""
    caps: Dict[str, int] = {}
    for name, node in graph.nodes.items():
        best = None
        for _t, c in node.edges:
            cond = c
            if predicates.is_error(c):
                expr = predicates.error_expr(c)            # '' | 'when <expr>' | '<expr>'
                if not expr:
                    continue
                cond = expr if expr.lower().startswith("when ") else "when " + expr
            tree = _parse(cond)
            if tree is None:
                continue
            if "visits" not in _fields_of(tree):
                continue
            nums = [v for v in _constants(tree) if isinstance(v, (int, float))
                    and not isinstance(v, bool)]
            m = max(nums) if nums else 0
            best = max(best or 0, int(m))
        if best is not None:
            caps[name] = best + 2
    return caps


def check_reach(graph, targets: List[str], assume: Optional[str] = None,
                bound: int = 25, include_errors: bool = True,
                include_events: bool = True) -> Dict[str, ReachResult]:
    """Adversarial-worker reachability for each target node. See module docstring for the
    semantics; `bound` limits search depth (steps), matching the engine's max_steps default."""
    if assume is not None and not assume.strip().lower().startswith("when "):
        assume = "when " + assume
    caps = _visit_caps(graph)
    sats = {name: _node_sat(graph, name, assume) for name in graph.nodes}

    def bump(counts: tuple, node: str) -> tuple:
        if node not in caps:
            return counts
        d = dict(counts)
        d[node] = min(d.get(node, 0) + 1, caps[node])
        return tuple(sorted(d.items()))

    start_state = (graph.start, bump((), graph.start))
    # state -> best certainty seen; parents for witness reconstruction
    best: Dict[tuple, str] = {start_state: CERTAIN}
    parent: Dict[tuple, Tuple[tuple, Step]] = {}
    frontier = deque([(start_state, 0)])
    depth_of = {start_state: 0}
    exhausted = True

    while frontier:
        state, depth = frontier.popleft()
        node_name, counts = state
        if depth >= bound:
            exhausted = False               # cut by the bound, not by the state space
            continue
        node = graph.nodes.get(node_name)
        if node is None or not node.edges:
            continue                        # terminal (or dangling target — analysis's problem)
        visits = dict(counts).get(node_name, 1)
        sat = sats[node_name]
        takeable, none_match = _edge_outcomes(sat, assume, visits)
        my_cert = best[state]

        moves: List[Tuple[int, Step]] = []
        for idx, ex in takeable.items():
            t, c = node.edges[idx]
            moves.append((idx, Step(node_name, t, c, "deterministic", my_cert, ex)))
        if not sat.complete:
            # over-approximation: any det edge we couldn't prove takeable might still be
            for idx, t, c in sat.det:
                if idx not in takeable:
                    moves.append((idx, Step(node_name, t, c, "deterministic", MAY, None)))
        if none_match is not False:         # the deterministic tier can fail -> semantic tier
            for i, (t, c) in enumerate(node.edges):
                if predicates.is_semantic(c):
                    moves.append((i, Step(node_name, t, c, "semantic", MAY,
                                          none_match if isinstance(none_match, dict) else None)))
        if include_errors:
            for i, (t, c) in enumerate(node.edges):
                if predicates.is_error(c):
                    moves.append((i, Step(node_name, t, c, "error", MAY, None)))
        if include_events:
            for i, (t, c) in enumerate(node.edges):
                if predicates.is_event(c):
                    moves.append((i, Step(node_name, t, c, "event", MAY, None)))

        for _idx, step in moves:
            if step.target not in graph.nodes:
                continue
            cert = CERTAIN if (my_cert == CERTAIN and step.certainty == CERTAIN) else MAY
            step.certainty = cert
            nstate = (step.target, bump(counts, step.target))
            prev = best.get(nstate)
            if prev is None or (prev == MAY and cert == CERTAIN):
                best[nstate] = cert
                parent[nstate] = (state, step)
                depth_of[nstate] = depth + 1
                frontier.append((nstate, depth + 1))

    results: Dict[str, ReachResult] = {}
    for target in targets:
        hits = [(s, c) for s, c in best.items() if s[0] == target]
        if not hits:
            results[target] = ReachResult(target, "no", proven=exhausted, depth=None)
            continue
        cert_hit = next((s for s, c in hits if c == CERTAIN), None)
        state = cert_hit or hits[0][0]
        verdict = "yes" if cert_hit else "may"
        # reconstruct the witness
        steps: List[Step] = []
        cur = state
        while cur in parent:
            prev, step = parent[cur]
            steps.append(step)
            cur = prev
        steps.reverse()
        results[target] = ReachResult(target, verdict, proven=False,
                                      depth=depth_of.get(state), witness=steps)
    return results


# ------------------------------------------------------------------ CLI (`prismpath verify`)

def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        'verify', help='Bounded model checking over the decidable tiers: can a node be reached '
                       '(under an assumption)? Exact over Level M; sound over-approximation '
                       'outside it. No model, no execution.')
    p.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    p.add_argument('--reach', action='append', default=[], metavar='NODE',
                   help='assert NODE is reachable (exit 1 if not); repeatable')
    p.add_argument('--forbid', action='append', default=[], metavar='NODE',
                   help='assert NODE can NEVER be reached (exit 1 if reachable or may-reachable); '
                        'repeatable')
    p.add_argument('--assume', default=None, metavar='EXPR',
                   help='a `when`-style constraint every worker outcome satisfies, '
                        'e.g. --assume "amount <= 500"')
    p.add_argument('--bound', type=int, default=25,
                   help='search depth limit in steps (default 25, the engine max_steps default)')
    p.add_argument('--no-errors', action='store_true',
                   help='exclude error-tier paths (assume workers never raise)')
    p.add_argument('--no-events', action='store_true',
                   help='exclude event-tier paths (assume suspended runs are never resumed)')
    p.add_argument('--level-m', action='store_true',
                   help='also report per-edge match-action fragment membership (SPEC §4.3)')
    p.add_argument('--json', action='store_true', help='machine-readable output')
    p.set_defaults(func=verify_cmd)

    cp = subparsers.add_parser(
        'capability', help='Report which targets a flow compiles to (python / portable js-rust-go / '
                           'Level M hardware) and, for the ones it does not, the blocking edges.')
    cp.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    cp.add_argument('--json', action='store_true', help='machine-readable output')
    cp.set_defaults(func=capability_cmd)

    xp = subparsers.add_parser(
        'context', help='Emit the verified facts PrismPath can PROVE about a flow (nodes, edges, '
                        'declared fields, reachability, Level M, capability) as grounding for an '
                        'agent authoring or editing it.')
    xp.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    xp.add_argument('--json', action='store_true', help='machine-readable output')
    xp.set_defaults(func=lambda a: __import__('prismpath.flow_context', fromlist=['context_cmd'])
                    .context_cmd(a))


def verify_cmd(args) -> int:
    from prismpath.parser import parse_file
    graph = parse_file(args.flow_md)
    targets = list(dict.fromkeys(args.reach + args.forbid)) or sorted(graph.nodes)
    results = check_reach(graph, targets, assume=args.assume, bound=args.bound,
                          include_errors=not args.no_errors,
                          include_events=not args.no_events)
    ok = True
    for n in args.reach:
        if results[n].reachable == "no":
            ok = False
    for n in args.forbid:
        if results[n].reachable != "no":
            ok = False

    lm_all, lm_bad = flow_level_m(graph)
    payload = {"ok": ok, "assume": args.assume, "bound": args.bound,
               "results": {n: r.as_dict() for n, r in results.items()},
               "level_m": {"flow": lm_all, "non_member_edges": lm_bad}
               if args.level_m else None}
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0 if ok else 1

    for name in targets:
        r = results[name]
        mark = {"yes": "●", "may": "◐", "no": "○"}[r.reachable]
        label = {"yes": "REACHABLE", "may": "MAY-REACH", "no": "UNREACHABLE"}[r.reachable]
        proof = " (proven for all bounds)" if r.reachable == "no" and r.proven else \
                (" (within bound only)" if r.reachable == "no" else "")
        flag = ""
        if name in args.forbid and r.reachable != "no":
            flag = "  ✗ FORBIDDEN"
        if name in args.reach and r.reachable == "no":
            flag = "  ✗ REQUIRED"
        print(f"  {mark} {name}: {label}{proof}{flag}")
        for s in r.witness:
            ex = f"  e.g. {s.example}" if s.example else ""
            print(f"      {s.node} -> {s.target}  [{s.via}, {s.certainty}] {s.condition!r}{ex}")
    if args.level_m:
        if lm_all:
            print("  ▦ Level M: every deterministic edge is in the match-action fragment")
        else:
            print(f"  ▦ Level M: {len(lm_bad)} edge(s) outside the fragment:")
            for r in lm_bad:
                print(f"      [{r['node']}] -> {r['target']}  {r['condition']!r}  ({r['reason']})")
    print(f"  {'✅ verified' if ok else '✗ verification failed'}")
    return 0 if ok else 1


def capability_cmd(args) -> int:
    from prismpath.parser import parse_file
    rep = capability_report(parse_file(args.flow_md))
    if args.json:
        print(json.dumps(rep, indent=2))
        return 0
    mark = {"yes": "✓", "needs-lockfile": "◐", "no": "✗"}
    names = {"python": "python (reference)", "portable": "portable (js / rust / go)",
             "level_m_hardware": "level-m hardware (fpga c-table / eBPF)"}
    print(f"  tier: {rep['tier']}   level_m: {rep['level_m']}")
    for key, tgt in rep["targets"].items():
        line = f"  {mark.get(tgt['status'], '?')} {names.get(key, key):34} {tgt['status']}"
        if tgt["reason"]:
            line += f"  — {tgt['reason']}"
        print(line)
        for e in tgt.get("blocking_edges", []):
            extra = f"  ({e['reason']})" if e.get("reason") else ""
            print(f"        · {e['node']} -> {e['target']}: {e['condition']}{extra}")
    return 0
