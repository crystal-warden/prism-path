# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""model_check.py: Level M fragment classification + bounded model checking (`prismpath verify`).

Two capabilities over the decidable heart of a flow (SPEC §4.3, §7):

1. **Level M membership**: per-edge classification into the match-action fragment: boolean
   combinations of `field OP constant`, `field in [scalar literals]`, and bare-`field` atoms.
   A P0 flow whose deterministic edges are all in the fragment compiles to table-driven
   targets; SPEC §4.3 says linters SHOULD report membership, and this module is that report.

2. **Reachability / invariant checking**: "can node X ever be reached (under assumption Y)?",
   answered by explicit-state search where the *worker is adversarial*: at every node it may
   emit any fields. Routing follows the engine exactly - deterministic edges first, in document
   order, first true wins (an edge is takeable iff `assume ∧ pred_i ∧ ¬pred_1..i-1` is
   satisfiable); semantic edges only when no deterministic edge can match.

   Satisfiability is decided by **candidate enumeration against the real evaluator**
   (`predicates.eval_condition`), so the semantics can never drift from the engine: for Level M
   predicates the candidate partition is exhaustive and verdicts are exact; anything outside the
   fragment is *over-approximated* (treated as possibly-takeable), which keeps UNREACHABLE
   verdicts sound. Witness paths are labeled `certain` (every hop proven with a concrete
   example outcome) or `may` (some hop crosses an over-approximated edge - a semantic edge, an
   error raise, or an event resume).

   `visits` counters are modeled exactly, with saturation at (largest compared constant + 2),
   which makes the state space finite: when the search exhausts it, UNREACHABLE holds for **all**
   bounds, not just the explored depth. Human `choose=` overrides are out of scope - they bypass
   routing by design and are recorded as overrides, not decisions this checker predicts.
"""
from __future__ import annotations

import ast
import itertools
import json
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from prismpath.kernel import predicates
from prismpath.kernel.level_m import (  # the fragment definition lives one level down; re exported here
    _R_CHAINED, _R_FIELD_VS_FIELD, _R_SUBSTRING, _R_NONLITERAL, _R_STRING_ORDER, _R_CONSTANT, _R_NESTED, _R_SYNTAX, _ORDER_OPS, _EQ_OPS, _scalar_const, _atom_reason, _desugar_chains, _classify, is_level_m, level_m_report, flow_level_m,
)
from prismpath.kernel.parser import reachable as _reachable
from prismpath.kernel.predicates import expr_ast as _parse

def capability_report(graph) -> dict:
    """Which targets a flow compiles to, and - for the ones it doesn't - the edges that push it out.
    Composes flow_level_m with a reachable-semantic-edge scan: a portable, verifiable answer to
    "where does this flow run?", turning "runs everywhere" into a per-flow, machine-checked matrix."""
    reach = _reachable(graph)
    semantic = []
    for name in sorted(reach):
        node = graph.nodes.get(name)
        if node is None:
            continue
        for target, condition in node.edges:
            if predicates.is_semantic(condition):
                semantic.append({"node": name, "target": target, "condition": condition})
    p0 = not semantic
    lm_ok, lm_bad = flow_level_m(graph)
    hw_ok = p0 and lm_ok
    targets = {
        "python": {"status": "yes", "reason": None, "blocking_edges": []},
        "portable": {                                   # JS / Rust / Go portable kernels
            "status": "yes" if p0 else "needs-lockfile",
            "reason": None if p0 else
                f"{len(semantic)} reachable semantic edge(s) \u2014 P0 runs unconditionally; lock them for P1",
            "blocking_edges": [] if p0 else semantic,
        },
        "level_m_hardware": {                           # FPGA C-table (and the future eBPF target)
            "status": "yes" if hw_ok else "no",
            "reason": None if hw_ok else (
                f"{len(semantic)} reachable semantic edge(s) \u2014 not deterministic" if not p0
                else f"{len(lm_bad)} deterministic edge(s) outside the match-action fragment"),
            "blocking_edges": semantic if not p0 else ([] if hw_ok else lm_bad),
        },
    }
    return {"tier": "P0" if p0 else "P1/P2", "level_m": lm_ok, "targets": targets}


# ------------------------------------------------------------------ satisfiability core

_FRESH_STR = "\x00fresh"          # a string equal to no authored literal


def _constants(node) -> list:
    out = []
    for ast_node in ast.walk(node):
        if isinstance(ast_node, ast.Constant):
            out.append(ast_node.value)
    return out


def _fields_of(node) -> set:
    return {ast_node.id for ast_node in ast.walk(node) if isinstance(ast_node, ast.Name)}


def _candidates(consts: list) -> list:
    """A finite candidate set that hits every truth-region a Level M atom set can carve out of
    one field's value space: each mentioned constant, numeric neighbours + midpoints (for strict
    /non-strict interval boundaries), the falsy/truthy poles, a fresh string, and None (the
    missing-field case - central to the totality rule)."""
    nums = sorted({constant for constant in consts if isinstance(constant, (int, float)) and not isinstance(constant, bool)})
    cands: list = [None, True, False, 0, 1, "", _FRESH_STR]
    for constant in consts:
        cands.append(constant)
    for num in nums:
        cands.extend([num - 1, num + 1])
    for a, b in zip(nums, nums[1:]):
        cands.append((a + b) / 2)
    # dedupe preserving order (values may repeat; bool/int collisions are fine - both present)
    seen, out = set(), []
    for val in cands:
        val_key = (type(val).__name__, val if not isinstance(val, float) or val == val else "nan")
        if val_key not in seen:
            seen.add(val_key)
            out.append(val)
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
    det = [(index, target, condition) for index, (target, condition) in enumerate(node.edges) if predicates.is_deterministic(condition)]
    consts: list = []
    fields: set = set()
    complete = True
    exprs = [condition for _, _, condition in det] + ([assume] if assume else [])
    for condition in exprs:
        tree = _parse(condition)
        if tree is None:
            continue                        # keyword catch-alls carry no fields/constants
        consts.extend(_constants(tree))
        fields |= _fields_of(tree)
        ok, _ = is_level_m(condition)
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
        for index, _target, condition in sat.det:
            try:
                hit = predicates.eval_condition(condition, ctx)
            except predicates.PredicateError:
                hit = False                 # unsafe predicate never matches (engine parity)
            if hit:
                matched = index
                break
        if matched is None:
            if none_match is None:
                none_match = {key: val for key, val in ctx.items() if key != "visits"}
        elif matched not in takeable:
            takeable[matched] = {key: val for key, val in ctx.items() if key != "visits"}
    if not saw_ctx:                          # product cap tripped - nothing enumerated
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
                "witness": [{"node": step.node, "target": step.target, "condition": step.condition,
                             "via": step.via, "certainty": step.certainty, "example": step.example}
                            for step in self.witness]}


def _visit_caps(graph) -> Dict[str, int]:
    """Saturation cap per node whose predicates read `visits`: largest compared constant + 2
    (so both strict and non-strict boundaries stay distinguishable). Nodes that never compare
    visits are not tracked at all."""
    caps: Dict[str, int] = {}
    for name, node in graph.nodes.items():
        best = None
        for _target, condition in node.edges:
            cond = condition
            if predicates.is_error(condition):
                expr = predicates.error_expr(condition)            # '' | 'when <expr>' | '<expr>'
                if not expr:
                    continue
                cond = expr if expr.lower().startswith("when ") else "when " + expr
            tree = _parse(cond)
            if tree is None:
                continue
            if "visits" not in _fields_of(tree):
                continue
            nums = [val for val in _constants(tree) if isinstance(val, (int, float))
                    and not isinstance(val, bool)]
            max_val = max(nums) if nums else 0
            best = max(best or 0, int(max_val))
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
        counts_dict = dict(counts)
        counts_dict[node] = min(counts_dict.get(node, 0) + 1, caps[node])
        return tuple(sorted(counts_dict.items()))

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
            continue                        # terminal (or dangling target - analysis's problem)
        visits = dict(counts).get(node_name, 1)
        sat = sats[node_name]
        takeable, none_match = _edge_outcomes(sat, assume, visits)
        my_cert = best[state]

        moves: List[Tuple[int, Step]] = []
        for index, example_ctx in takeable.items():
            target, condition = node.edges[index]
            moves.append((index, Step(node_name, target, condition, "deterministic", my_cert, example_ctx)))
        if not sat.complete:
            # over-approximation: any det edge we couldn't prove takeable might still be
            for index, target, condition in sat.det:
                if index not in takeable:
                    moves.append((index, Step(node_name, target, condition, "deterministic", MAY, None)))
        if none_match is not False:         # the deterministic tier can fail -> semantic tier
            for index, (target, condition) in enumerate(node.edges):
                if predicates.is_semantic(condition):
                    moves.append((index, Step(node_name, target, condition, "semantic", MAY,
                                          none_match if isinstance(none_match, dict) else None)))
        if include_errors:
            for index, (target, condition) in enumerate(node.edges):
                if predicates.is_error(condition):
                    moves.append((index, Step(node_name, target, condition, "error", MAY, None)))
        if include_events:
            for index, (target, condition) in enumerate(node.edges):
                if predicates.is_event(condition):
                    moves.append((index, Step(node_name, target, condition, "event", MAY, None)))

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
        hits = [(state_item, cert_val) for state_item, cert_val in best.items() if state_item[0] == target]
        if not hits:
            results[target] = ReachResult(target, "no", proven=exhausted, depth=None)
            continue
        cert_hit = next((state_item for state_item, cert_val in hits if cert_val == CERTAIN), None)
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
    verify_parser = subparsers.add_parser(
        'verify', help='Bounded model checking over the decidable tiers: can a node be reached '
                       '(under an assumption)? Exact over Level M; sound over-approximation '
                       'outside it. No model, no execution.')
    verify_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    verify_parser.add_argument('--reach', action='append', default=[], metavar='NODE',
                               help='assert NODE is reachable (exit 1 if not); repeatable')
    verify_parser.add_argument('--forbid', action='append', default=[], metavar='NODE',
                               help='assert NODE can NEVER be reached (exit 1 if reachable or may-reachable); '
                                    'repeatable')
    verify_parser.add_argument('--assume', default=None, metavar='EXPR',
                               help='a `when`-style constraint every worker outcome satisfies, '
                                    'e.g. --assume "amount <= 500"')
    verify_parser.add_argument('--bound', type=int, default=25,
                               help='search depth limit in steps (default 25, the engine max_steps default)')
    verify_parser.add_argument('--no-errors', action='store_true',
                               help='exclude error-tier paths (assume workers never raise)')
    verify_parser.add_argument('--no-events', action='store_true',
                               help='exclude event-tier paths (assume suspended runs are never resumed)')
    verify_parser.add_argument('--level-m', action='store_true',
                               help='also report per-edge match-action fragment membership (SPEC §4.3)')
    verify_parser.add_argument('--json', action='store_true', help='machine-readable output')
    verify_parser.set_defaults(func=verify_cmd)

    capability_parser = subparsers.add_parser(
        'capability', help='Report which targets a flow compiles to (python / portable js-rust-go / '
                           'Level M hardware) and, for the ones it does not, the blocking edges.')
    capability_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    capability_parser.add_argument('--json', action='store_true', help='machine-readable output')
    capability_parser.set_defaults(func=capability_cmd)

    context_parser = subparsers.add_parser(
        'context', help='Emit the verified facts PrismPath can PROVE about a flow (nodes, edges, '
                        'declared fields, reachability, Level M, capability) as grounding for an '
                        'agent authoring or editing it.')
    context_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    context_parser.add_argument('--json', action='store_true', help='machine-readable output')
    context_parser.set_defaults(func=_run_context_cmd)


def _run_context_cmd(command_args) -> int:
    # Importing directly from kernel.flow_context avoids deprecation warnings emitted by legacy root shims.
    from prismpath.kernel.flow_context import context_cmd
    return context_cmd(command_args)


def verify_cmd(args) -> int:
    from prismpath.kernel.parser import parse_file
    graph = parse_file(args.flow_md)
    targets = list(dict.fromkeys(args.reach + args.forbid)) or sorted(graph.nodes)
    results = check_reach(graph, targets, assume=args.assume, bound=args.bound,
                          include_errors=not args.no_errors,
                          include_events=not args.no_events)
    ok = True
    for node_name in args.reach:
        if results[node_name].reachable == "no":
            ok = False
    for node_name in args.forbid:
        if results[node_name].reachable != "no":
            ok = False

    lm_all, lm_bad = flow_level_m(graph)
    payload = {"ok": ok, "assume": args.assume, "bound": args.bound,
               "results": {node_name: res.as_dict() for node_name, res in results.items()},
               "level_m": {"flow": lm_all, "non_member_edges": lm_bad}
               if args.level_m else None}
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0 if ok else 1

    for name in targets:
        res = results[name]
        mark = {"yes": "●", "may": "◐", "no": "○"}[res.reachable]
        label = {"yes": "REACHABLE", "may": "MAY-REACH", "no": "UNREACHABLE"}[res.reachable]
        proof = " (proven for all bounds)" if res.reachable == "no" and res.proven else \
                (" (within bound only)" if res.reachable == "no" else "")
        flag = ""
        if name in args.forbid and res.reachable != "no":
            flag = "  ✗ FORBIDDEN"
        if name in args.reach and res.reachable == "no":
            flag = "  ✗ REQUIRED"
        print(f"  {mark} {name}: {label}{proof}{flag}")
        for step in res.witness:
            example_str = f"  e.g. {step.example}" if step.example else ""
            print(f"      {step.node} -> {step.target}  [{step.via}, {step.certainty}] {step.condition!r}{example_str}")
    if args.level_m:
        if lm_all:
            print("  ▦ Level M: every deterministic edge is in the match-action fragment")
        else:
            print(f"  ▦ Level M: {len(lm_bad)} edge(s) outside the fragment:")
            for bad_item in lm_bad:
                print(f"      [{bad_item['node']}] -> {bad_item['target']}  {bad_item['condition']!r}  ({bad_item['reason']})")
    print(f"  {'✅ verified' if ok else '✗ verification failed'}")
    return 0 if ok else 1


def capability_cmd(args) -> int:
    from prismpath.kernel.parser import parse_file
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
            line += f"  - {tgt['reason']}"
        print(line)
        for edge in tgt.get("blocking_edges", []):
            extra = f"  ({edge['reason']})" if edge.get("reason") else ""
            print(f"        · {edge['node']} -> {edge['target']}: {edge['condition']}{extra}")
    return 0
