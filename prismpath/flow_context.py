# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Verified-flow-facts as agent context.

PrismPath owns the control plane and can *prove* things about a flow graph — which nodes exist, how
edges route, which fields are declared, what is reachable (`model_check.check_reach`), whether the flow
is Level M (`model_check.flow_level_m`), and which targets it compiles to (`model_check.capability_report`).
This module packages exactly those proven facts as grounding for an agent authoring or editing a flow.

The distinction that keeps this in scope (see the guard, which is out of scope): this is the kernel
*publishing its own proofs*, not shaping how the model behaves. An agent handed this context cannot
route to a node that does not exist or add an edge to a node PrismPath proved unreachable — because the
ground truth is stated, and it is a proof, not a retrieval.

Everything here composes existing primitives; it computes no new analysis of its own.
"""
from __future__ import annotations

import ast
from typing import Dict, List

from prismpath import predicates
from prismpath.analysis import _parse, _reachable, analyze
from prismpath.model_check import capability_report, check_reach, flow_level_m


def _via(cond: str) -> str:
    """Classify an edge condition into its routing tier (the order matters: error/event first)."""
    if predicates.is_error(cond):
        return "error"
    if predicates.is_event(cond):
        return "event"
    if predicates.is_deterministic(cond):
        return "deterministic"
    if predicates.is_semantic(cond):
        return "semantic"
    return "unknown"


def _fields_in(cond: str) -> set:
    """Field names read by a deterministic condition (empty for semantic/keyword edges)."""
    if not predicates.is_deterministic(cond):
        return set()
    expr = predicates._expr_of(cond)
    if expr.lower() in predicates.ALWAYS or expr.lower() in predicates.NEVER:
        return set()
    tree = _parse(cond)
    if tree is None:
        return set()
    return {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}


def flow_context(graph) -> dict:
    """The complete bundle of facts PrismPath can PROVE about `graph`, as machine-readable JSON.

    Keys:
      name, start, n_nodes, n_edges
      nodes[]        — {name, terminal, annotations[], edges[{target, condition, via}]}
      fields[]       — every field name read by a deterministic edge, flow-wide
      terminal_nodes[]
      reachability   — {node: {reachable: yes|may|no, proven, depth}}  (adversarial-worker, proven)
      unreachable_nodes[]
      level_m        — {flow: bool, non_member_edges: [...]}
      capability     — capability_report(): tier + per-target compile status + blocking edges
      findings[]     — analysis.analyze(): errors + warnings ({severity, code, node, message})
    """
    nodes = []
    fields: set = set()
    for name, node in graph.nodes.items():          # authored order (dict preserves insertion)
        edges = []
        for t, c in node.edges:
            edges.append({"target": t, "condition": c, "via": _via(c)})
            fields |= _fields_in(c)
        nodes.append({
            "name": name,
            "terminal": node.terminal,
            "annotations": sorted(node.annotations.keys()),
            "edges": edges,
        })

    reach = check_reach(graph, sorted(graph.nodes))
    reachability = {n: {"reachable": r.reachable, "proven": r.proven, "depth": r.depth}
                    for n, r in reach.items()}
    lm_ok, lm_bad = flow_level_m(graph)

    return {
        "name": graph.name,
        "start": graph.start,
        "n_nodes": len(graph.nodes),
        "n_edges": sum(len(n.edges) for n in graph.nodes.values()),
        "nodes": nodes,
        "fields": sorted(fields),
        "terminal_nodes": sorted(n for n, nd in graph.nodes.items() if nd.terminal),
        "reachability": reachability,
        "unreachable_nodes": sorted(n for n, r in reachability.items()
                                    if r["reachable"] == "no"),
        "level_m": {"flow": lm_ok, "non_member_edges": lm_bad},
        "capability": capability_report(graph),
        "findings": [f.as_dict() for f in analyze(graph)],
    }


def render_context(facts: dict) -> str:
    """LLM-facing rendering of `flow_context`: a compact, prose block of PROVEN facts an agent must
    not contradict. Every line here is machine-checked, not asserted by the model."""
    L: List[str] = []
    L.append(f"# Verified facts about flow '{facts['name']}' "
             f"(proven by PrismPath — ground truth, do not contradict)")
    L.append(f"Start node: {facts['start']}")
    L.append(f"Nodes ({facts['n_nodes']}): " + ", ".join(n["name"] for n in facts["nodes"]))
    if facts["terminal_nodes"]:
        L.append("Terminal nodes (no outgoing edges): " + ", ".join(facts["terminal_nodes"]))
    L.append(f"Declared fields (read by deterministic edges): "
             + (", ".join(facts["fields"]) if facts["fields"] else "(none)"))
    L.append("")
    L.append("Edges (source -> target [tier]  condition):")
    for n in facts["nodes"]:
        for e in n["edges"]:
            L.append(f"  {n['name']} -> {e['target']}  [{e['via']}]  {e['condition']!r}")
    L.append("")
    L.append("Reachability (adversarial-worker analysis, proven):")
    mark = {"yes": "reachable", "may": "may be reachable", "no": "UNREACHABLE"}
    for node, r in facts["reachability"].items():
        proof = " (proven for all bounds)" if r["reachable"] == "no" and r["proven"] else ""
        L.append(f"  {node}: {mark[r['reachable']]}{proof}")
    if facts["unreachable_nodes"]:
        L.append("  -> unreachable nodes: " + ", ".join(facts["unreachable_nodes"]))
    L.append("")
    lm = facts["level_m"]
    if lm["flow"]:
        L.append("Level M: YES — every deterministic edge is in the hardware match-action fragment.")
    else:
        L.append(f"Level M: NO — {len(lm['non_member_edges'])} deterministic edge(s) outside the fragment:")
        for r in lm["non_member_edges"]:
            L.append(f"  [{r['node']}] -> {r['target']}  {r['condition']!r}  ({r['reason']})")
    cap = facts["capability"]
    L.append(f"Compiles to: tier {cap['tier']} — "
             + ", ".join(f"{k}={v['status']}" for k, v in cap["targets"].items()))
    if facts["findings"]:
        L.append("")
        L.append("Static findings:")
        for f in facts["findings"]:
            where = f"[{f['node']}] " if f["node"] else ""
            L.append(f"  {f['severity']}: {where}{f['message']} ({f['code']})")
    return "\n".join(L)


def context_cmd(args) -> int:
    import json
    from prismpath.parser import parse_file
    facts = flow_context(parse_file(args.flow_md))
    print(json.dumps(facts, indent=2) if args.json else render_context(facts))
    return 0
