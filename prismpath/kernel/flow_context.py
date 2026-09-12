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

from prismpath.kernel import predicates
from prismpath.kernel.analysis import _parse, _reachable, analyze
from prismpath.kernel.model_check import capability_report, check_reach, flow_level_m


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
    return {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}


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
    for name, flow_node in graph.nodes.items():     # authored order (dict preserves insertion)
        edges = []
        for edge_target, edge_condition in flow_node.edges:
            edges.append({"target": edge_target, "condition": edge_condition, "via": _via(edge_condition)})
            fields |= _fields_in(edge_condition)
        nodes.append({
            "name": name,
            "terminal": flow_node.terminal,
            "annotations": sorted(flow_node.annotations.keys()),
            "edges": edges,
        })

    reach = check_reach(graph, sorted(graph.nodes))
    reachability = {node: {"reachable": r.reachable, "proven": r.proven, "depth": r.depth}
                    for node, r in reach.items()}
    lm_ok, lm_bad = flow_level_m(graph)

    return {
        "name": graph.name,
        "start": graph.start,
        "n_nodes": len(graph.nodes),
        "n_edges": sum(len(node.edges) for node in graph.nodes.values()),
        "nodes": nodes,
        "fields": sorted(fields),
        "terminal_nodes": sorted(node for node, nd in graph.nodes.items() if nd.terminal),
        "reachability": reachability,
        "unreachable_nodes": sorted(node for node, r in reachability.items()
                                    if r["reachable"] == "no"),
        "level_m": {"flow": lm_ok, "non_member_edges": lm_bad},
        "capability": capability_report(graph),
        "findings": [finding.as_dict() for finding in analyze(graph)],
    }


def render_context(facts: dict) -> str:
    """LLM-facing rendering of `flow_context`: a compact, prose block of PROVEN facts an agent must
    not contradict. Every line here is machine-checked, not asserted by the model."""
    lines: List[str] = []
    lines.append(f"# Verified facts about flow '{facts['name']}' "
             f"(proven by PrismPath — ground truth, do not contradict)")
    lines.append(f"Start node: {facts['start']}")
    lines.append(f"Nodes ({facts['n_nodes']}): " + ", ".join(node["name"] for node in facts["nodes"]))
    if facts["terminal_nodes"]:
        lines.append("Terminal nodes (no outgoing edges): " + ", ".join(facts["terminal_nodes"]))
    lines.append(f"Declared fields (read by deterministic edges): "
             + (", ".join(facts["fields"]) if facts["fields"] else "(none)"))
    lines.append("")
    lines.append("Edges (source -> target [tier]  condition):")
    for node in facts["nodes"]:
        for edge in node["edges"]:
            lines.append(f"  {node['name']} -> {edge['target']}  [{edge['via']}]  {edge['condition']!r}")
    lines.append("")
    lines.append("Reachability (adversarial-worker analysis, proven):")
    mark = {"yes": "reachable", "may": "may be reachable", "no": "UNREACHABLE"}
    for flow_node, r in facts["reachability"].items():
        proof = " (proven for all bounds)" if r["reachable"] == "no" and r["proven"] else ""
        lines.append(f"  {flow_node}: {mark[r['reachable']]}{proof}")
    if facts["unreachable_nodes"]:
        lines.append("  -> unreachable nodes: " + ", ".join(facts["unreachable_nodes"]))
    lines.append("")
    lm = facts["level_m"]
    if lm["flow"]:
        lines.append("Level M: YES — every deterministic edge is in the hardware match-action fragment.")
    else:
        lines.append(f"Level M: NO — {len(lm['non_member_edges'])} deterministic edge(s) outside the fragment:")
        for r in lm["non_member_edges"]:
            lines.append(f"  [{r['node']}] -> {r['target']}  {r['condition']!r}  ({r['reason']})")
    cap = facts["capability"]
    lines.append(f"Compiles to: tier {cap['tier']} — "
                 + ", ".join(f"{target_name}={target_status['status']}"
                             for target_name, target_status in cap["targets"].items()))
    if facts["findings"]:
        lines.append("")
        lines.append("Static findings:")
        for finding in facts["findings"]:
            where = f"[{finding['node']}] " if finding["node"] else ""
            lines.append(f"  {finding['severity']}: {where}{finding['message']} ({finding['code']})")
    return "\n".join(lines)


def context_cmd(args) -> int:
    import json
    from prismpath.kernel.parser import parse_file
    facts = flow_context(parse_file(args.flow_md))
    print(json.dumps(facts, indent=2) if args.json else render_context(facts))
    return 0
