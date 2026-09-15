# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The flow topology the command center draws, plus the live checkpoint painted onto it."""
import glob
import json
import os

from .config import SETTINGS
from .files import is_contained


def _live_flow_path(proj):
    """The flow the followed run is executing: what its status file names, else the first flow document
    in the project, else the bundled coding flow."""
    sp = os.path.join(proj, "status.json")
    if os.path.isfile(sp):
        try:
            with open(sp, encoding="utf-8") as json_file:
                st = json.load(json_file)
            named = st.get("flow_path") or st.get("flow")
            if named:
                return named
        except Exception:
            pass
    candidates = glob.glob(os.path.join(proj, "flows", "*.md")) + glob.glob(os.path.join(proj, "*.md"))
    return candidates[0] if candidates else os.path.join(SETTINGS.prism_dir, "flows", "coding.md")


def _edge_tier(cond):
    """Which tier an edge's condition belongs to, in the order the kernel tests them."""
    from prismpath.kernel import predicates
    if predicates.is_error(cond):
        return "error"
    if predicates.is_event(cond):
        return "event"
    if predicates.is_deterministic(cond):
        return "deterministic"
    return "semantic"


def serialize_flow_graph(state, flow_path=None):
    """The flow topology the command center renders: nodes + tier-classified edges, plus the live
    checkpoint (active node, transcript, state vars). `flow_path` is resolved and CONTAINED to the
    followed project (or the bundled flows dir); it never reads an arbitrary path."""
    from prismpath.kernel.parser import parse_file
    proj = state["proj"]
    if not flow_path:
        flow_path = _live_flow_path(proj)
    resolved = os.path.abspath(flow_path)
    if not (is_contained(resolved, proj) or is_contained(resolved, SETTINGS.prism_dir)):
        return {"error": "flow path escapes project sandbox"}
    graph = parse_file(resolved)
    nodes_data = {}
    for name, flow_node in graph.nodes.items():
        edges = [{"target": target, "condition": cond, "tier": _edge_tier(cond)}
                 for target, cond in flow_node.edges]
        nodes_data[name] = {"name": name, "instruction": flow_node.instruction,
                            "terminal": flow_node.terminal,
                            "annotations": flow_node.annotations, "edges": edges}
    active = {}
    ckpt = os.path.join(proj, "checkpoint.json")
    if os.path.isfile(ckpt):
        try:
            with open(ckpt, encoding="utf-8") as json_file:
                active = json.load(json_file)
        except Exception:
            pass
    try:
        flow_text = open(resolved, encoding="utf-8").read()      # so the console can prove it (text-in)
    except Exception:
        flow_text = ""
    shown_path = os.path.relpath(resolved, proj) if is_contained(resolved, proj) else os.path.basename(resolved)
    return {"name": graph.name, "start": graph.start, "nodes": nodes_data,
            "flow_text": flow_text, "flow_path": shown_path,
            "active_node": active.get("node"), "transcript": active.get("transcript", []),
            "state_variables": active.get("state", {})}
