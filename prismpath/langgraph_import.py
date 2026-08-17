# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""langgraph_import.py — `prismpath import`: turn a LangGraph StateGraph into a skeleton flow.

Migration tooling is the classic adoption wedge — and the import itself demonstrates the thesis:
it forces LangGraph's *implicit, code-resident* control flow to become *explicit prose*. We walk the
Python AST for the common StateGraph calls (no langgraph install needed) and emit a `.md` flow:

  add_node("x", fn)                       -> ## x   (with a TODO from the function name)
  add_edge("a", "b")                      -> -> b: when always
  add_edge(START, "x") / set_entry_point  -> start: x
  add_edge("a", END)                      -> -> done: when always  (a terminal `done` node)
  add_conditional_edges("a", fn, {k: t})  -> -> t: TODO write the condition (router returned 'k')

Fidelity is deliberately ~70%: the routing *functions* can't be translated — that's exactly the
point. Each conditional edge lands a `TODO` where a human writes the readable condition prismpath needs.
"""
from __future__ import annotations

import ast
import re
from typing import List, Optional, Tuple


def _san(s: str) -> str:
    return re.sub(r"[^a-z0-9_]", "", s.strip().lower().replace(" ", "_").replace("-", "_")) or "node"


def _is_ref(node, names) -> bool:
    return (isinstance(node, ast.Name) and node.id in names) or \
           (isinstance(node, ast.Constant) and node.value in names)


def _node_name(node) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return _san(node.value)
    if isinstance(node, ast.Name):
        return _san(node.id)
    if isinstance(node, ast.Attribute):
        return _san(node.attr)
    return None


_START = {"START", "__start__"}
_END = {"END", "__end__"}


def import_langgraph(source: str, name: str = "imported") -> str:
    """Parse LangGraph Python `source` and return an prismpath flow (Markdown) skeleton."""
    tree = ast.parse(source)
    nodes: dict = {}                         # name -> function name (for the TODO)
    edges: List[Tuple[str, str, str]] = []   # (src, dst, condition)
    order: List[str] = []                    # node declaration order
    start: Optional[str] = None
    has_end = False

    def see(n):
        if n and n not in order:
            order.append(n)

    for call in ast.walk(tree):
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)):
            continue
        m, args = call.func.attr, call.args
        if m == "add_node" and args:
            if isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
                nm = _san(args[0].value)
                fn = args[1] if len(args) > 1 else None
            else:
                nm, fn = _node_name(args[0]), args[0]
            fnname = fn.id if isinstance(fn, ast.Name) else (fn.attr if isinstance(fn, ast.Attribute) else "")
            if nm:
                nodes[nm] = fnname
                see(nm)
        elif m in ("set_entry_point", "set_conditional_entry_point") and args:
            start = _node_name(args[0])
        elif m == "set_finish_point" and args:
            src = _node_name(args[0])
            has_end = True
            edges.append((src, "done", "when always"))
        elif m == "add_edge" and len(args) >= 2:
            a, b = args[0], args[1]
            if _is_ref(a, _START):
                start = _node_name(b)
            elif _is_ref(b, _END):
                has_end = True
                edges.append((_node_name(a), "done", "when always"))
                see(_node_name(a))
            else:
                sa, sb = _node_name(a), _node_name(b)
                edges.append((sa, sb, "when always"))
                see(sa); see(sb)
        elif m == "add_conditional_edges" and args:
            src = _node_name(args[0])
            see(src)
            pm = args[2] if len(args) > 2 else None
            for kw in call.keywords:
                if kw.arg in ("path_map", "path"):
                    pm = kw.value
            pairs: List[Tuple[Optional[str], Optional[object]]] = []
            if isinstance(pm, ast.Dict):
                for k, v in zip(pm.keys, pm.values):
                    key = k.value if isinstance(k, ast.Constant) else None
                    if _is_ref(v, _END):
                        pairs.append(("done", key)); has_end = True
                    else:
                        pairs.append((_node_name(v), key))
            elif isinstance(pm, (ast.List, ast.Tuple)):
                for v in pm.elts:
                    pairs.append((_node_name(v), None))
            for tgt, key in pairs:
                cond = (f"TODO write the condition (router returned {key!r})"
                        if key is not None else "TODO write the condition")
                edges.append((src, tgt, cond))
                see(tgt)

    if start is None and order:
        start = order[0]
    if has_end:
        see("done")

    # emit
    out = [f"---\nname: {name}\nstart: {start or 'start'}\n---\n"]
    outgoing = {}
    for s, d, c in edges:
        outgoing.setdefault(s, []).append((d, c))
    for nm in order:
        out.append(f"## {nm}")
        fn = nodes.get(nm)
        if nm == "done":
            out.append("Terminal (was END in the LangGraph).")
        elif fn:
            out.append(f"TODO: describe this step (was LangGraph node `{fn}`).")
        else:
            out.append("TODO: describe this step.")
        for d, c in outgoing.get(nm, []):
            out.append(f"-> {d}: {c}")
        out.append("")
    return "\n".join(out).rstrip() + "\n"
