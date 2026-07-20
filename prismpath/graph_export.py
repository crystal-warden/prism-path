"""graph_export.py — render a flow as a Mermaid diagram (`prismpath graph`).

Because the flow *is* the graph, one command turns it into a picture that renders natively in a
GitHub README, a PR, or any Mermaid viewer — with the routing spectrum legible at a glance:
**solid** arrows are deterministic `when` edges (exact), **dashed** arrows are semantic edges
(embedding / LLM-on-doubt). Terminal nodes are pill-shaped. No dependency; pure string output.
"""
from __future__ import annotations

from prismpath import predicates


def _label(cond: str, maxlen: int = 44) -> str:
    lbl = cond.replace('"', "'").replace("\n", " ").strip()
    return (lbl[: maxlen - 1] + "…") if len(lbl) > maxlen else lbl


def to_mermaid(graph, direction: str = "TD") -> str:
    """Return a Mermaid `flowchart` for the graph. `direction` is TD (top-down) or LR (left-right)."""
    lines = [f"flowchart {direction}"]
    lines.append(f'    _start(( )) --> {graph.start}')                     # entry marker
    for name, n in graph.nodes.items():
        lines.append(f'    {name}(["{name}"])' if n.terminal else f'    {name}["{name}"]')
    for name, n in graph.nodes.items():
        for t, c in n.edges:
            arrow = "-->" if predicates.is_deterministic(c) else "-.->"    # solid=det, dashed=semantic
            lines.append(f'    {name} {arrow}|"{_label(c)}"| {t}')
    terminals = [name for name, n in graph.nodes.items() if n.terminal]
    lines.append("    classDef terminal fill:#e6f7ec,stroke:#3aa76d;")
    if terminals:
        lines.append("    class " + ",".join(terminals) + " terminal;")
    return "\n".join(lines)


def to_mermaid_fenced(graph, direction: str = "TD") -> str:
    """The Mermaid diagram wrapped in a ```mermaid fence — paste straight into a Markdown README."""
    return "```mermaid\n" + to_mermaid(graph, direction) + "\n```"
