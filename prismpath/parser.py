"""Parse a workflow markdown file into a graph.

Format (human-authored, git-diffable):

    ---
    name: bugfix
    start: triage
    ---

    ## triage
    Understand the bug report and decide what to do next.
    -> implement: the bug is reproduced and the root cause is clear
    -> gather_info: it cannot be reproduced or more information is needed
    -> close: it is a duplicate or invalid

    ## done
    Summarize and finish.

Each `## heading` is a node; the prose under it is the node's instruction. Lines of the form
`-> target: condition` are outgoing edges (natural-language conditions). A node with no edges
is terminal.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

EDGE_RE = re.compile(r"^\s*-?\s*->\s*([A-Za-z0-9_\-]+)\s*:\s*(.+?)\s*$")
HEAD_RE = re.compile(r"^\s*##\s+(.+?)\s*$")
# Node annotation, e.g. `@checkpoint(unit=alert.id, proof=verdict, gate=staged_ok)` — an extension
# slot on a node (the control plane reads it; the kernel just parses it). Keeps the heading clean.
ANNO_RE = re.compile(r"^\s*@(\w+)\s*\((.*)\)\s*$")


def _parse_anno_args(argstr: str) -> dict:
    """`key=value` pairs (e.g. @checkpoint(unit=alert.id)) AND bare tokens mapped to None (e.g.
    @emits(recommended_action, rule_level)). Backward-compatible: existing key=value annotations are
    unchanged."""
    args = {}
    for part in argstr.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip()
            if k:                       # ignore a malformed `=value` with no key
                args[k] = v.strip()
        else:
            args[part] = None
    return args


@dataclass
class Node:
    name: str
    instruction: str = ""
    edges: List[Tuple[str, str]] = field(default_factory=list)  # (target, condition)
    annotations: Dict[str, dict] = field(default_factory=dict)  # {name: {arg: value}}

    @property
    def terminal(self) -> bool:
        return len(self.edges) == 0


@dataclass
class Graph:
    name: str
    start: str
    nodes: Dict[str, Node]

    def validate(self) -> List[str]:
        """Backward-compatible error list. The full static analysis (errors + warnings) lives in
        `prismpath.analysis.analyze`; this returns only the error-severity messages as strings."""
        from prismpath import analysis   # local import: parser stays dependency-light
        return [f"node '{f.node}': {f.message}" if f.node else f.message
                for f in analysis.analyze(self) if f.severity == "error"]


def parse(text: str) -> Graph:
    meta = {}
    body = text
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", text, re.DOTALL)
    if m:
        for line in m.group(1).splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip()] = v.strip()
        body = m.group(2)

    nodes: Dict[str, Node] = {}
    cur: Node | None = None
    instr_lines: List[str] = []

    def flush():
        if cur is not None:
            cur.instruction = "\n".join(instr_lines).strip()

    for line in body.splitlines():
        h = HEAD_RE.match(line)
        if h:
            flush()
            name = h.group(1).strip().lower().replace(" ", "_")
            cur = Node(name=name)
            nodes[name] = cur
            instr_lines = []
            continue
        if cur is None:
            continue
        e = EDGE_RE.match(line)
        a = ANNO_RE.match(line)
        if e:
            cur.edges.append((e.group(1).strip(), e.group(2).strip()))
        elif a:
            # merge repeated annotations of the same name (e.g. @emits split across two lines) rather
            # than overwriting, so a later declaration doesn't silently drop the earlier fields.
            cur.annotations.setdefault(a.group(1).strip(), {}).update(_parse_anno_args(a.group(2)))
        else:
            instr_lines.append(line)
    flush()

    start = meta.get("start") or (next(iter(nodes)) if nodes else "")
    g = Graph(name=meta.get("name", "flow"), start=start, nodes=nodes)
    return g


def parse_file(path: str) -> Graph:
    with open(path, encoding="utf-8") as f:
        return parse(f.read())
