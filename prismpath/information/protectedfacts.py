# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The `cc_graph` information point: whether an edit touches the owner's protected code, and whether it adds a reference
to it (`touches_protected` and `adds_protected_reference` of gate/escalate.py in the Context Cloud gate tracer).

  touches_protected         a changed line of the edit lies inside a protected function, in the old file or the new.
                            Restrictive value true.
  adds_protected_reference  the edit adds a reference that resolves to a protected function, or to one on a call path
                            with the protected set in either direction. Restrictive value true.

Both are true whenever the point cannot tell (doubt is true): no edit, a file that does not parse before or after, no
module name for the file, no way to list the added references, and any exception. `touches_protected` is also true,
beyond the tracer, for a change anywhere in a file whose module is itself protected, and for a line inside a protected
class that is not inside one of its functions: the tracer read the functions only, and a protected name protects
everything under it.

The point is evidence, never authority (prismpath/ports/information.py). What it needs from the Context Cloud index is
handed to it, as the zone point is handed `host_path`: `module_of` (the module name of a file under the project, from
the index's files table), `references` (the references the edit adds, each `{"resolved": "function" | "class" |
"methods" | other, "targets": [names]}`, from the call graph's reading of the edited file) and `graph` (a call graph
that answers `is_protected(name)`, `on_protected_path(name)` and `class_inits(name)`). A point without `graph` reads
true for any resolved reference. This module imports no other prismpath package.
"""
from __future__ import annotations

import ast
import difflib
from typing import Any, Callable, Iterable, List, Mapping, Optional, Protocol, Sequence, Set, Tuple

from prismpath.ports.information import Change, Evidence

NAME = "cc_graph"
RESOLVED = ("function", "class", "methods")


class CallGraph(Protocol):
    def is_protected(self, name: str) -> bool: ...
    def on_protected_path(self, name: str) -> bool: ...
    def class_inits(self, name: str) -> Iterable[str]: ...


def _covered(name: str, protected: Sequence[str]) -> bool:
    return any(name == p or name.startswith(p + ".") for p in protected)


def changed_lines(old: str, new: str) -> Tuple[Set[int], Set[int]]:
    """(lines of the old text that change, lines of the new text that are added), 1-based."""
    a, b = old.splitlines(), new.splitlines()
    old_lines, new_lines = set(), set()
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        old_lines.update(range(i1 + 1, i2 + 1))
        new_lines.update(range(j1 + 1, j2 + 1))
    return old_lines, new_lines


def spans(tree: ast.AST, module: str) -> List[Tuple[int, int, str]]:
    """(first line, last line, qualified name) of every function and class of a tree; the first line is the first
    decorator's."""
    found: List[Tuple[int, int, str]] = []

    def walk(node: ast.AST, names: List[str]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                inner = names + [child.name]
                start = min([child.lineno] + [d.lineno for d in child.decorator_list])
                found.append((start, child.end_lineno, ".".join([module] + inner)))
                walk(child, inner)
            else:
                walk(child, names)

    walk(tree, [])
    return found


def _enclosing(found: List[Tuple[int, int, str]], line: int) -> Optional[str]:
    best = None
    for start, end, name in found:
        if start <= line <= end and (best is None or start >= best[0]):
            best = (start, end, name)
    return best[2] if best else None


def touches_protected(old: str, new: str, module: str, protected: Sequence[str]) -> Optional[bool]:
    """True when a changed line is inside a protected function or class, or the module is protected; None for a text
    that does not parse, which the point reads as true."""
    try:
        old_tree, new_tree = ast.parse(old), ast.parse(new)
    except (SyntaxError, ValueError, RecursionError):
        return None
    if _covered(module, protected):
        return True
    old_lines, new_lines = changed_lines(old, new)
    for tree, lines in ((old_tree, old_lines), (new_tree, new_lines)):
        found = spans(tree, module)
        for line in lines:
            name = _enclosing(found, line)
            if name is not None and _covered(name, protected):
                return True
    return False


def adds_protected_reference(refs: Iterable[Mapping[str, Any]], graph: Optional[CallGraph]) -> bool:
    """True when an added reference resolves to a protected function or to one on a call path with the protected set,
    in either direction, at any certainty. Without the graph, true when any reference resolved."""
    for ref in refs:
        if ref.get("resolved") not in RESOLVED:
            continue
        if graph is None:
            return True
        for target in ref.get("targets") or []:
            dsts = list(graph.class_inits(target)) if ref["resolved"] == "class" else [target]
            for dst in dsts:
                if graph.is_protected(dst) or graph.on_protected_path(dst):
                    return True
    return False


class ProtectedFacts:
    """The `cc_graph` information point (see the module docstring)."""

    name = NAME
    fields = {"touches_protected": (False, True), "adds_protected_reference": (False, True)}
    restrictive = {"touches_protected": True, "adds_protected_reference": True}
    control_paths: Tuple[str, ...] = ()

    def __init__(self, protected: Iterable[str], module_of: Optional[Callable[[str], Optional[str]]] = None,
                 references: Optional[Callable[[Change], Optional[Iterable[Mapping[str, Any]]]]] = None,
                 graph: Optional[CallGraph] = None):
        self.protected = sorted({p for p in protected if isinstance(p, str) and p})
        self._module_of, self._references, self._graph = module_of, references, graph

    def facts(self, change: Change, budget_s: float) -> Evidence:
        why = []
        try:
            touches = self._touches(change, why)
        except Exception as exc:   # noqa: BLE001
            touches = True
            why.append(f"touches_protected could not be read ({type(exc).__name__})")
        try:
            adds = self._adds(change, why)
        except Exception as exc:   # noqa: BLE001
            adds = True
            why.append(f"adds_protected_reference could not be read ({type(exc).__name__})")
        return Evidence({"touches_protected": touches, "adds_protected_reference": adds}, frozenset(),
                        "; ".join(why), {})

    def _touches(self, change: Change, why: List[str]) -> bool:
        edit = getattr(change, "edit", None)
        if edit is None or not isinstance(edit.old, str) or not isinstance(edit.new, str):
            why.append("the edit cannot be applied to the file")
            return True
        module = self._module_of(edit.relative) if self._module_of is not None else None
        if not isinstance(module, str) or not module:
            why.append("no module name for the file, so its functions cannot be named")
            return True
        if not self.protected:
            why.append("no protected set")
            return True
        value = touches_protected(edit.old, edit.new, module, self.protected)
        if value is None:
            why.append("a version of the file does not parse")
        return value is not False

    def _adds(self, change: Change, why: List[str]) -> bool:
        if getattr(change, "edit", None) is None:
            why.append("the edit cannot be applied to the file, so its added references are not known")
            return True
        if self._references is None:
            why.append("no reading of the references the edit adds")
            return True
        refs = self._references(change)
        if refs is None:
            why.append("the references the edit adds could not be read")
            return True
        return adds_protected_reference(list(refs), self._graph) is not False
