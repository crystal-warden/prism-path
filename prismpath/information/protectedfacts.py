# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The `cc_graph` information point: whether an edit touches the owner's protected code, and whether it adds a reference
to it (`touches_protected` and `adds_protected_reference` of gate/escalate.py in the Context Cloud gate tracer).

  touches_protected         a changed line of the edit lies inside a protected function, in the old file or the new.
                            Restrictive value true.
  adds_protected_reference  the edit adds a reference that resolves to a protected function, or to one on a call path
                            with the protected set in either direction. Restrictive value true. It is false only when
                            every added reference is on a closed safe list (`adds_protected_reference`): an unresolved or
                            outside reference, a resolved one with no target and a class with no `__init__` all read
                            true. The tracer was safe on these because an unresolved added reference made its
                            `reaches_protected` `unknown` with `unknown_reason == "new_reference"`, and every delegate
                            rule needed that reason; `unknown_reason` is not ported, so the closed list does that job and
                            a policy should also require `zone_reach == "none"`. The fact was proven only together with
                            those.

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
import time
from typing import Any, Callable, Iterable, List, Mapping, Optional, Protocol, Sequence, Set, Tuple

from prismpath.information.parsefacts import too_big, utf8_declared
from prismpath.ports.information import Change, Evidence

NAME = "cc_graph"
RESOLVED = ("function", "class", "methods")
SAFE_RESOLVED = ("builtin",)     # the closed list: a reference an adapter proves reaches no project code


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


def _span_texts(tree: ast.AST, text: str, module: str, protected: Sequence[str]) -> dict:
    lines = text.splitlines()
    return {name: "\n".join(lines[start - 1:end]) for start, end, name in spans(tree, module)
            if _covered(name, protected)}


def touches_protected(old: str, new: str, module: str, protected: Sequence[str]) -> Optional[bool]:
    """True when the edit may change protected code: a changed line inside a protected function or class, the text of
    any protected span differing by name between the two versions (or present in only one), a changed line outside
    every function and class of a module that is protected or that defines a protected name (module code can rebind
    it), or either text declaring an encoding but utf-8. None for a text that does not parse, which the point reads as
    true."""
    if not utf8_declared(old, new):
        return True
    try:
        old_tree, new_tree = ast.parse(old), ast.parse(new)
    except (SyntaxError, ValueError, RecursionError):
        return None
    if _covered(module, protected):
        return True
    if _span_texts(old_tree, old, module, protected) != _span_texts(new_tree, new, module, protected):
        return True
    defines = any(p.startswith(module + ".") for p in protected)
    old_lines, new_lines = changed_lines(old, new)
    for tree, lines in ((old_tree, old_lines), (new_tree, new_lines)):
        found = spans(tree, module)
        for line in lines:
            name = _enclosing(found, line)
            if name is None:
                if defines:
                    return True
            elif _covered(name, protected):
                return True
    return False


def adds_protected_reference(refs: Iterable[Mapping[str, Any]], graph: Optional[CallGraph]) -> bool:
    """True unless every added reference is on the closed safe list. A reference is safe only when its `resolved` is in
    `SAFE_RESOLVED`, or it resolved to a function, class or methods with at least one target and a graph that finds no
    target protected or on a call path with the protected set (a class: no `__init__` found for it reads true). Any
    other value (unresolved, outside, a name the list does not hold), a resolved reference with no targets, and
    anything that is not a mapping read true. Without the graph, any resolved reference reads true."""
    for ref in refs:
        resolved = ref.get("resolved")
        if resolved in SAFE_RESOLVED:
            continue
        if resolved not in RESOLVED:
            return True
        targets = ref.get("targets")
        if graph is None or not isinstance(targets, (list, tuple)) or not targets \
                or not all(isinstance(t, str) for t in targets):
            return True
        for target in targets:
            if graph.is_protected(target) or graph.on_protected_path(target):
                return True
            if resolved == "class":
                inits = list(graph.class_inits(target))
                if not inits:
                    return True
                dsts = inits
            else:
                dsts = [target]
            if any(graph.is_protected(d) or graph.on_protected_path(d) for d in dsts):
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
        started = time.monotonic()
        why: List[str] = []
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
        if time.monotonic() - started > budget_s:
            touches = adds = True
            why.append("the reading took longer than its budget")
        return Evidence({"touches_protected": touches, "adds_protected_reference": adds}, frozenset(),
                        "; ".join(why), {})

    def _touches(self, change: Change, why: List[str]) -> bool:
        edit = getattr(change, "edit", None)
        if edit is None or not isinstance(edit.old, str) or not isinstance(edit.new, str):
            why.append("the edit cannot be applied to the file")
            return True
        if not isinstance(edit.relative, str) or not edit.relative.endswith(".py"):
            why.append("not a Python file, which this point cannot analyse")
            return True
        if too_big(edit.old, edit.new):
            why.append("the file is too big to read")
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
        try:
            ast.parse(change.edit.new)
        except (SyntaxError, ValueError, RecursionError):
            why.append("the edited file does not parse, so its references are not known")
            return True
        refs = self._references(change)
        if refs is None:
            why.append("the references the edit adds could not be read")
            return True
        return adds_protected_reference(list(refs), self._graph) is not False
