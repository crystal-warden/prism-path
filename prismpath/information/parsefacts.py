# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The parse facts: what an edit to a Python file is, read from the file's text before and after it and never from
the model. Two reading fields, both supplied by the `parse` information point (`ParseFacts`, at the end).

  edit_kind             `comment` (the two parses are identical), `docstring` (identical once docstrings are dropped),
                        `annotation` (identical once annotations are dropped too), or `code`. Restrictive value `code`.
                        The point reads `docstring` or `annotation` only when `behaviour_preserving` is also true for the
                        edit (an annotation is evaluated, a docstring may be read), else `code`. Both facts read `code`
                        and false when any version has a coding line for an encoding but utf-8, or a byte order mark: Python honours a coding line when it imports the file
                        from bytes and a parse of the text does not, so `# coding: utf-7` hides code in a "comment".
  behaviour_preserving  the edit changes no behaviour of the file, decided as the text below says. Restrictive value
                        false. This is gate/nochange.py of the Context Cloud gate tracer, which is stricter about
                        docstrings and annotations than `edit_kind` is (it keeps them whenever the file reads them) and
                        wider about local names. The tracer's delegate policy read `edit_kind != "code"` under this
                        name, and no rule of it read the field; here the field is the stricter fact alone.

The text of the second fact follows, as it was proven in the tracer.

`behaviour_preserving`: an edit that changes no behaviour of the file it edits, decided from the file's text alone.

The fact is true only when the edited file parses before and after the edit and the two syntax trees are EQUAL after
the normalization below. Anything else, and any doubt, is false. It reads no index, so it answers for any code base.

What the syntax tree already ignores: comments, blank lines, quote style, parentheses, line breaks, spacing.

What the normalization removes or equates (each with the reason it cannot change what the program does):

  docstrings    the first statement of a module, class or function when it is a plain string. It only sets `__doc__`.
                A body left empty becomes `pass`. KEPT (compared, so a change counts) when the file mentions `__doc__`,
                imports a module that reads docstrings (doctest, pydoc, inspect, cmd, ply, click, typer, fire, fastapi,
                pydantic ...), or the docstring holds `>>>` (a doctest); and for a function or class with a decorator
                outside the SAFE_DECORATORS list (a framework may read the text).
  annotations   function argument and return annotations, and the annotation of an AnnAssign that has a value (it
                becomes a plain assignment), when the annotation is inert (names, attributes, constants, subscripts,
                `|`, tuples and lists of those: nothing that calls code). An annotation-only AnnAssign (`x: int`) is
                KEPT: at module or class level dataclasses and NamedTuple read it, and in a function it makes the name
                local. KEPT everywhere (so any change to an annotation counts) when the file uses a reader of
                annotations: `get_type_hints`, `__annotations__`, `dataclass`, `NamedTuple`, `TypedDict`, `Annotated`,
                `singledispatch`, `signature`, pydantic-like names (BaseModel, ...) or modules (pydantic, attrs,
                msgspec, typer, fastapi, click ...), or `from __future__ import annotations`. A function with a
                decorator outside SAFE_DECORATORS keeps its annotations (a framework may read them); a class-body
                AnnAssign is removed only in a class with no decorator and no base but `object` or an exception.
  local names   alpha renaming inside ONE function: a name that is local to that function by Python's scoping rules
                and only ever bound by a plain assignment, augmented or annotated assignment, `for` target or `with`
                target, is renamed to a canonical name in order of first binding, so two versions that differ only by
                a consistent renaming are equal. NEVER renamed: parameters (callers may pass them by keyword), names
                declared `global` or `nonlocal` anywhere in the function, names bound any other way (`except ... as`,
                import, nested def or class, walrus, `match` capture, comprehension target), names bound in a nested
                function, lambda or class, attributes, keyword-argument names at call sites, module and class names.
                No renaming at all in a function that uses `locals`, `vars`, `dir`, `eval`, `exec`, `globals`,
                `_getframe`, `currentframe` or `f_locals`, has a `match` statement, or has an f-string debug
                specifier (`f"{x=}"`, read from the string parts, a part ending in `=` before a field).

Limits, stated: a docstring or annotation read by ANOTHER file through `__doc__`, `__annotations__` or inspect is not
seen (the owner accepted this); annotation expressions are not evaluated, so one that named a missing name stops
failing; exceptions' messages that carry a local's name change with a rename. A difference in anything else (a
constant, an operator, a call, an import, the order of statements, a decorator, a default value) makes the trees
differ, so the answer is false.
"""
from __future__ import annotations

import ast
import copy
import io
import time
import tokenize
from typing import Dict, Iterable, List, Optional, Set, Tuple

from prismpath.ports.information import Change, Evidence

NAME = "parse"
EDIT_KINDS = ("comment", "docstring", "annotation", "code")
MAX_CHARS = 2_000_000          # a text longer than this is read at the restrictive values, not parsed
MAX_LINES = 20_000


def declared_encoding(text: str) -> Optional[str]:
    """The source encoding Python would use for `text` written to a file as UTF-8: a PEP 263 coding line in its first
    two lines, or a BOM, are honoured when the file is imported from bytes and ignored when `ast.parse` gets a str, so
    a text that declares anything but plain `utf-8` is read by the interpreter differently from how it is read here.
    None when the declaration cannot be read."""
    try:
        return tokenize.detect_encoding(io.BytesIO(text.encode("utf-8")).readline)[0]
    except (SyntaxError, UnicodeError, ValueError):
        return None


def utf8_declared(*texts: str) -> bool:
    """Every text declares plain utf-8 (no other coding line, no BOM)."""
    return all(declared_encoding(t) == "utf-8" for t in texts)


def too_big(*texts: str) -> bool:
    return any(len(t) > MAX_CHARS or t.count("\n") > MAX_LINES for t in texts)


def _drop_docstrings(tree: ast.AST) -> ast.AST:
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
                    and isinstance(body[0].value.value, str):
                node.body = body[1:] or [ast.Pass()]
    return tree


class _DropAnnotations(ast.NodeTransformer):
    def visit_arg(self, node):
        node.annotation = None
        return node

    def _fn(self, node):
        node.returns = None
        self.generic_visit(node)
        return node

    visit_FunctionDef = visit_AsyncFunctionDef = _fn

    def visit_AnnAssign(self, node):
        self.generic_visit(node)
        if node.value is None:
            return ast.Pass()
        return ast.copy_location(ast.Assign(targets=[node.target], value=node.value, lineno=node.lineno), node)


def _dump(tree: ast.AST) -> str:
    return ast.dump(tree, include_attributes=False)


def edit_kind(old: str, new: str) -> str:
    """The kind of an edit from the file text before and after. A file that does not parse, or a text that cannot be
    read as one, is `code`."""
    try:
        if not utf8_declared(old, new) or too_big(old, new):
            return "code"
        a, b = ast.parse(old), ast.parse(new)
        if _dump(a) == _dump(b):
            return "comment"
        if _dump(_drop_docstrings(ast.parse(old))) == _dump(_drop_docstrings(ast.parse(new))):
            return "docstring"
        strip = lambda s: _dump(_DropAnnotations().visit(_drop_docstrings(ast.parse(s))))  # noqa: E731
        if strip(old) == strip(new):
            return "annotation"
    except Exception:   # noqa: BLE001 - a SyntaxError, a ValueError (a null byte), a RecursionError: any doubt is code
        return "code"
    return "code"


SAFE_DECORATORS = {"staticmethod", "classmethod", "property", "abstractmethod", "setter", "getter", "deleter",
                   "overload", "wraps", "cache", "lru_cache", "cached_property", "contextmanager", "final"}
ANN_NAMES = {"get_type_hints", "get_annotations", "__annotations__", "__annotate__", "dataclass", "dataclasses",
             "NamedTuple", "TypedDict", "Annotated", "singledispatch", "singledispatchmethod", "signature",
             "Signature", "BaseModel", "BaseSettings", "Struct", "TypeAdapter", "attrs", "define", "frozen",
             "annotations"}
ANN_MODULES = {"pydantic", "attr", "attrs", "msgspec", "marshmallow", "cattrs", "typer", "fastapi", "click", "inspect",
               "annotationlib", "sqlmodel", "beartype", "typeguard", "dataclasses"}
DOC_NAMES = {"__doc__", "getdoc", "cleandoc", "doctest"}
DOC_MODULES = {"doctest", "pydoc", "inspect", "cmd", "ply", "click", "typer", "fire", "fastapi", "pydantic", "docopt"}
DYNAMIC_NAMES = {"locals", "vars", "dir", "eval", "exec", "globals"}
FRAME_ATTRS = {"_getframe", "currentframe", "f_locals"}
EXCEPTION_BASES = {"object"}


def _decorator_name(node: ast.AST) -> str:
    while isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        return node.attr
    return node.id if isinstance(node, ast.Name) else "?"


def _safe_decorators(node) -> bool:
    return all(_decorator_name(d) in SAFE_DECORATORS for d in node.decorator_list)


def _markers(tree: ast.AST) -> Tuple[Set[str], Set[str]]:
    """(the names, attributes and imported modules the file uses, with `__future__` annotations spelled `annotations`)."""
    words: Set[str] = set()
    modules: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            words.add(node.id)
        elif isinstance(node, ast.Attribute):
            words.add(node.attr)
        elif isinstance(node, ast.Import):
            modules.update(a.name.split(".")[0] for a in node.names)
            words.update(a.name.split(".")[-1] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.add((node.module or "").split(".")[0])
            words.update(a.name for a in node.names)
            if node.module == "__future__" and any(a.name == "annotations" for a in node.names):
                words.add("future_annotations")
    return words, modules


def _inert(node: Optional[ast.AST]) -> bool:
    """An annotation that only names things: removing it removes no call."""
    if node is None or isinstance(node, (ast.Name, ast.Constant, ast.Attribute)):
        return not isinstance(node, ast.Attribute) or _inert(node.value)
    if isinstance(node, ast.Subscript):
        return _inert(node.value) and _inert(node.slice)
    if isinstance(node, ast.BinOp):
        return isinstance(node.op, ast.BitOr) and _inert(node.left) and _inert(node.right)
    if isinstance(node, (ast.Tuple, ast.List)):
        return all(_inert(e) for e in node.elts)
    return False


class _Strip(ast.NodeTransformer):
    """Docstrings and annotations, as far as the file and the node allow."""

    def __init__(self, docs: bool, anns: bool):
        self.docs, self.anns = docs, anns

    def _docstring(self, node, safe: bool):
        body = node.body
        if self.docs and safe and body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                and isinstance(body[0].value.value, str) and ">>>" not in body[0].value.value:
            node.body = body[1:] or [ast.Pass()]

    def visit_Module(self, node):
        self._docstring(node, True)
        self.generic_visit(node)
        return node

    def visit_ClassDef(self, node):
        self._docstring(node, _safe_decorators(node))
        allowed = not node.decorator_list and not node.keywords and all(
            isinstance(b, ast.Name) and (b.id in EXCEPTION_BASES or b.id.endswith(("Error", "Exception")))
            for b in node.bases)
        if not allowed:                     # a class-body annotation may be read by a base or a decorator: keep it
            for n in _own(node):
                if isinstance(n, ast.AnnAssign):
                    n._keep = True
        self.generic_visit(node)
        return node

    def _function(self, node):
        safe = _safe_decorators(node)
        self._docstring(node, safe)
        self.generic_visit(node)
        if self.anns and safe:
            a = node.args
            args = a.posonlyargs + a.args + a.kwonlyargs + [x for x in (a.vararg, a.kwarg) if x]
            if all(_inert(x.annotation) for x in args) and _inert(node.returns):
                for x in args:
                    x.annotation = None
                node.returns = None
        return node

    visit_FunctionDef = visit_AsyncFunctionDef = _function

    def _plain(self, stmt):
        if isinstance(stmt, ast.AnnAssign) and stmt.value is not None and _inert(stmt.annotation):
            return ast.copy_location(ast.Assign(targets=[stmt.target], value=stmt.value, type_comment=None), stmt)
        return stmt

    def visit_AnnAssign(self, node):
        self.generic_visit(node)
        return self._plain(node) if self.anns and not getattr(node, "_keep", False) else node


# ----------------------------------------------------------------------------------------------- alpha renaming

_NESTED = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _own(node: ast.AST) -> Iterable[ast.AST]:
    """Nodes evaluated in `node`'s own scope: its body, and what a nested scope's header evaluates here (decorators,
    defaults, bases), but not a nested scope's body."""
    stack: List[ast.AST] = list(node.body) if hasattr(node, "body") and isinstance(node.body, list) else []
    while stack:
        current = stack.pop()
        yield current
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = current.args
            stack.extend(current.decorator_list + a.defaults + [d for d in a.kw_defaults if d])
        elif isinstance(current, ast.Lambda):
            a = current.args
            stack.extend(a.defaults + [d for d in a.kw_defaults if d])
        elif isinstance(current, ast.ClassDef):
            stack.extend(current.decorator_list + current.bases + [k.value for k in current.keywords])
        else:
            stack.extend(ast.iter_child_nodes(current))


def _params(args: ast.arguments) -> Set[str]:
    return {a.arg for a in args.posonlyargs + args.args + args.kwonlyargs + [x for x in (args.vararg, args.kwarg) if x]}


def _debug_fstring(node: ast.AST) -> bool:
    for n in ast.walk(node):
        if isinstance(n, ast.JoinedStr):
            for before, after in zip(n.values, n.values[1:]):
                if isinstance(before, ast.Constant) and isinstance(before.value, str) \
                        and before.value.rstrip().endswith("=") and isinstance(after, ast.FormattedValue):
                    return True
    return False


def _renamable(func) -> Dict[str, str]:
    """name -> order of first binding, for the names of `func` that may be renamed; {} when none may."""
    for n in ast.walk(func):
        if isinstance(n, ast.Name) and n.id in DYNAMIC_NAMES:
            return {}
        if isinstance(n, ast.Attribute) and n.attr in FRAME_ATTRS:
            return {}
        if isinstance(n, ast.Match):
            return {}
    if _debug_fstring(func):
        return {}
    plain: Dict[str, int] = {}                  # bound by a plain Name store, with its order
    other: Set[str] = set(_params(func.args))   # bound some other way, or not renamable
    own = list(_own(func))
    own_ids = {id(n) for n in own}
    for n in own:
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            plain.setdefault(n.id, len(plain))
        elif isinstance(n, ast.NamedExpr):
            other.add(n.target.id)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            other.add(n.name)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            other.update((a.asname or a.name).split(".")[0] for a in n.names)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            other.add(n.name)
        elif isinstance(n, (ast.comprehension,)):
            other.update(t.id for t in ast.walk(n.target) if isinstance(t, ast.Name))
    for n in ast.walk(func):                    # anything below the function: its bindings and its declarations
        if n is func:
            continue
        if isinstance(n, (ast.Global, ast.Nonlocal)):
            other.update(n.names)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            other |= _params(n.args)
            if not isinstance(n, ast.Lambda):
                other.add(n.name)
        elif isinstance(n, ast.ClassDef):
            other.add(n.name)
            other.update(t.id for t in ast.walk(n) if isinstance(t, ast.Name))
        elif isinstance(n, ast.ExceptHandler) and n.name:
            other.add(n.name)
        elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store) and id(n) not in own_ids:
            other.add(n.id)
        elif isinstance(n, ast.comprehension):
            other.update(t.id for t in ast.walk(n.target) if isinstance(t, ast.Name))
    if isinstance(func, ast.Lambda):
        return {}
    return {name: order for name, order in plain.items() if name not in other}


def _rename(tree: ast.AST) -> ast.AST:
    counter = 0
    for func in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        mapping = _renamable(func)
        if not mapping:
            continue
        counter += 1
        canonical = {name: f"\0{counter}_{order}" for name, order in mapping.items()}
        for n in ast.walk(func):
            if isinstance(n, ast.Name) and n.id in canonical:
                n.id = canonical[n.id]
    return tree


# ----------------------------------------------------------------------------------------------- the fact

def _normalize(tree: ast.Module, words: Optional[Set[str]] = None, modules: Optional[Set[str]] = None):
    if words is None or modules is None:
        words, modules = _markers(tree)
    anns = not (words & ANN_NAMES or "future_annotations" in words or modules & ANN_MODULES)
    docs = not (words & DOC_NAMES or modules & DOC_MODULES)
    tree = _Strip(docs, anns).visit(copy.deepcopy(tree))
    tree = _rename(ast.fix_missing_locations(tree))
    return ast.dump(tree, annotate_fields=True, include_attributes=False), (anns, docs)


def behaviour_preserving(old: str, new: str) -> Tuple[bool, str]:
    """(value, why). True only when both texts parse and their normalized trees are equal."""
    if not utf8_declared(old, new):
        return False, "a version declares an encoding but utf-8, or has a byte order mark"
    if too_big(old, new):
        return False, "a version is too big to read"
    try:
        old_tree, new_tree = ast.parse(old), ast.parse(new)
    except (SyntaxError, ValueError, RecursionError) as exc:
        return False, f"a version does not parse: {type(exc).__name__}"
    try:
        ow, om = _markers(old_tree)
        nw, nm = _markers(new_tree)
        words, modules = ow | nw, om | nm          # the stricter reading of the two versions decides what is removed
        a, _ = _normalize(old_tree, words, modules)
        b, _ = _normalize(new_tree, words, modules)
    except Exception as exc:  # noqa: BLE001 - any doubt is false
        return False, f"the normalization failed: {type(exc).__name__}"
    if a == b:
        return True, "the syntax trees are equal after removing docstrings, annotations and renaming local names"
    return False, "the syntax trees differ"


# ------------------------------------------------------------------------------------------------ the point
class ParseFacts:
    """The `parse` information point: `edit_kind` and `behaviour_preserving` of the change's edit. It reads no index
    and runs nothing. A change with no edit (one that could not be applied to the file), a file that is not Python,
    a text that is not a str and any failure read both fields at their restrictive values."""

    name = NAME
    fields = {"edit_kind": EDIT_KINDS, "behaviour_preserving": (False, True)}
    restrictive = {"edit_kind": "code", "behaviour_preserving": False}
    control_paths: Tuple[str, ...] = ()

    def facts(self, change: Change, budget_s: float) -> Evidence:
        started = time.monotonic()
        try:
            edit = getattr(change, "edit", None)
            if edit is None:
                return self._none("the edit cannot be applied to the file")
            if not (isinstance(edit.relative, str) and edit.relative.endswith(".py")):
                return self._none("not a Python file")
            if not (isinstance(edit.old, str) and isinstance(edit.new, str)):
                return self._none("the file text is not text")
            if too_big(edit.old, edit.new):
                return self._none("the file is too big to read")
            kind = edit_kind(edit.old, edit.new)
            value, why = behaviour_preserving(edit.old, edit.new)
            value = bool(value) is True
            if kind in ("docstring", "annotation") and not value:
                kind = "code"          # a value that sounds inert is read only for an edit that is
            if time.monotonic() - started > budget_s:
                return self._none("the reading took longer than its budget")
            return Evidence({"edit_kind": kind, "behaviour_preserving": value}, frozenset(),
                            "" if value or why == "the syntax trees differ" else why, {"behaviour": why})
        except Exception as exc:   # noqa: BLE001 - a point that fails says nothing, which is its restrictive value
            return self._none(f"the point failed ({type(exc).__name__})")

    def _none(self, why: str) -> Evidence:
        return Evidence(dict(self.restrictive), frozenset(), why, {})
