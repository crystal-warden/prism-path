# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The finite reading domain of a core policy, and the walk over it.

A reading domain says which values each field of a reading may take. A bool is true or false, an int is its min to
max range (up to `MAX_INT_RANGE` values), and a category is one of the values the domain lists for it. A policy whose
rules name a value outside the domain is `policy:out-of-domain` (spec-policy-distribution.md, 9.4), because the walk
never meets that value and so no comparison could see a rule that allows it.

The domain is an argument, a `ReadingDomain`, so the walk knows no target. A target kind supplies its own. It names

  categories   the values of each category field
  unproduced   combinations the producer of readings never gives: (field, its empty value, the gate field, the gate
               values), a field that is empty unless the gate field has one of the gate values
  name_field   a category field read as one name, tested only for equality with one readable name (AF1, 21.2), and
               walked by the names the rules test rather than by a list of every name
  defaults     the most restrictive value of each field a policy opts in to by defining any of them, given to a
               reading that lacks them (`kernel.decision.Policy.reading_bytes`)

`domain_classes` walks one or more documents over the same fields by classes of values: every atom a rule has on a
field is true of all of a class or of none, so the first rule that holds is a function of the classes and each
document decides a combination of classes as one, by its first values. The profile compiler
(`prismpath.agent.profile`), the widening comparator (`prismpath.distribution.widening`) and `prismpath agent rules`
use it.

Each target kind registers its own domain with the kind registry (`prismpath.ports.target.TargetKind.domain`). The
agent kind's is `prismpath.agent.profile.AGENT_DOMAIN`, and the trust path asks the registry for it
(`distribution.kinds.reading_domain`), applying it to every kind as it always has (owner answer Q4) until each kind
has its own.

Nothing here does I/O.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

MAX_INT_RANGE = 64


class DomainError(Exception):
    """A field has no finite domain, so the walk cannot enumerate it; the caller decides nothing from a guess."""


@dataclass(frozen=True, eq=False)
class ReadingDomain:
    """The values a reading's fields take for one target kind. See the module docstring."""
    name: str
    categories: Mapping[str, Tuple[str, ...]]
    unproduced: Tuple[Tuple[str, str, str, Tuple[str, ...]], ...] = ()
    name_field: Optional[str] = None
    name_max: int = 512
    defaults: Mapping[str, Any] = field(default_factory=dict)


def names_read(when, fields) -> set:
    """The field names a rule's condition mentions (every string in it that is a field name, which can only
    add a field, never miss one)."""
    found, stack = set(), [when]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if item in fields:
                found.add(item)
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
    return found


def field_values(name: str, text: str, domain: ReadingDomain) -> List[Any]:
    """The finite list of values of a field from its definition, or DomainError saying why there is none."""
    words = text.split()
    if not words:
        raise DomainError(f"field {name!r} has an empty definition")
    kind = words[0]
    options = dict(w.split("=", 1) for w in words[1:] if "=" in w)
    if kind == "bool":
        values: List[Any] = [False, True]
    elif kind == "int":
        try:
            lo, hi = int(options["min"]), int(options["max"])
        except (KeyError, ValueError):
            raise DomainError(f"field {name!r} is an int without a readable min and max: {text!r}")
        if not 0 <= hi - lo < MAX_INT_RANGE:
            raise DomainError(f"field {name!r} is an int with {hi - lo + 1} values, past the {MAX_INT_RANGE} "
                              f"the walk enumerates")
        values = list(range(lo, hi + 1))
    elif kind == "category":
        if name not in domain.categories:
            raise DomainError(f"field {name!r} is a category the classifier does not produce, so it has "
                              f"no finite domain")
        values = list(domain.categories[name])
    else:
        raise DomainError(f"field {name!r} is a {kind!r}, which has no finite domain")
    if options.get("absent") == "allowed":
        values.append(None)
    return values


def _atoms(when, out) -> bool:
    """Collect every atom of a condition (cmp, in, truthy under and, or, not). False when one is not of a
    shape this reads, so the caller enumerates every value instead of grouping them."""
    head = when[0] if isinstance(when, list) and when else None
    if head in ("and", "or"):
        return all(_atoms(part, out) for part in when[1:])
    if head == "not":
        return _atoms(when[1], out)
    if head in ("always", "never"):
        return True
    if head in ("cmp", "in", "truthy"):
        out.append(when)
        return True
    return False


def _atom_true(atom, value) -> bool:
    head = atom[0]
    if head == "truthy":
        return bool(value)
    if head == "in":
        return value in [const[1] for const in atom[2]]
    _cmp, _field, op, (_kind, const) = atom
    return {"==": value == const, "!=": value != const, ">=": value >= const, ">": value > const,
            "<=": value <= const, "<": value < const}[op]


def _classes(values: List[Any], atoms: List[list]) -> List[List[Any]]:
    """The values grouped so that every atom on the field is true of all of a group or of none: the first
    rule that holds is a function of the atoms' truth, so a group is decided as one. A value of no group
    (absent, or one an atom cannot compare) stands alone, and so does every value if an atom is not
    understood. The first of a group stands for it."""
    groups: Dict[Any, List[Any]] = {}
    for n, value in enumerate(values):
        try:
            key: Any = None if value is None else tuple(_atom_true(a, value) for a in atoms)
        except (TypeError, ValueError, KeyError, IndexError):
            key = None
        groups.setdefault(key if key is not None else ("alone", n), []).append(value)
    return list(groups.values())


def unproduced(names: List[str], combo, domain: ReadingDomain) -> bool:
    """True when a combination of value groups is one the domain's producer never gives (`ReadingDomain.unproduced`)."""
    groups = dict(zip(names, combo))
    for name, empty, gate, values in domain.unproduced:
        if name in groups and gate in groups and empty not in groups[name] \
                and not any(value in groups[gate] for value in values):
            return True
    return False


def _wide_atoms(when, out) -> bool:
    """`_atoms`, also reading `not in`, for the boundary walk of a wide integer field."""
    head = when[0] if isinstance(when, list) and when else None
    if head in ("and", "or"):
        return all(_wide_atoms(part, out) for part in when[1:])
    if head == "not":
        return _wide_atoms(when[1], out)
    if head in ("always", "never"):
        return True
    if head in ("cmp", "in", "not in", "truthy"):
        out.append(when)
        return True
    return False


def _boundary_domain(name: str, text: str, atoms: List[list]) -> List[Any]:
    """The values of a wide integer field that stand for all of them: its ends and each constant an atom on it
    compares with, with its neighbours, inside the declared range. Between two of them every atom is true or
    false alike, so they meet every class `_classes` makes of the whole range. DomainError when an atom is not
    a comparison with integer constants."""
    options = dict(word.split("=", 1) for word in text.split()[1:] if "=" in word)
    low, high = int(options["min"]), int(options["max"])
    points = {low, high}
    for atom in atoms:
        if atom[0] == "cmp" and isinstance(atom[3], list) and isinstance(atom[3][1], int):
            constants = [atom[3][1]]
        elif atom[0] in ("in", "not in") and all(isinstance(const, list) and isinstance(const[1], int) for const in atom[2]):
            constants = [const[1] for const in atom[2]]
        elif atom[0] == "truthy":
            constants = [0]
        else:
            raise DomainError(f"field {name!r} is an int with an atom the boundary walk does not read")
        for const in constants:
            points.update(value for value in (const - 1, const, const + 1) if low <= value <= high)
    values: List[Any] = sorted(points)
    if options.get("absent") == "allowed":
        values.append(None)
    return values


def name_ok(name: Any, domain: ReadingDomain) -> bool:
    """A value the name field's point can read as one name: 1 to `name_max` characters and no path."""
    return isinstance(name, str) and 1 <= len(name) <= domain.name_max and "/" not in name and name not in (".", "..")


def _conjuncts(when) -> List[Any]:
    if isinstance(when, list) and when and when[0] == "and":
        return [part for operand in when[1:] for part in _conjuncts(operand)]
    return [when]


def _mentions(when, name: str) -> bool:
    if not isinstance(when, list):
        return False
    return (len(when) >= 2 and when[0] in ("cmp", "in", "not in", "truthy") and when[1] == name) or any(
        _mentions(part, name) for part in when[1:] if isinstance(part, list))


def name_problem(when, domain: ReadingDomain) -> bool:
    """AF1 (spec-policy-distribution.md, 21.2): a rule tests the domain's name field other than for equality with one
    name the point can read, as a conjunct of the whole rule. Such a rule is `policy:out-of-domain`."""
    field_name = domain.name_field
    if field_name is None:
        return False
    for conjunct in _conjuncts(when):
        if not _mentions(conjunct, field_name):
            continue
        if not (isinstance(conjunct, list) and len(conjunct) == 4 and conjunct[0] == "cmp" and conjunct[1] == field_name
                and conjunct[2] == "==" and isinstance(conjunct[3], list) and len(conjunct[3]) == 2
                and conjunct[3][0] == "str" and name_ok(conjunct[3][1], domain)):
            return True
    return False


def _names_tested(docs, field_name: str) -> List[Any]:
    """AF1, 9.4: the walk of the name field needs no list of every name, because a rule only tests equality. It takes
    the empty name, each name either document tests, and one name neither tests, which stands for every other."""
    tested = set()
    for doc in docs:
        for rule in doc["rules"]:
            for conjunct in _conjuncts(rule["when"]):
                if (isinstance(conjunct, list) and len(conjunct) == 4 and conjunct[:3] == ["cmp", field_name, "=="]
                        and isinstance(conjunct[3], list) and len(conjunct[3]) == 2):
                    tested.add(conjunct[3][1])
    other = "zone"
    while other in tested:
        other += "_"
    return ["", *sorted(tested), other]


def domain_classes(docs, domain: ReadingDomain, read_also: Tuple[str, ...] = (), boundary_ints: bool = False):
    """The finite reading domain of one or more policy documents over the same fields, as value classes:
    `(names, constant, groups)`. `names` are the fields some rule of some document reads (and `read_also`),
    `constant` gives every other field its first value, and `groups[i]` are the classes of `names[i]`, grouped
    so that every atom any of the documents has on that field is true of all of a class or of none (see
    `_classes`). A first rule that holds is then a function of the classes, so each document decides a
    combination of classes as one, by its first values, and `unproduced` names the combinations the
    producer never gives. Raises DomainError when a field has no finite domain. The profile compiler walks it for
    one image, and the widening comparator (`prismpath.distribution.widening`) for two. With `boundary_ints` an
    integer field whose range is too wide to list stands for itself by its boundary values
    (`_boundary_domain`), which is exact when every rule is read as atoms; the profile compiler does not use it."""
    fields = docs[0]["fields"]
    atoms: Dict[str, List[list]] = {name: [] for name in fields}
    understood = True
    read = set(read_also)
    for doc in docs:
        for rule in doc["rules"]:
            found: List[list] = []
            understood = _atoms(rule["when"], found) and understood
            for atom in found:
                if atom[1] in atoms:
                    atoms[atom[1]].append(atom)
            read |= names_read(rule["when"], fields)
    domains = {}
    for name, text in sorted(fields.items()):
        if domain.name_field is not None and name == domain.name_field and text.split()[:1] == ["category"]:
            if any(name_problem(rule["when"], domain) for doc in docs for rule in doc["rules"]):
                raise DomainError(f"a rule tests {name} other than for equality with one name")
            domains[name] = _names_tested(docs, name)
            continue
        try:
            domains[name] = field_values(name, text, domain)
        except DomainError:
            if not (boundary_ints and text.split()[0] == "int"):
                raise
            wide: List[list] = []
            if not all(_wide_atoms(rule["when"], wide) for doc in docs for rule in doc["rules"]):
                raise
            domains[name] = _boundary_domain(name, text, [atom for atom in wide if atom[1] == name])
    names = sorted(read)
    constant = {name: values[0] for name, values in domains.items() if name not in read}
    groups = [_classes(domains[n], atoms[n]) if understood else [[v] for v in domains[n]] for n in names]
    return names, constant, groups


def _bounds(name: str, text: str, domain: ReadingDomain):
    """The values a rule may name for a field: a set for a category the domain lists and for a bool, the
    (low, high) range of an int, or None for a field whose definition sets no bounds here."""
    words = text.split()
    kind = words[0] if words else ""
    if kind == "category":
        return frozenset(domain.categories[name]) if name in domain.categories else None
    if kind == "bool":
        return frozenset({False, True})
    if kind == "int":
        options = dict(word.split("=", 1) for word in words[1:] if "=" in word)
        try:
            return int(options["min"]), int(options["max"])
        except (KeyError, ValueError):
            return None
    return None


def reading_outside_domain(fields, reading, domain: ReadingDomain) -> Optional[str]:
    """The first category value of a reading outside its field's reading domain, the values the domain lists, as a
    sentence, or None. A bool or an int out of its declared kind or range is the core's to refuse, as it always has
    (`route:contract-violation`), and so is a key that is not one of the policy's fields, an absent value and a
    category with no known values."""
    if not isinstance(reading, dict):
        return None
    for name, text in fields.items():
        if name not in reading or reading[name] is None:
            continue
        if not text.split()[:1] == ["category"] or name not in domain.categories:
            continue
        value = reading[name]
        inside = isinstance(value, str) and value in domain.categories[name]
        if not inside:
            return f"the reading gives {name} {value!r}, which is outside the field's reading domain"
    return None


def outside_domain(doc, domain: ReadingDomain) -> Optional[str]:
    """The first value a rule of the policy document names outside its field's reading domain, as a sentence, or
    None when every value it names is inside. The domain is what the installer defined: the values the domain lists
    for a category, true and false for a bool, and min to max for an int, where an equality or a membership names a
    value and an ordering only bounds one. A value outside the domain is a resource nobody accounted for. The walk of
    `domain_classes` never meets it, so the widening comparator could not see a rule that allows it
    (spec-policy-distribution.md, 9.4)."""
    fields = doc.get("fields") if isinstance(doc, dict) else None
    if not isinstance(fields, dict):
        return None
    for rule in doc.get("rules") or ():
        if domain.name_field is not None and domain.name_field in fields and isinstance(rule, dict) \
                and name_problem(rule.get("when"), domain):
            return (f"a rule tests {domain.name_field} other than for equality with one name the zone point "
                    f"can read")
        stack = [rule.get("when") if isinstance(rule, dict) else None]
        while stack:
            item = stack.pop()
            if not isinstance(item, list) or not item:
                continue
            head = item[0]
            if head == "cmp" and len(item) == 4 and item[1] in fields:
                name, op, constants = item[1], item[2], [item[3]]
            elif head in ("in", "not in") and len(item) == 3 and item[1] in fields and isinstance(item[2], list):
                name, op, constants = item[1], head, item[2]
            else:
                stack.extend(item)
                continue
            bounds = _bounds(name, fields[name], domain)
            if bounds is None:
                continue
            for constant in constants:
                value = constant[1] if isinstance(constant, list) and len(constant) == 2 else constant
                if value is None:
                    continue                    # absence is the kernel's to check (policy:none)
                if isinstance(bounds, tuple):
                    inside = (op not in ("==", "!=", "in", "not in") or not isinstance(value, int)
                              or isinstance(value, bool) or bounds[0] <= value <= bounds[1])
                else:
                    inside = value in bounds and type(value) is type(next(iter(bounds)))
                if not inside:
                    return f"a rule names {name} {value!r}, which is outside the field's reading domain"
    return None
