# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The sandbox profile a signed policy image needs, and nothing more.

A profile says what a process tree started for an allowed call may reach: the paths mounted read only (the
system prefix), the one read write path (the workspace), whether a network is present, and a process and a
time limit. `compile_profile(image)` projects an image onto one by walking its whole allow set. The reading
domain is finite (every combination of the values of the image's fields: a bool is true or false, an int is its
min to max range, a category is one of the values the classifier produces), every reading in it is decided
through the reference decision path (`Policy.decide`, which is `prismpath.kernel.core_reference`), and a
capability is switched on only if some allowed reading needs it:

  outside the workspace   some allowed reading has path_scope "outside" (or "unknown", which could be
                          anywhere, or no value where the image lets the field be absent). Then the host
                          filesystem is mounted read only, and read write too when an allowed reading of that
                          kind changes something. Otherwise only the system prefix and the workspace exist.
  network                 some allowed reading has command_class "network" or git_op "network"
                          (or "unknown" for either, which could be anything). A git push is not counted: the
                          starters allow a push to a remote the owner named, so counting it would give every
                          starter a network. A push in the sandbox fails for want of one, which is the sandbox
                          being stricter than the oracle, the safe direction.

Nothing here decides a reading itself: the allow set is the set of readings the reference decides `allow`.

The domain walk is the one `prismpath agent rules` uses for its unreachable finding (`_domain` and
`_names_read` in prismpath/agent/rules.py, branch rule-table) and the one control-files adds a bool field to
(`path_control`): the same domains and the same constant for a field no rule reads. It is written out here
rather than imported so this file does not depend on code that is not merged yet. Once both are merged,
rules.py should keep the walker and this module should import `_domain`, `_names_read` and KNOWN_CATEGORIES
from it (or all three move to one `prismpath/agent/domain.py`), and `path_control` needs no change here
because a bool is enumerated by its definition, not by name.

Fail closed. An image that does not define the three fields a profile is projected from (`path_scope`,
`command_class`, `git_op`), or one with a field that has no finite domain (a category the classifier does not
produce, a fixed point number, an int with a range of 64 values or more, a definition that does not parse),
cannot be walked, so `compile_profile` raises `ProfileError` naming the field and why. It does not guess a
profile: a caller treats the error as a refusal and runs nothing. A caller that wants a profile anyway can use
`STRICTEST`, which mounts nothing but the system prefix and the workspace and has no network.

The canonical bytes are a canon/2 object (prismpath.kernel.canon2), and the hash is the SHA-256 of those bytes. A
profile with no `net` (every bash role profile, and the starters') is `prismpath.profile/1` with the same bytes it
always had, so its hash does not move. A profile that carries `net` is `prismpath.profile/2`, which adds that one field.

Roles. `compile_profile(image, "bash")` is the profile of one allowed shell command and never has a proxy: `net` is
`none`. `compile_profile(image, "agent")` is the profile of the whole agent process tree: the mounts are the fixed
ones (the system prefix read only and the workspace, never the host and never the host network), and `net` comes from
the allow set: `proxy_model` when some allowed `connect` reading has `net_dest` `model_api`, `proxy_allow` when some
has `allowed_host` as well, `none` otherwise (`other` and `unknown` never give a state). The proxy decides each
connection with the same image (prismpath/agent/egress_policy.py), so the compiled state and the proxy's answer are
one decision, held together by the differential test (prismpath/tests/test_egress_policy.py). The profile does not carry the image's hash: two images that need the same things
get the same profile and the same hash, and a receipt records the image's hash beside the profile's.
"""
from __future__ import annotations

import hashlib
import itertools
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

from prismpath.kernel import canon2

FORMAT = "prismpath.profile/1"          # a profile with no `net`: the bytes (and hash) every such profile has always had
FORMAT_NET = "prismpath.profile/2"      # a profile that carries `net`
COMPILER_VERSION = 1           # raise it when `compile_profile` changes what it makes from an image, so a cached profile is not reused
ROLES = ("bash", "agent")
SYSTEM_PREFIX = "/usr"
WORKSPACE = "workspace"        # the role of the one read write path; the runner binds the real directory
MAX_PROCESSES = 64
TIMEOUT_S = 30                 # the harness's limit for one call (integrations/governed_harness/sandbox.py)
MAX_INT_RANGE = 64

# the values each classifier field takes (the field list at the top of prismpath/agent/classifier.py)
KNOWN_CATEGORIES = {
    "tool": ("list_dir", "read_file", "write_file", "delete_path", "run_command", "git", "connect", "unknown"),
    "path_scope": ("none", "workspace", "outside", "unknown"),
    "command_class": ("none", "read_only", "mutating", "network", "git", "unknown"),
    "git_op": ("none", "local_read", "local_write", "mutating", "push", "network", "unknown"),
    "remote_class": ("none", "allowed", "other"),
    "net_dest": ("none", "model_api", "allowed_host", "other", "unknown"),
    "proc_class": ("none", "single", "tree", "unknown"),
    "zone_reach": ("none", "protected", "unknown"),
    "session_protected_changes": ("none", "some"),
    "session_shell_runs": ("none", "few", "many"),
}
REQUIRED_FIELDS = ("path_scope", "command_class", "git_op")
# What the classifier never produces, so the walk does not decide it: a field that is `none` unless another field has
# one of some values (a `net_dest` other than none only for a `connect`, a `proc_class` other than none only for a
# `run_command`, a `zone_reach` other than none only for a file tool or a `run_command`). (field, its empty value, the gate field, the gate values.) A group of values is skipped only when it
# holds no empty value and its gate group holds none of the gate values, so a policy whose rules cannot tell the gate
# values apart is still walked whole. Without this the three fields multiply the walk by their classes.
CLASSIFIER_ONLY = (("net_dest", "none", "tool", ("connect",)), ("proc_class", "none", "tool", ("run_command",)),
                   ("zone_reach", "none", "tool", ("write_file", "delete_path", "run_command")))
OUTSIDE_SCOPES = ("outside", "unknown", None)
NETWORK_VALUES = ("network", "unknown")
CHANGING_TOOLS = ("write_file", "delete_path")
CHANGING_COMMANDS = ("mutating", "network", "git", "unknown")
CHANGING_GIT_OPS = ("local_write", "mutating", "push", "network", "unknown")


NET_STATES = ("none", "proxy_model", "proxy_allow")


class ProfileError(Exception):
    """The image cannot be projected onto a profile; the caller runs nothing."""


@dataclass(frozen=True)
class Profile:
    ro_mounts: Tuple[str, ...] = (SYSTEM_PREFIX,)
    rw_path: str = WORKSPACE
    host_write: bool = False       # the host mount is read write, not read only (only with an outside mount)
    network: bool = False
    max_processes: int = MAX_PROCESSES
    timeout_s: int = TIMEOUT_S
    net: str = "none"      # none | proxy_model | proxy_allow: the two proxy states reach only a proxy socket, never the host network

    def __post_init__(self) -> None:
        if self.net not in NET_STATES:
            raise ProfileError(f"net must be one of {NET_STATES}, not {self.net!r}")
        if self.net != "none" and self.network:
            raise ProfileError("a profile with a proxy cannot also share the host network")

    def to_object(self) -> Dict[str, Any]:
        obj = {"format": FORMAT_NET if self.net != "none" else FORMAT, "ro_mounts": sorted(self.ro_mounts), "rw_path": self.rw_path,
               "host_write": self.host_write, "network": self.network, "max_processes": self.max_processes, "timeout_s": self.timeout_s}
        if self.net != "none":      # absent when none, so every profile that exists keeps its canonical bytes and hash
            obj["net"] = self.net
        return obj

    def canonical(self) -> bytes:
        """The profile's canonical canon/2 bytes."""
        return canon2.dumps(self.to_object())

    def hash(self) -> str:
        """The SHA-256 of the canonical bytes, lowercase hex."""
        return hashlib.sha256(self.canonical()).hexdigest()

    @property
    def host_visible(self) -> bool:
        """True when more than the system prefix and the workspace is mounted."""
        return tuple(self.ro_mounts) != (SYSTEM_PREFIX,)


STRICTEST = Profile()


# ------------------------------------------------------------------------------------------ the domain
def _names_read(when, fields) -> set:
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


def _domain(name: str, text: str) -> List[Any]:
    """The finite list of values of a field from its definition, or ProfileError saying why there is none."""
    words = text.split()
    if not words:
        raise ProfileError(f"field {name!r} has an empty definition")
    kind = words[0]
    options = dict(w.split("=", 1) for w in words[1:] if "=" in w)
    if kind == "bool":
        values: List[Any] = [False, True]
    elif kind == "int":
        try:
            lo, hi = int(options["min"]), int(options["max"])
        except (KeyError, ValueError):
            raise ProfileError(f"field {name!r} is an int without a readable min and max: {text!r}")
        if not 0 <= hi - lo < MAX_INT_RANGE:
            raise ProfileError(f"field {name!r} is an int with {hi - lo + 1} values, past the {MAX_INT_RANGE} "
                               f"the walk enumerates")
        values = list(range(lo, hi + 1))
    elif kind == "category":
        if name not in KNOWN_CATEGORIES:
            raise ProfileError(f"field {name!r} is a category the classifier does not produce, so it has "
                               f"no finite domain")
        values = list(KNOWN_CATEGORIES[name])
    else:
        raise ProfileError(f"field {name!r} is a {kind!r}, which has no finite domain")
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


def _gives(reading: Dict[str, Any]) -> Tuple[bool, bool, bool]:
    """(outside, outside_write, network): what one allowed reading needs of the sandbox."""
    scope, command, git = reading["path_scope"], reading["command_class"], reading["git_op"]
    outside = scope in OUTSIDE_SCOPES
    changes = (reading.get("tool") in CHANGING_TOOLS or command in CHANGING_COMMANDS
               or git in CHANGING_GIT_OPS or reading.get("tool") not in KNOWN_CATEGORIES["tool"])
    return outside, outside and changes, command in NETWORK_VALUES or git in NETWORK_VALUES


def _net_gives(reading: Dict[str, Any]) -> Tuple[bool, bool]:
    """(model_api, allowed_host): which proxy classes one allowed reading needs. Only a `connect` gives either."""
    if reading.get("tool") != "connect":
        return False, False
    dest = reading.get("net_dest")
    return dest == "model_api", dest == "allowed_host"


_PARSED: Dict[str, Any] = {}


def _holds(condition: str, reading: Dict[str, Any]) -> bool:
    """`predicates.eval_condition`, step for step, with the parse and the static check of a condition made once and
    kept (they depend on the condition's text alone). The walk asks the same few conditions of every reading, and
    parsing them each time was most of its cost."""
    import ast
    from prismpath.kernel import predicates
    cached = _PARSED.get(condition)
    if cached is None:
        expr = predicates._expr_of(condition)
        low = expr.lower()
        if low in predicates.ALWAYS or low in predicates.NEVER:
            cached = ("const", low in predicates.ALWAYS)
        else:
            try:
                tree = ast.parse(expr, mode="eval")
                predicates.fold_unary_signs(tree)
                for node in ast.walk(tree):
                    if not isinstance(node, predicates._ALLOWED_NODES):
                        raise predicates.PredicateError(f"disallowed syntax ({type(node).__name__})")
                cached = ("tree", tree)
            except (SyntaxError, ValueError):       # PredicateError is a ValueError: unreadable, never matching
                cached = ("never", False)
        _PARSED[condition] = cached
    kind, value = cached
    if kind == "tree":
        return bool(predicates._ev(value.body, reading, 0))
    return value


def _first_allows(policy, reading: Dict[str, Any]) -> bool:
    """A quick screen, never the answer: the two steps of the reference's decision (`system_boundary`, then the
    first rule that holds, as `core_reference._python_verdict` takes them) without the policy check
    `Policy.decide` also runs, which does not change a verdict but is most of its cost. A reading it turns away
    is refused or escalated by the reference as well; a reading it passes is still decided by `Policy.decide`
    before it counts. The first rule is found as `engine.first_deterministic` finds it, by `_holds`."""
    from prismpath.kernel import field_definitions, predicates
    try:
        if field_definitions.system_boundary(policy.graph, reading) is not None:
            return False
        for target, condition in policy.graph.nodes[policy.graph.start].edges:
            if not predicates.is_deterministic(condition):
                continue
            try:
                if _holds(condition, reading):
                    return target == "allow"
            except predicates.PredicateError:
                pass
        return False
    except Exception:  # noqa: BLE001 - decided by the full path, which refuses it
        return True


def kind_of(policy, reading: Dict[str, Any]) -> str:
    """The kind `Policy.decide` gives `reading`, `allow`, `refuse` or `escalate`, by the reference's two steps
    (`core_reference._python_verdict`): the system boundary, then the first deterministic rule that holds, found
    as `engine.first_deterministic` finds it but with each condition parsed once (`_holds`), and the policy check
    left out, which does not change a verdict. A reading the session fields are missing from is given them at
    their most restrictive, as `Policy.reading_bytes` does. The widening comparator walks a whole domain with
    it, and `prismpath/tests/test_distribution_widening.py` holds it to `Policy.decide`."""
    from prismpath.agent import session_state
    from prismpath.agent.policy import target_decision
    from prismpath.kernel import field_definitions, predicates
    if policy.stateful and not all(name in reading for name in session_state.FIELDS):
        reading = {**session_state.RESTRICTIVE, **reading}
    try:
        if field_definitions.system_boundary(policy.graph, reading) is not None:
            return "refuse"
        for target, condition in policy.graph.nodes[policy.graph.start].edges:
            if not predicates.is_deterministic(condition):
                continue
            try:
                if _holds(condition, reading):
                    decision = target_decision(target)
                    return decision[0] if decision is not None else "refuse"
            except predicates.PredicateError:
                pass
    except Exception:  # noqa: BLE001 - the reference refuses a reading it cannot decide
        return "refuse"
    return "refuse"


def _unproduced(names: List[str], combo) -> bool:
    """True when a combination of value groups is one the classifier never gives (`CLASSIFIER_ONLY`)."""
    groups = dict(zip(names, combo))
    for field, empty, gate, values in CLASSIFIER_ONLY:
        if field in groups and gate in groups and empty not in groups[field] \
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
    false alike, so they meet every class `_classes` makes of the whole range. ProfileError when an atom is not
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
            raise ProfileError(f"field {name!r} is an int with an atom the boundary walk does not read")
        for const in constants:
            points.update(value for value in (const - 1, const, const + 1) if low <= value <= high)
    values: List[Any] = sorted(points)
    if options.get("absent") == "allowed":
        values.append(None)
    return values


ZONE_NAME = "zone_name"
ZONE_NAME_MAX = 512


def zone_name_ok(name: Any) -> bool:
    """A value the zone point can read as one `agent.zones` name: 1 to 512 characters and no path."""
    return isinstance(name, str) and 1 <= len(name) <= ZONE_NAME_MAX and "/" not in name and name not in (".", "..")


def _conjuncts(when) -> List[Any]:
    if isinstance(when, list) and when and when[0] == "and":
        return [part for operand in when[1:] for part in _conjuncts(operand)]
    return [when]


def _mentions(when, name: str) -> bool:
    if not isinstance(when, list):
        return False
    return (len(when) >= 2 and when[0] in ("cmp", "in", "not in", "truthy") and when[1] == name) or any(
        _mentions(part, name) for part in when[1:] if isinstance(part, list))


def zone_name_problem(when) -> bool:
    """AF1 (spec-policy-distribution.md, 21.2): a rule tests `zone_name` other than for equality with one name the
    zone point can read, as a conjunct of the whole rule. Such a rule is `policy:out-of-domain`."""
    for conjunct in _conjuncts(when):
        if not _mentions(conjunct, ZONE_NAME):
            continue
        if not (isinstance(conjunct, list) and len(conjunct) == 4 and conjunct[0] == "cmp" and conjunct[1] == ZONE_NAME
                and conjunct[2] == "==" and isinstance(conjunct[3], list) and len(conjunct[3]) == 2
                and conjunct[3][0] == "str" and zone_name_ok(conjunct[3][1])):
            return True
    return False


def _zone_names(docs) -> List[Any]:
    """AF1, 9.4: the walk of `zone_name` needs no list of every name, because a rule only tests equality. It takes the
    empty name, each name either document tests, and one name neither tests, which stands for every other."""
    tested = set()
    for doc in docs:
        for rule in doc["rules"]:
            for conjunct in _conjuncts(rule["when"]):
                if (isinstance(conjunct, list) and len(conjunct) == 4 and conjunct[:3] == ["cmp", ZONE_NAME, "=="]
                        and isinstance(conjunct[3], list) and len(conjunct[3]) == 2):
                    tested.add(conjunct[3][1])
    other = "zone"
    while other in tested:
        other += "_"
    return ["", *sorted(tested), other]


def domain_classes(docs, read_also: Tuple[str, ...] = (), boundary_ints: bool = False):
    """The finite reading domain of one or more policy documents over the same fields, as value classes:
    `(names, constant, groups)`. `names` are the fields some rule of some document reads (and `read_also`),
    `constant` gives every other field its first value, and `groups[i]` are the classes of `names[i]`, grouped
    so that every atom any of the documents has on that field is true of all of a class or of none (see
    `_classes`). A first rule that holds is then a function of the classes, so each document decides a
    combination of classes as one, by its first values, and `_unproduced` names the combinations the
    classifier never gives. Raises ProfileError when a field has no finite domain. `needs_all` walks it for one
    image, and the widening comparator (`prismpath.distribution.widening`) for two. With `boundary_ints` an
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
            read |= _names_read(rule["when"], fields)
    domains = {}
    for name, text in sorted(fields.items()):
        if name == ZONE_NAME and text.split()[:1] == ["category"]:
            if any(zone_name_problem(rule["when"]) for doc in docs for rule in doc["rules"]):
                raise ProfileError("a rule tests zone_name other than for equality with one name")
            domains[name] = _zone_names(docs)
            continue
        try:
            domains[name] = _domain(name, text)
        except ProfileError:
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


unproduced = _unproduced          # the classifier's impossible combinations, for a walk of `domain_classes`


def _bounds(name: str, text: str):
    """The values a rule may name for a field: a set for a category the classifier produces and for a bool, the
    (low, high) range of an int, or None for a field whose definition sets no bounds here."""
    words = text.split()
    kind = words[0] if words else ""
    if kind == "category":
        return frozenset(KNOWN_CATEGORIES[name]) if name in KNOWN_CATEGORIES else None
    if kind == "bool":
        return frozenset({False, True})
    if kind == "int":
        options = dict(word.split("=", 1) for word in words[1:] if "=" in word)
        try:
            return int(options["min"]), int(options["max"])
        except (KeyError, ValueError):
            return None
    return None


def reading_outside_domain(fields, reading) -> Optional[str]:
    """The first category value of a reading outside its field's reading domain, the values the classifier
    produces (`KNOWN_CATEGORIES`), as a sentence, or None. A bool or an int out of its declared kind or range is
    the core's to refuse, as it always has (`route:contract-violation`), and so is a key that is not one of the
    policy's fields, an absent value and a category with no known values."""
    if not isinstance(reading, dict):
        return None
    for name, text in fields.items():
        if name not in reading or reading[name] is None:
            continue
        if not text.split()[:1] == ["category"] or name not in KNOWN_CATEGORIES:
            continue
        value = reading[name]
        inside = isinstance(value, str) and value in KNOWN_CATEGORIES[name]
        if not inside:
            return f"the reading gives {name} {value!r}, which is outside the field's reading domain"
    return None


def outside_domain(doc) -> Optional[str]:
    """The first value a rule of the policy document names outside its field's reading domain, as a sentence, or
    None when every value it names is inside. The domain is what the installer defined: the values the classifier
    produces for a category (`KNOWN_CATEGORIES`), true and false for a bool, and min to max for an int, where an
    equality or a membership names a value and an ordering only bounds one. A value outside the domain is a
    resource nobody accounted for. The walk of `domain_classes` never meets it, so the widening comparator could
    not see a rule that allows it (spec-policy-distribution.md, 9.4)."""
    fields = doc.get("fields") if isinstance(doc, dict) else None
    if not isinstance(fields, dict):
        return None
    for rule in doc.get("rules") or ():
        if ZONE_NAME in fields and isinstance(rule, dict) and zone_name_problem(rule.get("when")):
            return "a rule tests zone_name other than for equality with one name the zone point can read"
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
            bounds = _bounds(name, fields[name])
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


def needs(policy) -> Tuple[bool, bool, bool]:
    """(outside, outside_write, network) of `needs_all`, the three a bash role profile is made from."""
    return needs_all(policy)[:3]


def needs_all(policy, read_also: Tuple[str, ...] = ()) -> Tuple[bool, bool, bool, bool, bool]:
    """(outside, outside_write, network, model_api, allowed_host): the union over the allow set of what a reading needs, every reading
    of the finite domain decided through the reference (`Policy.decide`). Raises ProfileError when a field has
    no finite domain.

    The domain is walked by classes of values (see `_classes`), so a group is decided once, by its first value;
    when it is allowed, every value of the group is allowed alike, and the need of each reading of the group
    (a product of its members) is counted. A group whose readings need nothing not already found is not
    decided at all, since its answer could not change the result."""
    names, constant, groups = domain_classes([policy.doc], read_also)
    found = [False] * 5
    for combo in itertools.product(*groups):
        if _unproduced(names, combo):
            continue
        gave = [False] * 5
        for members in itertools.product(*combo):
            reading = dict(zip(names, members), **constant)
            gave = [a or b for a, b in zip(gave, (*_gives(reading), *_net_gives(reading)))]
        if all(f or not g for f, g in zip(found, gave)):
            continue        # nothing this group needs is still unknown, so it is not worth a decision
        reading = dict(zip(names, (g[0] for g in combo)), **constant)
        if _first_allows(policy, reading) and policy.decide(policy.reading_bytes(reading)).runs:
            found = [f or g for f, g in zip(found, gave)]
    return found[0], found[1], found[2], found[3], found[4]


def allow_set(policy):
    """Every reading of the finite domain the reference decides `allow`, as dicts (the whole set, undeduplicated;
    for inspection and tests, `needs` is what the compile uses). Raises ProfileError."""
    fields = policy.doc["fields"]
    domains = {name: _domain(name, text) for name, text in sorted(fields.items())}
    read = set()
    for rule in policy.doc["rules"]:
        read |= _names_read(rule["when"], fields)
    names = sorted(read)
    constant = {name: values[0] for name, values in domains.items() if name not in read}
    for combo in itertools.product(*(domains[name] for name in names)):
        reading = dict(zip(names, combo), **constant)
        if policy.decide(policy.reading_bytes(reading)).runs:
            yield reading


# ------------------------------------------------------------------------------------------- the compile
NET_ORDER = ("none", "proxy_model", "proxy_allow")


def join(*profiles: Profile) -> Profile:
    """The least profile that permits what each of `profiles` permits (spec-policy-distribution.md, AF1): the mounts
    of each, the host mount read write where one has it, the host network where one shares it, and the widest proxy
    state, which the host network replaces since a profile never has both. The limits are the first profile's."""
    if not profiles:
        raise ProfileError("a join of no profiles")
    first = profiles[0]
    mounts = ("/",) if any("/" in one.ro_mounts for one in profiles) else tuple(sorted({mount for one in profiles
                                                                                       for mount in one.ro_mounts}))
    network = any(one.network for one in profiles)
    net = "none" if network else max((one.net for one in profiles), key=NET_ORDER.index)
    return Profile(ro_mounts=mounts, rw_path=first.rw_path, host_write=any(one.host_write for one in profiles),
                   network=network, max_processes=first.max_processes, timeout_s=first.timeout_s, net=net)


def compile_profile(image: Union[bytes, "Policy"], role: str = "bash") -> Profile:  # noqa: F821
    """The profile an image needs: the strictest one its allow set permits. `role` is `bash` (one allowed shell
    command, never a proxy) or `agent` (the whole agent process tree, `net` from the allow set). Raises ProfileError."""
    from prismpath.agent.policy import Policy
    if role not in ROLES:
        raise ProfileError(f"role must be one of {ROLES}, not {role!r}")
    try:
        policy = image if isinstance(image, Policy) else Policy(image)
    except ValueError as exc:
        raise ProfileError(f"the image does not load: {exc}")
    required = REQUIRED_FIELDS + (("tool", "net_dest") if role == "agent" else ())
    for name in required:
        if name not in policy.doc["fields"]:
            raise ProfileError(f"the image does not define {name!r}, so its allow set cannot be projected")
    outside, outside_write, network, model, allowed = needs_all(policy, ("tool", "net_dest") if role == "agent" else ())
    if role == "agent":
        net = "proxy_allow" if allowed else "proxy_model" if model else "none"
        return Profile(net=net)         # the fixed mounts: the system prefix and the workspace, and never the host network
    mounts = ("/",) if outside else (SYSTEM_PREFIX,)
    return Profile(ro_mounts=mounts, host_write=outside_write, network=network)
