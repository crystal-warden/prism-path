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
                          being stricter than the oracle, the safe direction (plan WP4 lists such cases).

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


def _unproduced(names: List[str], combo) -> bool:
    """True when a combination of value groups is one the classifier never gives (`CLASSIFIER_ONLY`)."""
    groups = dict(zip(names, combo))
    for field, empty, gate, values in CLASSIFIER_ONLY:
        if field in groups and gate in groups and empty not in groups[field] \
                and not any(value in groups[gate] for value in values):
            return True
    return False


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
    doc = policy.doc
    fields = doc["fields"]
    domains = {name: _domain(name, text) for name, text in sorted(fields.items())}
    atoms: Dict[str, List[list]] = {name: [] for name in fields}
    understood = True
    for rule in doc["rules"]:
        found: List[list] = []
        understood = _atoms(rule["when"], found) and understood
        for atom in found:
            if atom[1] in atoms:
                atoms[atom[1]].append(atom)
    read = set(read_also)
    for rule in doc["rules"]:
        read |= _names_read(rule["when"], fields)
    names = sorted(read)
    constant = {name: values[0] for name, values in domains.items() if name not in read}
    groups = [_classes(domains[n], atoms[n]) if understood else [[v] for v in domains[n]] for n in names]
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
