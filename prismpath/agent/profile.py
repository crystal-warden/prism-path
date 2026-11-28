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

The domain walk is the kernel's (prismpath/kernel/domain.py), bound here to the agent's reading domain
(`AGENT_DOMAIN`). `prismpath agent rules` uses the same walk for its unreachable finding, with the same domains and the
same constant for a field no rule reads, and a bool field such as `path_control` needs no entry in the domain because
a bool is enumerated by its definition, not by name.

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
from prismpath.kernel import domain as _kernel_domain
from prismpath.kernel.decision import kind_of  # noqa: F401 - the kind `Policy.decide` gives a reading, for the widening walk
from prismpath.kernel.domain import AGENT_DOMAIN, MAX_INT_RANGE, DomainError  # noqa: F401
from prismpath.kernel.predicates import holds as _holds

FORMAT = "prismpath.profile/1"          # a profile with no `net`: the bytes (and hash) every such profile has always had
FORMAT_NET = "prismpath.profile/2"      # a profile that carries `net`
COMPILER_VERSION = 1           # raise it when `compile_profile` changes what it makes from an image, so a cached profile is not reused
ROLES = ("bash", "agent")
SYSTEM_PREFIX = "/usr"
WORKSPACE = "workspace"        # the role of the one read write path; the runner binds the real directory
MAX_PROCESSES = 64
TIMEOUT_S = 30                 # the harness's limit for one call (integrations/governed_harness/sandbox.py)

# the values each classifier field takes (the field list at the top of prismpath/agent/classifier.py), the agent's
# reading domain, which the kernel holds (prismpath/kernel/domain.py)
KNOWN_CATEGORIES = AGENT_DOMAIN.categories
REQUIRED_FIELDS = ("path_scope", "command_class", "git_op")
# What the classifier never produces, so the walk does not decide it (`ReadingDomain.unproduced`)
CLASSIFIER_ONLY = AGENT_DOMAIN.unproduced
OUTSIDE_SCOPES = ("outside", "unknown", None)
NETWORK_VALUES = ("network", "unknown")
CHANGING_TOOLS = ("write_file", "delete_path")
CHANGING_COMMANDS = ("mutating", "network", "git", "unknown")
CHANGING_GIT_OPS = ("local_write", "mutating", "push", "network", "unknown")


NET_STATES = ("none", "proxy_model", "proxy_allow")


# The image cannot be projected onto a profile; the caller runs nothing. It is the kernel's `DomainError`, so a walk
# of the domain that fails and a profile that cannot be made are caught alike.
ProfileError = DomainError


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
# The walk is the kernel's (prismpath/kernel/domain.py), here bound to the agent's domain. `prismpath agent rules`
# uses the same walk for its unreachable finding.
ZONE_NAME = AGENT_DOMAIN.name_field
ZONE_NAME_MAX = AGENT_DOMAIN.name_max


def _domain(name: str, text: str) -> List[Any]:
    """The finite list of values of a field from its definition, or ProfileError saying why there is none."""
    return _kernel_domain.field_values(name, text, AGENT_DOMAIN)


_names_read = _kernel_domain.names_read


def zone_name_ok(name: Any) -> bool:
    """A value the zone point can read as one `agent.zones` name: 1 to 512 characters and no path."""
    return _kernel_domain.name_ok(name, AGENT_DOMAIN)


def zone_name_problem(when) -> bool:
    """AF1 (spec-policy-distribution.md, 21.2): a rule tests `zone_name` other than for equality with one name the
    zone point can read, as a conjunct of the whole rule. Such a rule is `policy:out-of-domain`."""
    return _kernel_domain.name_problem(when, AGENT_DOMAIN)


def domain_classes(docs, read_also: Tuple[str, ...] = (), boundary_ints: bool = False):
    """`kernel.domain.domain_classes` over the agent's domain."""
    return _kernel_domain.domain_classes(docs, AGENT_DOMAIN, read_also, boundary_ints)


def unproduced(names: List[str], combo) -> bool:
    """True when a combination of value groups is one the classifier never gives (`CLASSIFIER_ONLY`)."""
    return _kernel_domain.unproduced(names, combo, AGENT_DOMAIN)


_unproduced = unproduced


def reading_outside_domain(fields, reading) -> Optional[str]:
    """`kernel.domain.reading_outside_domain` over the agent's domain."""
    return _kernel_domain.reading_outside_domain(fields, reading, AGENT_DOMAIN)


def outside_domain(doc) -> Optional[str]:
    """`kernel.domain.outside_domain` over the agent's domain."""
    return _kernel_domain.outside_domain(doc, AGENT_DOMAIN)




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
    from prismpath.kernel.decision import Policy as CorePolicy
    if role not in ROLES:
        raise ProfileError(f"role must be one of {ROLES}, not {role!r}")
    try:
        policy = image if isinstance(image, CorePolicy) else Policy(image)
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
