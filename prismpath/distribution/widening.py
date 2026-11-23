# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The widening rule of policy distribution (spec-policy-distribution.md, section 9.4, V12 and RB3).

A release is larger than another when some request is treated more permissively. The comparators here
answer that per artifact, `LARGER`, `NOT_LARGER` or `CANNOT_DECIDE`:

    policy.core      every reading of the finite reading domain, walked by the classes the agent profile
                     compiler uses (`profile.domain_classes`), and a reading that moves up the order refuse,
                     escalate, allow is larger. Two policies whose fields differ are larger
    egress.hosts     larger when the staged list is not a subset of the active one
    gateway.routes   any change is larger
    agent.zones      larger when a protected name is gone, and a release that drops the artifact drops them all
    policy.ppt       any change is larger, since the table format gives its nodes no meaning and nothing in
                     the image says which outcome is the more permissive one
    cfs.table        ordered by the core image inside it, registered from `integrations/cfs/dist_kind.py`

Going from no policy to any policy is larger, and an answer that cannot be reached is treated as larger. A
kind registered from outside this package, such as the XDP edge's `net.dests`, adds its comparator with
`register_comparator`.

`check` is V12 for one envelope at staging and `check_release` for a whole release at commit. A PEP that can
decide computes the answer itself (W1) and refuses a release it finds larger whose `widens` is false, even
with a statement (W6). A PEP that cannot decide treats a release as not larger only when `widens` is false
and `replaces` is its active policy hash (W2). A larger release needs a `trust.widening` statement of the
same release, staged before it, whose `from` is empty or holds the active policy hash (W3, W4). `covers`
answers that last part, and a rollback (RB3) uses the same comparison, with a release identical to the active
one never larger.
"""
from __future__ import annotations

from typing import Callable, Dict, Mapping, Optional, Sequence

from prismpath.distribution import kinds
from prismpath.distribution.adapters import CANNOT_DECIDE, LARGER, NOT_LARGER
from prismpath.distribution.kinds import Refused

UNSIGNED = "dist:widening-unsigned"
RANK = {"refuse": 0, "escalate": 1, "allow": 2}

Comparator = Callable[[bytes, bytes], str]       # (active body, staged body) -> LARGER, NOT_LARGER, CANNOT_DECIDE


def compare_policies(active: bytes, staged: bytes) -> str:
    """W1 for `policy.core`: walk the finite reading domain once for both images, a class at a time, and find
    the first reading the staged policy treats more permissively. A combination the classifier never gives
    (`profile.unproduced`) is walked too, so a release that allows more there is larger, and one that refuses
    more there is a tightening (9.4)."""
    from prismpath.agent import profile
    from prismpath.agent.policy import Policy
    if active == staged:
        return NOT_LARGER
    try:
        old, new = Policy(active), Policy(staged)
    except ValueError:
        return CANNOT_DECIDE
    if old.doc["fields"] != new.doc["fields"]:
        return LARGER                                  # 9.4: two policies without the same fields
    try:
        names, constant, groups = profile.domain_classes([old.doc, new.doc], boundary_ints=True)
    except profile.ProfileError:
        return CANNOT_DECIDE
    import itertools
    for combo in itertools.product(*groups):
        reading = dict(zip(names, (group[0] for group in combo)), **constant)
        before, after = RANK[profile.kind_of(old, reading)], RANK[profile.kind_of(new, reading)]
        if after > before:
            return LARGER                              # 9.4: on a combination the classifier never gives as well
    return NOT_LARGER


def _names(body: bytes, read: Callable[[object], Sequence[str]]) -> Optional[frozenset]:
    try:
        return frozenset(read(kinds.load_canonical(body, "a compared artifact")))
    except (Refused, TypeError, KeyError, ValueError):
        return None


def _host_list(doc) -> Sequence[str]:
    if not isinstance(doc, list) or not all(isinstance(name, str) for name in doc):
        raise ValueError("not a list of host names")
    return doc


def _protected(doc) -> Sequence[str]:
    if not isinstance(doc, dict) or not isinstance(doc.get("protected"), list):
        raise ValueError("not a zone file")
    return doc["protected"]


def compare_hosts(active: bytes, staged: bytes) -> str:
    """W1 for `egress.hosts`: larger when a staged host is not in the active list."""
    old, new = _names(active, _host_list), _names(staged, _host_list)
    if old is None or new is None:
        return CANNOT_DECIDE
    return NOT_LARGER if new <= old else LARGER


def compare_routes(active: bytes, staged: bytes) -> str:
    """W1 for `gateway.routes`: any change is larger, because a path that loses its route reads as another class."""
    return NOT_LARGER if bytes(active) == bytes(staged) else LARGER


def compare_ppt(active: bytes, staged: bytes) -> str:
    """W1 for `policy.ppt`: the same image is not larger and any other is (section 9.4)."""
    return NOT_LARGER if bytes(active) == bytes(staged) else LARGER


def compare_zones(active: Optional[bytes], staged: Optional[bytes]) -> str:
    """W1 for `agent.zones`: larger when a name the active file protects is gone. No file protects nothing."""
    old = frozenset() if active is None else _names(active, _protected)
    new = frozenset() if staged is None else _names(staged, _protected)
    if old is None or new is None:
        return CANNOT_DECIDE
    return NOT_LARGER if old <= new else LARGER


COMPARATORS: Dict[str, Comparator] = {
    "policy.core": compare_policies,
    "egress.hosts": compare_hosts,
    "gateway.routes": compare_routes,
    "agent.zones": compare_zones,
    "policy.ppt": compare_ppt,
}
OPTIONAL = frozenset({"agent.zones"})              # an artifact whose absence is a value: it drops every name


def register_comparator(artifact: str, comparator: Comparator) -> None:
    """Add the comparator of an artifact whose reader lives outside this package. One per artifact."""
    if artifact not in kinds.ARTIFACTS or artifact in kinds.TRUST_ARTIFACTS:
        raise ValueError(f"{artifact!r} is not an artifact a release carries")
    existing = COMPARATORS.get(artifact)
    if existing is not None and existing is not comparator:
        raise ValueError(f"{artifact} already has a comparator")
    COMPARATORS[artifact] = comparator


def compare_artifact(artifact: str, active: Optional[bytes], staged: Optional[bytes]) -> str:
    """W1 for one artifact. An artifact with no comparator compares only as unchanged bytes. Three follow the
    policy of their release and answer not larger: `sandbox.profile` and `net.edge`, which a kind that uses
    them holds to what it compiles from the staged policy (`dist:derived-mismatch`), and `policy.spiral`, which
    the host's adapter holds at commit to the sidecar hash the `policy.ppt` envelope signs (C2)."""
    if artifact in ("sandbox.profile", "net.edge", "policy.spiral"):
        return NOT_LARGER
    if artifact in OPTIONAL:
        return COMPARATORS[artifact](active, staged)
    if active is None or staged is None:
        return LARGER if staged is not None else NOT_LARGER
    comparator = COMPARATORS.get(artifact)
    if comparator is None:
        return NOT_LARGER if bytes(active) == bytes(staged) else CANNOT_DECIDE
    return comparator(bytes(active), bytes(staged))


def compare_release(active: Optional[Mapping[str, bytes]], staged: Mapping[str, bytes]) -> str:
    """W1 for a whole release, the artifacts of each as {artifact: body}, trust kinds left out. None for
    `active` is no policy, and any release is larger than that. The release is larger when one artifact is,
    and cannot be decided when one artifact cannot and none is larger."""
    if active is None:
        return LARGER
    active = {name: body for name, body in active.items() if name not in kinds.TRUST_ARTIFACTS}
    staged = {name: body for name, body in staged.items() if name not in kinds.TRUST_ARTIFACTS}
    if active == staged:
        return NOT_LARGER
    answers = {compare_artifact(name, active.get(name), staged.get(name))
               for name in sorted(set(active) | set(staged))
               if name in staged or name in OPTIONAL}
    if LARGER in answers:
        return LARGER
    return CANNOT_DECIDE if CANNOT_DECIDE in answers else NOT_LARGER


def covers(statement: Optional[bytes], active_policy: Optional[str]) -> bool:
    """W4: a widening statement covers a PEP when its `from` is empty or holds the PEP's active policy hash."""
    if statement is None:
        return False
    froms = kinds.read_widening(statement)["from"]
    return not froms or (active_policy is not None and active_policy in froms)


def larger(target: kinds.Target, *, widens: bool, replaces: str, active_policy: Optional[str],
           answer: Optional[str]) -> bool:
    """Whether the PEP treats a release as larger. `answer` is its own comparison when it can decide (W1), and
    anything but not larger counts as larger. A PEP that cannot decide reads the release's `widens` and
    `replaces` (W2), and still counts as larger what a comparison it can make, `answer`, finds larger."""
    if target.decides:
        return answer != NOT_LARGER
    return widens or active_policy is None or replaces != active_policy or answer == LARGER


def check(target: kinds.Target, *, widens: bool, replaces: str, active_policy: Optional[str],
          answer: Optional[str], statement: Optional[bytes]) -> Optional[str]:
    """V12 for a release with these `widens` and `replaces`, on a PEP whose active policy hash is
    `active_policy`. `answer` is the PEP's own comparison: of the whole release when it can decide, and on a kind
    that cannot of the artifacts in its row's `compares`, a table any change of which is larger, which no
    statement saves when `widens` is false (W6). `statement` is the body of the `trust.widening` envelope staged
    for the same release, or None. None when the release may be staged or committed, else
    `dist:widening-unsigned`. Going from no policy to any is a comparison every PEP makes, so a first install
    whose `widens` is false is refused on every kind, with a statement or without (W6)."""
    if active_policy is None:
        answer = LARGER
    if not larger(target, widens=widens, replaces=replaces, active_policy=active_policy, answer=answer):
        return None
    if not widens and (target.decides or answer == LARGER):
        return UNSIGNED                                # W6: the signer said it does not widen, and it does
    return None if covers(statement, active_policy) else UNSIGNED
