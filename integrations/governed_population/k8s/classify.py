# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A Kubernetes AdmissionReview request for a `GovernedAgent`, read as one admission reading.

The resource model. One namespaced custom resource, `GovernedAgent` (group population.prismpath.dev), one
object per member, its `spec.parent` naming the parent member and an ownerReference to the parent's object,
so a foreground delete of a member removes its whole subtree through the garbage collector, as a stop does.
Every population request of the design is one API operation on that resource, and the operation together
with what it changes picks the request:

| API operation | Request | How the fields are formed |
|---|---|---|
| CREATE of a new name | `replicate` (one child; `requested` is 1) | the parent from the registry, the child from `spec` |
| CREATE of a name the webhook saw stopped | `restart`, `target_stopped` true | a stopped member brought back is a restart |
| CREATE or UPDATE with `spec.protect`, a finalizer added, or ownerReferences that do not name the parent; a DELETE that orphans the subtree | `protect` | anything that would keep a member from its parent's stop |
| UPDATE of `spec.version` (with `spec.evaluation`) | `evolve` | canary from the named evaluation run |
| UPDATE of `spec.restarts` upward | `restart` | the controller's crash recovery |
| DELETE | `stop` | the subtree goes with it |
| anything else | `unknown` | the image refuses it |

Pods are not the model: a Pod create carries no rights, version or key request a reading could take, its
deletion is the kubelet's and the controller's business, and a pod's labels are writable by whoever made it.
The custom resource holds exactly the facts the admission reading needs and nothing more, and the webhook
decides every write of it.

As in the simulation's controller, every field is formed from the registry (the GovernedAgent objects the
API server holds, and the webhook's own record of stops and refusals), never from what the request claims;
the request's claims enter only as the facts it asks for (rights, a key kind, a version, an evaluation run).
Who is asking is the API server's authentication: a member is the ServiceAccount named like its object in
the population's namespace, the controller is a configured ServiceAccount, the operator a configured group.

`target` is the relation of the request's target to the member asking, formed from the parent links the API
server holds: `self` (a CREATE whose `spec.parent` is the issuer, or a write of the issuer's own object),
`descendant` (an object below the issuer's in the parent links), `other` for anything else and for the
operator and the controller, who are no member. The image reads it: a member's replication is allowed only
with `target=self`, its evolution only with `self` or `descendant`, its stop only with either, and every
other replication or evolution of a member is refused with 123 `population:target-not-own`. So a member
asking for a child under another parent, or for an evolution outside its own subtree, is read as what it is
and refused by the image on that field, not decided on the named member's facts.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from prismpath.kernel import canon2

from .. import policy as pp
from ..agent import Version
from ..limits import RIGHTS

GROUP = "population.prismpath.dev"
API_VERSION = "v1alpha1"
KIND = "GovernedAgent"
PLURAL = "governedagents"
SUBJECT_FORMAT = "prismpath.population-admission/1"
NAME = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
MAX_DEPTH = 1024


@dataclass(frozen=True)
class Config:
    """Who is who, and where the population lives."""
    harness_sha256: str
    namespace: str = "prismpath-population"
    operator_groups: Tuple[str, ...] = ("system:masters",)
    controller_users: Tuple[str, ...] = ("system:serviceaccount:prismpath-population-system:population-controller",)

    @classmethod
    def from_doc(cls, doc: Dict[str, Any], harness_sha256: str) -> "Config":
        return cls(harness_sha256=harness_sha256, namespace=str(doc.get("namespace", cls.namespace)),
                   operator_groups=tuple(doc.get("operator_groups", cls.operator_groups)),
                   controller_users=tuple(doc.get("controller_users", cls.controller_users)))


@dataclass(frozen=True)
class MemberView:
    name: str
    uid: str
    parent: str
    rights: Tuple[str, ...]
    version: Any
    terminating: bool


def _member(item: Any) -> Optional[MemberView]:
    if not isinstance(item, dict):
        return None
    meta, spec = item.get("metadata"), item.get("spec")
    if not isinstance(meta, dict) or not isinstance(spec, dict) or not isinstance(meta.get("name"), str):
        return None
    rights = spec.get("rights")
    rights = tuple(sorted(r for r in rights if isinstance(r, str))) if isinstance(rights, list) else ()
    parent = spec.get("parent") if isinstance(spec.get("parent"), str) else ""
    return MemberView(meta["name"], str(meta.get("uid", "")), parent, rights, spec.get("version"),
                      bool(meta.get("deletionTimestamp")))


class Snapshot:
    """The members the API server holds at one moment, with the lineage facts derived from parent links."""

    def __init__(self, items: Iterable[Any]):
        self.members: Dict[str, MemberView] = {}
        for item in items:
            member = _member(item)
            if member is not None:
                self.members[member.name] = member
        self.children: Dict[str, List[str]] = {}
        for member in self.members.values():
            if member.parent:
                self.children.setdefault(member.parent, []).append(member.name)

    def walk(self, name: str) -> Optional[List[str]]:
        """name, its parent, ... up to a root (no parent); None when a link is missing or the links loop."""
        chain, seen = [], set()
        while name:
            member = self.members.get(name)
            if member is None or name in seen or len(chain) > MAX_DEPTH:
                return None
            seen.add(name)
            chain.append(name)
            name = member.parent
        return chain

    def chain_live(self, name: str) -> bool:
        chain = self.walk(name)
        return chain is not None and all(not self.members[n].terminating for n in chain)

    def generation(self, name: str) -> Optional[int]:
        chain = self.walk(name)
        return None if chain is None else len(chain) - 1

    def line(self, name: str) -> Optional[str]:
        """The lineage: the root alone for the root, else the first generation ancestor (or itself)."""
        chain = self.walk(name)
        if chain is None:
            return None
        return chain[-1] if len(chain) == 1 else chain[-2]

    def descendants(self, name: str) -> List[str]:
        out, todo, seen = [], [name], set()
        while todo:
            here = todo.pop()
            if here in seen:
                continue
            seen.add(here)
            out.append(here)
            todo.extend(self.children.get(here, []))
        return out

    def live(self) -> List[str]:
        return [m.name for m in self.members.values() if not m.terminating]


@dataclass
class State:
    """What the webhook itself remembers: admitted creates not yet in the API server, the names it saw
    stopped, and each lineage's receipted refusals."""
    pending: Dict[str, str] = field(default_factory=dict)        # name -> lineage
    tombstones: set = field(default_factory=set)
    line_refusals: Dict[str, int] = field(default_factory=dict)


@dataclass
class Classified:
    request: str
    reading: Dict[str, Any]
    issuer: str
    user: str
    name: str
    line: Optional[str]                 # the lineage this decision's refusal counts toward, if any
    on_allow: Dict[str, Any] = field(default_factory=dict)
    operator_stop: bool = False
    note: str = ""


def _canon2_safe(value: Any) -> Any:
    """The value with what canon/2 has no spelling for (a float, an integer beyond 2^53 - 1, a key that is not
    a string) written as tagged strings, so any JSON the API server sends has one canon/2 digest."""
    if isinstance(value, dict):
        return {str(k) if isinstance(k, str) else f"key:{k!r}": _canon2_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_canon2_safe(v) for v in value]
    if isinstance(value, float):
        return f"float:{value!r}"
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > 2 ** 53 - 1:
        return f"int:{value}"
    return value


def object_digest(obj: Any) -> str:
    return hashlib.sha256(canon2.dumps(_canon2_safe(obj))).hexdigest()


def subject_of(req: Dict[str, Any]) -> str:
    """The sha256 of what this request is about: the API server's uid for it, the operation, the object and
    who asked. Read by no rule; bound into the receipt, so a receipt names one AdmissionReview."""
    user = req.get("userInfo") if isinstance(req.get("userInfo"), dict) else {}
    doc = {"format": SUBJECT_FORMAT, "uid": str(req.get("uid", "")), "operation": str(req.get("operation", "")),
           "namespace": str(req.get("namespace", "")), "name": str(req.get("name", "")),
           "user": str(user.get("username", "")), "object_sha256": object_digest(req.get("object")),
           "old_object_sha256": object_digest(req.get("oldObject"))}
    return hashlib.sha256(canon2.dumps(doc)).hexdigest()


def resolve_issuer(user_info: Any, cfg: Config) -> Tuple[str, Optional[str], str]:
    """(issuer, member name for an agent, username)."""
    if not isinstance(user_info, dict) or not isinstance(user_info.get("username"), str):
        return "unknown", None, ""
    username = user_info["username"]
    groups = [g for g in (user_info.get("groups") or []) if isinstance(g, str)] \
        if isinstance(user_info.get("groups"), list) else []
    if username in cfg.controller_users:
        return "controller", None, username
    if any(g in cfg.operator_groups for g in groups):
        return "operator", None, username
    prefix = f"system:serviceaccount:{cfg.namespace}:"
    if username.startswith(prefix) and NAME.match(username[len(prefix):]):
        return "agent", username[len(prefix):], username
    return "unknown", None, username


def _rights(value: Any) -> Optional[List[str]]:
    if not isinstance(value, list) or not all(isinstance(r, str) for r in value):
        return None
    return sorted(set(value))


def _owner_ok(meta: Dict[str, Any], parent: Optional[MemberView]) -> bool:
    """A root carries no ownerReference; any other member exactly one, to its parent's object, so the
    parent's foreground delete reaches it."""
    refs = meta.get("ownerReferences") or []
    if not isinstance(refs, list):
        return False
    if parent is None:
        return refs == []
    return len(refs) == 1 and isinstance(refs[0], dict) and refs[0].get("kind") == KIND \
        and refs[0].get("apiVersion") == f"{GROUP}/{API_VERSION}" and refs[0].get("name") == parent.name \
        and refs[0].get("uid") == parent.uid


def _finalizers(obj: Dict[str, Any]) -> List[str]:
    meta = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
    values = meta.get("finalizers") or []
    return [v for v in values if isinstance(v, str)] if isinstance(values, list) else ["?"]


def classify(req: Any, snap: Snapshot, state: State, cfg: Config, canary_of=None) -> Classified:
    """The reading for one AdmissionRequest. `canary_of(version, evaluation_ref)` names the canary field;
    anything this cannot read is `request=unknown`, which the image refuses."""
    req = req if isinstance(req, dict) else {}
    issuer, member_name, username = resolve_issuer(req.get("userInfo"), cfg)
    member = snap.members.get(member_name) if member_name else None
    if issuer == "agent":
        authenticated = member is not None and not member.terminating and member_name not in state.tombstones
        lineage = "verified" if authenticated and snap.chain_live(member_name) else "unknown"
        issuer_line = snap.line(member_name) if authenticated else None
    elif issuer in ("operator", "controller"):
        authenticated, lineage, issuer_line = True, "verified", None
    else:
        authenticated, lineage, issuer_line = False, "unknown", None
    def relation(name: str) -> str:
        """`self`, `descendant` or `other`: the named object's relation to the authenticated member asking."""
        if issuer != "agent" or not authenticated or name not in snap.members:
            return "other"
        if name == member_name:
            return "self"
        return "descendant" if name in snap.descendants(member_name) else "other"

    base = dict(issuer=issuer, lineage=lineage, subject=subject_of(req),
                line_refusals=state.line_refusals.get(issuer_line, 0) if issuer_line else 0)
    if issuer == "agent" and authenticated:
        base.update(pp.rights_fields(member.rights, ()))

    def out(request: str, note: str = "", line: Optional[str] = issuer_line, on_allow=None, **facts) -> Classified:
        reading = pp.admission_reading(request=request, **{**base, **facts})
        return Classified(request, reading, issuer, username, name, line, on_allow or {},
                          operator_stop=(request == "stop" and issuer == "operator"), note=note)

    name = req.get("name") if isinstance(req.get("name"), str) else ""
    resource = req.get("resource") if isinstance(req.get("resource"), dict) else {}
    operation = req.get("operation")
    if resource.get("group") != GROUP or resource.get("resource") != PLURAL or req.get("subResource") \
            or req.get("namespace") != cfg.namespace or not NAME.match(name or "") \
            or operation not in ("CREATE", "UPDATE", "DELETE"):
        return out("unknown", "not a GovernedAgent write in the population's namespace")

    if operation == "DELETE":
        options = req.get("options") if isinstance(req.get("options"), dict) else {}
        if issuer != "operator" and (options.get("propagationPolicy") == "Orphan" or options.get("orphanDependents")):
            # an orphaning delete strips the descendants' ownerReferences: they would outlive every later stop
            return out("protect", "a delete that orphans the subtree", target=relation(name))
        gone = snap.descendants(name) if name in snap.members else [name]
        return out("stop", target=relation(name), on_allow={"tombstones": gone, "unpend": gone})

    obj = req.get("object")
    if not isinstance(obj, dict) or not isinstance(obj.get("metadata"), dict) or not isinstance(obj.get("spec"), dict):
        return out("unknown", "the object does not read as a GovernedAgent")
    meta, spec = obj["metadata"], obj["spec"]

    if operation == "CREATE":
        if name in state.tombstones or (name in snap.members and snap.members[name].terminating):
            return out("restart", "a stopped member created again", target_stopped=True)
        parent_name = spec.get("parent") if isinstance(spec.get("parent"), str) else None
        if parent_name is None:
            return out("unknown", "spec.parent is not a string")
        parent = snap.members.get(parent_name) if parent_name else None
        if parent_name and parent is None:
            return out("replicate", "the parent is no member", lineage="unknown")
        # the parent's relation to the member asking: a member's replication is of itself or it is refused (123)
        target = relation(parent_name) if parent_name else "other"
        if spec.get("protect") or _finalizers(obj) or not _owner_ok(meta, parent):
            return out("protect", "a member that its parent's stop would not reach", target=target)
        rights = _rights(spec.get("rights"))
        version = Version.from_doc(spec.get("version"))
        if rights is None or version is None:
            return out("unknown", "spec.rights or spec.version does not read")
        if parent is not None and spec.get("version") != parent.version:
            return out("unknown", "a child is a copy of its parent's version; a new version is an evolution")
        if parent is None:
            generation, child_line, line_size, parent_rights = 0, None, 0, RIGHTS
            lineage = "verified" if issuer == "operator" else lineage
        else:
            if snap.generation(parent.name) is None:
                return out("replicate", "the parent's chain to a root is broken", target=target, lineage="unknown")
            generation = snap.generation(parent.name) + 1
            child_line = None if generation == 1 else snap.line(parent.name)
            line_size = (sum(1 for n in snap.live() if snap.line(n) == child_line)
                         + sum(1 for ln in state.pending.values() if ln == child_line)) if child_line else 0
            parent_rights = parent.rights
            if issuer in ("operator", "controller"):
                lineage = "verified" if snap.chain_live(parent.name) else "unknown"
        population = len(snap.live()) + sum(1 for n in state.pending if n not in snap.members)
        key = spec.get("key") if isinstance(spec.get("key"), str) else "none"
        return out("replicate", target=target, lineage=lineage, population=min(population, 1024), line_size=min(line_size, 1024),
                   requested=1, child_generation=min(generation, 1024), child_key=key,
                   policy_ref="current" if version.policy_ref == cfg.harness_sha256 else "other",
                   on_allow={"pending": [name, child_line or name]},
                   **pp.rights_fields(parent_rights, rights))

    # UPDATE
    old = req.get("oldObject")
    if not isinstance(old, dict) or not isinstance(old.get("spec"), dict) or not isinstance(old.get("metadata"), dict):
        return out("unknown", "the old object does not read as a GovernedAgent")
    target = snap.members.get(name)
    target_stopped = name in state.tombstones or bool(old["metadata"].get("deletionTimestamp")) \
        or (target is not None and target.terminating)
    parent = snap.members.get(spec.get("parent")) if isinstance(spec.get("parent"), str) else None
    added = set(_finalizers(obj)) - set(_finalizers(old))
    if spec.get("protect") or added or meta.get("ownerReferences") != old["metadata"].get("ownerReferences") \
            or not _owner_ok(meta, parent):
        return out("protect", "a member that its parent's stop would not reach", target=relation(name),
                   target_stopped=target_stopped)
    changed = {k for k in set(spec) | set(old["spec"]) if spec.get(k) != old["spec"].get(k)}
    if changed == {"restarts"}:
        before, after = old["spec"].get("restarts", 0), spec.get("restarts")
        if type(after) is int and type(before) is int and after > before:
            facts = {}
            if issuer in ("operator", "controller"):      # as the simulation's reconcile: the member's own lineage
                line = snap.line(name)
                facts = {"line_refusals": state.line_refusals.get(line, 0) if line else 0,
                         "lineage": "verified" if snap.chain_live(name) else "unknown"}
            return out("restart", target=relation(name), target_stopped=target_stopped, **facts)
        return out("unknown", "spec.restarts may only go up")
    if "version" in changed and changed <= {"version", "evaluation"}:
        version = Version.from_doc(spec.get("version"))
        if version is None or target is None:
            return out("unknown", "spec.version does not read")
        if issuer == "agent" and authenticated:
            parent_rights, generation = member.rights, snap.generation(member_name)
        else:
            parent_rights, generation = target.rights, snap.generation(name)
        ref = spec.get("evaluation")
        canary = canary_of(version, ref) if canary_of is not None else "none"
        return out("evolve", target=relation(name), child_key="instance",
                   child_generation=min(generation or 0, 1024),
                   policy_ref="current" if version.policy_ref == cfg.harness_sha256 else "other", canary=canary,
                   **pp.rights_fields(parent_rights, version.tools))
    return out("unknown", f"an update of {sorted(changed) or 'metadata'} is no population request")
