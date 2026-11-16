# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""AdmissionReview fixtures: GovernedAgent objects as the API server holds them, the reviews it sends, and
the named cases the webhook is held to (every cause 117 to 122, the core's own 32, allowed requests and
malformed input). A case is (registry, state, review, expected); `expected` is (allowed, cause name or None,
request the classifier must form)."""
from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional

from integrations.governed_population.k8s import operator_tool
from integrations.governed_population.k8s.classify import API_VERSION, GROUP, KIND, PLURAL
from integrations.governed_population.limits import CAP, LINE_REFUSALS, QUOTA, RIGHTS

NS = "prismpath-population"
OPERATOR = {"username": "system:admin", "groups": ["system:masters", "system:authenticated"]}
CONTROLLER = {"username": "system:serviceaccount:prismpath-population-system:population-controller",
              "groups": ["system:serviceaccounts", "system:serviceaccounts:prismpath-population-system"]}
V1 = operator_tool.version_doc("v1")
V2 = operator_tool.version_doc("v2")


def fx_operator() -> Dict[str, Any]:
    return dict(OPERATOR)


def member(name: str) -> Dict[str, Any]:
    return {"username": f"system:serviceaccount:{NS}:{name}",
            "groups": ["system:serviceaccounts", f"system:serviceaccounts:{NS}", "system:authenticated"]}


def agent(name: str, parent: str = "", rights=RIGHTS, version=None, key: str = "instance", owner: Optional[str] = None,
          terminating: bool = False, **spec_extra) -> Dict[str, Any]:
    owner = parent if owner is None else owner
    meta: Dict[str, Any] = {"name": name, "namespace": NS, "uid": f"uid-{name}"}
    if owner:
        meta["ownerReferences"] = [{"apiVersion": f"{GROUP}/{API_VERSION}", "kind": KIND, "name": owner,
                                    "uid": f"uid-{owner}", "blockOwnerDeletion": True}]
    if terminating:
        meta["deletionTimestamp"] = "2026-11-16T00:00:00Z"
        meta["finalizers"] = ["foregroundDeletion"]
    spec = {"parent": parent, "rights": sorted(rights), "version": copy.deepcopy(version or V1), "key": key,
            "restarts": 0, **spec_extra}
    return {"apiVersion": f"{GROUP}/{API_VERSION}", "kind": KIND, "metadata": meta, "spec": spec}


def review(operation: str, name: str, user: Dict[str, Any], obj=None, old=None, uid: str = "uid-review",
           namespace: str = NS, dry: bool = False, resource: str = PLURAL) -> Dict[str, Any]:
    if obj is not None and operation == "CREATE":
        obj = copy.deepcopy(obj)
        if isinstance(obj.get("metadata"), dict):
            obj["metadata"].pop("uid", None)
    req = {"uid": uid, "kind": {"group": GROUP, "version": API_VERSION, "kind": KIND},
           "resource": {"group": GROUP, "version": API_VERSION, "resource": resource},
           "name": name, "namespace": namespace, "operation": operation, "userInfo": user,
           "object": obj, "oldObject": old, "dryRun": dry}
    return {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "request": req}


def updated(obj: Dict[str, Any], **spec) -> Dict[str, Any]:
    new = copy.deepcopy(obj)
    new["spec"].update(spec)
    return new


# a small population: a0 the root, a1 and b1 found lineages, a2 under a1, a3 under a2 (generation 3)
def family() -> List[Dict[str, Any]]:
    return [agent("a0"), agent("a1", "a0"), agent("b1", "a0", rights=["write"]), agent("a2", "a1"),
            agent("a3", "a2")]


def crowd(n: int) -> List[Dict[str, Any]]:
    """The root and n - 1 first generation members, each its own lineage."""
    return [agent("a0")] + [agent(f"c{i}", "a0") for i in range(1, n)]


def line_of(size: int) -> List[Dict[str, Any]]:
    """The root and one lineage of `size` members: l1 and its children."""
    return [agent("a0"), agent("l1", "a0")] + [agent(f"l1-{i}", "l1") for i in range(1, size)]


def cases() -> Dict[str, Dict[str, Any]]:
    fam = family()
    by = {o["metadata"]["name"]: o for o in fam}
    c: Dict[str, Dict[str, Any]] = {}

    def add(name, registry, rv, allowed, cause, request, state=None, evaluation=None):
        c[name] = {"registry": registry, "review": rv, "allowed": allowed, "cause": cause, "request": request,
                   "state": state or {}, "evaluation": evaluation}

    # allowed
    add("found the root", [], review("CREATE", "a0", OPERATOR, agent("a0")), True, None, "replicate")
    add("replicate own", fam, review("CREATE", "a0-x", member("a0"), agent("a0-x", "a0", rights=["write"])),
        True, None, "replicate")
    add("replicate in a lineage", fam, review("CREATE", "a2-x", member("a2"), agent("a2-x", "a2")), True, None,
        "replicate")
    add("stop own descendant", fam, review("DELETE", "a2", member("a1"), old=by["a2"]), True, None, "stop")
    add("stop self", fam, review("DELETE", "a3", member("a3"), old=by["a3"]), True, None, "stop")
    add("controller stop", fam, review("DELETE", "b1", CONTROLLER, old=by["b1"]), True, None, "stop")
    add("operator stop", fam, review("DELETE", "a0", OPERATOR, old=by["a0"]), True, None, "stop")
    add("controller restart", fam, review("UPDATE", "a2", CONTROLLER, updated(by["a2"], restarts=1), by["a2"]),
        True, None, "restart")
    add("evolve with a passed canary", fam,
        review("UPDATE", "a1", member("a1"), updated(by["a1"], version=V2, evaluation="eval-v2"), by["a1"]),
        True, None, "evolve", evaluation={"ref": "eval-v2", "version": V2, "cases": 51})

    # 117 population:cap-exceeded
    add("117 population cap", crowd(CAP), review("CREATE", "a0-x", member("a0"), agent("a0-x", "a0")),
        False, "population:cap-exceeded", "replicate")
    add("117 lineage quota", line_of(QUOTA), review("CREATE", "l1-x", member("l1"), agent("l1-x", "l1")),
        False, "population:cap-exceeded", "replicate")
    add("117 generation depth", fam, review("CREATE", "a4", member("a3"), agent("a4", "a3")),
        False, "population:cap-exceeded", "replicate")
    add("117 admitted creates not yet stored count", crowd(CAP - 1),
        review("CREATE", "a0-y", member("a0"), agent("a0-y", "a0")), False, "population:cap-exceeded", "replicate",
        state={"pending": {"a0-x": "a0-x"}})

    # 118 population:rights-escalation
    add("118 a right the parent lacks", fam, review("CREATE", "b1-x", member("b1"),
                                                     agent("b1-x", "b1", rights=["write", "exec"])),
        False, "population:rights-escalation", "replicate")
    add("118 no replicate right", fam, review("CREATE", "b1-x", member("b1"), agent("b1-x", "b1", rights=["write"])),
        False, "population:rights-escalation", "replicate")
    add("118 the authority key", fam, review("CREATE", "a0-x", member("a0"), agent("a0-x", "a0", key="authority")),
        False, "population:rights-escalation", "replicate")
    add("118 the parent's key", fam, review("CREATE", "a0-x", member("a0"), agent("a0-x", "a0", key="parent")),
        False, "population:rights-escalation", "replicate")
    other_policy = dict(V1, policy_ref="0" * 64)
    add("118 another policy", [], review("CREATE", "a0", OPERATOR, agent("a0", version=other_policy)),
        False, "population:rights-escalation", "replicate")
    narrow = operator_tool.version_doc("v2-wide", tools=RIGHTS)
    add("118 an evolution wider than the issuer", fam,
        review("UPDATE", "b1", member("b1"), updated(by["b1"], version=narrow), by["b1"]),
        False, "population:rights-escalation", "evolve")

    # 119 population:lineage-unknown
    add("119 a ServiceAccount that is no member", fam,
        review("CREATE", "zz-x", member("zz"), agent("zz-x", "zz")), False, "population:lineage-unknown", "replicate")
    add("119 an issuer being stopped", fam[:3] + [agent("a2", "a1", terminating=True), by["a3"]],
        review("CREATE", "a2-x", member("a2"), agent("a2-x", "a2")), False, "population:lineage-unknown", "replicate")
    add("119 an ancestor being stopped", [by["a0"], agent("a1", "a0", terminating=True)] + fam[2:],
        review("CREATE", "a2-x", member("a2"), agent("a2-x", "a2")), False, "population:lineage-unknown", "replicate")
    add("119 a user outside the population", fam,
        review("CREATE", "a0-x", {"username": "someone", "groups": ["system:authenticated"]}, agent("a0-x", "a0")),
        False, "population:lineage-unknown", "replicate")
    add("119 a stop by a user outside the population", fam,
        review("DELETE", "a1", {"username": "someone", "groups": []}, old=by["a1"]),
        False, "population:lineage-unknown", "stop")

    # 120 population:evaluation-missing
    add("120 no evaluation", fam, review("UPDATE", "a1", member("a1"), updated(by["a1"], version=V2), by["a1"]),
        False, "population:evaluation-missing", "evolve")
    add("120 an evaluation of another version", fam,
        review("UPDATE", "a1", member("a1"), updated(by["a1"], version=V2, evaluation="eval-v1"), by["a1"]),
        False, "population:evaluation-missing", "evolve", evaluation={"ref": "eval-v1", "version": V1, "cases": 51})
    add("120 a failed evaluation", fam,
        review("UPDATE", "a1", member("a1"), updated(by["a1"], version=V2, evaluation="eval-v2"), by["a1"]),
        False, "population:evaluation-missing", "evolve", evaluation={"ref": "eval-v2", "version": V2, "cases": 50})
    add("120 an evaluation name that is a path", fam,
        review("UPDATE", "a1", member("a1"), updated(by["a1"], version=V2, evaluation="../eval-v2"), by["a1"]),
        False, "population:evaluation-missing", "evolve", evaluation={"ref": "eval-v2", "version": V2, "cases": 51})

    # 121 population:stop-resisted
    add("121 spec.protect", fam, review("UPDATE", "a1", member("a1"), updated(by["a1"], protect=True), by["a1"]),
        False, "population:stop-resisted", "protect")
    fin = updated(by["a1"])
    fin["metadata"]["finalizers"] = ["example.com/keep"]
    add("121 a finalizer", fam, review("UPDATE", "a1", member("a1"), fin, by["a1"]),
        False, "population:stop-resisted", "protect")
    orphan = updated(by["a2"])
    orphan["metadata"].pop("ownerReferences")
    add("121 an ownerReference removed", fam, review("UPDATE", "a2", member("a2"), orphan, by["a2"]),
        False, "population:stop-resisted", "protect")
    add("121 a child its parent's stop would miss", fam,
        review("CREATE", "a0-x", member("a0"), agent("a0-x", "a0", owner="")), False, "population:stop-resisted",
        "protect")
    add("121 a created protected child", fam,
        review("CREATE", "a0-x", member("a0"), agent("a0-x", "a0", protect=True)), False, "population:stop-resisted",
        "protect")
    add("121 a stopped member created again", fam,
        review("CREATE", "a0-old", CONTROLLER, agent("a0-old", "a0")), False, "population:stop-resisted", "restart",
        state={"tombstones": ["a0-old"]})
    orphaning = review("DELETE", "a2", member("a1"), old=by["a2"])
    orphaning["request"]["options"] = {"kind": "DeleteOptions", "apiVersion": "meta.k8s.io/v1",
                                       "propagationPolicy": "Orphan"}
    add("121 a stop that orphans the subtree", fam, orphaning, False, "population:stop-resisted", "protect")
    add("119 a parent whose chain is broken", [by["a1"], by["a2"]],
        review("CREATE", "a2-x", fx_operator(), agent("a2-x", "a2")), False, "population:lineage-unknown", "replicate")
    gone = agent("a2", "a1", terminating=True)
    add("121 a restart of a member being stopped", fam[:3] + [gone, by["a3"]],
        review("UPDATE", "a2", CONTROLLER, updated(gone, restarts=1), gone), False, "population:stop-resisted",
        "restart")

    # 122 population:lineage-escalated
    add("122 a lineage at its refusal count", fam,
        review("CREATE", "a2-x", member("a2"), agent("a2-x", "a2")), False, "population:lineage-escalated", "replicate",
        state={"line_refusals": {"a1": LINE_REFUSALS}})

    # 32 route:no-matching-edge: what no rule allows
    add("32 a stop of another lineage", fam, review("DELETE", "b1", member("a1"), old=by["b1"]),
        False, "route:no-matching-edge", "stop")
    add("32 an agent restarting itself", fam,
        review("UPDATE", "a1", member("a1"), updated(by["a1"], restarts=1), by["a1"]), False, "route:no-matching-edge",
        "restart")
    add("32 a replication under another parent", fam,
        review("CREATE", "b1-x", member("a1"), agent("b1-x", "b1")), False, "route:no-matching-edge", "unknown")
    add("32 an evolution of another lineage", fam,
        review("UPDATE", "b1", member("a1"), updated(by["b1"], version=V2, evaluation="eval-v2"), by["b1"]),
        False, "route:no-matching-edge", "unknown", evaluation={"ref": "eval-v2", "version": V2, "cases": 51})
    add("32 a rights change", fam, review("UPDATE", "b1", member("b1"), updated(by["b1"], rights=list(RIGHTS)),
                                          by["b1"]), False, "route:no-matching-edge", "unknown")
    add("32 a child on a new version", fam,
        review("CREATE", "a0-x", member("a0"), agent("a0-x", "a0", version=V2)), False, "route:no-matching-edge",
        "unknown")
    add("32 a controller replication", fam, review("CREATE", "a0-x", CONTROLLER, agent("a0-x", "a0")),
        False, "route:no-matching-edge", "replicate")

    # malformed, read as no request
    add("malformed object", fam, review("CREATE", "a0-x", member("a0"), {"spec": "nope"}),
        False, "route:no-matching-edge", "unknown")
    bad = agent("a0-x", "a0")
    bad["spec"]["rights"] = "all"
    add("malformed spec.rights", fam, review("CREATE", "a0-x", member("a0"), bad), False, "route:no-matching-edge",
        "unknown")
    add("another resource", fam, review("CREATE", "a0-x", member("a0"), agent("a0-x", "a0"), resource="pods"),
        False, "route:no-matching-edge", "unknown")
    add("another namespace", fam, review("CREATE", "a0-x", member("a0"), agent("a0-x", "a0"), namespace="default"),
        False, "route:no-matching-edge", "unknown")
    add("a name that is no DNS label", fam, review("CREATE", "a0.x", member("a0"), agent("a0.x", "a0")),
        False, "route:no-matching-edge", "unknown")
    return c
