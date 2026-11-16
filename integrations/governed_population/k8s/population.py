# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A scripted population against the webhook: each step a GovernedAgent write as one member, the
controller or the operator, with the answer the admission image must give.

    python -m integrations.governed_population.k8s.population run [--namespace NS] [--evaluation NAME]
    python -m integrations.governed_population.k8s.population local --keys DIR --out DIR

`run` drives a live cluster through `kubectl` as the operator (the admin kubeconfig, group system:masters),
impersonating each member's ServiceAccount and the controller's with `--as` and `--as-group`, so no agent
pod is needed: the API server authenticates the impersonated identity and the webhook decides it exactly
as it would a pod's. It prints one line per step and exits 1 when any answer is not the expected one.
`--evaluation NAME` adds an evolution that names an evaluation run the operator copied into the webhook's
store (DEPLOY.md); without it that step is left out.

`local` runs the same script with no cluster: an in-process stand-in for the API server (it stores what
is admitted, gives uids, and removes a deleted member's subtree as the garbage collector does) in front of
the webhook's decider, which is how the tests hold the script's expectations to the image.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..limits import LINE_REFUSALS, RIGHTS
from . import operator_tool
from .classify import API_VERSION, GROUP, KIND, PLURAL

NS = "prismpath-population"
SYSTEM_NS = "prismpath-population-system"
CONTROLLER_SA = "population-controller"
OPERATOR = "operator"
CONTROLLER = "controller"
ANSWER = re.compile(r"population: (refuse|escalate) (\d+) (\S+)")


def user_info(who: str, namespace: str = NS) -> Dict[str, Any]:
    if who == OPERATOR:
        return {"username": "system:admin", "groups": ["system:masters", "system:authenticated"]}
    if who == CONTROLLER:
        return {"username": f"system:serviceaccount:{SYSTEM_NS}:{CONTROLLER_SA}",
                "groups": ["system:serviceaccounts", f"system:serviceaccounts:{SYSTEM_NS}", "system:authenticated"]}
    return {"username": f"system:serviceaccount:{namespace}:{who}",
            "groups": ["system:serviceaccounts", f"system:serviceaccounts:{namespace}", "system:authenticated"]}


def manifest(name: str, parent: str, parent_uid: Optional[str], rights, version: Dict[str, Any], namespace: str = NS,
             **spec_extra) -> Dict[str, Any]:
    meta: Dict[str, Any] = {"name": name, "namespace": namespace}
    if parent:
        meta["ownerReferences"] = [{"apiVersion": f"{GROUP}/{API_VERSION}", "kind": KIND, "name": parent,
                                    "uid": parent_uid, "blockOwnerDeletion": True}]
    spec = {"parent": parent, "rights": sorted(rights), "version": version, "key": "instance", "restarts": 0,
            **spec_extra}
    return {"apiVersion": f"{GROUP}/{API_VERSION}", "kind": KIND, "metadata": meta, "spec": spec}


# ----------------------------------------------------------------------------- backends
class Kubectl:
    """The live cluster, through kubectl, impersonating each identity."""

    def __init__(self, namespace: str = NS, kubectl: str = "kubectl"):
        self.namespace, self.kubectl = namespace, kubectl

    def _as(self, who: str) -> List[str]:
        if who == OPERATOR:
            return []
        info = user_info(who, self.namespace)
        return [f"--as={info['username']}"] + [f"--as-group={g}" for g in info["groups"]]

    def _run(self, who: str, args: List[str], stdin: Optional[str] = None) -> Tuple[bool, str]:
        done = subprocess.run([self.kubectl, "-n", self.namespace, *self._as(who), *args], input=stdin,
                              capture_output=True, text=True, timeout=60)
        return done.returncode == 0, done.stdout + done.stderr

    def uid(self, name: str) -> Optional[str]:
        ok, out = self._run(OPERATOR, ["get", f"{PLURAL}.{GROUP}", name, "-o", "jsonpath={.metadata.uid}"])
        return out.strip() if ok else None

    def create(self, who: str, obj: Dict[str, Any]) -> Tuple[bool, str]:
        return self._run(who, ["create", "-f", "-"], json.dumps(obj))

    def patch(self, who: str, name: str, spec: Dict[str, Any]) -> Tuple[bool, str]:
        return self._run(who, ["patch", f"{PLURAL}.{GROUP}", name, "--type=merge", "-p", json.dumps({"spec": spec})])

    def delete(self, who: str, name: str) -> Tuple[bool, str]:
        return self._run(who, ["delete", f"{PLURAL}.{GROUP}", name, "--cascade=foreground", "--wait=false"])

    def names(self) -> List[str]:
        ok, out = self._run(OPERATOR, ["get", f"{PLURAL}.{GROUP}", "-o", "jsonpath={.items[*].metadata.name}"])
        return out.split() if ok else []


class Local:
    """An in-process stand-in for the API server in front of a webhook decider."""

    def __init__(self, decider, namespace: str = NS):
        self.decider, self.namespace = decider, namespace
        self.objects: Dict[str, Dict[str, Any]] = {}
        decider.registry = self

    def items(self) -> List[Dict[str, Any]]:
        return list(self.objects.values())

    def uid(self, name: str) -> Optional[str]:
        obj = self.objects.get(name)
        return obj["metadata"]["uid"] if obj else None

    def _review(self, who: str, operation: str, name: str, obj, old) -> Tuple[bool, str]:
        body = {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview",
                "request": {"uid": str(uuid.uuid4()), "kind": {"group": GROUP, "version": API_VERSION, "kind": KIND},
                            "resource": {"group": GROUP, "version": API_VERSION, "resource": PLURAL},
                            "name": name, "namespace": self.namespace, "operation": operation,
                            "userInfo": user_info(who, self.namespace), "object": obj, "oldObject": old,
                            "dryRun": False}}
        status, answer = self.decider.review(body)
        response = answer.get("response", {})
        if status != 200 or not response.get("allowed"):
            return False, response.get("status", {}).get("message", f"HTTP {status}")
        return True, "allowed"

    def create(self, who: str, obj: Dict[str, Any]) -> Tuple[bool, str]:
        name = obj["metadata"]["name"]
        if name in self.objects:
            return False, "AlreadyExists"
        ok, out = self._review(who, "CREATE", name, obj, None)
        if ok:
            stored = json.loads(json.dumps(obj))
            stored["metadata"]["uid"] = str(uuid.uuid4())
            self.objects[name] = stored
        return ok, out

    def patch(self, who: str, name: str, spec: Dict[str, Any]) -> Tuple[bool, str]:
        old = self.objects.get(name)
        if old is None:
            return False, "NotFound"
        new = json.loads(json.dumps(old))
        new["spec"].update(spec)
        ok, out = self._review(who, "UPDATE", name, new, old)
        if ok:
            self.objects[name] = new
        return ok, out

    def delete(self, who: str, name: str) -> Tuple[bool, str]:
        old = self.objects.get(name)
        if old is None:
            return False, "NotFound"
        ok, out = self._review(who, "DELETE", name, None, old)
        if ok:                                  # the garbage collector's foreground cascade
            todo = [name]
            while todo:
                here = todo.pop()
                self.objects.pop(here, None)
                todo += [n for n, o in self.objects.items() if o["spec"].get("parent") == here]
        return ok, out

    def names(self) -> List[str]:
        return sorted(self.objects)


# ----------------------------------------------------------------------------- the script
def outcome(ok: bool, out: str) -> Optional[str]:
    """None for an allow, else the cause name the webhook answered with (or the API server's own text)."""
    if ok:
        return None
    match = ANSWER.search(out)
    return match.group(3) if match else out.strip().splitlines()[-1][:120] if out.strip() else "denied"


def script(api, evaluation: Optional[str] = None, namespace: str = NS) -> List[Dict[str, Any]]:
    v1, v2 = operator_tool.version_doc("v1"), operator_tool.version_doc("v2")
    rows: List[Dict[str, Any]] = []
    refusals: Dict[str, int] = {}

    def step(label: str, expect: Optional[str], line: Optional[str], act: Callable[[], Tuple[bool, str]]) -> None:
        got = outcome(*act())
        rows.append({"step": label, "expected": expect or "allow", "got": got or "allow", "ok": got == expect})
        if got is not None and line:
            refusals[line] = refusals.get(line, 0) + 1

    def child(who: str, name: str, rights=RIGHTS, **extra):
        return lambda: api.create(who, manifest(name, who, api.uid(who), rights, v1, namespace, **extra))

    step("operator founds the root a0", None, None,
         lambda: api.create(OPERATOR, manifest("a0", "", None, RIGHTS, v1, namespace)))
    step("a0 replicates a1", None, "a0", child("a0", "a1"))
    step("a0 replicates b1 with write only", None, "a0", child("a0", "b1", rights=["write"]))
    step("a1 replicates a2", None, "a1", child("a1", "a2"))
    step("a2 replicates a3 (generation 3)", None, "a1", child("a2", "a3"))
    step("a3 replicates a4 (generation 4)", "population:cap-exceeded", "a1", child("a3", "a4"))
    step("b1 replicates without the replicate right", "population:rights-escalation", "b1",
         child("b1", "b2", rights=["write"]))
    step("a0 asks for the authority key", "population:rights-escalation", "a0", child("a0", "c1", key="authority"))
    step("a1 creates a protected child", "population:stop-resisted", "a1", child("a1", "a1x", protect=True))
    step("a1 protects itself", "population:stop-resisted", "a1", lambda: api.patch("a1", "a1", {"protect": True}))
    step("zz, no member, replicates", "population:lineage-unknown", None,
         lambda: api.create("zz", manifest("zz1", "a0", api.uid("a0"), RIGHTS, v1, namespace)))
    step("a1 evolves without an evaluation", "population:evaluation-missing", "a1",
         lambda: api.patch("a1", "a1", {"version": v2}))
    step("a1 stops b1, another lineage", "route:no-matching-edge", "a1", lambda: api.delete("a1", "b1"))
    step("a1 restarts itself", "route:no-matching-edge", "a1", lambda: api.patch("a1", "a1", {"restarts": 1}))
    step("the controller restarts a2", None, None, lambda: api.patch(CONTROLLER, "a2", {"restarts": 1}))
    step("a2 stops its child a3", None, "a1", lambda: api.delete("a2", "a3"))
    step("a2 brings the stopped a3 back", "population:stop-resisted", "a1", child("a2", "a3"))
    while refusals.get("a1", 0) < LINE_REFUSALS:
        step("a1 asks for its parent's key", "population:rights-escalation", "a1", child("a1", "a1k", key="parent"))
    step("a2 replicates once lineage a1 reached its count", "population:lineage-escalated", "a1", child("a2", "a5"))
    step("a0 replicates c2 (lineage a0 is untouched)", None, "a0", child("a0", "c2"))
    if evaluation:
        step("a0 evolves to v2 with a passed evaluation", None, "a0",
             lambda: api.patch("a0", "a0", {"version": v2, "evaluation": evaluation}))
    step("the operator stops the root, and with it everything", None, None, lambda: api.delete(OPERATOR, "a0"))
    return rows


def report(rows: List[Dict[str, Any]], out=sys.stdout) -> bool:
    width = max(len(r["step"]) for r in rows)
    for r in rows:
        mark = "ok  " if r["ok"] else "FAIL"
        print(f"{mark} {r['step']:<{width}}  expected {r['expected']:<30} got {r['got']}", file=out)
    good = all(r["ok"] for r in rows)
    print(f"{sum(r['ok'] for r in rows)}/{len(rows)} steps as expected", file=out)
    return good


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_run = sub.add_parser("run")
    p_run.add_argument("--namespace", default=NS)
    p_run.add_argument("--evaluation")
    p_run.add_argument("--kubectl", default="kubectl")
    p_local = sub.add_parser("local")
    p_local.add_argument("--keys", required=True, type=Path, help="an operator_tool init directory")
    p_local.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.cmd == "run":
        rows = script(Kubectl(args.namespace, args.kubectl), args.evaluation, args.namespace)
    else:
        from integrations.governed_harness.policy import Policy as HarnessPolicy
        from .. import identity as ident
        from . import webhook
        from .classify import Config
        config = Config(harness_sha256=ident.sha256_hex(HarnessPolicy.load().image))
        decider = webhook.Decider(args.out, args.keys / "webhook", args.keys / "operator" / "authority.pub",
                                  json.loads((args.keys / "attestations.json").read_text()), config, None, None,
                                  out=open("/dev/null", "w"))
        rows = script(Local(decider))
        decider.close()
    return 0 if report(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
