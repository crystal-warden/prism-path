# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Cerbos translator for the layer comparison.

Facts established on the pinned binary (0.55.0) before this was written, and confirmed by the
documentation: Cerbos has no ordered rule evaluation; when several rules match one action the
overall effect is EFFECT_DENY ("if some rules evaluated to EFFECT_ALLOW and some others evaluated
to EFFECT_DENY, the overall effect is EFFECT_DENY"); a CEL condition that reads a missing attribute
is an evaluation error, logged as a warning, and the rule does not match. Outputs fire for every
activated rule.

Idiom used. One resource policy per corpus policy, resource kind = policy id, one action `decide`.
Each corpus rule is one Cerbos rule on `decide`: effect EFFECT_ALLOW when the corpus outcome is
`allow` or `observe` (admit), EFFECT_DENY otherwise, and an `output` block whose `ruleActivated`
expression is a CEL map `{"outcome": ..., "rule": ...}`, which is how Cerbos returns information
beyond the effect. First match is emulated the only way Cerbos allows: every rule's condition is
its own condition AND the negation of every earlier rule's condition, so exactly one rule can
activate. Every attribute read is guarded with `has()` so absence is unsatisfied rather than an
evaluation error, matching the neutral semantics and the conditions documentation's own guidance.

Group B: the role hierarchy becomes derived roles with `parentRoles` (the documented Cerbos idiom
for hierarchies); the user's role is sent as the principal's role and the `user_*` fields as
principal attributes; field against field and set intersection are native CEL. The relationship
policy is not expressible: Cerbos has no relationship store, so the caller would have to flatten
the graph into attributes first, which is a Phase 5 combination test.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

from prismpath.comparisons.harness import TOOLCHAIN_BIN, Decision, Translation

SYSTEM = "cerbos"
HTTP_PORT, GRPC_PORT = 13592, 13593
CITATIONS = [
    "https://docs.cerbos.dev/cerbos/latest/policies/resource_policies (how Cerbos evaluates requests: ALLOW+DENY -> DENY; roles '*')",
    "https://docs.cerbos.dev/cerbos/latest/policies/conditions (CEL conditions; has() for optional attributes)",
    "https://docs.cerbos.dev/cerbos/latest/policies/outputs (output expressions per rule)",
    "https://docs.cerbos.dev/cerbos/latest/policies/derived_roles (parentRoles for role hierarchies)",
    "https://docs.cerbos.dev/cerbos/latest/api/index (CheckResources)",
]
PRINCIPAL_FIELDS = {"user_id", "user_groups", "user_role"}   # B1: attributes of the principal, not the resource
ROLE_FIELD = "user_role"


def _lit(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return json.dumps(value)


def _ref(field: str, policy: Dict[str, Any]) -> str:
    if policy.get("hierarchy") and field in PRINCIPAL_FIELDS:
        return f"request.principal.attr.{field}"
    return f"request.resource.attr.{field}"


class NotExpressible(Exception):
    """The policy, or one form inside it, is not expressible in this system.

    One spelling for this concept across `prismpath/comparisons`: the adjective is `expressible`,
    the outcome value is `not_expressible`, and this is the exception that reports it.
    """


def cel(cond: Any, policy: Dict[str, Any]) -> str:
    if cond is True:
        return "true"
    (form, arg), = cond.items()
    if form == "cmp":
        field, op, constant = arg
        reference = _ref(field, policy)
        return f"(has({reference}) && {reference} {op} {_lit(constant)})"
    if form == "in":
        reference = _ref(arg[0], policy)
        return f"(has({reference}) && {reference} in [{', '.join(_lit(value) for value in arg[1])}])"
    if form == "not_in":
        reference = _ref(arg[0], policy)
        return f"(has({reference}) && !({reference} in [{', '.join(_lit(value) for value in arg[1])}]))"
    if form == "missing":
        return f"!has({_ref(arg, policy)})"
    if form == "present":
        return f"has({_ref(arg, policy)})"
    if form == "all":
        return "(" + " && ".join(cel(condition, policy) for condition in arg) + ")"
    if form == "any":
        return "(" + " || ".join(cel(condition, policy) for condition in arg) + ")"
    if form == "not":
        return f"!{cel(arg, policy)}"
    if form == "eq_fields":
        left_reference, right_reference = _ref(arg[0], policy), _ref(arg[1], policy)
        return f"(has({left_reference}) && has({right_reference}) && {left_reference} == {right_reference})"
    if form == "intersects":
        left_reference, right_reference = _ref(arg[0], policy), _ref(arg[1], policy)
        return f"(has({left_reference}) && has({right_reference}) && {left_reference}.exists(g, g in {right_reference}))"
    if form == "role_at_least":
        # flattened in CEL over the principal's static roles: derived roles (the Cerbos idiom for a
        # hierarchy) gate a rule but cannot be referenced inside the condition, so they cannot join the
        # negation chain the first match emulation needs; the derived roles file is still emitted
        order = policy["hierarchy"]["order"]
        roles = ", ".join(json.dumps(role) for role in order[order.index(arg[1]):])
        return f"request.principal.roles.exists(r, r in [{roles}])"
    raise NotExpressible(form)


def translate(policy: Dict[str, Any]) -> Translation:
    tr = Translation(citations=list(CITATIONS))
    if any(rule["if"] is not True and "related" in rule["if"] for rule in policy["rules"]):
        tr.expressible = False
        tr.notes.append("not expressible: Cerbos has no relationship store; conditions see only the attributes "
                        "the caller sends, so the caller would have to flatten group membership and folder "
                        "inheritance into resource attributes first (a Phase 5 combination test, not a translation)")
        return tr
    hierarchy = policy.get("hierarchy")
    derived: List[str] = []
    if hierarchy:
        order = hierarchy["order"]
        for role_index, role in enumerate(order):
            parents = ", ".join(json.dumps(role) for role in order[role_index:])
            derived.append(f"    - name: at_least_{role}\n      parentRoles: [{parents}]")
        tr.idiomatic = False
        tr.notes.append("role hierarchy: derived roles with parentRoles are the documented Cerbos idiom and are emitted, "
                        "but a derived role can only gate a rule, it cannot be referenced inside a CEL condition, so it "
                        "cannot take part in the prior rule negation the first match emulation requires; the hierarchy "
                        "is therefore flattened in CEL over request.principal.roles (idiomatic=false recorded for that). "
                        "The user's role travels as the principal's role and also as a principal attribute so equality "
                        "rules read it; user_id and user_groups are principal attributes")
    rules_yaml, prior = [], []
    for rule in policy["rules"]:
        own = cel(rule["if"], policy)
        parts = [own] + [f"!{prior_condition}" for prior_condition in prior]
        expr = " && ".join(parts) if len(parts) > 1 else own
        if rule["if"] is not True:
            prior.append(own)
        effect = "EFFECT_ALLOW" if rule["then"] in ("allow", "observe") else "EFFECT_DENY"
        out = json.dumps({"outcome": rule["then"], "rule": rule["id"]})
        rules_yaml.append(
            f"    - name: {rule['id']}\n      actions: [\"decide\"]\n      effect: {effect}\n      roles: [\"*\"]\n"
            + (f"      derivedRoles: []\n" if False else "")
            + f"      condition:\n        match:\n          expr: {json.dumps(expr)}\n"
            + f"      output:\n        when:\n          ruleActivated: {json.dumps(out)}\n")
    tr.notes.append("first match emulated by conjoining the negation of every earlier rule's condition (Cerbos has no "
                    "ordered evaluation: ALLOW and DENY matching together resolve to DENY); every attribute read is "
                    "has() guarded so absence is unsatisfied, not a logged CEL evaluation error")
    tr.notes.append("outcomes beyond allow/deny ride the rule's output block as {outcome, rule}; the effect is "
                    "EFFECT_ALLOW for allow and observe, EFFECT_DENY otherwise")
    if not any(rule["if"] is True for rule in policy["rules"]):
        tr.notes.append("no catch all by design: no rule activates, the effect is the default EFFECT_DENY with no output")
    head = (f"apiVersion: api.cerbos.dev/v1\nresourcePolicy:\n  version: default\n  resource: {policy['id']}\n"
            + (f"  importDerivedRoles: [{policy['id']}_roles]\n" if hierarchy else "") + "  rules:\n")
    tr.files[f"{policy['id']}.yaml"] = head + "".join(rules_yaml)
    if hierarchy:
        tr.files[f"{policy['id']}_roles.yaml"] = (f"apiVersion: api.cerbos.dev/v1\nderivedRoles:\n  name: {policy['id']}_roles\n"
                                                  "  definitions:\n" + "\n".join(derived) + "\n")
    return tr


class Runner:
    def __init__(self, policy: Dict[str, Any], gen_dir: Path):
        self.policy = policy
        self.base = f"http://127.0.0.1:{HTTP_PORT}"
        self.tmp = tempfile.mkdtemp(prefix="cerbos_")
        store = Path(self.tmp) / "policies"
        store.mkdir()
        for policy_file in gen_dir.glob("*.yaml"):
            (store / policy_file.name).write_text(policy_file.read_text(encoding="utf-8"), encoding="utf-8")
        conf = Path(self.tmp) / "conf.yaml"
        conf.write_text(f"server:\n  httpListenAddr: \"127.0.0.1:{HTTP_PORT}\"\n  grpcListenAddr: \"127.0.0.1:{GRPC_PORT}\"\n"
                        f"storage:\n  driver: disk\n  disk:\n    directory: {store}\n", encoding="utf-8")
        self.log = open(Path(self.tmp) / "server.log", "w")
        self.proc = subprocess.Popen([str(TOOLCHAIN_BIN / "cerbos"), "server", f"--config={conf}"],
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        for _ in range(80):
            try:
                with urllib.request.urlopen(f"{self.base}/_cerbos/health", timeout=1) as response:
                    if response.status == 200:
                        break
            except (urllib.error.URLError, ConnectionError, OSError):
                time.sleep(0.25)
        else:
            # close() is never reached on this path, so the server and its log are released here
            self.proc.kill()
            self.log.close()
            raise RuntimeError("cerbos did not become healthy")

    def decide(self, inp: Dict[str, Any]) -> Decision:
        inp = {field: value for field, value in inp.items() if value is not None}
        hierarchy = self.policy.get("hierarchy")
        principal: Dict[str, Any] = {"id": "requester", "roles": ["user"], "attr": {}}
        attr = dict(inp)
        if hierarchy:
            role = attr.get(ROLE_FIELD)
            principal["roles"] = [role] if role else ["user"]
            for field in list(attr):
                if field in PRINCIPAL_FIELDS:
                    principal["attr"][field] = attr.pop(field)
        body = {"requestId": "cmp", "includeMeta": True, "principal": principal,
                "resources": [{"actions": ["decide"], "resource": {"kind": self.policy["id"], "id": "r1", "attr": attr}}]}
        req = urllib.request.Request(self.base + "/api/check/resources", data=json.dumps(body).encode(),
                                     headers={"content-type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                res = json.loads(response.read().decode())
        except urllib.error.HTTPError as error:
            return Decision("error", None, None, error.read().decode(errors="replace"))
        raw = json.dumps(res, sort_keys=True)
        result = res["results"][0]
        outputs = [output.get("val") for output in result.get("outputs", []) if isinstance(output.get("val"), dict)]
        if len(outputs) == 1:
            return Decision(outputs[0].get("outcome", "error"), outputs[0].get("rule"), None, raw)
        if not outputs:
            return Decision("no_match", None, None, raw)
        return Decision("error", None, None, raw)   # more than one rule activated: the ordering emulation failed

    def close(self) -> None:
        try:
            os.killpg(self.proc.pid, signal.SIGTERM)
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()
        self.log.close()
