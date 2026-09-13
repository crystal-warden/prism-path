# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Cedar translator for the layer comparison.

Cedar's decision is ALLOW or DENY for one (principal, action, resource, context) request: any
`permit` that applies allows unless a `forbid` applies; there is no ordering among policies and no
third outcome. Facts confirmed on the pinned CLI (4.12.0): `cedar authorize -v` names the policy
ids that determined the decision, a policy that reads a missing context attribute without a `has`
guard is skipped with an evaluation error (so the request falls to DENY), and DENY is signalled as
exit code 2 with a leading blank line.

Idiom used. One `permit` policy per corpus rule, annotated `@id("<rule>")`, all for the single
action `Action::"decide"`, on a nominal principal and resource. The rule's outcome is not a Cedar
decision, so it rides the annotation `@outcome("...")` and the runner reads the determining policy
id from the verbose output: exactly one policy should apply, its id is the rule, its outcome is the
decision. First match is emulated the only way Cedar allows: each policy's `when` is its own
condition AND the negation of every earlier rule's condition. Every context read is guarded with
`context has f &&` so absence is unsatisfied rather than an evaluation error. `forbid` is not used,
because forbid overriding permit regardless of position would break first match ordering.

Group B: the role hierarchy is the entity hierarchy (`principal in Role::"manager"`, with
Role::"admin" a child of Role::"manager" and so on), the documented Cedar idiom; field against
field and `containsAny` are native. The relationship policy is expressed as Cedar's documented
sharing idiom: group membership and folder parentage as the entity hierarchy, and one policy per
viewer tuple of the shape `permit(principal in <subject>, action == Action::"view", resource in
<object>)`, which is what a linked template instance per tuple expands to.
"""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismpath.comparisons.harness import TOOLCHAIN_BIN, Decision, Translation

SYSTEM = "cedar"
CITATIONS = [
    "https://docs.cedarpolicy.com/policies/syntax-policy.html (permit/forbid, when/unless, annotations)",
    "https://docs.cedarpolicy.com/auth/authorization.html (forbid overrides permit; no ordering; ALLOW only when a permit applies)",
    "https://docs.cedarpolicy.com/policies/syntax-operators.html (has, in, contains, containsAny)",
    "https://docs.cedarpolicy.com/overview/terminology.html#term-entity-hierarchy (entity hierarchy, `in`)",
    "https://docs.cedarpolicy.com/policies/templates.html (templates linked per relationship)",
]
NS_ROLE, NS_USER = "Role", "User"
ROLE_FIELD = "user_role"


class Inexpressible(Exception):
    pass


def _lit(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return json.dumps(value)


def cedar_cond(cond: Any, policy: Dict[str, Any]) -> str:
    if cond is True:
        return "true"
    (form, arg), = cond.items()
    if form == "cmp":
        field, op, constant = arg
        return f"(context has {field} && context.{field} {op} {_lit(constant)})"
    if form == "in":
        return f"(context has {arg[0]} && [{', '.join(_lit(value) for value in arg[1])}].contains(context.{arg[0]}))"
    if form == "not_in":
        return f"(context has {arg[0]} && !([{', '.join(_lit(value) for value in arg[1])}].contains(context.{arg[0]})))"
    if form == "missing":
        return f"!(context has {arg})"
    if form == "present":
        return f"(context has {arg})"
    if form == "all":
        return "(" + " && ".join(cedar_cond(condition, policy) for condition in arg) + ")"
    if form == "any":
        return "(" + " || ".join(cedar_cond(condition, policy) for condition in arg) + ")"
    if form == "not":
        return f"!{cedar_cond(arg, policy)}"
    if form == "eq_fields":
        left_field, right_field = arg
        return f"(context has {left_field} && context has {right_field} && context.{left_field} == context.{right_field})"
    if form == "intersects":
        left_field, right_field = arg
        return f"(context has {left_field} && context has {right_field} && context.{left_field}.containsAny(context.{right_field}))"
    if form == "role_at_least":
        return f'principal in {NS_ROLE}::{json.dumps(arg[1])}'
    raise Inexpressible(form)


def translate(policy: Dict[str, Any]) -> Translation:
    tr = Translation(citations=list(CITATIONS))
    if any(rule["if"] is not True and "related" in rule["if"] for rule in policy["rules"]):
        return _translate_rebac(policy, tr)
    lines, prior = [], []
    for rule in policy["rules"]:
        own = cedar_cond(rule["if"], policy)
        parts = [own] + [f"!{prior_condition}" for prior_condition in prior]
        if rule["if"] is not True:
            prior.append(own)
        when = " &&\n    ".join(parts)
        lines.append(f'@id("{rule["id"]}")\n@outcome("{rule["then"]}")\n'
                     f'permit(principal, action == Action::"decide", resource)\nwhen {{\n    {when}\n}};\n')
    tr.files[f"{policy['id']}.cedar"] = "\n".join(lines)
    tr.notes.append("first match emulated by conjoining the negation of every earlier rule's condition (Cedar has no "
                    "policy ordering and forbid would override regardless of position); every context read is "
                    "`context has` guarded so absence is unsatisfied, not an evaluation error")
    tr.notes.append("the outcome is not a Cedar decision: it rides the @outcome annotation of the one policy that "
                    "applies, read from `cedar authorize -v`; Cedar itself answers ALLOW (a rule applied) or DENY")
    if policy.get("hierarchy"):
        order = policy["hierarchy"]["order"]
        ents = [{"uid": {"type": NS_ROLE, "id": role}, "attrs": {},
                 "parents": [{"type": NS_ROLE, "id": order[role_index - 1]}] if role_index > 0 else []}
                for role_index, role in enumerate(order)]
        tr.files["roles.entities.json"] = json.dumps(ents, indent=2) + "\n"
        tr.notes.append("role hierarchy as the entity hierarchy: Role::admin is a child of Role::manager and so on, "
                        "the principal's parent is its role, and role_at_least is `principal in Role::floor` (native)")
    if not any(rule["if"] is True for rule in policy["rules"]):
        tr.notes.append("no catch all by design: no policy applies and Cedar returns DENY with 'no policies applied'")
    return tr


def _translate_rebac(policy: Dict[str, Any], tr: Translation) -> Translation:
    model = policy["model"]
    related = next(rule for rule in policy["rules"] if rule["if"] is not True and "related" in rule["if"])
    relation = "view"
    ents: Dict[str, Dict[str, Any]] = {}

    def ent(typed: str) -> Dict[str, Any]:
        entity_type, _, entity_id = typed.partition(":")
        key = f"{entity_type}:{entity_id}"
        if key not in ents:
            ents[key] = {"uid": {"type": entity_type.capitalize(), "id": entity_id}, "attrs": {}, "parents": []}
        return ents[key]

    policies = []
    def cid(typed: str) -> str:
        entity_type, _, entity_id = typed.partition(":")
        return f"{entity_type.capitalize()}::{json.dumps(entity_id)}"

    for subject, tuple_relation, object_ref in model["tuples"]:
        if tuple_relation == "parent":                       # (parent_object, parent, child): the child's parent in the hierarchy
            ent(object_ref)["parents"].append(ent(subject)["uid"])
        elif tuple_relation == "member":                     # (user, member, group): the user's parent is the group
            ent(subject)["parents"].append(ent(object_ref)["uid"])
        elif subject.endswith("#member"):             # (group#member, viewer, object): one policy for the group
            group = subject.split("#", 1)[0]
            ent(object_ref); ent(group)
            policies.append(f'@id("{subject}|{tuple_relation}|{object_ref}")\npermit(principal in {cid(group)}, action == Action::"{relation}", resource in {cid(object_ref)});\n')
        else:                                   # (user, viewer, object): one policy for the user
            ent(object_ref); ent(subject)
            policies.append(f'@id("{subject}|{tuple_relation}|{object_ref}")\npermit(principal == {cid(subject)}, action == Action::"{relation}", resource in {cid(object_ref)});\n')
    tr.files[f"{policy['id']}.cedar"] = "\n".join(policies)
    tr.files["entities.json"] = json.dumps(list(ents.values()), indent=2) + "\n"
    tr.notes.append("relationships as Cedar's sharing idiom: group membership and folder parentage are the entity "
                    "hierarchy, each viewer tuple is one policy `permit(principal in <subject>, action == view, "
                    "resource in <object>)` (the expansion of a linked template instance per tuple); inheritance to "
                    "documents comes from `resource in Folder` through the hierarchy")
    tr.notes.append(f"the corpus allow rule is {related['id']}, the catch all is the Cedar default DENY")
    tr.idiomatic = True
    return tr


def _parse_verbose(out: str) -> Dict[str, Any]:
    decision = "ALLOW" if re.search(r"^ALLOW\s*$", out, re.M) else ("DENY" if re.search(r"^DENY\s*$", out, re.M) else "ERROR")
    ids: List[str] = []
    policies_match = re.search(r"due to the following policies:\n((?:\s+\S.*\n?)+)", out)
    if policies_match:
        ids = [ln.strip() for ln in policies_match.group(1).splitlines() if ln.strip()]
    errors = "error" in out.lower() and decision == "ERROR"
    return {"decision": decision, "ids": ids, "errors": errors}


class Runner:
    def __init__(self, policy: Dict[str, Any], gen_dir: Path):
        self.policy = policy
        self.gen_dir = gen_dir
        self.pol = gen_dir / f"{policy['id']}.cedar"
        self.rebac = (gen_dir / "entities.json").exists()
        self.roles = gen_dir / "roles.entities.json"
        self.outcomes = {rule["id"]: rule["then"] for rule in policy["rules"]}
        self.tmp = Path(tempfile.mkdtemp(prefix="cedar_"))
        self.empty = self.tmp / "empty_entities.json"      # Cedar entities: a JSON list
        self.empty.write_text("[]\n", encoding="utf-8")
        self.empty_ctx = self.tmp / "empty_context.json"   # Cedar context: a JSON record
        self.empty_ctx.write_text("{}\n", encoding="utf-8")

    def _run(self, args: List[str]) -> subprocess.CompletedProcess:
        return subprocess.run([str(TOOLCHAIN_BIN / "cedar"), "authorize", "-v", "--policies", str(self.pol), *args],
                              capture_output=True, text=True, timeout=60)

    def decide(self, inp: Dict[str, Any]) -> Decision:
        inp = {field: value for field, value in inp.items() if value is not None}
        if self.rebac:
            rel = next(rule for rule in self.policy["rules"] if rule["if"] is not True and "related" in rule["if"])
            uf, _rf, of = rel["if"]["related"]
            user_ref, object_ref = inp.get(uf, ""), inp.get(of, "")
            ents = json.loads((self.gen_dir / "entities.json").read_text(encoding="utf-8"))
            if not any(entity["uid"] == {"type": user_ref.split(":")[0].capitalize(), "id": user_ref.split(":", 1)[1]} for entity in ents):
                ents.append({"uid": {"type": user_ref.split(":")[0].capitalize(), "id": user_ref.split(":", 1)[1]}, "attrs": {}, "parents": []})
            ef = self.tmp / "req_entities.json"
            ef.write_text(json.dumps(ents), encoding="utf-8")
            cp = self._run(["--entities", str(ef), "--principal", f'{user_ref.split(":")[0].capitalize()}::{json.dumps(user_ref.split(":", 1)[1])}',
                            "--action", 'Action::"view"', "--resource", f'{object_ref.split(":")[0].capitalize()}::{json.dumps(object_ref.split(":", 1)[1])}',
                            "--context", str(self.empty_ctx)])
            raw = cp.stdout + cp.stderr
            verbose = _parse_verbose(raw)
            catch = next((rule for rule in self.policy["rules"] if rule["if"] is True), None)
            if verbose["decision"] == "ALLOW":
                return Decision(rel["then"], rel["id"], None, raw)
            if verbose["decision"] == "DENY":
                return Decision(catch["then"], catch["id"], None, raw) if catch else Decision("no_match", None, None, raw)
            return Decision("error", None, None, raw)
        ctx = self.tmp / "ctx.json"
        ctx.write_text(json.dumps(inp), encoding="utf-8")
        entities = str(self.empty)
        principal = f'{NS_USER}::"requester"'
        if self.roles.exists():
            ents = json.loads(self.roles.read_text(encoding="utf-8"))
            role = inp.get(ROLE_FIELD)
            ents.append({"uid": {"type": NS_USER, "id": "requester"}, "attrs": {},
                         "parents": [{"type": NS_ROLE, "id": role}] if role else []})
            ef = self.tmp / "req_entities.json"
            ef.write_text(json.dumps(ents), encoding="utf-8")
            entities = str(ef)
        cp = self._run(["--entities", entities, "--principal", principal, "--action", 'Action::"decide"',
                        "--resource", 'Request::"r"', "--context", str(ctx)])
        raw = cp.stdout + cp.stderr
        verbose = _parse_verbose(raw)
        if verbose["decision"] == "ALLOW" and len(verbose["ids"]) == 1 and verbose["ids"][0] in self.outcomes:
            return Decision(self.outcomes[verbose["ids"][0]], verbose["ids"][0], None, raw)
        if verbose["decision"] == "DENY" and not verbose["ids"]:
            return Decision("no_match", None, None, raw)
        return Decision("error", None, None, raw)

    def close(self) -> None:
        pass
