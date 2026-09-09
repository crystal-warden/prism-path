# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""PrismPath's own translator for the layer comparison: neutral corpus policy -> one Markdown flow.

Idiom (SPEC.md sections 2 to 4): the policy is one `## decide` node whose `-> target: when ...`
edges are the rules in document order, first true wins, and every rule routes to its own terminal
node named `<rule>_<outcome>` so the decision the engine reports carries the rule identity the
corpus compares (two rules with the same outcome would otherwise be indistinguishable). The catch
all is `else`. Predicates are the neutral conditions spelled in the predicate language:

    cmp field OP const     -> `field OP const`   (bool == true -> `field`, bool == false -> `field == False`)
    in / not_in            -> `field in (...)` / `field not in (...)`
    any[missing f, f==false] on a bool -> `not f`  (a missing field is null, null is falsy: exact)
    all / any / not        -> and / or / not with parentheses

The worker is a stub that returns the scenario input as its emitted fields. One reserved field is
honored: the corpus's `human_requested` means the worker itself asked for a person, and PrismPath's
idiom for that is the reserved worker outcome field `needs_human` (SPEC section 5.5), so the stub
sets it and the engine suspends with cause 34 before routing. The matching rule is still emitted as
an edge, so a reader sees the whole policy in the document.

Constructs outside the predicate language (`eq_fields`, `intersects`, `related`) cannot be
expressed; `role_at_least` is flattened at authoring into the explicit list of roles at or above
the floor, which states the consequence of the hierarchy rather than the hierarchy itself.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismpath import model_check
from prismpath.comparisons.harness import Decision, Translation
from prismpath.engine import run
from prismpath.parser import parse

SYSTEM = "prismpath"
CITATIONS = [
    "SPEC.md section 2 (edges, tiers), section 3 (routing: deterministic first, document order, first true)",
    "SPEC.md section 4 (predicate language), section 4.3 (Level M fragment)",
    "SPEC.md section 5.5 (reserved worker outcome fields: needs_human)",
]
HUMAN_REQUEST_FIELD = "human_requested"


class Inexpressible(Exception):
    pass


def _lit(v: Any) -> str:
    if isinstance(v, bool):
        return "True" if v else "False"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v)
    raise Inexpressible(f"constant {v!r} has no predicate literal")


def _tuple(vals: List[Any]) -> str:
    inner = ", ".join(_lit(v) for v in vals)
    return f"({inner},)" if len(vals) == 1 else f"({inner})"


def render(cond: Any, policy: Dict[str, Any]) -> str:
    if cond is True:
        return "else"
    (form, arg), = cond.items()
    if form == "cmp":
        f, op, c = arg
        if isinstance(c, bool) and op == "==":
            return f if c else f"{f} == False"
        return f"{f} {op} {_lit(c)}"
    if form == "in":
        return f"{arg[0]} in {_tuple(arg[1])}"
    if form == "not_in":
        return f"{arg[0]} not in {_tuple(arg[1])}"
    if form == "any":
        # the exact bool spelling: any[missing f, f == false] -> not f
        if (len(arg) == 2 and isinstance(arg[0], dict) and "missing" in arg[0]
                and arg[1] == {"cmp": [arg[0]["missing"], "==", False]}
                and policy["fields"].get(arg[0]["missing"], {}).get("type") == "bool"):
            return f"not {arg[0]['missing']}"
        return " or ".join(f"({render(c, policy)})" for c in arg)
    if form == "all":
        return " and ".join(f"({render(c, policy)})" for c in arg)
    if form == "not":
        return f"not ({render(arg, policy)})"
    if form in ("missing", "present"):
        if policy["fields"].get(arg, {}).get("type") != "bool":
            raise Inexpressible(f"{form} on a non bool field {arg!r}: null is only exactly spelled through truthiness for bools")
        return f"not {arg}" if form == "missing" else arg
    if form == "role_at_least":
        f, floor = arg
        order = policy["hierarchy"]["order"]
        return f"{f} in {_tuple(order[order.index(floor):])}"
    raise Inexpressible(f"{form}: outside the predicate language (SPEC section 4)")


def translate(policy: Dict[str, Any]) -> Translation:
    tr = Translation(citations=list(CITATIONS))
    if any(r["if"] is not True and "related" in r["if"] for r in policy["rules"]):
        tr.expressible = False
        tr.notes.append("relationship graphs are outside PrismPath: no data plane, no relation model; "
                        "every derived tuple would have to be precomputed by the caller into a boolean field")
        return tr
    edges, terminals = [], []
    for r in policy["rules"]:
        node = f"{r['id']}_{r['then']}"
        try:
            cond = render(r["if"], policy)
        except Inexpressible as e:
            tr.dropped_rules.append(r["id"])
            tr.notes.append(f"{r['id']} dropped: {e}")
            continue
        if r["if"] is not True and "role_at_least" in json.dumps(r["if"]):
            tr.notes.append(f"{r['id']}: role hierarchy flattened at authoring into an explicit in list (WITH-WORK); the policy states the consequence, not the hierarchy")
        edges.append(f"-> {node}: {cond}" if cond == "else" else f"-> {node}: when {cond}")
        terminals.append(f"## {node}\n{r['why']}\n")
    if any(r["if"] is True for r in policy["rules"]) is False:
        tr.notes.append("no catch all by design: an input no rule covers stops the walk as stuck (cause 36)")
    fields = ", ".join(policy["fields"])
    text = (f"---\nname: {policy['id']}\nstart: decide\n---\n\n## decide\n{policy['title']}\n"
            f"The worker reports the request as fields; the edges below are the policy, first true wins.\n"
            f"@emits({fields})\n" + "\n".join(edges) + "\n\n" + "\n".join(terminals))
    tr.files[f"{policy['id']}.md"] = text
    graph = parse(text)
    ok, offenders = model_check.flow_level_m(graph)
    tr.notes.append(f"Level M: {'yes' if ok else 'NO'}" + ("" if ok else f" offenders {offenders}"))
    if policy.get("level_m_claim") and not ok:
        tr.notes.append("PRE REGISTERED LEVEL M CLAIM FAILED")
    return tr


class Runner:
    def __init__(self, policy: Dict[str, Any], gen_dir: Path):
        self.policy = policy
        self.graph = parse((gen_dir / f"{policy['id']}.md").read_text(encoding="utf-8"))
        self.human_rule = next((r["id"] for r in policy["rules"]
                                if r["if"] == {"cmp": [HUMAN_REQUEST_FIELD, "==", True]}), None)

    def decide(self, inp: Dict[str, Any]) -> Decision:
        fields = {k: v for k, v in inp.items() if v is not None}

        def worker(node: str, instruction: str, ctx: dict):
            out = dict(fields)
            if self.human_rule and fields.get(HUMAN_REQUEST_FIELD) is True:
                out["needs_human"] = True
                out["reason"] = "worker requested a person"
            return out

        res = run(self.graph, worker, router=_NoRouter(), max_steps=5)
        raw = json.dumps({"path": res.path, "stopped": res.stopped, "cause": res.cause})
        if res.stopped == "needs_human":
            return Decision("escalate_human", self.human_rule, res.cause, raw)
        if res.stopped == "stuck":
            return Decision("no_match", None, res.cause, raw)
        if res.stopped == "terminal":
            rule, _, outcome = res.path[-1].partition("_")
            return Decision(outcome, rule, res.cause, raw)
        return Decision("error", None, res.cause, raw)

    def close(self) -> None:
        pass


class _NoRouter:
    """The corpus policies are fully deterministic; a semantic route would be a translator bug."""
    def route(self, *a, **k):
        raise AssertionError("semantic routing reached in a deterministic corpus policy")
