# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A signed core policy image and the one decision on each reading, for any target kind.

`Policy(image, domain)` loads a `prismpath.core/1` image in its canonical canon/2 bytes the way the core reads it:

  * the image is checked by the port of the Lean oracle's `loadPolicy` (`prismpath.kernel.core_policy`), which must
    accept it;
  * it is rendered to its canonical flow text (`prismpath.kernel.core_render.render`) and parsed by the reference
    kernel (`prismpath.kernel.parser.parse`);
  * every rule's target must name something the harness knows (`target_decision`), and every value a rule names must
    be inside the reading domain (`prismpath.kernel.domain`), or the image is `policy:out-of-domain`.

A reading is decided by the reference's decision path (`prismpath.kernel.core_reference.python_reading`: the strict
canon/2 reader, the system boundary, the first deterministic rule that holds). A rule's target says what is done
with the request, and names the cause by its registered code:

  allow            the request goes ahead
  refuse_<code>    it never does; the decision is a refusal with that registered cause
  escalate_<code>  it never does; it is held for the owner, with that registered cause

A refusal of the core itself is a refusal too, so the policy fails closed by the core's own semantics.

The domain is an argument. `prismpath.agent.policy.Policy` is this class bound to the agent's domain, which the
trust path also applies to every kind for now (`prismpath.kernel.domain.AGENT_DOMAIN`).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

from prismpath.kernel import canon2, causes, core_policy, core_reference, core_render
from prismpath.kernel import domain as domains
from prismpath.kernel.domain import ReadingDomain
from prismpath.kernel.parser import parse

_TARGET = re.compile(r"^(allow|refuse_(\d+)|escalate_(\d+))$")


@dataclass(frozen=True)
class Decision:
    """What the harness does with one call: `allow`, `refuse` or `escalate`, with the registered cause of a
    refusal or an escalation, and the core's own verdict it came from."""
    kind: str
    cause: Optional[str]
    cause_code: Optional[int]
    verdict: Dict[str, Any]

    @property
    def runs(self) -> bool:
        return self.kind == "allow"


def target_decision(target: str):
    """(kind, cause, code) a rule's target names, or None when it names nothing the harness knows."""
    match = _TARGET.match(target)
    if not match:
        return None
    if match.group(1) == "allow":
        return "allow", None, None
    code = int(match.group(2) or match.group(3))
    name = causes.name(code)
    if name is None:
        return None
    return ("refuse" if match.group(2) else "escalate"), name, code


class OutsideDomain(ValueError):
    """The policy names a value outside its reading domain (`domain.outside_domain`), cause
    `policy:out-of-domain`."""


class Policy:
    def __init__(self, image: bytes, domain: ReadingDomain):
        if image.endswith(b"\n"):
            image = image[:-1]                 # the one line feed a file may end with
        self.image = image
        self.domain = domain
        refusal = core_policy.load_policy(image)
        if refusal is not None:
            raise ValueError(f"the core refuses the {domain.name} policy: {refusal}")
        self.doc = canon2.loads(image)
        self.flow = core_render.render(self.doc)
        self.graph = parse(self.flow)
        self.fields = sorted(self.doc["fields"])
        # the policy opts in to the fields the domain gives defaults for (the agent's session history)
        self.stateful = any(name in self.doc["fields"] for name in domain.defaults)
        for rule in self.doc["rules"]:
            if target_decision(rule["target"]) is None:
                raise ValueError(f"the policy names a target the harness does not know: {rule['target']}")
        outside = domains.outside_domain(self.doc, domain)
        if outside is not None:
            raise OutsideDomain(f"policy:out-of-domain: {outside}")

    def reading_bytes(self, reading: Dict[str, Any]) -> bytes:
        """A reading's canonical canon/2 bytes: the only spelling the core reads. A policy that opts in to the fields
        the domain gives defaults for is given each of them when the reading lacks any, at the most restrictive
        value: a caller that did not read them cannot make a decision they would have restricted."""
        if self.stateful and not all(name in reading for name in self.domain.defaults):
            reading = {**self.domain.defaults, **reading}
        return canon2.dumps(reading)

    def verdict(self, raw: bytes) -> Dict[str, Any]:
        """The core's verdict on one reading's bytes, from the reference decision path."""
        verdict = core_reference.python_reading(self.graph, raw)
        verdict.pop("policy_check", None)
        return verdict

    def decide(self, raw: bytes) -> Decision:
        """The decision on one reading's bytes. A reading with a value outside its field's reading domain is a
        resource nobody accounted for, so it is refused with `policy:out-of-domain` before the policy runs
        (spec-policy-distribution.md, 9.4)."""
        try:
            reading = canon2.loads(raw)
        except Exception:  # noqa: BLE001 - a reading that does not read is the core's to refuse
            reading = None
        outside = domains.reading_outside_domain(self.doc["fields"], reading, self.domain)
        if outside is not None:
            return Decision("refuse", "policy:out-of-domain", causes.code("policy:out-of-domain"),
                            {"verdict": "refuse", "cause": "policy:out-of-domain", "detail": outside})
        verdict = self.verdict(raw)
        if verdict.get("verdict") == "route":
            kind, cause, code = target_decision(verdict["target"])
            return Decision(kind, cause, code, verdict)
        cause = verdict.get("cause")
        code = causes.code(cause) if isinstance(cause, str) else None
        # an uncoded refusal (the reference crashed) is still a refusal, never a run; it carries no code, so
        # its receipt fails verification and the run reports it, rather than borrowing another cause
        return Decision("refuse", cause if isinstance(cause, str) else "crash", code, verdict)


def kind_of(policy: Policy, reading: Dict[str, Any]) -> str:
    """The kind `Policy.decide` gives `reading`, `allow`, `refuse` or `escalate`, by the reference's two steps
    (`core_reference._python_verdict`): the system boundary, then the first deterministic rule that holds, found
    as `engine.first_deterministic` finds it but with each condition parsed once (`predicates.holds`), and the policy
    check left out, which does not change a verdict. A reading the domain's default fields are missing from is given
    them at their most restrictive, as `Policy.reading_bytes` does. The widening comparator walks a whole domain with
    it, and `prismpath/tests/test_distribution_widening.py` holds it to `Policy.decide`."""
    from prismpath.kernel import field_definitions, predicates
    if policy.stateful and not all(name in reading for name in policy.domain.defaults):
        reading = {**policy.domain.defaults, **reading}
    try:
        if field_definitions.system_boundary(policy.graph, reading) is not None:
            return "refuse"
        for target, condition in policy.graph.nodes[policy.graph.start].edges:
            if not predicates.is_deterministic(condition):
                continue
            try:
                if predicates.holds(condition, reading):
                    decision = target_decision(target)
                    return decision[0] if decision is not None else "refuse"
            except predicates.PredicateError:
                pass
    except Exception:  # noqa: BLE001 - the reference refuses a reading it cannot decide
        return "refuse"
    return "refuse"
