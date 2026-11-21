# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""OpenTelemetry attributes for one governed tool call decision.

OpenTelemetry's GenAI semantic conventions (open-telemetry/semantic-conventions-genai, every attribute at status
Development) describe a tool call (`gen_ai.tool.name`, `gen_ai.tool.call.id`) but have no attribute for whether a
policy allowed it, refused it or sent it to a person, or why. This module proposes
attributes for that, carrying PrismPath's registered cause codes; this module produces them as a plain dict, so a
caller adds them to the span or event its own OpenTelemetry SDK makes. It imports no OpenTelemetry package.

Two namespaces. `PROPOSED` names are the ones the proposal asks the GenAI conventions to adopt
(`gen_ai.tool.call.decision.*`). Until they are adopted, `attributes()` emits the same values under
`prismpath.decision.*`, a namespace of PrismPath's own as OpenTelemetry advises for names it has not adopted, unless the caller
asks for the proposed names. The values are the same either way, so a backend can map one onto the other.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from prismpath.kernel import causes

VENDOR = "prismpath.decision"
PROPOSED = "gen_ai.tool.call.decision"

# the core's three outcomes, as the proposal spells them
OUTCOMES = {"allow": "allow", "refuse": "deny", "escalate": "ask"}


def attributes(kind: str, *, cause_code: Optional[int] = None, receipt_index: Optional[int] = None,
               run: Optional[str] = None, policy_sha256: Optional[str] = None, tool_name: Optional[str] = None,
               call_id: Optional[str] = None, proposed_names: bool = False) -> Dict[str, Any]:
    """The attributes for one decision. `kind` is the decision's `allow`, `refuse` or `escalate`; a refusal and an
    escalation carry their registered cause, an allow carries none. Values are only strings and integers, as
    OpenTelemetry attribute values must be."""
    if kind not in OUTCOMES:
        raise ValueError(f"unknown decision kind {kind!r}")
    if (kind == "allow") != (cause_code is None):
        raise ValueError("a refusal or an escalation carries its cause, and an allow carries none")
    prefix = PROPOSED if proposed_names else VENDOR
    out: Dict[str, Any] = {f"{prefix}.outcome": OUTCOMES[kind], f"{prefix}.decider": "prismpath.core/1"}
    if cause_code is not None:
        name = causes.name(cause_code)
        if name is None:
            raise ValueError(f"cause {cause_code} is not registered")
        out[f"{prefix}.cause.code"] = int(cause_code)
        out[f"{prefix}.cause.name"] = name
        out[f"{prefix}.cause.class"] = causes.cause_class(cause_code)
        out[f"{prefix}.cause.registry"] = causes.registry_sha256()
    if receipt_index is not None:
        out[f"{prefix}.receipt.index"] = int(receipt_index)
    if run is not None:
        out[f"{prefix}.receipt.run"] = str(run)
    if policy_sha256 is not None:
        out[f"{prefix}.policy.sha256"] = str(policy_sha256)
    # the call it decided, by the GenAI conventions' own names, when the caller knows them
    if tool_name is not None:
        out["gen_ai.tool.name"] = str(tool_name)
    if call_id is not None:
        out["gen_ai.tool.call.id"] = str(call_id)
    return out


def from_decision(decision, **context) -> Dict[str, Any]:
    """The attributes for a prismpath.agent.policy.Decision."""
    return attributes(decision.kind, cause_code=decision.cause_code, **context)
