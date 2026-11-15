# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The population's two policy images, loaded and decided exactly as the governed harness decides its own.

`governed_harness.policy.Policy` is reused unchanged: the image is checked by the port of the Lean
`loadPolicy`, rendered and parsed by the reference kernel, and a reading's bytes are decided by the
reference's decision path. A target names what the controller does, `allow`, `refuse_<code>` or
`escalate_<code>`, with the cause inside the signed image.

A reading holds every field the image defines, integers, booleans and categories only, built here from
the controller's facts (`admission_reading`). The controller is trusted code outside the verified core,
as the harness's classifier is: what is proved is about the reading it forms.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable

from integrations.governed_harness.policy import Decision, Policy, target_decision  # noqa: F401

from .limits import RIGHTS

HERE = Path(__file__).resolve().parent
ADMISSION_PATH = HERE / "policy" / "admission.core.json"
EVALUATION_PATH = HERE / "policy" / "evaluation.core.json"

REQUESTS = ("replicate", "evolve", "restart", "protect", "stop", "review")
ISSUERS = ("operator", "controller", "agent")


def admission() -> Policy:
    return Policy.load(ADMISSION_PATH)


def evaluation() -> Policy:
    return Policy.load(EVALUATION_PATH)


def base_reading() -> Dict[str, Any]:
    """Every admission field at its most refusing value: no request, no issuer, no lineage."""
    reading = {"admission_version": 1, "request": "unknown", "issuer": "unknown", "target": "other",
               "lineage": "unknown", "population": 0, "line_size": 0, "requested": 0, "child_generation": 0,
               "child_key": "none", "policy_ref": "none", "canary": "none", "target_stopped": False,
               "line_refusals": 0, "subject": "none"}
    for right in RIGHTS:
        reading[f"parent_{right}"] = False
        reading[f"child_{right}"] = False
    return reading


def rights_fields(parent: Iterable[str], child: Iterable[str]) -> Dict[str, bool]:
    parent, child = set(parent), set(child)
    out = {}
    for right in RIGHTS:
        out[f"parent_{right}"] = right in parent
        out[f"child_{right}"] = right in child
    return out


def admission_reading(**facts: Any) -> Dict[str, Any]:
    reading = base_reading()
    unknown = set(facts) - set(reading)
    if unknown:
        raise KeyError(f"not admission fields: {sorted(unknown)}")
    reading.update(facts)
    return reading


def evaluation_reading(*, cases: int, out_of_policy: int, wrong_cause: int, unverified: int, benign_failed: int,
                       subject: str) -> Dict[str, Any]:
    return {"evaluation_version": 1, "cases": cases, "out_of_policy": out_of_policy, "wrong_cause": wrong_cause,
            "unverified": unverified, "benign_failed": benign_failed, "subject": subject}
