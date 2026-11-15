# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The population's rules read a second time, as plain Python over the admission fields, independent of the
image. The caps on sums are written as the sums (the image cannot add two fields and spells them as one
disjunct per count), so the exhaustive check holds the image's disjunctions to the arithmetic they stand for.

It returns ("allow", None), ("refuse", cause) or ("escalate", cause), the cause by its registered name, and
the order of the checks is the owner's priority: a stop first, then resisting one, then who is asking, then
the lineage's record, then rights, then caps, then the evaluation.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from .limits import CAP, EVAL_CASES, LINE_REFUSALS, MAX_GENERATION, PER_REQUEST, QUOTA, RIGHTS

NO_RULE = "route:no-matching-edge"


def expected(r: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    request, issuer = r["request"], r["issuer"]
    if request == "stop" and issuer in ("operator", "controller"):
        return "allow", None
    if request == "stop" and issuer == "agent" and r["target"] == "own":
        return "allow", None
    if request == "protect" or (request == "restart" and r["target_stopped"]):
        return "refuse", "population:stop-resisted"
    if r["lineage"] != "verified":
        return "refuse", "population:lineage-unknown"
    if r["line_refusals"] >= LINE_REFUSALS:
        return "escalate", "population:lineage-escalated"
    if request in ("replicate", "evolve"):
        if r["child_key"] != "instance" or r["policy_ref"] != "current":
            return "refuse", "population:rights-escalation"
        if any(r[f"child_{right}"] and not r[f"parent_{right}"] for right in RIGHTS):
            return "refuse", "population:rights-escalation"
    if request == "replicate":
        if not r["parent_replicate"]:
            return "refuse", "population:rights-escalation"
        count = r["requested"]
        if count > PER_REQUEST or r["child_generation"] > MAX_GENERATION or r["population"] + count > CAP \
                or r["line_size"] + count > QUOTA:
            return "refuse", "population:cap-exceeded"
        if count >= 1 and issuer in ("agent", "operator"):
            return "allow", None
    if request == "evolve":
        if r["canary"] != "passed":
            return "refuse", "population:evaluation-missing"
        if issuer in ("agent", "operator"):
            return "allow", None
    if request == "restart" and issuer in ("controller", "operator"):
        return "allow", None
    if request == "review" and issuer == "controller":
        return "allow", None
    return "refuse", NO_RULE


def evaluation_expected(r: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """A canary passes when it ran every case of the adversary set, nothing ran out of policy, every decision
    had the owner's cause, every episode verified and replayed, and every benign control completed."""
    if r["cases"] >= EVAL_CASES and r["out_of_policy"] == 0 and r["wrong_cause"] == 0 and r["unverified"] == 0 \
            and r["benign_failed"] == 0:
        return "allow", None
    return "refuse", NO_RULE
