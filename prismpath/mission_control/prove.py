# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Proving router — the primary-adapter headline.

Text-in: callers POST a flow *document*, never a server-side path. That is what makes this a clean,
safe API for other services — there is no filesystem surface to traverse. All proving runs against
the same `prismpath.model_check` the kernel and CLI use, so a verdict here is the verdict everywhere.
"""
from fastapi import APIRouter, HTTPException

from . import core
from .models import ProveLevelMReq, ProveReachReq

router = APIRouter(prefix="/prove", tags=["prove"])


def _graph(flow_text: str):
    from prismpath.parser import parse
    if not (flow_text or "").strip():
        raise HTTPException(status_code=400, detail="flow is empty")
    try:
        return parse(flow_text)
    except Exception as e:                       # a malformed flow is a client error, not a 500
        raise HTTPException(status_code=400, detail=f"could not parse flow: {e}")


@router.post("/level-m")
def prove_level_m(req: ProveLevelMReq):
    """Does the flow's deterministic tier compile to a hardware match-action table (SPEC §7, Level M)?
    Returns membership plus the offending edges when it does not."""
    from prismpath import model_check
    all_in, bad = model_check.flow_level_m(_graph(req.flow))
    return {"level_m": all_in, "non_member_edges": bad}


@router.post("/reach")
def prove_reach(req: ProveReachReq):
    """Bounded reachability for each target node under an optional assumption. Verdicts are
    yes | may | no; `results` carries the witness path so the command center can paint it."""
    from prismpath import model_check
    graph = _graph(req.flow)
    targets = list(dict.fromkeys((req.reach or []) + (req.forbid or [])))
    if not targets:
        raise HTTPException(status_code=400, detail="provide at least one node in reach or forbid")
    results = model_check.check_reach(graph, targets, assume=(req.assume or None))
    return {"verdicts": {n: r.reachable for n, r in results.items()},
            "results": {n: r.as_dict() for n, r in results.items()}}


@router.get("/audit")
def prove_audit():
    """The console verifies its own append-only audit log (tamper-evidence, self-checked)."""
    return {"valid": core.AUDIT.verify_log(), "n": len(core.AUDIT.events)}
