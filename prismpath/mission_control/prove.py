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
    from prismpath.kernel.parser import parse
    if not (flow_text or "").strip():
        raise HTTPException(status_code=400, detail="flow is empty")
    try:
        return parse(flow_text)
    except Exception as error:                       # a malformed flow is a client error, not a 500
        raise HTTPException(status_code=400, detail=f"could not parse flow: {error}")


@router.post("/level-m")
def prove_level_m(req: ProveLevelMReq):
    """Does the flow's deterministic tier compile to a hardware match-action table (SPEC §7, Level M)?
    Returns membership plus the offending edges when it does not."""
    from prismpath.kernel import model_check
    all_in, bad = model_check.flow_level_m(_graph(req.flow))
    return {"level_m": all_in, "non_member_edges": bad}


@router.post("/reach")
def prove_reach(req: ProveReachReq):
    """Bounded reachability for each target node under an optional assumption. Verdicts are
    yes | may | no; `results` carries the witness path so the command center can paint it."""
    from prismpath.kernel import model_check
    graph = _graph(req.flow)
    targets = list(dict.fromkeys((req.reach or []) + (req.forbid or [])))
    if not targets:
        raise HTTPException(status_code=400, detail="provide at least one node in reach or forbid")
    results = model_check.check_reach(graph, targets, assume=(req.assume or None))
    return {"verdicts": {node_name: reach_result.reachable for node_name, reach_result in results.items()},
            "results": {node_name: reach_result.as_dict() for node_name, reach_result in results.items()}}


def signing_status(log) -> dict:
    """Whether the log's root statements verify, in the terms `prismpath trail` reports: status (signed,
    signed-unpinned, unsigned, invalid), how many statements cover how many events, the keys that signed,
    and the findings. `console_key` is the instance key this console signs with now (None when it has
    none), and `console_key_signed` whether every statement was made by it; the check pins no key itself,
    so a reader who needs the deployment's key pinned runs `prismpath trail --pub`."""
    from prismpath.extras import MissingExtra
    key = log.instance_key
    console_key = key.fingerprint if key is not None else None
    try:
        report = log.verify_statements()
    except MissingExtra as missing:                 # statements exist and this install cannot check signatures
        return {"status": "unchecked", "reason": missing.install, "console_key": console_key}
    return {"status": report["status"], "statements": report["statements"], "signed_leaves": report["signed_leaves"],
            "log_leaves": report["log_leaves"], "unsigned_tail": report["unsigned_tail"], "keys": report["keys"],
            "pinned": report["pinned"], "findings": report["findings"], "console_key": console_key,
            "console_key_signed": bool(console_key and report["keys"] == [console_key]),
            "last_statement_sha256": report["last_statement_sha256"]}


@router.get("/audit")
def prove_audit():
    """The console verifies its own append-only audit log (tamper-evidence, self-checked), and says
    whether the log is signed: `valid` is the Merkle check, `signing` the root statements beside it."""
    log = core.audit.LOG
    signing = signing_status(log)
    valid = log.verify_log()
    return {"valid": valid, "n": len(log.events), "signing": signing,
            "ok": valid and signing["status"] != "invalid"}
