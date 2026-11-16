# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Observe router — read-only views over the followed sprint's on-disk artifacts.

The operating interface's reads live here too: the human queue (runs suspended for a decision and runs
waiting for an event, nested fan-out children included), the policy host of a deployment whose state
directory is under the evidence roots, and the cause monitor's series over an audit log."""
import json
import os
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from . import core, evidence, policy
from prismpath.ledgers import audit_log

router = APIRouter(tags=["observe"])


@router.get("/status")
def get_status():
    return core.status(core.snapshot())


@router.get("/interactions")
def get_interactions():
    return core.interactions(core.snapshot())


@router.get("/flow")
def get_flow():
    return core.flow_state(core.snapshot())


@router.get("/flow/graph")
def get_flow_graph(path: str = Query(None, description="Contained flow path; omitted → the live flow.")):
    return core.serialize_flow_graph(core.snapshot(), path)


@router.get("/balance")
def get_balance():
    return core.balance_state(core.snapshot())


@router.get("/retrievals")
def get_retrievals():
    """Which RAG chunks the run pulled, per turn (source · path · score) — the Retrieval port, observed."""
    return core.retrievals(core.snapshot())


@router.get("/queue")
def get_queue():
    """Runs suspended for a human decision and runs waiting for an event (the Deferral port, surfaced),
    nested fan-out children included under their relative ids."""
    from prismpath.ledgers import checkpoint as _ckpt
    return {"items": _ckpt.list_queue(include_waiting=True)}


@router.get("/fanouts")
def get_fanouts():
    """Fan-out composition trees (read-only)."""
    from prismpath.workers import composer as _composer
    return {"fanouts": _composer.fanout_tree()}


@router.get("/fanout/ckpt")
def get_fanout_ckpt(path: str = Query(...)):
    from prismpath.ledgers import checkpoint as _ckpt
    qroot = os.path.realpath(_ckpt.queue_dir())
    rp = os.path.realpath(path)
    if not rp.startswith(qroot + os.sep) or not rp.endswith(".json"):
        raise HTTPException(status_code=400, detail="path escapes the queue dir")
    if os.path.getsize(rp) > core.SETTINGS.max_file_bytes:
        raise HTTPException(status_code=413, detail="checkpoint exceeds MC_MAX_FILE_BYTES")
    with open(rp, encoding="utf-8") as checkpoint_file:
        return {"path": path, "checkpoint": json.load(checkpoint_file)}


@router.get("/audit")
def get_audit():
    return {"root": core.audit.LOG.current_root(), "n": len(core.audit.LOG.events),
            "verify": core.audit.LOG.verify_log(), "events": core.audit.LOG.events[-100:]}


@router.get("/audit/proof")
def get_audit_proof(i: int = Query(0)):
    log = core.audit.LOG
    if not (0 <= i < len(log.leaves)):
        raise HTTPException(status_code=400, detail="bad index")
    pr = log.prove(i)
    return {"i": i, "path_len": len(pr["path"]), "peaks": len(pr["peaks"]),
            "leaf": log.leaves[i][:16], "root": log.current_root()[:16],
            "verified": audit_log.verify(log.leaves[i], pr, log.current_root())}


# How a transport answers an evidence reader's refusal (`evidence.EvidenceRefused.reason`).
REFUSAL_STATUS = {"outside-roots": 403, "not-found": 404, "too-large": 413}


def _refused(refusal: "evidence.EvidenceRefused") -> HTTPException:
    return HTTPException(status_code=REFUSAL_STATUS.get(refusal.reason, 400), detail=str(refusal))


@router.get("/policy/active")
def get_policy_active(state_dir: str = Query(..., description="A deployment's policy host state directory, "
                                                               "under an evidence root (MC_EVIDENCE)."),
                      last: int = Query(50, ge=0, le=1000, description="How many of the latest swaps.log events.")):
    """What a deployment runs: the active record, whether its image has the digest the record names, the
    swap history from `swaps.log` with whether its Merkle root holds, and the root statement chain beside
    it, with no key pinned. Reads only: nothing is created, attested or appended."""
    try:
        real, root = evidence._confine(state_dir, None)
    except evidence.EvidenceRefused as refusal:
        raise _refused(refusal)
    if not os.path.isdir(real):
        raise HTTPException(status_code=404, detail="no state directory there")
    # The report opens the files by name, so a link in the state directory that leads out of the evidence
    # roots would be followed; evidence is untrusted, and such a directory is refused whole.
    with os.scandir(real) as entries:
        for entry in entries:
            if entry.is_symlink() and not any(core.is_contained(os.path.realpath(entry.path), allowed)
                                              for allowed in evidence._roots(None)):
                raise HTTPException(status_code=403, detail="refused: the state directory links outside the evidence roots")
    report = policy.active_report(real, state_dir, last)
    report["evidence_root"] = root
    report["verdict_of"] = evidence.VERDICT_OF
    return report


@router.get("/trail/causes")
def get_trail_causes(path: Optional[str] = Query(None, description="An audit log under an evidence root; "
                                                                   "omitted, the console's own log."),
                     bucket_s: int = Query(3600, description="The width of one bucket, in seconds."),
                     since: Optional[str] = Query(None, description="Only events at or after this ISO 8601 time."),
                     last: Optional[int] = Query(None, description="Only the latest this many events.")):
    """Counts by cause (decisions) and by action (every event) per bucket of event time, the cause
    monitor's series (`evidence.cause_series`): sparse, oldest first, each cause decoded from the
    registry. The console's own log, when it holds no event yet, is an empty series."""
    roots = None
    if path is None:
        path = core.audit.LOG.path
        roots = [os.path.dirname(os.path.abspath(path))]
        if not os.path.exists(path):
            return {"path": path, "evidence_root": roots[0], "bucket_s": bucket_s, "events": 0, "untimed": 0,
                    "buckets": [], "causes": {}, "verdict_of": evidence.VERDICT_OF}
    try:
        return evidence.cause_series(path, bucket_s, since=since, last=last, roots=roots)
    except evidence.EvidenceRefused as refusal:
        raise _refused(refusal)
