"""Observe router — read-only views over the followed sprint's on-disk artifacts."""
import json
import os

from fastapi import APIRouter, HTTPException, Query

from . import core
from prismpath import audit_log

router = APIRouter(tags=["observe"])


@router.get("/status")
def get_status():
    return core.status(core.STATE)


@router.get("/interactions")
def get_interactions():
    return core.mc_interactions(core.STATE)


@router.get("/flow")
def get_flow():
    return core.flow_state(core.STATE)


@router.get("/flow/graph")
def get_flow_graph(path: str = Query(None, description="Contained flow path; omitted → the live flow.")):
    return core.serialize_flow_graph(core.STATE, path)


@router.get("/balance")
def get_balance():
    return core.balance_state(core.STATE)


@router.get("/retrievals")
def get_retrievals():
    """Which RAG chunks the run pulled, per turn (source · path · score) — the Retrieval port, observed."""
    return core.retrievals(core.STATE)


@router.get("/queue")
def get_queue():
    """Runs suspended for a human decision (the Deferral port, surfaced)."""
    from prismpath import checkpoint as _ckpt
    return {"items": _ckpt.list_queue()}


@router.get("/fanouts")
def get_fanouts():
    """Fan-out composition trees (read-only)."""
    from prismpath import composer as _composer
    return {"fanouts": _composer.fanout_tree()}


@router.get("/fanout/ckpt")
def get_fanout_ckpt(path: str = Query(...)):
    from prismpath import checkpoint as _ckpt
    qroot = os.path.realpath(_ckpt.queue_dir())
    rp = os.path.realpath(path)
    if not rp.startswith(qroot + os.sep) or not rp.endswith(".json"):
        raise HTTPException(status_code=400, detail="path escapes the queue dir")
    with open(rp, encoding="utf-8") as f:
        return {"path": path, "checkpoint": json.load(f)}


@router.get("/audit")
def get_audit():
    return {"root": core.AUDIT.current_root(), "n": len(core.AUDIT.events),
            "verify": core.AUDIT.verify_log(), "events": core.AUDIT.events[-100:]}


@router.get("/audit/proof")
def get_audit_proof(i: int = Query(0)):
    if not (0 <= i < len(core.AUDIT.leaves)):
        raise HTTPException(status_code=400, detail="bad index")
    pr = core.AUDIT.prove(i)
    return {"i": i, "path_len": len(pr["path"]), "peaks": len(pr["peaks"]),
            "leaf": core.AUDIT.leaves[i][:16], "root": core.AUDIT.current_root()[:16],
            "verified": audit_log.verify(core.AUDIT.leaves[i], pr, core.AUDIT.current_root())}
