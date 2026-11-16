# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Control router — start/stop the sprint and resolve human-in-the-loop decisions.

Every route here changes something, so every one carries the `write` capability and none is mounted in
the read only posture. A project named by a request (select, start) must be one the console may follow
(`core.confine_project`), and a route that acts on the followed project captures it once."""
import os

from fastapi import APIRouter, HTTPException

from . import core
from .models import QueueDecideReq, SprintSelectReq, SprintStartReq
from .posture import WRITE

router = APIRouter(tags=["control"])


@router.post("/sprint/start", openapi_extra=WRITE)
def sprint_start(req: SprintStartReq):
    # exclude_none so run_sprint's own defaults apply to fields the caller didn't set
    cfg = req.model_dump(exclude_none=True)
    if cfg.get("proj"):
        cfg["proj"] = core.confine_project(cfg["proj"], core.current_project())   # ValueError -> 400
    return core.start_sprint(cfg, core.STATE)


@router.post("/sprint/select", openapi_extra=WRITE)
def sprint_select(req: SprintSelectReq):
    """Pin the console to a chosen sprint dir (stop auto-following the live one). Only a discovered
    sprint, the launch project or a directory under an evidence root can be chosen."""
    proj = core.confine_project(req.proj, core.current_project())              # ValueError -> 400
    core.select_project(proj, pinned=True)
    return {"ok": True, "proj": proj, "pinned": True}


@router.post("/sprint/auto", openapi_extra=WRITE)
def sprint_auto():
    """Resume auto-following whichever sprint is live."""
    with core.STATE_LOCK:
        core.STATE["pinned"] = False
    core.follow_active_sprint(core.STATE)
    return {"ok": True, "proj": core.current_project(), "pinned": False}


@router.post("/sprint/stop", openapi_extra=WRITE)
def sprint_stop():
    return core.touch_marker(core.current_project(), "STOP", "sprint.stop")


@router.post("/sprint/pause", openapi_extra=WRITE)
def sprint_pause():
    return core.touch_marker(core.current_project(), "PAUSE", "sprint.pause")


@router.post("/sprint/resume", openapi_extra=WRITE)
def sprint_resume():
    proj = core.current_project()
    try:
        os.remove(os.path.join(proj, "PAUSE"))
    except OSError:
        pass
    core.audit.record("sprint.resume", {"proj": proj})
    return {"ok": True}


@router.post("/queue/decide", openapi_extra=WRITE)
def queue_decide(req: QueueDecideReq):
    """Human picks an edge for a suspended run. `resolve_queue_item` confines the id to the queue dir."""
    from prismpath.ledgers import checkpoint as _ckpt
    try:
        cpath = _ckpt.resolve_queue_item(req.id)
        _ckpt.record_decision(cpath, req.choose, decided_by=core.audit.ACTOR)
    except _ckpt.CheckpointError as refusal:     # an unknown queue item or an edge it does not offer: the caller's mistake
        raise HTTPException(status_code=400, detail=str(refusal))
    core.audit.record("queue.decide", {"id": req.id, "choose": req.choose})
    return {"ok": True}
