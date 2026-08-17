# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Control router — start/stop the sprint and resolve human-in-the-loop decisions."""
import os

from fastapi import APIRouter

from . import core
from .models import QueueDecideReq, SprintSelectReq, SprintStartReq

router = APIRouter(tags=["control"])


@router.post("/sprint/start")
def sprint_start(req: SprintStartReq):
    # exclude_none so run_sprint's own defaults apply to fields the caller didn't set
    return core.start_sprint(req.model_dump(exclude_none=True), core.STATE)


@router.post("/sprint/select")
def sprint_select(req: SprintSelectReq):
    """Pin the console to a chosen sprint dir (stop auto-following the live one)."""
    core.STATE["proj"] = os.path.abspath(req.proj)
    core.STATE["pinned"] = True
    return {"ok": True, "proj": core.STATE["proj"], "pinned": True}


@router.post("/sprint/auto")
def sprint_auto():
    """Resume auto-following whichever sprint is live."""
    core.STATE["pinned"] = False
    core._sync_active(core.STATE)
    return {"ok": True, "proj": core.STATE["proj"], "pinned": False}


@router.post("/sprint/stop")
def sprint_stop():
    return core._touch(core.STATE["proj"], "STOP", "sprint.stop")


@router.post("/sprint/pause")
def sprint_pause():
    return core._touch(core.STATE["proj"], "PAUSE", "sprint.pause")


@router.post("/sprint/resume")
def sprint_resume():
    try:
        os.remove(os.path.join(core.STATE["proj"], "PAUSE"))
    except OSError:
        pass
    core.AUDIT.append(core.ACTOR, "sprint.resume", {"proj": core.STATE["proj"]})
    return {"ok": True}


@router.post("/queue/decide")
def queue_decide(req: QueueDecideReq):
    """Human picks an edge for a suspended run. `resolve_queue_item` confines the id to the queue dir."""
    from prismpath import checkpoint as _ckpt
    cpath = _ckpt.resolve_queue_item(req.id)
    _ckpt.record_decision(cpath, req.choose, decided_by=core.ACTOR)
    core.AUDIT.append(core.ACTOR, "queue.decide", {"id": req.id, "choose": req.choose})
    return {"ok": True}
