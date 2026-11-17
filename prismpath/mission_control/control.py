# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Control router — start/stop the sprint and resolve human-in-the-loop decisions.

Every route here changes something, so every one carries the `write` capability and none is mounted in
the read only posture. A project named by a request (select, start) must be one the console may follow
(`core.confine_project`), and a route that acts on the followed project captures it once.

Every route is the operating interface's, so its audit actor is `console/operating/<session fp>`, and
each records its intent before it acts and its result after (`audit.audited`)."""
from fastapi import APIRouter, HTTPException, Request

from . import core
from .models import QueueDecideReq, QueueEventReq, SprintSelectReq, SprintStartReq
from .posture import WRITE

router = APIRouter(tags=["control"])


@router.post("/sprint/start", openapi_extra=WRITE)
def sprint_start(req: SprintStartReq, request: Request):
    """Start the sprint loop in the followed project, refused when the sprint flow is not authorized."""
    # exclude_none so run_sprint's own defaults apply to fields the caller didn't set
    cfg = req.model_dump(exclude_none=True)
    if cfg.get("proj"):
        cfg["proj"] = core.confine_project(cfg["proj"], core.current_project())   # ValueError -> 400
    return core.start_sprint(cfg, core.STATE, _actor(request))


@router.post("/sprint/select", openapi_extra=WRITE)
def sprint_select(req: SprintSelectReq, request: Request):
    """Pin the console to a chosen sprint dir (stop auto-following the live one). Only a discovered
    sprint, the launch project or a directory under an evidence root can be chosen."""
    current = core.current_project()
    proj = core.confine_project(req.proj, current)                             # ValueError -> 400
    with core.audit.audited("sprint.select", {"proj": proj, "from": current}, _actor(request)):
        core.select_project(proj, pinned=True)
    return {"ok": True, "proj": proj, "pinned": True}


@router.post("/sprint/auto", openapi_extra=WRITE)
def sprint_auto(request: Request):
    """Resume auto-following whichever sprint is live."""
    with core.audit.audited("sprint.auto", {"from": core.current_project()}, _actor(request)) as outcome:
        with core.STATE_LOCK:
            core.STATE["pinned"] = False
        core.follow_active_sprint(core.STATE)
        outcome["detail"] = {"proj": core.current_project()}
    return {"ok": True, "proj": core.current_project(), "pinned": False}


@router.post("/sprint/stop", openapi_extra=WRITE)
def sprint_stop(request: Request):
    """Ask the followed sprint to stop, by leaving a STOP marker in its directory."""
    return core.touch_marker(core.current_project(), "STOP", "sprint.stop", _actor(request))


@router.post("/sprint/pause", openapi_extra=WRITE)
def sprint_pause(request: Request):
    """Ask the followed sprint to pause, by leaving a PAUSE marker in its directory."""
    return core.touch_marker(core.current_project(), "PAUSE", "sprint.pause", _actor(request))


@router.post("/sprint/resume", openapi_extra=WRITE)
def sprint_resume(request: Request):
    """Remove the PAUSE marker so the followed sprint carries on."""
    return core.remove_marker(core.current_project(), "PAUSE", "sprint.resume", _actor(request))


@router.post("/queue/decide", openapi_extra=WRITE)
def queue_decide(req: QueueDecideReq, request: Request):
    """Human picks an edge for a suspended run. `resolve_queue_item` confines the id to the queue dir.
    The checkpoint's `decided_by` is the same actor the audit event names."""
    from prismpath.ledgers import checkpoint as _ckpt
    actor = _actor(request)
    with core.audit.audited("queue.decide", {"id": req.id, "choose": req.choose}, actor):
        try:
            cpath = _ckpt.resolve_queue_item(req.id)
            _ckpt.record_decision(cpath, req.choose, decided_by=actor)
        except _ckpt.CheckpointError as refusal:     # an unknown queue item or an edge it does not offer: the caller's mistake
            raise HTTPException(status_code=400, detail=str(refusal))
    return {"ok": True}


@router.post("/queue/event", openapi_extra=WRITE)
def queue_event(req: QueueEventReq, request: Request):
    """Record the event to deliver to a run suspended `waiting` (a `stand_down`, or the timeout), the way
    a decision is recorded, applied by the run's next resume, so the console never needs the flow's
    worker. The checkpoint's `decided_by` is the same actor the audit event names."""
    from prismpath.ledgers import checkpoint as _ckpt
    actor = _actor(request)
    with core.audit.audited("queue.event", {"id": req.id, "event": req.event}, actor):
        try:
            cpath = _ckpt.resolve_queue_item(req.id)
            _ckpt.record_event(cpath, req.event, decided_by=actor)
        except _ckpt.CheckpointError as refusal:     # an unknown item, a run not waiting, an event it does not await
            raise HTTPException(status_code=400, detail=str(refusal))
    return {"ok": True, "id": req.id, "event": req.event}


def _actor(request: Request) -> str:
    return core.audit.actor(request, "operating")
