"""Events router — Server-Sent Events so the command center is live, not polled.

Watches the followed sprint's artifacts on disk (status heartbeat, interactions lens, checkpoint) and
pushes a small ping when any changes; the client re-fetches the affected view. Mirrors the SSE shape
in orchestrator.py. Loopback, single worker — one operator, one stream.
"""
import asyncio
import json
import os

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from . import core

router = APIRouter(tags=["events"])


def _sse(obj) -> str:
    return "data: " + json.dumps(obj) + "\n\n"


def _sig(st: dict):
    """Stable status signature — excludes time-varying fields (age/elapsed) so we emit on real change."""
    return (st.get("running"), st.get("dir"), st.get("iteration"), st.get("valid"),
            st.get("done"), st.get("help_open"), st.get("paused"), st.get("audit_n"),
            st.get("unbuffered"))


def _mtime(path: str) -> float:
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0


@router.get("/events")
async def events(request: Request):
    async def gen():
        last_sig = last_ix = last_ckpt = None
        beat = 0
        while True:
            if await request.is_disconnected():
                break
            st = core.status(core.STATE)
            sig = _sig(st)
            if sig != last_sig or beat % 8 == 0:      # on change, plus a ~12s refresh (age/elapsed)
                last_sig = sig
                yield _sse({"type": "status", "status": st})
            proj = core.STATE["proj"]
            ixm = _mtime(os.path.join(proj, "interactions.jsonl"))
            if ixm != last_ix:
                last_ix = ixm
                yield _sse({"type": "interactions"})
            ckm = _mtime(os.path.join(proj, "checkpoint.json"))
            if ckm != last_ckpt:
                last_ckpt = ckm
                yield _sse({"type": "graph"})
            beat += 1
            await asyncio.sleep(1.5)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
