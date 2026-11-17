# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
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
    """Server sent events: a `status`, `interactions`, `graph` or `feed` ping when what the followed run or the
    collector feed shows has changed."""
    async def gen():
        last_sig = last_ix = last_ckpt = last_feed = None
        feed = getattr(request.app.state, "feed", None)
        beat = 0
        while True:
            if await request.is_disconnected():
                break
            # Following the live sprint happens here, under the state lock, and nowhere a request reads;
            # then one snapshot serves the whole tick. The disk reads run off the event loop.
            await asyncio.to_thread(core.follow_active_sprint, core.STATE)
            seen = core.snapshot()
            st = await asyncio.to_thread(core.status, seen)
            sig = _sig(st)
            if sig != last_sig or beat % 8 == 0:      # on change, plus a ~12s refresh (age/elapsed)
                last_sig = sig
                yield _sse({"type": "status", "status": st})
            proj = seen["proj"]
            ixm = _mtime(os.path.join(proj, "interactions.jsonl"))
            if ixm != last_ix:
                last_ix = ixm
                yield _sse({"type": "interactions"})
            ckm = _mtime(os.path.join(proj, "checkpoint.json"))
            if ckm != last_ckpt:
                last_ckpt = ckm
                yield _sse({"type": "graph"})
            # The collector feed's copy changed: the live screen re-reads /feed/live.
            if feed is not None and feed.version != last_feed:
                last_feed = feed.version
                yield _sse({"type": "feed", "connection": feed.connection})
            beat += 1
            await asyncio.sleep(1.5)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
