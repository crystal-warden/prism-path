# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The collector feed's read routes: the live view (operating) and the kept sessions (auditing).

    GET  /feed/live       the connection, the chain's state, the newest decisions and the enforcer's counters
    GET  /feed/causes     the cause monitor's series over the live feed, by arrival time
    POST /evidence/feed   a kept session under the evidence roots checked again from its bytes

Every route reads, so both postures mount them; in the read only posture no client runs (it would write
the kept evidence), and the live routes say so. The client is `app.state.feed` (`feed_client.FeedClient`,
or None), started and stopped with the app (`lifespan`). Every verdict is the console's over the
collector's unsigned seals (`verdict_of`, `statement`).
"""
from __future__ import annotations

import contextlib
from typing import Optional

from fastapi import APIRouter, FastAPI, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from . import evidence, feed, feed_client
from .auditing import _refusal

router = APIRouter(tags=["operating"])
evidence_router = APIRouter(prefix="/evidence", tags=["auditing"])


def attach(application: FastAPI, settings, read_only: bool) -> None:
    """Give the app its feed client (not started) and the reason when there is none."""
    application.state.feed, application.state.feed_off = None, None
    if read_only:
        application.state.feed_off = "the read-only posture connects to no collector"
        return
    if not settings.collector:
        application.state.feed_off = "no collector is named (MC_COLLECTOR)"
        return
    try:
        application.state.feed = feed_client.FeedClient.from_settings(settings, read_only)
    except feed_client.EndpointRefused as refused:
        application.state.feed_off = f"the collector endpoint is refused: {refused}"


@contextlib.asynccontextmanager
async def lifespan(application: FastAPI):
    client = getattr(application.state, "feed", None)
    if client is not None:
        client.start()
    try:
        yield
    finally:
        if client is not None:
            client.stop()


def _client(request: Request):
    return getattr(request.app.state, "feed", None)


@router.get("/feed/live")
def feed_live(request: Request, limit: int = Query(50, ge=0, le=feed_client.RECENT,
                                                   description="How many of the newest leaf records.")):
    """The live view: the connection, the chain's state (holes, findings, the last seal), the newest
    decisions and receipts, and the collector's last status (enforcer counters, loaded, image index, what
    the feed dropped)."""
    client = _client(request)
    if client is None:
        return feed_client.off_view(getattr(request.app.state, "feed_off", None) or "no feed client")
    return client.live(limit)


@router.get("/feed/causes")
def feed_causes(request: Request,
                bucket_s: int = Query(60, description="The width of one bucket, in seconds of arrival time."),
                last: Optional[int] = Query(None, ge=1, description="Only the latest this many records.")):
    """Counts by cause and by outcome per bucket of arrival time over the live feed, the shape
    `/trail/causes` answers, every cause decoded from the registry."""
    client = _client(request)
    if client is None:
        off = feed_client.off_view(getattr(request.app.state, "feed_off", None) or "no feed client")
        return {"source": "live", "path": "", "connection": "off", "reason": off["reason"], "bucket_s": bucket_s,
                "events": 0, "untimed": 0, "clock": "arrival", "buckets": [], "causes": {},
                "verdict_of": feed.VERDICT_OF}
    try:
        return client.series(bucket_s, last)
    except ValueError as error:
        return JSONResponse(status_code=400, content={"error": {"code": 400, "message": str(error)}})


class FeedReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(..., description="A kept feed session directory under the evidence roots.")
    segment: Optional[int] = Field(None, description="Check one segment alone, from its starting seal.")


@evidence_router.post("/feed")
def evidence_feed(req: FeedReq):
    """A kept collector feed session checked again from its bytes: the chain's status, the holes the
    console's copy has, the findings, and every segment's size and sha256."""
    try:
        return feed.feed_report(req.path, segment=req.segment)
    except evidence.EvidenceRefused as refused:
        return _refusal(refused)
