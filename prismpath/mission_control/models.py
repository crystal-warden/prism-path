# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Request models — the typed half of the API contract (pydantic → OpenAPI schema)."""
from typing import List, Optional

from pydantic import BaseModel, Field


class ProveLevelMReq(BaseModel):
    flow: str = Field(..., description="The flow document (Markdown text) — text-in, never a path.")


class ProveReachReq(BaseModel):
    flow: str = Field(..., description="The flow document (Markdown text).")
    reach: List[str] = Field(default_factory=list, description="Nodes to test for reachability.")
    forbid: List[str] = Field(default_factory=list, description="Nodes asserted unreachable.")
    assume: Optional[str] = Field(None, description="A predicate assumed true (e.g. 'amount <= 500').")


class SprintStartReq(BaseModel):
    """All optional; unset fields fall back to run_sprint's own defaults. `unbuffered` (default True)
    is the buffered/unbuffered console toggle."""
    proj: Optional[str] = None
    gate: Optional[str] = None
    arch: Optional[str] = None
    agent: Optional[str] = None
    exec: Optional[str] = None
    rag: Optional[bool] = None
    lessons: Optional[bool] = None
    fresh: Optional[bool] = None
    seconds: Optional[int] = None
    max_iters: Optional[int] = None
    model: Optional[str] = None
    nudge_file: Optional[str] = None
    unbuffered: Optional[bool] = None


class SprintSelectReq(BaseModel):
    proj: str = Field(..., description="Sprint directory to pin the console to.")


class FileWriteReq(BaseModel):
    path: str = Field(..., description="Project-relative path (contained; traversal rejected).")
    content: str


class QueueDecideReq(BaseModel):
    id: str = Field(..., description="Suspended-run checkpoint id (confined to the queue dir).")
    choose: str = Field(..., description="The edge/decision the human picks.")
