# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The single operator's live state: which sprint the console follows, and the locks that serialize writes.

`STATE` is shared by every request thread and by the event stream, so it is read and written only under
`STATE_LOCK`. A request captures the followed project once, with `snapshot()` or `current_project()`,
and resolves every path of that request against the captured value, so a project selected by another
request (or followed by the event stream) mid request cannot split one answer across two projects.
"""
import threading

from .config import SETTINGS

# One operator, one followed-sprint state. `proc` is the sprint we launched (if any); `proj` is the
# directory we observe; `pinned` freezes auto-follow to a chosen sprint.
STATE = {"proc": None, "proj": SETTINGS.proj, "cfg": {}, "pinned": False}

STATE_LOCK = threading.RLock()       # guards every read and write of STATE
LAUNCH_LOCK = threading.Lock()       # guards launch (one sprint at a time)
FILE_LOCK = threading.Lock()         # serializes flow-file writes


def snapshot() -> dict:
    """A consistent copy of STATE for one request. The copy is shallow: `cfg` is replaced, never
    mutated in place, by the code that changes it."""
    with STATE_LOCK:
        return dict(STATE)


def current_project() -> str:
    """The followed project, captured once."""
    with STATE_LOCK:
        return STATE["proj"]


def select_project(proj: str, pinned: bool) -> dict:
    """Point the console at `proj` (already confined by the caller) and return the new snapshot."""
    with STATE_LOCK:
        STATE["proj"] = proj
        STATE["pinned"] = pinned
        return dict(STATE)
