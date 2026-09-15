# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The status summary: one dict describing the followed run, which every view and the SSE stream poll."""
import json
import os

from . import audit
from .discovery import discover_sprints, follow_active_sprint
from .launch import sprint_running


def status(state):
    """The followed sprint's heartbeat, folded together with what the console knows about it."""
    follow_active_sprint(state)                       # auto-follow the live sprint (unless pinned)
    st = {}
    sp = os.path.join(state["proj"], "status.json")
    if os.path.isfile(sp):
        try:
            st = json.load(open(sp))
        except Exception:
            st = {}
    return {"running": sprint_running(state),
            "paused": os.path.isfile(os.path.join(state["proj"], "PAUSE")),
            "proj": os.path.basename(state["proj"]), "dir": state["proj"],
            "pinned": state.get("pinned", False),
            "unbuffered": state["cfg"].get("unbuffered"),     # the run's buffering mode (None if external)
            "sprints": discover_sprints(), "cfg": state["cfg"],
            "iteration": st.get("iteration"), "valid": st.get("valid"),
            "files": len(st.get("files", []) or []), "elapsed_s": st.get("elapsed_s"),
            "help_open": st.get("help_open"), "last_error": (st.get("last_error") or "")[:300],
            "done": st.get("done"), "model": st.get("model"),
            "audit_root": audit.LOG.current_root()[:16], "audit_n": len(audit.LOG.events)}
