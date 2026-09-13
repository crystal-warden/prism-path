# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Starting, stopping and detecting a sprint: the console's only subprocess surface.

A run is either one we launched (we hold the process) or one somebody else started, which we detect
by its still-fresh status.json heartbeat. Stop and pause are marker files the sprint itself polls,
so they work for both kinds of run.
"""
import json
import os
import subprocess
import time

from . import audit
from .config import SETTINGS
from .state import LAUNCH_LOCK


def sprint_running(state):
    """True while a sprint is running: ours by its process, anyone's by a fresh heartbeat."""
    proc = state["proc"]
    if proc and proc.poll() is None:
        return True
    # also detect an EXTERNALLY-launched run_sprint via its live status.json heartbeat
    sp = os.path.join(state["proj"], "status.json")
    try:
        st = json.load(open(sp))
        fresh = (time.time() - os.path.getmtime(sp)) < SETTINGS.heartbeat_stale_s
        return bool(fresh and not st.get("done"))
    except Exception:
        return False


def start_sprint(cfg, state):
    """Launch a sprint. `cfg['unbuffered']` (default True) governs whether the child streams live
    (`python -u` / PYTHONUNBUFFERED) or batches: the buffered/unbuffered console toggle."""
    with LAUNCH_LOCK:
        if sprint_running(state):
            return {"ok": False, "error": "a sprint is already running"}
        proj = os.path.abspath(cfg.get("proj") or state["proj"])
        env = dict(os.environ)
        env.update({
            "SPRINT_PROJ": proj, "SPRINT_GATE": cfg.get("gate", "browser"),
            "SPRINT_ARCH": cfg.get("arch", ""),   # empty -> run_sprint resolves it (plugin contract / browser default)
            "SPRINT_AGENT": cfg.get("agent", "swarm"), "SPRINT_EXEC": cfg.get("exec", "cecli"),
            "SPRINT_RAG": "1" if cfg.get("rag", True) else "0",
            "SPRINT_LESSONS": "1" if cfg.get("lessons", True) else "0",
            "SPRINT_FRESH": "1" if cfg.get("fresh", False) else "0",
            "SPRINT_SECONDS": str(int(cfg.get("seconds", 0))),      # 0 = open-ended (converge or STOP)
            "SPRINT_MAX_ITERS": str(int(cfg.get("max_iters", 0))),  # 0 = no cap
        })
        if cfg.get("model"):
            env["LLM_MODEL"] = cfg["model"]
        if cfg.get("nudge_file"):
            env["SPRINT_NUDGE_FILE"] = cfg["nudge_file"]
        unbuffered = bool(cfg.get("unbuffered", True))
        if unbuffered:
            env["PYTHONUNBUFFERED"] = "1"
        else:
            env.pop("PYTHONUNBUFFERED", None)
        argv = ["python"] + (["-u"] if unbuffered else []) + ["prismpath/run_sprint.py"]
        for marker_name in ("STOP", "PAUSE"):
            try:
                os.remove(os.path.join(proj, marker_name))
            except OSError:
                pass
        log = open(os.path.join(proj, "mc_sprint.log"), "a")
        proc = subprocess.Popen(argv, cwd=SETTINGS.repo_root, env=env, stdout=log, stderr=subprocess.STDOUT)
        cfg = dict(cfg, unbuffered=unbuffered)
        state.update({"proc": proc, "proj": proj, "cfg": cfg, "pinned": True})   # follow the one we started
    audit.record("sprint.start", {"proj": proj, "cfg": cfg, "pid": proc.pid, "unbuffered": unbuffered})
    return {"ok": True, "pid": proc.pid, "proj": proj, "unbuffered": unbuffered}


def touch_marker(proj, name, action):
    """Drop a STOP or PAUSE marker the running sprint polls for, and record who asked."""
    open(os.path.join(proj, name), "w").close()
    audit.record(action, {"proj": proj})
    return {"ok": True}
