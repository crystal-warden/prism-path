# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Starting, stopping and detecting a sprint: the console's only subprocess surface.

A run is either one we launched (we hold the process) or one somebody else started, which we detect
by its still-fresh status.json heartbeat. Stop and pause are marker files the sprint itself polls,
so they work for both kinds of run.

Each effect here is recorded before it happens and its result after (`audit.audited`): the start's
configuration before the process is spawned, its pid after; a marker's intent before the file is
dropped. A refusal has no effect and is one event. `actor` is the request's `console/<interface>/<fp>`.
"""
import json
import os
import subprocess
import sys
import time

from . import audit
from .config import SETTINGS
from .state import LAUNCH_LOCK, STATE_LOCK


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


def flow_refusal():
    """Why a sprint that runs `flows/sprint_loop.md` (SPRINT_FLOW=1) may not start, or None. The loop
    checks the flow itself when it loads it (`ledger_runner.run_ledgered_loop`); asking here as well means
    the console answers the request, and records the refusal, instead of leaving a traceback in the
    sprint's log. Honours PRISMPATH_REQUIRE_AUTHORIZATION and PRISMPATH_AUTHORITY_PUB; a sprint that does
    not run the flow, or authorization that is not required, is not refused."""
    if os.environ.get("SPRINT_FLOW", "0") != "1":
        return None
    from prismpath.hotswap import flow_authority
    from prismpath.orchestration.sprint_flow import DEFAULT_FLOW
    try:
        flow_authority.authorize_flow(DEFAULT_FLOW)
    except flow_authority.FlowNotAuthorized as refused:
        return {"ok": False, "error": f"refused: the sprint flow is not authorized: {', '.join(refused.causes)}",
                "refused": refused.causes, "flow": DEFAULT_FLOW}
    except flow_authority.AuthorizationConfigError as unconfigured:
        return {"ok": False, "error": f"refused: {unconfigured}", "refused": [], "flow": DEFAULT_FLOW}
    return None


def start_sprint(cfg, state, actor):
    """Launch a sprint, recording the intent (project, configuration) before the process is spawned and
    the pid after. `cfg['unbuffered']` (default True) governs whether the child streams live
    (`python -u` / PYTHONUNBUFFERED) or batches: the buffered/unbuffered console toggle."""
    with LAUNCH_LOCK:
        with STATE_LOCK:
            seen = dict(state)                         # one view of the state for the whole launch
        if sprint_running(seen):
            return {"ok": False, "error": "a sprint is already running"}
        refusal = flow_refusal()
        if refusal is not None:
            audit.record("sprint.refused", {"proj": cfg.get("proj") or seen["proj"], "reasons": refusal["refused"],
                                            "flow": refusal["flow"]}, actor)
            return refusal
        proj = os.path.abspath(cfg.get("proj") or seen["proj"])
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
        # The sprint is the installed module, run by the interpreter the console itself runs under,
        # with the selected project as its working directory. A bare "python" and a repo relative
        # script path only worked from a source checkout.
        argv = [sys.executable] + (["-u"] if unbuffered else []) + ["-m", "prismpath.orchestration.run_sprint"]
        cfg = dict(cfg, unbuffered=unbuffered)
        with audit.audited("sprint.start", {"proj": proj, "cfg": cfg, "argv": argv[1:]}, actor) as outcome:
            for marker_name in ("STOP", "PAUSE"):
                try:
                    os.remove(os.path.join(proj, marker_name))
                except OSError:
                    pass
            # the child gets its own descriptor at spawn, so the parent closes its copy here rather
            # than leaking one handle per start_sprint
            with open(os.path.join(proj, "mc_sprint.log"), "a") as log:
                proc = subprocess.Popen(argv, cwd=proj, env=env, stdout=log, stderr=subprocess.STDOUT)
            outcome["detail"] = {"pid": proc.pid}
            with STATE_LOCK:
                state.update({"proc": proc, "proj": proj, "cfg": cfg, "pinned": True})   # follow the one we started
    return {"ok": True, "pid": proc.pid, "proj": proj, "unbuffered": unbuffered}


def touch_marker(proj, name, action, actor):
    """Drop a STOP or PAUSE marker the running sprint polls for, recording who asked before it is dropped."""
    with audit.audited(action, {"proj": proj, "marker": name}, actor):
        open(os.path.join(proj, name), "w").close()
    return {"ok": True}


def remove_marker(proj, name, action, actor):
    """Remove a marker (PAUSE, to resume), recording who asked before it is removed and whether one was there."""
    with audit.audited(action, {"proj": proj, "marker": name}, actor) as outcome:
        try:
            os.remove(os.path.join(proj, name))
            outcome["detail"] = {"removed": True}
        except FileNotFoundError:
            outcome["detail"] = {"removed": False}
    return {"ok": True}
