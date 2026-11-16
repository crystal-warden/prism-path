# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Finding the sprints on this box, and following the live one.

A sprint announces itself by writing a `status.json` heartbeat. This is what lets Mission Control
follow a sprint started anywhere (control tab, CLI, by hand) without a restart.
"""
import glob
import json
import os
import time

from .config import SETTINGS
from .files import is_contained
from .state import STATE_LOCK


def _registry_projects():
    """The project directories sprints have self-announced into the registry file."""
    try:
        with open(SETTINGS.registry, encoding="utf-8") as registry_file:
            registry = json.load(registry_file)
        return list(registry.keys()) if isinstance(registry, dict) else list(registry)
    except Exception:
        return []


def candidate_projects():
    """The project directories the console knows of: the scan globs' matches, the registry's entries
    and the launch project. Discovery reads heartbeats from these, and only these can be selected
    (besides directories under an evidence root)."""
    projs = set()
    for pat in SETTINGS.scan.split(os.pathsep):
        if not pat:
            continue
        for sp in glob.glob(pat):
            projs.add(os.path.dirname(os.path.abspath(sp)))
    for proj_dir in _registry_projects():
        if isinstance(proj_dir, str) and proj_dir:
            projs.add(os.path.abspath(os.path.expanduser(proj_dir)))
    projs.add(os.path.abspath(SETTINGS.proj))
    return projs


def confine_project(proj, followed=None):
    """The absolute path of `proj` if the console may follow it, else ValueError (a 400).

    A project is followable when it is a discovered sprint, the launch project, the project followed
    now, or a directory under one of the evidence roots the launch named; and when the console's own
    audit log and statements are not inside it, since a project is a place the edit route writes."""
    from . import audit
    if not isinstance(proj, str) or not proj.strip():
        raise ValueError("refused: no project named")
    candidate = os.path.abspath(os.path.expanduser(proj))
    real = os.path.realpath(candidate)
    known = {os.path.realpath(path) for path in candidate_projects()}
    if followed:
        known.add(os.path.realpath(followed))
    under_root = any(is_contained(candidate, root) for root in SETTINGS.evidence_roots)
    if real not in known and not under_root:
        raise ValueError("refused: the project is not a discovered sprint and not under an evidence root")
    from .session import token_file_path
    own_files = (audit.LOG.path, getattr(audit.LOG, "statements_path", None),
                 token_file_path(SETTINGS.state_dir, SETTINGS.port))
    for own in own_files:
        if own and is_contained(own, candidate):
            raise ValueError("refused: the project holds the console's own audit log")
    return candidate


def discover_sprints():
    """Every sprint on the box, found by its status.json heartbeat: scan globs + the registry (sprints
    self-announce on start) + the launch default. Freshest still-heartbeating one is 'active' - this is
    what lets MC follow a sprint started ANYWHERE without a restart."""
    now, out = time.time(), []
    for proj_dir in candidate_projects():
        sp = os.path.join(proj_dir, "status.json")
        try:
            age = now - os.path.getmtime(sp)
            status_json = json.load(open(sp, encoding="utf-8"))
        except Exception:
            continue
        out.append({"proj": proj_dir, "name": os.path.basename(proj_dir), "age": round(age, 1),
                    "running": age < SETTINGS.heartbeat_stale_s and not status_json.get("done"),
                    "iteration": status_json.get("iteration"), "valid": status_json.get("valid"), "done": status_json.get("done")})
    out.sort(key=lambda sprint_row: (not sprint_row["running"],
                                     sprint_row["age"]))   # running first, then freshest
    return out


def follow_active_sprint(state):
    """Point state at the active sprint unless one is pinned. Called from the event stream's loop (and
    by `/sprint/auto`), never from a read, so a request never moves the project another request is
    reading. Discovery reads the disk outside the lock; the move is made under it, and only if nobody
    pinned a project meanwhile."""
    with STATE_LOCK:
        if state.get("pinned"):
            return
    found = discover_sprints()
    if found:
        with STATE_LOCK:
            if not state.get("pinned"):
                state["proj"] = found[0]["proj"]
