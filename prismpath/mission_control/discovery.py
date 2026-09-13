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


def _registry_projects():
    """The project directories sprints have self-announced into the registry file."""
    try:
        with open(SETTINGS.registry, encoding="utf-8") as registry_file:
            registry = json.load(registry_file)
        return list(registry.keys()) if isinstance(registry, dict) else list(registry)
    except Exception:
        return []


def discover_sprints():
    """Every sprint on the box, found by its status.json heartbeat: scan globs + the registry (sprints
    self-announce on start) + the launch default. Freshest still-heartbeating one is 'active' - this is
    what lets MC follow a sprint started ANYWHERE without a restart."""
    projs = set()
    for pat in SETTINGS.scan.split(os.pathsep):
        for sp in glob.glob(pat):
            projs.add(os.path.dirname(os.path.abspath(sp)))
    for proj_dir in _registry_projects():
        projs.add(os.path.abspath(os.path.expanduser(proj_dir)))
    projs.add(os.path.abspath(SETTINGS.proj))
    now, out = time.time(), []
    for proj_dir in projs:
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
    """Point state at the active sprint unless one is pinned. Called from the most-frequent poll so
    every view follows the live sprint within a tick."""
    if state.get("pinned"):
        return
    found = discover_sprints()
    if found:
        state["proj"] = found[0]["proj"]
