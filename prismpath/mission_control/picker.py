# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Picker router: list the project's files by extension so the CLI panels can offer a pick, not a typed
path. The editor's own file list whitelists editable text types; the panels also need the flow, label,
benchmark, pack, and key files, so this is a separate read only listing confined to the active project.
"""
import os

from fastapi import APIRouter

from . import core

router = APIRouter(tags=["pick"])

# the extensions the CLI panels operate on: flows, routing data, packs, and keys
ALLOWED_EXTENSIONS = {"md", "jsonl", "json", "ppt", "pem", "pub", "txt"}
MAX_PICK_ENTRIES = 2000


@router.get("/pick")
def pick(exts: str = "md,jsonl,ppt,json,pem,pub"):
    """Project files whose extension is in `exts` (comma list), relative to the active project."""
    proj = core.STATE["proj"]
    wanted = {e.strip().lower() for e in exts.split(",") if e.strip()} & ALLOWED_EXTENSIONS
    found = []
    for dirpath, dirnames, filenames in os.walk(proj):
        dirnames[:] = [d for d in dirnames if d not in (".git", "tools", "__pycache__", "last-good")]
        for filename in sorted(filenames):
            if filename.startswith("."):
                continue
            extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if extension in wanted:
                found.append(os.path.relpath(os.path.join(dirpath, filename), proj))
            if len(found) >= MAX_PICK_ENTRIES:
                return {"files": sorted(found)}
    return {"files": sorted(found)}
