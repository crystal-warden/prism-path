# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Edit router — list/read/write flow files, the only write surface, path-contained and fail-closed."""
import os

from fastapi import APIRouter, HTTPException, Query

from . import core
from .models import FileWriteReq

router = APIRouter(tags=["edit"])


@router.get("/files")
def list_files():
    return {"proj": os.path.basename(core.STATE["proj"]), "dir": core.STATE["proj"],
            "files": core.file_tree(core.STATE["proj"])}


@router.get("/file")
def read_file(path: str = Query(...)):
    fp = core.safe_path(core.STATE["proj"], path)      # ValueError on traversal -> 400 envelope
    fst = os.stat(fp)
    if fst.st_size > core.SETTINGS.max_file_bytes:
        raise HTTPException(413, f"file exceeds MC_MAX_FILE_BYTES ({core.SETTINGS.max_file_bytes} bytes)")
    return {"path": path, "content": open(fp, errors="ignore").read(),
            "mtime": fst.st_mtime, "size": fst.st_size}


@router.post("/file")
def write_file(req: FileWriteReq):
    resolved = core.safe_path(core.STATE["proj"], req.path)   # ValueError on traversal -> 400 envelope
    if len(req.content.encode("utf-8")) > core.SETTINGS.max_file_bytes:
        raise HTTPException(413, f"content exceeds MC_MAX_FILE_BYTES ({core.SETTINGS.max_file_bytes} bytes)")
    with core.FILE_LOCK:
        open(resolved, "w", encoding="utf-8").write(req.content)
    core.audit.record("file.edit", {"path": req.path, "bytes": len(req.content)})
    return {"ok": True, "mtime": os.stat(resolved).st_mtime}
