# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Edit router — list/read/write flow files, the only write surface, path-contained and fail-closed."""
import os
import stat
import tempfile

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


def _write_atomically(resolved: str, content: str) -> None:
    """Write a temp file in the same directory and rename it over the target.

    The sprint reads these flow files while the console writes them, so a half-written file must
    never be visible: the rename is the only moment the content changes, and it is atomic."""
    handle_fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(resolved), prefix=".mc-write-", suffix=".tmp")
    try:
        with os.fdopen(handle_fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        if os.path.exists(resolved):
            os.chmod(tmp_path, stat.S_IMODE(os.stat(resolved).st_mode))   # an edit keeps the file's mode
        else:
            os.chmod(tmp_path, 0o644)                                     # a new file is not owner-only
        os.replace(tmp_path, resolved)
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


@router.post("/file")
def write_file(req: FileWriteReq):
    resolved = core.safe_path(core.STATE["proj"], req.path)   # ValueError on traversal -> 400 envelope
    if len(req.content.encode("utf-8")) > core.SETTINGS.max_file_bytes:
        raise HTTPException(413, f"content exceeds MC_MAX_FILE_BYTES ({core.SETTINGS.max_file_bytes} bytes)")
    with core.FILE_LOCK:
        _write_atomically(resolved, req.content)
    core.audit.record("file.edit", {"path": req.path, "bytes": len(req.content)})
    return {"ok": True, "mtime": os.stat(resolved).st_mtime}
