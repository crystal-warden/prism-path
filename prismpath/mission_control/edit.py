"""Edit router — list/read/write flow files, the only write surface, path-contained and fail-closed."""
import os

from fastapi import APIRouter, Query

from . import core
from .models import FileWriteReq

router = APIRouter(tags=["edit"])


@router.get("/files")
def list_files():
    return {"proj": os.path.basename(core.STATE["proj"]), "dir": core.STATE["proj"],
            "files": core.file_tree(core.STATE["proj"])}


@router.get("/file")
def read_file(path: str = Query(...)):
    fp = core._safe(core.STATE["proj"], path)      # ValueError on traversal -> 400 envelope
    fst = os.stat(fp)
    return {"path": path, "content": open(fp, errors="ignore").read(),
            "mtime": fst.st_mtime, "size": fst.st_size}


@router.post("/file")
def write_file(req: FileWriteReq):
    p = core._safe(core.STATE["proj"], req.path)   # ValueError on traversal -> 400 envelope
    with core._FILE_LOCK:
        open(p, "w", encoding="utf-8").write(req.content)
    core.AUDIT.append(core.ACTOR, "file.edit", {"path": req.path, "bytes": len(req.content)})
    return {"ok": True, "mtime": os.stat(p).st_mtime}
