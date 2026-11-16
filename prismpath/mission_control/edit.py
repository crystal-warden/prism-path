# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Edit router — list/read/write flow files, path-contained and fail-closed.

The authoring interface writes flow documents and their fixture tables and nothing else (`files.file_kind`
and `files.not_editable`): any other path is refused with a 403 and one `file.edit.refused` event, so the
console never writes a flow manifest, a signature, a lockfile or a page of its own.

A save is the authoring interface's audit event `file.edit`, written before the file changes, carrying
the sha256 of the file before and of the text it is about to hold, and the flow's name, so the console's
log says which flow text a sprint ran afterwards. When the event cannot be written the file is left as it
was. The result event after the rename carries the hash of the file as it then is on disk."""
import hashlib
import os
import stat
import tempfile

from fastapi import APIRouter, HTTPException, Query, Request

from . import core, files
from .files import file_kind
from .posture import WRITE
from .models import FileWriteReq

router = APIRouter(tags=["authoring", "edit"])

REFUSALS = {
    "not-editable": "refused: the console edits flow documents (.md) and their fixtures (.tests.md) only",
    "hidden": "refused: the console edits only the flow documents and fixtures the editor lists, "
              "never a hidden file or one under a skipped directory",
}


@router.get("/files")
def list_files():
    proj = core.current_project()                             # one project for the whole request
    return {"proj": os.path.basename(proj), "dir": proj, "files": core.file_tree(proj)}


@router.get("/file")
def read_file(path: str = Query(...)):
    fp = core.safe_path(core.current_project(), path)      # ValueError on traversal -> 400 envelope
    fst = os.stat(fp)
    if fst.st_size > core.SETTINGS.max_file_bytes:
        raise HTTPException(413, f"file exceeds MC_MAX_FILE_BYTES ({core.SETTINGS.max_file_bytes} bytes)")
    with open(fp, errors="ignore") as handle:
        content = handle.read()
    return {"path": path, "content": content, "mtime": fst.st_mtime, "size": fst.st_size}


def _write_atomically(resolved: str, content: str) -> None:
    """Write a temp file in the same directory and rename it over the target.

    The sprint reads these flow files while the console writes them, so a half-written file must
    never be visible: the rename is the only moment the content changes, and it is atomic."""
    handle_fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(resolved), prefix=".mc-write-", suffix=".tmp")
    try:
        with os.fdopen(handle_fd, "wb") as handle:       # the bytes hashed in the audit event, untranslated
            handle.write(content.encode("utf-8"))
        if os.path.exists(resolved):
            os.chmod(tmp_path, stat.S_IMODE(os.stat(resolved).st_mode))   # an edit keeps the file's mode
        else:
            os.chmod(tmp_path, 0o644)                                     # a new file is not owner-only
        os.replace(tmp_path, resolved)
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def _sha256_of_file(path: str):
    """The sha256 of the file's bytes, or None when there is no file yet."""
    try:
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except FileNotFoundError:
        return None


def flow_name(text: str):
    """The `name:` of a flow document's front matter, or None. Read without parsing the flow, since a
    save in progress need not parse."""
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        return None
    for line in lines[1:]:
        if line.strip() == "---":
            return None
        key, _, value = line.partition(":")
        if key.strip() == "name" and value.strip():
            return value.strip()
    return None


@router.post("/file", openapi_extra=WRITE)
def write_file(req: FileWriteReq, request: Request):
    proj = core.current_project()                                 # one project for the whole request
    resolved = core.safe_path(proj, req.path)                     # ValueError on traversal -> 400 envelope
    # The kind is the path asked for and the file it resolves to: a flow named link to a manifest is refused.
    refusal = files.not_editable(req.path) or files.not_editable(os.path.relpath(resolved, os.path.realpath(proj)))
    if refusal is not None:
        core.audit.record("file.edit.refused", {"path": req.path, "kind": file_kind(req.path), "reason": refusal},
                          core.audit.actor(request, "authoring"))
        raise HTTPException(403, REFUSALS[refusal])
    content_bytes = req.content.encode("utf-8")
    if len(content_bytes) > core.SETTINGS.max_file_bytes:
        raise HTTPException(413, f"content exceeds MC_MAX_FILE_BYTES ({core.SETTINGS.max_file_bytes} bytes)")
    with core.FILE_LOCK:                                          # the hash before is the file this write replaces
        intent = {"path": req.path, "kind": file_kind(req.path), "flow": flow_name(req.content),
                  "bytes": len(content_bytes), "sha256_before": _sha256_of_file(resolved),
                  "sha256_after": hashlib.sha256(content_bytes).hexdigest()}
        with core.audit.audited("file.edit", intent, core.audit.actor(request, "authoring")) as outcome:
            _write_atomically(resolved, req.content)
            outcome["detail"] = {"sha256": _sha256_of_file(resolved)}
    return {"ok": True, "mtime": os.stat(resolved).st_mtime}
