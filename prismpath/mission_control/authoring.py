# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Authoring router: the process owner's scaffold (A6) and change status (A5).

`/author/templates` lists the templates `prismpath init` ships, the generic starter and every gallery
entry. `/author/scaffold` writes one of them into the followed project, as `prismpath init` does: the
starter as `<name>.md` beside `<name>.tests.md`, a gallery template as its own files, names kept, in a new
directory `<name>/` (a template's flows name each other, a fan-out its child, so the names stay). The
scaffold is the authoring interface's audit event `author.scaffold`, written before any file, naming every
file and the sha256 of the text it will hold, with `author.scaffold.result` after; it never writes over a
file, and a refusal is one `author.scaffold.refused` event.

`/author/status` reads and never writes. For a flow it reports the sha256 of the text, whether a flow
manifest beside it is signed by a pinned authority key and names that hash (`evidence.manifest_status`:
signed, stale, invalid, unsigned or unchecked), and, given a policy host state directory under the followed
project or an evidence root, what that deployment is running: the active image, whether the pack it came
from records this text's sha256, and whether the last attestation names the active image.

Authoring changes reach a running policy only through the signed path (plan section 3.4). The console never
signs, packs, swaps or attests, and holds no authority key: the status names the commands of that path, to
be run off the console by the people who hold the keys. Pinned authority keys are named as public key
FILES under the project or the evidence roots, never sent as key material.
"""
import os
import re
import shlex
import tempfile
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import core, evidence, policy
from .edit import _sha256_of_file
from .files import file_kind
from .posture import WRITE

router = APIRouter(prefix="/author", tags=["authoring"])

STARTER = "starter"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
STATUS_OF = {"outside-roots": 403, "not-found": 404, "too-large": 413}
NO_SIGNING = ("the console never signs, packs, swaps or attests: run these off the console, the authority "
              "key's holder signing and packing, the operator swapping and attesting")


class ScaffoldReq(BaseModel):
    name: str = Field(..., description="A plain name: the starter's flow is <name>.md, a gallery template "
                                       "goes into the directory <name>/.")
    template: str = Field(STARTER, description="`starter`, or a gallery template from /author/templates.")


class StatusReq(BaseModel):
    flow_md: str = Field(..., description="The flow, relative to the followed project.")
    pins: List[str] = Field(default_factory=list, description="Authority public key FILES under the followed "
                                                              "project or an evidence root.")
    state_dir: Optional[str] = Field(None, description="A policy host state directory under the followed "
                                                       "project or an evidence root.")


# --------------------------------------------------------------------------- templates
def _gallery() -> Dict[str, str]:
    from prismpath import cli
    return cli._gallery_templates()


def _template_parts(template_dir: str) -> List[str]:
    """The files `prismpath init --template` copies: every Markdown file of the entry but its README."""
    return sorted(item for item in os.listdir(template_dir) if item.endswith(".md") and item != "README.md")


def _about(template_dir: str) -> str:
    readme = os.path.join(template_dir, "README.md")
    if not os.path.isfile(readme):
        return ""
    with open(readme, encoding="utf-8") as handle:
        lines = [line.strip() for line in handle if line.strip() and not line.startswith("#")]
    return lines[0][:160] if lines else ""


@router.get("/templates")
def templates():
    """The templates a scaffold writes, each with the files it creates (`<name>` is the scaffold's name)."""
    listed = [{"name": STARTER, "files": ["<name>.md", "<name>.tests.md"], "flow": "<name>.md",
               "about": "a triage flow with deterministic `when` edges and semantic edges, and its routing tests"}]
    for name, template_dir in _gallery().items():
        listed.append({"name": name, "files": [f"<name>/{part}" for part in _template_parts(template_dir)],
                       "flow": f"<name>/{name}.md", "about": _about(template_dir)})
    return {"templates": listed}


def _planned(name: str, template: str) -> List[Dict[str, str]]:
    """[{path, text}] the scaffold writes, project relative, in order: the flow first."""
    from prismpath import cli
    if template == STARTER:
        return [{"path": f"{name}.md", "text": cli.STARTER_FLOW},
                {"path": f"{name}.tests.md", "text": cli.STARTER_TESTS}]
    gallery = _gallery()
    if template not in gallery:
        raise HTTPException(404, f"no template {template!r}; /author/templates lists them")
    template_dir = gallery[template]
    parts = _template_parts(template_dir)
    parts.sort(key=lambda part: part != f"{template}.md")
    planned = []
    for part in parts:
        with open(os.path.join(template_dir, part), encoding="utf-8") as handle:
            planned.append({"path": f"{name}/{part}", "text": handle.read()})
    return planned


@router.post("/scaffold", openapi_extra=WRITE)
def scaffold(req: ScaffoldReq, request: Request):
    """A new flow from a template, as `prismpath init` writes it, recorded before any file is written."""
    if not NAME.fullmatch(req.name or ""):
        raise HTTPException(400, "a scaffold name is a plain name: letters, digits, `_` and `-`, at most 64, "
                                 "starting with a letter or digit")
    actor = core.audit.actor(request, "authoring")
    proj = core.current_project()                             # one project for the whole request
    planned = _planned(req.name, req.template)
    for item in planned:
        item["real"] = core.safe_path(proj, item["path"])
        item["sha256"] = _sha256_of_text(item["text"])
    files = [{"path": item["path"], "sha256": item["sha256"]} for item in planned]
    with core.FILE_LOCK:
        present = [item["path"] for item in planned if os.path.lexists(item["real"])]
        if present:
            core.audit.record("author.scaffold.refused", {"template": req.template, "name": req.name,
                                                          "reason": "exists", "present": present}, actor)
            raise HTTPException(409, f"refused: {', '.join(present)} already exists; a scaffold never writes "
                                     "over a file, so pick another name")
        directory = None if req.template == STARTER else core.safe_path(proj, req.name)
        if directory is not None and os.path.lexists(directory) and not os.path.isdir(directory):
            core.audit.record("author.scaffold.refused", {"template": req.template, "name": req.name,
                                                          "reason": "exists", "present": [req.name]}, actor)
            raise HTTPException(409, f"refused: {req.name} already exists and is not a directory")
        intent = {"template": req.template, "name": req.name, "files": files}
        try:
            with core.audit.audited("author.scaffold", intent, actor) as outcome:
                _write_all(planned, directory)
                outcome["detail"] = {"files": [{"path": item["path"], "sha256": _sha256_of_file(item["real"])}
                                               for item in planned]}
        except FileExistsError as raced:            # another writer created a file after the check
            raise HTTPException(409, f"refused: {os.path.basename(str(raced.filename or ''))} appeared while the "
                                     "scaffold wrote; nothing it wrote was kept") from None
    return {"ok": True, "template": req.template, "files": [item["path"] for item in planned],
            "flow": planned[0]["path"]}


def _sha256_of_text(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _create_atomically(resolved: str, text: str) -> None:
    """Write a new file whole or not at all, and never over a file: the text goes to a temporary file in the
    same directory, which is then linked to its name, a link that fails when the name exists."""
    handle_fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(resolved), prefix=".mc-write-", suffix=".tmp")
    try:
        with os.fdopen(handle_fd, "wb") as handle:
            handle.write(text.encode("utf-8"))
        os.chmod(tmp_path, 0o644)
        try:
            os.link(tmp_path, resolved)
        except FileExistsError:
            raise FileExistsError(17, "exists", resolved) from None
        except OSError:                                      # a filesystem without hard links
            if os.path.lexists(resolved):
                raise FileExistsError(17, "exists", resolved) from None
            os.replace(tmp_path, resolved)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _write_all(planned, directory) -> None:
    """Write every planned file, or none: a failure part way removes what this scaffold wrote."""
    made_directory = False
    written = []
    try:
        if directory is not None and not os.path.isdir(directory):
            os.mkdir(directory, 0o755)
            made_directory = True
        for item in planned:
            _create_atomically(item["real"], item["text"])
            written.append(item["real"])
    except BaseException:
        for path in written:
            try:
                os.unlink(path)
            except OSError:
                pass
        if made_directory:
            try:
                os.rmdir(directory)
            except OSError:
                pass
        raise


# --------------------------------------------------------------------------- change status
def _refusal(refused: evidence.EvidenceRefused) -> JSONResponse:
    status = STATUS_OF.get(refused.reason, 400)
    return JSONResponse(status_code=status, content={"error": {"code": status, "message": str(refused),
                                                               "reason": refused.reason}})


def _q(path: str) -> str:
    return shlex.quote(path)


def _bounded_document(path: str, roots) -> Optional[dict]:
    """A canonical JSON document under the roots, read within the file bound, or None when it is not there
    or does not parse. Read for display only; a verdict on it comes from its own verifier."""
    from prismpath import canon
    try:
        real, _root = evidence._confine(path, roots)
        data = evidence._read_bounded(real, core.SETTINGS.max_file_bytes, "the document")
        document = canon.loads_document(data.decode("utf-8"))
    except (evidence.EvidenceRefused, UnicodeDecodeError, ValueError):
        return None
    if isinstance(document, dict):
        document.pop(canon.ENCODING_KEY, None)
        return document
    return None


def _confined_state_dir(state_dir: str, roots) -> str:
    real, _root = evidence._confine(state_dir, roots)
    if not os.path.isdir(real):
        raise evidence.EvidenceRefused("not-found", "no state directory there")
    # The report opens the state directory's files by name, so a link in it that leads out of the roots
    # would be followed; such a directory is refused whole.
    real_roots = evidence._roots(roots)
    with os.scandir(real) as entries:
        for entry in entries:
            if entry.is_symlink() and not any(core.is_contained(os.path.realpath(entry.path), allowed)
                                              for allowed in real_roots):
                raise evidence.EvidenceRefused("outside-roots", "refused: the state directory links outside "
                                                                "the roots")
    return real


def _deployment(state_dir: str, roots, pins: List[str], flow_sha: str) -> Dict[str, Any]:
    """What the deployment whose policy host state directory is `state_dir` runs, against this flow text."""
    real = _confined_state_dir(state_dir, roots)
    report = policy.active_report(real, state_dir, 10 ** 9)          # the whole history, bounded by its file size
    active = report.get("active")
    attestations = [event for event in report.get("history") or [] if event.get("action") == "attestation"]
    attestation = None
    if attestations:
        last = attestations[-1]
        data = last.get("data") or {}
        attestation = {"idx": last.get("idx"), "ts": data.get("ts") or last.get("ts"), "active": data.get("active"),
                       "version": data.get("version"), "names_active": bool(active) and data.get("active") == active}
    record = _bounded_document(os.path.join(real, "active_policy.json"), roots) or {}
    pack = None
    ppt_path = record.get("ppt_path")
    if active and isinstance(ppt_path, str):
        try:
            pack = evidence.pack_report(ppt_path, pins or None, roots)
        except evidence.EvidenceRefused as refused:
            pack = {"ppt": ppt_path, "status": refused.reason, "message": str(refused), "manifest": None}
        manifest = pack.get("manifest")
        checked = isinstance(manifest, dict)
        if not checked and pack.get("status") == "unchecked":
            from prismpath.hotswap import policy_pack
            manifest = (policy_pack.read_sealed_manifest(ppt_path) if os.path.exists(ppt_path + policy_pack.SEALED)
                        else _bounded_document(ppt_path + ".manifest.json", roots))
        manifest = manifest if isinstance(manifest, dict) else {}
        pack = {"ppt": pack.get("ppt", ppt_path), "status": pack.get("status"), "causes": pack.get("causes", []),
                "key": pack.get("key"), "message": pack.get("message"), "command": pack.get("command"),
                "flow_sha256": manifest.get("flow_sha256"), "flow_sha256_checked": checked and pack.get("status") == "signed",
                "image_sha256": manifest.get("image_sha256"),
                "image_is_active": manifest.get("image_sha256") == active if manifest.get("image_sha256") else None,
                "version": manifest.get("version"), "verdict_of": evidence.VERDICT_OF}
    if not active:
        runs = "nothing-active"
    elif not pack or not pack.get("flow_sha256") or pack.get("image_is_active") is not True:
        runs = "unknown"
    else:
        runs = "this-text" if pack["flow_sha256"] == flow_sha else "other-text"
    pub = " ".join(f"--pub {_q(path)}" for path in pins) or "--pub <authority.pub>"
    return {"state_dir": state_dir, "real": real, "active": active, "version": report.get("version"),
            "since": report.get("since"), "unsigned": report.get("unsigned"), "overlay_of": report.get("overlay_of"),
            "image_ok": report.get("image_ok"), "reason": report.get("reason"), "pending": report.get("pending"),
            "log": report.get("log"), "attestation": attestation, "pack": pack, "runs": runs,
            "verdict_of": evidence.VERDICT_OF,
            "commands": {"swap": f"prismpath swap swap --out {_q(real)} {pub} --envelope <envelope> --ppt <new.ppt>",
                         "attest": f"prismpath swap attest --out {_q(real)} {pub} --envelope <envelope>"}}


@router.post("/status")
def status(req: StatusReq):
    """A flow's change status: its sha256, its flow manifest's verdict under the pinned authority keys, and
    what the named deployment runs. Reads only; prints the commands of the signed path, runs none."""
    proj = core.current_project()                             # one project for the whole request
    real_flow = core.safe_path(proj, req.flow_md)             # ValueError on traversal -> 400 envelope
    if file_kind(req.flow_md) != "flow":
        raise HTTPException(400, "a change status is a flow document's; a fixture or another file has no manifest")
    roots = [proj] + [root for root in core.SETTINGS.evidence_roots if root]
    try:
        evidence.read_pins(req.pins, roots)                   # key files only, never the key itself
        pin_paths = [evidence._confine(path, roots)[0] for path in req.pins]
        manifest = evidence.manifest_status(real_flow, pin_paths or None, roots)
        deployment = (_deployment(req.state_dir, roots, pin_paths, manifest["flow_sha256"])
                      if req.state_dir else None)
    except evidence.EvidenceRefused as refused:
        return _refusal(refused)
    pub = " ".join(f"--pub {_q(path)}" for path in pin_paths) or "--pub <authority.pub>"
    version = (manifest.get("version") or 0) + 1 if isinstance(manifest.get("version"), int) else 1
    commands = {
        "sign": f"prismpath authorize sign {_q(real_flow)} --priv <authority.key> {pub} --version {version}",
        "verify": manifest["command"],
        "pack": (f"prismpath swap pack --ppt <image.ppt> --flow {_q(real_flow)} --version <N> "
                 f"--envelope-id <envelope id> --priv <authority.key> {pub}"),
    }
    return {"flow_md": req.flow_md, "flow": real_flow, "flow_sha256": manifest["flow_sha256"], "manifest": manifest,
            "deployment": deployment, "commands": commands, "writes": False, "note": NO_SIGNING,
            "verdict_of": evidence.VERDICT_OF}
