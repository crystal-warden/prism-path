# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Auditing router: the assessor's read routes over the evidence readers (U1, U2, U4, U5, U6, U7).

    GET  /evidence/logs      every audit log and evidence run under the roots, and the console's own log
    POST /evidence/trail     one trail: by action, outcome and cause, its root, its statement chain status
    POST /evidence/receipt   one receipt: decoded, its leaf, inclusion path, covering statement and bundle
    POST /evidence/raw       lines of a file under the roots as the bytes written (base64 beside the text)
    POST /evidence/run       an evidence run (core_evidence layout) verified
    POST /evidence/manifest  change control: is this flow authorized, and does a receipt name its text
    POST /evidence/pack      a signed policy pack verified
    POST /evidence/anchor    an anchored record verified (OpenTimestamps or RFC 3161)
    GET  /evidence/causes    the cause registry, for the page's decoder

Every route reads, so the read only posture mounts all of them and the auditing interface is whole there.
Paths are confined to the evidence roots the launch named (`MC_EVIDENCE`); the console's own log is named
with `console: true` rather than by a path, and that flag reaches the log and its statements file only.

Every verdict here is the console's (`verdict_of: "console"`), unpinned by default (`signed-unpinned`).
A pinned check on the server is possible only by naming public key FILES under the evidence roots, and it
is still the console's verdict. Key material is never accepted in a request body: every model forbids
fields it does not name, and a pin that is the hex of a key is refused. The assessor's own pinned keys
stay in the browser, and the independent check is the page's (WP5) or the command each report prints.

A refusal (`evidence.EvidenceRefused`) answers in the console's error envelope with its `reason`:
`outside-roots` 403, `not-found` 404, `too-large` 413, and 400 for the rest. Evidence that reads and does
not verify is a 200 report whose status is `invalid`.
"""
import base64
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from prismpath.ledgers import root_statement

from . import causes_view, core, evidence

router = APIRouter(prefix="/evidence", tags=["auditing"])

STATUS_OF = {"outside-roots": 403, "not-found": 404, "too-large": 413,
             "secret-kind": 403, "console-state": 403, "secret-content": 403}


class _Body(BaseModel):
    # A field the route does not name is refused (422), so a page cannot post a key it pinned.
    model_config = ConfigDict(extra="forbid")


class _LogBody(_Body):
    path: Optional[str] = Field(None, description="An audit log under the evidence roots (absolute, or relative to a root).")
    console: bool = Field(False, description="Read the console's own audit log instead of a path.")


class TrailReq(_LogBody):
    since: Optional[str] = Field(None, description="ISO 8601 lower bound on event time.")
    last: Optional[int] = Field(None, description="Only the most recent N events.")
    pins: List[str] = Field(default_factory=list, description="Public key FILES under the roots for a pinned check.")


class ReceiptReq(_LogBody):
    index: int = Field(..., description="The receipt's index among the log's events.")
    pins: List[str] = Field(default_factory=list, description="Public key FILES under the roots for a pinned check.")


class RawReq(_LogBody):
    statements: bool = Field(False, description="With console, the console log's statements file.")
    start: int = Field(0, description="First line, from 0.")
    count: int = Field(100, description="How many lines, at most evidence.MAX_RAW_LINES.")


class RunPins(_Body):
    authority: Optional[str] = Field(None, description="The authority public key file under the roots.")
    instance: Optional[str] = Field(None, description="The instance public key file under the roots.")


class RunReq(_Body):
    path: str = Field(..., description="An evidence run directory under the roots.")
    pins: RunPins = Field(default_factory=RunPins)
    sample: Optional[int] = Field(None, description="Receipts to replay, at most MC_EVIDENCE_SAMPLE.")
    seed: int = Field(0, description="The replay sample's seed.")


class ManifestReq(_Body):
    flow: str = Field(..., description="A flow document under the roots.")
    pins: List[str] = Field(default_factory=list, description="Authority public key FILES under the roots.")
    log: Optional[str] = Field(None, description="An audit log under the roots holding the receipt to compare.")
    index: Optional[int] = Field(None, description="The receipt's index in `log`.")


class PackReq(_Body):
    ppt: str = Field(..., description="A signed policy image under the roots.")
    pins: List[str] = Field(default_factory=list, description="Authority public key FILES under the roots.")


class AnchorReq(_Body):
    leaf: Optional[str] = Field(None, description="Leaf hash hex (OpenTimestamps unit verify).")
    dir: Optional[str] = Field(None, description="The anchor directory under the roots (OpenTimestamps).")
    label: str = Field("v1", description="The anchor label.")
    root: Optional[str] = Field(None, description="The root file (RFC 3161).")
    tsr: Optional[str] = Field(None, description="The RFC 3161 response file.")
    cafile: Optional[str] = Field(None, description="The TSA's CA certificate file.")


# --------------------------------------------------------------------------- helpers
def _refusal(refused: evidence.EvidenceRefused) -> JSONResponse:
    status = STATUS_OF.get(refused.reason, 400)
    return JSONResponse(status_code=status, content={"error": {"code": status, "message": str(refused),
                                                               "reason": refused.reason}})


def _bytes(data: bytes) -> Dict[str, str]:
    """Bytes as JSON: base64 of exactly what was written, and the text it reads as (for people)."""
    return {"b64": base64.b64encode(data).decode("ascii"), "text": data.decode("utf-8", errors="replace")}


def _console_log() -> str:
    return os.path.realpath(core.audit.LOG.path)


def _target(body: _LogBody, statements: bool = False):
    """(path, roots) the reader is called with: a path under the evidence roots, or the console's own log
    (or its statements file) under the directory that holds it, and nothing else in that directory."""
    if body.console == bool(body.path):
        raise evidence.EvidenceRefused("bad-request", "name a log path under an evidence root, or console: true")
    if body.console:
        log_path = _console_log()
        path = root_statement.statements_path_for(log_path) if statements else log_path
        return path, [os.path.dirname(log_path)]
    if statements:
        raise evidence.EvidenceRefused("bad-request", "statements names the console log's statements file; "
                                                      "name another log's statements file by its path")
    return body.path, None


def _read(call):
    try:
        return call()
    except evidence.EvidenceRefused as refused:
        return _refusal(refused)


# --------------------------------------------------------------------------- endpoints
@router.get("/logs")
def logs():
    """Every audit log (with its statements file) and evidence run under the roots, and the console's own log."""
    def listing():
        found = evidence.discover_logs()
        log = core.audit.LOG
        found["console"] = {"path": log.path, "present": os.path.isfile(log.path), "events": len(log.events),
                            "root": log.current_root(),
                            "verifies": log.verify_log(), "verdict_of": evidence.VERDICT_OF,
                            "statements": os.path.exists(root_statement.statements_path_for(log.path))}
        return found
    return _read(listing)


@router.post("/trail")
def trail(req: TrailReq):
    """One trail as `prismpath trail` reads it, with the console's own actions paired intent to result."""
    def report():
        path, roots = _target(req)
        pinned = evidence.read_pins(req.pins)
        return evidence.trail_report(path, since=req.since, last=req.last, pinned=pinned, roots=roots)
    return _read(report)


@router.post("/receipt")
def receipt(req: ReceiptReq):
    """One receipt with its leaf, inclusion path, covering statement and bundle, and the raw line."""
    def view():
        path, roots = _target(req)
        result = evidence.receipt_view(path, req.index, pinned=evidence.read_pins(req.pins), roots=roots)
        result["raw"] = _bytes(result["raw"])
        return result
    return _read(view)


@router.post("/raw")
def raw(req: RawReq):
    """Lines of a file under the roots as written, each as base64 and as text."""
    def lines():
        path, roots = _target(req, statements=req.statements)
        result = evidence.raw_lines(path, req.start, req.count, roots=roots)
        result["lines"] = [_bytes(line) for line in result["lines"]]
        return result
    return _read(lines)


@router.post("/run")
def run(req: RunReq):
    """An evidence run verified by `core_evidence.verify`; a run that does not verify is status `invalid`."""
    pins = {role: path for role, path in (("authority", req.pins.authority), ("instance", req.pins.instance)) if path}
    return _read(lambda: evidence.run_report(req.path, pins=pins, sample=req.sample, seed=req.seed))


@router.post("/manifest")
def manifest(req: ManifestReq):
    """Change control (U6): whether a flow is authorized under the pinned authority key files, and with a
    receipt named, whether the root statement covering it names this flow's text."""
    def status():
        result = evidence.manifest_status(req.flow, pins=req.pins)
        if req.log is not None or req.index is not None:
            if req.log is None or req.index is None:
                raise evidence.EvidenceRefused("bad-request", "a receipt is named by its log and its index")
            view = evidence.receipt_view(req.log, req.index)
            policy = (view.get("statement") or {}).get("policy")
            named = policy.get("flow_sha256") if isinstance(policy, dict) else None
            result["receipt"] = {"log": view["log"], "index": req.index, "flow": policy.get("flow") if isinstance(policy, dict) else None,
                                 "flow_sha256": named, "uncovered": view["uncovered"],
                                 "agrees": None if named is None else named == result["flow_sha256"]}
        return result
    return _read(status)


@router.post("/pack")
def pack(req: PackReq):
    """A signed policy pack verified against the pinned authority key files (U7)."""
    return _read(lambda: evidence.pack_report(req.ppt, pins=req.pins))


@router.post("/anchor")
def anchor(req: AnchorReq):
    """An anchored record verified, read only (U4)."""
    return _read(lambda: evidence.anchor_report(leaf=req.leaf, anchor_dir=req.dir, label=req.label,
                                                root_file=req.root, tsr=req.tsr, cafile=req.cafile))


@router.get("/causes")
def cause_registry():
    """The cause registry in code order with its hash: what the page decodes a cause from."""
    return causes_view.registry()
