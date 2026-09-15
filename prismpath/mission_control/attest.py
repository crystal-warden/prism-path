# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Attest router: the read and verify side of the attestation CLI, exposed for Mission Control.

The evaluator persona's scripted commands (`prismpath verify`, `prismpath trail`, and the read only
`prismpath ledger` actions) surfaced over the same in process libraries the CLI calls, so a verdict
here is the verdict on the command line. Three questions this router answers, all of them read only:

    POST /attest/model-check   does this flow behave, provably, the way it reads (bounded model check)?
    POST /attest/trail         what has the sealed receipt trail been deciding, and does its root hold?
    POST /attest/ledger-verify does an anchored ledger record still verify against Bitcoin or a TSA?

SAFETY: this router exposes only reading and verifying. The mutating and publishing ledger actions
(anchor, upgrade, export-request, relay-stamp, import-proofs) stamp timestamp calendars or change the
ledger, so they are deliberately absent here. There is no code path in this file that anchors, upgrades,
relays, exports, or imports. Paths that name files are confined to the followed project the way the edit
router confines them (core._safe against core.STATE["proj"]); a path that escapes fails closed with a
client error rather than reading anywhere on disk.
"""
import os

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from . import core

router = APIRouter(prefix="/attest", tags=["attest"])

# The anchor label the CLI defaults to (`prismpath ledger ... --label v1`). Verify reads the anchor
# artifacts written under this label; it is a read key, never a write.
DEFAULT_LABEL = "v1"


# --------------------------------------------------------------------------- request models (inline)
class ModelCheckReq(BaseModel):
    flow_md: str = Field(..., description="Project relative path to the flow markdown file (contained).")


class TrailReq(BaseModel):
    source: Optional[str] = Field(
        None, description="Project relative path to the append only audit log JSONL to walk. "
                          "Omitted walks the console's own mission audit log.")
    since: Optional[str] = Field(None, description="ISO 8601 lower bound on event time (UTC if no zone).")
    last: Optional[int] = Field(None, description="Only the most recent N events.")


class LedgerVerifyReq(BaseModel):
    """Verify an anchored ledger record. Two verify modes, chosen by which inputs are present, and
    both are read only. Provide `leaf` for the OTS Merkle plus Bitcoin unit verify; provide `root`
    with `tsr` and `cafile` for the RFC 3161 trusted timestamp verify."""
    leaf: Optional[str] = Field(
        None, description="Leaf hash hex to verify against the anchored Merkle root (OTS unit verify).")
    root: Optional[str] = Field(
        None, description="Project relative path. For the OTS verify it is the anchor directory holding "
                          "manifest and root artifacts; for the RFC 3161 verify it is the root file.")
    ots: Optional[bool] = Field(
        None, description="Advisory parity with the CLI --ots flag; the OTS unit verify always checks "
                          "the full Bitcoin proof chain, so this is echoed rather than gating.")
    cafile: Optional[str] = Field(
        None, description="Project relative path to the TSA CA cert (RFC 3161 verify).")
    tsr: Optional[str] = Field(
        None, description="Project relative path to the RFC 3161 response file to verify.")


# --------------------------------------------------------------------------- endpoints
@router.post("/model-check")
def model_check_flow(req: ModelCheckReq):
    """Bounded model check a flow: adversarial worker reachability over every node plus per edge Level M
    membership, exactly what `prismpath verify` computes. Reuses model_check.check_reach and
    model_check.flow_level_m so the answer cannot drift from the kernel and CLI."""
    from prismpath.kernel.parser import parse_file
    from prismpath.kernel import model_check

    resolved = _confine(req.flow_md)
    if not os.path.isfile(resolved):
        raise HTTPException(status_code=404, detail="flow file not found in the project")
    if os.path.getsize(resolved) > core.MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="flow exceeds MC_MAX_FILE_BYTES")
    try:
        graph = parse_file(resolved)
    except Exception as e:                            # a malformed flow is a client error, not a 500
        raise HTTPException(status_code=400, detail=f"could not parse flow: {e}")

    results = model_check.check_reach(graph, sorted(graph.nodes))
    lm_all, lm_bad = model_check.flow_level_m(graph)
    return {"flow": os.path.relpath(resolved, core.STATE["proj"]),
            "start": graph.start,
            "results": {name: r.as_dict() for name, r in results.items()},
            "level_m": {"flow": lm_all, "non_member_edges": lm_bad}}


@router.post("/trail")
def walk_trail(req: TrailReq):
    """Walk the sealed receipt trail: summarise an append only audit log by action, outcome, and cause
    code, and report whether its Merkle root still verifies. Reuses trail.run, the same walker the
    operator's `prismpath trail` command drives. With no source, walks the console's own audit log."""
    from prismpath import trail

    if req.source:
        path = _confine(req.source)
        if not os.path.isfile(path):
            raise HTTPException(status_code=404, detail="audit log not found in the project")
        if os.path.getsize(path) > core.MAX_FILE_BYTES:
            raise HTTPException(status_code=413, detail="audit log exceeds MC_MAX_FILE_BYTES")
    else:
        path = core.AUDIT.path                        # the console's own mission audit log

    try:
        return trail.run(path, since=req.since, last=req.last)
    except ValueError as e:                           # a bad --since timestamp is a client error
        raise HTTPException(status_code=400, detail=f"could not read trail: {e}")


@router.post("/ledger-verify")
def ledger_verify(req: LedgerVerifyReq):
    """Verify an anchored ledger record. READ AND VERIFY ONLY: this reuses only the verify functions of
    the ledger libraries (ledger_ots.verify_unit for the OTS Merkle plus Bitcoin chain, and
    ledger_airgap.rfc3161_verify for the trusted timestamp tier). It never anchors, upgrades, relays,
    exports, or imports, so it cannot publish to a timestamp calendar or mutate the ledger."""
    from prismpath.ledgers import ledger_ots, ledger_airgap

    # RFC 3161 trusted timestamp verify: needs the root file, the response, and the TSA CA cert.
    if req.tsr or req.cafile:
        if not (req.root and req.tsr and req.cafile):
            raise HTTPException(status_code=400,
                                detail="rfc3161 verify needs root, tsr, and cafile")
        rootfile = _confine(req.root)
        tsr = _confine(req.tsr)
        cafile = _confine(req.cafile)
        for label, fp in (("root", rootfile), ("tsr", tsr), ("cafile", cafile)):
            if not os.path.isfile(fp):
                raise HTTPException(status_code=404, detail=f"{label} not found in the project")
        res = ledger_airgap.rfc3161_verify(rootfile, tsr, cafile)
        return {"mode": "rfc3161", **res}

    # OTS Merkle plus Bitcoin unit verify: the leaf hash against the anchor artifacts on disk.
    if req.leaf:
        out_dir = _confine(req.root) if req.root else core.STATE["proj"]
        if not os.path.isdir(out_dir):
            raise HTTPException(status_code=404, detail="anchor directory not found in the project")
        try:
            res = ledger_ots.verify_unit(req.leaf, out_dir, DEFAULT_LABEL)
        except FileNotFoundError:
            raise HTTPException(status_code=404,
                                detail=f"no anchor artifacts for label {DEFAULT_LABEL!r} in that directory")
        return {"mode": "ots", "ots_flag": bool(req.ots), **res}

    raise HTTPException(status_code=400,
                        detail="provide leaf for OTS verify, or root with tsr and cafile for rfc3161 verify")


# --------------------------------------------------------------------------- helpers
def _confine(rel: str) -> str:
    """Resolve a request path against the followed project, refusing anything that escapes it. A
    traversal raises ValueError from core._safe, which we translate to a client error (fail closed)."""
    try:
        return core._safe(core.STATE["proj"], rel)
    except ValueError:
        raise HTTPException(status_code=400, detail="path escapes the project")


# Register in app.py alongside the other routers:
# app.include_router(attest.router, prefix=API_PREFIX)
