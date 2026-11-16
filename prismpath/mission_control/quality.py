# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Quality router exposes the routing-quality and calibration commands to Mission Control.

Mission Control needs to run the same routing-quality checks the CLI runs and show their reports in
the runtime view. Rather than shell out to the command line, every endpoint here calls the exact same
library functions the CLI handlers call (lock_flow, calibrate_cmd, centroids_cmd, kappa_cmd in
prismpath.cli), so a verdict shown in the console is the verdict the operator would get on the
terminal. Where the CLI prints human text, we return the structured result objects instead so the
front end can render them.

Every filesystem path a caller supplies is confined under the active project with core.safe_path the same
way the edit router confines its writes. A path that tries to escape the project raises ValueError,
which the application maps to a 400 response, so the router fails closed against traversal.

Writing the lockfile is the one effect here. `/quality/lock` is a write route of the operating
interface: it records its intent (the flow and its sha256, the centroid file and its sha256) before the
lockfile is written, writes it under the console's file lock, and records the lockfile's sha256 after.
Checking a lock writes nothing, so it is the read route `/quality/lock-check`, mounted in the read only
posture as well.
"""
import hashlib

from pydantic import BaseModel

from fastapi import APIRouter, Request

from . import core
from .posture import WRITE

router = APIRouter(prefix="/quality", tags=["quality"])


# Request models are declared inline here so this router carries its own contract without touching the
# shared models module.
class LockReq(BaseModel):
    flow_md: str                              # flow markdown path, relative to the active project
    check: bool = False                       # verify an existing lock instead of writing a new one
    centroids: str | None = None             # optional labeled JSONL to pin learned routing centroids
    prior: float = 4.0                        # centroid shrinkage prior weight (pseudo-count)


class LockCheckReq(BaseModel):
    flow_md: str                              # flow markdown path, relative to the active project


class CalibrateReq(BaseModel):
    labels_path: str                          # labeled routing-decision JSONL
    alpha: float = 0.05                       # target risk for the escalation threshold


class CentroidsReq(BaseModel):
    benchmark_path: str                       # labeled benchmark JSONL
    folds: int = 5                            # cross-validation fold count
    prior: float = 4.0                        # centroid shrinkage prior weight


class KappaReq(BaseModel):
    a_path: str                               # annotator A annotations JSONL
    b_path: str                               # annotator B annotations JSONL
    by_stratum: bool = False                  # also break the agreement down per stratum


def _check_lock(flow_path: str) -> dict:
    """Load the lock beside the flow and let verify_tree confirm the local embedder still reproduces the
    pinned fingerprint. verify_tree degrades to the single-flow fingerprint check when the flow has no
    children, matching the CLI. A missing or drifted lock is a failed check, not a 500."""
    from prismpath.routing import lockfile
    try:
        lock_doc = lockfile.load_lock(lockfile.lock_path(flow_path))
        reproduces = lockfile.verify_tree(flow_path, policy="warn")
    except lockfile.LockError as e:
        return {"mode": "check", "ok": False, "error": str(e)}
    except FileNotFoundError:
        return {"mode": "check", "ok": False, "error": "no lockfile beside the flow"}
    return {
        "mode": "check",
        "ok": reproduces,
        "probe_cosine": lockfile.probe_cosine(lock_doc),
        "children": len(lock_doc.get("children") or {}),
        "detail": ("embedder reproduces the fingerprint" if reproduces
                   else "drift detected: the local embedder no longer matches the lock"),
    }


def _sha256_of(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


@router.post("/lock-check")
def lock_check(req: LockCheckReq):
    """Check the routing lockfile beside a flow. Reads only. Mirrors `prismpath lock --check`."""
    return _check_lock(core.safe_path(core.current_project(), req.flow_md))


@router.post("/lock", openapi_extra=WRITE)
def lock(req: LockReq, request: Request):
    """Write the routing lockfile (or, with `check`, only check it, which `/quality/lock-check` does
    in either posture).

    The lock is built for the whole composition tree, optionally pinning learned per-condition
    centroids from a labeled benchmark, and saved beside the flow. Mirrors lock_flow in prismpath.cli.
    """
    from prismpath.routing import lockfile
    proj = core.current_project()                     # one project for the whole request
    flow_path = core.safe_path(proj, req.flow_md)
    if req.check:
        return _check_lock(flow_path)

    centroids_path = core.safe_path(proj, req.centroids) if req.centroids else None
    with core.FILE_LOCK:                              # the flow hashed is the flow the lock is built from
        intent = {"flow_md": req.flow_md, "sha256_flow": _sha256_of(flow_path),
                  "centroids": req.centroids, "sha256_centroids": _sha256_of(centroids_path) if centroids_path else None,
                  "prior": repr(req.prior)}           # a float has no canonical form; its repr is exact
        with core.audit.audited("quality.lock", intent, core.audit.actor(request, "operating")) as outcome:
            # When a caller asks to pin learned centroids, read the labeled records from the confined
            # path and build per-condition centroids against this flow's semantic conditions.
            centroids = counts = None
            if centroids_path:
                import json
                from prismpath.routing import centroid
                from prismpath.kernel.parser import parse_file
                with open(centroids_path, encoding="utf-8") as records_file:
                    records = [json.loads(line) for line in records_file if line.strip()]
                graph = parse_file(flow_path)
                centroids, counts = centroid.build_centroids(records, {graph.name: graph})
            # lock_tree pins the whole composition tree and degrades to a single-flow lock when there
            # are no children. save_lock writes it beside the flow, inside the confined project.
            lock_doc = lockfile.lock_tree(flow_path, centroids=centroids, centroid_counts=counts,
                                          prior_weight=req.prior)
            saved_path = lockfile.save_lock(flow_path, lock_doc)
            outcome["detail"] = {"path": lockfile.lock_path(req.flow_md),
                                 "sha256": _sha256_of(saved_path)}
    return {
        "mode": "write",
        "path": saved_path,
        "conditions": len(lock_doc.get("conditions") or {}),
        "embedder": lock_doc.get("embedder"),
        "delta": lock_doc.get("delta"),
        "centroids": len(lock_doc.get("centroids") or {}),
        "children": len(lock_doc.get("children") or {}),
    }


@router.post("/calibrate")
def calibrate(req: CalibrateReq):
    """Calibrate the escalation threshold tau from labeled routing decisions.

    Loads the labeled decision records and runs the conformal calibration, returning the whole
    calibration object (n, alpha, tau, and the accuracy/escalation curve). Mirrors calibrate_cmd.
    """
    from prismpath.routing import calibrate as calibrate_lib
    from prismpath.routing import routelog
    labels_path = core.safe_path(core.current_project(), req.labels_path)
    records = routelog.load_records(labels_path)
    return calibrate_lib.calibrate(records, alpha=req.alpha)


@router.post("/centroids")
def centroids(req: CentroidsReq):
    """Cross-validate prototype/centroid routing against zero-shot embedding on a labeled benchmark.

    Returns the full cross-validation report. Mirrors centroids_cmd. The flows directory is left at its
    default (the package flows/) because Mission Control does not expose a separate flows path here.
    """
    import json
    from prismpath.routing import centroid
    benchmark_path = core.safe_path(core.current_project(), req.benchmark_path)
    records = [json.loads(line) for line in open(benchmark_path, encoding="utf-8") if line.strip()]
    return centroid.cross_validate(records, flows_dir=None, folds=req.folds, prior_weight=req.prior)


@router.post("/kappa")
def kappa(req: KappaReq):
    """Cohen's kappa between two annotation files.

    Loads both annotation files and returns the agreement report (the kappa value, its band, the
    co-labeled count, and the per-stratum breakdown when requested). Mirrors kappa_cmd; the gold and
    disagreement side outputs are omitted because this endpoint reports rather than writes datasets.
    """
    from prismpath.evals import kappa as kappa_lib
    proj = core.current_project()                     # one project for the whole request
    a_path = core.safe_path(proj, req.a_path)
    b_path = core.safe_path(proj, req.b_path)
    a = kappa_lib.load(a_path)
    b = kappa_lib.load(b_path)
    return kappa_lib.report(a, b, by_stratum=req.by_stratum)

