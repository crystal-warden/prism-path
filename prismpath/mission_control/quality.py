# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Quality router exposes the routing-quality and calibration commands to Mission Control.

Mission Control needs to run the same routing-quality checks the CLI runs and show their reports in
the runtime view. Rather than shell out to the command line, every endpoint here calls the exact same
library functions the CLI handlers call (lock_flow, calibrate_cmd, centroids_cmd, kappa_cmd in
prismpath.cli), so a verdict shown in the console is the verdict the operator would get on the
terminal. Where the CLI prints human text, we return the structured result objects instead so the
front end can render them.

Every filesystem path a caller supplies is confined under the active project with core._safe the same
way the edit router confines its writes. A path that tries to escape the project raises ValueError,
which the application maps to a 400 response, so the router fails closed against traversal.
"""
from pydantic import BaseModel

from fastapi import APIRouter, HTTPException

from . import core

router = APIRouter(prefix="/quality", tags=["quality"])


# Request models are declared inline here so this router carries its own contract without touching the
# shared models module.
class LockReq(BaseModel):
    flow_md: str                              # flow markdown path, relative to the active project
    check: bool = False                       # verify an existing lock instead of writing a new one
    centroids: str | None = None             # optional labeled JSONL to pin learned routing centroids
    prior: float = 4.0                        # centroid shrinkage prior weight (pseudo-count)


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


@router.post("/lock")
def lock(req: LockReq):
    """Write or check the routing lockfile.

    In check mode we load the existing lock and let verify_tree confirm the local embedder still
    reproduces the pinned fingerprint. Otherwise we build the lock for the whole composition tree,
    optionally pinning learned per-condition centroids from a labeled benchmark, and save it. Mirrors
    lock_flow in prismpath.cli.
    """
    from prismpath.routing import lockfile
    flow_path = core._safe(core.STATE["proj"], req.flow_md)

    if req.check:
        # verify_tree degrades to the single-flow fingerprint check when the flow has no children,
        # matching the CLI. A missing or drifted lock is reported as a failed check, not a 500.
        try:
            lock_doc = lockfile.load_lock(lockfile.lock_path(flow_path))
            reproduces = lockfile.verify_tree(flow_path, policy="warn")
        except lockfile.LockError as e:
            return {"mode": "check", "ok": False, "error": str(e)}
        children = len(lock_doc.get("children") or {})
        return {
            "mode": "check",
            "ok": reproduces,
            "probe_cosine": lockfile.probe_cosine(lock_doc),
            "children": children,
            "detail": ("embedder reproduces the fingerprint" if reproduces
                       else "drift detected: the local embedder no longer matches the lock"),
        }

    # Write mode. When a caller asks to pin learned centroids, read the labeled records from a
    # project-confined path and build per-condition centroids against this flow's semantic conditions.
    centroids = counts = None
    if req.centroids:
        import json
        from prismpath.routing import centroid
        from prismpath.kernel.parser import parse_file
        centroids_path = core._safe(core.STATE["proj"], req.centroids)
        records = [json.loads(line) for line in open(centroids_path, encoding="utf-8") if line.strip()]
        graph = parse_file(flow_path)
        centroids, counts = centroid.build_centroids(records, {graph.name: graph})

    # lock_tree pins the whole composition tree and degrades to a single-flow lock when there are no
    # children. save_lock writes it beside the flow, inside the confined project.
    lock_doc = lockfile.lock_tree(flow_path, centroids=centroids, centroid_counts=counts,
                                  prior_weight=req.prior)
    saved_path = lockfile.save_lock(flow_path, lock_doc)
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
    labels_path = core._safe(core.STATE["proj"], req.labels_path)
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
    benchmark_path = core._safe(core.STATE["proj"], req.benchmark_path)
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
    a_path = core._safe(core.STATE["proj"], req.a_path)
    b_path = core._safe(core.STATE["proj"], req.b_path)
    a = kappa_lib.load(a_path)
    b = kappa_lib.load(b_path)
    return kappa_lib.report(a, b, by_stratum=req.by_stratum)


# Register in prismpath/mission_control/app.py alongside the other routers with:
# app.include_router(quality.router, prefix=API_PREFIX)
