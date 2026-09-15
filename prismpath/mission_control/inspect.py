# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Inspect router: the flow inspection CLI, exposed for Mission Control's runtime view.

Every endpoint here answers a question the process owner already asks from the terminal
(`prismpath validate|lint|contract|portable|test|graph`), so the console can ask it of a
selected flow without a shell. Each handler reuses the SAME kernel library functions the CLI
handlers call, which keeps a verdict here identical to a verdict at the command line.

Unlike the proving router, which takes flow *text* over the wire, these commands operate on a
flow *path*, because contract, portability, composition, and fixture resolution all read sibling
files (spawned children, the `.tests.md` fixture) relative to that path. To keep that from
becoming a filesystem traversal surface, every path is confined under the active project with
`core._safe`, exactly the way the edit router does it. A path that escapes the project raises
ValueError, which the app's error handler turns into a clean client error rather than a leak.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from . import core
from prismpath.kernel.parser import parse_file
from prismpath.kernel import analysis

router = APIRouter(prefix="/inspect", tags=["inspect"])


# --------------------------------------------------------------- request models
# These live here rather than in models.py so the inspect surface owns its own contract; the
# orchestrator wires the router in without touching shared model definitions.
class FlowReq(BaseModel):
    """A flow to inspect, named by a project-relative path."""
    flow_md: str


class GraphReq(BaseModel):
    """A flow plus the Mermaid layout direction (TD top-down, LR left-right)."""
    flow_md: str
    direction: str = "TD"


class TestReq(BaseModel):
    """A flow plus an optional fixture path; when omitted the sibling default fixture is used."""
    flow_md: str
    tests_md: str | None = None


def _resolve(flow_md: str) -> str:
    """Confine a client-supplied flow path under the active project, failing closed.

    An empty path is a client error, not a stat of the project root, so we reject it up front.
    `core._safe` raises ValueError on any path that would escape the project tree; we translate
    that into a 400 here so the caller sees a contained refusal instead of a traceback.
    """
    if not (flow_md or "").strip():
        raise HTTPException(status_code=400, detail="flow_md is empty")
    try:
        return core._safe(core.STATE["proj"], flow_md)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


def _parse(flow_path: str):
    """Parse a confined flow path into a graph, turning a malformed flow into a client error.

    A parse failure means the caller handed us an unparseable document, which is a 400 rather
    than a server fault, mirroring how the proving router treats a bad flow.
    """
    try:
        return parse_file(flow_path)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"could not parse flow: {e}")


@router.post("/validate")
def inspect_validate(req: FlowReq):
    """Does the flow compile? The fast, model free check: static analysis plus the cross flow
    `@spawn` composition checks, exactly what `prismpath validate` runs. `ok` is false when any
    finding is an error, matching the CLI's non-zero exit contract."""
    flow_path = _resolve(req.flow_md)
    graph = _parse(flow_path)
    findings = list(analysis.analyze(graph))
    findings += analysis.analyze_composition(graph, flow_path)
    errors = [f for f in findings if f.severity == "error"]
    warnings = [f for f in findings if f.severity == "warning"]
    return {"ok": not errors, "errors": len(errors), "warnings": len(warnings),
            "findings": [f.as_dict() for f in findings]}


@router.post("/lint")
def inspect_lint(req: FlowReq):
    """The full lint, including the checks that need the embedder: semantic near ties and the
    polarity mirror class the static pass cannot see. This is `prismpath lint`, so it is the
    heavier call. Findings are sorted errors first, then by code, as the CLI presents them."""
    flow_path = _resolve(req.flow_md)
    graph = _parse(flow_path)
    findings = list(analysis.analyze(graph))
    findings += analysis.analyze_composition(graph, flow_path)
    # The non decidable checks that require the embedder, the same two the CLI folds in.
    from prismpath.kernel.lint import semantic_ambiguity, polarity_mirror
    findings += semantic_ambiguity(graph)
    findings += polarity_mirror(graph)
    findings.sort(key=lambda f: (f.severity != "error", f.code, f.node or ""))
    errors = [f for f in findings if f.severity == "error"]
    warnings = [f for f in findings if f.severity == "warning"]
    return {"ok": not errors, "errors": len(errors), "warnings": len(warnings),
            "findings": [f.as_dict() for f in findings]}


@router.post("/contract")
def inspect_contract(req: FlowReq):
    """Each node's derived worker output schema: the fields its `when` edges read, with inferred
    types, rendered as JSON Schema. `prismpath contract`. A field used two incompatible ways is a
    real authoring bug, so those conflicts are surfaced and drive `ok` false."""
    from prismpath.kernel import contract
    flow_path = _resolve(req.flow_md)
    graph = _parse(flow_path)
    derived = contract.derive_contract(graph)
    schemas = {n: contract.to_json_schema(fs) for n, fs in derived.items() if fs}
    conflicts = [{"node": n, "field": f, "detail": s["conflict"]}
                 for n, fs in derived.items() for f, s in fs.items() if s.get("conflict")]
    return {"ok": not conflicts, "schemas": schemas, "conflicts": conflicts}


@router.post("/portable")
def inspect_portable(req: FlowReq):
    """Is the flow in the ML free portable subset? Reports the portability tier for the whole
    composition tree. `prismpath portable`. P0 is the ML free subset (`portable` verdict true);
    P1 means every reachable semantic edge is locked so only an outcome side embedder is needed;
    P2 needs the full engine. We return the whole tree so the console can paint the offenders."""
    flow_path = _resolve(req.flow_md)
    graph = _parse(flow_path)
    tree = analysis.portability_tier_tree(graph, flow_path)
    flows = {p: {"tier": d["tier"],
                 "semantic_edges": [{"node": n, "target": t, "condition": c}
                                    for n, t, c in d["semantic_edges"]],
                 "unlocked": d["unlocked"], "lock": d["lock"]}
             for p, d in tree["flows"].items()}
    return {"tier": tree["tier"], "portable": tree["tier"] == "P0", "flows": flows}


@router.post("/test")
def inspect_test(req: TestReq):
    """Assert routing from the fixture, no LLM in the loop: `prismpath test`. Runs the flow's test
    cases and reports each case's node, how it routed, what it got, and what was expected. When no
    fixture path is given the sibling default fixture is used; a missing fixture is a 404 so the
    console can prompt the author to write one."""
    from prismpath.kernel import flow_test
    import os
    flow_path = _resolve(req.flow_md)
    if req.tests_md:
        tests_path = _resolve(req.tests_md)
    else:
        tests_path = flow_test.default_tests_path(flow_path)
    if not os.path.exists(tests_path):
        raise HTTPException(status_code=404, detail=f"no fixture found: {tests_path}")
    report = flow_test.run_tests(flow_path, tests_path)
    return {"ok": report.ok, "passed": report.passed, "failed": report.failed,
            "cases": [vars(r) for r in report.results]}


@router.post("/graph")
def inspect_graph(req: GraphReq):
    """The Mermaid diagram string for the flow, so Mission Control can render it: `prismpath graph`.
    We return the raw (unfenced) Mermaid source, which is what a renderer wants; the caller adds a
    code fence only if it is dropping the string into Markdown."""
    from prismpath.kernel import graph_export
    if req.direction not in ("TD", "LR"):
        raise HTTPException(status_code=400, detail="direction must be TD or LR")
    flow_path = _resolve(req.flow_md)
    graph = _parse(flow_path)
    return {"mermaid": graph_export.to_mermaid(graph, req.direction), "direction": req.direction}


# To register this router, add `inspect` to the mission_control import in app.py and this line
# alongside the other app.include_router calls:
#     app.include_router(inspect.router, prefix=API_PREFIX)
