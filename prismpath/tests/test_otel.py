# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""OpenTelemetry-export tests (critic #5) — span records, no SDK required."""
import numpy as np

from prismpath import embedder, otel
from prismpath.parser import parse
from prismpath.router import EmbeddingRouter

FLOW = """---
name: triage
start: classify
---
## classify
Decide.
-> bug: something is broken
-> billing: about a payment
## bug
-> done: when always
## billing
-> done: when always
## done
"""


def test_span_records_node_and_route(monkeypatch):
    vecs = {"something is broken": [1.0, 0.0], "about a payment": [0.0, 1.0],
            "app is broken": [0.95, 0.05]}
    monkeypatch.setattr(embedder, "embed",
                        lambda texts, is_query=False: np.asarray([vecs[t] for t in texts], "float32"))
    spans = []
    agent = lambda n, i, s: {"text": "app is broken" if n == "classify" else n, "always": True}
    otel.span_records(parse(FLOW), agent, spans.append, router=EmbeddingRouter(), run_id="R")

    node_spans = [s for s in spans if s["name"] == "prismpath.node"]
    route_spans = [s for s in spans if s["name"] == "prismpath.route"]
    # terminal `done` never runs the agent -> no span for it
    assert [s["attributes"]["prismpath.node"] for s in node_spans] == ["classify", "bug"]
    assert len(route_spans) == 1
    r = route_spans[0]["attributes"]
    assert r["prismpath.node"] == "classify" and r["prismpath.chosen"] == "bug"
    assert r["prismpath.mechanism"] == "embed" and r["prismpath.candidates"] == 2


def test_error_span_status():
    spans = []
    def agent(node, instr, state):
        if node == "classify":
            raise RuntimeError("boom")
        return {"text": node, "always": True}
    flow = parse("---\nstart: classify\n---\n## classify\n-> done: on error\n## done\n")
    otel.span_records(flow, agent, spans.append)
    err = [s for s in spans if s["status"] == "error"]
    assert err and err[0]["attributes"]["prismpath.error"].startswith("RuntimeError")


def test_console_tracer_requires_sdk_gracefully():
    import pytest
    try:
        import opentelemetry.sdk  # noqa: F401
    except ImportError:
        with pytest.raises(RuntimeError, match="opentelemetry-sdk"):
            otel.console_tracer()
