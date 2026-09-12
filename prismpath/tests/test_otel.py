# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""OpenTelemetry-export tests (critic #5) — span records, no SDK required."""
import numpy as np

from prismpath.routing import embedder
from prismpath.ledgers import otel
from prismpath.kernel.parser import parse
from prismpath.routing.router import EmbeddingRouter

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
                        lambda texts, is_query=False: np.asarray([vecs[text] for text in texts], "float32"))
    spans = []
    agent = lambda node, instruction, state: {"text": "app is broken" if node == "classify" else node, "always": True}
    otel.span_records(parse(FLOW), agent, spans.append, router=EmbeddingRouter(), run_id="R")

    node_spans = [span for span in spans if span["name"] == "prismpath.node"]
    route_spans = [span for span in spans if span["name"] == "prismpath.route"]
    # terminal `done` never runs the agent -> no span for it
    assert [span["attributes"]["prismpath.node"] for span in node_spans] == ["classify", "bug"]
    assert len(route_spans) == 1
    attributes = route_spans[0]["attributes"]
    assert attributes["prismpath.node"] == "classify" and attributes["prismpath.chosen"] == "bug"
    assert attributes["prismpath.mechanism"] == "embed" and attributes["prismpath.candidates"] == 2


def test_error_span_status():
    spans = []
    def agent(node, instr, state):
        if node == "classify":
            raise RuntimeError("boom")
        return {"text": node, "always": True}
    flow = parse("---\nstart: classify\n---\n## classify\n-> done: on error\n## done\n")
    otel.span_records(flow, agent, spans.append)
    err = [span for span in spans if span["status"] == "error"]
    assert err and err[0]["attributes"]["prismpath.error"].startswith("RuntimeError")


def test_console_tracer_requires_sdk_gracefully():
    import pytest
    try:
        import opentelemetry.sdk  # noqa: F401
    except ImportError:
        with pytest.raises(RuntimeError, match="opentelemetry-sdk"):
            otel.console_tracer()
