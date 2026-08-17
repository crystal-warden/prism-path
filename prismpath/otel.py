# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""otel.py — export a run as OpenTelemetry spans (critic capability #5).

Each node execution and each semantic routing decision becomes a span with the scores/margins as
attributes — so a flow shows up in Grafana, Jaeger, or Datadog without building a single dashboard.
The observability weakness ("Mission Control is embryonic") becomes "integrates with what you
already run."

Design: `span_records()` runs a flow and emits OTel-*shaped* span dicts to a `sink` callback — fully
testable with no OpenTelemetry installed. `to_otel_sink(tracer)` adapts those to real spans when the
SDK is present; `console_tracer()` wires a console exporter for a quick demo.

    from prismpath import otel
    otel.span_records(graph, agent, otel.to_otel_sink(otel.console_tracer()))
"""
from __future__ import annotations

from typing import Callable, Optional


def span_records(graph, agent, sink: Callable[[dict], None], run_id: Optional[str] = None, **run_kw):
    """Run `graph` emitting a span-record dict per node execution and per semantic routing decision
    to `sink`. Each record: {name, attributes, status}. Returns the RunResult."""
    from prismpath.engine import run
    seq = {"i": 0}

    def traced_agent(node, instruction, state):
        seq["i"] += 1
        rec = {"name": "prismpath.node", "status": "ok",
               "attributes": {"prismpath.flow": graph.name, "prismpath.node": node, "prismpath.seq": seq["i"]}}
        try:
            out = agent(node, instruction, state)
        except Exception as e:
            rec["status"] = "error"
            rec["attributes"]["prismpath.error"] = f"{type(e).__name__}: {e}"
            sink(rec)
            raise
        text = out.get("text", "") if isinstance(out, dict) else str(out)
        rec["attributes"]["prismpath.outcome"] = text[:200]
        sink(rec)
        return out

    def on_decision(d: dict):
        sink({"name": "prismpath.route", "status": "ok", "attributes": {
            "prismpath.flow": d.get("flow"), "prismpath.node": d.get("node"),
            "prismpath.chosen": d.get("chosen"), "prismpath.mechanism": d.get("mechanism"),
            "prismpath.margin": d.get("margin"), "prismpath.top1": d.get("top1"),
            "prismpath.top2": d.get("top2"), "prismpath.escalated": d.get("escalated"),
            "prismpath.candidates": len(d.get("candidates", []))}})

    return run(graph, traced_agent, on_decision=on_decision, run_id=run_id, **run_kw)


def to_otel_sink(tracer) -> Callable[[dict], None]:
    """Adapt span-record dicts to real OpenTelemetry spans on `tracer`."""
    from opentelemetry.trace import Status, StatusCode

    def sink(rec: dict) -> None:
        with tracer.start_as_current_span(rec["name"]) as span:
            for k, v in rec.get("attributes", {}).items():
                if v is not None:
                    span.set_attribute(k, v)
            if rec.get("status") == "error":
                span.set_status(Status(StatusCode.ERROR))
    return sink


def console_tracer(service_name: str = "prismpath"):
    """A tracer that prints spans to the console (needs `pip install opentelemetry-sdk`)."""
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
    except ImportError as e:
        raise RuntimeError("OpenTelemetry export needs `pip install opentelemetry-sdk`") from e
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(provider)
    return trace.get_tracer(service_name)
