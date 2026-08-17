# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""chat_agent — the `--agent ollama:MODEL` / `openai:MODEL@BASE` worker, against a stub endpoint.

Pins the contract: JSON replies (bare or fenced) become field outcomes that route `when` edges;
plain text routes semantically; endpoint failures RAISE (riding the flow's error tier, never a
silent mis-route); spec parsing is loud on malformed input.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from prismpath.chat_agent import ChatAgentError, chat_agent, parse_spec, _extract_json
from prismpath.engine import run
from prismpath.parser import parse

FLOW = """---
name: t
start: classify
---

## classify
Classify the report. Reply with JSON {"text": "...", "kind": "bug"|"question"}.
-> handle_bug: when kind == "bug"
-> handle_question: when kind == "question"

## handle_bug
File it.

## handle_question
Answer it.
"""


class _Stub(BaseHTTPRequestHandler):
    reply = json.dumps({"text": "it crashes", "kind": "bug"})
    status = 200

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        type(self).last_request = json.loads(self.rfile.read(n))
        body = json.dumps({"choices": [{"message": {"content": type(self).reply}}]}).encode()
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if type(self).status == 200:
            self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture()
def stub():
    srv = HTTPServer(("127.0.0.1", 0), _Stub)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    _Stub.reply = json.dumps({"text": "it crashes", "kind": "bug"})
    _Stub.status = 200
    yield f"openai:testmodel@http://127.0.0.1:{srv.server_port}/v1"
    srv.shutdown()


def test_spec_parsing_loud():
    assert parse_spec("openai:m@http://h:1/v1") == ("http://h:1/v1", "m")
    base, model = parse_spec("ollama:llama3.2")
    assert model == "llama3.2" and base.endswith("/v1")
    for bad in ("ollama", "openai:modelonly", "mystery:x"):
        with pytest.raises(ValueError):
            parse_spec(bad)


def test_json_reply_routes_when_edges(stub):
    res = run(parse(FLOW), chat_agent(stub))
    assert res.path == ["classify", "handle_bug"]
    assert res.state["_outcomes"]["classify"]["kind"] == "bug"
    assert _Stub.last_request["model"] == "testmodel"          # spec's model reached the wire


def test_fenced_json_also_parses(stub):
    _Stub.reply = 'Here you go:\n```json\n{"text": "how do I export?", "kind": "question"}\n```'
    res = run(parse(FLOW), chat_agent(stub))
    assert res.path == ["classify", "handle_question"]


def test_plain_text_returns_string(stub):
    _Stub.reply = "just prose, no JSON here"
    out = chat_agent(stub)("n", "say something", {"transcript": []})
    assert out == "just prose, no JSON here"                   # a string routes semantically


def test_endpoint_failure_raises_for_error_tier(stub):
    _Stub.status = 500
    with pytest.raises(ChatAgentError):
        chat_agent(stub)("n", "x", {"transcript": []})
    dead = "openai:m@http://127.0.0.1:9/v1"                    # discard port: connection refused
    with pytest.raises(ChatAgentError):
        chat_agent(dead, timeout=2)("n", "x", {"transcript": []})


def test_prior_outcome_flows_as_context(stub):
    chat_agent(stub)("n", "next step", {"transcript": [{"node": "a", "outcome": "the build is red"}]})
    sent = _Stub.last_request["messages"][-1]["content"]
    assert "next step" in sent and "the build is red" in sent


def test_extract_json_ignores_non_objects():
    assert _extract_json("[1,2,3]") is None
    assert _extract_json("no json") is None
