# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The same request from any worker. A gateway protects the resource, not a worker, so one HTTP request sent by a
curl subprocess, by a Python script and by a local model that can only call `http_request` gets the identical
reading, the identical decision and the identical receipt (apart from where it sits in the run). No identity is
involved anywhere: the three clients differ in their user agent, their accept header and their address of origin,
and none of that is read.

The model is the local Gemma at GEMMA_BASE (default http://localhost:8888/v1, model gemma4); the test is skipped
where no model answers there."""
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath.tests.test_gateway import (  # noqa: E402,F401
    Running, Upstream, gcli, home, receipts)

BASE = os.environ.get("GEMMA_BASE", "http://localhost:8888/v1")
MODEL = os.environ.get("GEMMA_MODEL", "gemma4")
CASES = ("/api/orders/7?status=open", "/admin/users")


def by_curl(port, path):
    if not shutil.which("curl"):
        pytest.skip("no curl")
    done = subprocess.run(["curl", "-s", "-i", "-H", "Accept: */*", f"http://127.0.0.1:{port}{path}"],
                          capture_output=True, timeout=30)
    head, _, body = done.stdout.partition(b"\r\n\r\n")
    lines = head.decode().split("\r\n")
    headers = dict(line.split(": ", 1) for line in lines[1:])
    return int(lines[0].split()[1]), headers, body


def by_python(port, path):
    return _get(f"http://127.0.0.1:{port}{path}", {"User-Agent": "a-python-script/1.0", "Accept": "application/json"})


def _get(url, headers):
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers), err.read()


NATIVE_CALL = re.compile(r"<\|tool_call>call:(\w+)\{(.*?)\}<tool_call\|>", re.S)
NATIVE_ARG = re.compile(r'(\w+):<\|"\|>(.*?)<\|"\|>', re.S)


def tool_calls(message):
    """The calls of a model message: the server's own `tool_calls` when it parsed them, else Gemma's native
    `<|tool_call>call:NAME{key:<|"|>value<|"|>}<tool_call|>` text, which this server leaves in the content."""
    if message.get("tool_calls"):
        return [(c["id"], c["function"]["name"], json.loads(c["function"]["arguments"])) for c in message["tool_calls"]]
    return [(f"call{n}", name, dict(NATIVE_ARG.findall(args)))
            for n, (name, args) in enumerate(NATIVE_CALL.findall(message.get("content") or ""))]


def by_gemma(port, path):
    """A tool calling loop whose only tool is `http_request`. Returns the first request it made, answered."""
    made = []

    def http_request(method, path):
        made.append(_get(f"http://127.0.0.1:{port}{path}", {"User-Agent": "gemma-tool"})
                    if method.upper() == "GET" else (0, {}, b"only GET"))
        status, _headers, body = made[-1]
        return json.dumps({"status": status, "body": body.decode("utf-8", "replace")})

    tools = [{"type": "function", "function": {
        "name": "http_request", "description": "Send one HTTP request to the service and return its answer.",
        "parameters": {"type": "object", "properties": {"method": {"type": "string"}, "path": {"type": "string"}},
                       "required": ["method", "path"]}}}]
    messages = [{"role": "system", "content": "You can only use the http_request tool. Call it exactly once with the "
                                              "method and path you are given, then say the status code you got."},
                {"role": "user", "content": f"Send GET {path}"}]
    for _ in range(4):
        body = json.dumps({"model": MODEL, "messages": messages, "tools": tools, "temperature": 0, "max_tokens": 400,
                           "chat_template_kwargs": {"enable_thinking": False}}).encode()
        req = urllib.request.Request(f"{BASE}/chat/completions", data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                message = json.loads(resp.read())["choices"][0]["message"]
        except OSError:
            pytest.skip(f"no model answers at {BASE}")
        messages.append(message)
        calls = tool_calls(message)
        if not calls:
            break
        for call_id, name, args in calls:
            result = http_request(str(args.get("method", "GET")), str(args.get("path", ""))) if name == "http_request" \
                else json.dumps({"error": "no such tool"})
            messages.append({"role": "tool", "tool_call_id": call_id, "content": result})
        if made:
            break
    assert made, "the model never called http_request"
    return made[0]


@pytest.mark.parametrize("path", CASES)
def test_three_workers_one_request_one_decision(path, home):
    up = Upstream()
    gw = Running(up, home)
    try:
        answers = {name: fn(gw.port, path) for name, fn in (("curl", by_curl), ("python", by_python), ("gemma", by_gemma))}
    finally:
        gw.close()
        up.close()
    rows = receipts(home)
    assert len(rows) == 3
    status = {name: a[0] for name, a in answers.items()}
    assert len(set(status.values())) == 1, status
    assert status["curl"] == (200 if path.startswith("/api") else 403)
    # the answers are the same bytes, apart from the receipt they name
    stripped = {}
    for name, (_s, _h, body) in answers.items():
        stripped[name] = body if status[name] == 200 else {k: v for k, v in json.loads(body).items() if k != "receipt"}
    assert len({json.dumps(v, sort_keys=True, default=str) for v in stripped.values()}) == 1
    # the same reading and the same decision; the receipt differs only in its place in the run
    assert len({r["reading"] for r in rows}) == 1
    sans_place = [{k: v for k, v in r["receipt"].items() if k not in ("idx", "reading")} for r in rows]
    assert sans_place[0] == sans_place[1] == sans_place[2]
    assert [r["receipt"]["idx"] for r in rows] == [0, 1, 2]
    for name, (_s, headers, _b) in answers.items():
        assert {k.lower(): v for k, v in headers.items()}["x-prismpath-receipt"] in ("0", "1", "2"), name
    assert len(up.seen) == (3 if path.startswith("/api") else 0)
    assert len({s["headers"].get("User-Agent") for s in up.seen}) == len(up.seen)    # the upstream saw three different clients
    assert gcli.verify(home, False, out=open(os.devnull, "w")) == 0
