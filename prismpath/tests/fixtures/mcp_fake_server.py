# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A fake downstream MCP server over stdio for the proxy tests.

    python mcp_fake_server.py LOG_DIR

It writes every line it reads to LOG_DIR/received.bin and every line it writes to LOG_DIR/sent.bin, as bytes,
so a test can compare what the client sent with what reached the server, and what the server said with what
reached the client. Every `tools/call` it is given is also recorded in LOG_DIR/calls.jsonl.

Tools: `list_dir`, `read_file`, `git` (the classifier's names), `read_text_file` (the filesystem server's), and
`slow_echo` (`{"token": str, "delay": seconds}`), which answers from its own thread after the delay so that
answers to concurrent calls come back in another order than their requests.
"""
import json
import sys
import threading
import time
from pathlib import Path

LOG = Path(sys.argv[1])
LOCK = threading.Lock()
TOOLS = [
    {"name": "list_dir", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    {"name": "read_file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}},
                                          "required": ["path"]}},
    {"name": "git", "inputSchema": {"type": "object", "properties": {"subcommand": {"type": "string"},
                                                                     "args": {"type": "array"}}}},
    {"name": "read_text_file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    {"name": "slow_echo", "inputSchema": {"type": "object", "properties": {"token": {"type": "string"},
                                                                           "delay": {"type": "number"}}}},
]


def _log(name, data):
    with open(LOG / name, "ab") as handle:
        handle.write(data)


def send(message):
    line = json.dumps(message, separators=(",", ":")).encode() + b"\n"
    with LOCK:
        _log("sent.bin", line)
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()


def result(request, text):
    return {"jsonrpc": "2.0", "id": request["id"],
            "result": {"content": [{"type": "text", "text": text}], "isError": False}}


def answer(request):
    method = request.get("method")
    if "id" not in request:
        return None
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": request["id"],
                "result": {"protocolVersion": request["params"].get("protocolVersion", "2025-11-25"),
                           "capabilities": {"tools": {}}, "serverInfo": {"name": "fake", "version": "1"}}}
    if method == "server/discover":
        return {"jsonrpc": "2.0", "id": request["id"],
                "result": {"resultType": "complete", "supportedVersions": ["2026-07-28"],
                           "capabilities": {"tools": {}}, "serverInfo": {"name": "fake", "version": "1"}}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request["id"], "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = request["params"]
        return result(request, f"ran {params['name']} {json.dumps(params.get('arguments', {}), sort_keys=True)}")
    return {"jsonrpc": "2.0", "id": request["id"], "error": {"code": -32601, "message": f"no method {method}"}}


def handle(request):
    if isinstance(request, list):
        answers = [a for a in (answer(r) for r in request) if a is not None]
        for r in request:
            if r.get("method") == "tools/call":
                _log("calls.jsonl", json.dumps({"id": r.get("id"), "params": r["params"]}).encode() + b"\n")
        if answers:
            send(answers)
        return
    if request.get("method") == "tools/call":
        _log("calls.jsonl", json.dumps({"id": request.get("id"), "params": request["params"]}).encode() + b"\n")
        params = request["params"]
        if params["name"] == "slow_echo" and "id" in request:
            def later():
                time.sleep(float(params["arguments"].get("delay", 0)))
                send(result(request, "echo " + params["arguments"]["token"]))
            threading.Thread(target=later).start()
            return
    reply = answer(request)
    if reply is not None:
        send(reply)


for raw in iter(sys.stdin.buffer.readline, b""):
    _log("received.bin", raw)
    if raw.strip():
        handle(json.loads(raw))
