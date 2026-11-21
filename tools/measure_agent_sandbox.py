# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""WP10 measurements for docs/design/agent-sandbox-results.md: launch time, the hook round trip over the decider
socket, and the egress proxy's added latency per CONNECT. Linux, bwrap and socat needed. Nothing real is used.

    HOME=/var/tmp/x XDG_CONFIG_HOME=/var/tmp/x/cfg PYTHONPATH=. python tools/measure_agent_sandbox.py WORKSPACE

The HOME must hold a recorded policy (`prismpath agent init --project WORKSPACE --yes`). WORKSPACE is under /var/tmp."""
import json
import os
import socket
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

from prismpath.agent import launcher

STAND_IN = r'''
import json, os, socket, subprocess, sys, time
steps = json.load(open("steps.json"))
cfg = os.environ["CLAUDE_CONFIG_DIR"]
hook = json.load(open(cfg + "/settings.json"))["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
sock_path = hook.split()[3]
ws = os.getcwd()
def bash(session, n): return {"session_id": session, "cwd": ws, "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls -la"}}
def read(session, n): return {"session_id": session, "cwd": ws, "hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": ws + "/README.md"}}
def ms(t0): return (time.perf_counter() - t0) * 1000
out = {}
for name, make in (("hook_command_bash", bash), ("hook_command_read", read)):
    times = []
    for i in range(steps["n"] + 1):
        raw = json.dumps(make("m-" + name, i)).encode()
        t0 = time.perf_counter()
        done = subprocess.run(hook, shell=True, input=raw, capture_output=True)
        times.append(ms(t0))
        assert json.loads(done.stdout)["hookSpecificOutput"]["permissionDecision"] == "allow", done.stdout
    out[name] = times[1:]
for name, make in (("decider_socket_bash", bash), ("decider_socket_read", read)):
    times = []
    for i in range(steps["n"] + 1):
        raw = json.dumps(make("m-" + name, i)).encode()
        t0 = time.perf_counter()
        s = socket.socket(socket.AF_UNIX); s.connect(sock_path); s.sendall(raw); s.shutdown(socket.SHUT_WR)
        data = b""
        while True:
            c = s.recv(65536)
            if not c: break
            data += c
        times.append(ms(t0)); s.close()
        assert json.loads(data)["hookSpecificOutput"]["permissionDecision"] == "allow"
    out[name] = times[1:]
proxy = os.environ["HTTPS_PROXY"].split("//")[1].rsplit(":", 1)
def connect(host):
    t0 = time.perf_counter()
    s = socket.create_connection((proxy[0], int(proxy[1])), timeout=5)
    s.sendall(("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n" % (host, host)).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = s.recv(4096)
        if not c: break
        buf += c
    return s, ms(t0), buf.split(b"\r\n")[0].decode()
hs, echo, refused = [], [], []
for i in range(steps["n"] + 1):
    s, t, status = connect("api.anthropic.com")
    assert " 200 " in status, status
    hs.append(t)
    rt = []
    for _ in range(20):
        t0 = time.perf_counter(); s.sendall(b"x" * 64); got = b""
        while len(got) < 64: got += s.recv(64)
        rt.append(ms(t0))
    echo += rt; s.close()
    s, t, status = connect("evil.example")
    assert " 403 " in status, status
    refused.append(t); s.close()
out["connect_model_handshake"] = hs[1:]
out["connect_refused_handshake"] = refused[1:]
out["tunnel_echo_64b"] = echo[20:]
json.dump(out, open("measure.json", "w"))
'''


def stats(values):
    values = sorted(values)
    return {"n": len(values), "median_ms": round(statistics.median(values), 3),
            "p95_ms": round(values[min(len(values) - 1, int(0.95 * len(values)))], 3), "max_ms": round(values[-1], 3)}


class Echo:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo(conn):
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()


def main(argv):
    ws = Path(argv[1]).resolve()
    n = int(argv[2]) if len(argv) > 2 else 60
    result = {}
    # launch time: stage, proxy, policy, nested probe, decider, bwrap, relays, exit, teardown of a program that does nothing
    for label, kwargs in (("launch_no_model_route", {}), ("launch_with_model_route", {"local_model": "http://localhost:8888"})):
        times = []
        for _ in range(12):
            t0 = time.perf_counter()
            code = launcher.launch(["/usr/bin/true"], str(ws), **kwargs)
            times.append((time.perf_counter() - t0) * 1000)
            assert code == 0
        result[label] = stats(times[2:])
    # inside the launcher
    echo = Echo()
    (ws / "steps.json").write_text(json.dumps({"n": n}))
    (ws / "stand_in.py").write_text(STAND_IN)
    (ws / "measure.json").unlink(missing_ok=True)
    code = launcher.launch(["/usr/bin/python3", "stand_in.py"], str(ws), resolver=lambda name: ["93.184.216.34"],
                           connect=lambda address, port, timeout: socket.create_connection(("127.0.0.1", echo.port), timeout=timeout))
    assert code == 0, code
    for name, values in json.loads((ws / "measure.json").read_text()).items():
        result[name] = stats(values)
    # the baseline: the same echo server, a direct connect and a 64 byte round trip on the host
    handshake, rtts = [], []
    for _ in range(n):
        t0 = time.perf_counter()
        s = socket.create_connection(("127.0.0.1", echo.port))
        handshake.append((time.perf_counter() - t0) * 1000)
        for _ in range(20):
            t0 = time.perf_counter()
            s.sendall(b"x" * 64)
            got = b""
            while len(got) < 64:
                got += s.recv(64)
            rtts.append((time.perf_counter() - t0) * 1000)
        s.close()
    result["direct_connect_baseline"] = stats(handshake)
    result["direct_echo_64b_baseline"] = stats(rtts)
    print(json.dumps(result, indent=1))


if __name__ == "__main__":
    main(sys.argv)
