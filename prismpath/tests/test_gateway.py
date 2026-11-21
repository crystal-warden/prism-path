# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The gateway in front of a resource: the reading of an HTTP request, the demo policy, the decision and receipt of
every request, and the bounds. A stand-in upstream records what reaches it."""
import http.client
import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath.agent import commands  # noqa: E402
from prismpath.agent.run import RunStore  # noqa: E402
from prismpath.gateway import cli as gcli, proxy, reading as rd  # noqa: E402
from prismpath.kernel import causes, policy_source  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "prismpath" / "gateway" / "policy"
ROUTES = rd.Routes.load(POLICY / "demo.routes.json")


# ------------------------------------------------------------------------------------------- the reading
def hdrs(**kw):
    return {k.replace("_", "-"): v if isinstance(v, list) else [v] for k, v in kw.items()}


def test_reading_fields_and_canonical_bytes():
    r = rd.read_request("GET", "/api/orders/7?x=1", {}, ROUTES, 0)
    assert tuple(r) == rd.FIELDS
    assert r == {"http_reading_version": 1, "method_class": "read", "path_class": "orders", "body_class": "none",
                 "content_class": "none", "query": "present", "grant": "none"}
    from prismpath.agent.policy import Policy
    policy = Policy.load(POLICY / "demo.core.json")
    assert policy.reading_bytes(r) == policy.reading_bytes(dict(reversed(list(r.items()))))   # canon/2 sorts the keys


@pytest.mark.parametrize("method,expected", [("GET", "read"), ("HEAD", "read"), ("POST", "write"), ("PUT", "write"),
                                             ("PATCH", "write"), ("DELETE", "delete"), ("OPTIONS", "other"),
                                             ("TRACE", "other"), ("PURGE", "other"), ("G ET", "unknown"),
                                             ("", "unknown"), (None, "unknown"), ("get", "other")])
def test_method_class(method, expected):
    assert rd.method_class(method) == expected


@pytest.mark.parametrize("target,cls", [
    ("/admin", "admin"), ("/admin/", "admin"), ("/admin/users/1", "admin"), ("/ADMIN/users", "admin"),
    ("/api/orders", "orders"), ("/api/orders/7", "orders"), ("/api/orderss", "other"), ("/adminx", "other"),
    ("/health", "other"), ("/", "other"),
    ("/admin/../api", "unknown"), ("/a/./b", "unknown"), ("//admin", "unknown"), ("/a//b", "unknown"),
    ("/%61dmin", "unknown"), ("/admin%2fx", "unknown"), ("/admin;x=1/y", "unknown"), ("/a\\b", "unknown"),
    ("/café", "unknown"), ("/a b", "unknown"), ("admin", "unknown"), ("http://h/admin", "unknown"),
    ("*", "unknown"), ("/" + "a" * 3000, "unknown"), ("", "unknown"), (None, "unknown")])
def test_path_class(target, cls):
    path, _q = rd.split_target(target)
    assert ("unknown" if path is None else ROUTES.classify(path)) == cls


@pytest.mark.parametrize("target,query", [("/a", "none"), ("/a?", "none"), ("/a?x=1", "present"),
                                          ("/a?x=1 2", "unknown"), ("/a?x=\x01", "unknown"), ("/a?x=é", "unknown"),
                                          ("/a?x=1#f", "unknown")])
def test_query_class(target, query):
    assert rd.split_target(target)[1] == query


def test_route_table_first_entry_wins_and_is_validated():
    table = rd.Routes.from_doc({"routes": [{"match": "/api/orders/secret", "class": "secret"},
                                           {"match": "/api/*", "class": "api"}]})
    assert [table.classify(p) for p in ("/api/orders/secret", "/api/orders", "/api", "/x")] == ["secret", "api", "api", "other"]
    assert rd.Routes.from_doc({"routes": [{"match": "/*", "class": "everything"}]}).classify("/any/thing") == "everything"
    for bad in ({"routes": [{"match": "/a*", "class": "x"}]}, {"routes": [{"match": "/a/", "class": "x"}]},
                {"routes": [{"match": "/a", "class": "unknown"}]}, {"routes": [{"match": "/a", "class": "Other"}]},
                {"routes": [{"match": "/a", "class": "x", "extra": 1}]}, {"routes": "x"}, [], {"routes": [], "x": 1}):
        with pytest.raises(rd.RouteError):
            rd.Routes.from_doc(bad)


@pytest.mark.parametrize("values,cls", [([], "none"), (["application/json"], "json"),
                                        (["Application/JSON; charset=utf-8"], "json"), (["application/vnd.x+json"], "json"),
                                        (["application/x-www-form-urlencoded"], "form"), (["text/plain"], "text"),
                                        (["image/png"], "other"), (["json"], "unknown"),
                                        (["application/json", "text/plain"], "unknown"), ([""], "unknown")])
def test_content_class(values, cls):
    assert rd.content_class(values) == cls


@pytest.mark.parametrize("lengths,te,length,cls", [
    ([], [], 0, "none"), (["0"], [], 0, "none"), (["10"], [], 10, "small"), ([str(rd.SMALL_BODY + 1)], [], rd.SMALL_BODY + 1, "large"),
    ([str(rd.MAX_BODY + 1)], [], rd.MAX_BODY + 1, "oversize"), (["-1"], [], None, "unknown"), (["1x"], [], None, "unknown"),
    (["1", "1"], [], None, "unknown"), ([], ["chunked"], None, "unknown"), (["5"], ["chunked"], None, "unknown"),
    ([" 5"], [], None, "unknown"), (["9" * 30], [], None, "unknown")])
def test_body_class(lengths, te, length, cls):
    assert rd.declared_length(lengths, te) == length
    assert rd.body_class(length) == cls


def test_a_grant_read_without_a_verifier():
    assert rd.grant_state([]) == "none"
    assert rd.grant_state(["anything signed"]) == "invalid"      # outside a gateway nothing can verify it
    assert rd.grant_state(["a", "b"]) == "invalid"


# ------------------------------------------------------------------------------------------- the policy
def test_demo_policy_compiles_to_the_shipped_image_and_is_registered():
    text = (POLICY / "demo.rules.md").read_text(encoding="utf-8")
    assert policy_source.compile_source(text) + b"\n" == (POLICY / "demo.core.json").read_bytes()
    assert causes.code("gateway:request-refused") == 131 and max(causes.CODES) == 134
    from prismpath.agent.policy import Policy
    assert sorted(Policy.load(POLICY / "demo.core.json").fields) == sorted(rd.FIELDS)


def test_demo_policy_decides_the_readings_it_is_written_for():
    from prismpath.agent.policy import Policy
    policy = Policy.load(POLICY / "demo.core.json")

    def kind(**kw):
        base = dict(zip(rd.FIELDS, (1, "read", "other", "none", "none", "none", "none")))
        base.update(kw)
        d = policy.decide(policy.reading_bytes(base))
        return d.kind, d.cause_code

    assert kind() == ("allow", None)
    assert kind(path_class="orders") == ("allow", None)
    assert kind(path_class="admin") == ("refuse", 131)
    assert kind(path_class="admin", grant="valid") == ("allow", None)          # a valid grant reads admin
    assert kind(path_class="admin", grant="expired") == ("refuse", 131)
    assert kind(path_class="admin", method_class="delete", grant="valid") == ("refuse", 131)
    assert kind(method_class="write", path_class="orders", body_class="small", content_class="json") == ("refuse", 131)
    assert kind(method_class="write", path_class="orders", body_class="small", content_class="json", grant="valid") == ("allow", None)
    assert kind(method_class="write", path_class="orders", body_class="small", content_class="form", grant="valid") == ("refuse", 131)
    assert kind(method_class="delete") == ("refuse", 131)
    for field in ("method_class", "path_class", "body_class", "content_class", "query"):
        assert kind(**{field: "unknown"}) == ("refuse", 131), field
    assert kind(body_class="oversize") == ("refuse", 131)
    assert kind(grant="invalid") == ("refuse", 131) and kind(grant="expired", path_class="orders") == ("allow", None)


# ---------------------------------------------------------------------------------------------- harness
class Upstream:
    """A stand-in service that records every request that reaches it."""

    def __init__(self, answer=b"order", status=200, delay=0.0):
        outer = self
        self.seen, self.answer, self.status, self.delay = [], answer, status, delay

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _do(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                outer.seen.append({"method": self.command, "target": self.path, "headers": {k.title(): v for k, v in self.headers.items()}, "body": body})
                if outer.delay:
                    time.sleep(outer.delay)
                self.send_response(outer.status)
                self.send_header("Content-Length", str(len(outer.answer)))
                self.send_header("Content-Type", "text/plain")
                self.send_header("Set-Cookie", "secret=1")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(outer.answer)

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _do

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class Running:
    def __init__(self, upstream, home, routes=ROUTES, **kw):
        self.gateway = proxy.Gateway(upstream.url, routes, home, session=kw.pop("session", "t1"), **kw)
        self.server = proxy.make_server(self.gateway, "127.0.0.1", 0)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def request(self, method, target, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, target, body=body, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def raw(self, data: bytes, wait=1.0, half_close=False) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(data)
            if half_close:
                s.shutdown(socket.SHUT_WR)
            s.settimeout(wait)
            out = b""
            try:
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    out += chunk
            except socket.timeout:
                pass
            return out

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "gwhome"
    assert gcli.init(h, None, out=open(os.devnull, "w")) == 0
    return h


@pytest.fixture
def upstream():
    up = Upstream()
    yield up
    up.close()


@pytest.fixture
def gw(upstream, home):
    g = Running(upstream, home)
    yield g
    g.close()


def receipts(home, session="t1"):
    run = RunStore(home / "runs").get(session)
    return [json.loads(line) for line in (run.dir / "journal.jsonl").read_text().splitlines()]


# --------------------------------------------------------------------------------------------- proxying
def test_allowed_request_reaches_the_upstream_and_the_answer_comes_back(gw, upstream, home):
    status, headers, body = gw.request("GET", "/api/orders/7?x=1", headers={
        "Accept": "text/plain", "Cookie": "s=1", "Authorization": "Bearer x", "X-PrismPath-Grant": "g", "X-Other": "1"})
    assert (status, body) == (403, body)      # a grant header that is not a signed grant is refused
    assert upstream.seen == []
    status, headers, body = gw.request("GET", "/api/orders/7?x=1", headers={
        "Accept": "text/plain", "Cookie": "s=1", "Authorization": "Bearer x", "X-Other": "1", "User-Agent": "ua"})
    assert (status, body) == (200, b"order")
    assert headers["X-PrismPath-Receipt"] == "1" and headers["X-PrismPath-Run"] == "t1"
    assert "Set-Cookie" not in headers                       # only the listed answer headers pass back
    (seen,) = upstream.seen
    assert seen["target"] == "/api/orders/7?x=1" and seen["method"] == "GET"
    assert seen["headers"]["Accept"] == "text/plain" and seen["headers"]["User-Agent"] == "ua"
    assert seen["headers"]["X-Prismpath-Receipt"] == "1"
    assert not {"Cookie", "Authorization", "X-Other", "X-Prismpath-Grant"} & set(seen["headers"])


def test_forward_header_is_passed_when_named(upstream, home):
    g = Running(upstream, home, forward_headers=["X-Request-Id"])
    try:
        g.request("GET", "/health", headers={"X-Request-Id": "abc", "Cookie": "no"})
    finally:
        g.close()
    assert upstream.seen[0]["headers"]["X-Request-Id"] == "abc" and "Cookie" not in upstream.seen[0]["headers"]


def test_refusal_is_a_403_with_the_registered_cause_and_the_receipt(gw, upstream):
    status, headers, body = gw.request("GET", "/admin/users")
    doc = json.loads(body)
    assert status == 403 and upstream.seen == []
    assert (doc["cause"], doc["code"], doc["decision"], doc["receipt"]) == ("gateway:request-refused", 131, "refuse", 0)
    assert headers["X-PrismPath-Cause"] == "131" and headers["X-PrismPath-Receipt"] == "0"


@pytest.mark.parametrize("method,target,body,headers", [
    ("DELETE", "/api/orders/1", None, {}),
    ("POST", "/api/orders/", b"{}", {"Content-Type": "application/json"}),          # needs a valid grant
    ("GET", "/api/orders/../admin/x", None, {}),
    ("GET", "/api/orders/%2e%2e/admin", None, {}),
    ("GET", "/api/orders/1", b"x", {}),                                              # a read with a body
])
def test_refused_requests_never_reach_the_upstream(gw, upstream, method, target, body, headers):
    status, _h, _b = gw.request(method, target, body, headers)
    assert status == 403 and upstream.seen == []


def test_a_repeated_content_type_or_grant_header_is_refused(gw, upstream):
    twice = b"GET /health HTTP/1.1\r\nHost: x\r\nContent-Type: a/b\r\nContent-Type: a/c\r\n\r\n"
    assert b"403 Forbidden" in gw.raw(twice)
    assert b"200 OK" in gw.raw(b"GET /health HTTP/1.1\r\nHost: x\r\nContent-Type: a/b\r\n\r\n")
    assert len(upstream.seen) == 1


def test_head_and_upstream_answer_framing(gw, upstream):
    status, headers, body = gw.request("HEAD", "/health")
    assert status == 200 and body == b"" and headers["Content-Length"] == "5"


def test_every_decision_is_a_receipt_and_the_run_verifies(gw, home, upstream):
    for target in ("/health", "/admin", "/api/orders/1", "/a/../b"):
        gw.request("GET", target)
    gw.close()
    rows = receipts(home)
    assert len(rows) == 4
    assert len(upstream.seen) == 2
    out = open(os.devnull, "w")
    assert gcli.verify(home, False, out=out) == 0
    report = []

    class Sink:
        def write(self, text):
            report.append(text)
    assert gcli.verify(home, True, out=Sink()) in (0, 1)
    doc = json.loads("".join(report))
    assert doc["verified"] and doc["runs"][0]["receipts"] == 4 and doc["runs"][0]["disagree"] == 0


def test_rules_report_counts_hits(gw, home):
    for target in ("/health", "/health", "/admin"):
        gw.request("GET", target)
    gw.close()
    data = []

    class Sink:
        def write(self, text):
            data.append(text)
    assert gcli.rules(home, True, out=Sink()) == 0
    doc = json.loads("".join(data))
    hits = {r["rule"]: r["hits"] for r in doc["rules"]}
    assert hits[6] == 2 and hits[2] == 1 and doc["receipts"]["counted"] == 3      # rule 6: a read of another path


# ---------------------------------------------------------------------------------------------- fail closed
def test_missing_policy_refuses_everything_without_a_receipt(upstream, tmp_path):
    g = Running(upstream, tmp_path / "nothing")
    try:
        status, _h, body = g.request("GET", "/health")
    finally:
        g.close()
    doc = json.loads(body)
    assert status == 403 and upstream.seen == [] and doc["receipt"] is None and doc["code"] == 131
    assert "policy" in doc["detail"] and "No receipt was written" in doc["detail"]


def test_a_policy_that_is_not_attested_or_not_the_gateways_refuses(upstream, home, tmp_path):
    (home / commands.POLICY_FILE).write_bytes((ROOT / "prismpath/agent/policy/agent_rules.core.json").read_bytes())
    g = Running(upstream, home)
    try:
        assert g.request("GET", "/health")[0] == 403
    finally:
        g.close()
    other = tmp_path / "h2"
    gcli.init(other, None, out=open(os.devnull, "w"))
    agent_image = (ROOT / "prismpath/agent/policy/agent_rules.core.json").read_bytes()
    with pytest.raises(commands.AgentError):
        gcli.init(other, str(ROOT / "prismpath/agent/policy/agent_rules.core.json"), out=open(os.devnull, "w"))
    assert agent_image                                                # an agent policy is not a gateway policy
    assert upstream.seen == []


def test_a_receipt_that_cannot_be_written_refuses(gw, upstream, monkeypatch):
    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(gw.gateway.run, "append", boom)
    status, _h, body = gw.request("GET", "/health")
    assert status == 403 and upstream.seen == [] and "receipt could not be written" in json.loads(body)["detail"]


def test_a_decision_that_fails_refuses(gw, upstream, monkeypatch):
    monkeypatch.setattr(gw.gateway.policy, "decide", lambda raw: (_ for _ in ()).throw(RuntimeError("x")))
    assert gw.request("GET", "/health")[0] == 403 and upstream.seen == []


def test_the_parser_refusing_a_request_reads_unknown_and_is_receipted(gw, upstream, home):
    out = gw.raw(b"GET /health HTTP/9.9\r\nHost: x\r\n\r\n") + gw.raw(b"NOT A REQUEST\r\n\r\n")
    assert out.count(b'"code":131') == 2 and upstream.seen == []
    assert b"403 Forbidden" in gw.raw(b"GET /health\r\n\r\n") and b"403 Forbidden" in gw.raw(b"GET /he", half_close=True)
    gw.close()
    rows = receipts(home)
    assert len(rows) == 4
    reading_doc = json.loads(bytes.fromhex(rows[0]["reading"]))
    assert reading_doc["method_class"] == "unknown" and reading_doc["path_class"] == "unknown"


def test_unsupported_method_and_chunked_bodies_are_refused(gw, upstream):
    assert b"403 Forbidden" in gw.raw(b"PURGE /health HTTP/1.1\r\nHost: x\r\n\r\n")
    chunked = b"POST /api/orders/ HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"
    assert b"403 Forbidden" in gw.raw(chunked)
    both = b"POST /api/orders/ HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}x"
    assert b"403 Forbidden" in gw.raw(both)
    assert upstream.seen == []


def test_an_oversize_body_is_never_read_or_forwarded(gw, upstream, home):
    head = f"POST /api/orders/ HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {rd.MAX_BODY + 1}\r\n\r\n".encode()
    out = gw.raw(head + b"x" * 1000)
    assert b"403 Forbidden" in out and upstream.seen == []
    gw.close()
    assert json.loads(bytes.fromhex(receipts(home)[0]["reading"]))["body_class"] == "oversize"


def test_a_short_body_is_refused(upstream, home):
    g = Running(upstream, home, timeout=0.5)
    try:
        out = g.raw(b"POST /api/orders/ HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 50\r\n\r\n{}", wait=3)
    finally:
        g.close()
    assert b"403 Forbidden" in out and upstream.seen == []


def test_a_silent_client_is_cut_off(upstream, home):
    g = Running(upstream, home, timeout=0.3)
    try:
        started = time.monotonic()
        out = g.raw(b"GET /health HTTP/1.1\r\nHost: x\r\n", wait=5)      # never finishes its headers
        assert time.monotonic() - started < 4 and upstream.seen == [] and b"200 OK" not in out
        assert g.request("GET", "/health")[0] == 200                      # and the gateway goes on
    finally:
        g.close()


def test_a_connection_open_too_long_is_cut_off(upstream, home):
    g = Running(upstream, home, timeout=30, deadline=0.5)
    try:
        started = time.monotonic()
        with socket.create_connection(("127.0.0.1", g.port), timeout=5) as s:
            s.sendall(b"GET /heal")
            s.settimeout(5)
            try:
                s.recv(10)
            except OSError:
                pass
        assert time.monotonic() - started < 3
    finally:
        g.close()


def test_connections_over_the_cap_get_a_503(upstream, home):
    g = Running(upstream, home, timeout=5, max_connections=1)
    try:
        hold = socket.create_connection(("127.0.0.1", g.port), timeout=5)
        hold.sendall(b"GET /he")
        time.sleep(0.2)
        assert b"503" in g.raw(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
        hold.close()
        time.sleep(0.2)
        assert g.request("GET", "/health")[0] == 200 and len(upstream.seen) == 1
    finally:
        g.close()


def test_upstream_down_is_a_502_with_its_receipt(home, upstream):
    port = upstream.port
    upstream.close()
    g = Running(upstream, home)
    try:
        status, _h, body = g.request("GET", "/health")
    finally:
        g.close()
    doc = json.loads(body)
    assert status == 502 and doc["decision"] == "allow" and doc["receipt"] == 0 and port


def test_an_upstream_answer_over_the_cap_is_a_502(home):
    up = Upstream(answer=b"x" * 5000)
    g = Running(up, home, max_response=1000)
    try:
        status, _h, body = g.request("GET", "/health")
    finally:
        g.close()
        up.close()
    assert status == 502 and b"x" * 100 not in body


def test_a_slow_upstream_is_a_502(home):
    up = Upstream(delay=1.5)
    g = Running(up, home, upstream_timeout=0.3)
    try:
        assert g.request("GET", "/health")[0] == 502
    finally:
        g.close()
        up.close()


def test_the_upstream_url_is_checked(home):
    for bad in ("ftp://x", "http://x/path", "http://u:p@x", "http://", "x"):
        with pytest.raises(ValueError):
            proxy.Gateway(bad, ROUTES, home)


# -------------------------------------------------------------------------------------------------- the CLI
def test_cli_serves_and_refuses_without_a_policy(upstream, tmp_path):
    env = dict(os.environ, PYTHONPATH=str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""),
               XDG_CONFIG_HOME=str(tmp_path / "cfg"))
    cmd = [sys.executable, "-m", "prismpath.cli", "gateway", "--upstream", upstream.url, "--listen", "127.0.0.1:0",
           "--home", str(tmp_path / "empty")]
    child = subprocess.Popen(cmd, env=env, stderr=subprocess.PIPE, text=True)
    try:
        lines = [child.stderr.readline(), child.stderr.readline()]
        text = "".join(lines)
        assert "every request will be refused" in text
        port = int(text.split("listening on 127.0.0.1:")[1].split()[0])
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/health")
        resp = conn.getresponse()
        assert resp.status == 403 and json.loads(resp.read())["receipt"] is None and upstream.seen == []
    finally:
        child.terminate()
        child.wait(timeout=10)


def test_cli_init_serve_verify_end_to_end(upstream, tmp_path):
    env = dict(os.environ, PYTHONPATH=str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""),
               XDG_CONFIG_HOME=str(tmp_path / "cfg"))
    base = [sys.executable, "-m", "prismpath.cli", "gateway", "--home", str(tmp_path / "h")]
    assert subprocess.run(base[:4] + ["init", "--home", str(tmp_path / "h")], env=env).returncode == 0
    child = subprocess.Popen(base + ["--upstream", upstream.url, "--listen", "127.0.0.1:0", "--session", "e2e",
                                     "--routes", str(POLICY / "demo.routes.json")], env=env, stderr=subprocess.PIPE, text=True)
    try:
        port = int(child.stderr.readline().split("listening on 127.0.0.1:")[1].split()[0])
        for target in ("/api/orders/1", "/admin/x"):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", target)
            conn.getresponse().read()
    finally:
        child.terminate()
        child.wait(timeout=10)
    done = subprocess.run(base + ["verify"], env=env, capture_output=True, text=True)
    assert done.returncode == 0 and "e2e: 2 receipts, 2 replayed" in done.stdout and "root statement signed" in done.stdout
    assert len(upstream.seen) == 1
