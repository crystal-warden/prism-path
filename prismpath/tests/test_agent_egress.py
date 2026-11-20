# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The egress proxy decides each CONNECT by name and port, resolves the name itself, refuses local results in
every spelling, bounds its input and its tunnels, logs every attempt, and writes only its socket and log. No test
resolves a real name or opens a real connection: a resolver override and a connect override stand in."""
import json
import os
import socket
import threading
import time

import pytest

from prismpath.agent import egress
from prismpath.agent.egress import EgressProxy, Refusal, parse_authority

PUBLIC = "93.184.216.34"


class Echo:
    """A plain TCP echo server on loopback standing in for the destination."""

    def __init__(self):
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(16)
        self.port = self.server.getsockname()[1]
        self.dialled = []
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                conn, _ = self.server.accept()
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


@pytest.fixture
def echo():
    server = Echo()
    yield server
    server.server.close()


def allow_api(host, port):
    """A test decider: the one name the tests dial. The proxy itself holds no allowlist."""
    return (True, "test-allow") if host == "api.anthropic.com" else (False, "host-not-allowed")


def make_proxy(tmp_path, echo, hosts=None, **kwargs):
    hosts = hosts if hosts is not None else {"api.anthropic.com": [PUBLIC]}
    kwargs.setdefault("decider", allow_api)
    dialled = []

    def resolver(name):
        if name not in hosts:
            raise OSError("no such name")
        return hosts[name]

    def connect(address, port, timeout):
        dialled.append((address, port))
        return socket.create_connection(("127.0.0.1", echo.port), timeout=timeout)

    sock_dir = tmp_path / "run"
    sock_dir.mkdir(exist_ok=True)
    proxy = EgressProxy(sock_dir / "e.sock", sock_dir / "e.log", resolver=resolver, connect=connect, **kwargs)
    proxy.dialled = dialled
    return proxy


def talk(proxy, request, read_all=True, timeout=5):
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(timeout)
    client.connect(proxy.socket_path)
    if request:
        client.sendall(request)
    return client


def answer(client):
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            chunk = client.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


def connect_line(target, method="CONNECT"):
    return f"{method} {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode()


def status(response):
    return int(response.split(b" ", 2)[1]) if response else None


def log_lines(proxy):
    with open(proxy.log_path) as handle:
        return [json.loads(line) for line in handle]


def wait_log(proxy, count=1):
    for _ in range(100):
        if os.path.exists(proxy.log_path) and len(log_lines(proxy)) >= count:
            return log_lines(proxy)
        time.sleep(0.02)
    return log_lines(proxy) if os.path.exists(proxy.log_path) else []


def test_an_allowed_host_tunnels_through_the_resolver_override(tmp_path, echo):
    with make_proxy(tmp_path, echo) as proxy:
        client = talk(proxy, connect_line("api.anthropic.com:443"))
        assert status(answer(client)) == 200
        client.sendall(b"hello through the tunnel")
        assert client.recv(100) == b"hello through the tunnel"
        client.close()
        assert proxy.dialled == [(PUBLIC, 443)]
        entry = wait_log(proxy)[0]
        assert (entry["host"], entry["port"], entry["decision"], entry["reason"]) == ("api.anthropic.com", 443, "allow", "test-allow")


def test_a_trailing_dot_and_upper_case_are_the_same_destination(tmp_path, echo):
    with make_proxy(tmp_path, echo) as proxy:
        client = talk(proxy, connect_line("API.Anthropic.COM.:443"))
        assert status(answer(client)) == 200
        client.close()
        assert wait_log(proxy)[0]["host"] == "api.anthropic.com"


def test_a_host_the_decider_does_not_allow_gets_403_with_a_reason(tmp_path, echo):
    with make_proxy(tmp_path, echo, hosts={"evil.example": [PUBLIC]}) as proxy:
        client = talk(proxy, connect_line("evil.example:443"))
        response = answer(client)
        assert status(response) == 403 and b"host-not-allowed" in client.recv(100) + response
        entry = wait_log(proxy)[0]
        assert (entry["host"], entry["decision"], entry["reason"]) == ("evil.example", "refuse", "host-not-allowed")
        assert proxy.dialled == []


def test_the_decider_is_the_callers_function(tmp_path, echo):
    seen = []

    def decider(host, port):
        seen.append((host, port))
        return host == "ok.example", "test-decider"

    with make_proxy(tmp_path, echo, hosts={"ok.example": [PUBLIC], "no.example": [PUBLIC]}, decider=decider) as proxy:
        assert status(answer(talk(proxy, connect_line("ok.example:443")))) == 200
        assert status(answer(talk(proxy, connect_line("no.example:443")))) == 403
    assert sorted(seen) == [("no.example", 443), ("ok.example", 443)]


def test_a_decider_that_raises_is_a_refusal(tmp_path, echo):
    def decider(host, port):
        raise RuntimeError("boom")

    with make_proxy(tmp_path, echo, decider=decider) as proxy:
        assert status(answer(talk(proxy, connect_line("api.anthropic.com:443")))) == 403
        assert wait_log(proxy)[0]["reason"] == "decider-error"


@pytest.mark.parametrize("address,reason", [
    ("127.0.0.1", "loopback-address"),
    ("::ffff:127.0.0.1", "loopback-address"),
    ("::ffff:7f00:1", "loopback-address"),
    ("::1", "loopback-address"),
    ("169.254.169.254", "link-local-address"),
    ("::ffff:169.254.169.254", "link-local-address"),
    ("fe80::1", "link-local-address"),
    ("10.1.2.3", "private-address"),
    ("192.168.0.9", "private-address"),
    ("172.16.5.5", "private-address"),
    ("::ffff:10.0.0.1", "private-address"),
    ("fd00::1", "private-address"),
    ("100.64.0.1", "non-global-address"),
    ("0.0.0.0", "private-address"),
    ("64:ff9b::7f00:1", "loopback-address"),
    ("2002:7f00:1::", "loopback-address"),
])
def test_a_name_resolving_to_a_local_address_is_refused(tmp_path, echo, address, reason):
    with make_proxy(tmp_path, echo, hosts={"api.anthropic.com": [address]}) as proxy:
        response = answer(talk(proxy, connect_line("api.anthropic.com:443")))
        assert status(response) == 403
        assert wait_log(proxy)[0]["reason"] == reason
        assert proxy.dialled == []


def test_one_bad_address_among_good_ones_refuses_the_name(tmp_path, echo):
    with make_proxy(tmp_path, echo, hosts={"api.anthropic.com": [PUBLIC, "127.0.0.1"]}) as proxy:
        assert status(answer(talk(proxy, connect_line("api.anthropic.com:443")))) == 403
        assert proxy.dialled == []


def test_a_name_that_does_not_resolve_is_502_and_logged_as_an_error(tmp_path, echo):
    with make_proxy(tmp_path, echo, hosts={}) as proxy:
        assert status(answer(talk(proxy, connect_line("api.anthropic.com:443")))) == 502
        assert wait_log(proxy)[0]["decision"] == "error"


def test_a_port_not_listed_is_refused_and_a_listed_one_is_served(tmp_path, echo):
    with make_proxy(tmp_path, echo) as proxy:
        assert status(answer(talk(proxy, connect_line("api.anthropic.com:8443")))) == 403
        assert wait_log(proxy)[0]["reason"] == "port-not-allowed"
    with make_proxy(tmp_path, echo, allowed_ports=(443, 8443)) as proxy:
        assert status(answer(talk(proxy, connect_line("api.anthropic.com:8443")))) == 200


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "DELETE", "OPTIONS", "connect"])
def test_a_method_other_than_connect_is_refused(tmp_path, echo, method):
    with make_proxy(tmp_path, echo) as proxy:
        response = answer(talk(proxy, f"{method} http://api.anthropic.com/ HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n".encode()))
        assert status(response) == 405
        assert proxy.dialled == []


@pytest.mark.parametrize("line", [
    b"CONNECT\r\n\r\n", b"CONNECT api.anthropic.com:443\r\n\r\n", b"CONNECT a b c d\r\n\r\n",
    b"CONNECT api.anthropic.com:443 SPDY/3\r\n\r\n", b"\r\n\r\n", b"\x00\x01\x02garbage\r\n\r\n",
    b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nbroken header line\r\n\r\n",
    b"CONNECT api.anthropic.com:443 HTTP/1.1\nHost: x\n\n\r\n\r\n",
    b"CONNECT \xff\xfe:443 HTTP/1.1\r\n\r\n",
])
def test_a_malformed_request_is_400_and_nothing_is_dialled(tmp_path, echo, line):
    with make_proxy(tmp_path, echo) as proxy:
        assert status(answer(talk(proxy, line))) == 400
        assert proxy.dialled == []


def test_an_oversized_header_is_431(tmp_path, echo):
    with make_proxy(tmp_path, echo, max_header=1024) as proxy:
        big = b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nX-Pad: " + b"a" * 5000 + b"\r\n\r\n"
        assert status(answer(talk(proxy, big))) == 431
        # and a head that never ends, with no terminator at all
        assert status(answer(talk(proxy, b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nX: " + b"b" * 5000))) == 431
        assert proxy.dialled == []


def test_a_slow_client_times_out_with_408(tmp_path, echo):
    with make_proxy(tmp_path, echo, header_timeout=0.4) as proxy:
        client = talk(proxy, b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n")
        start = time.monotonic()
        assert status(answer(client)) == 408
        assert time.monotonic() - start < 3
        # a trickle that keeps sending does not extend the deadline
        client = talk(proxy, b"")
        start = time.monotonic()
        for byte in b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nX: ":
            try:
                client.sendall(bytes([byte]))
            except OSError:
                break
            time.sleep(0.05)
        assert status(answer(client)) == 408
        assert time.monotonic() - start < 3


def test_too_many_concurrent_connections_get_503_and_a_slot_frees_on_close(tmp_path, echo):
    with make_proxy(tmp_path, echo, max_connections=2) as proxy:
        held = [talk(proxy, connect_line("api.anthropic.com:443")) for _ in range(2)]
        for client in held:
            assert status(answer(client)) == 200
        extra = talk(proxy, connect_line("api.anthropic.com:443"))
        assert status(answer(extra)) == 503
        held[0].close()
        for _ in range(100):
            again = talk(proxy, connect_line("api.anthropic.com:443"))
            if status(answer(again)) == 200:
                break
            time.sleep(0.05)
        else:
            pytest.fail("the slot never came back")
        assert any(entry["reason"] == "too-many-connections" for entry in wait_log(proxy, 4))


def test_an_idle_tunnel_is_closed(tmp_path, echo):
    with make_proxy(tmp_path, echo, idle_timeout=0.3) as proxy:
        client = talk(proxy, connect_line("api.anthropic.com:443"))
        assert status(answer(client)) == 200
        start = time.monotonic()
        assert client.recv(10) == b""
        assert time.monotonic() - start < 3


def test_the_process_writes_only_its_socket_and_log(tmp_path, echo, monkeypatch):
    home = tmp_path / "home"
    cwd = tmp_path / "cwd"
    tmpdir = tmp_path / "tmp"
    for folder in (home, cwd, tmpdir):
        folder.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("TMPDIR", str(tmpdir))

    def snapshot(root):
        found = {}
        for base, dirs, files in os.walk(root):
            for name in dirs + files:
                path = os.path.join(base, name)
                found[path] = os.lstat(path).st_mtime_ns
        return found

    before = {folder: snapshot(folder) for folder in (home, cwd, tmpdir)}
    with make_proxy(tmp_path, echo, hosts={"api.anthropic.com": [PUBLIC], "x.example": ["127.0.0.1"]}) as proxy:
        for target in ("api.anthropic.com:443", "x.example:443", "GET"):
            client = talk(proxy, connect_line(target) if target != "GET" else connect_line("a:1", method="GET"))
            answer(client)
            client.close()
        wait_log(proxy, 3)
        run = os.path.dirname(proxy.socket_path)
        assert sorted(os.listdir(run)) == ["e.log", "e.sock"]
        assert os.stat(proxy.socket_path).st_mode & 0o777 == 0o600
    assert {folder: snapshot(folder) for folder in (home, cwd, tmpdir)} == before
    assert sorted(os.listdir(run)) == ["e.log"]


def test_start_refuses_to_replace_a_file_that_is_not_a_socket(tmp_path, echo):
    victim = tmp_path / "precious"
    victim.write_text("keep")
    proxy = EgressProxy(victim, tmp_path / "log")
    with pytest.raises(FileExistsError):
        proxy.start()
    assert victim.read_text() == "keep"


def test_the_proxy_holds_no_allowlist_and_refuses_everything_without_a_decision(tmp_path, echo):
    assert not hasattr(egress, "INTERIM_ALLOWLIST") and not hasattr(egress, "interim_decider")
    with make_proxy(tmp_path, echo, decider=egress.refuse_all) as proxy:
        client = talk(proxy, connect_line("api.anthropic.com:443"))
        assert status(answer(client)) == 403
        assert wait_log(proxy)[0]["reason"] == "no-decider"
