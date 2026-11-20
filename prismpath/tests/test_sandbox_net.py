# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Profile.net: the proxy states reach one unix socket through a relay and nothing else, and have no route."""
import os
import shutil
import socket
import tempfile
import threading

import pytest

from prismpath.agent import sandbox_exec
from prismpath.agent.profile import Profile, ProfileError, STRICTEST
from prismpath.agent.sandbox_exec import SandboxUnavailable, bwrap_argv, profile_from_json, run_sandboxed
from prismpath.tests.test_sandbox_exec import needs_bwrap

needs_socat = pytest.mark.skipif(not os.access(sandbox_exec.RELAY, os.X_OK), reason="no socat")
STARTER_HASH = "767dd3c8"


def _pump(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass


def _serve_proxy(listener):
    """A stand-in CONNECT proxy: reads the request line, opens the named TCP connection, relays bytes."""
    while True:
        try:
            client, _ = listener.accept()
        except OSError:
            return

        def handle(client=client):
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = client.recv(4096)
                if not chunk:
                    client.close()
                    return
                head += chunk
            host, _, port = head.split(b" ")[1].decode().rpartition(":")
            try:
                upstream = socket.create_connection((host, int(port)), timeout=5)
            except OSError:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                client.close()
                return
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            threading.Thread(target=_pump, args=(client, upstream), daemon=True).start()
            _pump(upstream, client)
        threading.Thread(target=handle, daemon=True).start()


@pytest.fixture
def world():
    """A workspace and proxy socket under /var/tmp (the sandbox must see them), and a TCP server on the host."""
    root = tempfile.mkdtemp(dir="/var/tmp", prefix="pp-net-")
    sock_path = os.path.join(root, "egress.sock")
    workspace = os.path.join(root, "ws")
    os.mkdir(workspace)
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(sock_path)
    listener.listen(8)
    threading.Thread(target=_serve_proxy, args=(listener,), daemon=True).start()
    server = socket.socket()
    server.bind(("0.0.0.0", 0))
    server.listen(4)

    def answer():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            conn.sendall(b"hello from the host\n")
            conn.close()
    threading.Thread(target=answer, daemon=True).start()
    yield workspace, sock_path, server.getsockname()[1]
    listener.close()
    server.close()
    shutil.rmtree(root, ignore_errors=True)


def _host_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
        return ip if not ip.startswith("127.") else "10.255.255.1"
    except OSError:
        return "10.255.255.1"


VIA_PROXY = """
import socket, sys
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", 3128), timeout=5)
s.sendall(f"CONNECT 127.0.0.1:{port} HTTP/1.1\\r\\nHost: 127.0.0.1:{port}\\r\\n\\r\\n".encode())
buf = b""
while b"\\r\\n\\r\\n" not in buf:
    buf += s.recv(4096)
assert b" 200 " in buf.split(b"\\r\\n")[0], buf
data = b""
while True:
    c = s.recv(4096)
    if not c:
        break
    data += c
print(data.decode().strip())
"""


def test_net_none_keeps_the_canonical_bytes_and_the_starter_hash():
    assert "net" not in STRICTEST.to_object()
    assert STRICTEST.hash().startswith(STARTER_HASH)
    assert Profile(net="proxy_model").hash() != STRICTEST.hash()
    assert profile_from_json(Profile(net="proxy_allow").canonical().decode()).net == "proxy_allow"
    assert profile_from_json(STRICTEST.canonical().decode()) == STRICTEST


def test_bad_net_states_and_a_proxy_with_the_host_network_are_refused():
    with pytest.raises(ProfileError):
        Profile(net="open")
    with pytest.raises(ProfileError):
        Profile(net="proxy_model", network=True)


def test_a_proxy_profile_without_a_socket_is_not_run(tmp_path):
    with pytest.raises(SandboxUnavailable):
        bwrap_argv(tmp_path, Profile(net="proxy_model"), ["/usr/bin/true"])


@pytest.mark.parametrize("state", ["proxy_model", "proxy_allow"])
def test_the_proxy_states_never_share_the_host_network(tmp_path, state):
    argv = bwrap_argv(tmp_path, Profile(net=state), ["/usr/bin/true"], proxy_socket=str(tmp_path))
    assert "--share-net" not in argv and "--unshare-all" in argv
    assert "HTTPS_PROXY" in argv and "https_proxy" in argv


@needs_bwrap
@needs_socat
@pytest.mark.parametrize("state", ["proxy_model", "proxy_allow"])
def test_the_proxy_reaches_the_server_and_nothing_else_does(world, state):
    workspace, sock, port = world
    profile = Profile(net=state, timeout_s=30)

    def run(code, *args):
        return run_sandboxed(["/usr/bin/python3", "-c", code, *args], workspace, profile, proxy_socket=sock)

    done = run(VIA_PROXY, str(port))
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == b"hello from the host"

    raw = run("import socket,sys\ntry:\n socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3)\n"
              "except OSError as e:\n print(e.errno)\n sys.exit(3)", _host_ip(), str(port))
    assert raw.returncode == 3 and raw.stdout.strip() == b"101"       # ENETUNREACH: no route

    loop = run("import socket,sys\ntry:\n socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=3)\n"
               "except OSError:\n sys.exit(3)", str(port))
    assert loop.returncode == 3                                          # the host's loopback is not the sandbox's

    dns = run("import socket,sys\ntry:\n socket.getaddrinfo('example.com', 443)\nexcept OSError:\n sys.exit(3)")
    assert dns.returncode == 3

    env = run("import os; print(os.environ['HTTPS_PROXY'], os.environ['https_proxy'])")
    assert env.stdout.split() == [b"http://127.0.0.1:3128"] * 2


@needs_bwrap
def test_the_tracer_path_with_net_none_is_unchanged(tmp_path):
    done = run_sandboxed(["/usr/bin/python3", "-c", "import os; print(os.environ.get('HTTPS_PROXY'))"], tmp_path)
    assert done.stdout.strip() == b"None"
