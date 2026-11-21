# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""prismpath agent run: the launcher stages, confines, runs a stand-in program and tears everything down.

The stand-in is a small python script. It talks HTTPS through HTTPS_PROXY to a local TLS stub that plays the
model API, reached through the proxy's resolver and connect overrides, so no name is resolved and no real
network is used. Nothing here reads or uses a real login or API key. Paths the sandbox must see are under /var/tmp."""
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from prismpath.agent import commands, launcher, sandbox_exec
from prismpath.tests.test_sandbox_exec import needs_bwrap

needs_socat = pytest.mark.skipif(not os.access(sandbox_exec.RELAY, os.X_OK), reason="no socat")
needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="no openssl")
PUBLIC = "93.184.216.34"
PYTHON = "/usr/bin/python3"
MARKER = "300.7311"

STAND_IN = r'''
import json, os, socket, ssl, subprocess, sys
out = {}
def attempt(name, fn):
    try:
        out[name] = fn()
    except BaseException as exc:
        out[name] = "fail: " + type(exc).__name__
def write(path, text="x"):
    def go():
        with open(path, "w") as handle:
            handle.write(text)
        return "wrote"
    return go
def connect(host):
    proxy = os.environ["HTTPS_PROXY"].split("//")[1].rsplit(":", 1)
    s = socket.create_connection((proxy[0], int(proxy[1])), timeout=5)
    s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    return s, buf.split(b"\r\n")[0].decode()
def model():
    s, status = connect("api.anthropic.com")
    assert " 200 " in status, status
    ctx = ssl.create_default_context(cafile="ca.pem")
    t = ctx.wrap_socket(s, server_hostname="api.anthropic.com")
    t.sendall(b"GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nConnection: close\r\n\r\n")
    data = b""
    while True:
        c = t.recv(4096)
        if not c:
            break
        data += c
    return data.split(b"\r\n\r\n", 1)[1].decode()
def refused():
    return connect("evil.example")[1]
def raw():
    socket.create_connection(("%s", 443), timeout=3).close()
    return "connected"
cfg = os.environ["CLAUDE_CONFIG_DIR"]
attempt("model", model)
attempt("refused_host", refused)
attempt("raw_connect", raw)
attempt("write_settings", write(cfg + "/settings.json"))
attempt("unlink_settings", lambda: os.unlink(cfg + "/settings.json"))
attempt("write_local_settings", write(".claude/settings.local.json"))
attempt("write_normal", write("normal.txt", "hello"))
attempt("write_mcp", write(".mcp.json"))
attempt("write_claude_md", write("CLAUDE.md"))
for extra in sys.argv[1:]:
    attempt("extra:" + extra, write(extra))
out["settings"] = json.load(open(cfg + "/settings.json"))
out["env"] = {k: os.environ.get(k) for k in ("HOME", "CLAUDE_CONFIG_DIR", "DISABLE_AUTOUPDATER",
              "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "ENABLE_CLAUDEAI_MCP_SERVERS")}
out["credential_present"] = os.path.exists(cfg + "/.credentials.json")
if out["credential_present"]:
    out["credential"] = open(cfg + "/.credentials.json").read()
    attempt("write_credential", write(cfg + "/.credentials.json"))
subprocess.Popen(["/usr/bin/sleep", "%s"])
json.dump(out, open("out.json", "w"))
sys.exit(7)
''' % (PUBLIC, MARKER)


def _make_ca(directory: Path):
    cert, key = directory / "ca.pem", directory / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "2", "-subj", "/CN=api.anthropic.com",
                    "-addext", "subjectAltName=DNS:api.anthropic.com"], check=True, capture_output=True)
    return cert, key


@pytest.fixture(scope="module")
def agent_home(tmp_path_factory):
    """A recorded policy (keys, starter, attestation) in a home of its own, so `launch` never reads the real one."""
    home = tmp_path_factory.mktemp("agent-home")
    saved = {k: os.environ.get(k) for k in ("HOME", "XDG_CONFIG_HOME", "APPDATA")}
    os.environ["HOME"] = str(home)
    os.environ.pop("XDG_CONFIG_HOME", None)
    os.environ.pop("APPDATA", None)
    try:
        assert commands.init(home, yes=True, as_json=False, out=open(os.devnull, "w")) == 0
        yield home
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@pytest.fixture(autouse=True)
def use_agent_home(agent_home, monkeypatch):
    monkeypatch.setenv("HOME", str(agent_home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("APPDATA", raising=False)


@pytest.fixture
def world():
    root = Path(tempfile.mkdtemp(dir="/var/tmp", prefix="pp-launch-"))
    workspace, stages = root / "ws", root / "stages"
    workspace.mkdir()
    stages.mkdir()
    (workspace / "agent.py").write_text(STAND_IN)
    yield workspace, stages, root
    shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def stub(world):
    """A TLS server standing in for the model API; yields its port."""
    workspace, _stages, root = world
    cert, key = _make_ca(root)
    shutil.copy(cert, workspace / "ca.pem")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(4096)
                    body = b"stub model says ok"
                    tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
            except (OSError, ssl.SSLError):
                pass
    threading.Thread(target=serve, daemon=True).start()
    yield server.getsockname()[1]
    server.close()


def _launch(world, stub_port, *args, **kwargs):
    workspace, stages, root = world
    log = root / "egress.log"
    kwargs.setdefault("egress_log", str(log))
    code = launcher.launch([PYTHON, "agent.py", *args], str(workspace), stage_base=str(stages),
                           resolver=lambda name: [PUBLIC],
                           connect=lambda address, port, timeout: socket.create_connection(("127.0.0.1", stub_port), timeout=timeout),
                           **kwargs)
    return code, json.loads((workspace / "out.json").read_text()), log


def _processes_with(text: str):
    found = []
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                if text.encode() in Path(f"/proc/{entry}/cmdline").read_bytes():
                    found.append(int(entry))
            except OSError:
                pass
    return found


@needs_bwrap
@needs_socat
@needs_openssl
def test_the_stand_in_reaches_the_stub_through_the_proxy_and_is_confined(world, stub):
    workspace, stages, _root = world
    code, out, log = _launch(world, stub)
    assert code == 7                                                # the program's own status
    assert out["model"] == "stub model says ok"                     # HTTPS over CONNECT to the stub
    assert "403" in out["refused_host"]                             # a host the allowlist lacks
    assert out["raw_connect"].startswith("fail")                    # no route but the relay
    assert out["write_settings"].startswith("fail")                 # the staged settings.json is read only
    assert out["unlink_settings"].startswith("fail")
    assert out["write_local_settings"].startswith("fail")           # .claude is a read only bind
    assert out["write_mcp"].startswith("fail") and out["write_claude_md"].startswith("fail")
    assert out["write_normal"] == "wrote" and (workspace / "normal.txt").read_text() == "hello"
    assert out["credential_present"] is False                       # off unless a file is named
    assert out["env"] == {"HOME": "/home/agent", "CLAUDE_CONFIG_DIR": "/home/agent/.claude", "DISABLE_AUTOUPDATER": "1",
                          "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "ENABLE_CLAUDEAI_MCP_SERVERS": "false"}
    hooks = out["settings"]["hooks"]
    assert set(hooks) == {"PreToolUse", "SessionEnd", "PostToolUse", "PostToolUseFailure"}
    assert all(h["command"] == launcher.client_hook_command() for event in hooks.values() for g in event for h in g["hooks"])
    decisions = [(json.loads(line)["host"], json.loads(line)["decision"]) for line in log.read_text().splitlines()]
    assert ("api.anthropic.com", "allow") in decisions and ("evil.example:443", "refuse") in decisions
    # the proxy's decisions are receipts of a run the policy decided, sealed at exit, and they verify
    home = commands.config_dir()
    _policy, store = commands.load_checked(home)
    egress_runs = [r for r in store.runs() if r.session.startswith("egress-")]
    assert len(egress_runs) == 1 and not egress_runs[0].is_open()
    summary = egress_runs[0].verify(home)
    assert summary["receipts"] == 2 and summary["disagree"] == 0
    # torn down: the staged directory (and with it the proxy socket) is gone, no child survives, no litter
    assert list(stages.iterdir()) == []
    assert _processes_with(MARKER) == []
    for name in (".claude", ".mcp.json", "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md"):
        assert not (workspace / name).exists()


@needs_bwrap
@needs_socat
@needs_openssl
def test_without_an_egress_log_path_the_log_is_kept_in_the_egress_run_directory(world, stub):
    code, _out, _log = _launch(world, stub, egress_log=None)
    assert code == 7
    _policy, store = commands.load_checked(commands.config_dir())
    egress_run = max((r for r in store.runs() if r.session.startswith("egress-") and (r.dir / launcher.EGRESS_LOG_NAME).exists()),
                     key=lambda r: r.session)
    kept = egress_run.dir / launcher.EGRESS_LOG_NAME
    decisions = [(json.loads(line)["host"], json.loads(line)["decision"]) for line in kept.read_text().splitlines()]
    assert ("evil.example:443", "refuse") in decisions
    assert egress_run.verify(commands.config_dir())["disagree"] == 0          # the extra file does not disturb the seal


@needs_bwrap
@needs_socat
@needs_openssl
def test_existing_control_paths_are_read_only_and_kept(world, stub):
    workspace, _stages, _root = world
    (workspace / ".claude").mkdir()
    (workspace / ".claude" / "settings.json").write_text("{}")
    (workspace / "sub").mkdir()
    (workspace / "sub" / "claude.md").write_text("notes")
    (workspace / ".git" / "hooks").mkdir(parents=True)
    (workspace / ".git" / "config").write_text("[core]\n")
    extra = [".claude/settings.json", ".claude/new.json", "sub/claude.md", ".git/config", ".git/hooks/pre-commit", "sub/other.txt"]
    code, out, _log = _launch(world, stub, *extra)
    refused = [e for e in extra if out["extra:" + e].startswith("fail")]
    assert refused == extra[:5]
    assert out["extra:sub/other.txt"] == "wrote"
    assert (workspace / ".claude" / "settings.json").read_text() == "{}"      # what was there stays
    assert (workspace / "sub" / "claude.md").read_text() == "notes"
    assert (workspace / ".git" / "config").read_text() == "[core]\n"


@needs_bwrap
@needs_socat
@needs_openssl
def test_a_named_credential_is_copied_read_only_and_removed_after(world, stub, tmp_path):
    workspace, stages, root = world
    fake = root / "fake-credential.json"
    fake.write_text('{"fake": "not a real login"}')
    _code, out, _log = _launch(world, stub, credential=str(fake))
    assert out["credential_present"] is True and out["credential"] == fake.read_text()
    assert out["write_credential"].startswith("fail")
    assert list(stages.iterdir()) == []                      # the copy went with the staged directory
    assert fake.read_text() == '{"fake": "not a real login"}'


@needs_bwrap
@needs_socat
def test_a_program_outside_the_system_prefix_is_pinned_at_its_real_path_and_runs(world):
    workspace, stages, root = world
    copy = root / "mytouch"
    shutil.copy("/usr/bin/touch", copy)
    link = workspace / "alias"
    link.symlink_to(copy)                                    # resolved once, on the host
    inside, binds = launcher.pin_program(launcher.resolve_program(str(link)), ("/usr",))
    assert (inside, binds) == ("/opt/agent/mytouch", [(str(copy), "/opt/agent/mytouch")])
    assert launcher.pin_program("/usr/bin/python3.12", ("/usr",)) == ("/usr/bin/python3.12", [])
    code = launcher.launch([str(link), str(workspace / "marker")], str(workspace), stage_base=str(stages))
    assert code == 0 and (workspace / "marker").exists()


@needs_bwrap
@needs_socat
def test_the_exit_status_of_a_failing_program_is_passed_on_and_teardown_still_runs(world):
    workspace, stages, _root = world
    code = launcher.launch([PYTHON, "-c", "import sys; sys.exit(3)"], str(workspace), stage_base=str(stages))
    assert code == 3 and list(stages.iterdir()) == [] and list(workspace.iterdir()) == [workspace / "agent.py"]


@needs_bwrap
@needs_socat
def test_no_recorded_policy_runs_nothing(world, monkeypatch, tmp_path):
    workspace, stages, _root = world
    monkeypatch.setenv("HOME", str(tmp_path / "empty-home"))
    with pytest.raises(launcher.LaunchError, match="agent init"):
        launcher.launch([PYTHON, "-c", "open('ran', 'w')"], str(workspace), stage_base=str(stages))
    assert not (workspace / "ran").exists() and list(stages.iterdir()) == [] and not (workspace / ".claude").exists()


@needs_bwrap
@needs_socat
def test_a_policy_with_no_model_route_runs_nothing(world, monkeypatch):
    workspace, stages, _root = world
    monkeypatch.setattr(launcher, "compile_profile", lambda image, role: launcher.Profile(net="none"))
    with pytest.raises(launcher.LaunchError, match="allows no connection to the model API"):
        launcher.launch([PYTHON, "-c", "open('ran', 'w')"], str(workspace), stage_base=str(stages))
    assert not (workspace / "ran").exists() and list(stages.iterdir()) == [] and not (workspace / ".claude").exists()


def test_missing_bwrap_is_an_error_and_nothing_runs(world, monkeypatch):
    workspace, stages, _root = world
    monkeypatch.setattr(sandbox_exec, "BWRAP", "/nonexistent/bwrap")
    with pytest.raises(launcher.LaunchError, match="bubblewrap"):
        launcher.launch([PYTHON, "-c", "open('ran', 'w')"], str(workspace), stage_base=str(stages))
    assert not (workspace / "ran").exists() and list(stages.iterdir()) == []
    assert not (workspace / ".claude").exists()              # nothing was prepared in the workspace either


def test_missing_socat_is_an_error_and_nothing_runs(world, monkeypatch):
    workspace, stages, _root = world
    monkeypatch.setattr(sandbox_exec, "RELAY", "/nonexistent/socat")
    with pytest.raises(launcher.LaunchError, match="socat"):
        launcher.launch([PYTHON, "-c", "open('ran', 'w')"], str(workspace), stage_base=str(stages))
    assert not (workspace / "ran").exists() and list(stages.iterdir()) == []


def test_off_linux_is_an_error_and_nothing_runs(world, monkeypatch):
    workspace, stages, _root = world
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(launcher.LaunchError, match="Linux only"):
        launcher.launch([PYTHON, "-c", "open('ran', 'w')"], str(workspace), stage_base=str(stages))
    assert not (workspace / "ran").exists() and list(stages.iterdir()) == []


@needs_bwrap
@needs_socat
def test_a_program_that_is_not_found_or_a_credential_that_is_not_a_file_runs_nothing(world):
    workspace, stages, root = world
    with pytest.raises(launcher.LaunchError, match="not found"):
        launcher.launch(["no-such-program-pp"], str(workspace), stage_base=str(stages))
    with pytest.raises(launcher.LaunchError, match="not a file"):
        launcher.launch([PYTHON, "-c", "open('ran', 'w')"], str(workspace), stage_base=str(stages),
                        credential=str(root / "missing.json"))
    assert not (workspace / "ran").exists() and list(stages.iterdir()) == []


@needs_bwrap
@needs_socat
def test_the_cli_wiring_passes_the_program_after_double_dash(world, monkeypatch, capsys):
    import io
    from prismpath import cli
    from prismpath.agent import commands
    workspace, _stages, root = world
    monkeypatch.setenv("HOME", str(root / "home"))                 # `agent run` needs the recorded keys and policy
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    commands.init(workspace, True, False, out=io.StringIO())
    code = cli.main(["agent", "run", "--workspace", str(workspace), "--egress-log", str(root / "e.log"), "--",
                     PYTHON, "-c", "import sys; open('cli-ran', 'w').write(' '.join(sys.argv[1:])); sys.exit(4)", "a", "--b"])
    assert code == 4 and (workspace / "cli-ran").read_text() == "a --b"


def test_prepare_controls_creates_what_is_missing_and_never_a_git_directory(tmp_path):
    controls = launcher.Controls()
    launcher.prepare_controls(tmp_path, controls)
    names = sorted(os.path.relpath(p, tmp_path) for p in controls.binds)
    assert names == [".claude", ".mcp.json", "AGENTS.md", "CLAUDE.local.md", "CLAUDE.md"]
    assert not (tmp_path / ".git").exists()
    controls.remove_created()
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------------- the local model route
MODEL_STAND_IN = r'''
import json, socket, sys, urllib.request
out = {}
def attempt(name, fn):
    try:
        out[name] = fn()
    except BaseException as exc:
        out[name] = "fail: " + type(exc).__name__
def get(port):
    return urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/models", timeout=5).read().decode()
def raw(host, port):
    socket.create_connection((host, port), timeout=3).close()
    return "connected"
good, other = int(sys.argv[1]), int(sys.argv[2])
attempt("model", lambda: get(good))
attempt("model_again", lambda: get(good))
attempt("other_local_port", lambda: get(other))
attempt("raw_to_host_port", lambda: raw("127.0.0.1", other))
attempt("raw_outside", lambda: raw("%s", 8888))
json.dump(out, open("out.json", "w"))
''' % PUBLIC


def _http_stub(body: bytes):
    """A plain HTTP server on a host port; yields (port, hits)."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    hits = []

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                request = conn.recv(4096)
                hits.append(request.split(b"\r\n")[0])
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
    threading.Thread(target=serve, daemon=True).start()
    return server, hits


def _model_run(world, good_port, other_port, **kwargs):
    workspace, stages, root = world
    (workspace / "model.py").write_text(MODEL_STAND_IN)
    log = root / "egress.log"
    code = launcher.launch([PYTHON, "model.py", str(good_port), str(other_port)], str(workspace), stage_base=str(stages),
                           egress_log=str(log), **kwargs)
    return code, json.loads((workspace / "out.json").read_text()), log


@needs_bwrap
@needs_socat
def test_the_local_model_route_reaches_only_its_one_host_and_port(world):
    good, good_hits = _http_stub(b"model one")
    other, other_hits = _http_stub(b"model two")
    good_port = good.getsockname()[1]
    try:
        code, out, log = _model_run(world, good_port, other.getsockname()[1], local_model=f"http://localhost:{good_port}")
    finally:
        good.close()
        other.close()
    assert code == 0
    assert out["model"] == "model one" and out["model_again"] == "model one"     # through the route, twice
    assert out["other_local_port"].startswith("fail")                             # a different host port is not reachable
    assert out["raw_to_host_port"].startswith("fail")                             # no raw loopback to the host either
    assert out["raw_outside"].startswith("fail")
    assert len(good_hits) == 2 and other_hits == []
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    assert [r["route"] for r in rows] == ["local-model", "local-model"]
    assert all(r["decision"] == "allow" and r["port"] == good_port for r in rows)
    assert list(world[1].iterdir()) == []                                         # the route's socket went with the stage


@needs_bwrap
@needs_socat
def test_without_the_option_there_is_no_model_route(world):
    good, good_hits = _http_stub(b"model one")
    try:
        _code, out, _log = _model_run(world, good.getsockname()[1], good.getsockname()[1])
    finally:
        good.close()
    assert out["model"].startswith("fail") and good_hits == []


def test_a_bad_local_model_target_or_port_clash_starts_nothing(world):
    workspace, stages, _root = world
    for target in ("https://localhost:8888", "http://localhost", "http://u:p@localhost:8888", "http://localhost:8888/v1",
                   "http://localhost:3128"):
        with pytest.raises(launcher.LaunchError):
            launcher.launch([PYTHON, "-c", "pass"], str(workspace), stage_base=str(stages), local_model=target)
    assert list(stages.iterdir()) == []


def test_parse_target():
    from prismpath.agent import local_route
    assert local_route.parse_target("http://localhost:8888") == ("localhost", 8888)
    assert local_route.parse_target("127.0.0.1:9000/") == ("127.0.0.1", 9000)
    with pytest.raises(local_route.RouteError):
        local_route.parse_target("http://localhost:99999")
