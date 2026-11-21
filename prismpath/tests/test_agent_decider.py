# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The decider and the thin hook client.

Host side: every recorded hook input goes through the client and a decider and gets the answer and the receipt
that `prismpath agent hook` gives, The client fails closed, and the
decider survives bad requests. Sandbox side: under the launcher a stand-in program runs the client command from
the staged settings.json and gets decisions, and cannot read the keys, the policy or the journal.
Nothing reads a real login or key; the keys here are made fresh in a throwaway HOME. Paths the sandbox must see
are under /var/tmp."""
import ast
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath.agent import commands, decider as decider_module, hook_client, launcher, run as run_module  # noqa: E402
from prismpath.kernel import causes  # noqa: E402
from prismpath.tests import test_agent_cli as cli_tests  # noqa: E402
from prismpath.tests.test_sandbox_exec import needs_bwrap  # noqa: E402
from prismpath.tests.test_agent_launcher import needs_socat  # noqa: E402

CLIENT = Path(hook_client.__file__)
HOOK_ERROR_CODE = causes.code("agent:hook-error")
REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _no_real_config_dir(monkeypatch):
    """The config directory comes from HOME only: GitHub's runners set XDG_CONFIG_HOME, which config_dir prefers, so
    a copy of os.environ with HOME swapped would still find the runner's own (empty) config directory."""
    for name in ("XDG_CONFIG_HOME", "APPDATA"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture()
def world(tmp_path):
    root = Path(tempfile.mkdtemp(dir="/var/tmp", prefix="pp-decider-"))
    home_a, home_b = root / "homeA", root / "homeB"
    for home in (home_a, home_b):
        (home / "tmp").mkdir(parents=True)
    ws, decoy = root / "ws", root / "decoy"
    for directory in (ws / "src", ws / "logs", ws / "build", ws / ".toolchain" / "bin", ws / ".toolchain" / "lib",
                      decoy / "old_build"):
        directory.mkdir(parents=True, exist_ok=True)
    for path, text in {ws / "README.md": "# demo\n", ws / "notes.txt": "first note\nsecond note\n",
                       ws / "src" / "app.py": "# TODO\n", ws / "scratch.tmp": "s\n", decoy / "sentinel.txt": "s\n"}.items():
        path.write_text(text)
    os.symlink(decoy, ws / "link_out")
    os.symlink(decoy / "sentinel.txt", ws / "cfg")
    os.symlink("notes.txt", ws / "inner_link")
    yield {"home": home_a, "home_b": home_b, "ws": str(ws.resolve()), "decoy": str(decoy.resolve()), "root": root}
    shutil.rmtree(root, ignore_errors=True)


def _client(sock, raw, timeout=60):
    done = subprocess.run([sys.executable, "-I", str(CLIENT), str(sock)], input=raw, capture_output=True, timeout=timeout)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def _entries(home, session="s1"):
    run = run_module.Run.existing(commands.config_dir({"HOME": str(home)}) / commands.RUNS_DIR, session)
    return [{k: v for k, v in e.items() if k != "sandbox"} for e in run._entries()]


def _comparable(answer, from_cli):
    out = json.loads(json.dumps(answer))["hookSpecificOutput"]
    out.pop("updatedInput", None)
    reason = out.get("permissionDecisionReason")
    if reason is not None:
        reason = reason.replace(" If you approve it, it runs inside the PrismPath sandbox.", "")
        out["permissionDecisionReason"] = reason
    out = {k: v for k, v in out.items() if not (k == "permissionDecisionReason" and v is None)}
    return out


# ------------------------------------------------------------------------------- the corpus, same answers
def test_every_recorded_hook_input_gets_the_cli_answer_and_receipt_through_the_client(world):
    cli_tests._init(world)                                      # home A: the stdin hook
    done = cli_tests._cli(world["home_b"], "agent", "init", "--project", world["ws"], "--yes")
    assert done.returncode == 0, done.stderr                    # home B: the decider, same starter policy
    sock = world["root"] / "d.sock"
    decider = decider_module.Decider(sock, env={**os.environ, "HOME": str(world["home_b"])}).start()
    try:
        for n, case in enumerate(cli_tests.FIXTURES):
            extra = {"CLAUDE_PROJECT_DIR": cli_tests._fill(case["project_dir"], world)} if case.get("project_dir") else {}
            decider.env.pop("CLAUDE_PROJECT_DIR", None)
            decider.env.update(extra)
            payload = cli_tests._input(case, world)
            via_cli = cli_tests._hook(world["home"], payload, **extra)
            via_client = _client(sock, json.dumps(payload).encode())
            assert _comparable(via_client, False) == _comparable(via_cli, True), case["id"]
            out = via_client["hookSpecificOutput"]
            assert out["permissionDecision"] == case["expect"]["answer"], case["id"]
            if case["expect"]["answer"] == "deny":
                assert f"Receipt {n} of session s1." in out["permissionDecisionReason"], case["id"]
    finally:
        decider.close()
    a, b = _entries(world["home"]), _entries(world["home_b"])
    assert len(a) == len(b) == len(cli_tests.FIXTURES) and a == b      # same readings, same verdicts, same receipts
    assert not sock.exists()



def test_agent_run_without_init_says_so_and_runs_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    ws = tmp_path / "ws"
    ws.mkdir()
    with pytest.raises(commands.AgentError, match="prismpath agent init.*nothing was run"):
        commands.run([sys.executable, "-c", f"open({str(ws / 'ran')!r}, 'w')"], workspace=str(ws))
    assert not (ws / "ran").exists()


# ----------------------------------------------------------------------------------------- client fails closed
def _is_hook_error(answer):
    out = answer["hookSpecificOutput"]
    return (out["permissionDecision"] == "deny"
            and f"cause {HOOK_ERROR_CODE} agent:hook-error" in out["permissionDecisionReason"])


def test_the_hook_error_text_matches_the_hook_commands_own_deny():
    ours = hook_client.deny("x")["hookSpecificOutput"]["permissionDecisionReason"].split(" (x)")[0]
    theirs = commands.deny_answer("x")["hookSpecificOutput"]["permissionDecisionReason"].split(" (x)")[0]
    assert ours == theirs


PRE = json.dumps({"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Bash",
                  "tool_input": {"command": "ls"}}).encode()


def test_a_missing_socket_is_a_deny_with_hook_error(tmp_path):
    answer = _client(tmp_path / "nothing.sock", PRE)
    assert _is_hook_error(answer)
    done = subprocess.run([sys.executable, "-I", str(CLIENT)], input=PRE, capture_output=True, timeout=30)
    assert done.returncode == 0 and _is_hook_error(json.loads(done.stdout))      # no argument at all


def _serve_once(path, reply, delay=0.0):
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(path))
    server.listen(1)

    def go():
        conn, _ = server.accept()
        conn.recv(65536)
        time.sleep(delay)
        try:
            conn.sendall(reply)
        except OSError:
            pass
        conn.close()
        server.close()
    threading.Thread(target=go, daemon=True).start()


@pytest.mark.parametrize("reply", [b"", b"not json", b"[]", b"{}", b'{"hookSpecificOutput": {"permissionDecision": "maybe"}}'])
def test_a_reply_that_does_not_decide_is_a_deny_with_hook_error(tmp_path, reply):
    _serve_once(tmp_path / "s.sock", reply)
    assert _is_hook_error(_client(tmp_path / "s.sock", PRE))


def test_a_decider_that_never_answers_is_a_deny_after_the_timeout(tmp_path, monkeypatch):
    _serve_once(tmp_path / "s.sock", b"{}", delay=5)
    monkeypatch.setattr(hook_client, "TIMEOUT_S", 0.3)
    start = time.monotonic()
    assert _is_hook_error(hook_client.ask(str(tmp_path / "s.sock"), PRE))
    assert time.monotonic() - start < 3


def test_an_oversized_input_is_a_deny_and_session_end_failure_is_a_message_not_a_deny(tmp_path):
    big = b'{"hook_event_name": "PreToolUse", "x": "' + b"a" * (hook_client.MAX_INPUT + 10) + b'"}'
    assert _is_hook_error(_client(tmp_path / "none.sock", big))
    end = json.dumps({"session_id": "s", "hook_event_name": "SessionEnd"}).encode()
    answer = _client(tmp_path / "none.sock", end)
    assert "systemMessage" in answer and "hookSpecificOutput" not in answer


def test_the_client_imports_only_the_standard_library():
    tree = ast.parse(CLIENT.read_text())
    names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert names and names <= set(sys.stdlib_module_names), names


# ----------------------------------------------------------------------------------- the decider survives
def test_one_bad_request_never_stops_the_decider(tmp_path):
    calls = []

    def handler(raw):
        calls.append(raw)
        if raw == b"boom":
            raise RuntimeError("handler crashed")
        return {"ok": True}

    decider = decider_module.Decider(tmp_path / "d.sock", handler=handler, max_input=100, read_timeout_s=0.5).start()
    try:
        def talk(data, shut=True, wait=True):
            s = socket.socket(socket.AF_UNIX)
            s.settimeout(5)
            s.connect(str(tmp_path / "d.sock"))
            try:
                s.sendall(data)
            except OSError:
                pass
            if shut:
                s.shutdown(socket.SHUT_WR)
            try:
                got = s.recv(65536) if wait else b""
            except OSError:
                got = b""
            s.close()
            return got

        assert json.loads(talk(b"fine")) == {"ok": True}
        assert b"cause" in talk(b"boom") and b"hook-error" in talk(b"boom")                 # the handler raised: a deny
        assert b"too large" in talk(b"x" * 500)                                              # over the bound: not decided
        assert b"did not arrive" in talk(b"half", shut=False)                                # a client that stalls
        talk(b"gone", wait=False)                                                            # a client that leaves
        assert json.loads(talk(b"still fine")) == {"ok": True}
        assert b"x" * 500 not in calls and b"half" not in calls
    finally:
        decider.close()


def test_decisions_are_taken_one_at_a_time(tmp_path):
    active, peak, lock = [0], [0], threading.Lock()

    def handler(raw):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.05)
        with lock:
            active[0] -= 1
        return {"ok": 1}

    decider = decider_module.Decider(tmp_path / "d.sock", handler=handler).start()
    try:
        threads = [threading.Thread(target=lambda: _client_raw(tmp_path / "d.sock")) for _ in range(6)]
        [t.start() for t in threads]
        [t.join() for t in threads]
    finally:
        decider.close()
    assert peak[0] == 1


def _client_raw(path):
    s = socket.socket(socket.AF_UNIX)
    s.connect(str(path))
    s.sendall(b"{}")
    s.shutdown(socket.SHUT_WR)
    s.recv(100)
    s.close()


# --------------------------------------------------------------------------------------- under the launcher
STAND_IN = r'''
import json, os, subprocess, sys
out = {"decisions": [], "reads": {}}
cfg = os.environ["CLAUDE_CONFIG_DIR"]
settings = json.load(open(cfg + "/settings.json"))
command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
out["command"] = command
for raw in json.load(open("inputs.json")):
    done = subprocess.run(["/bin/sh", "-c", command], input=json.dumps(raw).encode(), capture_output=True)
    out["decisions"].append([done.returncode, done.stdout.decode()])
broken = command.replace("/tmp/.pp-decider.sock", "/tmp/nothing.sock")
done = subprocess.run(["/bin/sh", "-c", broken], input=b"{}", capture_output=True)
out["missing_socket"] = [done.returncode, done.stdout.decode()]
for path in sys.argv[1:]:
    try:
        if os.path.isdir(path):
            out["reads"][path] = "listed: " + repr(os.listdir(path))
        else:
            out["reads"][path] = "read: " + str(len(open(path, "rb").read()))
    except BaseException as exc:
        out["reads"][path] = "fail: " + type(exc).__name__
try:
    open(cfg + "/pp-hook.py", "w").write("# swapped")
    out["rewrite_client"] = "wrote"
except BaseException as exc:
    out["rewrite_client"] = "fail: " + type(exc).__name__
json.dump(out, open("out.json", "w"))
'''


@needs_bwrap
@needs_socat
def test_under_the_launcher_the_client_gets_decisions_the_sandbox_cannot_read_the_keys_and_verify_passes(world, monkeypatch):
    home, ws = world["home"], Path(world["ws"])
    monkeypatch.setenv("HOME", str(home))
    for name in ("XDG_CONFIG_HOME", "APPDATA", "CLAUDE_PROJECT_DIR"):
        monkeypatch.delenv(name, raising=False)
    cli_tests._init(world)
    agent_dir = cli_tests._agent_dir(home)
    base = {"session_id": "ls1", "cwd": world["ws"], "hook_event_name": "PreToolUse"}
    inputs = [
        {**base, "tool_name": "Read", "tool_input": {"file_path": world["ws"] + "/README.md"}},
        {**base, "tool_name": "Bash", "tool_input": {"command": "ls src"}},
        {**base, "tool_name": "Write", "tool_input": {"file_path": world["decoy"] + "/sentinel.txt", "content": "x"}},
        {**base, "tool_name": "Bash", "tool_input": {"command": "rm " + world["decoy"] + "/sentinel.txt"}},
        {**base, "hook_event_name": "SessionEnd"},
    ]
    (ws / "inputs.json").write_text(json.dumps(inputs))
    (ws / "agent.py").write_text(STAND_IN)
    journal = agent_dir / commands.RUNS_DIR / run_module.run_dir_name("ls1") / run_module.JOURNAL
    secret_paths = [str(agent_dir), str(agent_dir / "authority.key"), str(agent_dir / "instance.key"),
                    str(agent_dir / commands.POLICY_FILE), str(agent_dir / commands.ATTESTATION_FILE),
                    str(agent_dir / commands.RUNS_DIR), str(journal), str(home)]
    stages = world["root"] / "stages"
    stages.mkdir()
    code = launcher.launch(["/usr/bin/python3", "agent.py", *secret_paths], str(ws), stage_base=str(stages))
    assert code == 0
    out = json.loads((ws / "out.json").read_text())
    assert out["command"] == launcher.client_hook_command() and out["command"].endswith("|| exit 2")

    def answer(n):
        rc, text = out["decisions"][n]
        assert rc == 0
        return json.loads(text)["hookSpecificOutput"] if text.strip() != "{}" else {}
    assert answer(0)["permissionDecision"] == "allow"
    shell = answer(1)
    from prismpath.tests.test_agent_nested import NESTING
    if NESTING:
        assert shell["permissionDecision"] == "allow" and shell["updatedInput"]["command"].startswith(
            f"{launcher.HOOK_PYTHON} -I {launcher.RUNNER_IN} ")
    else:   # a host that forbids the nested sandbox: every shell command is refused, never run under the outer one
        assert shell["permissionDecision"] == "deny" and "129" in shell["permissionDecisionReason"]
    shift = 0 if NESTING else 1     # the 129 refusal writes no receipt, so later receipts are numbered one lower
    assert answer(2)["permissionDecision"] == "deny" and f"Receipt {2 - shift} of session ls1" in answer(2)["permissionDecisionReason"]
    assert answer(3)["permissionDecision"] == "deny" and f"Receipt {3 - shift} of session ls1" in answer(3)["permissionDecisionReason"]
    assert json.loads(out["decisions"][4][1]) == {}                                    # SessionEnd sealed the run
    rc, text = out["missing_socket"]
    assert rc == 0 and _is_hook_error(json.loads(text))                                 # no socket: deny, exit 0
    assert all(v.startswith("fail") for v in out["reads"].values()), out["reads"]       # keys, policy, journal, home
    assert out["rewrite_client"].startswith("fail")                                     # the client is read only
    assert list(stages.iterdir()) == []                                                 # and the staged dir is gone
    # outside again: the run the decider wrote verifies
    verified = cli_tests._cli(home, "agent", "verify", "--json")
    report = json.loads(verified.stdout)
    assert verified.returncode == 0 and report["verified"] is True
    assert [r["receipts"] for r in report["runs"]] == [4 - shift]
