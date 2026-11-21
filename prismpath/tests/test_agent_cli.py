# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`prismpath agent init | hook | verify | status`, driven end to end as Claude Code drives them: separate
processes, the hook JSON on stdin, the answer on stdout.

Every process runs with HOME set to a throwaway directory and XDG_CONFIG_HOME and APPDATA removed, so the
keys, the policy and the runs are written under the test's own directory and never under the real
configuration directory; the project whose `.claude/settings.json` is written is a throwaway one too.
The hook inputs are the A2 recordings (`fixtures/claude_code_hooks.json`), with the same `@WS@` and `@DECOY@`
world as tests/test_agent_claude_code.py.
"""
import json
import shlex
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath.agent import commands  # noqa: E402
from prismpath.kernel import causes  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "claude_code_hooks.json").read_text(encoding="utf-8"))
HOOK_ERROR_CODE = causes.code("agent:hook-error")
HEAVY = ("numpy", "scipy", "pandas", "torch", "sklearn", "onnxruntime", "transformers", "tokenizers",
         "sentence_transformers", "requests", "httpx", "urllib3", "yaml", "jsonschema", "matplotlib")


def _env(home: Path, **extra):
    env = {k: v for k, v in os.environ.items()
           if k not in ("XDG_CONFIG_HOME", "APPDATA", "CLAUDE_PROJECT_DIR", "PRISMPATH_DEBUG")}
    env.update(HOME=str(home), USERPROFILE=str(home), PYTHONPATH=str(REPO), TMPDIR=str(home / "tmp"))
    (home / "tmp").mkdir(parents=True, exist_ok=True)
    env.update(extra)
    return env


def _cli(home, *args, stdin=b"", **extra):
    return subprocess.run([sys.executable, "-m", "prismpath", *args], input=stdin, capture_output=True,
                          env=_env(home, **extra), cwd=str(home), timeout=120)


def _hook(home, payload, **extra):
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    done = _cli(home, "agent", "hook", stdin=raw, **extra)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def _agent_dir(home: Path) -> Path:
    return home / ".config" / "prismpath" / "agent"


@pytest.fixture()
def world(tmp_path):
    home, root = tmp_path / "home", tmp_path / "world"
    ws, decoy = root / "ws", root / "decoy"
    for directory in (home, ws / "src", ws / "logs", ws / "build", ws / ".toolchain" / "bin", ws / ".toolchain" / "lib",
                      decoy / "old_build"):
        directory.mkdir(parents=True, exist_ok=True)
    for path, text in {ws / "README.md": "# demo\n", ws / "notes.txt": "first note\nsecond note\n",
                       ws / "src" / "app.py": "# TODO\n", ws / "scratch.tmp": "s\n", decoy / "sentinel.txt": "s\n"}.items():
        path.write_text(text)
    os.symlink(decoy, ws / "link_out")
    os.symlink(decoy / "sentinel.txt", ws / "cfg")
    os.symlink("notes.txt", ws / "inner_link")
    return {"home": home, "ws": str(ws.resolve()), "decoy": str(decoy.resolve())}


def _fill(value, world):
    if isinstance(value, str):
        return value.replace("@WS@", world["ws"]).replace("@DECOY@", world["decoy"])
    if isinstance(value, list):
        return [_fill(v, world) for v in value]
    if isinstance(value, dict):
        return {k: _fill(v, world) for k, v in value.items()}
    return value


def _input(case, world, session="s1"):
    return {"session_id": session, "transcript_path": "/tmp/t.jsonl", "cwd": _fill(case["cwd"], world),
            "hook_event_name": "PreToolUse", "tool_name": case["tool_name"], "tool_use_id": "toolu_1",
            "tool_input": _fill(case["tool_input"], world)}


def _init(world, *flags):
    done = _cli(world["home"], "agent", "init", "--project", world["ws"], "--yes", *flags)
    assert done.returncode == 0, done.stderr
    return done


# ------------------------------------------------------------------------------------------------- init
def test_config_dir_per_platform():
    assert commands.config_dir({"HOME": "/h"}, "linux") == Path("/h/.config/prismpath/agent")
    assert commands.config_dir({"HOME": "/h", "XDG_CONFIG_HOME": "/x"}, "linux") == Path("/x/prismpath/agent")
    assert commands.config_dir({"HOME": "/h", "XDG_CONFIG_HOME": "rel"}, "linux") == Path("/h/.config/prismpath/agent")
    assert commands.config_dir({"HOME": "/h"}, "darwin") == Path("/h/Library/Application Support/prismpath/agent")
    assert commands.config_dir({"HOME": "/h", "APPDATA": "/a"}, "win32") == Path("/a/prismpath/agent")


def test_init_shows_the_change_writes_it_only_when_told_and_keeps_other_settings(world):
    home, ws = world["home"], Path(world["ws"])
    settings = ws / ".claude" / "settings.json"
    settings.parent.mkdir()
    other = {"model": "x", "permissions": {"allow": ["Bash(ls:*)"]},
             "hooks": {"PostToolUse": [{"matcher": "Write", "hooks": [{"type": "command", "command": "fmt"}]}]}}
    settings.write_text(json.dumps(other))
    before = settings.read_bytes()

    asked = _cli(home, "agent", "init", "--project", str(ws))           # no --yes, no terminal: not written
    assert asked.returncode == 1
    assert settings.read_bytes() == before
    assert "+++ " + str(settings) in asked.stdout.decode() and '"PreToolUse"' in asked.stdout.decode()

    done = _cli(home, "agent", "init", "--project", str(ws), "--yes", "--json")
    assert done.returncode == 0, done.stderr
    report = json.loads(done.stdout)
    assert report["settings"]["state"] == "written" and report["policy"]["state"] in ("kept", "recorded")
    written = json.loads(settings.read_text())
    assert written["model"] == "x" and written["permissions"] == other["permissions"]
    post = written["hooks"]["PostToolUse"]             # the person's own entry stays first; ours is added for outcomes
    assert post[0] == other["hooks"]["PostToolUse"][0] and len(post) == 2 and post[1]["matcher"] == "*"
    assert post[1]["hooks"][0]["command"].endswith(" prismpath agent hook || exit 2")
    assert written["hooks"]["PostToolUseFailure"][0]["hooks"][0]["command"] == post[1]["hooks"][0]["command"]
    pre, end = written["hooks"]["PreToolUse"], written["hooks"]["SessionEnd"]
    assert pre[0]["matcher"] == "*" and pre[0]["hooks"][0]["command"].endswith(" prismpath agent hook || exit 2")
    assert end[0]["hooks"][0]["command"] == pre[0]["hooks"][0]["command"]

    agent = _agent_dir(home)
    assert (agent.stat().st_mode & 0o777) == 0o700
    for name in ("authority.key", "authority.pub", "instance.key", "instance.pub", "policy.core.json",
                 "policy.attestation.json"):
        assert ((agent / name).stat().st_mode & 0o777) == 0o600, name
    ids = report["keys"]

    again = json.loads(_init(world, "--json").stdout)                  # idempotent, and never a new key
    assert again["settings"]["state"] == "unchanged" and again["settings"]["diff"] == ""
    assert again["policy"]["state"] == "kept"
    assert {r: again["keys"][r]["id"] for r in ids} == {r: ids[r]["id"] for r in ids}
    assert all(again["keys"][r]["state"] == "kept" for r in ids)
    assert json.loads(settings.read_text()) == written


def test_init_asks_and_a_yes_writes(world, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(world["home"]))
    for name in ("XDG_CONFIG_HOME", "APPDATA"):
        monkeypatch.delenv(name, raising=False)
    prompts = []
    assert commands.init(Path(world["ws"]), yes=False, as_json=False, confirm=lambda p: prompts.append(p) or False) == 1
    assert not (Path(world["ws"]) / ".claude" / "settings.json").exists()
    assert commands.init(Path(world["ws"]), yes=False, as_json=False, confirm=lambda p: prompts.append(p) or True) == 0
    assert len(prompts) == 2 and (Path(world["ws"]) / ".claude" / "settings.json").exists()
    assert str(_agent_dir(world["home"])) in capsys.readouterr().out


def test_init_never_replaces_half_a_key_pair(world):
    _init(world)
    (_agent_dir(world["home"]) / "instance.pub").unlink()
    done = _cli(world["home"], "agent", "init", "--project", world["ws"], "--yes")
    assert done.returncode == 2 and b"half of the instance key pair" in done.stderr
    assert (_agent_dir(world["home"]) / "instance.key").exists()


# ------------------------------------------------------------------------------------- hook, end to end
def test_every_recorded_hook_input_end_to_end(world):
    home = world["home"]
    _init(world)
    allows = 0
    for n, case in enumerate(FIXTURES):
        extra = {"CLAUDE_PROJECT_DIR": _fill(case["project_dir"], world)} if case.get("project_dir") else {}
        out = _hook(home, _input(case, world), **extra)["hookSpecificOutput"]
        expect = case["expect"]
        assert out["hookEventName"] == "PreToolUse"
        assert out["permissionDecision"] == expect["answer"], case["id"]
        if expect["cause_code"] is None:
            assert "permissionDecisionReason" not in out
            allows += 1
        else:
            reason = out["permissionDecisionReason"]
            assert f"cause {expect['cause_code']} {causes.name(expect['cause_code'])}" in reason, case["id"]
            assert f"Receipt {n} of session s1." in reason, (case["id"], reason)
    assert allows and allows < len(FIXTURES)

    status = json.loads(_cli(home, "agent", "status", "--json", "--project", world["ws"]).stdout)
    assert [{k: v for k, v in r.items() if k != "outcomes"} for r in status["runs"]] == [
        {"session": "s1", "receipts": len(FIXTURES), "state": "open"}]
    assert status["runs"][0]["outcomes"]["allowed_ran"] == 0       # no PostToolUse was sent, so nothing ran as far as it knows
    assert status["project"]["hooks"] == {"PreToolUse": True, "SessionEnd": True, "PostToolUse": True, "PostToolUseFailure": True}

    assert _hook(home, {"session_id": "s1", "hook_event_name": "SessionEnd", "reason": "exit", "cwd": world["ws"]}) == {}
    status = json.loads(_cli(home, "agent", "status", "--json", "--project", world["ws"]).stdout)
    assert status["runs"][0]["state"] == "sealed"
    assert status["keys"]["authority"]["present"] and status["keys"]["instance"]["present"]
    assert status["policy"]["attested"] is True and len(status["policy"]["sha256"]) == 64

    done = _cli(home, "agent", "verify", "--json", "--tamper-demo")
    assert done.returncode == 0, done.stdout + done.stderr
    report = json.loads(done.stdout)
    run = report["runs"][0]
    assert run["verified"] and run["receipts"] == run["replayed"] == len(FIXTURES) and run["disagree"] == 0
    assert run["root_statement"] == "signed" and run["was"] == "sealed"
    demo = report["tamper_demo"]
    assert demo["refused"] is True and demo["session"] == "s1" and demo["reason"]
    assert list((home / "tmp").iterdir()) == []                         # the tampered copy was deleted

    text = _cli(home, "agent", "status", "--project", world["ws"]).stdout.decode()
    assert f"run s1: {len(FIXTURES)} receipts, sealed" in text and "PreToolUse yes" in text


def test_verify_seals_an_open_run_and_a_second_session_is_its_own_run(world):
    home = world["home"]
    _init(world)
    case = next(c for c in FIXTURES if c["expect"]["answer"] == "deny")
    for session in ("a", "b", "a"):
        _hook(home, _input(case, world, session))
    text = _cli(home, "agent", "verify").stdout.decode()
    assert "a: 2 receipts" in text and "b: 1 receipts" in text and "(was open)" in text
    out = _hook(home, _input(case, world, "a"))["hookSpecificOutput"]        # a resumed session reseals
    assert "Receipt 2 of session a." in out["permissionDecisionReason"]
    report = json.loads(_cli(home, "agent", "verify", "--json").stdout)
    assert {r["session"]: r["receipts"] for r in report["runs"]} == {"a": 3, "b": 1} and report["verified"]


def test_a_tampered_run_fails_verify(world):
    home = world["home"]
    _init(world)
    _hook(home, _input(FIXTURES[0], world))
    _hook(home, _input(FIXTURES[1], world))
    assert _cli(home, "agent", "verify").returncode == 0
    path = _agent_dir(home) / "runs" / "s1" / "receipts.jsonl"
    data = bytearray(path.read_bytes())
    data[len(data) // 3] ^= 1
    path.write_bytes(bytes(data))
    done = _cli(home, "agent", "verify", "--json")
    assert done.returncode == 1 and json.loads(done.stdout)["runs"][0]["verified"] is False


# ------------------------------------------------------------------------------------------ fail closed
def _assert_hook_error(answer):
    out = answer["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert f"cause {HOOK_ERROR_CODE} agent:hook-error" in out["permissionDecisionReason"]


def test_the_hook_fails_closed(world):
    home = world["home"]
    allowed = next(c for c in FIXTURES if c["expect"]["answer"] == "allow")
    good = _input(allowed, world)
    _assert_hook_error(_hook(home, good))                                  # nothing set up yet
    _init(world)
    assert _hook(home, good)["hookSpecificOutput"]["permissionDecision"] == "allow"
    for garbage in (b"", b"not json", b"\xff\xfe", b"[1, 2]", b'{"hook_event_name": "PreToolUse"}',
                    json.dumps({**good, "hook_event_name": "PostToolUse"}).encode()):
        _assert_hook_error(_hook(home, garbage))
    agent = _agent_dir(home)
    for name, damage in (("instance.key", lambda b: b"-----BEGIN PRIVATE KEY-----\nbroken\n"),
                         ("authority.pub", lambda b: bytes([b[0] ^ 1]) + b[1:]),
                         ("policy.core.json", lambda b: b.replace(b'"allow"', b'"allow" ', 1)),
                         ("policy.attestation.json", lambda b: b[:-10] + b"0000000000"),
                         ("authority.key", None)):
        path = agent / name
        original = path.read_bytes()
        if damage is None:
            path.unlink()
        else:
            path.write_bytes(damage(original))
        _assert_hook_error(_hook(home, good))
        path.write_bytes(original)
        assert _hook(home, good)["hookSpecificOutput"]["permissionDecision"] == "allow", name
    status = json.loads(_cli(home, "agent", "status", "--json").stdout)
    assert [{k: v for k, v in r.items() if k != "outcomes"} for r in status["runs"]] == [
        {"session": "s1", "receipts": 6, "state": "open"}]     # no receipt for an error


def test_a_session_end_that_cannot_seal_says_so_and_allows_nothing(world):
    home = world["home"]
    answer = _hook(home, {"session_id": "s1", "hook_event_name": "SessionEnd"})
    assert "permissionDecision" not in json.dumps(answer) and "agent:hook-error" in answer["systemMessage"]


# ------------------------------------------------------------------------------------------ the hot path
_PROBE = """
import io, json, sys
sys.stdin = io.TextIOWrapper(io.BytesIO(sys.argv[1].encode()))
out = io.StringIO()
real, sys.stdout = sys.stdout, out
from prismpath import cli
cli.main(["agent", "hook"])
sys.stdout = real
print(json.dumps({"answer": json.loads(out.getvalue()), "modules": sorted(sys.modules)}))
"""


def test_the_hook_path_imports_nothing_heavy(world):
    _init(world)
    allowed = next(c for c in FIXTURES if c["expect"]["answer"] == "deny")
    done = subprocess.run([sys.executable, "-c", _PROBE, json.dumps(_input(allowed, world))], capture_output=True,
                          env=_env(world["home"]), timeout=60)
    assert done.returncode == 0, done.stderr
    result = json.loads(done.stdout)
    assert result["answer"]["hookSpecificOutput"]["permissionDecision"] == "deny"
    heavy = sorted(m for m in result["modules"] if m.split(".")[0] in HEAVY)
    assert heavy == [], heavy
    assert "prismpath.workers.chat_agent" not in result["modules"] and "prismpath.evals" not in result["modules"]


def test_the_hook_answer_time_is_reported(world, capsys):
    _init(world)
    raw = json.dumps(_input(FIXTURES[0], world)).encode()
    times = []
    for _ in range(7):
        start = time.perf_counter()
        _hook(world["home"], raw)
        times.append((time.perf_counter() - start) * 1000)
    print(f"hook wall clock: median {statistics.median(times):.0f} ms, max {max(times):.0f} ms")
    assert statistics.median(times) < 1000          # the 150 ms budget is measured on the floor host, in the PR


@pytest.mark.skipif(os.name == "nt", reason="the written hook command is a POSIX shell line")
def test_the_hook_command_blocks_when_prismpath_cannot_even_be_imported(tmp_path):
    """Claude Code blocks only on exit 2, so a hook whose interpreter cannot import prismpath must exit 2, not 1."""
    from prismpath.agent import commands
    broken = tmp_path / "python"
    broken.write_text("#!/bin/sh\necho 'No module named prismpath' >&2\nexit 1\n")
    broken.chmod(0o755)
    line = commands.hook_command().replace(shlex.quote(sys.executable), shlex.quote(str(broken)), 1)
    done = subprocess.run(["sh", "-c", line], input=b"{}", capture_output=True)
    assert done.returncode == 2
    assert commands._is_ours(commands.hook_command())
