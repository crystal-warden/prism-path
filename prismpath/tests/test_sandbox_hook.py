# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Claude Code hook runs an allowed Bash call inside the sandbox its own policy compiles to.

Driven as Claude Code drives it (the hook JSON on stdin, the answer on stdout), with HOME and the project in a
throwaway directory. The hook inputs are the A2 recordings used by test_agent_cli.py.
"""
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath.agent import commands, profile as profile_module, sandbox_exec, sandbox_hook  # noqa: E402
from prismpath.agent.run import RunStore  # noqa: E402
from prismpath.kernel import causes  # noqa: E402
from prismpath.tests.test_agent_cli import (FIXTURES, _agent_dir, _cli, _env, _hook, _init, _input,  # noqa: E402,F401
                                            world)

SANDBOX_CODE = causes.code("agent:sandbox-unavailable")


def _bwrap_works() -> str:
    if not sandbox_exec.available():
        return f"no {sandbox_exec.BWRAP}"
    try:
        sandbox_exec.run_sandboxed(["/usr/bin/true"], os.getcwd())
    except sandbox_exec.SandboxUnavailable as exc:
        return f"bwrap cannot start here: {exc}"
    return ""


_WHY = _bwrap_works()
needs_bwrap = pytest.mark.skipif(bool(_WHY), reason=_WHY or "bwrap works")


def _bash(world, command, cwd=None, **extra):
    return {"session_id": "s1", "transcript_path": "/tmp/t.jsonl", "cwd": cwd or world["ws"],
            "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": "toolu_1",
            "tool_input": {"command": command, **extra}}


def _output(answer):
    return answer["hookSpecificOutput"]


# ------------------------------------------------------------------------------------- the rewrite
def test_an_allowed_ls_comes_back_rewritten_with_every_other_field_kept(world):
    _init(world)
    answer = _output(_hook(world["home"], _bash(world, "ls -la src", description="list src", timeout=5000,
                                                run_in_background=False)))
    assert answer["permissionDecision"] == "allow"
    updated = answer["updatedInput"]
    assert {k: v for k, v in updated.items() if k != "command"} == {
        "description": "list src", "timeout": 5000, "run_in_background": False}
    words = shlex.split(updated["command"])
    assert words[1] == "-I" and os.path.isabs(words[0]) and words[2] == str(sandbox_hook.RUNNER)
    assert words[-2:] == ["--", "ls -la src"]
    assert "--workspace" in words and "--profile" in words


@needs_bwrap
def test_the_rewritten_command_runs_ls_in_the_sandbox(world):
    _init(world)
    command = _output(_hook(world["home"], _bash(world, "ls -la src")))["updatedInput"]["command"]
    done = subprocess.run(["/bin/bash", "-c", command], capture_output=True, cwd=world["ws"], timeout=60,
                          env={"PATH": "/usr/bin:/bin"})
    assert done.returncode == 0, done.stderr
    assert b"app.py" in done.stdout


@needs_bwrap
def test_it_runs_from_the_directory_claude_code_was_in_and_the_workspace_keeps_its_real_path(world):
    _init(world)
    command = _output(_hook(world["home"], _bash(world, "cat app.py", cwd=world["ws"] + "/src")))["updatedInput"]["command"]
    done = subprocess.run(["/bin/bash", "-c", command], capture_output=True, cwd=world["ws"] + "/src", timeout=60)
    assert (done.returncode, done.stdout) == (0, b"# TODO\n")
    command = _output(_hook(world["home"], _bash(world, "grep -n TODO " + world["ws"] + "/src/app.py")))["updatedInput"]["command"]
    done = subprocess.run(["/bin/bash", "-c", command], capture_output=True, cwd=world["ws"], timeout=60)
    assert done.stdout.startswith(b"1:# TODO")


@needs_bwrap
def test_what_the_command_does_not_get_is_not_there(world):
    """The sandbox is the profile of the image: no /etc, no network namespace, and a decoy beside the workspace is not mounted."""
    _init(world)
    profile = sandbox_hook.profile_for(_agent_dir(world["home"]), (_agent_dir(world["home"]) / "policy.core.json").read_bytes())
    def run(probe):
        wrapped = sandbox_hook.rewrite_command(probe, world["ws"], world["ws"], profile)
        return subprocess.run(["/bin/bash", "-c", wrapped], capture_output=True, timeout=60)
    assert b"No such file" in run("cat /etc/hostname").stderr
    assert run(f"ls {world['decoy']}").returncode != 0
    interfaces = run("cat /proc/net/dev").stdout.decode().splitlines()[2:]
    names = [line.split(":")[0].strip() for line in interfaces]
    assert "lo" in names and not any(n.startswith(("eth", "en", "wl", "docker", "tailscale")) for n in names), names  # no host interface


HOSTILE = ["ls", "echo 'a b'", 'echo "it\'s"', "echo a; touch HOST_MARK", "echo $(touch HOST_MARK)", "echo `touch HOST_MARK`",
           "ls\ntouch HOST_MARK", "echo '\"; touch HOST_MARK; echo \"'", "echo $HOME ${PATH} \\' \\\"", "a&b|c>d<e", "echo \\", "",
           "echo ünï\tcode", "'; touch HOST_MARK; '", "--version"]


@pytest.mark.parametrize("command", HOSTILE)
def test_the_original_command_is_one_argument_the_outer_shell_cannot_break_out_of(world, command):
    profile = profile_module.STRICTEST
    wrapped = sandbox_hook.rewrite_command(command, world["ws"], world["ws"], profile)
    words = shlex.split(wrapped)
    assert words[-1] == command and words[-2] == "--"
    # the outer shell sees exactly these words and runs nothing of the command's text
    marker = Path(world["ws"]) / "HOST_MARK"
    probe = subprocess.run(["/bin/bash", "-c", "printf '%s\\0' " + wrapped.split(" -- ", 1)[1]], capture_output=True)
    assert probe.stdout == command.encode() + b"\0"
    assert not marker.exists()


# --------------------------------------------------------------------------------- the receipt and the cache
def test_the_receipt_line_carries_the_profile_hash_and_the_run_still_verifies(world):
    _init(world)
    home = world["home"]
    _hook(home, _bash(world, "wc -l notes.txt"))
    _hook(home, _input(next(c for c in FIXTURES if "curl" in str(c["tool_input"])), world))
    run = RunStore(_agent_dir(home) / "runs").get("s1")
    lines = [json.loads(line) for line in (run.dir / "journal.jsonl").read_text().splitlines()]
    image = (_agent_dir(home) / "policy.core.json").read_bytes()
    assert lines[0]["sandbox"] == {"profile_sha256": profile_module.compile_profile(image).hash(), "backend": "bwrap"}
    assert "sandbox" not in lines[1]                        # the refused call has no profile
    done = _cli(home, "agent", "verify")
    assert done.returncode == 0, done.stdout + done.stderr


def test_the_profile_is_cached_by_image_hash_and_a_damaged_cache_is_recompiled(world, monkeypatch):
    _init(world)
    agent = _agent_dir(world["home"])
    image = (agent / "policy.core.json").read_bytes()
    first = sandbox_hook.profile_for(agent, image)
    cached = list((agent / "profiles").glob("*.json"))
    assert [p.name for p in cached] == [sandbox_hook._sha256_hex(image) + ".json"]

    def boom(_image):
        raise AssertionError("compiled again")
    monkeypatch.setattr(profile_module, "compile_profile", boom)
    assert sandbox_hook.profile_for(agent, image) == first          # from the cache
    entry = json.loads(cached[0].read_text())
    entry["profile"]["network"] = True                              # a widened profile whose hash no longer matches
    cached[0].write_text(json.dumps(entry))
    with pytest.raises(sandbox_hook.SandboxRefused, match="compiled again"):
        sandbox_hook.profile_for(agent, image)                      # not trusted, so it tried to compile


def test_a_cache_entry_is_used_only_for_the_image_and_compiler_it_was_made_for(world, monkeypatch):
    _init(world)
    agent = _agent_dir(world["home"])
    image = (agent / "policy.core.json").read_bytes()
    sandbox_hook.profile_for(agent, image)
    entry_path = agent / "profiles" / (sandbox_hook._sha256_hex(image) + ".json")
    other = image + b" "                                            # another image, its own digest
    other_path = agent / "profiles" / (sandbox_hook._sha256_hex(other) + ".json")
    other_path.write_bytes(entry_path.read_bytes())                 # the first image's entry filed under the second's name
    compiled = []

    def counting(img, role="bash"):
        compiled.append(img)
        raise profile_module.ProfileError("stop here")
    monkeypatch.setattr(profile_module, "compile_profile", counting)
    with pytest.raises(sandbox_hook.SandboxRefused):
        sandbox_hook.profile_for(agent, other)
    assert compiled == [other]                                      # not taken from the cache
    entry = json.loads(entry_path.read_text())
    entry["compiler"] = profile_module.COMPILER_VERSION + 1         # made by another compiler version
    entry_path.write_text(json.dumps(entry))
    with pytest.raises(sandbox_hook.SandboxRefused):
        sandbox_hook.profile_for(agent, image)
    assert compiled == [other, image]


# ------------------------------------------------------------------------------------- refuse, ask, fail closed
def test_a_refusal_carries_no_rewrite_and_a_question_asks_with_the_rewrite(world):
    _init(world)
    answer = _output(_hook(world["home"], _bash(world, "curl -o data.csv https://example.invalid/data.csv")))
    assert answer["permissionDecision"] == "deny" and "updatedInput" not in answer
    for command in ("rm scratch.tmp", "git push origin HEAD"):
        answer = _output(_hook(world["home"], _bash(world, command, description="d")))
        assert answer["permissionDecision"] == "ask", command
        assert answer["updatedInput"]["description"] == "d"
        assert answer["updatedInput"]["command"].endswith(shlex.quote(command))
        assert "runs inside the PrismPath sandbox" in answer["permissionDecisionReason"]
    run = RunStore(_agent_dir(world["home"]) / "runs").get("s1")
    assert all(line for line in (run.dir / "journal.jsonl").read_text().splitlines() if '"sandbox"' in line)


def test_a_missing_bwrap_denies_a_question_with_the_new_cause_and_no_receipt(world, monkeypatch):
    _init(world)
    monkeypatch.setattr(sandbox_exec, "BWRAP", str(Path(world["home"]) / "no-such-bwrap"))
    env = _env(world["home"])
    out = _output(commands.hook(json.dumps(_bash(world, "rm scratch.tmp")).encode(), {**env, "PATH": os.environ["PATH"]}))
    assert out["permissionDecision"] == "deny" and "updatedInput" not in out
    assert f"cause {SANDBOX_CODE} agent:sandbox-unavailable" in out["permissionDecisionReason"]
    assert not any((_agent_dir(world["home"]) / "runs").glob("*/journal.jsonl"))


def test_non_bash_tools_are_not_rewritten(world):
    _init(world)
    answer = _output(_hook(world["home"], {**_bash(world, "x"), "tool_name": "Read",
                                           "tool_input": {"file_path": world["ws"] + "/notes.txt"}}))
    assert answer["permissionDecision"] == "allow" and "updatedInput" not in answer


def _deny_with_sandbox_cause(world, raw=None):
    env = _env(world["home"])
    answer = commands.hook(json.dumps(_bash(world, "ls -la src")).encode(), {**env, "PATH": os.environ["PATH"]})
    out = _output(answer)
    assert out["permissionDecision"] == "deny" and "updatedInput" not in out
    assert f"cause {SANDBOX_CODE} agent:sandbox-unavailable" in out["permissionDecisionReason"]
    run_dir = _agent_dir(world["home"]) / "runs"
    assert not any(run_dir.glob("*/journal.jsonl")), "a call that was not run must leave no allow receipt"
    return out


def test_a_missing_bwrap_is_a_deny_with_the_new_cause(world, monkeypatch):
    _init(world)
    monkeypatch.setattr(sandbox_exec, "BWRAP", str(Path(world["home"]) / "no-such-bwrap"))
    assert "missing" in _deny_with_sandbox_cause(world)["permissionDecisionReason"]


def test_a_profile_that_cannot_compile_is_a_deny_with_the_new_cause(world, monkeypatch):
    _init(world)
    shutil.rmtree(_agent_dir(world["home"]) / "profiles")           # init cached the profile; a changed image would have none

    def broken(_image):
        raise profile_module.ProfileError("field 'x' has no finite domain")
    monkeypatch.setattr(profile_module, "compile_profile", broken)
    assert "did not compile" in _deny_with_sandbox_cause(world)["permissionDecisionReason"]


def test_the_new_cause_is_registered_after_the_highest_earlier_one():
    assert causes.code("agent:sandbox-unavailable") == SANDBOX_CODE
    assert SANDBOX_CODE == 129 and causes.code("agent:control-write") == 128


def test_the_runner_told_to_use_bwrap_without_bwrap_says_so_and_runs_nothing(world, tmp_path):
    """The hook always names its backend (`--backend bwrap` outside the launcher), so a missing bwrap is a refusal and
    never a silent Landlock run; only `--backend auto`, the default of a runner started by hand, falls back."""
    fake = tmp_path / "marker"
    script = ("import sys; sys.argv=['x','--workspace',%r,'--backend','bwrap','--profile',%r,'--','touch %s']; "
              "from prismpath.agent import sandbox_exec as s; s.BWRAP='/nonexistent/bwrap'; sys.exit(s.main(sys.argv[1:]))"
              % (world["ws"], json.dumps(profile_module.STRICTEST.to_object()), fake))
    done = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, %r)\n%s" % (str(Path(__file__).parents[2]), script)],
                          capture_output=True)
    assert done.returncode == 126 and b"did not run" in done.stderr and not fake.exists()


# ------------------------------------------------------------------------------- platform, time limit, init
def test_off_linux_an_allowed_bash_call_is_allowed_unchanged_and_status_and_doctor_say_it_is_not_confined(world, monkeypatch, capsys):
    from prismpath.agent import doctor
    _init(world)
    monkeypatch.setattr(sandbox_hook, "supported", lambda: False)
    monkeypatch.setattr(sandbox_exec, "BWRAP", str(Path(world["home"]) / "no-such-bwrap"))     # irrelevant off Linux
    env = {**_env(world["home"]), "PATH": os.environ["PATH"]}
    out = _output(commands.hook(json.dumps(_bash(world, "ls -la src")).encode(), env))
    assert out["permissionDecision"] == "allow" and "updatedInput" not in out
    state = commands.confinement_state()
    assert not state["confined"] and "decided but not confined" in state["detail"] and "linux only" in state["detail"].lower()
    monkeypatch.setenv("HOME", str(world["home"]))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    commands.status(Path(world["ws"]), False)
    assert "decided but not confined on this platform" in capsys.readouterr().out
    row = next(c for c in doctor.diagnose(Path(world["ws"]))["checks"] if c["check"] == "shell-confinement")
    assert row["status"] == "warn" and "not confined" in row["detail"]


def test_on_linux_a_broken_bwrap_stays_a_deny_and_status_says_so(world, monkeypatch):
    _init(world)
    monkeypatch.setattr(sandbox_hook, "supported", lambda: True)
    monkeypatch.setattr(sandbox_exec, "BWRAP", str(Path(world["home"]) / "no-such-bwrap"))
    state = commands.confinement_state()
    assert not state["confined"] and "cause 129" in state["detail"]
    _deny_with_sandbox_cause(world)


@pytest.mark.parametrize("given, seconds", [(None, 120), (5000, 5), (5001, 6), (90000, 90), (900000, 600), (0, 120),
                                            (-5, 120), ("9", 120), (True, 120), (1, 1)])
def test_the_call_time_limit_is_the_bash_timeout_else_120_s_at_most_600_s(given, seconds):
    tool_input = {} if given is None else {"timeout": given}
    assert sandbox_hook.call_timeout_s(tool_input) == seconds


def test_the_rewrite_carries_the_time_limit_and_the_profile_hash_does_not_depend_on_it(world):
    _init(world)
    first = _output(_hook(world["home"], _bash(world, "ls", timeout=7000)))["updatedInput"]["command"]
    second = _output(_hook(world["home"], _bash(world, "ls")))["updatedInput"]["command"]
    assert shlex.split(first)[shlex.split(first).index("--timeout") + 1] == "7"
    assert shlex.split(second)[shlex.split(second).index("--timeout") + 1] == "120"
    assert profile_module.STRICTEST.timeout_s == 30 and profile_module.STRICTEST.hash() == "767dd3c84cbb5ec504548e158571d52e7c217a530b8f43350305e14856010595"


@needs_bwrap
def test_the_runner_stops_a_command_at_the_given_limit(world):
    command = sandbox_hook.rewrite_command("sleep 20", world["ws"], world["ws"], profile_module.STRICTEST, timeout_s=1)
    done = subprocess.run(["/bin/bash", "-c", command], capture_output=True, timeout=30)
    assert done.returncode == 124 and b"stopped this command" in done.stderr


def test_init_compiles_the_profile_cache_so_the_first_bash_call_does_not(world):
    _init(world)
    image = (_agent_dir(world["home"]) / "policy.core.json").read_bytes()
    assert (_agent_dir(world["home"]) / "profiles" / (sandbox_hook._sha256_hex(image) + ".json")).is_file()


def test_init_says_when_the_sandbox_profile_cannot_be_prepared(world, monkeypatch):
    """A compile that fails at init is not silent: init warns that every allowed shell command will be refused."""
    import io
    monkeypatch.setenv("HOME", str(world["home"]))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(sandbox_hook, "supported", lambda: True)

    def broken(home, image):
        raise sandbox_hook.SandboxRefused("bwrap is not executable")
    monkeypatch.setattr(sandbox_hook, "profile_for", broken)
    out = io.StringIO()
    commands.init(Path(world["ws"]), True, False, out=out)
    assert "could not be prepared (bwrap is not executable)" in out.getvalue()
    assert "cause 129" in out.getvalue()
    out = io.StringIO()
    commands.init(Path(world["ws"]), True, True, out=out)
    assert json.loads(out.getvalue())["sandbox"]["problem"] == "bwrap is not executable"
