# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The governed agent never changes its own controls (cause 128 agent:control-write).

The paths inside the workspace that hold the agent's controls or shape its behaviour (everything under `.claude/`,
`.mcp.json`, `.git/config`, everything under `.git/hooks/`, `CLAUDE.md`, `CLAUDE.local.md` and `AGENTS.md` at any depth,
the program an installed PrismPath hook runs, the workspace root and every directory that holds one of these) are
refused for every change, under all three starters, by whichever tool names them: the file tools, the MCP file
tools, the shell commands the plain word grammar reads and the commands the hazard scan reads (a redirection or a
file changing program). A path is matched after it resolves and without regard to case, so `..`, a symbolic link
and `.CLAUDE` do not hide it, and a hard link to a control file is one too. A read is decided as before. The paths outside the workspace (`~/.claude`,
`~/.prismpath`) were already refused as outside the workspace and stay so.
"""
import json
import os
from pathlib import Path

import pytest

from prismpath.agent import claude_code, classifier, mcp_map
from prismpath.agent.policy import STARTERS, Policy, starter_path
from prismpath.kernel import causes

CAUSE = causes.code("agent:control-write")
POLICIES = {name: Policy.load(starter_path(name)) for name in STARTERS}
CONTROL = [".claude/settings.json", ".claude/settings.local.json", ".claude/hooks/guard.sh", ".claude/hooks/sub/x.py",
           ".mcp.json", ".claude"]


@pytest.fixture()
def ws(tmp_path):
    root = (tmp_path / "ws").resolve()
    for directory in (root / ".claude" / "hooks", root / "src", root / "other"):
        directory.mkdir(parents=True)
    for path in (root / ".claude" / "settings.json", root / ".mcp.json", root / "src" / "a.py"):
        path.write_text("{}\n")
    return root


def _decide(name, ws, tool, tool_input, cwd=None):
    hook = {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input,
            "cwd": str(cwd or ws)}
    result = claude_code.evaluate(hook, {"CLAUDE_PROJECT_DIR": str(ws)}, POLICIES[name])
    return result.decision.kind, result.decision.cause_code, result


def test_the_cause_is_registered_and_described():
    assert CAUSE == 128 and causes.name(128) == "agent:control-write" and causes.cause_class(128) == "routing"


@pytest.mark.parametrize("name", sorted(STARTERS))
@pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit"])
@pytest.mark.parametrize("target", CONTROL)
def test_a_file_tool_never_changes_a_control_file(name, tool, target, ws):
    key = {"file_path": str(ws / target)}
    if tool == "MultiEdit":
        key["edits"] = [{"old_string": "a", "new_string": "b"}]
    assert _decide(name, ws, tool, key)[:2] == ("refuse", CAUSE)
    assert _decide(name, ws, tool, {"file_path": target})[:2] == ("refuse", CAUSE)      # relative to cwd


@pytest.mark.parametrize("name", sorted(STARTERS))
def test_a_notebook_edit_of_a_control_file_is_refused(name, ws):
    assert _decide(name, ws, "NotebookEdit", {"notebook_path": str(ws / ".mcp.json")})[:2] == ("refuse", CAUSE)


@pytest.mark.parametrize("name,expected", [("strict", ("allow", None)), ("default", ("allow", None)),
                                           ("review", ("escalate", 127))])
def test_an_ordinary_write_keeps_its_old_verdict(name, expected, ws):
    assert _decide(name, ws, "Write", {"file_path": str(ws / "src" / "a.py"), "content": "x"})[:2] == expected
    assert _decide(name, ws, "Write", {"file_path": str(ws / "notes" / "CLAUDE.txt"), "content": "x"})[:2] == expected


@pytest.mark.parametrize("name", sorted(STARTERS))
@pytest.mark.parametrize("command", ["cat .claude/settings.json", "ls .claude/hooks", "grep x .mcp.json",
                                     "sed -n 1p .mcp.json"])
def test_a_read_of_a_control_file_is_decided_as_before(name, command, ws):
    assert _decide(name, ws, "Bash", {"command": command})[:2] == ("allow", None)
    assert _decide(name, ws, "Read", {"file_path": str(ws / ".claude" / "settings.json")})[:2] == ("allow", None)
    assert _decide(name, ws, "Glob", {"pattern": ".claude/*"})[:2] == ("allow", None)


@pytest.mark.parametrize("name", sorted(STARTERS))
@pytest.mark.parametrize("command", [
    "rm .claude/settings.json", "rm -rf .claude", "mv .claude/settings.json x", "mv src/a.py .mcp.json",
    "cp src/a.py .claude/settings.local.json", "cp .mcp.json other/x", "mkdir .claude/hooks/new",
    "touch .claude/hooks/guard.sh", "sed -i s/a/b/ .claude/settings.json", "tee .mcp.json", "ln -s src/a.py .mcp.json",
    "chmod 777 .claude/hooks"])
def test_a_shell_command_the_grammar_reads_never_changes_a_control_file(name, command, ws):
    # `cp .mcp.json other/x` only reads the control file, but the command changes files and names it, so it is
    # refused too: the classifier does not tell a source from a destination
    assert _decide(name, ws, "Bash", {"command": command})[:2] == ("refuse", CAUSE), command


@pytest.mark.parametrize("name", sorted(STARTERS))
def test_the_path_is_matched_after_it_resolves(name, ws):
    os.symlink(ws / ".claude" / "settings.json", ws / "src" / "innocent.json")
    os.symlink(ws / ".claude", ws / "dotdir")
    for path in ("src/../.claude/settings.json", "src/innocent.json", "dotdir/settings.json", "./.claude/./settings.json",
                 str(ws / "src" / ".." / ".mcp.json")):
        assert _decide(name, ws, "Write", {"file_path": path, "content": "x"})[:2] == ("refuse", CAUSE), path
    assert _decide(name, ws, "Bash", {"command": "rm src/innocent.json"})[:2] == ("refuse", CAUSE)
    from_src = _decide(name, ws, "Write", {"file_path": "../.claude/settings.json", "content": "x"}, cwd=ws / "src")
    assert from_src[:2] == ("refuse", CAUSE)


@pytest.mark.parametrize("name", sorted(STARTERS))
def test_the_program_an_installed_hook_runs_is_a_control_file(name, ws):
    venv = ws / ".venv" / "bin"
    venv.mkdir(parents=True)
    (venv / "python").write_text("#!/bin/sh\n")
    hook = f"'{venv / 'python'}' -m prismpath agent hook || exit 2"
    (ws / ".claude" / "settings.json").write_text(json.dumps(
        {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": hook}]}]}}))
    assert _decide(name, ws, "Write", {"file_path": str(venv / "python"), "content": "x"})[:2] == ("refuse", CAUSE)
    assert _decide(name, ws, "Bash", {"command": "rm .venv/bin/python"})[:2] == ("refuse", CAUSE)
    assert _decide(name, ws, "Write", {"file_path": str(ws / ".venv" / "bin" / "other"), "content": "x"})[1] != CAUSE


@pytest.mark.parametrize("name", sorted(STARTERS))
def test_the_mcp_file_tools_never_change_a_control_file(name, ws):
    policy = POLICIES[name]
    config = classifier.Config.for_workspace(ws)
    for tool, arguments in [("write_file", {"path": str(ws / ".mcp.json"), "content": "x"}),
                            ("edit_file", {"path": str(ws / ".claude" / "settings.json"), "edits": []}),
                            ("create_directory", {"path": str(ws / ".claude" / "hooks" / "new")}),
                            ("delete_path", {"path": str(ws / ".claude" / "settings.local.json")})]:
        call = mcp_map.classifier_call({"name": tool, "arguments": arguments}, str(ws))
        reading = classifier.classify(call, config)
        assert reading["path_control"] is True, tool
        decision = policy.decide(policy.reading_bytes(reading))
        assert (decision.kind, decision.cause_code) == ("refuse", CAUSE), tool
    read = mcp_map.classifier_call({"name": "read_text_file", "arguments": {"path": str(ws / ".mcp.json")}}, str(ws))
    reading = classifier.classify(read, config)
    assert reading["path_control"] is True
    assert policy.decide(policy.reading_bytes(reading)).kind == "allow" or name == "review"


@pytest.mark.parametrize("name", sorted(STARTERS))
def test_the_agents_files_outside_the_workspace_are_still_refused_as_outside(name, ws, tmp_path):
    home = tmp_path / "home"
    for rel in (".claude/settings.json", ".prismpath/agent/policy.core.json"):
        got = _decide(name, ws, "Write", {"file_path": str(home / rel), "content": "x"})
        assert got[:2] == ("refuse", causes.code("agent:outside-workspace")), rel
    assert _decide(name, ws, "Write", {"file_path": "~/.claude/settings.json", "content": "x"})[0] != "allow"


def test_the_refusal_carries_its_cause_and_a_receipt_slot(ws):
    answer = _decide("default", ws, "Write", {"file_path": str(ws / ".claude" / "settings.json"), "content": "x"})[2].answer
    out = answer["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "cause 128 agent:control-write" in out["permissionDecisionReason"]
    assert claude_code.RECEIPT_PLACEHOLDER in out["permissionDecisionReason"]


def test_a_git_change_naming_a_control_file_is_refused(ws):
    config = classifier.Config.for_workspace(ws)
    reading = classifier.classify({"tool": "git", "args": {"subcommand": "mv", "args": [".mcp.json", "x"]}}, config)
    assert reading["path_control"] is True and reading["git_op"] == "local_write"
    for name, policy in POLICIES.items():
        decision = policy.decide(policy.reading_bytes(reading))
        assert (decision.kind, decision.cause_code) == ("refuse", CAUSE), name
    status = classifier.classify({"tool": "git", "args": {"subcommand": "status"}}, config)
    assert status["path_control"] is False


def test_the_rules_say_that_these_refusals_are_observations_not_policy():
    for name in STARTERS.values():
        text = (Path(__file__).resolve().parents[1] / "agent" / "policy" / f"{name}.rules.md").read_text("utf-8")
        assert "observations a later policy proposal may read" in text and "never change the policy on their own" in text


# ---------------------------------------------------------------- the gaps PR #60 left open
@pytest.mark.parametrize("name", sorted(STARTERS))
@pytest.mark.parametrize("command", [
    "echo x > .claude/settings.json", "printf y >> .mcp.json", "echo x>.mcp.json", "cat a.txt | tee .claude/hooks/g.sh",
    "cd .claude && echo x > settings.json", "ls && rm -rf .claude/hooks", "echo x &> .mcp.json", "echo x >&.mcp.json",
    "echo x > .CLAUDE/settings.json", "echo x > CLAUDE.md", "sed -i s/a/b/ AGENTS.md; ls", "git add .mcp.json && git commit -m x"])
def test_a_command_outside_the_grammar_that_redirects_onto_a_control_file_is_refused(name, command, ws):
    (ws / "a.txt").write_text("x\n")
    assert _decide(name, ws, "Bash", {"command": command})[:2] == ("refuse", CAUSE), command


@pytest.mark.parametrize("name", sorted(STARTERS))
@pytest.mark.parametrize("command", ["cat .mcp.json | head", "cat .mcp.json 2>&1 | head", "grep x .claude/settings.json; ls",
                                     "echo x > notes.txt", "ls -la . | head", "python -m pytest . 2>&1 | tail -3"])
def test_a_command_outside_the_grammar_that_only_reads_a_control_file_is_not_a_control_change(name, command, ws):
    kind, code, _ = _decide(name, ws, "Bash", {"command": command})
    assert code != CAUSE, command


def test_the_scan_asks_with_the_scan_reading(ws):
    _, _, result = _decide("default", ws, "Bash", {"command": "echo x > .claude/settings.json"})
    assert result.reading["path_control"] is True and result.reading["command_class"] == "mutating"
    assert result.reading["tool"] == "run_command"


@pytest.mark.parametrize("name", sorted(STARTERS))
@pytest.mark.parametrize("target", [".CLAUDE/settings.json", ".Claude/Hooks/g.sh", ".MCP.JSON", ".GIT/CONFIG", ".Git/Hooks/pre-commit",
                                    "claude.MD", "src/Claude.Local.MD", "agents.md"])
def test_a_spelling_in_another_case_names_the_same_file(name, target, ws):
    assert _decide(name, ws, "Write", {"file_path": str(ws / target), "content": "x"})[:2] == ("refuse", CAUSE)
    assert _decide(name, ws, "Bash", {"command": f"rm {target}"})[:2] == ("refuse", CAUSE)


@pytest.mark.parametrize("name", sorted(STARTERS))
def test_a_hard_link_to_a_control_file_is_a_control_path(name, ws):
    os.link(ws / ".mcp.json", ws / "other" / "innocent.txt")
    (ws / "CLAUDE.md").write_text("rules\n")
    (ws / "src" / "deep").mkdir()
    os.link(ws / "CLAUDE.md", ws / "src" / "deep" / "notes.txt")
    for path in ("other/innocent.txt", "src/deep/notes.txt"):
        assert _decide(name, ws, "Write", {"file_path": path, "content": "x"})[:2] == ("refuse", CAUSE), path
        assert _decide(name, ws, "Bash", {"command": f"rm {path}"})[:2] == ("refuse", CAUSE), path
        assert _decide(name, ws, "Read", {"file_path": path})[:2] == ("allow", None) or name == "review"
    assert _decide(name, ws, "Write", {"file_path": "other/plain.txt", "content": "x"})[1] != CAUSE
    (ws / "other" / "single.txt").write_text("x")           # one link only: not a control file
    assert _decide(name, ws, "Write", {"file_path": "other/single.txt", "content": "x"})[1] != CAUSE


@pytest.mark.parametrize("name", sorted(STARTERS))
@pytest.mark.parametrize("target", [".git/hooks/pre-commit", ".git/hooks/sub/x", ".git/config", ".git/hooks"])
def test_git_hooks_and_config_are_control_paths(name, target, ws):
    (ws / ".git" / "hooks").mkdir(parents=True)
    assert _decide(name, ws, "Write", {"file_path": str(ws / target), "content": "x"})[:2] == ("refuse", CAUSE)
    assert _decide(name, ws, "Bash", {"command": f"rm {target}"})[:2] == ("refuse", CAUSE)
    assert _decide(name, ws, "Write", {"file_path": str(ws / ".git" / "HEAD"), "content": "x"})[1] != CAUSE


@pytest.mark.parametrize("name", sorted(STARTERS))
@pytest.mark.parametrize("target", ["CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "src/CLAUDE.md", "src/deep/er/AGENTS.md",
                                    ".claude/commands/x.md", ".claude/agents/a.md", ".claude/skills/s/SKILL.md",
                                    ".claude/anything.txt"])
def test_files_that_shape_the_agent_are_control_paths_and_reads_stay_allowed(name, target, ws):
    assert _decide(name, ws, "Write", {"file_path": str(ws / target), "content": "x"})[:2] == ("refuse", CAUSE)
    assert _decide(name, ws, "Edit", {"file_path": target, "old_string": "a", "new_string": "b"})[:2] == ("refuse", CAUSE)
    if name != "review":
        assert _decide(name, ws, "Read", {"file_path": str(ws / target)})[:2] == ("allow", None)


@pytest.mark.parametrize("name", sorted(STARTERS))
@pytest.mark.parametrize("command", ["rm -r .", "rm -rf ./", "mv . x", "rm -rf .git", "rm -rf src/../.", "mv src/deep x",
                                     "rm -rf src/deep", "rm -rf other/../src/deep/", "rm -r .", "rmdir src/deep", "find . -delete",
                                     "git rm -r .", "git clean -fdx ."])
def test_a_change_to_the_root_or_a_directory_that_holds_a_control_file_is_refused(name, command, ws):
    (ws / "src" / "deep").mkdir()
    (ws / "src" / "deep" / "AGENTS.md").write_text("x\n")
    (ws / ".git").mkdir()
    kind, code, result = _decide(name, ws, "Bash", {"command": command})
    assert result.reading["path_control"] is True and kind == "refuse", command
    assert code == CAUSE, command
    assert _decide(name, ws, "Bash", {"command": "ls ."})[:2] == ("allow", None)         # a read of the root is a read


@pytest.mark.parametrize("name", sorted(STARTERS))
@pytest.mark.parametrize("command", ["git add .", "git checkout .", "cp notes.txt .", "cp -r src/deep .", "mv notes.txt .",
                                     "mv notes.txt ./", "pytest .", "tee ./new", "tar czf out.tgz .", "echo x > fresh.txt",
                                     "cat notes.txt | tee ./new"])
def test_writing_into_the_root_or_a_holder_is_decided_as_before(name, command, ws):
    """The root and the directories that hold control files are control targets only for a removal or a move; a
    command that names them to write into them, or to read them, gets the verdict it had before the rule."""
    (ws / "notes.txt").write_text("n\n")
    (ws / "src" / "deep").mkdir()
    (ws / "src" / "deep" / "AGENTS.md").write_text("x\n")
    _, _, result = _decide(name, ws, "Bash", {"command": command})
    assert result.reading["path_control"] is False and result.decision.cause_code != CAUSE, command


@pytest.mark.parametrize("name", sorted(STARTERS))
def test_a_directory_that_holds_no_control_file_is_not_control(name, ws):
    (ws / "build").mkdir()
    (ws / "build" / "out.o").write_text("x")
    assert _decide(name, ws, "Bash", {"command": "rm -rf build"})[1] != CAUSE
    assert _decide(name, ws, "Bash", {"command": "rm build/out.o"})[1] != CAUSE


def test_the_directories_of_a_hook_program_are_control(ws):
    venv = ws / ".venv" / "bin"
    venv.mkdir(parents=True)
    (venv / "python").write_text("#!/bin/sh\n")
    hook = f"'{venv / 'python'}' -m prismpath agent hook || exit 2"
    (ws / ".claude" / "settings.json").write_text(json.dumps(
        {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": hook}]}]}}))
    assert _decide("default", ws, "Bash", {"command": "rm -rf .venv"})[:2] == ("refuse", CAUSE)
    assert _decide("default", ws, "Bash", {"command": "rm -rf .venv/bin"})[:2] == ("refuse", CAUSE)
    assert _decide("default", ws, "Bash", {"command": "cp x .venv/bin"})[1] != CAUSE      # into it: decided as before


def test_the_walk_below_a_directory_is_bounded(ws, monkeypatch):
    monkeypatch.setattr(classifier, "WALK_LIMIT", 5)
    (ws / "many").mkdir()
    for index in range(10):
        (ws / "many" / f"f{index}").write_text("x")
    (ws / "many" / "zz").mkdir()
    (ws / "many" / "zz" / "CLAUDE.md").write_text("x")
    assert classifier.disk_facts("many", classifier.Config.for_workspace(ws)).control in (True, False)   # it returns


@pytest.mark.skipif(os.name == "nt", reason="the written hook command is a POSIX shell line")
def test_a_package_planted_in_the_workspace_does_not_shadow_the_hook(tmp_path):
    """`python -m prismpath` run from the workspace would import a planted `prismpath/` first; the written command
    does not put the working directory on sys.path (-P, or the -c launcher before Python 3.11), and it still finds
    PrismPath through PYTHONPATH, which -I would have dropped."""
    import subprocess
    import sys
    from prismpath.agent import commands
    work = tmp_path / "work"
    (work / "prismpath").mkdir(parents=True)
    marker = tmp_path / "RAN"
    (work / "prismpath" / "__init__.py").write_text(f"open({str(marker)!r}, 'w').write('planted')\n")
    (work / "sitecustomize.py").write_text(f"open({str(marker)!r}, 'w').write('site')\n")
    (work / "x.pth").write_text("import os\n")
    root = str(Path(__file__).resolve().parents[2])
    env = {**os.environ, "PYTHONPATH": root}
    unsafe = subprocess.run([sys.executable, "-m", "prismpath", "agent", "hook"], input=b"{}",
                            capture_output=True, cwd=work, env=env)
    assert marker.exists(), "the premise: without the guard the planted package runs"
    assert unsafe.returncode in (0, 1, 2)
    import shlex
    launcher = " ".join(shlex.quote(w) for w in
                        [sys.executable, "-c", commands.LAUNCHER_310, "prismpath", "agent", "hook"]) + " || exit 2"
    for line in (commands.hook_command(), launcher):           # the written line, and the 3.10 form on this Python
        marker.unlink(missing_ok=True)
        done = subprocess.run(["sh", "-c", line], input=b"{}", capture_output=True, cwd=work, env=env)
        assert not marker.exists(), line
        assert json.loads(done.stdout)["hookSpecificOutput"]["hookEventName"] == "PreToolUse", done.stderr
