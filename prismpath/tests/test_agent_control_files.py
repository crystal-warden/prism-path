# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The governed agent never changes its own controls (cause 128 agent:control-write).

The files inside the workspace that hold the agent's controls (`.claude/settings.json`, `.claude/settings.local.json`,
everything under `.claude/hooks/`, `.mcp.json`, `.claude` itself and the program an installed PrismPath hook runs)
are refused for every change, under all three starters, by whichever tool names them: the file tools, the MCP file
tools and the shell commands the plain word grammar reads. A path is matched after it resolves, so `..` and a
symbolic link do not hide it. A read is decided as before. The paths outside the workspace (`~/.claude`,
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
    assert _decide(name, ws, "Write", {"file_path": str(ws / ".claude" / "commands" / "x.md"), "content": "x"})[:2] \
        == expected                                                  # the rest of .claude is not a control file


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
