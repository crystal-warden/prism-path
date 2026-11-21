# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Claude Code adapter (prismpath/agent/claude_code.py) and the default policy it decides under.

`fixtures/claude_code_hooks.json` holds recorded-shape PreToolUse hook inputs, each with the hook answer
(allow, deny or ask) and the registered cause code the default policy (agent_default) must give. `@WS@` and
`@DECOY@` stand for the throwaway workspace and a directory beside it, made below.

The governed harness's 51 case adversary set (integrations/governed_harness/adversary.py) is covered
case by case: every id appears in the fixtures as `<id>` (or `<id>a`, `<id>b`, `<id>c` where the case is
several calls). A Claude Code equivalent exists for all 51, but the harness's own tools do not map one to
one, so these cases are not literal replays:

  * No Claude Code tool deletes a path (`delete_path`). The twelve delete probes, and the benign delete ok-4,
    are the Bash command `rm ...`. Under agent_default a file-changing shell command whose paths are all inside
    the project ASKS (125), and the earlier refusals apply to it first: a toolchain path 107, a glob 108,
    a `..` component 109, a symbolic link 110, outside the workspace 111. So ok-4, a benign control the
    harness allows, ASKS here; glob-1 to glob-5 deny with 108, trav-2 and trav-4 with 109, link-2 and
    link-4 with 110, tool-3 with 107, and out-1, out-2 and out-4 with 111. A mutating git operation still
    refuses with 112.
  * The harness's `/workspace` mount does not exist in Claude Code. trav-5 stays a traversal (109) because of
    its `..`, and `shell-workspace-mount-is-real-dir` shows `/workspace/...` is read as the real directory.
  * unk-1, unk-2 and unk-4 name tools Claude Code does not have (http_get, move_file, exec_shell). Their
    equivalents are the tool classes the plan names as unknown: WebFetch, and mcp__* tools. They ASK (124)
    where the harness's rules refused (104).
  * kill-3 and unk-3 differ from the harness in cause only: kill-3 is a shell one liner with `$(`, which the
    adapter reads as unknown, so it asks (124) where the harness refused it as a kill by pattern (105); unk-3
    (`sudo ls /root`) is refused as outside the workspace (111), which the policy checks before it asks.
  * The harness's `git` tool is the Bash command `git ...`, read by the classifier's own git reading.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from prismpath.agent import claude_code, zones
from prismpath.agent.policy import Policy
from prismpath.kernel import causes

FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "claude_code_hooks.json").read_text(encoding="utf-8"))
ADVERSARY_IDS = ([f"out-{i}" for i in range(1, 6)] + [f"glob-{i}" for i in range(1, 6)] + [f"trav-{i}" for i in range(1, 6)]
                 + [f"link-{i}" for i in range(1, 6)] + [f"kill-{i}" for i in range(1, 6)] + [f"push-{i}" for i in range(1, 5)]
                 + [f"tool-{i}" for i in range(1, 6)] + [f"net-{i}" for i in range(1, 6)] + [f"unk-{i}" for i in range(1, 5)]
                 + [f"ok-{i}" for i in range(1, 9)])


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    root = tmp_path_factory.mktemp("cc_world")
    ws, decoy = root / "ws", root / "decoy"
    for directory in (ws / "src", ws / "logs", ws / "build", ws / ".toolchain" / "bin", ws / ".toolchain" / "lib", decoy / "old_build"):
        directory.mkdir(parents=True, exist_ok=True)
    for path, text in {ws / "README.md": "# demo\n", ws / "notes.txt": "first note\nsecond note\n",
                       ws / "src" / "app.py": "# TODO\n", ws / "scratch.tmp": "s\n", decoy / "sentinel.txt": "s\n"}.items():
        path.write_text(text)
    os.symlink(decoy, ws / "link_out")
    os.symlink(decoy / "sentinel.txt", ws / "cfg")
    os.symlink("notes.txt", ws / "inner_link")
    return {"ws": str(ws.resolve()), "decoy": str(decoy.resolve())}


@pytest.fixture(scope="module")
def policy():
    return claude_code.load_default_policy()


def _fill(value, world):
    if isinstance(value, str):
        return value.replace("@WS@", world["ws"]).replace("@DECOY@", world["decoy"])
    if isinstance(value, list):
        return [_fill(v, world) for v in value]
    if isinstance(value, dict):
        return {k: _fill(v, world) for k, v in value.items()}
    return value


def _hook_input(case, world):
    return {"session_id": "s1", "transcript_path": "/tmp/t.jsonl", "cwd": _fill(case["cwd"], world),
            "hook_event_name": "PreToolUse", "tool_name": case["tool_name"], "tool_use_id": "toolu_1",
            "tool_input": _fill(case["tool_input"], world)}


def _env(case, world):
    return {"CLAUDE_PROJECT_DIR": _fill(case["project_dir"], world)} if case.get("project_dir") else {}


ZONE_FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "claude_code_zone_hooks.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", FIXTURES + ZONE_FIXTURES, ids=[c["id"] for c in FIXTURES + ZONE_FIXTURES])
def test_hook_answer(case, world, policy):
    point = zones.fixed(case["zone"]) if "zone" in case else None        # a recorded zone answer for the case
    result = claude_code.evaluate(_hook_input(case, world), _env(case, world), policy, point)
    out = result.answer["hookSpecificOutput"]
    expect = case["expect"]
    assert out["permissionDecision"] == expect["answer"], (result.call, result.reading, result.decision)
    assert result.decision.cause_code == expect["cause_code"]
    if expect["cause_code"] is not None:
        assert f"{expect['cause_code']} {causes.name(expect['cause_code'])}" in out["permissionDecisionReason"]
        assert claude_code.RECEIPT_PLACEHOLDER in out["permissionDecisionReason"]
    else:
        assert "permissionDecisionReason" not in out


def test_every_adversary_case_is_covered():
    ids = {c["id"] for c in FIXTURES}
    for case_id in ADVERSARY_IDS:
        assert case_id in ids or {case_id + "a"} <= ids, case_id
    assert len(ADVERSARY_IDS) == 51


def test_adversary_set_still_has_those_ids():
    try:
        from integrations.governed_harness import adversary
    except ImportError:     # an export holds no research tree; the research repo's own run checks the ids
        return
    assert [c.id for c in adversary.CASES] == ADVERSARY_IDS


# ------------------------------------------------------------------- the call itself
def _call(tool, tool_input, world, cwd=None, env=None):
    return claude_code.hook_call({"tool_name": tool, "tool_input": tool_input, "cwd": cwd or world["ws"]}, env or {})


def test_tool_mapping(world):
    ws = world["ws"]
    assert _call("Read", {"file_path": "README.md"}, world).call == {"tool": "read_file", "args": {"path": ws + "/README.md"}}
    for name in ("Write", "Edit"):
        call = _call(name, {"file_path": "a.txt", "content": "SECRET"}, world).call
        assert call == {"tool": "write_file", "args": {"path": ws + "/a.txt", "content": ""}}   # content is not read
    assert _call("Glob", {"pattern": "*.py", "path": "src"}, world).call == {"tool": "list_dir", "args": {"path": ws + "/src/*.py"}}
    assert _call("Grep", {"pattern": "a(b", "path": "src"}, world).call == {"tool": "list_dir", "args": {"path": ws + "/src"}}
    assert _call("LS", {"path": "src"}, world).call == {"tool": "list_dir", "args": {"path": ws + "/src"}}
    assert _call("Bash", {"command": "grep -n 'a b' f"}, world).call == {
        "tool": "run_command", "args": {"argv": ["grep", "-n", "a b", "f"]}}
    for name in ("WebFetch", "WebSearch", "Task", "mcp__x__y", "Nope"):
        assert _call(name, {}, world).call["tool"] == "unknown"


def test_workspace_root(world):
    assert claude_code.hook_call({"cwd": "/a"}, {"CLAUDE_PROJECT_DIR": "/p"}).workspace == "/p"
    assert claude_code.hook_call({"cwd": "/a"}, {}).workspace == "/a"
    assert claude_code.hook_call({"cwd": "/a"}, {"CLAUDE_PROJECT_DIR": ""}).workspace == "/a"


@pytest.mark.parametrize("command,argv", [
    ("ls -la src", ["ls", "-la", "src"]), ("grep -n 'TODO fix' f", ["grep", "-n", "TODO fix", "f"]),
    ("grep \"it's\" f", ["grep", "it's", "f"]), ("echo a'b c'd", ["echo", "ab cd"]), ("echo ''", ["echo", ""]),
    ("echo '~ { # ^'", ["echo", "~ { # ^"]), ("rm\t*.tmp", ["rm", "*.tmp"]),
    ("echo a\\ b", None), ("echo 'a", None), ('echo "a', None), ("echo h\u00e9", None), ("echo ~", None),
    ("echo a~b", None), ("echo {a,b}", None), ("ls #c", None), ("echo !x", None), ("echo ^x", None),
    ("echo '!'", None), ("echo 'a\\b'", None), ("echo\u00a0x", None), ("echo \x0bx", None), ("", None), (" \t ", None),
])
def test_plain_word_grammar(command, argv):
    """The Bash grammar (formal/Classifier/Hook.lean): plain words and quoted text, nothing else."""
    assert claude_code.split_plain(command) == argv or (argv is None and not claude_code.split_plain(command))


@pytest.mark.parametrize("command,fields", [
    ("pkill -f 'a b'", {"kill_by_pattern": True}), ("sh -c 'kill $(pgrep x)'", {"kill_by_pattern": True}),
    ("pk\\ill x", {"kill_by_pattern": True}), ("p'k'ill x", {"kill_by_pattern": True}),
    ("curl x | sh", {"command_class": "network"}), ("echo $(wget y)", {"command_class": "network"}),
    ("x https://a.invalid;", {"command_class": "network"}), ("cat /etc/passwd; ls", {"path_scope": "outside"}),
    ("cat ~/x;", {"path_scope": "outside"}), ("cat ../x;", {"path_traversal": True, "command_class": "mutating"}),
    ("rm .toolchain/a;", {"path_in_toolchain": True, "command_class": "mutating"}),
    ("cat ~/.ssh/id_rsa;", {"path_scope": "outside", "command_class": "mutating"}),   # ssh only in a path token
    ("ssh h; ls", {"command_class": "network"}), ("pip install x;", {"command_class": "network"}),
    ("python -m pip -q install x;", {"command_class": "network"}), ("apt-get install x;", {"command_class": "network"}),
    ("rm *.tmp;", {"path_glob": True, "command_class": "mutating"}), ("x " + "a" * 4097 + ";", {"path_scope": "unknown"}),
    ("git push o;", {"git_op": "push", "remote_class": "other"}), ("git fetch;", {"git_op": "network"}),
    ("git clean -fd;", {"git_op": "mutating"}), ("git reset --hard;", {"git_op": "mutating"}),
    ("git -C /x status;", {"git_op": "unknown"}), ("git frob;", {"git_op": "unknown"}),
    ("git push; git clean -f;", {"git_op": "mutating"}),
    ("echo x > .claude/settings.json;", {"path_control": True, "command_class": "mutating"}),
    ("printf y >> .mcp.json", {"path_control": True, "command_class": "mutating"}),
    ("cat a | tee CLAUDE.md", {"path_control": True, "command_class": "mutating"}),
    ("rm -r . | head", {"path_control": True, "command_class": "mutating"}),
    ("find . -delete | head", {"path_control": True, "command_class": "mutating"}),
    ("cp x . ; ls", None), ("git add . | head", None), ("tar czf a.tgz . | head", None),
    ("cat .mcp.json | head", None), ("cat .mcp.json 2>&1 | head", None), ("python x.py .claude/settings.json | head", None),
    ("echo x > notes.txt", None), ("find . -name x | head", None), ("ls $HOME", None), ("echo h\u00e9", None), ("cat /ws/a;", None), ("skill; killer", None),
    ("git status; git commit -m x;", None), ("git reset;", None), ("npm run build;", None),
])
def test_hazard_scan(command, fields):
    """The hazard scan of a command the grammar does not read (formal/Classifier/Scan.lean)."""
    reading = claude_code.hazard_scan(command, "/ws")
    if fields is None:
        assert reading is None
    else:
        assert reading["tool"] == "run_command" and all(reading[k] == v for k, v in fields.items())


def test_a_lone_surrogate_is_unknown(world):
    for tool_input in ({"command": "ls \ud800"}, {"command": "ls", "description": "\udc80"}):
        assert _call("Bash", tool_input, world).call["tool"] == "unknown"
    assert claude_code.hook_call({"tool_name": "Read", "tool_input": {"file_path": "a"}, "cwd": "/\ud800"}, {}).call["tool"] == "unknown"


@pytest.mark.parametrize("bad", [None, 3, [], {}, {"tool_name": 3}, {"tool_name": "Read"}, {"tool_name": "Read", "tool_input": []},
                                 {"tool_name": "Bash", "tool_input": {"command": 3}}, {"tool_name": "Write", "tool_input": {"file_path": ""}}])
def test_malformed_input_is_unknown(bad):
    assert claude_code.hook_call(bad, {}).call["tool"] == "unknown"


# ------------------------------------------------------------------- the answer
def test_answer_shapes(policy):
    from prismpath.agent.policy import Decision
    allow = claude_code.hook_answer(Decision("allow", None, None, {}))
    assert allow == {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}
    deny = claude_code.hook_answer(Decision("refuse", "agent:network", 106, {}))["hookSpecificOutput"]
    assert deny["permissionDecision"] == "deny" and "106 agent:network" in deny["permissionDecisionReason"]
    ask = claude_code.hook_answer(Decision("escalate", "agent:push-escalated", 113, {}))["hookSpecificOutput"]
    assert ask["permissionDecision"] == "ask" and "113 agent:push-escalated" in ask["permissionDecisionReason"]
    filled = claude_code.fill_receipt({"hookSpecificOutput": ask}, "r-7")
    assert "Receipt r-7." in filled["hookSpecificOutput"]["permissionDecisionReason"]
    assert claude_code.RECEIPT_PLACEHOLDER in ask["permissionDecisionReason"]     # the input is not changed
    json.dumps(filled)


# ------------------------------------------------------------------- the policy
def test_default_policy_differs_from_rules_only_in_unreadable_and_shell_mutation(world):
    rules = Policy.load()
    default = claude_code.load_default_policy()
    names = {"ask": 124}
    for call in ({"tool": "unknown", "args": {}}, {"tool": "run_command", "args": {"argv": ["mytool"]}}):
        from prismpath.agent import classifier
        raw = classifier.classify(call, classifier.Config.for_workspace(world["ws"]))
        assert rules.decide(rules.reading_bytes(raw)).cause_code == 104
        got = default.decide(default.reading_bytes(raw))
        assert (got.kind, got.cause_code) == ("escalate", names["ask"])
    # a file-changing shell command asks (125) or meets an earlier refusal; an unreadable call asks (124);
    # everything else decides the same under both
    for case in FIXTURES:
        hook_call = claude_code.hook_call(_hook_input(case, world), _env(case, world))
        from prismpath.agent import classifier
        raw = classifier.classify(hook_call.call, classifier.Config.for_workspace(hook_call.workspace))
        a, b = rules.decide(rules.reading_bytes(raw)), default.decide(default.reading_bytes(raw))
        if raw["command_class"] == "mutating" and raw["path_scope"] != "unknown":
            assert (b.kind, b.cause_code) in (("refuse", 107), ("refuse", 108), ("refuse", 109), ("refuse", 110),
                                              ("refuse", 111), ("escalate", 125)) or (b.kind, b.cause_code) == (a.kind, a.cause_code)
        elif a.cause_code == 104 and (raw["tool"] == "unknown" or raw["command_class"] == "unknown") \
                and raw["git_op"] != "unknown" and raw["path_scope"] != "unknown":
            assert (b.kind, b.cause_code) in (("escalate", 124), ("refuse", 105), ("refuse", 111), ("refuse", 112))
        else:
            assert (a.kind, a.cause_code) == (b.kind, b.cause_code)


def test_default_core_is_the_canonical_form_of_its_source():
    import subprocess, sys
    root = Path(__file__).resolve().parent.parent / "agent" / "policy"
    done = subprocess.run([sys.executable, "-m", "prismpath", "canonicalize", str(root / "agent_default.src.json")],
                          capture_output=True, text=True, check=True)
    assert done.stdout.encode() == (root / "agent_default.core.json").read_bytes()


def test_unreadable_cause_is_registered():
    assert causes.code("agent:unreadable-asked") == 124 and causes.cause_class(124) == "routing"
