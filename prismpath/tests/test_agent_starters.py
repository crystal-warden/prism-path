# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The three starter policies `prismpath agent init --policy` offers (prismpath/agent/policy.py STARTERS):

  strict   agent_rules     a call it cannot read and a shell command that changes files are refused
  default  agent_default   those two ask the person instead
  review   agent_review    agent_default, but every change inside the workspace asks (127 agent:change-asked)

Each ships as a readable source `<image>.rules.md` beside the canonical image `<image>.core.json`, unsigned;
`init` attests the chosen image with the user's own authority key. The table below is the answer each starter
gives to every Claude Code equivalent of the governed harness's 51 case adversary set (the A2 recordings in
fixtures/claude_code_hooks.json, the same world as tests/test_agent_claude_code.py), and the hazards are held
to never allowed over every reading the classifier can produce, not only over the recordings.
"""
import itertools
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from prismpath.agent import claude_code
from prismpath.agent.policy import DEFAULT_STARTER, STARTERS, Policy, starter_of, starter_path
from prismpath.kernel import policy_source as ps

POLICY = Path(__file__).resolve().parents[1] / "agent" / "policy"
FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "claude_code_hooks.json").read_text(encoding="utf-8"))
ADVERSARY = re.compile(r"^(out|glob|trav|link|kill|push|tool|net|unk|ok)-\d+[abc]?$")
HAZARDS = ("out", "glob", "trav", "link", "tool", "kill", "net")

# (strict, default, review): the hook answer and the registered cause code
TABLE = {
    "out-1": (("deny", 111), ("deny", 111), ("deny", 111)),
    "out-2": (("deny", 111), ("deny", 111), ("deny", 111)),
    "out-3": (("deny", 111), ("deny", 111), ("deny", 111)),
    "out-4": (("deny", 111), ("deny", 111), ("deny", 111)),
    "out-5": (("deny", 111), ("deny", 111), ("deny", 111)),
    "glob-1": (("deny", 112), ("deny", 108), ("deny", 108)),
    "glob-2": (("deny", 112), ("deny", 108), ("deny", 108)),
    "glob-3": (("deny", 112), ("deny", 108), ("deny", 108)),
    "glob-4": (("deny", 112), ("deny", 108), ("deny", 108)),
    "glob-5": (("deny", 112), ("deny", 108), ("deny", 108)),
    "trav-1": (("deny", 109), ("deny", 109), ("deny", 109)),
    "trav-2": (("deny", 111), ("deny", 109), ("deny", 109)),
    "trav-3": (("deny", 109), ("deny", 109), ("deny", 109)),
    "trav-4": (("deny", 112), ("deny", 109), ("deny", 109)),
    "trav-5": (("deny", 109), ("deny", 109), ("deny", 109)),
    "link-1": (("deny", 110), ("deny", 110), ("deny", 110)),
    "link-2": (("deny", 111), ("deny", 110), ("deny", 110)),
    "link-3": (("deny", 110), ("deny", 110), ("deny", 110)),
    "link-4": (("deny", 112), ("deny", 110), ("deny", 110)),
    "link-5": (("deny", 110), ("deny", 110), ("deny", 110)),
    "kill-1": (("deny", 105), ("deny", 105), ("deny", 105)),
    "kill-2": (("deny", 105), ("deny", 105), ("deny", 105)),
    "kill-3": (("deny", 104), ("deny", 105), ("deny", 105)),   # the hazard scan sees the kill word
    "kill-4": (("deny", 105), ("deny", 105), ("deny", 105)),
    "kill-5": (("deny", 105), ("deny", 105), ("deny", 105)),
    "push-1": (("ask", 113), ("ask", 113), ("ask", 113)),
    "push-2": (("ask", 113), ("ask", 113), ("ask", 113)),
    "push-3": (("ask", 113), ("ask", 113), ("ask", 113)),
    "push-4": (("ask", 113), ("ask", 113), ("ask", 113)),
    "tool-1": (("deny", 107), ("deny", 107), ("deny", 107)),
    "tool-2": (("deny", 107), ("deny", 107), ("deny", 107)),
    "tool-3": (("deny", 112), ("deny", 107), ("deny", 107)),
    "tool-4": (("deny", 107), ("deny", 107), ("deny", 107)),
    "tool-5": (("deny", 107), ("deny", 107), ("deny", 107)),
    "net-1": (("deny", 106), ("deny", 106), ("deny", 106)),
    "net-2": (("deny", 106), ("deny", 106), ("deny", 106)),
    "net-3": (("deny", 106), ("deny", 106), ("deny", 106)),
    "net-4": (("deny", 106), ("deny", 106), ("deny", 106)),
    "net-5": (("deny", 106), ("deny", 106), ("deny", 106)),
    "unk-1": (("deny", 104), ("ask", 124), ("ask", 124)),
    "unk-2": (("deny", 104), ("ask", 124), ("ask", 124)),
    "unk-3": (("deny", 104), ("deny", 111), ("deny", 111)),
    "unk-4": (("deny", 104), ("ask", 124), ("ask", 124)),
    "ok-1": (("allow", None), ("allow", None), ("allow", None)),
    "ok-2": (("allow", None), ("allow", None), ("allow", None)),
    "ok-3": (("allow", None), ("allow", None), ("ask", 127)),
    "ok-4": (("deny", 112), ("ask", 125), ("ask", 127)),
    "ok-5": (("allow", None), ("allow", None), ("allow", None)),
    "ok-6": (("allow", None), ("allow", None), ("allow", None)),
    "ok-7a": (("allow", None), ("allow", None), ("allow", None)),
    "ok-7b": (("allow", None), ("allow", None), ("allow", None)),
    "ok-8a": (("allow", None), ("allow", None), ("ask", 127)),
    "ok-8b": (("allow", None), ("allow", None), ("ask", 127)),
    "ok-8c": (("allow", None), ("allow", None), ("ask", 127)),
}
ORDER = ("strict", "default", "review")


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    root = tmp_path_factory.mktemp("starter_world")
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
def policies():
    return {name: Policy.load(starter_path(name)) for name in STARTERS}


def _fill(value, world):
    if isinstance(value, str):
        return value.replace("@WS@", world["ws"]).replace("@DECOY@", world["decoy"])
    if isinstance(value, list):
        return [_fill(v, world) for v in value]
    if isinstance(value, dict):
        return {k: _fill(v, world) for k, v in value.items()}
    return value


def _answer(case, world, policy):
    hook_input = {"session_id": "s1", "cwd": _fill(case["cwd"], world), "hook_event_name": "PreToolUse",
                  "tool_name": case["tool_name"], "tool_input": _fill(case["tool_input"], world)}
    env = {"CLAUDE_PROJECT_DIR": _fill(case["project_dir"], world)} if case.get("project_dir") else {}
    result = claude_code.evaluate(hook_input, env, policy)
    return result.answer["hookSpecificOutput"]["permissionDecision"], result.decision.cause_code


ADVERSARY_CASES = [case for case in FIXTURES if ADVERSARY.match(case["id"])]


# ----------------------------------------------------------------- the starters themselves
def test_the_starters_are_strict_default_review_and_session():
    assert STARTERS == {"strict": "agent_rules", "default": "agent_default", "review": "agent_review",
                        "session": "agent_session"}
    assert DEFAULT_STARTER == "default"


@pytest.mark.parametrize("name", sorted(STARTERS))
def test_each_starter_compiles_from_its_source_to_the_shipped_image_byte_for_byte(name):
    image = STARTERS[name]
    source = (POLICY / f"{image}.rules.md").read_text(encoding="utf-8")
    assert ps.compile_source(source, f"{image}.rules.md") + b"\n" == starter_path(name).read_bytes()
    assert starter_of(starter_path(name).read_bytes()[:-1]) == name       # the bytes init records
    assert starter_of(starter_path(name).read_bytes()) is None            # exact: another spelling is custom


def test_default_is_agent_default_unchanged():
    # the image every existing setup recorded; a starter changing it would re-attest every user's policy
    import hashlib
    assert hashlib.sha256(starter_path("default").read_bytes()).hexdigest() == \
        hashlib.sha256((POLICY / "agent_default.core.json").read_bytes()).hexdigest()
    assert starter_path("default") == POLICY / "agent_default.core.json"
    assert starter_path("strict") == POLICY / "agent_rules.core.json"


# ----------------------------------------------------------------- the adversary set under each starter
def test_the_table_covers_every_adversary_case_in_the_recordings():
    assert sorted(TABLE) == sorted(case["id"] for case in ADVERSARY_CASES)
    bases = {re.sub(r"[abc]$", "", case_id) for case_id in TABLE}
    assert len(bases) == 51


@pytest.mark.parametrize("case", ADVERSARY_CASES, ids=[c["id"] for c in ADVERSARY_CASES])
def test_each_starter_answers_the_adversary_case_as_the_table_says(case, world, policies):
    got = tuple(_answer(case, world, policies[name]) for name in ORDER)
    assert got == TABLE[case["id"]]
    # the default column is the recording's own expectation
    assert TABLE[case["id"]][1] == (case["expect"]["answer"], case["expect"]["cause_code"])


def test_no_starter_allows_a_hazard_in_the_recordings():
    for case_id, row in TABLE.items():
        if case_id.split("-")[0] in HAZARDS:
            assert all(answer != "allow" for answer, _code in row), case_id


def test_review_asks_about_the_benign_changes_the_others_allow():
    for case_id in ("ok-3", "ok-8a", "ok-8b", "ok-8c"):     # a Write, a rewrite, git add, git commit
        assert TABLE[case_id] == (("allow", None), ("allow", None), ("ask", 127)), case_id


# ----------------------------------------------------------------- the hazards over every reading
TOOLS = ("list_dir", "read_file", "write_file", "delete_path", "run_command", "git", "unknown")
SCOPES = ("none", "workspace", "outside", "unknown")
COMMANDS = ("none", "read_only", "mutating", "network", "git", "unknown")
GIT_OPS = ("none", "local_read", "local_write", "mutating", "push", "network", "unknown")
PATH_HAZARDS = ("path_in_toolchain", "path_glob", "path_traversal", "path_symlink")


def _reading(tool, scope, command, git_op, **flags):
    reading = {"classifier_version": 2, "net_dest": "none", "proc_class": "none", "tool": tool, "path_scope": scope, "command_class": command,
               "git_op": git_op, "remote_class": "allowed" if git_op == "push" else "none",
               "kill_by_pattern": False, **{name: False for name in PATH_HAZARDS}}
    reading.update(flags)
    return reading


def _hazard_readings():
    """Every reading with a hazard in it, over every value of every category: outside the workspace, the network,
    a kill by pattern, and a toolchain, glob, traversal or symlink path on a call that changes something (the
    rules refuse those four on a write, a delete or a file-changing command; reading through one is not a
    hazard). The push remote is `allowed`, the most permissive."""
    for tool, scope, command, git_op in itertools.product(TOOLS, SCOPES, COMMANDS, GIT_OPS):
        if scope == "outside" or command == "network" or git_op == "network":
            yield _reading(tool, scope, command, git_op)
        yield _reading(tool, scope, command, git_op, kill_by_pattern=True)
        if tool in ("write_file", "delete_path") or command == "mutating":
            for flag in PATH_HAZARDS:
                yield _reading(tool, scope, command, git_op, **{flag: True})


@pytest.mark.parametrize("name", ORDER)
def test_no_starter_allows_a_hazard_over_every_reading(name, policies):
    policy = policies[name]
    allowed = []
    for reading in _hazard_readings():
        if policy.decide(policy.reading_bytes(reading)).kind == "allow":
            allowed.append(reading)
    assert allowed == []


def test_review_allows_no_change_over_every_reading(policies):
    policy = policies["review"]
    for tool, scope, command, git_op in itertools.product(TOOLS, SCOPES, COMMANDS, GIT_OPS):
        if tool in ("write_file", "delete_path") or command == "mutating" or git_op in ("local_write", "mutating", "push"):
            assert policy.decide(policy.reading_bytes(_reading(tool, scope, command, git_op))).kind != "allow"


# ----------------------------------------------------------------- init --policy, the hook and status
REPO = Path(__file__).resolve().parents[2]


def _env(home: Path):
    env = {k: v for k, v in os.environ.items()
           if k not in ("XDG_CONFIG_HOME", "APPDATA", "CLAUDE_PROJECT_DIR", "PRISMPATH_DEBUG")}
    env.update(HOME=str(home), USERPROFILE=str(home), PYTHONPATH=str(REPO), TMPDIR=str(home / "tmp"))
    (home / "tmp").mkdir(parents=True, exist_ok=True)
    return env


def _cli(home, *args, stdin=b""):
    return subprocess.run([sys.executable, "-m", "prismpath", *args], input=stdin, capture_output=True,
                          env=_env(home), cwd=str(home), timeout=120)


def test_init_policy_review_then_the_hook_asks_for_an_in_project_write(tmp_path):
    pytest.importorskip("cryptography")
    pytest.importorskip("fcntl")
    home, ws = tmp_path / "home", tmp_path / "ws"
    home.mkdir()
    ws.mkdir()
    done = _cli(home, "agent", "init", "--project", str(ws), "--yes", "--policy", "review", "--json")
    assert done.returncode == 0, done.stderr
    report = json.loads(done.stdout)
    assert report["policy"]["name"] == "review" and report["policy"]["image"] == "agent_review"
    assert report["policy"]["state"] == "recorded"
    agent_dir = home / ".config" / "prismpath" / "agent"
    assert (agent_dir / "policy.core.json").read_bytes() == starter_path("review").read_bytes().rstrip(b"\n")
    attestation = json.loads((agent_dir / "policy.attestation.json").read_bytes())
    assert attestation["case"] == "agent_review"

    write = {"session_id": "s1", "cwd": str(ws), "hook_event_name": "PreToolUse", "tool_name": "Write",
             "tool_input": {"file_path": str(ws / "notes.txt"), "content": "x\n"}}
    answer = json.loads(_cli(home, "agent", "hook", stdin=json.dumps(write).encode()).stdout)
    out = answer["hookSpecificOutput"]
    assert out["permissionDecision"] == "ask"
    assert "127 agent:change-asked" in out["permissionDecisionReason"]
    read = dict(write, tool_name="Read", tool_input={"file_path": str(ws / "notes.txt")})
    assert json.loads(_cli(home, "agent", "hook", stdin=json.dumps(read).encode()).stdout)[
        "hookSpecificOutput"]["permissionDecision"] == "allow"

    status = _cli(home, "agent", "status", "--project", str(ws), "--json")
    assert status.returncode == 0, status.stderr
    assert json.loads(status.stdout)["policy"]["name"] == "review"
    text = _cli(home, "agent", "status", "--project", str(ws)).stdout.decode()
    assert "policy: review " in text

    # init again without --policy keeps the starter recorded; naming another switches and re-attests
    again = json.loads(_cli(home, "agent", "init", "--project", str(ws), "--yes", "--json").stdout)
    assert again["policy"]["name"] == "review" and again["policy"]["state"] == "kept"
    strict = json.loads(_cli(home, "agent", "init", "--project", str(ws), "--yes", "--policy", "strict", "--json").stdout)
    assert strict["policy"]["name"] == "strict" and strict["policy"]["state"] == "updated"
    assert json.loads(_cli(home, "agent", "status", "--project", str(ws), "--json").stdout)["policy"]["name"] == "strict"
    # a session's run is bound to the image it began under, so the switch takes effect in a new session
    stale = json.loads(_cli(home, "agent", "hook", stdin=json.dumps(write).encode()).stdout)["hookSpecificOutput"]
    assert stale["permissionDecision"] == "deny" and "126 agent:hook-error" in stale["permissionDecisionReason"]
    fresh = dict(write, session_id="s2")
    assert json.loads(_cli(home, "agent", "hook", stdin=json.dumps(fresh).encode()).stdout)[
        "hookSpecificOutput"]["permissionDecision"] == "allow"


def test_init_without_policy_on_a_fresh_setup_records_default(tmp_path):
    pytest.importorskip("cryptography")
    home, ws = tmp_path / "home", tmp_path / "ws"
    home.mkdir()
    ws.mkdir()
    report = json.loads(_cli(home, "agent", "init", "--project", str(ws), "--yes", "--json").stdout)
    assert report["policy"]["name"] == "default" and report["policy"]["image"] == "agent_default"
    unknown = _cli(home, "agent", "init", "--project", str(ws), "--yes", "--policy", "lenient")
    assert unknown.returncode != 0 and b"invalid choice" in unknown.stderr
