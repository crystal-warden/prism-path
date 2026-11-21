# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Every program the classifier reads as `read_only`, and every git form it reads as a plain local read, is RUN here.

The Lean theorems prove the model's readings given the model's lists. They cannot prove that a listed program is
read only: that is a fact about `sed`, `sort` and `git`. This test checks it against the programs themselves, so it
cannot agree with the model by construction. For each program (and each git subcommand the classifier calls a local
read) it takes the options the program prints in its own `--help` (`-h` for git), builds invocations with and
without a file operand and an output-looking value, keeps those the classifier reads as read only (so a change to the
lists or the argument rules changes what is run), and runs each in a fresh temporary tree with a fake settings file
and git hooks, HOME inside the tree, no network. The tree must come out byte for byte, mode and mtime the same, and
a fake `touch`, `tee`, `cp` and `sh` on the PATH (which a command run by `sed e`, `find -exec` or a pager would
call) must not have been called. The commands that once read as read only and were not are fixtures too.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from prismpath.agent import claude_code, classifier
from prismpath.agent.policy import Policy

HERE = Path(__file__).parent
POLICY_DIR = Path(classifier.__file__).parent / "policy"
STARTERS = ("agent_default", "agent_review", "agent_rules")
FIXTURES = json.loads((HERE / "fixtures" / "claude_code_hooks.json").read_text(encoding="utf-8"))

# What once read as read only or as a plain git listing and can write a file or run a program.
WRITERS = ["sed -ri s/a/b/ .claude/settings.json", "sort -o.claude/settings.json notes.txt",
           "uniq notes.txt .claude/settings.json", "sed 'w .claude/settings.json' notes.txt",
           "sed '1e touch pwned' notes.txt", "xxd -r notes.txt .git/hooks/pre-commit",
           "git diff --output=.claude/settings.json", "git grep -O sh pat", "git grep --open-files-in-pager=sh pat",
           "git diff --no-index /etc/passwd /dev/null", "git diff --ext-diff", "git log --outp=out.txt",
           "git grep -nOsh pat", "git diff -Oorderfile", "git blame --contents /etc/passwd notes.txt",
           "tree -o out.txt", "file -C", "date -s 2000-01-01", "find . -fprint out.txt"]


def _reading(command, ws):
    hook = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(ws)}
    call = claude_code.hook_call(hook, {"CLAUDE_PROJECT_DIR": str(ws)})
    return call, classifier.classify(call.call, classifier.Config(workspace=Path(ws)))


def _plain(command, ws):
    """True when the command reads as a read only program or a plain git local read."""
    _call, reading = _reading(command, ws)
    return reading["command_class"] == "read_only" or (reading["command_class"] == "git"
                                                      and reading["git_op"] == "local_read")


def _world(root: Path) -> Path:
    ws, home, fake = root / "ws", root / "ws" / "home", root / "fakebin"
    for directory in (ws / "sub", ws / ".claude", home, fake):
        directory.mkdir(parents=True, exist_ok=True)
    (ws / "notes.txt").write_text("first note\nsecond note\nthird\n")
    (ws / "sub" / "b.txt").write_text("b one\nb two\n")
    (ws / ".claude" / "settings.json").write_text('{"hooks": {}}\n')
    env = os.environ | {"HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"), "LC_ALL": "C",
                        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0",
                        "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat", "PAGER": "cat",
                        "http_proxy": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9", "TZ": "UTC"}
    env.pop("GIT_DIR", None)
    log = root / "canary.log"
    for name in ("touch", "tee", "cp", "sh", "bash", "mv", "rm"):
        script = fake / name
        script.write_text(f"#!/usr/bin/env python3\nimport sys\nopen({str(log)!r}, 'a').write({name!r} + ' ' + ' '.join(sys.argv[1:]) + '\\n')\n")
        script.chmod(0o755)
    env["PATH"] = f"{fake}:/usr/bin:/bin"
    for args in (["init", "-q"], ["add", "-A"], ["-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "first"]):
        subprocess.run(["git", *args], cwd=ws, env=env, check=True, capture_output=True)
    return ws, env, log


def _snapshot(ws: Path):
    state = {}
    for path in sorted([ws, *ws.rglob("*")]):
        info = path.lstat()
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() and not path.is_symlink() else ""
        state[str(path.relative_to(ws))] = (oct(info.st_mode), info.st_size, info.st_mtime_ns, digest,
                                            os.readlink(path) if path.is_symlink() else "")
    return state


def _flags(argv):
    """The options a program prints in its own help, or nothing when it prints none."""
    out = ""
    for tail in (["--help"], ["-h"]):
        with tempfile.TemporaryDirectory() as empty:
            try:
                done = subprocess.run([*argv, *tail], capture_output=True, text=True, timeout=3,
                                      stdin=subprocess.DEVNULL, cwd=empty,
                                      env=os.environ | {"LC_ALL": "C", "GIT_PAGER": "cat", "PAGER": "cat"})
            except subprocess.TimeoutExpired:
                continue
        out += done.stdout + done.stderr
    longs = set(re.findall(r"(?<![\w-])(--[A-Za-z][A-Za-z0-9-]*)", out))
    shorts = set(re.findall(r"(?<![\w-])(-[A-Za-z0-9])(?![\w-])", out))
    return sorted(longs | shorts)


def _forms(argv):
    forms = [[]]
    for flag in _flags(argv):
        for value in ([], ["out.txt"], ["sub/out.txt"], ["sh"]):
            forms.append([flag, *value])
        if flag.startswith("--"):
            forms.append([f"{flag}=out.txt"])
        else:
            forms.append([f"{flag}out.txt"])
    return forms


def _programs():
    return sorted(p for p in classifier.READ_ONLY if shutil.which(p))


@pytest.mark.parametrize("program", _programs())
def test_a_read_only_program_changes_nothing_under_any_option_it_documents(program, tmp_path):
    ws, env, log = _world(tmp_path)
    ran = 0
    for form in _forms([program]):
        for operands in ([], ["notes.txt"], ["notes.txt", "sub/b.txt"], ["pat", "notes.txt"], ["notes.txt", ".claude/settings.json"]):
            argv = [program, *form, *operands]
            if not _plain(shlex.join(argv), ws):
                continue
            before = _snapshot(ws)
            try:
                subprocess.run(argv, cwd=ws, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=3)
            except subprocess.TimeoutExpired:
                pass
            ran += 1
            assert not log.exists(), f"{shlex.join(argv)} ran a child: {log.read_text()}"
            assert _snapshot(ws) == before, f"{shlex.join(argv)} changed the tree"
    assert ran


GIT_READS = sorted(classifier.GIT_LOCAL_READ)


@pytest.mark.parametrize("sub", GIT_READS)
def test_a_git_local_read_changes_nothing_under_any_option_it_documents(sub, tmp_path):
    ws, env, log = _world(tmp_path)
    ran = 0
    for form in _forms(["git", sub]):
        for operands in ([], ["notes.txt"], ["HEAD"]):
            argv = ["git", sub, *form, *operands]
            if not _plain(shlex.join(argv), ws):
                continue
            before = _snapshot(ws)
            try:
                subprocess.run(argv, cwd=ws, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
            except subprocess.TimeoutExpired:
                pass
            ran += 1
            assert not log.exists(), f"{shlex.join(argv)} ran a child: {log.read_text()}"
            assert _snapshot(ws) == before, f"{shlex.join(argv)} changed the tree"
    assert ran


def _fixture_commands():
    out = []
    for case in FIXTURES:
        command = (case["tool_input"] or {}).get("command") if case["tool_name"] == "Bash" else None
        if command and "@" not in command.replace("@WS@", ""):
            out.append((case["id"], command.replace("@WS@", "{ws}")))
    return out


@pytest.mark.parametrize("ident,command", _fixture_commands(), ids=[i for i, _ in _fixture_commands()])
def test_every_fixture_the_classifier_reads_as_plain_runs_without_a_change(ident, command, tmp_path):
    ws, env, log = _world(tmp_path)
    command = command.replace("{ws}", str(ws))
    if not _plain(command, ws) or any(c in command for c in ";&|><`$\n"):
        pytest.skip("not a plain read, or a compound command")
    argv = shlex.split(command)
    if not shutil.which(argv[0]):
        pytest.skip("program not installed")
    before = _snapshot(ws)
    try:
        subprocess.run(argv, cwd=ws, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
    except subprocess.TimeoutExpired:
        pass
    assert not log.exists() and _snapshot(ws) == before


@pytest.mark.parametrize("command", WRITERS)
def test_the_commands_that_wrote_no_longer_read_as_plain_or_allowed(command, tmp_path):
    ws, _env, _log = _world(tmp_path)
    assert not _plain(command, ws), command
    call, reading = _reading(command, ws)
    for name in STARTERS:
        policy = Policy.load(POLICY_DIR / f"{name}.core.json")
        assert policy.decide(policy.reading_bytes(reading)).kind != "allow", (name, command)
