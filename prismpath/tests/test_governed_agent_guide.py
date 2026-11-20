# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The commands of docs/guides/governed-agent.md run as written, so the guide cannot drift from the code.

A fenced `sh` block directly under an `<!-- guide-test: NAME -->` comment is a tested block. The blocks run in
the order the guide gives them, in a bash whose PATH has a `prismpath` that runs this checkout, in a throwaway
HOME and a throwaway project, so nothing under the real ~/.config or any real .claude/settings.json is read or
written. Claude Code itself is replaced by the hook inputs the guide's own `try_hook` block sends to
`prismpath agent hook`, and the answers are checked against the guide's claims.
"""
import json
import os
import pty
import re
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath.tests._repo import REPO_ROOT  # noqa: E402

GUIDE = REPO_ROOT / "docs" / "guides" / "governed-agent.md"
if not GUIDE.exists():   # skipped here, not in _repo.py, so the acceptance skip budget can name this file
    pytest.skip(f"{GUIDE} is only in a repo checkout", allow_module_level=True)
BLOCK = re.compile(r"<!-- guide-test: (\w+) -->\n```sh\n(.*?)\n```", re.S)


def _blocks():
    return [(name, body) for name, body in BLOCK.findall(GUIDE.read_text(encoding="utf-8"))]


@pytest.fixture()
def sandbox(tmp_path):
    home, project, bin_dir = tmp_path / "home", tmp_path / "project", tmp_path / "bin"
    for directory in (home, project, bin_dir, tmp_path / "tmp"):
        directory.mkdir()
    (project / "notes.txt").write_text("a note\n")
    shim = bin_dir / "prismpath"
    shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" -m prismpath "$@"\n')
    shim.chmod(0o755)
    env = {k: v for k, v in os.environ.items()
           if k not in ("XDG_CONFIG_HOME", "APPDATA", "CLAUDE_PROJECT_DIR", "PRISMPATH_DEBUG")}
    env.update(HOME=str(home), USERPROFILE=str(home), TMPDIR=str(tmp_path / "tmp"),
               PATH=f"{bin_dir}{os.pathsep}{env['PATH']}", PYTHONPATH=str(REPO_ROOT))
    return {"home": home, "project": project, "env": env}


def _answer(line):
    return json.loads(line)["hookSpecificOutput"]


def test_the_guide_has_its_tested_blocks():
    assert [name for name, _ in _blocks()] == ["init", "try", "status", "verify", "tamper"]


def test_the_guide_runs_as_written(sandbox):
    blocks = dict(_blocks())
    home, project, env = sandbox["home"], sandbox["project"], sandbox["env"]
    settings = project / ".claude" / "settings.json"

    # init asks first: with no terminal to answer on, it shows the change and writes nothing
    asked = subprocess.run(["bash", "-c", blocks["init"]], cwd=project, env=env, capture_output=True,
                           stdin=subprocess.DEVNULL, timeout=120, text=True)
    assert asked.returncode == 1, asked.stderr
    assert '"PreToolUse"' in asked.stdout and "was not changed" in asked.stdout
    assert not settings.exists()

    # and a yes at a terminal writes it
    master, slave = pty.openpty()
    os.write(master, b"y\n")
    told = subprocess.run(["bash", "-c", blocks["init"]], cwd=project, env=env, capture_output=True,
                          stdin=slave, timeout=120, text=True)
    os.close(master), os.close(slave)
    assert told.returncode == 0, told.stderr
    written = json.loads(settings.read_text())
    commands = [h["command"] for event in ("PreToolUse", "SessionEnd") for g in written["hooks"][event]
                for h in g["hooks"]]
    assert len(commands) == 2 and all(c.endswith("prismpath agent hook || exit 2") for c in commands)
    assert (home / ".config" / "prismpath" / "agent" / "authority.key").is_file()

    # the remaining blocks in one shell, so the guide's shell function is there for the calls that follow it
    script = "set -e\n" + "\n".join(f'echo "@@{name}"\n{blocks[name]}' for name in ("try", "status", "verify", "tamper"))
    done = subprocess.run(["bash", "-c", script], cwd=project, env=env, capture_output=True, timeout=300, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
    parts = {m.group(1): m.group(2) for m in re.finditer(r"^@@(\w+)\n(.*?)(?=^@@|\Z)", done.stdout, re.S | re.M)}

    answers = [_answer(line) for line in parts["try"].splitlines() if line.strip()]
    assert [a["permissionDecision"] for a in answers] == ["allow", "deny", "ask", "ask"]
    assert "permissionDecisionReason" not in answers[0]
    assert "cause 111 agent:outside-workspace. It was not run. Receipt 1 of session guide." in answers[1]["permissionDecisionReason"]
    assert "cause 125 agent:shell-mutation-asked" in answers[2]["permissionDecisionReason"]
    assert "cause 113 agent:push-escalated" in answers[3]["permissionDecisionReason"]
    assert (project / "notes.txt").exists()                     # nothing was run

    assert "authority key" in parts["status"] and "(attested)" in parts["status"]
    assert "PreToolUse yes, SessionEnd yes" in parts["status"]
    assert "run guide: 4 receipts, open" in parts["status"]

    assert "guide: 4 receipts, 4 replayed through the reference kernel, 0 disagree, root statement signed" in parts["verify"]
    assert "tamper demo: a copy of guide with byte" in parts["tamper"] and "is refused" in parts["tamper"]
    assert "The copy was deleted." in parts["tamper"]
    assert not list(Path(sandbox["env"]["TMPDIR"]).glob("prismpath-tamper-*"))
