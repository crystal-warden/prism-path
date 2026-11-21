# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Hook inputs recorded from a real Claude Code session (fixtures/claude_code_live_2026-11-21.json).

Unlike fixtures/claude_code_hooks.json, which is written in the shape Claude Code sends, these 18 inputs are what
Claude Code 2.1.326 sent to `prismpath agent hook` in a headless session: PreToolUse for Read, Glob, Grep, Bash, Write
and Edit, PostToolUse for each call that ran, and SessionEnd. Each PreToolUse input is answered again here, in a
workspace made below, and must get the answer `expect` names (the live answer, unless a later change to the
classifier moved it and says so in `changed`). The real inputs carry fields the written ones do not (`session_id`,
`transcript_path`, `permission_mode`, `tool_use_id`, `prompt_id`, `scratchpad_dir`, `effort`, and on PostToolUse
`tool_response` and `duration_ms`), and the adapter must read them as it reads the written ones.
"""
import json
from pathlib import Path

import pytest

from prismpath.agent import claude_code

LIVE = json.loads((Path(__file__).parent / "fixtures" / "claude_code_live_2026-11-21.json").read_text(encoding="utf-8"))
PRE = [r for r in LIVE["inputs"] if r["input"]["hook_event_name"] == "PreToolUse"]
WRITTEN_KEYS = {"cwd", "hook_event_name", "tool_name", "tool_input"}


@pytest.fixture(scope="module")
def ws(tmp_path_factory):
    root = tmp_path_factory.mktemp("live_ws")
    (root / "notes.txt").write_text("hello\nworld\n")
    (root / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    return str(root.resolve())


def _fill(value, ws):
    if isinstance(value, str):
        return value.replace("@WS@", ws)
    if isinstance(value, list):
        return [_fill(v, ws) for v in value]
    if isinstance(value, dict):
        return {k: _fill(v, ws) for k, v in value.items()}
    return value


def test_the_recording_covers_every_event_and_file_tool_it_names():
    events = {r["input"]["hook_event_name"] for r in LIVE["inputs"]}
    tools = {r["input"]["tool_name"] for r in PRE}
    assert events == {"PreToolUse", "PostToolUse", "SessionEnd"}
    assert tools == {"Read", "Glob", "Grep", "Bash", "Write", "Edit"}
    assert len(LIVE["inputs"]) == 18 and len(PRE) == 9


def test_real_inputs_carry_more_than_the_written_shape():
    for record in PRE:
        assert WRITTEN_KEYS < set(record["input"]), record["id"]
        assert record["input"]["tool_use_id"].startswith("toolu_"), record["id"]


@pytest.mark.parametrize("record", PRE, ids=[r["id"] for r in PRE])
def test_each_recorded_call_gets_the_answer_it_got_live(record, ws):
    hook_input = _fill(record["input"], ws)
    result = claude_code.evaluate(hook_input, {"CLAUDE_PROJECT_DIR": ws}, claude_code.load_default_policy())
    assert result.reading["tool"] != "unknown", (record["id"], result.call)
    assert result.answer["hookSpecificOutput"]["permissionDecision"] == record["expect"], (
        record["id"], record.get("changed"), result.reading, result.decision)
