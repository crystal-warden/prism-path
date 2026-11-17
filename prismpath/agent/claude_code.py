# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Claude Code adapter: a PreToolUse hook input read into the classifier's call, and the core's decision
written back as the hook's answer.

Two pure functions do the work, with no file written and no process started:

  hook_call(hook_input, env)   the classifier call (`{"tool": ..., "args": ...}`) for one hook input, and the
                               workspace root it is classified against
  hook_answer(decision)        the JSON object the hook prints on standard output

This module is trusted code outside the verified core, like the classifier (classifier.py). What the call
would do is read here, so it is read conservatively: whatever this module cannot read in full is the
`unknown` call, which the default policy (`policy/agent_default`) escalates to the person.

The mapping (docs/design/governed-agent-plan.md, A2):

  Read                          read_file     the file path
  Write, Edit, MultiEdit,       write_file    the file path (the content is never classified)
  NotebookEdit
  Glob                          list_dir      the base directory joined to the pattern, as one glob path fact
  Grep, LS                      list_dir      the searched or listed path (a Grep regex is not a path)
  Bash                          run_command   the command split by shlex; any shell operator is `unknown`
  anything else                 unknown       WebFetch, WebSearch, Task, every mcp__* tool, and tools not yet invented

Claude Code resolves a relative path against its own working directory, not against the workspace, so every
path is made absolute against the hook input's `cwd` before it is classified. The workspace is
CLAUDE_PROJECT_DIR when that is set, else `cwd`. The classifier reads `/workspace` as the sandbox's mount
of the workspace; Claude Code has no such mount, so a path under `/workspace` is spelled `/./workspace/...`
for the classifier, which keeps it the real directory it names.

A shell does more to a word than shlex does, so a Bash command is `unknown` when any of these holds: a shell
operator (`| ; & $ backtick > < ( )` or a newline) anywhere in the string, a string shlex cannot split, a word
that starts with `~` (home expansion), a word with `{` (brace expansion), a `cwd` outside the workspace, or an
empty command.
"""
from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from . import classifier
from .policy import DEFAULT_POLICY_PATH, Decision, Policy

RECEIPT_PLACEHOLDER = "{receipt}"      # the caller replaces it with the receipt's id (fill_receipt)
SHELL_OPERATORS = frozenset("|;&$`<>()\n\r")
WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})
_PATH_KEYS = ("file_path", "notebook_path")


@dataclass(frozen=True)
class HookCall:
    call: Dict[str, Any]
    workspace: str


def workspace_for(hook_input: Mapping[str, Any], env: Optional[Mapping[str, str]] = None) -> str:
    """CLAUDE_PROJECT_DIR when set and not empty, else the input's cwd, else the process's."""
    env = os.environ if env is None else env
    root = env.get("CLAUDE_PROJECT_DIR")
    if not root:
        root = hook_input.get("cwd") if isinstance(hook_input.get("cwd"), str) else ""
    return root or os.getcwd()


def _unknown() -> Dict[str, Any]:
    return {"tool": "unknown", "args": {}}


def _spell(raw: str) -> str:
    """The classifier reads /workspace as the sandbox mount; here it is only a directory."""
    if raw == classifier.MOUNT or raw.startswith(classifier.MOUNT + "/"):
        return "/." + raw
    return raw


def _absolute(raw: Any, cwd: str) -> Optional[str]:
    if not isinstance(raw, str) or not raw:
        return None
    if raw.startswith("~"):
        return None             # the classifier would read ~ as a workspace entry; a person reads it
    if raw.startswith("/"):
        return _spell(raw)
    return _spell(os.path.join(cwd, raw))


def _inside(path: str, root: str) -> bool:
    path, root = os.path.realpath(path), os.path.realpath(root)
    return path == root or path.startswith(root.rstrip("/") + "/")


def _first_path(tool_input: Mapping[str, Any]) -> Optional[Any]:
    for key in _PATH_KEYS:
        if key in tool_input:
            return tool_input[key]
    return None


def _file_paths(tool_name: str, tool_input: Mapping[str, Any]) -> Optional[List[Any]]:
    """Every file a file tool names. MultiEdit may carry one path per edit group; any path that is missing or
    not a string makes the call unreadable (None)."""
    paths: List[Any] = []
    top = _first_path(tool_input)
    if top is not None:
        paths.append(top)
    edits = tool_input.get("edits")
    if isinstance(edits, list):
        for edit in edits:
            if isinstance(edit, dict) and any(key in edit for key in _PATH_KEYS):
                paths.append(_first_path(edit))
    if not paths or not all(isinstance(path, str) and path for path in paths):
        return None
    return paths


def _bash_argv(command: Any, cwd: str, workspace: str) -> Optional[List[str]]:
    if not isinstance(command, str) or not command.strip() or any(char in SHELL_OPERATORS for char in command):
        return None
    if not _inside(cwd, workspace):
        return None             # a command run from outside the workspace acts on the directory it is in
    try:
        words = shlex.split(command)
    except ValueError:
        return None
    if not words:
        return None
    out = [words[0]]
    here = os.path.realpath(cwd) == os.path.realpath(workspace)   # then the classifier's own join is the right one
    for word in words[1:]:
        if word.startswith("~") or "{" in word:
            return None
        out.append(_spell_word(word) if here else _from_cwd(word, cwd))
    return out


def _spell_word(word: str) -> str:
    head, eq, value = word.partition("=") if word.startswith("-") else ("", "", word)
    return head + eq + _spell(value) if value.startswith("/") else word


def _from_cwd(word: str, cwd: str) -> str:
    """A word of a command run from a directory below the workspace root, spelled as the path it names: the
    classifier joins a relative path to the workspace root, which is not where the command runs. A bare word
    is a path only when something of that name is there, so a subcommand or a pattern is left alone."""
    head, eq, value = word.partition("=") if word.startswith("-") else ("", "", word)
    if word.startswith("-") and not (eq and "/" in value):
        return word
    if value.startswith("/"):
        return head + eq + _spell(value)
    if "/" in value or value.startswith(".") or os.path.lexists(os.path.join(cwd, value)):
        return head + eq + _spell(os.path.join(cwd, value))
    return word


def hook_call(hook_input: Any, env: Optional[Mapping[str, str]] = None) -> HookCall:
    """The classifier call for one PreToolUse hook input. Never raises: what it cannot read is `unknown`."""
    try:
        workspace = workspace_for(hook_input if isinstance(hook_input, dict) else {}, env)
        return HookCall(_call(hook_input, workspace), workspace)
    except Exception:   # noqa: BLE001 - an adapter failure must fail to unknown, never to a guess
        return HookCall(_unknown(), os.getcwd())


def _call(hook_input: Any, workspace: str) -> Dict[str, Any]:
    if not isinstance(hook_input, dict):
        return _unknown()
    name, tool_input = hook_input.get("tool_name"), hook_input.get("tool_input")
    cwd = hook_input.get("cwd") if isinstance(hook_input.get("cwd"), str) and hook_input.get("cwd") else workspace
    if not isinstance(name, str) or not isinstance(tool_input, dict):
        return _unknown()
    if name == "Read":
        path = _absolute(tool_input.get("file_path"), cwd)
        return {"tool": "read_file", "args": {"path": path}} if path else _unknown()
    if name in WRITE_TOOLS:
        paths = _file_paths(name, tool_input)
        spelled = {_absolute(path, cwd) for path in paths} if paths else set()
        if len(spelled) != 1 or None in spelled:
            return _unknown()
        return {"tool": "write_file", "args": {"path": spelled.pop(), "content": ""}}
    if name in ("Glob", "Grep", "LS"):
        return _list_call(name, tool_input, cwd)
    if name == "Bash":
        argv = _bash_argv(tool_input.get("command"), cwd, workspace)
        return {"tool": "run_command", "args": {"argv": argv}} if argv else _unknown()
    return _unknown()


def _list_call(name: str, tool_input: Dict[str, Any], cwd: str) -> Dict[str, Any]:
    base = tool_input.get("path")
    if "paths" in tool_input:
        return _unknown()       # one call names one path; a search of several is read by a person
    if base is not None and not (isinstance(base, str) and base):
        return _unknown()
    base_abs = _absolute(base, cwd) if base else _spell(cwd)
    if base_abs is None:
        return _unknown()
    if name == "Glob":
        pattern = tool_input.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            return _unknown()
        if pattern.startswith("~"):
            return _unknown()
        path = _spell(pattern) if pattern.startswith("/") else base_abs.rstrip("/") + "/" + pattern
        return {"tool": "list_dir", "args": {"path": path}}
    return {"tool": "list_dir", "args": {"path": base_abs}}


def load_default_policy() -> Policy:
    return Policy.load(DEFAULT_POLICY_PATH)


@dataclass(frozen=True)
class HookResult:
    decision: Decision
    reading: Dict[str, Any]
    call: Dict[str, Any]
    workspace: str
    answer: Dict[str, Any]


def evaluate(hook_input: Any, env: Optional[Mapping[str, str]] = None, policy: Optional[Policy] = None) -> HookResult:
    """Classify one hook input, decide it under `policy` (agent_default when None) and write the hook answer."""
    policy = policy or load_default_policy()
    hc = hook_call(hook_input, env)
    reading = classifier.classify(hc.call, classifier.Config.for_workspace(hc.workspace))
    decision = policy.decide(policy.reading_bytes(reading))
    return HookResult(decision, reading, hc.call, hc.workspace, hook_answer(decision))


_KIND_TO_PERMISSION = {"allow": "allow", "refuse": "deny", "escalate": "ask"}


def hook_answer(decision: Decision) -> Dict[str, Any]:
    """The PreToolUse hook's JSON answer to one decision. A refusal's reason names the registered cause and
    holds RECEIPT_PLACEHOLDER for the caller to fill (fill_receipt); an allow carries no reason."""
    permission = _KIND_TO_PERMISSION[decision.kind]
    output: Dict[str, Any] = {"hookEventName": "PreToolUse", "permissionDecision": permission}
    if decision.kind == "refuse":
        output["permissionDecisionReason"] = (
            f"PrismPath refused this call: cause {_cause(decision)}. It was not run. Receipt {RECEIPT_PLACEHOLDER}.")
    elif decision.kind == "escalate":
        output["permissionDecisionReason"] = (
            f"PrismPath asks you to decide this call: cause {_cause(decision)}. Receipt {RECEIPT_PLACEHOLDER}.")
    return {"hookSpecificOutput": output}


def _cause(decision: Decision) -> str:
    return f"{decision.cause_code} {decision.cause}" if decision.cause_code is not None else f"{decision.cause}"


def fill_receipt(answer: Dict[str, Any], receipt_id: str) -> Dict[str, Any]:
    """The answer with the receipt placeholder replaced; the input is not changed."""
    out = {"hookSpecificOutput": dict(answer["hookSpecificOutput"])}
    reason = out["hookSpecificOutput"].get("permissionDecisionReason")
    if reason is not None:
        out["hookSpecificOutput"]["permissionDecisionReason"] = reason.replace(RECEIPT_PLACEHOLDER, receipt_id)
    return out
