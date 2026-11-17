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
  Bash                          run_command   the command split by the plain word grammar below
  anything else                 unknown       WebFetch, WebSearch, Task, every mcp__* tool, and tools not yet invented

Claude Code resolves a relative path against its own working directory, not against the workspace, so every
path is made absolute against the hook input's `cwd` before it is classified. The workspace is
CLAUDE_PROJECT_DIR when that is set, else `cwd`. The classifier reads `/workspace` as the sandbox's mount
of the workspace; Claude Code has no such mount, so a path under `/workspace` is spelled `/./workspace/...`
for the classifier, which keeps it the real directory it names.

A shell does more to a word than any tokenizer outside it can promise, so a Bash command is read only in a
narrow grammar that is defined and proved in Lean (formal/Classifier/Hook.lean, docs/design/spec-verified-classifier.md)
and on which the shell and this reading agree. A command is words separated by spaces and tabs; a word is a
run of plain characters (`PLAIN`: ASCII letters and digits and `- _ . / , : = + @ % * ? [ ] }`), single quoted
text and double quoted text, joined; quoted text holds plain characters, spaces, tabs, `~ { # ^` and the other
quote. A Bash command is `unknown` when any of these holds: a shell operator (`| ; & $ backtick > < ( )`, a
carriage return or a newline) anywhere in the string, any other character outside the grammar (a backslash,
`~`, `{`, `#`, `!` or `^` outside quotes, any non ASCII or control character), a quote left open, a word after
the first that starts with `~` or holds `{`, a `cwd` outside the workspace, or no word at all. This grammar
replaced shlex on 2026-11-17 (owner decision): what it does not read is `unknown`, which agent_default asks
the person about.

**The hazard scan.** A Bash command that reads unknown is not left at that: `hazard_scan` looks at its raw text
for evidence of a hazard, by rules simple enough to state and prove (formal/Classifier/Scan.lean), and when it
finds any the reading carries it, so the refusal rules fire before the unclassifiable escalation. The text is
first stripped of backslashes and quotes, so `pk\\ill` and `p'k'ill` are seen as the shell would join them.

  kill        an ASCII word (a maximal run of letters, digits and `_`) that is `pkill`, `killall` or `kill`
  network     an ASCII word in `classifier.NETWORK`, or a URL scheme (`classifier._URL`)
  outside     a token (split at whitespace, shell operators and `= : , { }`) that starts with `~`, or starts
              with `/` and is neither the workspace nor below it
  traversal   a token with a `..` component
  toolchain   a token with a `.toolchain` component

Evidence makes the reading a run_command reading with `kill_by_pattern`, `command_class` network (network) or
mutating (any path evidence), `path_scope` outside, `path_traversal` and `path_in_toolchain` as found; under every
shipped policy that reading is refused (`Theorems.scan_refuses`, checked per image by the oracle). No evidence
leaves the unknown reading exactly as it was: the command still asks. The scan never reads a command the
grammar reads, so it never changes an allowed call.

Three facts are read off the disk, not the text: whether `cwd` is inside the workspace (`_inside`), whether it
is the workspace (`_same_dir`) and whether a bare word names something in `cwd` (`_exists`). They are
observations, like the classifier's `disk_facts`, and are not proved.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from . import classifier
from .policy import DEFAULT_POLICY_PATH, Decision, Policy

RECEIPT_PLACEHOLDER = "{receipt}"      # the caller replaces it with the receipt's id (fill_receipt)
SHELL_OPERATORS = frozenset("|;&$`<>()\n\r")
PLAIN = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./,:=+@%*?[]}")
QUOTED = PLAIN | frozenset(" \t~{#^")      # inside quotes, with the other quote character
BLANKS = frozenset(" \t")
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
    """Disk fact: `path` resolves to `root` or below it."""
    path, root = os.path.realpath(path), os.path.realpath(root)
    return path == root or path.startswith(root.rstrip("/") + "/")


def _same_dir(path: str, root: str) -> bool:
    """Disk fact: `path` resolves to `root` itself."""
    return os.path.realpath(path) == os.path.realpath(root)


def _exists(path: str) -> bool:
    """Disk fact: something (a link included) is at `path`."""
    return os.path.lexists(path)


def split_plain(command: str) -> Optional[List[str]]:
    """The words of a command in the plain word grammar, or None when the command is outside it."""
    words: List[str] = []
    word: Optional[str] = None
    at, size = 0, len(command)
    while at < size:
        char = command[at]
        if char in BLANKS:
            if word is not None:
                words.append(word)
                word = None
            at += 1
        elif char in PLAIN:
            word = (word or "") + char
            at += 1
        elif char in "'\"":
            close = command.find(char, at + 1)
            if close < 0:
                return None
            text = command[at + 1:close]
            allowed = QUOTED | {"'\"".replace(char, "")}
            if any(c not in allowed for c in text):
                return None
            word = (word or "") + text
            at = close + 1
        else:
            return None
    if word is not None:
        words.append(word)
    return words


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
    if not isinstance(command, str) or any(char in SHELL_OPERATORS for char in command):
        return None
    words = split_plain(command)
    if not words:
        return None
    if not _inside(cwd, workspace):
        return None             # a command run from outside the workspace acts on the directory it is in
    out = [words[0]]
    here = _same_dir(cwd, workspace)   # then the classifier's own join is the right one
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
    if "/" in value or value.startswith(".") or _exists(os.path.join(cwd, value)):
        return head + eq + _spell(os.path.join(cwd, value))
    return word


def hook_call(hook_input: Any, env: Optional[Mapping[str, str]] = None) -> HookCall:
    """The classifier call for one PreToolUse hook input. Never raises: what it cannot read is `unknown`."""
    try:
        workspace = workspace_for(hook_input if isinstance(hook_input, dict) else {}, env)
        if not classifier.scalar(hook_input) or not classifier.scalar(workspace):
            # outside the model's domain (formal/Classifier): unknown, against a workspace a path can name
            return HookCall(_unknown(), workspace if classifier.scalar(workspace) else os.getcwd())
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


# ----------------------------------------------------------------- the hazard scan
_STRIP = frozenset("\\'\"")
_NOT_WORD = re.compile(r"[^A-Za-z0-9_]")
_TOKEN_SEPS = frozenset("=:,{}") | SHELL_OPERATORS


def _tokens(text: str) -> List[str]:
    out, cur = [], []
    for char in text:
        if char.isspace() or char in _TOKEN_SEPS:
            if cur:
                out.append("".join(cur))
            cur = []
        else:
            cur.append(char)
    if cur:
        out.append("".join(cur))
    return out


def hazard_scan(command: str, workspace: str) -> Optional[Dict[str, Any]]:
    """The reading of a Bash command the grammar does not read, when its text shows a hazard; None when the
    scan finds nothing (the command then keeps the unknown reading and asks)."""
    text = "".join(char for char in command if char not in _STRIP)
    words = [word for word in _NOT_WORD.split(text) if word]
    tokens = _tokens(text)
    kill = any(word in ("pkill", "killall", "kill") for word in words)
    network = any(word in classifier.NETWORK for word in words) or classifier._URL.search(text) is not None
    outside = any(token.startswith("~") or (token.startswith("/") and not (token == workspace or
                                                                           token.startswith(workspace + "/")))
                  for token in tokens)
    traversal = any(".." in token.split("/") for token in tokens)
    toolchain = any(".toolchain" in token.split("/") for token in tokens)
    paths = outside or traversal or toolchain
    if not (kill or network or paths):
        return None
    reading = classifier.base_reading()
    reading.update({"tool": "run_command", "kill_by_pattern": kill,
                    "command_class": "network" if network else "mutating" if paths else "unknown",
                    "path_scope": "outside" if outside else "none", "path_traversal": traversal,
                    "path_in_toolchain": toolchain})
    return reading


def hook_reading(hook_input: Any, hc: HookCall, config: classifier.Config) -> Dict[str, Any]:
    """The reading of a hook input: its call classified, or, for a Bash command that reads unknown, the hazard
    scan's reading when it finds evidence."""
    reading = classifier.classify(hc.call, config)
    if hc.call.get("tool") == "unknown" and isinstance(hook_input, dict) and classifier.scalar(hook_input) \
            and classifier.scalar(hc.workspace) and hook_input.get("tool_name") == "Bash" \
            and isinstance(hook_input.get("tool_input"), dict) \
            and isinstance(hook_input["tool_input"].get("command"), str):
        scanned = hazard_scan(hook_input["tool_input"]["command"], hc.workspace)
        if scanned is not None:
            return scanned
    return reading


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
    reading = hook_reading(hook_input, hc, classifier.Config.for_workspace(hc.workspace))
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
