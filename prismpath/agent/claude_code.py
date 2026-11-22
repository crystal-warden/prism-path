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

The mapping:

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
  network     an ASCII word in `classifier.NETWORK` inside a token that gives no path evidence (so `ssh` in
              `~/.ssh/id_rsa` is a path, not a network word), a URL scheme (`classifier._URL`), or an installer
              token (`SCAN_INSTALLERS`, by base name) followed by one of its fetch words (`pip install`)
  outside     a token (split at whitespace, shell operators and `= : , { }`) that starts with `~`, or starts
              with `/` and is neither the workspace nor below it
  traversal   a token with a `..` component
  toolchain   a token with a `.toolchain` component
  glob        a token with `* ? [ ]`
  long        a token longer than `classifier.MAX_PATH` or holding a NUL (path scope unknown)
  control     a token that, taken as a path against the hook's `cwd`, the disk says is one of the agent's control
              paths (`classifier.disk_facts`), in a command that is not read-only: it holds a redirection to a
              file (not `2>&1`, `>&2` or `>/dev/null`) or the name of a file changing program (`rm`, `mv`, `cp`,
              `tee`, `sed -i`, `git add`, ...; an interpreter or a build tool is not one). The scan does not
              follow a `cd`; the token naming the directory is itself a control path when it is `.claude`. A token
              that is the workspace root or a directory holding control files counts only in a command that removes
              or moves (`rm`, `rmdir`, `mv`, `find -delete`, `git rm`, `git clean`): `rm -r . | head` refuses,
              `cp x . ; ls` does not
  git         after a token whose base name is `git`: an unsafe option or a subcommand the classifier does not
              know (unknown), a network subcommand (network), a mutating one or `reset --hard` (mutating), `push`
              (a push to a remote that is not allowed); the most severe of every git token wins

Evidence makes the reading a run_command reading with `kill_by_pattern`, `command_class` network (network) or
mutating (any path evidence, control included), `path_scope` unknown (long) or outside, the path flags,
`path_control` and `git_op` as found; under
every shipped policy that reading is never allowed and, but for a push alone (which asks as before), refused
(`ScanTheorems.scan_safe_reading`, checked per image by the oracle). No evidence
leaves the unknown reading exactly as it was: the command still asks. The scan never reads a command the
grammar reads, so it never changes an allowed call.

Three facts are read off the disk, not the text (and the scan's control rule reads a fourth, `classifier.disk_facts`, for each token): whether `cwd` is inside the workspace (`_inside`), whether it
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
        return raw              # a home path: the classifier reads it as outside the workspace, never expanded
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
            path = pattern      # a home pattern reads as outside the workspace, like a home path
        else:
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


_SCAN_GLOB = frozenset("*?[]")
SCAN_INSTALLERS = {**{name: tuple(subs) for name, subs in classifier.INSTALLERS.items()},
                   "apt": ("install",), "apt-get": ("install",), "brew": ("install",), "dnf": ("install",),
                   "yum": ("install",), "apk": ("add",), "pipx": ("install",), "conda": ("install",), "port": ("install",)}
_GIT_RANK = {"none": 0, "push": 1, "mutating": 2, "network": 3, "unknown": 4}


def _path_token(token: str, workspace: str) -> bool:
    parts = token.split("/")
    return (token.startswith("~") or (token.startswith("/") and not (token == workspace or token.startswith(workspace + "/")))
            or ".." in parts or ".toolchain" in parts or any(c in _SCAN_GLOB for c in token)
            or len(token) > classifier.MAX_PATH or "\x00" in token)


def _git_op_of(rest: List[str]) -> str:
    """What the tokens after a `git` token say it does (formal/Classifier/Scan.lean, gitOpOf)."""
    if any(classifier.git_unsafe_option(arg) for arg in rest):
        return "unknown"
    sub = next((arg for arg in rest if not arg.startswith("-")), None)
    if sub is None:
        return "none"
    if sub == "push":
        return "push"
    if sub in classifier.GIT_NETWORK:
        return "network"
    if sub in classifier.GIT_MUTATING:
        return "mutating"
    if sub == "reset":
        return "mutating" if "--hard" in rest else "none"
    if sub == "remote":
        after = rest[rest.index(sub) + 1:]
        return "none" if all(arg in ("-v", "--verbose") for arg in after) else "unknown"
    if sub in classifier.GIT_LOCAL_READ or sub in classifier.GIT_LOCAL_WRITE:
        return "none"
    return "unknown"


def _git_scan(tokens: List[str]) -> str:
    op = "none"
    for at, token in enumerate(tokens):
        here = _git_op_of(tokens[at + 1:]) if os.path.basename(token) == "git" else "none"
        if _GIT_RANK[here] >= _GIT_RANK[op]:
            op = here
    return op


# A command that is not read-only, by its text: a redirection to a file, or a program that changes files (or a
# git subcommand that does) met anywhere in it. Only the scan's control rule reads this. An interpreter or a
# build tool (`python`, `pytest`, `make`) is not one: what it writes is not in the text, and the command asks.
SCAN_WRITERS = frozenset({"rm", "rmdir", "mv", "cp", "ln", "chmod", "chown", "chgrp", "touch", "mkdir", "dd", "truncate",
                          "shred", "tee", "install", "unlink", "tar", "unzip", "zip", "gzip", "gunzip", "patch", "vim",
                          "vi", "nano", "ed", "sed", "sort", "uniq", "xxd", "tree"})
_GIT_WRITE_WORDS = frozenset(classifier.GIT_LOCAL_WRITE | classifier.GIT_MUTATING | {"reset"})


def _writer_at(token: str, rest: List[str]) -> bool:
    base = os.path.basename(token)
    return (base in SCAN_WRITERS
            or (base == "find" and any(arg in classifier._FIND_EFFECTS for arg in rest))
            or (base == "git" and any(arg in _GIT_WRITE_WORDS for arg in rest)))


def _redirects(text: str) -> bool:
    """A `>` that sends output to a file: not `2>&1` or `>&2` (a duplicated descriptor) and not `>/dev/null`."""
    at, size = 0, len(text)
    while at < size:
        if text[at] != ">":
            at += 1
            continue
        at += 1
        if at < size and text[at] == ">":
            at += 1
        while at < size and text[at] in " \t":
            at += 1
        if text.startswith("&", at) and at + 1 < size and (text[at + 1] in "0123456789-"):
            at += 1
        elif text.startswith("/dev/null", at):
            at += len("/dev/null")
        else:
            return True
    return False


def _destroyer_at(token: str, rest: List[str]) -> bool:
    base = os.path.basename(token)
    return (base in ("rm", "rmdir", "mv") or (base == "find" and "-delete" in rest)
            or (base == "git" and any(arg in ("rm", "clean") for arg in rest)))


def _destroy_evidence(tokens: List[str]) -> bool:
    return any(_destroyer_at(token, tokens[at + 1:]) for at, token in enumerate(tokens))


def _write_evidence(text: str, tokens: List[str]) -> bool:
    return _redirects(text) or any(_writer_at(token, tokens[at + 1:]) for at, token in enumerate(tokens))


def _scan_path(cwd: str, token: str) -> str:
    """The path a token names, as the plain grammar would hand it to the classifier: absolute against `cwd`."""
    return _spell(token if token.startswith("/") else os.path.join(cwd, token))


def _control_evidence(text: str, tokens: List[str], cwd: str, config: classifier.Config) -> bool:
    """A token that resolves, on the disk, to one of the agent's control paths, in a command that is not
    read-only (`echo x > .claude/settings.json`, `printf y >> .mcp.json`, `cd .claude && tee settings.json`); or
    to the workspace root or a directory that holds one, in a command that removes or moves (`rm -r .`)."""
    if not _write_evidence(text, tokens):
        return False
    destroys = _destroy_evidence(tokens)
    for token in tokens:
        path = _scan_path(cwd, token)
        if path and "\x00" not in path and len(path) <= classifier.MAX_PATH:
            facts = classifier.disk_facts(path, config)
            if facts.control or (destroys and facts.holder):
                return True
    return False


def hazard_scan(command: str, workspace: str, cwd: Optional[str] = None,
                config: Optional[classifier.Config] = None) -> Optional[Dict[str, Any]]:
    """The reading of a Bash command the grammar does not read, when its text shows a hazard; None when the
    scan finds nothing (the command then keeps the unknown reading and asks)."""
    text = "".join(char for char in command if char not in _STRIP)
    words = [word for word in _NOT_WORD.split(text) if word]
    tokens = _tokens(text)
    kill = any(word in ("pkill", "killall", "kill") for word in words)
    network_word = any(not _path_token(token, workspace) and
                       any(word in classifier.NETWORK for word in _NOT_WORD.split(token) if word) for token in tokens)
    installer = any(os.path.basename(token) in SCAN_INSTALLERS and
                    any(arg in SCAN_INSTALLERS[os.path.basename(token)] for arg in tokens[at + 1:])
                    for at, token in enumerate(tokens))
    network = network_word or classifier._URL.search(text) is not None or installer
    outside = any(token.startswith("~") or (token.startswith("/") and not (token == workspace or
                                                                           token.startswith(workspace + "/")))
                  for token in tokens)
    traversal = any(".." in token.split("/") for token in tokens)
    toolchain = any(".toolchain" in token.split("/") for token in tokens)
    glob = any(any(c in _SCAN_GLOB for c in token) for token in tokens)
    long = any(len(token) > classifier.MAX_PATH or "\x00" in token for token in tokens)
    git = _git_scan(tokens)
    control = _control_evidence(text, tokens, cwd or workspace, config or classifier.Config.for_workspace(workspace))
    paths = outside or traversal or toolchain or glob or long or control
    if not (kill or network or paths or git != "none"):
        return None
    reading = classifier.base_reading()
    reading.update({"tool": "run_command", "kill_by_pattern": kill,
                    "command_class": "network" if network else "mutating" if paths else "unknown",
                    "path_scope": "unknown" if long else "outside" if outside else "none",
                    "path_traversal": traversal, "path_in_toolchain": toolchain, "path_glob": glob,
                    "path_control": control, "proc_class": "unknown",
                    "git_op": git, "remote_class": "other" if git == "push" else "none"})
    return reading


def hook_reading(hook_input: Any, hc: HookCall, config: classifier.Config) -> Dict[str, Any]:
    """The reading of a hook input: its call classified, or, for a Bash command that reads unknown, the hazard
    scan's reading when it finds evidence."""
    reading = classifier.classify(hc.call, config)
    if hc.call.get("tool") == "unknown" and isinstance(hook_input, dict) and classifier.scalar(hook_input) \
            and classifier.scalar(hc.workspace) and hook_input.get("tool_name") == "Bash" \
            and isinstance(hook_input.get("tool_input"), dict) \
            and isinstance(hook_input["tool_input"].get("command"), str):
        cwd = hook_input.get("cwd") if isinstance(hook_input.get("cwd"), str) and hook_input.get("cwd") else hc.workspace
        scanned = hazard_scan(hook_input["tool_input"]["command"], hc.workspace, cwd, config)
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


def evaluate(hook_input: Any, env: Optional[Mapping[str, str]] = None, policy: Optional[Policy] = None,
             zones: Any = None) -> HookResult:
    """Classify one hook input, decide it under `policy` (agent_default when None) and write the hook answer.
    `zones` is the zone information point (prismpath/agent/zones.py), or a function of the workspace that gives it;
    None declares no zone, so nothing is protected."""
    policy = policy or load_default_policy()
    hc = hook_call(hook_input, env)
    point = zones(hc.workspace) if callable(zones) else zones
    config = classifier.Config.for_workspace(hc.workspace) if point is None \
        else classifier.Config.for_workspace(hc.workspace, zones=point)
    reading = hook_reading(hook_input, hc, config)
    decision = policy.decide(policy.reading_bytes(reading))
    return HookResult(decision, reading, hc.call, hc.workspace, hook_answer(decision))


_KIND_TO_PERMISSION = {"allow": "allow", "refuse": "deny", "escalate": "ask"}


def hook_answer(decision: Decision, updated_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The PreToolUse hook's JSON answer to one decision. A refusal's reason names the registered cause and
    holds RECEIPT_PLACEHOLDER for the caller to fill (fill_receipt); an allow carries no reason.
    `updated_input`, for an allow or a question (a person's approval then runs the rewritten call), is the whole tool input the call is to run with instead of the one
    the model sent (`updatedInput`); a refusal never carries it."""
    permission = _KIND_TO_PERMISSION[decision.kind]
    output: Dict[str, Any] = {"hookEventName": "PreToolUse", "permissionDecision": permission}
    if decision.kind == "refuse":
        output["permissionDecisionReason"] = (
            f"PrismPath refused this call: cause {_cause(decision)}. It was not run. Receipt {RECEIPT_PLACEHOLDER}.")
    elif decision.kind == "escalate":
        output["permissionDecisionReason"] = (
            f"PrismPath asks you to decide this call: cause {_cause(decision)}. Receipt {RECEIPT_PLACEHOLDER}."
            + (" If you approve it, it runs inside the PrismPath sandbox." if updated_input is not None else ""))
    if updated_input is not None and decision.kind in ("allow", "escalate"):
        output["updatedInput"] = updated_input
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
