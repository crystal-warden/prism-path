# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The classifier: one raw tool call an agent proposed, read into the typed fields the policy routes on.

This is TRUSTED CODE OUTSIDE THE VERIFIED CORE. The core (docs/design/spec-verified-core.md) decides one
reading against one signed policy image, and what is proved about that decision is proved about the
reading it is given. Whether the reading says truthfully what the call would do is this module's job
alone: a call the classifier reads as `read_only` when it deletes files would be allowed by a perfectly
correct core. So the classifier is kept small, deterministic (the same call and the same workspace
state give the same reading), conservative (a call it cannot read is `unknown`, never a guess), and
tested on its own (tests/test_classifier.py). Its version is a field of the reading, bounded by the
signed policy (`classifier_version`), so a reading from another classifier is refused at the boundary.

Every reading holds every field the policy defines, with no absence, no float, only the kinds the policy
declares:

  classifier_version  int, this module's CLASSIFIER_VERSION
  tool                list_dir | read_file | write_file | delete_path | run_command | git | unknown
  path_scope          none | workspace | outside | unknown      (the worst path the call names)
  path_in_toolchain   a named path resolves into a toolchain directory
  path_control        a named path is one of the agent's own controls (CONTROL_FILES, CONTROL_DIRS, the hook it runs)
  path_glob           a named path is a pattern (* ? [ ] { } or a leading ~), not one exact path
  path_traversal      a named path has a .. component
  path_symlink        a named path passes through, or ends at, a symbolic link
  command_class       none | read_only | mutating | network | git | unknown   (run_command only)
  kill_by_pattern     the call signals processes chosen by a name or pattern, not by one process id
  git_op              none | local_read | local_write | mutating | push | network | unknown
  remote_class        none | allowed | other                    (a push's remote)

The reading has two halves (docs/design/spec-verified-classifier.md). The SYNTACTIC half is everything read
off the call's text: the tool and its argument schema, the command class of an argv, a kill by pattern, the
git operation and remote, a glob or a `..` component in a path. It is defined in Lean (formal/Classifier/),
proved there, and this module is held to that definition by a differential harness
(formal/diff/classifier_diff.py). The DISK half is three observations per named path, made by `disk_facts`
alone: whether the path resolves inside the workspace, into a toolchain directory, through a symbolic
link, and onto one of the agent's control files. They are read off the workspace as it is when the call is classified (`os.path.realpath`,
`os.path.islink`). Between that and the execution the workspace could change; the sandbox (sandbox.py) is
what bounds the effect of such a race, not this module, and nothing about them is proved.

A call holding a string that is not Unicode scalar values (a lone surrogate, which JSON's `\\ud800` escape can
spell) is outside the model's domain and reads unknown (`scalar`).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

CLASSIFIER_VERSION = 1
MOUNT = "/workspace"          # where the sandbox mounts the workspace, and the path the model is told
TOOLS = ("list_dir", "read_file", "write_file", "delete_path", "run_command", "git")
GLOB_CHARS = set("*?[]{}")
# The agent's management plane: the files inside the workspace that hold its own controls (the hook that governs it,
# its settings, its MCP servers). A change to one of them, made by a path that resolves onto it, is refused under
# every shipped policy (cause 128). `.claude` itself is named too, since removing or renaming it removes them all.
CONTROL_FILES = (".claude/settings.json", ".claude/settings.local.json", ".mcp.json")
CONTROL_DIRS = (".claude/hooks",)         # the directory and everything below it
CONTROL_EXACT = (".claude",)              # the directory itself only
MAX_PATH = 4096
MAX_ARGV = 64

# The argument schema of each tool: (required, optional) keys and the type of every value.
_SCHEMA: Dict[str, Tuple[Dict[str, type], Dict[str, type]]] = {
    "list_dir": ({}, {"path": str}),
    "read_file": ({"path": str}, {}),
    "write_file": ({"path": str, "content": str}, {}),
    "delete_path": ({"path": str}, {}),
    "run_command": ({"argv": list}, {}),
    "git": ({"subcommand": str}, {"args": list}),
}

# run_command: what a program is, by the basename of argv[0]. Anything in none of these sets is unknown.
READ_ONLY = frozenset({"ls", "cat", "head", "tail", "wc", "grep", "egrep", "fgrep", "echo", "pwd", "true", "false",
                       "sort", "uniq", "diff", "cmp", "stat", "file", "date", "basename", "dirname", "realpath",
                       "readlink", "tree", "du", "md5sum", "sha1sum", "sha256sum", "cut", "printf", "which", "whoami",
                       "uname", "id", "find", "sed", "nl", "od", "xxd", "column", "comm", "join", "paste", "rev",
                       "seq", "tac", "test", "expr", "pgrep", "ps"})
MUTATING = frozenset({"rm", "rmdir", "mv", "cp", "ln", "chmod", "chown", "chgrp", "touch", "mkdir", "dd", "truncate",
                      "shred", "tee", "install", "unlink", "tar", "unzip", "zip", "gzip", "gunzip", "patch", "kill",
                      "pkill", "killall", "python", "python3", "perl", "ruby", "node", "bash", "sh", "zsh", "dash",
                      "make", "cargo", "rustc", "gcc", "cc", "npm", "npx", "pytest", "xargs", "env", "nohup",
                      "timeout", "nice", "awk", "gawk", "mawk", "vim", "vi", "nano", "ed", "crontab", "systemctl"})
NETWORK = frozenset({"curl", "wget", "ssh", "scp", "sftp", "nc", "ncat", "netcat", "telnet", "ftp", "ping", "ping6",
                     "dig", "nslookup", "host", "traceroute", "tracepath", "socat", "apt", "apt-get", "brew", "aria2c",
                     "http", "https", "lynx", "w3m", "links", "rsync", "torsocks"})
PRIVILEGE = frozenset({"sudo", "su", "doas", "pkexec", "chroot", "nsenter", "unshare", "setpriv", "bwrap"})
INSTALLERS = {"pip": ("install", "download", "wheel"), "pip3": ("install", "download", "wheel"),
              "npm": ("install", "i", "add", "ci", "update"), "yarn": ("add", "install"), "pnpm": ("add", "install", "i"),
              "cargo": ("install", "fetch", "update", "search", "publish"), "gem": ("install",), "go": ("get", "install")}
_FIND_EFFECTS = ("-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls")
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
WRAPPERS = frozenset({"sh", "bash", "zsh", "dash", "env", "timeout", "nohup", "nice", "xargs", "python", "python3",
                      "perl", "ruby", "node", "sudo", "doas", "su", "watch", "setsid", "stdbuf", "chroot"})
# ASCII word boundaries: every boundary Unicode \b finds, ASCII \b finds too, so this flags at least as much
_KILL_WORD = re.compile(r"\b(pkill|killall)\b", re.ASCII)
_SHELL_SEPARATORS = re.compile(r"[;&|()`\n]")
_SIGNAL = re.compile(r"-(\d+|[A-Z][A-Z0-9]*|SIG[A-Z0-9]+)", re.ASCII)     # used with fullmatch
_DIGITS = frozenset("0123456789")

# git: the subcommands, by what they do.
GIT_LOCAL_READ = frozenset({"status", "log", "diff", "show", "rev-parse", "ls-files", "blame", "shortlog", "describe",
                            "grep", "cat-file", "ls-tree"})
GIT_LOCAL_WRITE = frozenset({"add", "commit", "checkout", "switch", "stash", "tag", "merge", "branch", "mv", "init"})
GIT_MUTATING = frozenset({"rm", "clean", "restore", "filter-branch", "filter-repo", "gc", "prune", "reflog", "update-ref",
                          "rebase", "cherry-pick", "revert", "am", "apply"})
GIT_NETWORK = frozenset({"fetch", "pull", "clone", "ls-remote", "submodule", "send-email", "request-pull", "archive"})
GIT_PATH_ARGS = frozenset({"add", "rm", "mv", "restore", "blame", "ls-files"})
# `git tag` and `git branch` list or write by their argv. A form is a listing only when every argument is on these
# allowlists; any other flag, or a bare name with no list flag, is a local write (the stricter class).
_GIT_LIST_FLAGS = {
    "tag": frozenset({"-l", "--list", "-n", "-i", "--ignore-case", "--column", "--no-column"}),
    "branch": frozenset({"--list", "-a", "--all", "-r", "--remotes", "-v", "-vv", "--verbose", "--show-current",
                         "-i", "--ignore-case", "--column", "--no-column", "--color", "--no-color", "--no-abbrev"}),
}
_GIT_LIST_VALUE_FLAGS = frozenset({"--contains", "--no-contains", "--merged", "--no-merged", "--points-at"})
_GIT_LIST_PREFIXES = ("--sort=", "--format=", "--abbrev=", "--color=", "--column=")
_GIT_LIST_SWITCH = {"tag": ("-l", "--list"), "branch": ("--list",)}


def git_listing(subcommand: str, args: List[str]) -> bool:
    """True when `git tag ARGS` or `git branch ARGS` only lists: no arguments at all, or every argument a listing
    flag, a listing flag's value, or (after an explicit list flag) a pattern. Everything else is not a listing."""
    flags, switch = _GIT_LIST_FLAGS[subcommand], _GIT_LIST_SWITCH[subcommand]
    listing = any(arg in switch for arg in args)
    expect_value = False
    for arg in args:
        if expect_value:
            expect_value = False
            if arg.startswith("-"):
                return False
        elif arg in _GIT_LIST_VALUE_FLAGS:
            expect_value = True
        elif arg in flags or arg.startswith(_GIT_LIST_PREFIXES) or (subcommand == "tag" and re.fullmatch(r"-n\d+", arg, re.ASCII)):
            continue
        elif arg.startswith("-") or not listing:
            return False       # an unrecognised flag, or a bare name that would create something
    return not expect_value


GIT_UNSAFE_OPTIONS = ("--exec", "--upload-pack", "--receive-pack", "-c", "--config", "--git-dir", "--work-tree", "-C")


@dataclass
class Config:
    """What the classifier is told about the world: the workspace on the host, the toolchain directories,
    and the remote names a push may go to without the owner (none in this example)."""
    workspace: Path
    toolchain_dirs: Tuple[Path, ...] = ()
    allowed_remotes: Tuple[str, ...] = ()

    def __post_init__(self):
        self.workspace = Path(os.path.realpath(self.workspace))

    @classmethod
    def for_workspace(cls, workspace, allowed_remotes: Iterable[str] = ()) -> "Config":
        """The example's configuration: the workspace's own `.toolchain` directory and the host's toolchain
        directories (the system prefixes and the per user toolchain homes)."""
        workspace = Path(os.path.realpath(workspace))
        home = Path(os.path.expanduser("~"))
        dirs = [workspace / ".toolchain", Path("/usr"), Path("/opt"), Path("/etc"), home / ".cargo",
                home / ".rustup", home / ".elan", home / ".local", home / ".npm", home / ".pyenv"]
        return cls(workspace, tuple(dirs), tuple(allowed_remotes))


def base_reading() -> Dict[str, Any]:
    return {"classifier_version": CLASSIFIER_VERSION, "tool": "unknown", "path_scope": "none",
            "path_in_toolchain": False, "path_control": False, "path_glob": False, "path_traversal": False, "path_symlink": False,
            "command_class": "none", "kill_by_pattern": False, "git_op": "none", "remote_class": "none"}


def unknown_reading() -> Dict[str, Any]:
    """The reading of a call the classifier cannot read: it routes to `agent:unclassifiable`."""
    return base_reading()


def scalar(value: Any) -> bool:
    """True when every string in a JSON value, keys included, is Unicode scalar values (no lone surrogate).
    The model's strings are Lean strings, which hold scalar values only; anything else reads unknown."""
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return False
        return True
    if isinstance(value, dict):
        return all(scalar(key) and scalar(item) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return all(scalar(item) for item in value)
    return True


# ----------------------------------------------------------------- paths
@dataclass
class PathFacts:
    scope: str                 # workspace | outside | unknown
    toolchain: bool = False
    glob: bool = False
    traversal: bool = False
    symlink: bool = False
    control: bool = False


def _under(path: str, root: Path) -> bool:
    root_text = str(root)
    return path == root_text or path.startswith(root_text.rstrip("/") + "/")


def host_path(raw: str, config: Config) -> str:
    """The host path a model's path names, lexically (no normalization): relative paths are inside the
    workspace, and `/workspace` is the workspace's mount point in the sandbox."""
    if raw == MOUNT or raw.startswith(MOUNT + "/"):
        return str(config.workspace) + raw[len(MOUNT):]
    if raw.startswith("/"):
        return raw
    return str(config.workspace) + "/" + raw


@dataclass(frozen=True)
class DiskFacts:
    """The three observations of one path on the disk: not proved, bounded by the sandbox."""
    inside: bool               # resolves (and normalizes) inside the workspace
    toolchain: bool            # resolves (or normalizes) into a toolchain directory
    symlink: bool              # some prefix below the workspace root (or /) is a symbolic link
    control: bool = False      # resolves (or normalizes) onto one of the agent's control files


def path_facts(raw: Any, config: Config) -> PathFacts:
    """The facts of one named path: the syntactic ones read here off the text, the rest observed on the disk."""
    if not isinstance(raw, str) or not raw or "\x00" in raw or len(raw) > MAX_PATH:
        return PathFacts("unknown")
    glob = any(char in GLOB_CHARS for char in raw) or raw.startswith("~")
    traversal = ".." in raw.split("/")
    disk = disk_facts(raw, config)
    return PathFacts("workspace" if disk.inside else "outside", disk.toolchain, glob, traversal, disk.symlink,
                     disk.control)


def disk_facts(raw: str, config: Config) -> DiskFacts:
    """What the disk says about a path the syntactic checks passed (the only part of a reading that is an
    observation, not a function of the call's text)."""
    lexical = host_path(raw, config)
    resolved = os.path.realpath(lexical)
    # every prefix of the lexical path below the workspace root (or below / for a path outside it)
    symlink = False
    start = str(config.workspace) if _under(lexical, config.workspace) else ""
    parts = [part for part in lexical[len(start):].split("/") if part]
    prefix = start
    for part in parts:
        prefix = prefix + "/" + part
        if os.path.islink(prefix):
            symlink = True
            break
    normal = os.path.normpath(lexical)
    toolchain = any(_under(resolved, root) or _under(normal, root) for root in config.toolchain_dirs)
    inside = _under(resolved, config.workspace) and _under(normal, config.workspace)
    control = _is_control(resolved, normal, config)
    return DiskFacts(inside, toolchain, symlink, control)


def hook_programs(config: Config) -> List[str]:
    """The program each PrismPath hook command in the workspace's `.claude/settings.json` runs (its first word),
    when it is a path inside the workspace: the interpreter the installed hook starts. Read off the disk at the
    moment of the call; an unreadable or unusual settings file names none."""
    out: List[str] = []
    try:
        import json
        import shlex
        text = (config.workspace / ".claude" / "settings.json").read_text(encoding="utf-8")
        for groups in json.loads(text).get("hooks", {}).values():
            for group in groups:
                for hook in group.get("hooks", []):
                    words = shlex.split(hook["command"].replace("$CLAUDE_PROJECT_DIR", str(config.workspace)))
                    if words and "agent" in words and "hook" in words and any("prismpath" in w for w in words) \
                            and words[0].startswith("/") and _under(os.path.normpath(words[0]), config.workspace):
                        out.append(words[0])
    except Exception:   # noqa: BLE001 - a settings file that does not read names no program
        return out
    return out


def _is_control(resolved: str, normal: str, config: Config) -> bool:
    """True when the resolved or the normalized path is a control file, is below a control directory, is `.claude`
    itself, or is the program an installed PrismPath hook runs."""
    workspace = config.workspace
    files = [workspace / name for name in CONTROL_FILES + CONTROL_EXACT] + [Path(p) for p in hook_programs(config)]
    dirs = [workspace / name for name in CONTROL_DIRS]
    targets = {os.path.realpath(f) for f in files} | {os.path.normpath(f) for f in files}
    roots = {os.path.realpath(d) for d in dirs} | {os.path.normpath(d) for d in dirs}
    return any(path in targets or any(_under(path, Path(root)) for root in roots) for path in (resolved, normal))


_SCOPE_RANK = {"none": 0, "workspace": 1, "outside": 2, "unknown": 3}


def _merge_paths(reading: Dict[str, Any], facts: List[PathFacts]) -> None:
    for fact in facts:
        if _SCOPE_RANK[fact.scope] > _SCOPE_RANK[reading["path_scope"]]:
            reading["path_scope"] = fact.scope
        reading["path_in_toolchain"] |= fact.toolchain
        reading["path_glob"] |= fact.glob
        reading["path_traversal"] |= fact.traversal
        reading["path_symlink"] |= fact.symlink
        reading["path_control"] |= fact.control


def _path_like_args(args: List[str]) -> List[str]:
    """The arguments of a command that may name a path: every non option word, and the value of an
    `--option=value` that holds a slash."""
    out, after_dashes = [], False
    for arg in args:
        if after_dashes:
            out.append(arg)
        elif arg == "--":
            after_dashes = True
        elif arg.startswith("-"):
            if "=" in arg and "/" in arg.split("=", 1)[1]:
                out.append(arg.split("=", 1)[1])
        else:
            out.append(arg)
    return out


# ----------------------------------------------------------------- commands
def _kill_args_by_pid(args: List[str]) -> bool:
    """`kill [-SIGNAL | -s SIGNAL] PID...` with every target one positive process id."""
    rest = list(args)
    if rest[:1] == ["-s"] and len(rest) >= 2:
        rest = rest[2:]
    elif rest and _SIGNAL.fullmatch(rest[0]):
        rest = rest[1:]
    return bool(rest) and all(arg and set(arg) <= _DIGITS and arg != "0" for arg in rest)


def kill_by_pattern(argv: List[str]) -> bool:
    base = os.path.basename(argv[0])
    if base in ("pkill", "killall"):
        return True
    if base == "kill" and not _kill_args_by_pid(argv[1:]):
        return True
    if base == "xargs" and "kill" in argv[1:]:
        return True            # the process ids come from standard input, chosen by whatever wrote it
    if base not in WRAPPERS:
        return False
    # a kill written inside the arguments of a program that runs other programs (a shell's -c text, env,
    # timeout, nohup): any pkill or killall word, or a kill whose targets are not all process ids
    for arg in argv[1:]:
        if _KILL_WORD.search(arg):
            return True
        for command in _SHELL_SEPARATORS.split(arg):
            words = command.split()
            for at, word in enumerate(words):
                if word == "kill" and not _kill_args_by_pid(words[at + 1:]):
                    return True
    return False


def command_class(argv: List[str]) -> str:
    first = argv[0]
    if first.startswith("/") and os.path.dirname(first) in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
        base = os.path.basename(first)
    elif "/" in first:
        return "mutating"          # a program of the workspace: the classifier cannot see what it does
    else:
        base = first
    if not base or base in PRIVILEGE:
        return "unknown"
    if base == "git":
        return "git"               # git_facts reads what it does, a URL included
    if base in NETWORK or any(_URL.search(arg) for arg in argv[1:]):
        return "network"
    if base in INSTALLERS and any(arg in INSTALLERS[base] for arg in argv[1:2]):
        return "network"
    if base in ("python", "python3") and argv[1:3] == ["-m", "pip"]:
        return "network"
    if base == "find" and any(arg in _FIND_EFFECTS for arg in argv[1:]):
        return "mutating"
    if base == "sed" and any(arg == "-i" or arg.startswith("-i") or arg.startswith("--in-place") for arg in argv[1:]):
        return "mutating"
    if base == "sort" and any(arg == "-o" or arg.startswith("--output") for arg in argv[1:]):
        return "mutating"
    if base == "tree" and "-o" in argv[1:]:
        return "mutating"
    if base in READ_ONLY:
        return "read_only"
    if base in MUTATING or base in INSTALLERS:
        return "mutating"
    return "unknown"


def git_facts(subcommand: Any, args: Any, config: Config) -> Tuple[str, str, List[PathFacts]]:
    """(git_op, remote_class, path facts) of `git SUBCOMMAND ARGS...`."""
    if not isinstance(subcommand, str) or not subcommand or subcommand.startswith("-") or \
            not isinstance(args, list) or len(args) > MAX_ARGV or \
            not all(isinstance(arg, str) and "\x00" not in arg for arg in args):
        return "unknown", "none", []
    if any(arg == option or arg.startswith(option + "=") for arg in args for option in GIT_UNSAFE_OPTIONS):
        return "unknown", "none", []
    if subcommand == "push":
        words = [arg for arg in args if not arg.startswith("-")]
        remote = words[0] if words else "origin"
        return "push", ("allowed" if remote in config.allowed_remotes else "other"), []
    if any(_URL.search(arg) for arg in args) or subcommand in GIT_NETWORK:
        return "network", "none", []
    if subcommand == "remote":
        return ("local_read" if all(arg in ("-v", "--verbose") for arg in args) else "unknown"), "none", []
    if subcommand == "reset":
        return ("mutating" if "--hard" in args else "local_write"), "none", []
    paths = [path_facts(arg, config) for arg in _path_like_args(args)] if subcommand in GIT_PATH_ARGS else []
    if subcommand in GIT_LOCAL_READ:
        return "local_read", "none", paths
    if subcommand in ("tag", "branch") and git_listing(subcommand, args):
        return "local_read", "none", paths
    if subcommand in GIT_LOCAL_WRITE:
        return "local_write", "none", paths
    if subcommand in GIT_MUTATING:
        return "mutating", "none", paths
    return "unknown", "none", []


# ----------------------------------------------------------------- one call
def _schema_ok(tool: str, args: Any) -> bool:
    if not isinstance(args, dict):
        return False
    required, optional = _SCHEMA[tool]
    if not set(required) <= set(args) or not set(args) <= set(required) | set(optional):
        return False
    return all(type(args[key]) is kind for key, kind in {**required, **optional}.items() if key in args)


def classify(call: Any, config: Config) -> Dict[str, Any]:
    """The reading of one proposed call `{"tool": name, "args": {...}}`. Never raises: any call it cannot
    read in full is the unknown reading."""
    try:
        if not scalar(call):
            return unknown_reading()
        return _classify(call, config)
    except Exception:   # noqa: BLE001 - a classifier failure must fail closed, never open
        return unknown_reading()


def _classify(call: Any, config: Config) -> Dict[str, Any]:
    if not isinstance(call, dict) or set(call) - {"tool", "args"} or call.get("tool") not in TOOLS:
        return unknown_reading()
    tool, args = call["tool"], call.get("args", {})
    if not _schema_ok(tool, args):
        return unknown_reading()
    reading = base_reading()
    reading["tool"] = tool
    if tool in ("list_dir", "read_file", "write_file", "delete_path"):
        _merge_paths(reading, [path_facts(args.get("path", "."), config)])
        return reading
    if tool == "git":
        op, remote, paths = git_facts(args["subcommand"], args.get("args", []), config)
        reading["git_op"], reading["remote_class"] = op, remote
        _merge_paths(reading, paths)
        return reading
    argv = args["argv"]
    if not argv or len(argv) > MAX_ARGV or not all(isinstance(arg, str) and arg and "\x00" not in arg for arg in argv):
        reading["command_class"] = "unknown"
        return reading
    reading["kill_by_pattern"] = kill_by_pattern(argv)
    reading["command_class"] = command_class(argv)
    if reading["command_class"] == "git":
        op, remote, paths = git_facts(argv[1] if len(argv) > 1 else None, argv[2:], config)
        reading["git_op"], reading["remote_class"] = op, remote
        _merge_paths(reading, paths)
    else:
        _merge_paths(reading, [path_facts(arg, config) for arg in _path_like_args(argv[1:])])
    return reading
