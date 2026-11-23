# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The workspace's control paths, found in one place for every layer that has to keep them read only.

A control path is a file or directory whose content the agent harness reads as instructions or hooks, or that holds a
fact the policy relies on: the zone index (`.contextcloud/` by default, named by the signed zone file, zones.py), which
`discover` takes as `extra` and the hook reads off the zone information point's `control_paths`. The fixed ones are `.claude/`,
`.mcp.json`, every CLAUDE.md, CLAUDE.local.md and AGENTS.md, `.git/config` and `.git/hooks/` (the classifier's
`CONTROL_NAMES` and walker decide which names count, so this list cannot drift from the hook's own rule). The
launcher binds them read only over the writable workspace for the whole run (launcher.prepare_controls), and the per
call sandbox does so for each call, with bubblewrap by a bind mount and with Landlock by leaving them out of the write
rules (landlock.py, `workspace_rules`), because a Landlock rule can only add access to a tree, never take it away.

`discover` only looks. It returns every control path that exists (links are never bound) and what would have to be
created to bind the root ones that are missing, so that a script cannot create `.claude/settings.json` where there is
none. `Controls` records what a caller created, to remove what is still empty afterwards. What it creates is also
written to a marker file in a private directory outside the workspace (`marker_dir`), named for the workspace and the
creating process, so that a run that was killed before it could clean up is cleaned up by the next one (`sweep_stale`).
The sweep removes only what a marker lists, only while it is still empty, and only when the process that wrote the
marker is gone. A file or directory that someone else made, or that has content, is never touched.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence

from prismpath.agent import classifier

ROOT_CONTROL_NAMES = ("CLAUDE.md", "CLAUDE.local.md", "AGENTS.md")


@dataclass
class Controls:
    """The workspace's control paths: what to bind read only, and what the caller created to bind it."""
    binds: List[str] = field(default_factory=list)
    created_files: List[Path] = field(default_factory=list)
    created_dirs: List[Path] = field(default_factory=list)
    marker: Optional[Path] = None

    def remove_created(self) -> None:
        for path in self.created_files:
            try:
                if path.is_file() and not path.is_symlink() and path.stat().st_size == 0:
                    path.unlink()
            except OSError:
                pass
        for path in reversed(self.created_dirs):
            try:
                path.rmdir()
            except OSError:
                pass
        if self.marker is not None:
            try:
                self.marker.unlink()
            except OSError:
                pass
            self.marker = None


def marker_dir() -> Path:
    """The private directory the markers live in, outside every workspace."""
    return Path(tempfile.gettempdir()) / f"prismpath-controls-{os.getuid()}"


def _workspace_key(workspace: Path) -> str:
    return hashlib.sha256(os.path.realpath(workspace).encode("utf-8", "surrogateescape")).hexdigest()[:24]


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _private(directory: Path) -> bool:
    """Whether the marker directory is a real directory this user owns that no one else can write or read. Anything
    else (a link, another user's directory made first in a shared temp, a loose mode) is not trusted with markers."""
    try:
        st = os.lstat(directory)
    except OSError:
        return False
    return stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & 0o077


def _sweepable(workspace: Path, extra: Sequence[str] = ()) -> set:
    """The only paths a sweep may remove: the control paths `discover` can create at this workspace's root and in its
    `.git`, whatever a marker says."""
    root = Path(os.path.realpath(workspace))
    names = [root / n for n in (".claude", ".mcp.json") + ROOT_CONTROL_NAMES]
    named = [Path(os.path.realpath(Path(e.rstrip("/")).parent)) / Path(e.rstrip("/")).name for e in extra]
    return set(names + named + [root / ".git" / "config", root / ".git" / "hooks"])


def _in(path: Path, allowed: set) -> bool:
    return Path(os.path.realpath(path.parent)) / path.name in allowed


def sweep_stale(workspace: Path, directory: Optional[Path] = None, extra: Sequence[str] = ()) -> None:
    """Remove what an earlier run of this workspace created and did not clean up, when it is provably still ours: a
    marker in the private marker directory, written by a process that no longer exists, lists it, it is one of the
    workspace's own control paths, and it is still an empty file or an empty directory."""
    directory = directory or marker_dir()
    if not _private(directory):
        return
    key = _workspace_key(workspace)
    allowed = _sweepable(workspace, extra)
    try:
        markers = [m for m in directory.iterdir() if m.name.startswith(key + ".") and m.name.endswith(".json")]
    except OSError:
        return
    for marker in markers:
        try:
            record = json.loads(marker.read_text(encoding="utf-8"))
            pid = int(record["pid"])
            if pid == os.getpid() or _alive(pid):
                continue
            Controls(created_files=[Path(p) for p in record["files"] if _in(Path(p), allowed)],
                     created_dirs=[Path(p) for p in record["dirs"] if _in(Path(p), allowed)]).remove_created()
        except (OSError, ValueError, KeyError, TypeError):
            pass
        try:
            marker.unlink()
        except OSError:
            pass


def _write_marker(out: "Controls", workspace: Path, directory: Optional[Path], files, dirs) -> None:
    """Record, before it is created, what is about to be, so that a crash cannot lose it."""
    directory = directory or marker_dir()
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not _private(directory):
            out.marker = None
            return
        if out.marker is None:
            out.marker = directory / f"{_workspace_key(workspace)}.{os.getpid()}.{id(out):x}.json"
        out.marker.write_text(json.dumps({"pid": os.getpid(), "workspace": str(workspace),
                                          "files": [str(p) for p in files], "dirs": [str(p) for p in dirs]}), encoding="utf-8")
    except OSError:
        out.marker = None       # no marker means no later sweep, and the caller still removes its own


@dataclass
class Found:
    """`binds` are the control paths to protect (existing ones and the ones `create_*` would make), `create_files` and
    `create_dirs` are the root ones that are missing."""
    binds: List[str] = field(default_factory=list)
    create_files: List[Path] = field(default_factory=list)
    create_dirs: List[Path] = field(default_factory=list)
    workspace: str = ""


def _extra_path(named: str, workspace: Path):
    """(the path, its parent) of an extra control path when it names something directly or deeper below the workspace,
    else (None, None): one outside is left to the sandbox's own read only view. A directory is named with a trailing
    slash."""
    path = Path(named.rstrip("/") or "/")
    parent = Path(os.path.realpath(path.parent))
    root = os.path.realpath(workspace).rstrip("/") + "/"
    if not (str(parent).rstrip("/") + "/").startswith(root):
        return None, None
    return path, parent


def discover(workspace: Path, extra: Sequence[str] = ()) -> Found:
    """Look at `workspace` and list its control paths, creating nothing. `extra` are further control paths the owner's
    signed files name (the directory of the zone index, zones.py `control_paths`): each one that exists below the
    workspace is bound like the fixed ones, and one outside the workspace is left to the sandbox's own read only view."""
    workspace = Path(workspace)
    found = Found(workspace=str(workspace))

    def bind(path: Path) -> None:
        if not path.is_symlink():
            found.binds.append(str(path))

    existing = {classifier._fold(n): n for n in os.listdir(workspace)}
    for name in (".claude", ".mcp.json") + ROOT_CONTROL_NAMES:
        if classifier._fold(name) not in existing:
            path = workspace / name
            (found.create_dirs if name == ".claude" else found.create_files).append(path)
            existing[classifier._fold(name)] = name
        bind(workspace / existing[classifier._fold(name)])
    git = workspace / ".git"
    if git.is_dir() and not git.is_symlink():
        for name, files in (("config", found.create_files), ("hooks", found.create_dirs)):
            path = git / name
            if not path.exists() and not path.is_symlink():
                files.append(path)
            bind(path)
    for named in extra:
        path, parent = _extra_path(named, workspace)
        if path is None:
            continue
        if not os.path.lexists(path):       # a missing one is made empty to be bound, as a missing `.claude/` is
            if not parent.is_dir():
                continue
            (found.create_dirs if named.endswith("/") else found.create_files).append(path)
        bind(path)
    for hit in classifier._walk_names(str(workspace)):
        path = Path(hit)
        if path.parent != workspace:        # the root ones are bound above
            bind(path)
    found.binds = list(dict.fromkeys(found.binds))
    return found


def materialize(found: Found, out: Controls, directory: Optional[Path] = None) -> Controls:
    """Create what `found` says is missing (empty), so that it can be bound, and record it in `out` as it goes.
    The marker is written before the creating, so that a crash cannot lose what was made."""
    workspace = Path(found.workspace) if found.workspace else None
    if workspace is not None:
        files = [p for p in found.create_files if p.parent.is_dir()]
        dirs = [p for p in found.create_dirs if p.parent.is_dir()]
        if files or dirs:
            _write_marker(out, workspace, directory, files, dirs)
    for path in found.create_dirs:
        if path.parent.is_dir():
            path.mkdir(exist_ok=True)
            out.created_dirs.append(path)
    for path in found.create_files:
        if path.parent.is_dir():
            path.touch()
            out.created_files.append(path)
    out.binds = list(found.binds)
    return out


def on_read_only_mount(path: str) -> bool:
    """True when `path` is under a read only mount already (the launcher's bind), so nothing more is needed for it."""
    try:
        return bool(os.statvfs(path).f_flag & os.ST_RDONLY)
    except OSError:
        return False


def prepare(workspace: Path, out: Controls, directory: Optional[Path] = None, extra: Sequence[str] = ()) -> Found:
    """`sweep_stale`, then `discover`, then `materialize` into `out`, in that order, so that what a killed run left is
    gone before the control paths are looked at. Returns what was found."""
    sweep_stale(workspace, directory, extra)
    found = discover(workspace, extra)
    materialize(found, out, directory)
    return found
