# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The workspace's control paths, found in one place for every layer that has to keep them read only.

A control path is a file or directory whose content the agent harness reads as instructions or hooks: `.claude/`,
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
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

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


def sweep_stale(workspace: Path, directory: Optional[Path] = None) -> None:
    """Remove what an earlier run of this workspace created and did not clean up, when it is provably still ours: a
    marker written by a process that no longer exists lists it, and it is still an empty file or an empty directory."""
    directory = directory or marker_dir()
    key = _workspace_key(workspace)
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
            Controls(created_files=[Path(p) for p in record["files"]], created_dirs=[Path(p) for p in record["dirs"]]).remove_created()
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


def discover(workspace: Path) -> Found:
    """Look at `workspace` and list its control paths, creating nothing."""
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


def prepare(workspace: Path, out: Controls, directory: Optional[Path] = None) -> Found:
    """`sweep_stale`, then `discover`, then `materialize` into `out`, in that order, so that what a killed run left is
    gone before the control paths are looked at. Returns what was found."""
    sweep_stale(workspace, directory)
    found = discover(workspace)
    materialize(found, out, directory)
    return found
