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
none. `Controls` records what a caller created, to remove what is still empty afterwards.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from prismpath.agent import classifier

ROOT_CONTROL_NAMES = ("CLAUDE.md", "CLAUDE.local.md", "AGENTS.md")


@dataclass
class Controls:
    """The workspace's control paths: what to bind read only, and what the caller created to bind it."""
    binds: List[str] = field(default_factory=list)
    created_files: List[Path] = field(default_factory=list)
    created_dirs: List[Path] = field(default_factory=list)

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


@dataclass
class Found:
    """`binds` are the control paths to protect (existing ones and the ones `create_*` would make), `create_files` and
    `create_dirs` are the root ones that are missing."""
    binds: List[str] = field(default_factory=list)
    create_files: List[Path] = field(default_factory=list)
    create_dirs: List[Path] = field(default_factory=list)


def discover(workspace: Path) -> Found:
    """Look at `workspace` and list its control paths, creating nothing."""
    workspace = Path(workspace)
    found = Found()

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


def materialize(found: Found, out: Controls) -> Controls:
    """Create what `found` says is missing (empty), so that it can be bound, and record it in `out` as it goes."""
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
