# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""An MCP `tools/call` read into the classifier's call shape (`{"tool": ..., "args": {...}}`).

This is TRUSTED CODE OUTSIDE THE VERIFIED CORE, like the classifier (classifier.py). It is kept small and
conservative: a tool whose name and arguments it does not know in full is the `unknown` call, which the
policy refuses (`agent_rules`, cause 104) or escalates (`agent_default`). It never raises.

Two families of MCP tools are read, and nothing else:

  * the classifier's own tools by their own names (`list_dir`, `read_file`, `write_file`, `delete_path`,
    `run_command`, `git`) with the classifier's own argument schema. The arguments are handed to the
    classifier as they are, so its schema check decides whether they read; a server that serves these names
    serves the classifier's contract, `/workspace` as the workspace's mount included (classifier.MOUNT).
  * the file tools of the reference filesystem server (@modelcontextprotocol/server-filesystem), by name,
    with every argument key known. Their paths are host paths: an absolute path is the path it names (a path
    under `/workspace` is spelled `/./workspace/...` so the classifier does not read it as the mount), and a
    relative path is joined to the directory the server was started in. A path whose first component is `~` or
    `~user` is handed over as it is, and the classifier reads it as outside the workspace.

      read_text_file, read_media_file, get_file_info          read_file    the path
      list_directory, list_directory_with_sizes, directory_tree list_dir   the path
      search_files                                            list_dir     the path joined to the pattern
      write_file (path and content), edit_file, create_directory write_file the path
      list_allowed_directories                                list_dir     the workspace

    `move_file` and `read_multiple_files` name several paths and are `unknown`.

Where a filesystem tool shares a classifier tool's name (`read_file`, `write_file`), the classifier's schema
is what decides: the filesystem server's `read_file` with `head` or `tail` does not read and is `unknown`.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Mapping, Optional, Tuple

from . import classifier

# filesystem tool name -> (classifier tool, required keys, optional keys)
_FS: Dict[str, Tuple[str, Tuple[str, ...], Tuple[str, ...]]] = {
    "read_text_file": ("read_file", ("path",), ("head", "tail")),
    "read_media_file": ("read_file", ("path",), ()),
    "get_file_info": ("read_file", ("path",), ()),
    "list_directory": ("list_dir", ("path",), ()),
    "list_directory_with_sizes": ("list_dir", ("path",), ("sortBy",)),
    "directory_tree": ("list_dir", ("path",), ("excludePatterns",)),
    "search_files": ("list_dir", ("path", "pattern"), ("excludePatterns",)),
    "edit_file": ("write_file", ("path", "edits"), ("dryRun",)),
    "create_directory": ("write_file", ("path",), ()),
    "list_allowed_directories": ("list_dir", (), ()),
}


def _unknown() -> Dict[str, Any]:
    return {"tool": "unknown", "args": {}}


def _spell(raw: str) -> str:
    if raw == classifier.MOUNT or raw.startswith(classifier.MOUNT + "/"):
        return "/." + raw
    return raw


def host_path(raw: Any, server_cwd: str) -> Optional[str]:
    """The absolute host path a filesystem tool's path names, spelled for the classifier, or None."""
    if not isinstance(raw, str) or not raw:
        return None
    if raw.startswith("~"):
        return raw              # a home path: the classifier reads it as outside the workspace
    if raw.startswith("/"):
        return _spell(raw)
    return _spell(os.path.join(server_cwd, raw))


def classifier_call(params: Any, server_cwd: str) -> Dict[str, Any]:
    """The classifier call of one `tools/call` request's params. Never raises."""
    try:
        if not classifier.scalar(params) or not classifier.scalar(server_cwd):
            return _unknown()
        return _call(params, server_cwd)
    except Exception:   # noqa: BLE001 - a mapping failure must fail to unknown, never to a guess
        return _unknown()


def _call(params: Any, server_cwd: str) -> Dict[str, Any]:
    if not isinstance(params, Mapping):
        return _unknown()
    name = params.get("name")
    arguments = params.get("arguments", {})
    if not isinstance(name, str) or not isinstance(arguments, Mapping):
        return _unknown()
    if name in classifier.TOOLS:
        return {"tool": name, "args": dict(arguments)}
    if name not in _FS:
        return _unknown()
    tool, required, optional = _FS[name]
    keys = set(arguments)
    if not set(required) <= keys or not keys <= set(required) | set(optional):
        return _unknown()
    if not required:                           # list_allowed_directories: the server's own configuration
        return {"tool": tool, "args": {}}
    path = host_path(arguments["path"], server_cwd)
    if path is None:
        return _unknown()
    if name == "search_files":
        pattern = arguments["pattern"]
        if not isinstance(pattern, str) or not pattern or pattern.startswith(("~", "/")):
            return _unknown()
        path = path.rstrip("/") + "/" + pattern
    if tool == "write_file":
        return {"tool": "write_file", "args": {"path": path, "content": ""}}
    return {"tool": tool, "args": {"path": path}}
