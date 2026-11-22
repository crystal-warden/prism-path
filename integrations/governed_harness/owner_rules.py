# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The owner's agent rules read a second time, as plain Python over the classifier's fields, independent of
the policy image. It is the reference the scorer and the exhaustive test hold the signed policy to: if the
image and this reading ever decide one reading differently, one of them states the rules wrongly.

It returns what the rules say should happen to a call with these facts: ("allow", None), ("refuse",
cause) or ("escalate", cause), the cause by its registered name. The order of the checks is the priority
the owner gave them: a call that cannot be read is refused before anything else is looked at, and the most
specific path rule names the refusal of a write or delete.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

WRITES = ("write_file", "delete_path")
FILE_TOOLS = ("list_dir", "read_file", "write_file", "delete_path")
NO_RULE = "route:no-matching-edge"


def expected(r: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    # anything unclassifiable is refused: never fail open
    if "unknown" in (r["tool"], r["command_class"], r["git_op"], r["path_scope"]):
        return "refuse", "agent:unclassifiable"
    # never kill processes by pattern
    if r["kill_by_pattern"]:
        return "refuse", "agent:kill-by-pattern"
    # no network commands
    if r["command_class"] == "network" or r["git_op"] == "network":
        return "refuse", "agent:network"
    # a connection to anything but the model's own API (a host a starter does not list, one it cannot read): refused
    if r["net_dest"] in ("allowed_host", "other", "unknown") or (r["tool"] == "connect" and r["net_dest"] == "none"):
        return "refuse", "agent:net-refused"
    # a change to the agent's own controls (settings, hooks, MCP configuration): refused, never asked
    if r["path_control"] and (r["tool"] in WRITES or r["command_class"] == "mutating"
                              or r["git_op"] in ("local_write", "mutating")):
        return "refuse", "agent:control-write"
    # writes and deletes: never into a toolchain, only by one exact path, never through .. or a link
    if r["tool"] in WRITES:
        if r["path_in_toolchain"]:
            return "refuse", "agent:toolchain-write"
        if r["path_glob"]:
            return "refuse", "agent:glob-path"
        if r["path_traversal"]:
            return "refuse", "agent:path-traversal"
        if r["path_symlink"]:
            return "refuse", "agent:symlink-path"
    # only inside the workspace
    if r["path_scope"] == "outside":
        return "refuse", "agent:outside-workspace"
    # files change only through the exact path tools
    if r["command_class"] == "mutating" or r["git_op"] == "mutating":
        return "refuse", "agent:shell-mutation"
    # a file change that reaches one of the owner's zones, or whose reach is not known, waits for the owner
    if r.get("zone_reach", "none") in ("protected", "unknown") and r["tool"] in WRITES:
        return "escalate", "agent:zone-asked"
    # no push except to an allowed remote class; otherwise the owner decides
    if r["git_op"] == "push":
        return ("allow", None) if r["remote_class"] == "allowed" else ("escalate", "agent:push-escalated")
    if r["tool"] == "connect" and r["net_dest"] == "model_api":
        return "allow", None
    if r["tool"] in FILE_TOOLS and r["path_scope"] == "workspace":
        return "allow", None
    if r["tool"] == "run_command" and r["command_class"] == "read_only" and r["path_scope"] in ("none", "workspace"):
        return "allow", None
    if r["git_op"] in ("local_read", "local_write") and r["path_scope"] in ("none", "workspace"):
        return "allow", None
    return "refuse", NO_RULE
