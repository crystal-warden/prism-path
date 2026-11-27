# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The fields an agent rules source may declare, for a person writing one.

This is the reference the guide's field table is generated from (docs/guides/writing-agent-rules.md, written by
tools/gen_rules_reference.py). It adds no vocabulary. The values of a category come from `profile.KNOWN_CATEGORIES`,
the reading domain the agent loads a policy against, and the tests hold that list to the classifier's own field
list (prismpath/agent/classifier.py), the oracle's tuples (prismpath/agent/policy.py) and the session fields
(prismpath/agent/session_state.py). What each field means is said once here, in the words of the classifier's
docstring, and where a value depends on something outside the rules (a host list, a zone file, a fixed number)
the entry says where that lives.

`REQUIRED` names the fields the agent needs to do more than decide a call. A policy without them still loads and
decides, but the sandbox cannot be built for one without the first three, and `agent status` and `agent doctor`
report one without `path_control`. `prismpath policy compile --target agent` (prismpath/agent/target.py) refuses
any of them missing.
"""
from __future__ import annotations

from typing import Dict, Tuple

from prismpath.agent import profile, session_state

# (name, kind, meaning). The order is the classifier's.
FIELDS: Tuple[Tuple[str, str, str], ...] = (
    ("classifier_version", "int", "the classifier's version, which a starter bounds with min and max to the version it was made for"),
    ("tool", "category", "the tool the call uses"),
    ("path_scope", "category", "the worst path the call names, which is none, inside the workspace, outside it, or not read"),
    ("path_in_toolchain", "bool", "a named path resolves into a toolchain directory (/usr, /opt, /etc and the language toolchains under the home directory)"),
    ("path_control", "bool", "a named path is one of the agent's own controls (.claude/, .mcp.json, .git/config, .git/hooks/, CLAUDE.md, CLAUDE.local.md, AGENTS.md, the program its hook runs, or a directory that holds one)"),
    ("path_glob", "bool", "a named path is a pattern (* ? [ ] { }), not one exact path"),
    ("path_traversal", "bool", "a named path has a .. component"),
    ("path_symlink", "bool", "a named path passes through, or ends at, a symbolic link"),
    ("command_class", "category", "what a run_command does, which is read only, change files, reach the network, run git, or not read"),
    ("kill_by_pattern", "bool", "the call signals processes chosen by a name or pattern, not by one process id"),
    ("git_op", "category", "the git operation, which is a local read, a local write, a change that cannot be undone, a push, a network operation, or not read"),
    ("remote_class", "category", "a push's remote, allowed when it is in the classifier's `Config.allowed_remotes`. No command sets that list today, so every push reads other"),
    ("net_dest", "category", "where a connect goes, which is the model's own API, a host the owner listed with `agent run --allow-host` (not part of the signed policy), another host, or one that is not read"),
    ("proc_class", "category", "what a run_command needs of the process table, one process or a tree. The limit is `agent run --max-processes`"),
    ("zone_reach", "category", "a change that reaches code in one of the owner's zones (`agent zones set`), or whose reach is not known"),
    ("session_protected_changes", "category", "this session already made a change whose zone_reach was not none"),
    ("session_shell_runs", "category", f"the shell commands this session already ran, none, few (below {session_state.SHELL_MANY}) or many"),
)

# The fields `compile_profile` projects a sandbox from, then the two the control and connection checks read.
REQUIRED: Tuple[Tuple[str, str], ...] = tuple(
    [(name, "since the sandbox profile is projected from it, and an allowed shell call is refused without one (cause 129)") for name in profile.REQUIRED_FIELDS]
    + [("path_control", "since without it no rule can refuse a change to a control file (cause 128)"),
       ("net_dest", "since without it no rule can refuse a connection (cause 130)")])


def values(name: str) -> Tuple[str, ...]:
    """The values a category field takes, as the agent's reading domain lists them; () for another kind."""
    return tuple(profile.KNOWN_CATEGORIES.get(name, ()))


def by_name() -> Dict[str, Tuple[str, str]]:
    return {name: (kind, meaning) for name, kind, meaning in FIELDS}
