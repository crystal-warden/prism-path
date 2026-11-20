---
name: agent_review
description: agent_default, except that every call that would change something inside the workspace asks the person
start: core_decision
field.classifier_version: int min=1 max=1
field.command_class: category
field.git_op: category
field.kill_by_pattern: bool
field.path_control: bool
field.path_glob: bool
field.path_in_toolchain: bool
field.path_scope: category
field.path_symlink: bool
field.path_traversal: bool
field.remote_class: category
field.tool: category
---
## core_decision
The review starter, `prismpath agent init --policy review`. Reads run, every change asks, and the hazards are refused as in the others.
The rules are read from the top. The first one that holds decides the call.
Compile with `prismpath policy compile agent_review.rules.md -o agent_review.core.json`.

A git operation or a path the classifier cannot read is refused before anything else is looked at.
-> refuse agent:unclassifiable: when git_op == "unknown" or path_scope == "unknown"

Calls that are never allowed, whatever else holds.
The agent's own controls (its settings, hook scripts and MCP configuration) are never changed by the agent. These refusals
are observations a later policy proposal may read; they never change the policy on their own.
-> refuse agent:kill-by-pattern: when kill_by_pattern
-> refuse agent:network: when command_class == "network" or git_op == "network"
-> refuse agent:control-write: when (tool in ["write_file", "delete_path"] or command_class == "mutating" or git_op in ["local_write", "mutating"]) and path_control
-> refuse agent:toolchain-write: when (tool in ["write_file", "delete_path"] or command_class == "mutating") and path_in_toolchain
-> refuse agent:glob-path: when (tool in ["write_file", "delete_path"] or command_class == "mutating") and path_glob
-> refuse agent:path-traversal: when (tool in ["write_file", "delete_path"] or command_class == "mutating") and path_traversal
-> refuse agent:symlink-path: when (tool in ["write_file", "delete_path"] or command_class == "mutating") and path_symlink
-> refuse agent:outside-workspace: when path_scope == "outside"
-> refuse agent:shell-mutation: when git_op == "mutating"

A tool or command the classifier cannot read waits for the person.
-> escalate agent:unreadable-asked: when tool == "unknown" or command_class == "unknown"

Every push waits for the person, whatever the remote.
-> escalate agent:push-escalated: when git_op == "push"

Every change inside the workspace waits for the person: a file written or deleted, a shell command that
changes files, and a local git change such as a commit. A path outside the workspace or one the
classifier cannot read was refused above, so these name no path scope.
-> escalate agent:change-asked: when tool in ["write_file", "delete_path"] or command_class == "mutating" or git_op == "local_write"

What runs without asking: reading and listing inside the workspace, read only commands, and git reads.
-> allow: when tool in ["list_dir", "read_file"] and path_scope == "workspace"
-> allow: when tool == "run_command" and command_class == "read_only" and path_scope in ["none", "workspace"]
-> allow: when git_op == "local_read" and path_scope in ["none", "workspace"]
