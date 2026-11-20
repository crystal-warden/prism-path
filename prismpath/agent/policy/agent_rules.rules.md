---
name: agent_rules
description: the owner's rules for a governed coding agent; a call no rule allows is refused
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
The strict starter, `prismpath agent init --policy strict`. A call it cannot read and a shell command that changes files are refused.
The rules are read from the top. The first one that holds decides the call.
Compile with `prismpath policy compile agent_rules.rules.md -o agent_rules.core.json`.

A call the classifier cannot read is refused before anything else is looked at.
-> refuse agent:unclassifiable: when tool == "unknown" or command_class == "unknown" or git_op == "unknown" or path_scope == "unknown"

Calls that are never allowed, whatever else holds.
The agent's own controls (its settings, hook scripts and MCP configuration) are never changed by the agent. These refusals
are observations a later policy proposal may read; they never change the policy on their own.
-> refuse agent:kill-by-pattern: when kill_by_pattern
-> refuse agent:network: when command_class == "network" or git_op == "network"
-> refuse agent:control-write: when (tool in ["write_file", "delete_path"] or command_class == "mutating" or git_op in ["local_write", "mutating"]) and path_control
-> refuse agent:toolchain-write: when tool in ["write_file", "delete_path"] and path_in_toolchain
-> refuse agent:glob-path: when tool in ["write_file", "delete_path"] and path_glob
-> refuse agent:path-traversal: when tool in ["write_file", "delete_path"] and path_traversal
-> refuse agent:symlink-path: when tool in ["write_file", "delete_path"] and path_symlink
-> refuse agent:outside-workspace: when path_scope == "outside"
-> refuse agent:shell-mutation: when command_class == "mutating" or git_op == "mutating"

A push runs only to a remote the owner allowed; any other push waits for the owner.
-> allow: when git_op == "push" and remote_class == "allowed"
-> escalate agent:push-escalated: when git_op == "push"

What runs: file tools and read only commands inside the workspace, and local git.
-> allow: when tool in ["list_dir", "read_file", "write_file", "delete_path"] and path_scope == "workspace"
-> allow: when tool == "run_command" and command_class == "read_only" and path_scope in ["none", "workspace"]
-> allow: when git_op in ["local_read", "local_write"] and path_scope in ["none", "workspace"]
