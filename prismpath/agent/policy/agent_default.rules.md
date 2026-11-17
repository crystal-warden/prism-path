---
name: agent_default
description: agent_rules, except that a call it cannot read or a shell command that changes files asks the person
start: core_decision
field.classifier_version: int min=1 max=1
field.command_class: category
field.git_op: category
field.kill_by_pattern: bool
field.path_glob: bool
field.path_in_toolchain: bool
field.path_scope: category
field.path_symlink: bool
field.path_traversal: bool
field.remote_class: category
field.tool: category
---
## core_decision
The default starter, what `prismpath agent init` records. A call it cannot read and a shell command that changes files inside the workspace ask the person.
The rules are read from the top. The first one that holds decides the call.
Compile with `prismpath policy compile agent_default.rules.md -o agent_default.core.json`.

A git operation or a path the classifier cannot read is refused before anything else is looked at.
-> refuse agent:unclassifiable: when git_op == "unknown" or path_scope == "unknown"

Calls that are never allowed, whatever else holds.
-> refuse agent:kill-by-pattern: when kill_by_pattern
-> refuse agent:network: when command_class == "network" or git_op == "network"
-> refuse agent:toolchain-write: when (tool in ["write_file", "delete_path"] or command_class == "mutating") and path_in_toolchain
-> refuse agent:glob-path: when (tool in ["write_file", "delete_path"] or command_class == "mutating") and path_glob
-> refuse agent:path-traversal: when (tool in ["write_file", "delete_path"] or command_class == "mutating") and path_traversal
-> refuse agent:symlink-path: when (tool in ["write_file", "delete_path"] or command_class == "mutating") and path_symlink
-> refuse agent:outside-workspace: when path_scope == "outside"
-> refuse agent:shell-mutation: when git_op == "mutating"

A shell command that changes files inside the workspace, or a tool or command the classifier cannot
read, waits for the person.
-> escalate agent:shell-mutation-asked: when command_class == "mutating"
-> escalate agent:unreadable-asked: when tool == "unknown" or command_class == "unknown"

A push runs only to a remote the owner allowed; any other push waits for the owner.
-> allow: when git_op == "push" and remote_class == "allowed"
-> escalate agent:push-escalated: when git_op == "push"

What runs: file tools and read only commands inside the workspace, and local git.
-> allow: when tool in ["list_dir", "read_file", "write_file", "delete_path"] and path_scope == "workspace"
-> allow: when tool == "run_command" and command_class == "read_only" and path_scope in ["none", "workspace"]
-> allow: when git_op in ["local_read", "local_write"] and path_scope in ["none", "workspace"]
