---
name: agent_session
description: agent_default, except that what the session already did can make a later call ask the person (changes after a protected change, read only shell commands past a budget)
start: core_decision
field.classifier_version: int min=2 max=2
field.command_class: category
field.git_op: category
field.kill_by_pattern: bool
field.net_dest: category
field.path_control: bool
field.path_glob: bool
field.path_in_toolchain: bool
field.path_scope: category
field.path_symlink: bool
field.path_traversal: bool
field.proc_class: category
field.remote_class: category
field.session_protected_changes: category
field.session_shell_runs: category
field.tool: category
field.zone_reach: category
---
## core_decision
The session starter, `prismpath agent init --policy session`. It is agent_default and two more questions that depend on what this session already did (`session_protected_changes` and `session_shell_runs`, read from the session's own receipts and never from anything the agent writes). A history that cannot be read counts as the most of both.
The rules are read from the top. The first one that holds decides the call.
Compile with `prismpath policy compile agent_session.rules.md -o agent_session.core.json`.

A git operation or a path the classifier cannot read is refused before anything else is looked at.
-> refuse agent:unclassifiable: when git_op == "unknown" or path_scope == "unknown"

Calls that are never allowed, whatever else holds.
The agent's own controls (its settings, hook scripts and MCP configuration) are never changed by the agent. These refusals
are observations a later policy proposal may read; they never change the policy on their own.
-> refuse agent:kill-by-pattern: when kill_by_pattern
-> refuse agent:network: when command_class == "network" or git_op == "network"
-> refuse agent:net-refused: when net_dest in ["allowed_host", "other", "unknown"] or (tool == "connect" and net_dest == "none")
-> refuse agent:control-write: when (tool in ["write_file", "delete_path"] or command_class == "mutating" or git_op in ["local_write", "mutating"]) and path_control
-> refuse agent:toolchain-write: when (tool in ["write_file", "delete_path"] or command_class == "mutating") and path_in_toolchain
-> refuse agent:glob-path: when (tool in ["write_file", "delete_path"] or command_class == "mutating") and path_glob
-> refuse agent:path-traversal: when (tool in ["write_file", "delete_path"] or command_class == "mutating") and path_traversal
-> refuse agent:symlink-path: when (tool in ["write_file", "delete_path"] or command_class == "mutating") and path_symlink
-> refuse agent:outside-workspace: when path_scope == "outside"
-> refuse agent:shell-mutation: when git_op == "mutating"

A change to code the owner protects waits for the person, and so does one whose reach is not known (no zone information
point answered, or the file is not one it can read). Only a change that reads `none` for every path it names goes on to the rules below.
-> escalate agent:zone-asked: when (tool in ["write_file", "delete_path"] or command_class == "mutating") and zone_reach in ["protected", "unknown"]

Once this session has changed code the owner protects (asked about it or let it through), a later change inside the workspace waits for the person, and so does a commit and a push to an allowed remote.
-> escalate agent:session-change-asked: when session_protected_changes == "some" and ((tool in ["write_file", "delete_path"] and path_scope == "workspace") or (git_op == "local_write" and path_scope in ["none", "workspace"]) or (git_op == "push" and remote_class == "allowed"))

A session that has already run many shell commands asks before the next one that would run without asking.
-> escalate agent:session-shell-asked: when session_shell_runs == "many" and tool == "run_command" and path_scope in ["none", "workspace"] and (command_class == "read_only" or git_op in ["local_read", "local_write"])

A shell command that changes files inside the workspace, or a tool or command the classifier cannot
read, waits for the person.
-> escalate agent:shell-mutation-asked: when command_class == "mutating"
-> escalate agent:unreadable-asked: when tool == "unknown" or command_class == "unknown"

A push runs only to a remote the owner allowed; any other push waits for the owner.
-> allow: when git_op == "push" and remote_class == "allowed"
-> escalate agent:push-escalated: when git_op == "push"

A connection the sandboxed agent asks its proxy to open runs only to the model's own API. Any other destination was refused above.
-> allow: when tool == "connect" and net_dest == "model_api"

What runs: file tools and read only commands inside the workspace, and local git.
-> allow: when tool in ["list_dir", "read_file", "write_file", "delete_path"] and path_scope == "workspace"
-> allow: when tool == "run_command" and command_class == "read_only" and path_scope in ["none", "workspace"]
-> allow: when git_op in ["local_read", "local_write"] and path_scope in ["none", "workspace"]
