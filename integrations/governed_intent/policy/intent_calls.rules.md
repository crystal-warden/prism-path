---
name: intent_calls
description: the intent layer's decision on a proposed call
start: core_decision
field.classifier_version: int min=3 max=3
field.command_class: category
field.git_op: category
field.harm_bp: fixed scale=10000 unit=cosine rounding=floor min=0 max=10000
field.intent_class: category
field.intent_margin_bp: int min=0 max=10000
field.intent_reader_version: int min=2 max=2
field.kill_by_pattern: bool
field.net_dest: category
field.path_control: bool
field.path_glob: bool
field.path_in_toolchain: bool
field.path_scope: category
field.path_symlink: bool
field.path_traversal: bool
field.probing_count: int min=0 max=1000
field.proc_class: category
field.remote_class: category
field.semantic_lock: category
field.semantic_status: category
field.tool: category
field.zone_reach: category
---
## core_decision
Written by `python -m integrations.governed_intent.policy` from the harness's floor and thresholds.json.
Edit those and run it again, not this file. The tests hold it to the image byte for byte.

-> refuse agent:unclassifiable: when tool == "unknown" or command_class == "unknown" or git_op == "unknown" or path_scope == "unknown"
-> refuse agent:kill-by-pattern: when kill_by_pattern
-> refuse agent:network: when command_class == "network" or git_op == "network"
-> refuse agent:net-refused: when net_dest in ["allowed_host", "other", "unknown"] or (tool == "connect" and net_dest == "none")
-> refuse agent:control-write: when (tool in ["write_file", "delete_path"] or command_class == "mutating" or git_op in ["local_write", "mutating"]) and path_control
-> refuse agent:toolchain-write: when tool in ["write_file", "delete_path"] and path_in_toolchain
-> refuse agent:glob-path: when tool in ["write_file", "delete_path"] and path_glob
-> refuse agent:path-traversal: when tool in ["write_file", "delete_path"] and path_traversal
-> refuse agent:symlink-path: when tool in ["write_file", "delete_path"] and path_symlink
-> refuse agent:outside-workspace: when path_scope == "outside"
-> refuse agent:shell-mutation: when command_class == "mutating" or git_op == "mutating"
-> refuse semantic:harm: when (semantic_status == "verified" and semantic_lock == "d9fa93f77b82bc08cb611f5faa4f0f810ef191ce4f3bdaf6c97325bc92355d23") and (not (tool in ["write_file", "delete_path"] and zone_reach in ["protected", "unknown"]) and ((git_op == "push" and remote_class == "allowed") or (git_op != "push" and ((tool == "connect" and net_dest == "model_api") or (tool in ["list_dir", "read_file", "write_file", "delete_path"] and path_scope == "workspace") or (tool == "run_command" and command_class == "read_only" and path_scope in ["none", "workspace"]) or (git_op in ["local_read", "local_write"] and path_scope in ["none", "workspace"]))))) and harm_bp >= 0.7300
-> escalate semantic:probing-episode: when (semantic_status == "verified" and semantic_lock == "d9fa93f77b82bc08cb611f5faa4f0f810ef191ce4f3bdaf6c97325bc92355d23") and (not (tool in ["write_file", "delete_path"] and zone_reach in ["protected", "unknown"]) and ((git_op == "push" and remote_class == "allowed") or (git_op != "push" and ((tool == "connect" and net_dest == "model_api") or (tool in ["list_dir", "read_file", "write_file", "delete_path"] and path_scope == "workspace") or (tool == "run_command" and command_class == "read_only" and path_scope in ["none", "workspace"]) or (git_op in ["local_read", "local_write"] and path_scope in ["none", "workspace"]))))) and probing_count >= 2
-> escalate semantic:intent-mismatch: when (semantic_status == "verified" and semantic_lock == "d9fa93f77b82bc08cb611f5faa4f0f810ef191ce4f3bdaf6c97325bc92355d23") and (not (tool in ["write_file", "delete_path"] and zone_reach in ["protected", "unknown"]) and ((git_op == "push" and remote_class == "allowed") or (git_op != "push" and ((tool == "connect" and net_dest == "model_api") or (tool in ["list_dir", "read_file", "write_file", "delete_path"] and path_scope == "workspace") or (tool == "run_command" and command_class == "read_only" and path_scope in ["none", "workspace"]) or (git_op in ["local_read", "local_write"] and path_scope in ["none", "workspace"]))))) and intent_margin_bp >= 400 and intent_class == "inspect" and (tool in ["write_file", "delete_path"] or git_op == "local_write")
-> escalate semantic:intent-mismatch: when (semantic_status == "verified" and semantic_lock == "d9fa93f77b82bc08cb611f5faa4f0f810ef191ce4f3bdaf6c97325bc92355d23") and (not (tool in ["write_file", "delete_path"] and zone_reach in ["protected", "unknown"]) and ((git_op == "push" and remote_class == "allowed") or (git_op != "push" and ((tool == "connect" and net_dest == "model_api") or (tool in ["list_dir", "read_file", "write_file", "delete_path"] and path_scope == "workspace") or (tool == "run_command" and command_class == "read_only" and path_scope in ["none", "workspace"]) or (git_op in ["local_read", "local_write"] and path_scope in ["none", "workspace"]))))) and intent_margin_bp >= 400 and not intent_class in ["vcs-publish", "network", "unknown"] and git_op in ["push", "network"]
-> escalate semantic:intent-mismatch: when (semantic_status == "verified" and semantic_lock == "d9fa93f77b82bc08cb611f5faa4f0f810ef191ce4f3bdaf6c97325bc92355d23") and (not (tool in ["write_file", "delete_path"] and zone_reach in ["protected", "unknown"]) and ((git_op == "push" and remote_class == "allowed") or (git_op != "push" and ((tool == "connect" and net_dest == "model_api") or (tool in ["list_dir", "read_file", "write_file", "delete_path"] and path_scope == "workspace") or (tool == "run_command" and command_class == "read_only" and path_scope in ["none", "workspace"]) or (git_op in ["local_read", "local_write"] and path_scope in ["none", "workspace"]))))) and intent_margin_bp >= 400 and not intent_class in ["toolchain-change", "unknown"] and path_in_toolchain
-> escalate agent:zone-asked: when tool in ["write_file", "delete_path"] and zone_reach in ["protected", "unknown"]
-> allow: when git_op == "push" and remote_class == "allowed"
-> escalate agent:push-escalated: when git_op == "push"
-> allow: when tool == "connect" and net_dest == "model_api"
-> allow: when tool in ["list_dir", "read_file", "write_file", "delete_path"] and path_scope == "workspace"
-> allow: when tool == "run_command" and command_class == "read_only" and path_scope in ["none", "workspace"]
-> allow: when git_op in ["local_read", "local_write"] and path_scope in ["none", "workspace"]
