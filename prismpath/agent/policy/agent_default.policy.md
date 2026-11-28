---
name: agent-default
description: the manifest of the default starter, which keeps today's defaults
policy.id: agent-default-1
policy.stream: agent-default
policy.seq: 1
policy.targets: agent
policy.rules: agent_default.rules.md
policy.rules_sha256: 5c0579c327e272b22a1cae556881ffc84414e9371380a6e8d9b08a98595d4ca4
policy.image: agent_default.core.json
policy.image_sha256: 89bf2fa786fb0b80041f539cd4cd46795b58fcd45ab2372c974f180c40c08c58
policy.widens: yes
policy.valid_days: 90
policy.allowed_remotes:
policy.max_processes: 64
policy.timeout_s: 30
policy.shell_many: 20
policy.toolchain_dirs: workspace:.toolchain | /usr | /opt | /etc | ~/.cargo | ~/.rustup | ~/.elan | ~/.local | ~/.npm | ~/.pyenv
policy.ro_mounts:
---
## manifest
This is the policy manifest of the default starter, `agent_default`. It names the rules source and the image it compiles to, each by path and sha256, and it keeps what a run does today: no extra egress hosts, no zones, a limit of 64 processes and 30 seconds for one call, a session reading `many` shell runs from 20, the toolchain directories the sandbox shows read only (`workspace:` is under the workspace and `~/` under the home), and no other read only mounts.

The keys are written once here, in this file. Sign it with `prismpath authorize sign agent_default.policy.md`, and check it with `prismpath policy manifest check agent_default.policy.md --pub <authority key>`. Change the rules source and the hashes above no longer hold until they are written again.

The one rule below exists only because a signed document must parse as a flow. It refuses.
-> refuse_135: always
