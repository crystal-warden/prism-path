---
name: agent-default
description: the manifest of the default starter
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
---
## manifest
This is the policy manifest of the default starter, `agent_default`. It names the rules source and the image it compiles to, each by path and sha256, and it names no egress hosts and no zones, so a release sealed from it reaches no extra host and declares no zone. It writes no process limit, call timeout, shell count, toolchain directory or read only mount: no artifact of a release holds those yet, so the sealing tool refuses them, and a run keeps the launcher's own values.

The keys are written once here, in this file. Sign it with `prismpath authorize sign agent_default.policy.md --version 1` (the version is `policy.seq`), and check it with `prismpath policy manifest check agent_default.policy.md --pub <authority key>`. Change the rules source and the hashes above no longer hold until they are written again.

The one rule below exists only because a signed document must parse as a flow. It refuses.
-> refuse_135: always
