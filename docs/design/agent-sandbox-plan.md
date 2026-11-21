# The whole agent under the sandbox

*A plan, not an implementation. Written 2026-11-20 against research main 2c9c31f. It follows the owner decisions of 2026-11-19 in `docs/design/enforcement-points-plan.md` section 6 and the tracer results in `docs/design/sandbox-tracer-results.md`. Linux only. Nothing here is built unless a path says it is. Claims about Claude Code come from its documentation, cited by URL, and from the binary installed on the build host (2.1.326). Anything not checked is marked unverified, and the spike (WP1) exists to check it.*

## 0. What this is for

The tracer confines the children of an allowed Bash call. It does not confine Claude Code. Claude's own Read, Write and Edit run in its process and are advisory (`sandbox-tracer-results.md`, "What it does not guarantee"). Claude Code's own sandbox has the same limit by design. Its documentation says the sandbox "wraps shell commands" and that the built-in file and web tools, command hooks, and local MCP servers run outside it (https://code.claude.com/docs/en/sandboxing.md).

The owner decided the whole agent runs under the sandbox next (decision 2), through a launcher, with the model's API as an allowlist entry. This plan says how, what it guarantees, and in what order to build it. The one-line shape:

```
prismpath agent run -- claude
  launcher (outside, trusted)          sandbox (bwrap, untrusted)
  ├─ decider: keys, journal, policy    ├─ claude (native binary)
  ├─ egress proxy on a unix socket  ◄──┼─ socat 127.0.0.1:PORT ⇄ socket
  ├─ pty relay                      ◄──┼─ controlling terminal
  └─ staged config directory (ro)  ──► └─ hook client, Bash children
```

The principle from `~/cwprojects/cc-gate-tracer/NORTH-STAR.md` holds throughout. Anything the sandbox stops is an observation with a receipt. It never changes what the policy permits. Only a signed image does that.

## 1. What running Claude Code under bwrap needs

### 1.1 The binary

On this host `~/.local/bin/claude` is a symlink to `~/.local/share/claude/versions/2.1.326`, a 370 MB native aarch64 ELF. `ldd` shows only libc, libm, libdl, libpthread, librt and the loader. There is no separate Node runtime to expose for a native install. An npm install of Claude Code would also need a Node binary and its modules. The network page says npm installs need Node 22.15 or later to read the OS certificate store (https://code.claude.com/docs/en/network-config.md). The first build supports the native install only. This is a choice, and the spike checks it.

Mounts for the binary. The existing profile mounts `/usr` read only and symlinks `/bin`, `/lib`, `/lib64` (`bwrap_argv` in `prismpath/agent/sandbox_exec.py`). That covers libc and the loader here. The binary itself lives under `$HOME`, so the launcher resolves the symlink and binds only the one version file, read only, at a fixed path such as `/opt/claude/claude`. Not `~/.local`, and not the versions directory, so the agent cannot read other versions or the installer state.

Self-update must be off. The installed native binary updates itself and reaches `downloads.claude.ai` for that (network page, table). In the sandbox the binary is read only, so an update could not land. The launcher sets `DISABLE_AUTOUPDATER` (the name is from memory and unverified against the env var page, which was only partly read) and `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`. The second is documented to cover auto-updates, telemetry, error reporting and feature flag fetching (https://code.claude.com/docs/en/env-vars.md). The cost is that feature flags are not fetched. Whether the agent still runs normally without them is a spike measurement.

### 1.2 Config and credentials

Claude Code reads `~/.claude/settings.json`, writes `~/.claude.json` for itself (account, MCP servers, per project trust state), and `CLAUDE_CONFIG_DIR` moves the `.claude` folder (https://code.claude.com/docs/en/settings.md). On this host `~/.claude/.credentials.json` exists, mode 0600. `~/.claude.json` is 169 KB and holds an account id, cached feature flags and per project history. Whether `~/.claude.json` moves into `CLAUDE_CONFIG_DIR` when that is set is unverified.

Do not bind the owner's `~/.claude` or `~/.claude.json`. Instead the launcher builds a per run staged directory and sets `CLAUDE_CONFIG_DIR` to it, with `HOME` set to a private tmpfs:

| Item | In the sandbox | Why |
|---|---|---|
| `settings.json` | written by the launcher, bound read only | holds the hook entry and the permission floor. The agent cannot edit it. |
| credentials | a copy of only the one credential the run needs, writable only if token refresh must persist | the owner's other state (history, MCP servers, other accounts) stays out |
| `.claude.json` | a minimal generated file, trust pre-accepted for the workspace, discarded at exit | no per project history leaks in, and nothing the agent writes outlives the run |
| sessions, debug, cache | a writable tmpfs inside the staged directory | Claude writes transcripts and caches there |
| owner's `settings.local.json`, plugins, skills, `CLAUDE.md` | not present | each is a way to widen or redirect the agent. A later work package can add chosen ones read only. |

The hook entry is passed so the settings cannot be overridden from below. `--settings` sits above project and user settings and below managed settings (https://code.claude.com/docs/en/settings.md, "Settings precedence"). A managed settings file would sit above even that. Its system path is on the managed settings page (https://code.claude.com/docs/en/managed-settings.md) and was not read here. The spike should check whether a managed file bound read only into the sandbox is the stronger way to place the hook.

Never let the sandboxed agent write its own hook settings. Three layers, so that no one of them is relied on:

1. Cause 128 refuses a hook decided change to a control file (`path_control` in `prismpath/agent/classifier.py`). That covers Bash and the file tools when the hook decides them.
2. The staged `settings.json` is a read only bind, so the write fails even if the hook were bypassed.
3. In the workspace, the control paths are bound read only on top of the writable workspace, the way `bwrap_argv` already binds `.toolchain`. The list is the classifier's own control set (`.claude/`, `.mcp.json`, `.git/config`, `.git/hooks/`, `CLAUDE.md`; see `CONTROL_TREES`, `CONTROL_FILES`, `CONTROL_NAMES` in `classifier.py`). A path in that set that does not exist yet cannot be bound, so the launcher creates empty ones first, or the mount list is a refusal when one is missing. Without this, the agent can create `.claude/settings.local.json` in the workspace. A project local file can add allow rules and hooks (settings page, "Project local settings"). A hook `deny` still wins over those, but the agent should not be editing its own permissions at all.

A consequence to state plainly. Claude Code writes `.claude/settings.local.json` itself when a person picks "Yes, and don't ask again" (settings page). Under the sandbox that write fails. The person's choice then does not persist. That is a refusal and a receipt, consistent with decision 4, and the launcher's help text should say so.

### 1.3 The workspace

The workspace is the one read write path, as in the tracer (`Profile.rw_path`). Mounted at its own real path, not at `/workspace`, so transcript paths and `git` behave. The profile's `host_write` and read only host root (for an image that allows outside reads) are not used for the agent profile in the first build. The agent sees `/usr`, its staged config, the pinned binary, the workspace and a tmpfs `/tmp`. If a pack or tool needs more, the image must allow it and the compile must grant it.

### 1.4 A terminal

Interactive `claude` needs a terminal. `bwrap_argv` passes `--new-session`, which calls `setsid` and so removes the controlling terminal. That is right for the tracer (it blocks `TIOCSTI` injection into the person's terminal) and wrong for a program that wants job control, `SIGINT` from the keyboard and `SIGWINCH` on resize. Whether Claude Code works without a controlling terminal is unverified. Raw mode on an inherited pty slave probably handles typed input, but resize signals reach only the foreground process group of the controlling terminal.

Recommended: the launcher allocates its own pty pair (Python `pty.openpty`), starts the sandbox with the slave as stdin, stdout and stderr and a new session, makes the slave the sandbox's controlling terminal, and relays bytes between the master and the person's real terminal. It forwards `SIGWINCH` by copying the window size with `TIOCSWINSZ`. The person's terminal is then never an fd inside the sandbox, so `TIOCSTI` has nothing to inject into. `bwrap --dev /dev` supplies a private devpts. Non-interactive use (`claude -p`) needs no pty and is the spike's first target.

### 1.5 The network

Only the model API hosts. The documented list for Claude Code is a table of 18 hosts (https://code.claude.com/docs/en/network-config.md, "Network access requirements"). Almost all are optional for a headless coding session. What a run needs:

| Host | Needed for | In the first allowlist |
|---|---|---|
| `api.anthropic.com` | Claude API requests, feature flags, telemetry events, the WebFetch domain safety check | yes |
| `platform.claude.com` | OAuth token exchange, refresh and revocation for claude.ai accounts | yes, only when the credential is OAuth. Unneeded with an `ANTHROPIC_API_KEY`. |
| `claude.ai`, `claude.com`, `sso.claude.com` | interactive sign-in in a browser | no. The person signs in outside, before the launcher runs. |
| `mcp-proxy.anthropic.com` | claude.ai MCP connectors | no. Switch off with `ENABLE_CLAUDEAI_MCP_SERVERS=false` (named on that page). |
| `downloads.claude.ai`, `storage.googleapis.com`, `registry.npmjs.org`, `github.com`, `raw.githubusercontent.com` | updates, plugins, marketplaces, release notes | no. Plugins are not loaded in the first build. |
| `http-intake.logs.us5.datadoghq.com`, `browser-intake-us5-datadoghq.com` | operational telemetry and error reports | no. `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` covers both (same page). |
| `bridge.claudeusercontent.com`, `*.frame.claudeusercontent.com`, `*-review.googlesource.com`, `formulae.brew.sh`, `code.claude.com` | Chrome bridge, artifacts, Gerrit lookup, brew, docs lookups | no |

The page says Claude Code does not support SOCKS proxies and honours `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`, trying `https_proxy`, `HTTPS_PROXY`, `http_proxy`, `HTTP_PROXY` in that order. It validates the proxy URL at startup and wants a full URL with `http://`. These are the same page's statements. They are what the proxy design below relies on. The spike must confirm that the model API traffic really goes through the proxy and that nothing important is skipped. Claude Code's own WebSocket and OTLP paths are possible exceptions, unverified. WebFetch and WebSearch will be refused by the allowlist, because they fetch arbitrary hosts from inside the sandbox. Claude's own sandbox leaves them outside its boundary (sandboxing page), so here the whole-agent sandbox is stricter, and the agent loses those tools until the policy allows a destination class for them.

## 2. Network egress from inside bwrap without root

The profile already has no network by default (`--unshare-all`). The question is how to let one thing through.

### 2.1 Options

**A. A socket only proxy (recommended for the first build).** The launcher runs an HTTP `CONNECT` proxy on a unix socket outside the sandbox. The sandbox has its own network namespace with only a loopback interface. The socket is bound into the sandbox at a fixed path. A small relay inside (`socat TCP-LISTEN:PORT,bind=127.0.0.1,fork UNIX-CONNECT:/run/prismpath/egress.sock`) listens on loopback and forwards to the socket. `HTTPS_PROXY=http://127.0.0.1:PORT` is set. This is the construction Claude Code's own sandbox uses on Linux: bubblewrap for filesystem isolation, `socat` as the relay to a proxy on the host, a separate network namespace with no connection to the host network, and the proxy checking each connection's hostname against `allowedDomains` (sandboxing page). It needs only `bwrap` and `socat`. `socat` is installed on the build host and `/usr/bin/socat` is under the bound `/usr`. A pure Python relay inside is a drop in replacement if `socat` must not be a dependency.

What it guarantees. A process in the sandbox has no network interface except `lo`, so a process that ignores `HTTPS_PROXY` (raw sockets, `ssh`, a database driver, a Go or Rust program that does its own dialing) gets no route at all, not even to an allowed host. It can reach only the relay on loopback, and the relay reaches only the proxy. The proxy decides per `CONNECT` by hostname and port, resolves the name itself, and refuses names that resolve to loopback, link local or private addresses (Claude's sandbox page describes the same rule for local addresses). There is no DNS inside the sandbox, so DNS cannot be a side channel. UDP, QUIC and ICMP cannot leave. The proxy does not terminate TLS in the first build, so it sees the host name and port and nothing else.

What it does not guarantee. A model API host accepts any valid API key, so a compromised agent could send workspace data to the allowed host under a different account. The allowlist limits where, not what. The agent can also reach anything its own loopback port reaches. If the proxy code has a flaw, the sandbox's only door is flawed, so the proxy is small, stdlib only and fuzzed in WP2. Abstract unix sockets are per network namespace, so `--unshare-all` isolates them. Pathname sockets reach the sandbox only if bound in.

**B. `slirp4netns` or `pasta` (rootless user mode networking).** These give the sandbox a real routed interface and NAT it out through a userspace stack. Egress would then be limited by firewall rules in the sandbox's namespace (nftables needs privileges inside the user namespace, and rules the agent can see are rules a process with capabilities could change, though capabilities are dropped). The agent gets a route, so a process that ignores `HTTPS_PROXY` can connect to anything the rules permit. Neither tool is installed on the build host (`which` found only `socat`). It adds a dependency and removes the "no route at all" property. Not recommended.

**C. The XDP edge in `integrations/governed_net`.** That program decides UDP datagrams to one tool server address at a host NIC, from a signed table, and drops everything else for that match only (`integrations/governed_net/README.md`). It sees packets, not processes, so it cannot tell the agent from anything else on the host, and it needs root and a LAN NIC the owner provisions. It is the right tool for the edge between hosts (`enforcement-points-plan.md` section 2). It is not the first tool for one process tree on a developer machine. It stays as the host layer, behind the owner's LAN edge, and the two decide the same destination classes from the same image when section 3 lands. The owner's decision 1 ties the new policy fields to the XDP compile, so the XDP compile is where `net_dest` is first used on the wire.

**Recommendation.** A for the first build. It is rootless, uses what is installed, matches a design that is already documented as working in Claude Code's own sandbox, and gives the strongest property (no route), at the cost of one trusted proxy process.

### 2.2 The proxy reads the policy (was an interim allowlist)

The first build of the proxy carried a constant allowlist, a permission outside the signed image. WP7 removed it. The proxy has no list of its own: the launcher passes it a gate (`prismpath/agent/egress_policy.py`) that reads each `CONNECT` target as written into a `connect` reading with the classifier (`Config.allowed_hosts` from `--allow-host`), decides it with the reference kernel under the active attested image, and appends a receipt to a run of its own (`egress-<time>-<pid>`, sealed at exit) with the agent profile's hash on the journal line. A refusal is cause 130, an escalation is a refusal at the proxy (nobody is there to answer), and a receipt that cannot be written is a refusal. With no gate and no decider the proxy refuses everything. `compile_profile(image, "agent")` derives the net state from the same image, and `prismpath/tests/test_egress_policy.py` holds both to the Lean oracle over the connect readings.

### 2.3 Optional hardening, later

Credential injection. Claude Code can send API requests to another base URL (`ANTHROPIC_BASE_URL`, named on the network page and in the gateways docs). The proxy could be that base URL on plain HTTP inside the sandbox, hold the real API key outside, add the header, and open TLS to the API itself. The sandbox would never hold the key. That works for an API key. Whether it works for subscription OAuth is unverified. It is open question 1.

## 3. The new reading fields

### 3.1 What exists, and the precedent

A reading is a flat object of classifier fields (`prismpath/agent/classifier.py`). Every field has a finite domain, declared in the signed image: `bool`, a bounded `int`, or a `category` of strings. `compile_profile` walks the cross product of the domains of fields the rules read and decides each reading with the reference kernel (`prismpath/agent/profile.py`, `needs`). A field domain of 64 or more int values, or a category the classifier does not produce, is a `ProfileError`. The Lean side defines the same enumerations (`formal/Classifier/Control.lean`: `allTools`, `allScopes`, `allCmds`, `allGitOps`, `allRemotes` with membership lemmas) and a computed safety check over the finite reading space (`controlSafe`, `control_refused`). `remote_class` (`none | allowed | other`) is the precedent for "a class of destination decided by the owner's configuration". New fields follow it.

### 3.2 The fields

Two categories, one new tool value. Domains stay finite and small.

| Field | Domain | Meaning |
|---|---|---|
| `tool` gains `connect` | existing values plus `connect` | a connection the sandboxed agent asks the proxy to open. A new value, so the tool domain is `list_dir, read_file, write_file, delete_path, run_command, git, connect, unknown`. |
| `net_dest` | `none \| model_api \| allowed_host \| other \| unknown` | the class of the host and port a `connect` names. `none` for every other tool. |
| `proc_class` | `none \| single \| tree \| unknown` | what a `run_command` needs of the process table. `single` is one program. `tree` is a build or test runner that forks workers (`make`, `pytest -n`, a package manager). `unknown` is anything the classifier cannot read. |

`classifier_version` goes from 1 to 2. The image already bounds that field, so a reading from the old classifier is refused at the boundary (`classifier.py` header). Existing readings gain `net_dest = none` and `proc_class` set from the command, so every existing rule keeps its meaning. The default rules stay as they are for `command_class` and `git_op`.

Where the classes come from, since a hostname cannot be classified by text alone.

- `model_api` is a constant list in the classifier, version controlled, and defined in Lean with the rest of the syntactic half (`docs/design/spec-verified-classifier.md`). Today that is `api.anthropic.com` and `platform.claude.com`. A change to it is a classifier version bump, so it is signed, not configured.
- `allowed_host` comes from the owner's configured remotes list, the way `remote_class == "allowed"` does today (`classify(..., remotes=...)` and `Config` in `classifier.py`). The list is part of the config that the run records.
- `other` is every other well formed host. `unknown` is a host the classifier cannot read (an IP literal in an odd form, a host with a trailing dot or mixed case it does not normalise, a port outside 1 to 65535). It is refused first, as `path_scope == "unknown"` is today.

Why not a single `network: bool`. The profile today has a `network` bool and compile sets it when any allowed reading has `command_class == "network"` or `git_op == "network"` (`profile.py`, `_gives`). That is a tool wide switch. The agent profile needs "the model API only", which is a different thing from "a network" for a build. Three network states then follow from the allow set:

| `Profile.net` | Meaning | Set when some allowed reading has |
|---|---|---|
| `none` | no network namespace access, no socket | no `connect` and no network command |
| `proxy_model` | proxy with the `model_api` class only | `tool == connect` and `net_dest == model_api` |
| `proxy_allow` | proxy with `model_api` and `allowed_host` | also `net_dest == allowed_host` |

`other` and `unknown` never give a state. The `network: bool` field stays for compatibility with `sandbox_hook.py` and maps to `proxy_allow` for a Bash call whose image really allows a network command, until WP8.

The process limit. Today `max_processes` is a constant (64) and `timeout_s` is 30 (`profile.py`, top). `proc_class` makes it a reading: compile takes the largest class some allowed reading has (`single` gives the small limit, `tree` the larger, `unknown` is refused like any unreadable call unless a rule allows it). The class to number table is a constant in `profile.py`, `single: 16, tree: 256`, to be set from the spike's measurements. One trap, to be measured. Linux `RLIMIT_NPROC` counts threads, not only processes, and a native Node style runtime runs many. The agent profile's limit is not the Bash profile's limit. The agent role gets its own number, found in WP1.

### 3.3 The compile

`compile_profile(image, role)` gains a role, `bash` (today's behaviour) or `agent` (the whole agent process tree). For `agent`, the allow set is walked the same way and the result adds `net`, `max_processes` from `proc_class`, and the fixed mounts of section 1 (binary, staged config, workspace, control paths read only). The projection stays a pure function of the image, so the same image twice gives the same bytes (`prismpath.profile/1`, canon/2). The format version goes to `prismpath.profile/2` since the object gains fields. The profile hash is still on the journal line and the receipt format is unchanged, as in the tracer. The tracer results list that as a known gap (profile not in the signed root). This plan does not close it. It is a separate decision, and open question 7 asks.

Fail closed as today. An image missing `net_dest` or `proc_class` cannot be projected, so `compile_profile` raises `ProfileError` and the launcher refuses to start. The old default image is re-signed with the new fields in WP6, so `prismpath agent init` still works.

### 3.4 What the Lean model and proofs need

The core decision procedure (`formal/Core/`) is generic over field definitions, so a new category field and a new tool value need no change to the core theorems. What changes is the classifier model and the checks over it.

1. `formal/Classifier/Basic.lean` and `Control.lean`: add `Tool.connect`, `NetDest` (five constructors) and `ProcClass` (four), with `allNetDests`, `allProcClasses` and their `_mem` lemmas, as for `allRemotes`.
2. The syntactic half: the host normaliser and the `model_api` table, and the `proc_class` rule for a command. Both are text functions, so they are in the part proved and held by `formal/diff/classifier_diff.py`.
3. A computed check in the style of `controlSafe`. `netSafe p` over the finite reading space says every reading with `net_dest = other` or `unknown` is refused (or escalated, if the owner prefers) under policy `p`. A theorem `connect_other_refused` says a `connect` whose host is not in `model_api` or the configured list cannot reach `allow` under a policy with `netSafe`. This is the sentence the owner asked for, that the proof covers the network.
4. What is not proved. `compile_profile` itself is Python. It is held by the differential test of WP4 in the tracer (`prismpath/tests/test_profile_differential.py`) and by a new one in WP7 that checks the compiled `net` against the oracle for every reading. Nothing here proves bwrap or the proxy. The Lean proof covers the decision, the compile is tested, the enforcement is measured. The plan keeps those three claims apart.
5. Cause codes. A refused `connect` gets a new registered cause, appended after 129 and never renumbered (`docs/design/spec-cause-codes.md`). The refusal reason names the destination class, not the host, so a receipt does not carry a full URL by accident. Whether it carries the host as well is open question 8.

The "arriving with the XDP compile" wording of decision 1 is kept. WP6 and WP7 land the fields in the classifier, Lean and the profile. The XDP compile then reads the same `net_dest` classes, so it is a consumer and not the first user.

## 4. The hook and the outer sandbox

Two deciders now cover the same agent, at different layers. The enforcement plan's rule is "the stricter answer, recorded" (section 2, "Disagreement"). Here is how that applies.

**What the hook still does.** It sees each tool call before it is a syscall, so it is the only point that knows intent, can escalate to a person, and writes one receipt per call. It decides Bash, Read, Write, Edit, MCP calls, and everything else the matcher lists. For an allowed Bash call it still rewrites the command to run in the per call sandbox (`updatedInput`, `docs/design/hook-rewrite-note.md`).

**What the outer sandbox does.** It bounds everything the agent process does whether or not a hook fired: its own file tools, any tool the matcher misses, a child that a tool's own code starts, the model API client. For Read, Write and Edit it turns "advisory" into a mount view. A path outside the mounts does not exist. A write outside the workspace fails. A write to a control path fails.

**Where the hook runs.** The hook is a process Claude Code starts, so under the launcher it runs inside the sandbox. It must not hold the authority key or the journal there, because the agent could read or edit them. The hook becomes a thin client. It sends the hook JSON over a second unix socket to a decider in the launcher, outside the sandbox, which holds the keys, the policy, the run directory and `RunStore`, classifies (the disk facts are read on the host, against the real workspace), decides, appends the receipt and returns the answer. The hook client fails closed: no socket or a bad reply is a deny with `agent:hook-error`, as today (`governed-agent-plan.md`, section 1). `prismpath/agent/commands.py` already holds the decision path, so the decider is that code behind a socket instead of behind stdin. This is a change of where code runs and not of what it decides. The spike should confirm the Python the hook client needs is small enough to bind, or use a one file client with no imports beyond the standard library.

**Per call sandbox inside the outer one.** The tracer runs `bwrap` for each allowed Bash command. Inside the outer sandbox that is a nested bwrap. Unprivileged nested user namespaces usually work, but they depend on the host (`user.max_user_namespaces`, and on Ubuntu the AppArmor restriction, which Claude Code's own docs call out: https://code.claude.com/docs/en/sandboxing.md). Claude's docs also say nested user namespaces "weaken the boundary" when enabled as an option there, so the spike checks what is needed and what is exposed. The nested sandbox matters. Bash children of an allowed command then see `/usr` and the workspace only, not the staged credentials, which the outer sandbox has to expose to Claude itself. Without nesting, every Bash child can read the model credential. If nesting does not work on a host, the recommended behaviour is fail closed. The hook denies Bash on that host with a registered cause, rather than running it with the weaker view. That is open question 4.

**When the two disagree.** Each case, and who wins:

| Hook says | Sandbox does | Result | Record |
|---|---|---|---|
| deny | not reached | the call never runs | the hook's refusal receipt, as today |
| ask, person says no | not reached | the call never runs | the hook's escalate receipt (the person's answer is Claude Code's own record, `governed-agent-plan.md`) |
| allow | allows | runs | receipt |
| allow | blocks (path not mounted, write refused, no route, fork limit) | the call fails | an observation bound to that receipt, with the image hash, profile hash, and what was seen (`observe.py`). Method is `stderr-pattern` for Bash and `post-tool-error` for file tools (below), both with the same stated blind spots. |
| allow with a *wider* mount than the oracle would give | blocks nothing | **a defect and a failing test** | the differential in WP8 must never see this |

For Claude's own file tools there is no command to read stderr from. Claude Code has a `PostToolUse` hook (https://code.claude.com/docs/en/hooks), and its input probably carries the tool result and an error flag. That is unverified here, so the first step in WP8 is to read that page and, if it works, record a failed Read, Write or Edit after an allow as an observation, with the same receipt index. If it does not, the observation for file tools is omitted and the plan says so, rather than inferring it from a later retry.

**Status after WP8.** The nested sandbox is built. The launcher binds the `prismpath` package read only at `/opt/pp` and, before it starts the agent, runs the real runner once nested inside the same outer sandbox (`launcher.probe_nested`). The decider then rewrites an allowed or approved Bash call to `/usr/bin/python3 -I /opt/pp/prismpath/agent/sandbox_exec.py ...` with the bash role profile, and the receipt carries that profile's hash. The runner has no run directory, so it reports what the command showed to the decider over the decider's socket (`observe.send`), and the decider binds it to the receipt as outside. Where the probe fails the decider denies every shell command with cause 129, and so does a profile that asks for a view of the host, because inside `/` is the outer sandbox's own root with the credential in it. The outer profile alone is never used. `tests/test_agent_nested.py` holds the table above as a test. Two results from it. A Read of `~/.ssh/config` is a question for the person (the classifier does not expand `~`), and under the outer sandbox the agent's home is a tmpfs without it. A Read of the staged credential is denied by the hook and not by the outer sandbox, which is the known gap, asserted by `KNOWN_GAP_CREDENTIAL_READ`.

**Status after the Landlock backend.** Where nesting is forbidden (Ubuntu 24.04's AppArmor setting, which GitHub's runners carry) the per call sandbox no longer has to be refused. `launcher.probe_nested` now tries the per call backends in the owner's order, bubblewrap and then Landlock (`launcher.BACKENDS`), by running the real runner once with each (`--backend`), and the first that works is what the decider is told (`Nested.backend`). Every receipt's journal line records it (`sandbox: {profile_sha256, backend}`, and a line without a backend is a bubblewrap one), the rewrite passes it to the runner, which holds to it and never substitutes another, and the observation carries the backend that ran and is refused when it is not the receipt's. Only a host where neither works denies shell commands with cause 129.

The Landlock backend (`prismpath/agent/landlock.py`, `sandbox_exec.run_landlock`, standard library `ctypes` on the Landlock syscalls, ABI detected at run time) applies the bash role profile to the child before it execs `bash -c`:

- Files: read and execute under the profile's read only mounts, read write under the workspace, one private scratch directory for `TMPDIR` and `HOME` (removed after the call), five harmless devices and a few global `/proc` files. Nothing else, so the credential, the agent's home, the staged sockets and `/tmp` are out of reach. What the outer sandbox mounted read only over the workspace stays read only, because a mount flag is below Landlock. A `.toolchain` that is not a read only mount cannot be made read only inside a writable directory by Landlock, so the backend refuses to run then. A profile with a network or a proxy is refused too.
- Network, ABI 4 and later: Landlock handles TCP bind and connect and the child gets no port. Before ABI 4 nothing in Landlock stops a connect to the outer sandbox's relay on 127.0.0.1:3128, which forwards to the egress proxy. The choice made is a small seccomp filter that refuses `socket()` on every ABI (`socketpair` stays). That also closes what Landlock before ABI 9 cannot, a connect to a unix socket by path (the proxy's and the decider's both sit in the outer `/tmp`), and UDP and `io_uring`. The child's environment carries no proxy variable. The filter also refuses `ptrace`, `process_vm_readv`, `process_vm_writev` and the System V IPC calls, because the child shares the outer sandbox's processes and IPC namespace, and kills a call made through another architecture's table or the x32 range. x86_64 and aarch64 only.
- Processes: `RLIMIT_NPROC` set to the user's tasks in the outer sandbox now plus `max_processes`, since without a user namespace the count is every task of the user there, not the call's. A fork past it fails with EAGAIN. The runner is a subreaper and ends the command's process group and whatever it orphaned when the command ends or times out, as the end of bubblewrap's PID namespace does.
- Signals: from ABI 6 the child cannot signal a process outside its Landlock domain. Before that it can signal another process of the same user in the outer sandbox, the agent among them. Bubblewrap does not have that gap. It is left open and reported by `landlock.describe()`. The Landlock ABI on a host is `python -c "from prismpath.agent import landlock; print(landlock.abi_version())"`.
- Differences that are stricter, never wider: no `/proc/<pid>` (a Landlock rule is bound to one pid, and the outer `/proc` lists the agent), no `/tmp`, no loopback server inside the call.

`tests/test_landlock_backend.py` runs one set of adversary cases (a decoy outside the workspace, a write outside, the fake credential, a TCP connect and a unix socket connect) under each backend and asserts they stop the same set, runs each layer alone, and runs the nested launcher path with the bubblewrap probe forced off. `PRISMPATH_REQUIRE_LANDLOCK=1` makes a missing Landlock a failure, and CI sets it and fails if one of those tests is skipped.

**PostToolUse observation for file tools: not built.** The hooks reference gives `PostToolUseFailure` an `error` string, `tool_name`, `tool_input` and `tool_use_id`, and says the error format depends on the tool. It does not fire for permission denials. That is not enough yet. The receipt does not store `tool_use_id`, so a failure cannot be bound to a receipt without changing the journal line, and `Run.observe` binds to a profile hash that a file tool's receipt does not have. The error texts of Read, Write and Edit are not specified, so a pattern would be a guess that cannot be checked without a real Claude run. If it is built later, it needs the `tool_use_id` on the journal line first.

Observations feed knowledge only. Nothing here lets an observation widen a mount, a host or a limit. A cluster of refused `connect` attempts to one host can become a proposal for a rule, which needs the signed envelope of `enforcement-points-plan.md` section 3 before it changes anything.

## 5. Work packages

Each is about 30 to 40 minutes of agent work. Linux only. Gate before each commit: `prismpath/tests` and `integrations/governed_harness/tests` with `PRISMPATH_REQUIRE_CORE_ORACLE=1`, as in `sandbox-tracer-results.md`. Order is WP1 to WP10. WP2 and WP3 can run side by side once WP1 is in.

**WP1 Spike. Claude Code starts and answers one prompt inside bwrap with only the model API reachable.** No repository code, only a script and a results note (`docs/design/agent-sandbox-spike.md`). Build the sandbox by hand: `--unshare-all`, `/usr`, the pinned binary, a staged config directory, a tmpfs, a unix socket relay to a throwaway CONNECT proxy outside (stdlib Python, hostname allowlist, logs every attempt), `HTTPS_PROXY` set, environment cleared. Run `claude -p "say ok"` with an API key, then with the OAuth credential. Done when, measured and written down:

- it answers, and the exit status and wall time are recorded, with and without the sandbox;
- the proxy log lists every host Claude Code contacted in the run, so the real list replaces the documented one;
- a direct `curl`, a raw socket and a DNS lookup from inside the sandbox all fail with no route;
- the peak thread and process count, so `max_processes` for the agent role has a basis;
- which files it wrote under the config directory, whether `.claude.json` follows `CLAUDE_CONFIG_DIR`, and whether credentials were refreshed and written;
- whether it works with `--new-session` and no controlling terminal, and the failure if not (decides the pty relay);
- whether a nested `bwrap` works inside it (decides question 4);
- the result with `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` and `ENABLE_CLAUDEAI_MCP_SERVERS=false`, and what, if anything, stops working.

If it does not answer, the note says where it stopped and the plan is revised before anything else is built. Nothing later starts until this is merged.

**WP2 The egress proxy.** `prismpath/agent/egress.py`: an HTTP CONNECT proxy on a unix socket, stdlib only, with a destination decider function passed in. Resolves the name itself, refuses loopback, link local and private results, refuses non CONNECT methods and ports other than 443 unless listed, caps header size and concurrent connections, times out idle tunnels, and returns 403 with a short reason. Interim allowlist is the constant of section 2.2. Done when tests pass for an allowed host (a local TLS echo standing in through a hosts override), a refused host, a name that resolves to `127.0.0.1`, an oversized header, a slow client, and a malformed request line, and the process never writes outside its socket and log.

**WP3 The profile and runner grow `net`.** In `profile.py` and `sandbox_exec.py`: `Profile.net` with the three states, a bind of the proxy socket and the in sandbox relay for the two proxy states, `HTTPS_PROXY` set, `--share-net` never used. Keep `network: bool` working for the tracer path. Done when a test shows a sandboxed `python3` reaches a local test server through the proxy, a raw `socket.connect` to the same address fails with no route, and the existing tracer tests are unchanged.

**WP4 The launcher, non interactive.** `prismpath agent run -- claude ...` in `prismpath/agent/commands.py`. Stage the config directory, resolve and pin the binary, build the agent profile (fixed mounts, control paths read only, empty control files created), start the proxy, run the sandbox, tear everything down on exit, reap the process group, and fail closed on a missing bwrap or socat. Done when `claude -p` runs through it end to end with a stub model server, the staged `settings.json` cannot be written from inside, and a write to `.claude/settings.local.json` in the workspace fails.

**WP5 The decider socket and the thin hook.** The decider in the launcher and a standard library hook client. Keys, policy and run directory stay outside. Done when a scripted hook input through the client gets the same answer and the same receipt as `prismpath agent hook` does today for the tracer's corpus, a missing socket is a deny with `agent:hook-error`, and the sandbox cannot read the keys or the journal.

**WP6 The classifier and Lean fields.** `tool: connect`, `net_dest`, `proc_class`, classifier version 2, the Lean enumerations, the `model_api` table, the `netSafe` check and `connect_other_refused`. Re-sign the starter policies. Done when `formal/diff/classifier_diff.py` agrees on a corpus that includes odd hosts (case, trailing dot, IP literals, userinfo tricks, port 0 and 65536), the Lean build and the standard axioms check pass, and a new registered cause is appended after 129.

**WP7 The compile and the proxy read the policy.** `compile_profile(image, role)`, `prismpath.profile/2`, and the proxy's decider changed to classify each CONNECT into a reading, decide it with the reference kernel and write a receipt. The constant allowlist goes away. Done when `compile_profile` on the starter image gives `net == proxy_model` for the agent role and `none` for the bash role, on an image allowing `allowed_host` it gives `proxy_allow`, the differential checks the compiled `net` against the oracle for every reading, a refused CONNECT has a receipt that `prismpath agent verify` accepts, and the interim allowlist is deleted.

**WP8 Per call Bash inside the outer sandbox, and the disagreement tests.** Nested bwrap for rewritten Bash calls with the tracer's profile, the fail closed deny where nesting is unavailable, and the PostToolUse observation for file tools if the hook page supports it. Done when a table of the section 4 cases is a test, including one where the agent's own Read tool asks for `~/.ssh/config` and for the staged credential. The Read of the credential through the file tool is the case the outer sandbox alone cannot stop, because the credential is mounted for Claude's own use. That limit is written into the test as a known gap, and it is the reason for question 1.

**WP9 The terminal.** The pty relay and `SIGWINCH` forwarding for interactive `claude`. Done when an interactive session started under the launcher accepts typing, Ctrl-C and a resize, and a program inside cannot write to the person's real terminal device, checked with a `TIOCSTI` attempt.

**WP10 The adversary set and the write up.** Adapt the tracer's adversary test and the harness set to the whole agent: a model or script asks Claude to read a decoy secret with the Read tool, write outside the workspace with Write, edit `.claude/settings.json`, connect to a non model host, ignore `HTTPS_PROXY`, and fork past the limit. Each runs once with the hook alone and once under the launcher, and both results are asserted, as in `test_sandbox_adversary.py`. Measure start time and the hook round trip over the socket against the 150 ms budget. Done when the gate passes and `docs/design/agent-sandbox-results.md` says what is guaranteed, what is not (the model credential visible to the agent, the allowed host as a data path, a kernel or bwrap flaw, the unsigned profile hash), and the measured costs.

## 6. Open questions for the owner

Each has a recommended answer. Each is safe and reversible, so the lead can take it if the owner does not reply.

1. **Which credential does the first build support, a subscription login or an API key?** Recommended: both. Stage a copy of the one credential the run uses, and treat the exposure to the agent as a stated gap. Reversible: later, base URL injection (section 2.3) removes the key from the sandbox for API keys. It is unverified for subscription OAuth.
2. **Switch off Claude Code's non essential traffic inside the sandbox?** Recommended: yes (`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, `ENABLE_CLAUDEAI_MCP_SERVERS=false`, auto-update off). It cuts the allowlist to the model API, and the page says it also stops feature flag fetching. The spike measures what that costs. If it breaks the agent, the allowlist gains `api.anthropic.com` flag traffic only, which it already has.
3. **Allow `platform.claude.com` for OAuth refresh?** Recommended: yes, only when the staged credential is OAuth. No other host is added for sign in.
4. **If a nested sandbox is not available on a host, what happens to Bash?** Recommended: deny it with a registered cause and say why in the reason. The alternative, running Bash under the outer profile only, lets every child read the model credential. The cost is that such a host cannot run Bash under the governed agent until it is fixed. Reversible by a flag the owner sets later.
5. **Where does the proxy live?** Recommended: inside the launcher process, as a thread or task, so one process owns keys, proxy, decider and teardown. A separate process is easy to add later.
6. **Keep the hook's keys and journal outside the sandbox, with a thin hook client?** Recommended: yes. The alternative leaves the authority key where the agent can read it, which defeats the receipts.
7. **Put the profile hash in the signed root, so the oracle replay sees it?** Recommended: not in this plan. It changes `prismpath.core-receipt/1`, which the tracer deliberately left alone. Ask again after WP10 with the measured cost. Until then the hash stays on the journal line.
8. **Does a refused `connect` receipt carry the host name?** Recommended: the class only in the receipt, the host in the observation file beside it, which is outside the signed root and can be redacted when a run is exported. A host can be sensitive. Reversible, since the observation file format is separate.
9. **WebFetch and WebSearch while the agent is sandboxed?** Recommended: refused, as the allowlist gives them no route. A later policy can add an `allowed_host` class for documentation hosts. Reversible by that one rule.
10. **First `max_processes` for the agent role?** Recommended: four times the peak the spike measures, not a guess, and the number goes into the results note. A limit that is too low looks like a hang, so WP10 includes a test that a fork refusal is reported with its cause.
11. **Native install only in the first build?** Recommended: yes. An npm install adds a Node runtime and modules to expose. Add it after WP10 if anyone needs it.

## 6a. Decisions taken, 2026-11-20

The lead took the recommended answer to questions 2 to 11 under the owner's standing rule (take the safe, reversible choice and list it). The owner may overturn any of them.

Question 1 waits for the owner. WP1 needs a real credential inside the sandbox, either a copy of the owner's OAuth login or an API key, and credentials stay with the owner. WP1 and the live parts of WP4 and WP10 wait for that answer. WP2, WP3 and WP6 need no credential and start now.

## 7. What this does not change

- The hook still fails closed, and the old behaviour (hook only, no sandbox) stays available as `prismpath agent hook` alone for macOS and Windows, which are decided and not confined (`sandbox-tracer-results.md`).
- No signed policy changes meaning. The new fields are additive, the classifier version gates them, and the default image is re-signed once in WP6.
- The first device target (cFS on NOS3, decision 6) is not touched. The same `net_dest` idea applies there as a destination class on a bus command, but that is `docs/design/cfs-app-plan.md`.
- Landlock, seccomp and cgroups (decision 3) arrive later behind the same `Profile` type. `Profile.net` and `proc_class` are what they would also read. A seccomp filter would be the natural second line for the proxy's socket, and cgroups the proper process and memory bound where `RLIMIT_NPROC` counts threads.

## 8. Sources

- https://code.claude.com/docs/en/network-config.md (hosts, proxy variables, no SOCKS, CA store)
- https://code.claude.com/docs/en/sandboxing.md (Claude Code's own sandbox, what it does and does not cover, nested namespace notes)
- https://code.claude.com/docs/en/settings.md (settings files, precedence, `CLAUDE_CONFIG_DIR`, `~/.claude.json`)
- https://code.claude.com/docs/en/env-vars.md (`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`, `ANTHROPIC_API_KEY`; the page was read only in part)
- https://code.claude.com/docs/en/corporate-launcher.md (`CLAUDE_CODE_PROCESS_WRAPPER` and `processWrapper`, the contract for a launcher that sets a sandbox and network controls)
- https://code.claude.com/docs/en/hooks (cited by `hook-rewrite-note.md`; `PostToolUse` input not read for this plan)

The corporate launcher page matters for one more reason. `processWrapper` starts every Claude Code process the binary launches itself through a launcher that must end in `exec "$@"`, pass the inherited environment through, and reach `exec` within about three seconds. It is meant for background sessions and agent view. `prismpath agent run -- claude` is the same idea for the foreground session. If the owner later wants background agents governed, the wrapper is how, and the launcher contract (inherited environment intact, no output before `exec`) is a constraint on WP4's design. The page's rule that the environment must be passed through verbatim conflicts with `--clearenv` in the sandbox, so the launcher would have to re-export the inherited environment inside, as that page allows. This is not needed for the first build, and it is not verified.
