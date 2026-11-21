# One signed policy, many enforcement points

*A plan, not an implementation. Written 2026-11-19 against research main 3bf9526. Nothing in sections 1 to 3 is built unless a path says it is. Section 4 is the first work.*

## 0. Why

The owner wants PrismPath to work like a firewall. If the signed policy does not authorize an action, the resource cannot be reached, whatever the worker is. A model is one kind of worker. A shell script, a build, a microcontroller and a flight app are others.

Today the governed agent is a Claude Code `PreToolUse` hook (`prismpath/agent/claude_code.py`, `prismpath/agent/commands.py`) and an MCP proxy (`prismpath/agent/mcp_proxy.py`). Both decide from the text of a call and fail closed. Both live in or beside the agent's own process and files. They guarantee nothing about what an allowed call then does. The hook's answer has three values and no more (`hook_answer` in `prismpath/agent/claude_code.py`). An allowed `pytest` can read any file the user can and open any socket. `docs/design/governed-agent-plan.md` section 2 says so on the first page. This plan is about closing that gap, and about doing the same for workers that are not models.

## 1. One policy, many targets

### What the one policy is

The signed policy is a `prismpath.core/1` image (`prismpath/kernel/core_policy.py`, format `prismpath.core/1`). It is authored as readable rules (`prismpath/agent/policy/agent_default.rules.md`), compiled to canonical bytes, and checked by a port of the Lean oracle's `loadPolicy`. Field definitions bind scale, range and absence into the signature (SPEC.md section 4.5). The decision is the first rule that holds (`prismpath/agent/policy.py`). The decision procedure is proved in `formal/Core/`, and every receipted decision is replayed through the oracle (`prismpath/agent/evidence.py`).

One fact shapes everything below. The policy decides over a reading, not over a raw action. Today a reading is eleven fields the classifier fills in (`prismpath/agent/classifier.py`): `tool`, `path_scope`, `command_class`, `git_op` and so on. The field space is finite, and it has already been enumerated in full for other images (`integrations/governed_population/exhaustive.py`, `prismpath/tests/test_agent_starters.py`). So the set of readings a policy allows can be computed. Call it the allow set.

The policy has no field for a destination host, a port, a pin or a child process count. `path_scope` is `none`, `workspace`, `outside` or `unknown`. A network call is a `command_class` of `network`, and the starters refuse it (`agent:network` in `agent_default.rules.md`). So the policy today can say "no network" and "workspace only". It cannot say "this host only". Section 5 asks whether to add fields.

### The pattern to reuse

The network target already shows the pattern. A signed image goes through a compiler that fixes the field schema, refuses what the target cannot decide faithfully, and emits the target's table (`prismpath-ebpf/net_compile.py`). A certifier builds frames from an independent definition of the reading, has the host engine decide them, and replays them through the real target with `BPF_PROG_TEST_RUN` (`prismpath-ebpf/net_cert.py`). The two must agree on every case. `integrations/governed_net/differential.py` does the same for the tool call path. Every new target in this plan gets four parts. A compiler. A refusal list for what it cannot express. An independent reading of the observed operation. A differential against the oracle.

### The targets

**Agent intent (the hook and the MCP proxy).** It observes the text of a tool call, read by the classifier. The disk half of the reading is observed at classification time and can change before the call runs (`prismpath/agent/classifier.py` says so, and names the sandbox as the answer). It can prevent one thing, the call being issued through that tool. It cannot see what an allowed call does after it starts. The hook runs in the agent's own process tree, and the settings file that installs it sits in the project the agent works in (`prismpath/agent/doctor.py` checks it, nothing prevents its edit by a path the classifier calls `workspace`; to be confirmed in WP1). The proxy sits in front of one MCP server and does not see tools the client runs itself. **Advisory.** It is the right layer for intent and for the record, since only it sees what the model asked for. It is not a guarantee about reach.

**Any process on Linux (the sandbox).** The harness already runs each allowed call in bubblewrap (`integrations/governed_harness/sandbox.py`). All namespaces are unshared, so no network. Only `/usr` is bound read only. The workspace is the one read write path. Capabilities are dropped, the environment is empty and a call has 30 seconds. Journeyman has a stronger stack for the same job (`~/cwprojects/journeyman/app/src-tauri/src/sandbox/`). Landlock limits reads and executes to an allowlist and writes to the workspace, and with ABI 4 it limits TCP connect and bind to a port range (`landlock.rs`). Seccomp removes syscalls with no legitimate role, as a deny list on purpose (`seccomp.rs`). A cgroup bounds processes and memory (`cgroup.rs`, `lifetime.rs`). bubblewrap is the fallback when Landlock is missing (`mod.rs`, `sandbox.rs`). Both are driven by fixed profiles today. Neither is compiled from a policy. That compile does not exist. A **real guarantee** for the process and its children, since the child has no other path through the kernel. It holds only for what the profile closes, and the Journeyman notes themselves say what it does not (no PID namespace, signals before Landlock ABI 6). The tracer in section 4 builds this.

**Network (XDP).** It observes a frame. `prismpath-ebpf/ppt_net.bpf.c` fills eight packet fields (`src_ip`, `dst_ip`, ports, protocol, length, flags, ttl) and evaluates a compiled table. It drops a packet when the matched node is flagged for drop (`net_triage_enforce.md`, `cfg->drop_mask` in `ppt_net.bpf.c`). `integrations/governed_net/` goes further. The program decides a tool call datagram and passes it only on `allow`, and the tool server decides again and runs the call in bwrap only when both agree (`integrations/governed_net/README.md`). The XDP program was measured in kernel, and the userspace twin is a test path, not the kernel (`xdp_userspace.py` says so). A **real guarantee** for traffic that crosses the guarded interface, and the README names the gap. The program guards only its own NIC, so the client pins its socket to it. It also reads packets, not users or files. It cannot tell which process sent a packet. For one host's own processes the answer is a network namespace in the sandbox, with XDP as the edge. The compile from the agent policy to packet fields (an allowlist of destinations) does not exist. `net_triage_enforce.md` is a hand written flow.

**Devices (prismpath-hw, cFS, F Prime).** The embedded evaluator is C with static buffers (`prismpath-hw/ppt_eval.h`). It is certified against the frozen corpus on an ESP32-C6 over UART (`prismpath-hw/esp/certify_esp32.py`, `prismpath-hw/esp/main/ppt_esp32.c`), and on other boards and on fabric (`prismpath-hw/README.md`). That shows the decision runs on the device. It does not by itself make the device refuse anything. Whether an actuator can be reached without passing the evaluator is a property of the firmware's wiring, which no file here proves for the ESP32 (`ppt_esp32.c` is the certification harness, not a governed actuator; there is no ESP32 enforcement app in the repo). The cFS app and the F Prime component put the decision on the command path. An allowed command is republished on `VEHICLE_CMD`, and a refusal is an event (`integrations/cfs/README.md`, `integrations/fprime/README.md`, plan in `docs/design/cfs-app-plan.md`). The apps decide every command sent to the proposal message id. Nothing in the plan or the READMEs stops another app from publishing directly to the vehicle's message id on the software bus, so the guarantee is only as strong as the mission's wiring. **Advisory** until a mission closes that path, and the plan should say so on its first page. A device is a real guarantee only when the actuator is physically behind the evaluator, for example a relay driven only by the pod's output pin.

| Target | Observes | Can prevent | Compiled from the policy today | Guarantee |
|---|---|---|---|---|
| Hook and MCP proxy | text of one call | the call being issued through that tool | yes, it is the policy | Advisory for reach |
| Linux sandbox | syscalls and paths of a process tree | file, network and process access outside the profile | no, fixed profiles | Real, once compiled (section 4) |
| XDP | one frame | packets on the guarded NIC | no, hand written flow plus a certified compiler | Real for that NIC |
| Device, cFS, F Prime | a command or a pin | a command that goes through the app | partly, the image is the policy | Advisory until the bus or the pin is closed |

## 2. Layering

Each resource is held by the layer that is the worker's only path to it. The other layers decide the same way and add the record.

| Resource | Holds the guarantee | Also decides | Why |
|---|---|---|---|
| Files | sandbox (mount view, Landlock) | hook, for the receipt and for tools that run in the agent process | A path check at the hook is a race with the disk. The sandbox is not. |
| Outbound network from a process | network namespace or Landlock port rules in the sandbox | XDP at the edge, hook for `network` class | Only the kernel of the host sees which process opened the socket. |
| Network between hosts | XDP or the host firewall at the edge | the sandbox of each end | XDP cannot see a process, the sandbox cannot see another host. |
| Child processes and memory | cgroup and rlimits in the sandbox | none | Policy text cannot bound a fork bomb. |
| Intent (what the model asked for, escalation to a person) | hook and MCP proxy | none | Only they see the call before it is a syscall. |
| The record | the hook, the proxy and every other point, each writing receipts | verifier | One run format (`prismpath/agent/run.py`) for all of them. |
| An actuator | the wiring, so the evaluator on the device | the ground or host decision | A pin cannot be argued with in software. |

**Consistency.** Each layer's profile is derived from one image by a stated projection. The image's hash is recorded in every layer's receipts. A layer refuses to start on an image whose signature or version floor fails, as the cFS app already does (`integrations/cfs/README.md`). Profiles are never edited by hand. A profile that cannot express a rule the image holds is a compile refusal, not a silent widening, as `net_compile.py` refuses an ordering on an address.

**Disagreement.** The rule is the stricter answer, recorded. If the hook allows and the sandbox blocks, the call fails and the sandbox's refusal is a receipt that names the hook's allow. If the hook refuses, nothing runs. The reverse, a layer allowing what the oracle refuses, is a defect and a failing test. `governed_net` already treats any disagreement between the two deciders as a finding and not a run (`integrations/governed_net/README.md`). Section 4 makes this a test.

## 3. Observations back to policy

Every enforcement point reports each refusal it enforces as an observation with a receipt, in the run format the hook already uses. A sandbox stop reads as "this tree tried path X, the profile of image H refused it". It is evidence about what the worker tried and what the policy lacks. It is not an instruction.

This keeps the principle in `~/cwprojects/cc-gate-tracer/NORTH-STAR.md`. Observations may change what the system knows. They must not silently change what it is permitted to do. A cluster of refusals can become a proposal for a new rule. Only a signed, scoped and expiring envelope widens what is permitted. `~/cwprojects/cc-gate-tracer/DESIGN-envelope.md` is the model. The owner signs a bounded class of growth in advance, the adopter checks a request fits it, every adoption is receipted and can be reverted, and an expired or unverifiable envelope leaves the signed base policy alone. The enforcement points feed the proposer and never the adopter. No profile changes between signatures.

## 4. First tracer bullet (Linux only)

**Goal.** The governed agent's allowed Bash calls run inside a sandbox whose profile is compiled from the same signed policy. A differential test checks the compiled profile against the Lean oracle. An adversary case, an allowed command whose child tries a refused path or the network, is stopped by the sandbox.

**Where it hooks in.** The hook already decides every Bash call before it runs. For an allowed Bash call it must change the command to run under the sandbox. Claude Code's hook protocol is believed to let a hook return a changed tool input (`updatedInput`). `hook_answer` returns none today. WP1 confirms this against the current Claude Code docs before anything else, because the plan depends on it. If it is not available, the fallback is to deny Bash in the hook and run the command through a PrismPath MCP tool (`prismpath/agent/mcp_proxy.py`).

**Scope of the guarantee.** Bash calls only. Claude Code's own `Read`, `Write` and `Edit` run in its process and stay advisory in this tracer. A later package runs the whole agent under the sandbox.

**Work packages.** Each is about 30 to 40 minutes.

**WP1 Confirm the hook can rewrite, and write the sandbox runner.** Check the Claude Code hook output for a rewritten command. Add `prismpath/agent/sandbox_exec.py`, a function that takes a command, a workspace and a profile and runs it under bwrap (starting from `bwrap_argv` in `integrations/governed_harness/sandbox.py`, moved into the wheel as A1 of the governed agent plan did for the classifier). Done when a test runs `echo ok` and `cat /etc/hostname` through it, the first succeeds, the second fails because `/etc` is not bound, and the note on the hook protocol is in the PR.

**WP2 The profile type and the projection.** Add `prismpath/agent/profile.py`. A profile holds the paths mounted read only, the one read write path, whether a network is present, and a process and time limit. `compile_profile(image)` walks the image's whole allow set, enumerated as in `integrations/governed_population/exhaustive.py`, and sets each capability only if some allowed reading needs it. No allowed reading with `path_scope == "outside"` means nothing outside the workspace and the system prefix is mounted. No allowed reading with `command_class == "network"` or a network `git_op` means no network. Done when `compile_profile` on `agent_default.core.json` gives workspace only and no network, on a test image that allows `network` it gives a network, and on the same image twice it gives byte identical output.

**WP3 Wire it into the hook.** For an allowed `run_command`, the hook compiles the profile from the active image, rewrites the command to run under `sandbox_exec`, and writes the profile hash into the receipt. Refuse and escalate are unchanged. Fail closed. A profile that cannot compile, or a sandbox that cannot start, is a deny with a registered cause (a new cause appended after the existing ones, never renumbered, as `docs/design/spec-cause-codes.md` requires). Done when a scripted hook input for an allowed `ls` returns a rewritten command, one for `curl` is still refused, and a missing bwrap gives a deny.

**WP4 The differential against the oracle.** Add `prismpath/tests/test_profile_differential.py`. Build a corpus of operations from an independent definition (as `net_cert.py` defines its canonical reading separately from the C). Include reads and writes of a workspace file, of `/etc/passwd`, of `~/.ssh`, of a `..` path and of a symlink out, and connects to a loopback and a remote address. Read each operation into a reading with the classifier's disk facts, decide it with the oracle binary (the way `formal/diff/core_evidence.py` does), run it in the sandbox, and compare. Done when the sandbox allows no operation the oracle refuses, and each case where the sandbox is stricter than the oracle is listed in the test output with its reason, not hidden.

**WP5 The adversary case.** Add an allowed command whose child does the refused thing. For example an allowed `python3 -c` style call, or a script in the workspace the policy allows to run, that opens `/etc/shadow`, writes outside the workspace, and connects to an outside address. Run it once with the hook alone (the old behavior) and once with the sandbox. Done when the first run reaches the refused resource and the second is stopped, and the test asserts both, so the old gap stays measured.

**WP6 Refusals become observations.** When the sandbox stops an access, the run gets a receipt of kind observation with the image hash, the profile hash and the path or address. Keep it small. Reuse `RunStore` (`prismpath/agent/run.py`). Done when the WP5 run verifies with `prismpath agent verify` and shows the stopped accesses as receipts that the oracle replay accepts.

**WP7 Gate and write up.** Run the existing agent tests and the harness adversary set to show nothing regressed. Measure the hook's added latency (the plan's budget is 150 ms on the floor tier, `governed-agent-plan.md` A4). Done when the tests pass, the latency is in the PR, and a short note says what the tracer guarantees (Bash children) and what it does not (Claude's own file tools, the settings file, a kernel escape).

Order: WP1, WP2, then WP3 and WP4 together, then WP5, WP6, WP7.

## 5. Open questions for the owner

1. **Add network and process fields to the policy, or keep a separate profile section?** Recommended: add reading fields (a destination class, a process limit class) to the policy so the one image stays the only source and the oracle's proof covers them. The tracer does not need them, so this can wait for the XDP compile. The alternative is a second signed section, which is quicker but is a second thing to keep consistent.
2. **Run the whole agent under the sandbox next, or only its shell calls?** Recommended: the whole agent, as the second step after WP7, since it is the only way Claude's file tools stop being advisory. It costs a launcher (`prismpath agent run -- claude`) and a way to reach the model's API from inside, which is an allowlist entry and so depends on question 1.
3. **Which sandbox backend becomes the shared one, bubblewrap or Journeyman's Landlock, seccomp and cgroup stack?** Recommended: bubblewrap for the tracer, since it exists in this repo and needs no unprivileged user namespaces beyond what the harness already uses, and Landlock and seccomp as a second backend behind the same profile type once the tracer is green. The profile type is the interface, so the choice stays reversible.
4. **Should a refused access in the sandbox ever escalate to a person while the command runs?** Recommended: no. It stays a refusal and a receipt, and the proposal path of section 3 is how the policy grows. A prompt in the middle of a build is the pattern the owner is trying to leave.
5. **Protect the hook's own settings file by policy?** Recommended: yes, add a rule that refuses writes to `.claude/settings.json` and the policy and key directories, and check in WP1 whether it is already covered. Without it the hook can be removed by the agent it governs.
6. **Which device target is the first honest one?** Recommended: the cFS app on the NOS3 scenario (`docs/design/cfs-app-plan.md` S3), with the plan stating the software bus gap, before any ESP32 claim. The ESP32 has a certified evaluator but no governed actuator here, so a real guarantee there needs a small board with a relay behind the pod's output pin. That is worth building only after the Linux tracer shows the compile and differential pattern works.

## 6. Owner decisions, 2026-11-19

1. Network and process limits become reading fields in the one signed policy, so the proof covers them. They come with the XDP compile, not the tracer.
2. The whole agent runs under the sandbox as the next step after WP7, through a launcher, with the model's API as an allowlist entry.
3. bubblewrap is the first backend. Landlock, seccomp and cgroups follow behind the same profile type.
4. A refused access in the sandbox stays a refusal and a receipt. It never prompts the person mid run. Refusals feed proposals under section 3.
5. Writes to the agent's own control files are refused (cause 128, PR #60).
6. The first device target is the cFS app on NOS3, with the software bus gap stated plainly. The ESP32 waits for the Linux tracer.

The plan for decisions 1 to 4 is in `docs/design/agent-sandbox-plan.md`.
7. The enforcement point also goes in front of the resource, whatever the worker is, and one protocol carries the signed policy to every point. See `docs/design/prismpath-at-the-resource.md` and `docs/design/policy-distribution.md`.
