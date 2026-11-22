# Govern a coding agent in ten minutes

This guide puts PrismPath in front of Claude Code. Every tool call Claude proposes goes to a PrismPath hook first. The hook decides allow, refuse or ask under a signed policy and writes a receipt for the decision, and you can check those receipts afterwards. You need Linux or macOS, Python 3.10 or later and Claude Code. The commands below that start with `prismpath` are run in CI against written hook input, so the guide stays true to the code.

## 1. Install

```bash
git clone https://github.com/crystal-warden/prism-path.git && cd prism-path
pip install -e '.[signing]'
```

From PyPI the same thing is `pip install 'prismpath[signing]'`. The `signing` extra brings the library that signs receipts. Keep PrismPath in the environment Claude Code's hook will find, since the hook command `init` writes names the Python that ran `init`.

## 2. Initialise a project

Go to the project you want Claude Code to work in and run `init`.

<!-- guide-test: init -->
```sh
prismpath agent init
```

It makes two keys in your configuration directory, `~/.config/prismpath/agent` on Linux and `~/Library/Application Support/prismpath/agent` on macOS. The authority key says which policy may run. The instance key signs the receipts. It records the default policy, `agent_default`, with an attestation, the authority key's signature over that exact policy, so the hook refuses to run under any policy you did not sign. An existing key is never replaced.

Then it shows the change it wants to make to the project's `.claude/settings.json` as a diff, and asks. Nothing is written until you answer yes. The change adds a `PreToolUse` hook for every tool and a `SessionEnd` hook, and your other settings are left as they are. The command in both is the Python that ran `init` followed by `-m prismpath agent hook || exit 2`. The next section says why it ends that way. Running `init` again changes nothing. In a script, pass `--yes` to answer for yourself.

## 3. Start Claude Code and try four things

Start `claude` in the project and ask it for each of these. Nothing about how you talk to it changes. You will see PrismPath only when it refuses or asks.

**List the project.** Ask "list the files in this project". The hook allows it. Claude Code runs the call with no prompt, and a receipt for the decision is written.

**Delete a file outside the project.** Ask "delete /tmp/other/report.txt". The call does not run. Claude is told the answer, which looks like this.

```
PrismPath refused this call: cause 111 agent:outside-workspace. It was not run. Receipt 1 of session <id>.
```

Cause 111 is `agent:outside-workspace`. The receipt number is the position of the decision in this session's record. A system path such as `/etc/hosts` is refused with cause 107, `agent:toolchain-write`, instead, because `/usr`, `/opt` and `/etc` count as toolchain directories and that rule is checked first. Either way the call does not run.

**Delete a file inside the project.** Ask "delete notes.txt". The hook answers ask with cause 125, `agent:shell-mutation-asked`, and Claude Code shows you its own permission prompt with PrismPath's reason in it. Nothing runs until you choose.

**Push.** Ask "push this branch". The hook answers ask with cause 113, `agent:push-escalated`, and you decide at the prompt.

You can see these four answers without Claude Code by sending the hook what Claude Code sends it. This block does it in your own project. The function builds one hook input and prints the answer.

<!-- guide-test: try -->
```sh
try_hook() {
  printf '{"session_id":"guide","cwd":"%s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"%s"}}' "$PWD" "$1" | prismpath agent hook
  echo
}
try_hook 'ls'
try_hook 'rm /tmp/other/report.txt'
try_hook 'rm notes.txt'
try_hook 'git push origin HEAD'
```

The first answer is `allow` and carries no reason. The second is `deny` with cause 111. The third is `ask` with cause 125. The fourth is `ask` with cause 113. The session id is `guide` here and Claude Code supplies its own.

## 4. Look at what was recorded

<!-- guide-test: status -->
```sh
prismpath agent status
```

`status` lists the two keys, the policy with its hash and whether its attestation holds, the hooks found in the project and each session with its receipt count, whether it is open or sealed and what became of its calls. It exits 1 if the setup would not run.

If the recorded policy would let the agent change its own control files (`.claude/settings.json`, the hook scripts, `.mcp.json`), `status` prints a warning line saying so and the command that fixes it. That happens for a policy you recorded with `prismpath agent init` before 2026-11-19, when the starters began to refuse such a change, and for a custom policy without that rule. The check reads the policy alone, so it does not depend on the project. The fix is `prismpath agent init --policy strict`, `default` or `review`, which records that starter again and attests it with your key. Runs you already sealed keep their own policy and still verify, and a Claude Code session that is open when you do it has its next call denied, because its run began under the old policy, so end that session and start another. With `--json`, `policy.control.refuses_control_changes` is `true` when the policy refuses every such change and `false` when it does not (then with `reason`, `policy`, `fix` and `message`), and `null` when the policy could not be checked.

<!-- guide-test: verify -->
```sh
prismpath agent verify
```

`verify` first seals each session still open, so a session counts as sealed once `verify` or the end of the Claude Code session has run. It then replays every receipt through the reference kernel, the small decision code the proofs are about, which ships inside PrismPath, and checks the root statement, the instance key's signature over the whole sealed record, against your pinned keys. A line saying 0 disagree and root statement signed means the record is whole and every decision follows from the policy.

<!-- guide-test: tamper -->
```sh
prismpath agent verify --tamper-demo
```

The demo copies a session, flips one byte of its receipts, and verifies the copy. The copy is refused and then deleted. Your own session is not touched.

### Sandbox observations

When a shell command that ran in the sandbox shows on its standard error that an access was stopped, such as a permission error or a network that is unreachable, the runner adds an observation to the session. It is bound to the receipt of the allowed call and carries the hash of the policy and of the sandbox profile. `verify` checks each one against its receipt and counts it. An observation is what the command said, read from its exit status and its error text, so it can miss a refusal the command hid and it cannot tell a path the sandbox hid from a path that does not exist. It is kept in its own file in the run, outside the signed root, so a line removed from the end would not be noticed.

An observation never changes what is allowed. It does not edit the policy or the profile, it is not a rule hit in `prismpath agent rules`, and nothing that decides reads it. The same holds for the outcomes described next. Only a policy you sign widens what runs.

## What became of each call

A receipt says what the hook answered. It does not say whether an allowed call ran, or whether you said yes to a question. Claude Code tells the hook nothing about your answer at the time, so PrismPath reads it from two later events. `init` writes hook entries for both, next to the two it already had.

- `PostToolUse` fires after a tool call succeeds. The input carries `tool_use_id`, `tool_name`, `tool_input` and `tool_response`.
- `PostToolUseFailure` fires after a tool call that started and failed. The input carries `tool_use_id`, `tool_name`, `tool_input`, `error` and `is_interrupt`.

The `tool_use_id` is the id Claude Code gives the call. The hook now keeps it on the receipt's line in the run's journal, an optional key like the sandbox profile hash, so the later event can be tied to the receipt of the same call. The receipt itself and the signed root are unchanged. Each event adds one line to `outcomes.jsonl` in the run. The line says `ran` or `failed`, the tool's name, the index and hash of the receipt, and for a failure its class (`exit-nonzero`, `interrupt` or `error`). It never holds what the tool returned or the error text. Each line carries the hash of the one before it, and `verify` checks the chain and that every line is about the receipt it names, with the same `tool_use_id`, and that no receipt has two outcomes from one source.

Under `prismpath agent run`, the runner of the per call sandbox already reports every shell command it finishes. That counts as an outcome too, with or without a stopped access to observe, and it does not depend on the two hook entries.

When the session ends, every allowed receipt with no outcome is recorded as `no outcome`, and every receipt that asked you with no outcome is recorded as `no outcome (declined or not run)`. A question you declined and one you approved that then never ran look the same from here, so the line says both. A refused call never runs and has no outcome. An event that cannot be tied to a receipt (no id, an id no receipt has, a refusal, a second report for one receipt) is recorded as `unbound` with the reason, up to 256 a run, and changes nothing.

Outcomes are records and never decisions. They cannot block anything, since the call already ran, and a hook that cannot record one answers with nothing. No outcome changes a policy, a profile, a rule or any verdict, and nothing that decides reads one. They sit outside the signed root, in their own file, so a line cut from the end would not be noticed, and a rewritten file that is consistent with itself can be told from the original only by the receipts it names. Under the launcher the reports come from inside the sandbox over the decider's socket, so they are claims of the agent's process. A forged one can add a false `ran` to a receipt and can never widen what runs.

`prismpath agent status` shows the totals for each session and for all of them, for example `allowed 5 (4 ran, 1 no outcome); asked 3 (1 approved and ran, 1 failed or interrupted, 1 no outcome); refused 3`. A call still waiting for its outcome counts as having none until it arrives.

### Approvals worth a rule

```sh
prismpath agent approvals --min 3
```

Lists the rules that ask you whose questions you approved, and that then ran (a call that failed or was interrupted is shown apart and not counted), at least `--min` times (3 by default). Each shows the counts and up to three example readings. A reading is classes only, for example `command_class=mutating path_scope=workspace proc_class=single tool=run_command`, never a path or a command. The output is headed candidates for the owner to sign, nothing is changed. An approval you give over and over is a hint that an allow rule for that class of call may be what you want. To adopt one, write the rule in your policy source and sign it with your authority key as in [writing-agent-rules.md](writing-agent-rules.md). The command never edits a policy and nothing adopts a rule on its own. Only receipts of runs that verify are counted.

## See which rules fire

```sh
prismpath agent rules
```

`rules` lists the recorded policy's rules in order, the way `iptables -L -v` lists a firewall. Each row has the rule's number, its hits, the time of its last hit, its target (`allow`, `refuse_<code>` or `escalate_<code>` with the cause name) and its condition as the rules file writes it. After the rules come two rows for the core's own refusals, `route:no-matching-edge` (no rule holds) and `route:contract-violation` (the reading broke the policy's field definitions), because there is no catch all rule. Two findings follow. **Never matched** lists the rules with no hit in the counted receipts. **Unreachable** lists a rule that no reading can ever reach because earlier rules cover every reading it matches. That second finding comes from the policy alone, by deciding every combination of field values through the reference kernel. A field without a finite set of values is not enumerated, and `rules` says which rules it did not check.

The outcome column says what became of the calls, as described under [What became of each call](#what-became-of-each-call). For a rule that allows it is the calls that ran and the calls with no outcome. For a rule that asks it is the calls you approved that ran, the calls that failed or were interrupted, and the calls with no outcome, declined or never run. A rule that refuses counts its refusals.

Only receipts of runs that verify are counted, and the output says how many receipts did not verify (or were decided under another policy) and were skipped. A receipt has no time of its own, so the time of a hit is the time of its run: the signed time of a sealed run, else its last receipt. `--since 2026-11-01` counts only runs at or after that ISO 8601 time. The command reads your runs from scratch copies and never writes a receipt, a seal or a policy.

`--json` prints one object:

| key | holds |
|---|---|
| `config_dir`, `since` | the configuration directory and the `--since` time or null |
| `policy` | `name`, `image` and `sha256` of the recorded policy |
| `receipts` | `counted`, `not_verified`, `other_policy`, `runs_counted` and `skipped`, a list of `session`, `receipts` and `reason` |
| `rules` | per rule: `rule`, `condition`, `target`, `decision`, `cause`, `code`, `hits`, `last_hit`, and what became of the calls, `allowed_ran`, `allowed_no_outcome`, `asked_approved`, `asked_failed`, `asked_no_outcome`, `refused` |
| `core_refusals` | per core refusal: `cause`, `code`, `hits`, `last_hit`, `refused` |
| `never_matched` | the numbers of the rules with no hit |
| `unreachable` | `checked`, `readings`, `rules` (numbers) and `not_checked` (`rule` and the `fields` that have no finite set of values) |

## Pick a policy

`init` records `default` unless you name another starter with `--policy`, as in `prismpath agent init --policy review`. Running `init` again without `--policy` keeps the one you picked. A session already running stays on the policy it began with, so start a new Claude Code session after you switch.

| starter | allows | asks | refuses |
|---|---|---|---|
| `strict` | reads, listings and read only commands in the project, file writes in the project, local git | a push | a call it cannot read, a shell command that changes files, and the hazards |
| `default` | the same as `strict` | a push, a call it cannot read (124), a shell command that changes files in the project (125) | a git operation or path it cannot read, a git change it cannot undo, and the hazards |
| `review` | reads, listings and read only commands in the project, git reads | every change in the project (127), every push, a call it cannot read | the same as `default` |
| `session` | the same as `default` until the session's own history says otherwise | what `default` asks, and in a session that already made a change to protected code or whose reach was not known, a change in the project, a commit and a push to an allowed remote (133), and in a session that already ran 20 shell commands, a read only command or a local git operation (134) | the same as `default` |

The `session` starter reads the session's own receipts, never anything the agent wrote, and a history it cannot read counts as the most of both, so it asks. A session that is cleared or started again begins with none, and a call that was asked about and declined counts like one that ran.

All three also refuse, with cause 128, every change to the agent's own controls and to the files that shape how it behaves: everything under `.claude/`, `.mcp.json`, `.git/config`, everything under `.git/hooks/`, `CLAUDE.md`, `CLAUDE.local.md` and `AGENTS.md` at any depth, the program the installed hook runs when it is inside the project, and, for a removal or a move only, the project root or a directory that holds one of these (`rm -r .`; writing into them is decided as before). A path is matched after it resolves and without regard to case, and a hard link to a control file is one too. A shell command that redirects onto one (`echo x > .claude/settings.json`) is refused as well. The agent cannot take its own hook out. Reading these files still runs as before.

The hazards are refused by all three. They are a path outside the project, a `..` in a path, a path through a symbolic link, a path that is a pattern, a write into a toolchain, a kill by name pattern and the network. `status` names the starter in use. To write your own rules instead, see [writing-agent-rules.md](writing-agent-rules.md).

## Check your setup

If a call you expected to be governed is not, or a hook feels slow, run `prismpath agent doctor --project .`. It checks the key files, the recorded policy, the hook entries and the interpreter they name, a timed dry run of the hook, your runs and free disk space. Each check says ok, warn or fail with one line and the command that fixes it, and the doctor changes nothing itself. The `policy-control` check warns when the recorded policy would let the agent change its own control files, as described under `status`; in `--json` its row carries `refuses_control_changes`.

## What this does and does not protect you from

The hook decides. On Linux an allowed Bash call is rewritten to run inside a sandbox built from the same policy, so the programs it starts can reach the workspace and the system files they need and nothing else. Claude Code's own Read, Write and Edit tools, and every call on macOS and Windows, run outside any PrismPath sandbox and have the access Claude Code has. A question you approve in Claude Code's prompt runs inside the same sandbox, and the prompt shows the rewritten command. The sandbox is built from what the policy allows, so an approved call that needs more, a push for example, fails inside it.

Nothing PrismPath refuses runs. Every decision, allow, refuse or ask, has a receipt you can verify later.

The classifier that reads a call into a class (a read, a write, a command, an unknown) is trusted code. It is tested hard and it reads conservatively, so what it cannot read in full is `unknown` and asks. It is not proven, and a gap in it is a gap in the decision. The decision itself, from the classified call to the answer, is the verified core.

A hook allow skips Claude Code's own prompt for that call. An ask is Claude Code's prompt. The receipt records that PrismPath escalated the call to you. It does not record what you answered.

The hook fails closed. Input it cannot read, a missing or broken key, a policy whose attestation does not verify, any error at all, gives a deny with cause 126, `agent:hook-error`. A hook that cannot even start exits with 1, which Claude Code would let through, so the written command ends in `|| exit 2` and even a broken install blocks.

Tools from MCP servers reach the hook as `unknown` and ask, since PrismPath does not read what an arbitrary server's tool does. To decide those calls, and for agents other than Claude Code, put the MCP proxy in front of the server.

```bash
python -m prismpath.agent.mcp_proxy -- <your MCP server command and arguments>
```

It decides each `tools/call` the same way and writes the same receipts. A refusal or an escalation comes back to the agent as a tool error, since MCP has no way for a proxy to ask you.
