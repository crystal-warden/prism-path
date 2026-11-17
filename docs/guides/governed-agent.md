# Govern a coding agent in ten minutes

This guide puts PrismPath in front of Claude Code. Every tool call Claude proposes goes to a PrismPath hook first. The hook decides allow, refuse or ask under a signed policy and writes a receipt for the decision, and you can check those receipts afterwards. You need Linux or macOS, Python 3.10 or later and Claude Code. The commands below that start with `prismpath` are run in CI against recorded hook input, so the guide stays true to the code.

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

It makes two keys in your configuration directory, `~/.config/prismpath/agent` on Linux and `~/Library/Application Support/prismpath/agent` on macOS. The authority key says which policy may run. The instance key signs the receipts. It records the default policy, `agent_default`, with an attestation signed by the authority key. An existing key is never replaced.

Then it shows the change it wants to make to the project's `.claude/settings.json` as a diff, and asks. Nothing is written until you answer yes. The change adds a `PreToolUse` hook for every tool and a `SessionEnd` hook, and your other settings are left as they are. The command in both is the Python that ran `init` followed by `-m prismpath agent hook || exit 2`. The next section says why it ends that way. Running `init` again changes nothing. In a script, pass `--yes` to answer for yourself.

## 3. Start Claude Code and try four things

Start `claude` in the project and ask it for each of these. Nothing about how you talk to it changes. You will see PrismPath only when it refuses or asks.

**List the project.** Ask "list the files in this project". The hook allows it. Claude Code runs the call with no prompt, and a receipt for the decision is written.

**Delete a file outside the project.** Ask "delete /tmp/other/report.txt". The call does not run. Claude is told the answer, which looks like this.

```
PrismPath refused this call: cause 111 agent:outside-workspace. It was not run. Receipt 1 of session <id>.
```

Cause 111 is `agent:outside-workspace`. The receipt number is the position of the decision in this session's record.

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

`status` lists the two keys, the policy with its hash and whether its attestation holds, the hooks found in the project and each session with its receipt count and whether it is open or sealed. It exits 1 if the setup would not run.

<!-- guide-test: verify -->
```sh
prismpath agent verify
```

`verify` seals each open session, replays every receipt through the reference kernel, and checks the root statement's signature against your pinned keys. A line saying 0 disagree and root statement signed means the record is whole and every decision follows from the policy.

<!-- guide-test: tamper -->
```sh
prismpath agent verify --tamper-demo
```

The demo copies a session, flips one byte of its receipts, and verifies the copy. The copy is refused and then deleted. Your own session is not touched.

## What this does and does not protect you from

The hook decides. Claude Code runs an allowed call itself, outside any PrismPath sandbox. PrismPath does not wrap the process, so a call it allows has the access Claude Code has.

Nothing PrismPath refuses runs. Every decision, allow, refuse or ask, has a receipt you can verify later.

The classifier that reads a call into a class (a read, a write, a command, an unknown) is trusted code. It is tested hard and it reads conservatively, so what it cannot read in full is `unknown` and asks. It is not proven, and a gap in it is a gap in the decision. The decision itself, from the classified call to the answer, is the verified core.

A hook allow skips Claude Code's own prompt for that call. An ask is Claude Code's prompt. The receipt records that PrismPath escalated the call to you. It does not record what you answered.

The hook fails closed. Input it cannot read, a missing or broken key, a policy whose attestation does not verify, any error at all, gives a deny with cause 126, `agent:hook-error`. The written command ends in `|| exit 2` so that even a broken install blocks, because a hook that cannot start exits with a code Claude Code treats as a block.

Tools from MCP servers reach the hook as `unknown` and ask, since PrismPath does not read what an arbitrary server's tool does. To decide those calls, and for agents other than Claude Code, put the MCP proxy in front of the server.

```bash
python -m prismpath.agent.mcp_proxy -- <your MCP server command and arguments>
```

It decides each `tools/call` the same way and writes the same receipts. A refusal or an escalation comes back to the agent as a tool error, since MCP has no way for a proxy to ask you.
