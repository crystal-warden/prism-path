# One command governed agent

*A plan for putting a coding agent people already run under PrismPath with one install and one command. Written 2026-11-16 against research main e94872d, after Mission Control WP8. Both market notes of 2026-11 put this first: today nothing installable takes a newcomer from `pip install` to a signed receipt.*

## 0. What exists and what is missing

`integrations/governed_harness` already does the hard part. A classifier reads a proposed tool call into eleven typed fields, the verified core decides the reading against a signed `prismpath.core/1` policy of agent rules, the receipt is written before anything runs, and a refusal carries a registered cause (104 to 113). The 51 case adversary set and `RESULTS.md` say what it holds and what it does not.

It is not reachable by a newcomer. It lives under `integrations/`, which the wheel does not ship. It drives its own model loop (Gemma over an OpenAI compatible endpoint) instead of the agents people use. Its keys are made by test helpers. Its evidence is verified with `formal/diff/core_evidence.py`, a research script.

## 1. The shape

The first adapter is a Claude Code `PreToolUse` hook, because the hook protocol already has the three answers PrismPath gives:

| PrismPath decision | hook answer | what the person sees |
|---|---|---|
| `allow` | `permissionDecision: allow` | the tool runs |
| `refuse_<code>` | `permissionDecision: deny`, reason names the cause and the receipt | the agent is told why and the call never runs |
| `escalate_<code>` | `permissionDecision: ask`, reason names the cause | Claude Code asks the person, as it does today |

The person's answer to an `ask` is not seen by the hook. The receipt records the escalation, which is what the core decided; what the person chose is Claude Code's own record. This is said plainly in the guide.

Commands, under the existing `prismpath` entry point:

- `prismpath agent init` makes the authority and instance keys (files under the user's config directory, mode 0600), signs the default policy, and writes the hook entry into the project's `.claude/settings.json` (shown and confirmed, never silently). One command, no key ceremony to read about first.
- `prismpath agent hook` is what Claude Code calls. It reads the hook JSON on stdin, classifies, decides, appends the receipt, and answers on stdout. It fails closed: any error is a `deny` with cause `agent:hook-error`, never an allow.
- `prismpath agent verify` seals the open run and verifies every run with both keys pinned, replaying each receipt through the reference kernel. `--tamper-demo` copies a run, changes one byte and shows the verify fail.
- `prismpath agent status` names the keys, the policy hash, the open run and its receipt count.

## 2. What it does not do, said on the first page

- The hook decides; Claude Code runs the allowed call outside any PrismPath sandbox. The harness's bubblewrap bound does not carry over. What carries over is that nothing PrismPath refuses runs, and every decision has a receipt.
- The classifier is trusted code outside the proof, as in the harness. A shell string it cannot read is `unknown`, and the default policy escalates `unknown` rather than guessing.
- It governs the tools the hook is given. Tools added by MCP servers reach the hook by name; ones the classifier does not know are `unknown`.

## 3. Work packages

**A1 Package the harness core.** Move the classifier, the policy loader and the evidence writer into `prismpath/agent/` so the wheel ships them. `integrations/governed_harness` imports them from there, and its tests and adversary set keep passing unchanged. The research only loop (Gemma chat, live scoring) stays in `integrations/`. Check: the 51 case probes give the same scores from the moved code.

**A2 Claude Code adapter.** Map Claude Code's tools to the classifier's: `Read` to `read_file`, `Write` and `Edit` to `write_file`, `Glob` and `Grep` and `LS` to `list_dir` (with the pattern as a glob path fact), `Bash` to `run_command` with the string split by `shlex` and any shell operator (`| ; & $ \` > < ( )` and newlines) read as `unknown` (since 2026-11-17 split by the plain word grammar instead, docs/design/spec-verified-classifier.md section 4). Anything else is `unknown`. The workspace is `CLAUDE_PROJECT_DIR`. A new default policy, `agent_default`, starts from `agent_rules` and differs in one way: `unknown` escalates instead of refusing, so a person is asked instead of stopped. New causes are appended, never renumbered. Check: recorded hook inputs for every row of the adversary set give the expected answer; the classifier's existing tests pass.

**A3 Receipts across processes.** Each hook call is a new process, so the run is a directory with a lock: the call takes the lock, appends one receipt, and releases. A `SessionEnd` hook, or `agent verify`, seals the run into a signed root statement. A run left open by a crash is sealed by the next `verify`, and nothing is lost. Check: 200 concurrent hook calls give 200 receipts in one run that verifies; a killed call leaves the run verifiable.

**A4 The commands.** `init`, `hook`, `verify`, `status` as above, with a `--json` answer for each. Startup cost is measured: the hook must answer within 150 ms on the floor tier, or the hot path is trimmed (lazy imports, no numpy). Check: the measurement is in the PR.

**A5 Ten minute walkthrough.** `docs/guides/governed-agent.md`: install, `prismpath agent init`, start Claude Code, ask it to list the project (allowed), to delete a file outside the project (refused with its cause), to push (asked), then `prismpath agent verify` and the tamper demo. Every command in it runs in CI against a scripted hook input, so the guide cannot drift.

**A6 MCP proxy (second adapter).** A stdio MCP proxy that sits in front of any MCP server and decides each `tools/call` the same way, for agents other than Claude Code. Separate PR, after A1 to A5 merge.

## 4. Order and gates

A1 alone first, since everything imports it. Then A2 and A3 in parallel, then A4, then A5. A6 last. Each lands as a research PR with all checks green; the product picks it up by export. Gates per PR: the research tests, the harness tests and probes, and an export with `tools/acceptance.sh --leg full` inside it.
