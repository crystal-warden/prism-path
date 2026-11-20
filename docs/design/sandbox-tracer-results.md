# Sandbox tracer: results

Written 2026-11-20 against branch `sandbox-observe`, which holds PR #65 (`sandbox-hook`) and WP5 to WP7 of `docs/design/enforcement-points-plan.md` section 4.

## What the tracer guarantees

On Linux, an allowed Bash call in the Claude Code hook runs inside bubblewrap under a profile compiled from the same signed policy image (`prismpath/agent/sandbox_hook.py`, `prismpath/agent/sandbox_exec.py`, `prismpath/agent/profile.py`). The command and every child it starts see only `/usr` and the workspace, have no network unless the image allows one, and are bounded by a process and a time limit. If the profile does not compile or bwrap is missing, the call is denied with cause 129.

`prismpath/tests/test_sandbox_adversary.py` measures this. The policy there allows a script that changes files in the workspace to run. Each of `python3 tool.py` and `sh build.sh` opens a decoy secret under `/var/tmp`, writes beside it and connects to a listener on the host's own non-loopback address. Run as the hook alone allowed it (the original command, which is what main does), the script reaches all three. Run as the rewritten command, it reaches none. Both runs are asserted, so the old gap stays measured.

The test also shows the compiler being strict in the right direction. A first draft of the allow rule did not name `git_op`, so some allowed readings could be a network git operation, and `compile_profile` gave that image a network. Naming `git_op == "none"` removed it.

## What it does not guarantee

- Claude's own Read, Write and Edit tools run in Claude Code's process and are not confined.
- A question the person approves in Claude Code's prompt runs as the model wrote it, without the sandbox, because only an `allow` carries `updatedInput` (`hook_answer` in `prismpath/agent/claude_code.py`). The default policy asks for any script that changes files, so approving one runs it unconfined. This is open.
- macOS and Windows are decided and not confined (`sandbox_hook.supported`).
- A kernel escape, or a bwrap flaw, defeats it. There is no seccomp filter and no PID namespace limit beyond `--unshare-all`.
- The profile hash is on the journal line beside the receipt, not in the signed root. The receipt format `prismpath.core-receipt/1` is unchanged, so the oracle replay does not see the profile, and a journal line is bound only by the journal's own check.
- The hook's settings file is protected by the control-file rule (cause 128), not by the sandbox.

## Observations (WP6)

When a sandboxed command shows on standard error that an access was stopped, the runner records an observation in `observations.jsonl` in the run directory (`prismpath/agent/observe.py`, `Run.observe` in `prismpath/agent/run.py`). Each entry carries the receipt index and the receipt's SHA-256, the image hash, the profile hash, what was seen (exit status, time-out, matched error lines cut to 200 characters), the hash of the previous entry and its own hash. `Run.verify_observations`, called from `Run.verify` and so from `prismpath agent verify`, checks every entry against the journal and refuses a damaged or unbound one. `prismpath agent rules` reads only the journal, so observations are not rule hits, and a test checks its report is unchanged by them.

Design choices:

- bwrap reports no denied open, and seccomp or Landlock audit was not used because it needs privilege or a kernel facility. The method is the command's error text, recorded as `method: "stderr-pattern"`. It misses a refusal the command hides, and `No such file or directory` is recorded as `path-absent` because a path the sandbox did not mount and a missing file read the same.
- The format is a separate, separately hashed file, not a change to `core-receipt/1` or the root. The cost is that the file is outside the signed root, so removing lines from its end is not detected.
- Observations change nothing. No code that decides reads them, and no policy, profile or rule is written from one. A proposal for a new rule from a cluster of observations is for a later package and would need the signed envelope of section 3 of the plan.

The hook now appends the receipt before it builds the rewritten command, so the runner can name the receipt. A rewrite that cannot be built after the append cannot happen, since the command is checked first.

## Latency

Measured on the gx10 (aarch64, 20 cores), through the real hook process (`python -c` calling `commands.hook_main`, as Claude Code does) for an allowed `ls -la`, 60 calls each, profile cache warm unless said.

| | median | p95 |
|---|---|---|
| hook, sandbox switched off | 74 ms | 80 ms |
| hook, sandboxed, cache warm | 72 ms | 82 ms |
| hook, sandboxed, cache cold (5 runs) | 3312 ms | 3315 ms |
| running `ls -la` plain | 1.2 ms | 2.2 ms |
| running it through the runner and bwrap | 40 ms | 57 ms |

The hook is inside the 150 ms budget of A4 in `docs/design/governed-agent-plan.md`, and the sandbox adds nothing measurable to it when the cache is warm. The cold figure is the profile compile, which walks the image's whole allow set. `prismpath agent init` compiles it ahead, so it is paid once per policy, and it is over budget if a policy changes and the cache is not warmed. The sandbox itself adds about 40 ms to the command's own run. The floor tier (Protectli N150) was not measured.

## Where the sandbox is stricter than the oracle (WP4)

`prismpath/tests/test_profile_differential.py` lists each case where the oracle allows and the sandbox stops it. There is one, a `git push` to the allowed remote: the starters allow it, the profile has no network, and the remote is outside the workspace. A push counts as no network need in `compile_profile` for that reason. The test fails if the sandbox allows anything the oracle refuses or escalates, and fails if a stricter case has no recorded reason.

## Gate

With `PRISMPATH_REQUIRE_CORE_ORACLE=1` and the Lean oracle built: `prismpath/tests` 2922 passed, 46 skipped; `integrations/governed_harness/tests` 184 passed; the adversary probes ran 51 cases with 0 out-of-policy executions, 0 wrong causes, 51 receipts verified and 54 replays through the oracle. The live Claude Code check could not be run, see the PR.
