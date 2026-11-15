# governed_worker · gates decide, claims are advisory

A pattern for anyone running autonomous coding agents: the agent's "done, everything passes" is
the least trustworthy sentence in your pipeline. Agents overclaim. The fix is not trusting them
harder; it is a control flow where the claim can never route anything.

## The pattern

1. **Quarantine the work.** The worker runs in an isolated workspace (a git worktree is ideal): a
   rejected run is a discarded directory, zero blast radius, fail closed.
2. **Gates decide.** A sandboxed code node runs the task's real gates (tests, build, lint) and the
   flow routes on their exit codes. The worker's claim enters the state as one advisory field.
3. **Lies get a name.** The edge `when claimed_success and not gates_pass` routes to its own
   verdict, `reject_lie`. Over time the claim versus gate record becomes a measured reliability
   rate for each worker, which is far more useful than a grudge.
4. **The selection rule.** If you cannot write the gate, do not send the task. A task whose
   done-ness is not mechanically checkable is not a task for an untrusted worker.

The flow is nine lines of routing. Everything load bearing is decidable: `prismpath verify` can
prove that no path reaches `accept` without `gates_pass`, which is the whole point stated as a
checkable property.

## Run it

```bash
PYTHONPATH=prismpath/examples/governed_worker \
  python prismpath/examples/governed_worker/run_demo.py
```

No model, no network; Linux + bwrap for the code-node sandbox. Three scripted workers go through:
an honest success, an honest failure, and a liar that claims success while its gates fail. The
demo asserts all three verdicts and exits nonzero if any is wrong, so it doubles as its own
regression test.

## Wire a real agent

Replace the scripted scenarios with a driver that: creates a detached git worktree; launches your
CLI agent against it (with a timeout, and kill its process group on expiry, never a pattern
match); parses the agent's own report into `claimed_success`; runs the gates (driver side if they
write, since the sandbox is read only); passes `precomputed_gates` into the flow; merges on
`accept`, discards the worktree otherwise; and appends `{claimed, verdict, agreement}` to a
reliability log. Two practical rules from running this against a real agent: verify the tree you
are merging into is clean before any write, and make gates vacuity proof (assert the files the
task demands exist, so an agent that does nothing cannot pass on a green exit code alone).

The composition seam is the same one every code-node flow uses:
`code_agent(graph, handlers, runner=SandboxRunner(), base=...)`; see
[`code_nodes_gemma`](../code_nodes_gemma/) for mixing gated code nodes with an LLM worker in one
governed flow.
