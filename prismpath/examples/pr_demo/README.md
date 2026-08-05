# The money demo — "The PR is the process change"

Thirty seconds that show the category shift instead of arguing it: a PM changes one routing
rule **in prose**, CI asserts the new behavior **with a fixture row**, and merging the PR *is*
the production change. No deploy, no engineer, no framework.

The change: *billing disputes over $500 now route to a human.* In `triage.md` that is one edge
line plus its target node:

```diff
+-> human_review: when category == "billing_dispute" and amount > 500

+## human_review
+A person decides. High-value billing disputes are never auto-routed.
```

And one fixture row in `triage.tests.md` asserts it forever:

```
| classify | customer disputes a $700 charge | category=billing_dispute; amount=700 | human_review |
```

## Run it

```bash
bash prismpath/examples/pr_demo/demo.sh
```

Shows the diff → `prismpath validate` (clean) → `prismpath test` (6/6, deterministic, milliseconds,
no model) → `prismpath portable` (P0 — this policy also runs on the browser/edge kernel).

## Recording the GIF

Terminal at ~100×30, a slow-ish font size, then:

1. `git diff` view of the change (or just let `demo.sh` print it) — hold 4s on the diff.
2. Let the three CI steps scroll — the green fixture rows are the payoff frame; hold on `6/6 passed`.
3. End card on the final line: **"Merge. Production routing changed. The PR was the process change."**

`asciinema rec` + `agg` (or `vhs`) both work; keep it under 30 seconds. The second demo for the
compliance audience — an uncertain alert suspending with its evidence packet, a human picking the
edge in Mission Control, the run resuming with attribution — records against the queue tab with
any `needs_human` flow (e.g. the playground's "human handoff" preset run through `run_durable`).

Files: `triage.md` (after), `triage.before.md` (before, for the diff), `triage.tests.md`
(the CI assertion), `demo.sh` (the whole sequence, colorized).
