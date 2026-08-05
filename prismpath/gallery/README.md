# The flow gallery — real workflows, contributed by the people who run them

Most tools can only be extended by programmers. This one can be extended by **anyone who owns a
process**, because a flow is a Markdown document — not code. If you route support tickets,
triage alerts, gate releases, onboard people, or make any repeatable "look at the outcome,
decide what's next" decision, your workflow is a welcome contribution.

Every entry here **doubles as a starter**: `prismpath init --template <name>` scaffolds your flow +
its tests into someone's working directory (`--template list` enumerates them). Contributing a
gallery entry is contributing a template.

## What a gallery entry is

A directory `prismpath/gallery/<your-flow-name>/` containing:

1. **`<name>.md`** — the flow. It must `prismpath validate` clean (`pip install -e .` then
   `prismpath validate prismpath/gallery/<name>/<name>.md`). Keep worker prose generic — no secrets, no
   internal hostnames, no customer data.
2. **`<name>.tests.md`** — a fixture table asserting the key routing decisions (at least the
   ones that matter). This is what proves your flow does what you say; `prismpath test` runs it
   with no model.
3. **`README.md`** — one paragraph: what real decision this makes, and who reads it. Say what
   *tier* it is if you know (`prismpath portable <name>.md`), but you don't have to.

That's the whole bar. You do not need to write Python, run an LLM, or understand the engine.

## Submitting

Open a PR adding your directory. CI runs `prismpath validate` + `prismpath test` on it automatically
(see [`action.yml`](../../action.yml)). A maintainer checks that the prose is generic and the
fixtures assert something real, and merges. Sign your commit (`git commit -s`).

## Starting points

The [persona examples](../examples/README.md) are gallery-shaped already — copy the one closest
to your domain and change the decisions. Good first entries we'd love: fraud/chargeback triage,
content-moderation escalation, incident severity routing, procurement approval, patient-intake
routing, lead qualification, code-review assignment. If your domain isn't listed, that's the
best reason to add it.
