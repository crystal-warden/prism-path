# The process owner's guide

You own the policy of record: the long term statement of what the system is allowed to do. You are not
expected to be an engineer. The flow document is yours, the tests beside it are yours, and a change to
production is a diff of that document that you can read.

## 1. What you write

A flow: a Markdown file where each `## heading` is a step and each `-> target: condition` an edge. The
prose under a heading is the instruction a worker follows; the edges are the decisions. Deterministic
edges (`when <expression>`, `else`) decide first and in document order; a plain language edge hands the
decision to an embedding router and, on doubt, to a person. The authoring reference is
[`authoring.md`](authoring.md); the canonical example is `prismpath/examples/pr_demo/triage.md`.

Two rules that keep the policy honest:

- Every field you compare against must be emitted by the step, declared with `@emits(...)`. The
  engineer's contract is derived from those declarations, so adding a field here is a change to the
  interface they build against.
- Spell booleans by truthiness (`when incident_active`), integers and strings by comparison; the
  deterministic fragment (Level M) is exactly what every substrate can execute, and `prismpath capability`
  tells you when an edge left it.

## 2. What you run

```bash
prismpath validate flow.md      # does it compile: undefined targets, dead branches, unbounded cycles
prismpath test flow.md          # the fixture table beside the flow, asserted with no model
prismpath graph flow.md         # the flow as a diagram, solid = deterministic, dashed = semantic
prismpath context flow.md       # the proven facts about the flow, as grounding for an assistant editing it
prismpath lint flow.md          # ambiguous semantic conditions (needs the embedder)
```

The fixture table is a Markdown table of `node`, `outcome`, `fields`, `expect` rows. It is the process
change stated as a test: when you change a rule, you add the row that proves it. `prismpath test` runs
in milliseconds and CI runs it on every pull request, rendering the before and after graph in the review.

## 3. How a change reaches production

1. You edit the flow and add or change fixture rows. `validate` and `test` pass locally.
2. The pull request shows the diff of the document and the diff of the graph. That is the review.
3. The engineer's `contract` says whether any interface moved. If not, nothing on their side changes.
4. The engineer compiles and packs the deterministic fragment; the operator swaps it in and attests.
5. The evaluator can later point at the receipt of any decision and at the version of your document that
   produced it.

## 4. Who you hand off to

The [engineer](engineer.md) establishes the input schema once from your `@emits` declarations and owns
calibration and delivery. The [operator](operator.md) runs the system day to day and may author short
lived changes on top of your policy; those expire by construction and never replace the policy of
record, and the trail shows when one is in force. The [evaluator](evaluator.md) reads the receipts.

## 5. Where to look next

[`docs/SYSTEM_MAP.md`](../SYSTEM_MAP.md) for the whole system, [`tour.md`](tour.md) for a ten minute
walk through, `prismpath/examples/` for flows written for people in your position.
