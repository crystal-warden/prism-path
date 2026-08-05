# Council — the deliberation expansion (optional; the exception, not the default)

The default PrismPath shape is a **flow**: one worker per node, edges routing on the outcome. The
council pattern is what a spec-driven build loop grew when single-voice decisions kept fixating:
several voices **propose**, a weighted **vote** picks, and a **seeded dice roll** steers the round
toward neglected territory. Keep it demoted in your mental model — reach for a
council only after a plain flow has demonstrably plateaued on a decision that benefits from
deliberate diversity (design/expand rounds, contested triage). Everything else is better served by
an ordinary edge.

## Why it lives here (and what made it worth keeping)

The two pieces shipped as workers are the *auditable* core the pattern discovered:

- **`council.roll`** (`dice.py`) — structured, **seeded** stochasticity. The round key + the project
  file set seed the RNG, so the same state always rolls the same mandate: exploration you can replay
  in a review instead of vibes. Direction weight = coverage (missing axes 3× likelier) × balance
  (a ledger of past selections discounts over-chosen axes).
- **`council.tally`** — the same balance weighting applied to votes ({voter: category}), with a
  deterministic tie-break. An over-built category's votes count for less, so growth stays balanced
  without a human referee.

LLM-backed **voices** (propose/critique) deliberately stay in *your* harness — they're model calls,
composed around these two deterministic anchors. The auditability story is exactly that split: the
model parts are ordinary workers you already log; the selection machinery is seeded, weighted, and
replayable.

## Wiring it

```markdown
## steer
Roll the expansion mandate for this round.
@worker(council.roll)
-> propose: always

## propose
Draft one proposal per voice for the mandate.       <- your LLM worker(s), plain prismpath
-> tally: always

## tally
Weigh the votes; select the category.
@worker(council.tally)
-> execute: when winner
-> steer: when not winner
```

```python
from prismpath.plugins import registry
agent = registry.worker_agent(graph, default=my_llm_agent)   # bound nodes -> plugin, rest -> yours
```

`prismpath plugins --check flow.md` verifies the bindings resolve before anything runs;
`prismpath plugins` shows what's installed. Outcomes from bound nodes carry `_worker` provenance in the
transcript.
