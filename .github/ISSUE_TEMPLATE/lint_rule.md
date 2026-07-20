---
name: Lint rule (good first issue)
about: Propose or claim a new decidable static-analysis check
labels: good first issue, lint
---

**The mistake it catches.** A flow-authoring error a real author makes.

**A broken flow that triggers it** (goes in `tests/fixtures/broken/`):

```markdown

```

**Severity.** error (breaks the run) or warning (likely mistake that still runs)?

**Decidability check.** Confirm it stays inside the `when`-language fragment and produces **zero
false positives** on the shipping flows — that's the bar (see CONTRIBUTING.md → "The perfect
first contribution").

_If you're claiming one of the ten in CONTRIBUTING.md, name it here._
