# Routing tests for `triage.md` — the fixture rows CI asserts

Run with `python -m prismpath.cli test examples/pr_demo/triage.md`. Every row is deterministic —
no model, no network; this table runs in CI in milliseconds. The first row is the one the PR
adds: it *is* the process change, asserted.

| node     | outcome                                   | fields                                      | expect       |
|----------|-------------------------------------------|---------------------------------------------|--------------|
| classify | customer disputes a $700 charge           | category=billing_dispute; amount=700        | human_review |
| classify | customer disputes a $200 charge           | category=billing_dispute; amount=200        | billing      |
| classify | question about an invoice line item       | category=billing; amount=0                  | billing      |
| classify | the dashboard is completely down          | category=outage; amount=0                   | outage       |
| classify | long-time customer threatening to leave   | category=other; amount=0; sentiment=angry   | retention    |
| classify | how do I reset my password                | category=other; amount=0; sentiment=neutral | general      |
