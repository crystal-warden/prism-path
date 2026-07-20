---
name: support_triage
start: classify
---

## classify
Read the incoming support ticket. Emit `category` (billing, billing_dispute, outage, or other),
`amount` (the disputed USD amount; 0 if not applicable), and `sentiment`.
@emits(category, amount, sentiment)
-> billing: when category in ("billing", "billing_dispute")
-> outage: when category == "outage"
-> retention: when sentiment == "angry"
-> general: else

## billing
The standard billing queue.

## outage
Page the on-call engineer.

## retention
Route to a retention specialist.

## general
The general support queue.
