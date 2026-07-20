---
name: support_triage
start: classify
---

## classify
Read the incoming support ticket. Emit `category` (billing, billing_dispute, outage, or other),
`amount` (the disputed USD amount; 0 if not applicable), and `sentiment`.
@emits(category, amount, sentiment)
-> human_review: when category == "billing_dispute" and amount > 500
-> billing: when category in ("billing", "billing_dispute")
-> outage: when category == "outage"
-> retention: when sentiment == "angry"
-> general: else

## human_review
A person decides. High-value billing disputes are never auto-routed — the customer gets a human,
and the decision gets an owner.

## billing
The standard billing queue.

## outage
Page the on-call engineer.

## retention
Route to a retention specialist.

## general
The general support queue.
