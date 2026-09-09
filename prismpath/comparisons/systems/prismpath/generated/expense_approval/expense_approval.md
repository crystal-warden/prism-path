---
name: expense_approval
start: decide
---

## decide
Expense approval: allow, deny, abstain on missing evidence, escalate to a person
The worker reports the request as fields; the edges below are the policy, first true wins.
@emits(amount_cents, category, requester_role, receipt_present, vendor_risk)
-> r1_deny: when vendor_risk == "high"
-> r2_abstain: when not receipt_present
-> r3_escalate_human: when amount_cents > 1000000
-> r4_escalate_human: when (category == "other") and (amount_cents > 50000)
-> r5_allow: when amount_cents <= 50000
-> r6_allow: when (requester_role in ("manager", "director")) and (amount_cents <= 1000000)
-> r7_escalate_human: else

## r1_deny
blocked vendor, no amount makes it acceptable

## r2_abstain
insufficient evidence: no receipt, so nothing is decided and nothing is paid

## r3_escalate_human
above ten thousand dollars a person signs

## r4_escalate_human
uncategorized spend above five hundred dollars needs a person

## r5_allow
small, receipted, low risk

## r6_allow
managers self approve to ten thousand

## r7_escalate_human
an employee above five hundred dollars goes to a manager; the catch all is the fail safe
