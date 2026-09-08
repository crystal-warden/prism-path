package comparison.expense_approval

cond_r2 if {
    object.get(input, "receipt_present", null) == null
}
cond_r2 if {
    input.receipt_present == false
}

decision := {"outcome": "deny", "rule": "r1"} if {
    input.vendor_risk == "high"
}
else := {"outcome": "abstain", "rule": "r2"} if {
    cond_r2
}
else := {"outcome": "escalate_human", "rule": "r3"} if {
    input.amount_cents > 1000000
}
else := {"outcome": "escalate_human", "rule": "r4"} if {
    input.category == "other"
    input.amount_cents > 50000
}
else := {"outcome": "allow", "rule": "r5"} if {
    input.amount_cents <= 50000
}
else := {"outcome": "allow", "rule": "r6"} if {
    input.requester_role in {"manager", "director"}
    input.amount_cents <= 1000000
}
else := {"outcome": "escalate_human", "rule": "r7"}
