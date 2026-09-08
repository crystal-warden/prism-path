package comparison.ai_action_gate

decision := {"outcome": "escalate_human", "rule": "r1"} if {
    input.human_requested == true
}
else := {"outcome": "deny", "rule": "r2"} if {
    input.data_class == "cui"
    input.target_scope == "external"
}
else := {"outcome": "deny", "rule": "r3"} if {
    input.action_class == "delete"
    input.reversible == false
    input.target_scope in {"org", "external"}
}
else := {"outcome": "escalate_human", "rule": "r4"} if {
    input.action_class in {"send_external", "execute"}
    input.data_class in {"confidential", "cui"}
}
else := {"outcome": "abstain", "rule": "r5"} if {
    input.worker_confidence < 60
}
else := {"outcome": "allow", "rule": "r6"} if {
    input.action_class == "read"
}
else := {"outcome": "allow", "rule": "r7"} if {
    input.reversible == true
    input.target_scope in {"own", "team"}
}
else := {"outcome": "escalate_human", "rule": "r8"}
