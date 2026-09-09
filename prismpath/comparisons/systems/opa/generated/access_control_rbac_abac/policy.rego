package comparison.access_control_rbac_abac

decision := {"outcome": "allow", "rule": "r1"} if {
    input.user_role == "admin"
}
else := {"outcome": "deny", "rule": "r2"} if {
    input.resource_sensitivity == "high"
    input.user_role != null
    not input.user_role in {"admin", "manager"}
}
else := {"outcome": "allow", "rule": "r3"} if {
    input.user_id == input.resource_owner_id
}
else := {"outcome": "allow", "rule": "r4"} if {
    input.action == "read"
    count({x | x := input.user_groups[_]} & {x | x := input.resource_groups[_]}) > 0
}
else := {"outcome": "allow", "rule": "r5"} if {
    data.hierarchy[input.user_role] >= data.hierarchy["manager"]
    input.action in {"read", "write"}
    input.hour_utc >= 8
    input.hour_utc < 18
}
else := {"outcome": "deny", "rule": "r6"}
