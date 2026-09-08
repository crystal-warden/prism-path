---
name: access_control_rbac_abac
start: decide
---

## decide
Expressiveness: role hierarchy, ownership, group intersection, and a time window in one policy
The worker reports the request as fields; the edges below are the policy, first true wins.
@emits(user_id, user_role, user_groups, resource_owner_id, resource_groups, resource_sensitivity, action, hour_utc)
-> r1_allow: when user_role == "admin"
-> r2_deny: when (resource_sensitivity == "high") and (user_role not in ("admin", "manager"))
-> r5_allow: when (user_role in ("manager", "admin")) and (action in ("read", "write")) and (hour_utc >= 8) and (hour_utc < 18)
-> r6_deny: else

## r1_allow
admins do anything

## r2_deny
high sensitivity is management only, ownership notwithstanding

## r5_allow
managers read and write in business hours

## r6_deny
default deny
