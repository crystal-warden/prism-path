---
name: incident_severity
start: assess
---

## assess
Read the incoming alert and classify it. Emit `user_facing` (bool), `error_rate` (percent of
requests failing, 0–100), and `data_at_risk` (bool).
@emits(user_facing, error_rate, data_at_risk)
-> sev1_page: when data_at_risk
-> sev1_page: when user_facing and error_rate >= 25
-> sev2_oncall: when user_facing and error_rate >= 5
-> sev3_ticket: when error_rate >= 1
-> watch: else

## sev1_page
Page the on-call lead and open a bridge — customer-facing or data-at-risk.

## sev2_oncall
Notify on-call; user-facing but contained.

## sev3_ticket
File a ticket for business hours.

## watch
Log and keep an eye on it.
