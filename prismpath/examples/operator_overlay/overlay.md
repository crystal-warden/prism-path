---
name: operator_overlay
start: gate
---

## gate
The baseline posture, the policy of record. Read one request and emit `severity` (0 to 5, the
detector's score), `source_internal` (true for traffic from inside the enclave), and
`incident_active` (true while the operator has declared an incident).
@emits(severity, source_internal, incident_active)
-> escalate: when visits > 3
-> heightened: when incident_active and severity >= 2
-> deny: when severity >= 4
-> allow: when source_internal
-> observe: else

## heightened
The operator's short lived change. While an incident is active, anything at or above severity 2 is
held here for review instead of being allowed or observed. The worker suspends the run
(`{"wait": true, "timeout_s": 3600}`); the hold ends when the operator stands down or when the
timer expires, and either way the run returns to the baseline posture. The change expires by
construction: no pack metadata, no second policy, one signed flow.
-> gate: on event stand_down
-> gate: on timeout

## escalate
A request has been held and released more than three times in one run: hand it to a person rather
than cycle again. This caps the hold and release loop the validator would otherwise flag as unbounded.

## deny
Refused at the baseline posture. Severity 4 and above never needs an incident to be refused.

## allow
Internal traffic below the refusal line is allowed.

## observe
External traffic below the refusal line is observed, not blocked.
