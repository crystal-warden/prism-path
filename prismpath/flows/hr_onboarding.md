---
name: hr_onboarding
start: intake
---

## intake
Collect the new hire's paperwork status. Emit `role`, `docs_complete`, `equipment_ordered`,
and `start_days` (days until the start date).
@emits(role, docs_complete, equipment_ordered, start_days)
-> escalate_hr: when visits > 6
-> chase_docs: when not docs_complete and start_days <= 5
-> order_equipment: when docs_complete and not equipment_ordered
-> provision: when docs_complete and equipment_ordered
-> waiting_room: else

## chase_docs
Start date is inside a week and paperwork is incomplete — notify the recruiter and the hiring
manager, then wait for the missing documents.
-> intake: on event docs_received
-> escalate_hr: on timeout

## order_equipment
Place the laptop/badge order for the role, then re-check readiness.
-> intake: always
-> escalate_hr: on error when error_count >= 2
-> order_equipment: on error

## provision
Create the accounts (email, SSO, payroll). Anything unusual — a duplicate identity, a role with
elevated access — suspends for a human instead of guessing.
@emits(provisioned, needs_review)
-> escalate_hr: when visits > 3
-> security_review: when needs_review
-> ready: when provisioned
-> escalate_hr: else

## security_review
A person approves elevated access or resolves the identity conflict, then provisioning resumes.
-> provision: the reviewer approved — finish provisioning
-> escalate_hr: the reviewer rejected or found a conflict

## waiting_room
Paperwork pending with time to spare — wait for the docs webhook or check back tomorrow.
-> intake: on event docs_received
-> intake: on timeout

## ready
Day-one ready: accounts live, equipment shipped, checklist archived.

## escalate_hr
A human in HR owns it from here, with the full transcript as the evidence packet.
