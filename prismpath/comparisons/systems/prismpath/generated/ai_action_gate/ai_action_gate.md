---
name: ai_action_gate
start: decide
---

## decide
AI worker action gate: a model proposes a pre specified action, the policy returns allow, deny, abstain, or a person, with a receipt per decision
The worker reports the request as fields; the edges below are the policy, first true wins.
@emits(action_class, target_scope, reversible, data_class, worker_confidence, human_requested)
-> r1_escalate_human: when human_requested
-> r2_deny: when (data_class == "cui") and (target_scope == "external")
-> r3_deny: when (action_class == "delete") and (reversible == False) and (target_scope in ("org", "external"))
-> r4_escalate_human: when (action_class in ("send_external", "execute")) and (data_class in ("confidential", "cui"))
-> r5_abstain: when worker_confidence < 60
-> r6_allow: when action_class == "read"
-> r7_allow: when (reversible) and (target_scope in ("own", "team"))
-> r8_escalate_human: else

## r1_escalate_human
the worker asked for a person; honored before anything else

## r2_deny
controlled data never leaves

## r3_deny
irreversible destruction beyond the team is refused outright

## r4_escalate_human
sensitive data leaving or code running needs a person

## r5_abstain
the worker is not sure; nothing is acted on

## r6_allow
reads are safe once the above are cleared

## r7_allow
reversible and local

## r8_escalate_human
anything else goes to a person
