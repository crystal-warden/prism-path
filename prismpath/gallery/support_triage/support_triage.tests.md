# Routing tests — `prismpath test support_triage.md` (deterministic rows, no model needed)

| node            | outcome                                     | fields        | expect  |
|-----------------|---------------------------------------------|---------------|---------|
| bug_report      | checkout is down for all users              | severity=high | escalate|
| billing         | disputed enterprise invoice                 | amount=1200   | escalate|
| billing         | small double-charge, refunding on the spot  | amount=18     | resolve |
| feature_request | wants CSV export on the dashboard           |               | resolve |
| general_question| how do I rotate my API key?                 |               | resolve |
