# Routing tests for `overlay.md`

Run with `prismpath test prismpath/examples/operator_overlay/overlay.md`. Every row is deterministic.
The first two rows are the operator's change in force: the same request goes to `heightened` when an
incident is active and to the baseline outcome when it is not. The timer and stand down paths are
event edges, exercised by `prismpath/tests/test_operator_overlay.py` with a real suspension and
resume.

| node | outcome                                   | fields                                                   | expect     |
|------|-------------------------------------------|----------------------------------------------------------|------------|
| gate | external scan during the incident         | severity=2; source_internal=false; incident_active=true  | heightened |
| gate | the same scan with no incident declared   | severity=2; source_internal=false; incident_active=false | observe    |
| gate | internal request during the incident      | severity=3; source_internal=true; incident_active=true   | heightened |
| gate | internal request, no incident             | severity=3; source_internal=true; incident_active=false  | allow      |
| gate | severity four is refused regardless       | severity=4; source_internal=true; incident_active=false  | deny       |
| gate | quiet external traffic during the incident| severity=1; source_internal=false; incident_active=true  | observe    |
