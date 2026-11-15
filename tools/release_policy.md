---
name: release_eligibility
start: assess
---

## assess
Read the acceptance facts for one artifact set: which leg ran, how many gates failed or never ran,
whether the compatibility, provenance, boundary, skip budget, reproducibility and end to end gates
passed, and whether every required piece of evidence is present. Emit `leg`, `evidence_complete`,
`gates_failed`, `gates_missing`, `compatibility_ok`, `provenance_ok`, `boundary_ok`, `skip_budget_ok`,
`reproducible_ok`, `end_to_end_ok`.
-> missing_evidence: when not evidence_complete
-> eligible: when leg == "full" and gates_failed == 0 and gates_missing == 0 and compatibility_ok and provenance_ok and boundary_ok and skip_budget_ok and reproducible_ok and end_to_end_ok
-> refused: else

## missing_evidence
A required report or gate row is absent. Nothing is decided about the artifacts; the run is not
evidence of anything until the missing piece exists.

## eligible
Every required gate passed on the full leg with the evidence present. The artifacts named in the
receipt may be offered for the owner's release decision.

## refused
A required gate failed, a gate never ran, or the leg was not the full one. The artifacts are not
eligible; the receipt names which fact refused them.
