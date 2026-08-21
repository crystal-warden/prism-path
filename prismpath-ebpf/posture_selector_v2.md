---
name: posture_selector_v2
start: normal
safe: lockdown
migration: by-name
---

A reindexed revision of `posture_selector`: the SAME posture ladder and the SAME node names, but the
sections are declared in a different order, so the compiled node indices differ (normal=0, lockdown=1,
elevated=2 here, vs normal=0, elevated=1, lockdown=2 in v1). That is exactly the hazard by-name
migration exists for: carrying a raw resident index across this swap would reinterpret the posture, so
the loader re-resolves it by NAME.

## normal
Baseline admission posture.
-> elevated: when ev == 1
-> normal: else

## lockdown
Maximum posture: only a de-escalate event steps back.
-> elevated: when ev == 2
-> lockdown: else

## elevated
Heightened posture: an escalate event locks down, a de-escalate returns to normal.
-> lockdown: when ev == 1
-> normal: when ev == 2
-> elevated: else
