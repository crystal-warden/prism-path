---
name: posture_selector
start: normal
safe: lockdown
---

## normal
Baseline admission posture.
-> elevated: when ev == 1
-> normal: else

## elevated
Heightened posture: an escalate event locks down, a de-escalate returns to normal.
-> lockdown: when ev == 1
-> normal: when ev == 2
-> elevated: else

## lockdown
Maximum posture: only a de-escalate event steps back.
-> elevated: when ev == 2
-> lockdown: else
