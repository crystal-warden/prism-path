---
name: room_fusion
version: 2
start: room
---

## room
Two cameras on one room, fused on the host relay from the readings it forwards and its own receive
clock. `a_fresh` and `b_fresh` are 1 while a camera's last reading is younger than the freshness window;
a camera that goes quiet is not missing, it is STALE, and that is a state this policy decides on.
`a_occ_age` and `b_occ_age` are the milliseconds since the camera last said someone is there (occupied,
door or evidence), 65535 if never: a person whose motion pauses for a moment is still there, so presence
holds for two seconds after the last such route, and the hold is this policy's constant, not the relay's.
`a_tamper` and `b_tamper` are 1 when the camera's last route said tamper. The room's verdict is traceable to the two
readings it was made from, which the decision record names by sequence.
@emits(a_fresh, b_fresh, a_occ_age, b_occ_age, a_tamper, b_tamper)
-> blind: when a_fresh == 0 and b_fresh == 0
-> tamper: when (a_fresh and a_tamper) or (b_fresh and b_tamper)
-> degraded_present: when (a_fresh == 0 and b_occ_age < 2000) or (b_fresh == 0 and a_occ_age < 2000)
-> degraded_clear: when a_fresh == 0 or b_fresh == 0
-> conflict: when (a_occ_age < 2000 and b_occ_age >= 2000) or (a_occ_age >= 2000 and b_occ_age < 2000)
-> present: when a_occ_age < 2000 and b_occ_age < 2000
-> clear: else

## blind
Neither camera is fresh: the room has no verdict and says so.

## tamper
A fresh camera reports tamper: escalate, the room's verdict is not trusted until a person looks.

## degraded_present
One camera is stale and the other saw someone within the hold: present, on one witness, flagged degraded.

## degraded_clear
One camera is stale and the other sees nobody: clear, on one witness, flagged degraded.

## conflict
Both fresh and they disagree about presence: the disagreement is the verdict, escalated, never averaged.

## present
Both fresh and both saw someone within the hold: a quorum of two.

## clear
Both fresh and neither sees anyone: a quorum of two.
