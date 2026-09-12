---
name: normal_policy
start: tick
---

## tick
Once a second, for one camera, at the relay or the receiver: whether the normal it measures against
should stay, be replaced, or be looked at. `quiet_s` is the seconds since the camera's last route with
motion (occupied, door or evidence); `departed_pct` is the share of cells departed from the normal on
its last reading; `scene_changed` and `tamper` are the camera's own escalations, 1 while they hold;
`operator` is 1 for the tick on which an operator asked for adoption; `living` is the deployment's
choice, 0 for a fixed normal (an empty lot, an office out of hours), 1 for a living normal (a space
where people are normal and what matters is what outlasts them); `quiet_for` is the deployment's quiet
period in seconds for a living normal. The guards come first: nothing is adopted while the camera says
tamper or scene_changed, whatever the rule, and an operator's request under those conditions is
escalated, not obeyed.
@emits(quiet_s, departed_pct, scene_changed, tamper, operator, living, quiet_for)
-> escalate: when tamper
-> escalate: when scene_changed
-> adopt_operator: when operator
-> adopt_quiet: when living and quiet_s >= quiet_for and departed_pct >= 10
-> hold_drift: when living == 0 and departed_pct >= 25 and quiet_s >= 60
-> hold: else

## escalate
The camera itself says its normal cannot be trusted (a covered lens, a lit or moved scene): no
adoption by anyone until a person has looked; the evidence frame is already on its way.

## adopt_operator
An operator asked and nothing forbids it: the current frame becomes the normal, a keyframe with the new
id follows, and the receipt names the id it replaced.

## adopt_quiet
A living normal: the space has been quiet for the deployment's period and at least a tenth of it has
departed from the old normal, so what the space usually looks like has moved and the normal moves with
it. A receipt names both ids. People are not adopted because they are never quiet for the period.

## hold_drift
A fixed normal that has drifted a quarter of the frame with nothing moving for a minute: the normal
stays, because in this deployment the departure is the signal (a car that stayed, a door left open),
and the map route keeps reporting it. Worth a person's look, not an adoption.

## hold
Nothing to do: the normal stands.
