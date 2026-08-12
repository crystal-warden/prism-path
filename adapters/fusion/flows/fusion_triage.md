---
name: fusion_triage
start: intake
---

## intake
One fused observation per adjudicated SIEM alert: the alert's cyber verdict (rule_level and
soc_action) joined with the device's physical posture for the same window (stability and dev_mg,
the sensor bridge's own fields). Every threshold in this flow is a real operational boundary
inherited from the systems that produce the fields — none exists to shape the decision space:
150 / 500 / 2500 dev_mg are the bridge's DEADBAND / MOVE_DEV / SHAKE_DEV constants (x1000);
7 and 12 are the SIEM's triage floor and containment line (the wazuh_triage flow's own edges).
-> physical_check: when always

## physical_check
Classify the physical posture on the bridge's operational boundaries: 2500 dev_mg is the
violent-spike threshold (SHAKE_DEV), 500 is the sustained-handling threshold (MOVE_DEV).
The stability field carries the bridge's temporal state (a shake persists for its hold window
even after the deviation returns to zero), so magnitude and persistence are distinct axes.
-> tamper_path: when stability == "shaken" or dev_mg >= 2500
-> handling_path: when stability == "moving" or dev_mg >= 500
-> quiescent_path: else

## tamper_path
The device reports physical tamper. Carry that posture into the fusion decision.
-> correlate: when always

## handling_path
The device reports sustained handling or movement. Carry that posture into the fusion decision.
-> correlate: when always

## quiescent_path
The device is physically quiet. Carry that posture into the fusion decision.
-> correlate: when always

## correlate
The fusion decision, escalation-default: coincidence of physical disturbance and a
containment-grade cyber verdict is the worst case and is checked first; quiet must be shown on
both axes before anything is dismissed. The deadband edge (dev_mg >= 150) treats any detectable
motion during a containment-grade alert as coincidence: 150 is the sensor's noise floor, used
here only jointly with rule_level >= 12, never alone.
-> coincident_critical: when stability == "shaken" and rule_level >= 12
-> coincident_critical: when stability == "shaken" and soc_action == "contain"
-> coincident_critical: when dev_mg >= 2500 and soc_action == "contain"
-> coincident_critical: when dev_mg >= 150 and rule_level >= 12
-> physical_escalation: when stability == "shaken" or dev_mg >= 2500
-> cyber_containment: when soc_action == "contain" or rule_level >= 12
-> tandem_watch: when stability == "moving" and rule_level >= 7
-> tandem_watch: when dev_mg >= 500 and soc_action == "watch"
-> cyber_watch: when soc_action == "watch" or rule_level >= 7
-> physical_watch: when stability == "moving" or dev_mg >= 500
-> all_quiet: else

## coincident_critical
Physical disturbance coincident with a containment-grade cyber verdict — the highest severity
this flow can assign. Escalate to a human immediately with both evidence chains attached.
-> record: when always

## physical_escalation
Physical tamper without a matching cyber verdict. Dispatch a physical-site check; the cyber
axis stays on watch.
-> record: when always

## cyber_containment
A containment-grade cyber verdict with the device physically quiet. Follow the SOC containment
path (staged action, human approval); physical posture recorded as context.
-> record: when always

## tandem_watch
Elevated activity on both axes below their escalation lines. Watch with both evidence chains
linked so recurrence is visible as a pair.
-> record: when always

## cyber_watch
A watch-grade cyber verdict with the device physically quiet. Standard SOC watchlist path.
-> record: when always

## physical_watch
Movement or handling without any cyber signal. Log the posture; no cyber action.
-> record: when always

## all_quiet
Both axes quiet. Store the observation so the baseline stays measured, not assumed.
-> record: when always

## record
@checkpoint(unit=alert.id, proof=verdict)
Write the fused decision: the alert reference, the physical posture, the verdict band, and the
path taken. Reaching this node means the fused observation is fully adjudicated.
-> end: when always

## end
Cycle complete.
