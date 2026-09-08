---
name: sensor_interlock
start: decide
---

## decide
Plant interlock: integer thresholds, a sensor dark while armed escalates, and deliberately no catch all
The worker reports the request as fields; the edges below are the policy, first true wins.
@emits(temp_c, pressure_kpa, armed, sensor_ok)
-> r1_escalate_human: when (sensor_ok == False) and (armed)
-> r2_deny: when (temp_c >= 150) or (pressure_kpa >= 900)
-> r3_observe: when (temp_c >= 120) or (pressure_kpa >= 750)
-> r4_allow: when (temp_c < 120) and (pressure_kpa < 750) and (sensor_ok)

## r1_escalate_human
a dark sensor while running is itself the alarm

## r2_deny
shutdown line

## r3_observe
warning band

## r4_allow
nominal with a healthy sensor
