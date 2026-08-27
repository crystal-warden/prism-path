---
name: demo_fusion
start: correlate
---

## correlate
The fusion policy, version 1 (permissive). Three inputs, one decision: `pot` is the knob's raw
XADC count (0 to 4095), `armed` is slide switch SW0 (GPIO, 0 or 1), `range` is the VL53L0X time
of flight reading in millimeters (a hand near the sensor reads small). CRITICAL is the forbidden
region: it requires all three inputs to agree (armed, knob hot at 3000 or more, object within
200 mm). WARN needs any two. No single input can move the decision past OK: that invariant is
the fusion story, and the fixtures pin it.
-> critical: when armed == 1 and pot >= 3000 and range <= 200
-> warn: when pot >= 3000 and range <= 200
-> warn: when armed == 1 and pot >= 3000
-> warn: when armed == 1 and range <= 200
-> ok: else

## critical
All three agree. Page the human: the PS raises the operator alert and no model is consulted.
RGB LEDs red, OLED and dashboard read CRITICAL.

## warn
Two of three elevated. Hand the event to the investigator model: the PS sends the field context
to the LLM on the bench inference node (the GX10) and renders its triage note on the dashboard.
The fabric decided, provably and in nanoseconds, that this event deserves a model's attention;
the model never sees the events that do not. RGB LEDs amber, OLED and dashboard read WARN.

## ok
Quiet, or a single input alone. No worker runs. RGB LEDs green, OLED and dashboard read OK.
