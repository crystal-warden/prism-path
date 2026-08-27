---
name: demo_binary
start: decide
---

## decide
The first stage of the escalation: the simplest possible decision on the knob. One threshold, one
line, a yes or no. `pot` is the potentiometer's raw XADC count (0 to 4095). The cut sits at 1024,
calibrated to the physical knob. Below the line it is low; at or above it is high. This is "we can decide straight from the number" made minimal. Swap in
the stepped policy next and the same knob value gets three bands instead of two; the reading never
changed, the rule did.
-> high: when pot >= 1024
-> low: else

## high
At or above the line. RGB LEDs red, OLED and dashboard read HIGH.

## low
Below the line. RGB LEDs green, OLED and dashboard read LOW.
