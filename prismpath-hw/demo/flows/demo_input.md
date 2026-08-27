---
name: demo_input
start: decide
---

## decide
The warm up policy: one analog field, three bands. `pot` is the potentiometer's raw XADC count
(12 bit, 0 to 4095). The thresholds are authored here, in prose, and the fabric decides at them:
turn the knob past 665 and the decision moves, past 1631 and it moves again. Nothing else is
consulted; the point is that the threshold line on the dashboard IS this file.
-> high: when pot >= 1631
-> mid: when pot >= 665
-> low: else

## high
Upper band. RGB LEDs red, OLED and dashboard read HIGH.

## mid
Middle band. RGB LEDs blue, OLED and dashboard read MID.

## low
Lower band. RGB LEDs green, OLED and dashboard read LOW.
