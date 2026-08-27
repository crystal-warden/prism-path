---
name: hyst_band
start: low
stateful: true
safe: high
migration: reset-to
---

## low
The steady band policy: the same one analog field as demo_input, but the band is resident state,
not a stateless recompute. `pot` is the potentiometer's raw XADC count (12 bit, 0 to 4095) and the
band you are in decides which thresholds apply next: each boundary is entered 16 counts above the
line and left 16 counts below it, so the measured 7 count analog jitter can sit on a line without
flipping the decision. The deadband is authored here, in prose, and the resident FSM holds it.
RGB LEDs green, OLED and dashboard read LOW.
-> mid: when pot >= 681
-> low: else

## mid
Middle band, entered from below at 681 and held down to 649, entered from above at 1615. The hold
edge is explicit: staying put is a decision the fabric makes every evaluate, not an absence of one.
RGB LEDs blue, OLED and dashboard read MID.
-> high: when pot >= 1647
-> mid: when pot >= 649
-> low: else

## high
Upper band, entered at 1647 and held down to 1615. Declared the fail safe: an uninitialized or torn
resident state lands here, alarm visible, never silently back to baseline.
RGB LEDs red, OLED and dashboard read HIGH.
-> high: when pot >= 1615
-> mid: else
