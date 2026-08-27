---
name: demo_fusion
start: correlate
---

## correlate
The fusion policy, version 2 (tightened). Identical to version 1 except one number: the knob
threshold drops from 3000 to 1500. Same circuit, same wiring, same inputs; after the signed swap
the same knob position that read WARN reads CRITICAL, because the rule changed, not the world.
CRITICAL still requires all three inputs to agree and WARN still needs any two; the forbidden
region invariant is unchanged, only its boundary moved.
-> critical: when armed == 1 and pot >= 1500 and range <= 200
-> warn: when pot >= 1500 and range <= 200
-> warn: when armed == 1 and pot >= 1500
-> warn: when armed == 1 and range <= 200
-> ok: else

## critical
All three agree. Page the human: the PS raises the operator alert and no model is consulted.
RGB LEDs red, OLED and dashboard read CRITICAL. After the swap, the composite beat: the same
inputs that v1 handed to the model are now handed to a person, because the rule changed.

## warn
Two of three elevated. Hand the event to the investigator model: the PS sends the field context
to the LLM on the bench inference node (the GX10) and renders its triage note on the dashboard.
RGB LEDs amber, OLED and dashboard read WARN.

## ok
Quiet, or a single input alone. No worker runs. RGB LEDs green, OLED and dashboard read OK.
