---
name: switch_nav
start: page_decision
---

## page_decision
Live decision (pot to band to color).
-> page_policy: when (sw1 == 1 and sw1_prev == 0) or (sw1 == 0 and sw1_prev == 1)
-> page_symbol: when (sw2 == 1 and sw2_prev == 0) or (sw2 == 0 and sw2_prev == 1)
-> page_decision: else

## page_policy
The signed policy.
-> page_wcet: when (sw1 == 1 and sw1_prev == 0) or (sw1 == 0 and sw1_prev == 1)
-> page_decision: when (sw2 == 1 and sw2_prev == 0) or (sw2 == 0 and sw2_prev == 1)
-> page_policy: else

## page_wcet
The WCET proof.
-> page_symbol: when (sw1 == 1 and sw1_prev == 0) or (sw1 == 0 and sw1_prev == 1)
-> page_policy: when (sw2 == 1 and sw2_prev == 0) or (sw2 == 0 and sw2_prev == 1)
-> page_wcet: else

## page_symbol
The shipped symbol.
-> page_decision: when (sw1 == 1 and sw1_prev == 0) or (sw1 == 0 and sw1_prev == 1)
-> page_wcet: when (sw2 == 1 and sw2_prev == 0) or (sw2 == 0 and sw2_prev == 1)
-> page_symbol: else
