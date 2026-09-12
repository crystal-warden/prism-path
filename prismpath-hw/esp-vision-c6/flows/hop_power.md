---
name: hop_power
start: window
---

## window
One second of the air relay's own counters. `give_up_run` is the number of sub frames given up in a row
(an ack ends the run); `retry_pct` is retries per hundred sub frames over the last ten seconds; `backoff`
is how far the 802.15.4 transmitter sits below full power, in dB, 0 at full power and 44 at the floor.
Measured on the bench 2026-09-11: loss stays under two percent while retries climb from ten to forty
percent, then the link falls off a cliff in four decibels, so retries are the early warning and a run of
give ups is the edge.
@emits(give_up_run, retry_pct, backoff)
-> full_power: when give_up_run >= 8
-> step_up: when retry_pct >= 30 and backoff > 0
-> step_down: when retry_pct <= 5 and backoff < 44
-> hold: when retry_pct < 30
-> full_power: else

## full_power
The link is failing or the policy cannot tell where it is: transmit at full power. This is also the else
route, so it is the state the relay is in whenever nothing else is decided.

## step_up
Retries are past the band: raise the transmitter by one step (6 dB).

## step_down
Retries are comfortably low and there is room below: lower the transmitter by one step (6 dB), the
battery story for a constrained link.

## hold
In the band: leave the transmitter where it is.
