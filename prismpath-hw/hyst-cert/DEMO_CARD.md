# FPGA demo card: the signed dial (power cord only)

State after cold boot (once the board is power cycled with the v2 service): the stateful finale
bitstream self checks on signed demo_input, then loads signed hyst_band, arms the resident band,
and lights the OLED in RESIDENT mode. Nothing attached but power, the pot, and the OLED.

The passport frame: the rulebook is a signed document, the border agent applies it exactly, the
stamp is the receipt. Every beat below is that story on silicon.

## Beat 1: the exact policy (press BTN0)

The fabric replays signed demo_input from its ROM, no processor in the loop, and arms it stateless.
Park the knob on the 665 line: the LED flickers green and blue with the analog noise.

Say: the decision is exact and instantaneous, and it refuses to hide the truth of a noisy input.
Every flicker is a real decision at the signed threshold. Most systems would smooth this in the
display. We do not touch the display, we change the signed rule.

## Beat 2: the steady policy (press BTN1)

The signed hyst_band pack replays: a resident finite state machine whose transition function is the
signed policy. Its arm word carries the stateful flag and the fail safe node, so the MODE rides the
signature, never a runtime negotiation. Same knob, same spot: one solid color. Sweep up, the band
enters MID at 681; sweep down, it leaves at 649. The deadband is authored prose in a Markdown file.

Say: the fix for the flicker was not a filter, it was a new signed law. The band you see is a
register inside the fabric, and the OLED reads the same register the LED renders, one authority.
This exact policy is certified 4568 for 4568 against a frozen oracle, in simulation and again on
this silicon.

## Beat 3: the finale controls (press BTN3)

Meta swap into the finale profile, also a signed table. The switches become a severity baseline
(the same signed policy reads a biased field, so the room gets more dangerous without touching the
rule), BTN1 freezes the input like an unplugged sensor, BTN0 cycles a color override. Press BTN3
again to come back.

Say: every control on this board passes through a signed table. Change what a button means and you
have changed a document someone signed, not a wire.

## Do not touch (as of now)

- Switches in Act 1 (profile 0): SW0 flips the input source to the walker UART. With no walker
  node attached everything reads LOW. Keep switches at 00 unless the walker beat is wired.
- BTN2: loads the display page navigator and disarms auto (meant for the second OLED dashboard,
  not built yet).

## If something looks wrong

- LED dark or wrong after a swap: press BTN1 to return to the steady policy (its arm word restores
  everything).
- Whole board suspect: power cycle. The boot service rebuilds the entire demo state from scratch,
  give it about two minutes after power for jupyter to settle first.

## The numbers behind the claims (if asked)

- hyst_band: signed Ed25519 key d519348f, analytic WCET 11 cycles in the signed manifest.
- Deadbands 649/681 and 1615/1647 against measured 7 count pot noise.
- Certification chain: Python reference, C reference, RTL simulation 4568/4568, silicon replay
  4568/4568, live sweep witness with zero transitions parked on the line.
- Timing closure WNS +1.754 ns. The stateless path is byte identical when the stateful bit is 0.
