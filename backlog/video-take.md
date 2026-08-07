# The take — edit a sentence, gain a capability

*Owner's cut (2026-08-07): one continuous take. On-screen: the flow.md in an editor, a
terminal, and the board+sensor as one handheld object with fabric-driven LEDs. The edit
changes a threshold AND adds a condition for a physical behavior the first flow ignored.
60–90s discipline; the first 15 seconds must land the premise.*

## The design principle that makes it honest

The board-side harness emits a **superset of fields from the first frame**: the three the
opening flow routes on (`data_at_risk`, `user_facing`, `error_rate`) **plus latent fields
no rule consumes yet** — they stream, visibly ignorable, the whole time. The edit adds a
sentence that reads one. Nothing about the sensor loop, the circuit, or the bitstream
changes on camera. Policy is the only moving part.

## The latent field: `flipped` (recommended) vs `spin_dps`

- **`flipped`** — gravity's sign on Z (`az < -5g/2` milli-units): "the board is upside
  down." Derived from the SAME accelerometer stream we already trust — zero new sensor
  plumbing, zero new failure modes, and unmistakably physical on camera.
- `spin_dps` — gyro magnitude; sexier word ("rotation") but requires enabling a second
  BNO086 report, the exact thing Day-2 bring-up taught us to respect. Bench-test it under
  the hardened loop; adopt only if it holds the same stability bar. `flipped` is the take;
  `spin_dps` is the stretch.

## Shot list (one take)

1. **[0–10s] The premise.** Editor shows the whole flow — small enough to read. Voiceover
   line: the routing below is running inside that chip. Terminal shows
   `sha256(ppt_overlay.bit)` — on screen the entire take.
2. **[10–25s] The behavior that exists.** Board still → green. Shake → red (sev1), decays
   back. Then **flip the board upside down → nothing.** Hold the beat. The narrator does
   not have to say "it ignores rotation" — the viewer just watched it.
3. **[25–45s] The edit.** On screen, in the .md: change the shake threshold number, and
   add one line to an existing node routing to an existing severity:
   `-> sev1_page: when flipped`
   (Existing nodes only — the LED map keys on node index; adding NODES mid-take reshuffles
   it. Adding EDGES is free.)
4. **[45–60s] Recompile, live.** `./deploy.sh flow.md <board>` in the terminal: prints the
   image sha256 and completes in ~2s; the board console prints
   `*** TABLE RELOADED in Xms — same circuit, new policy ***`. The bitstream sha on screen
   has not changed.
5. **[60–80s] The capability exists.** Flip the board → **red, instantly, from fabric.**
   Then the threshold change: the old shake intensity that used to page now only tickets.
   Set it down → green.
6. **[80–90s] The receipts.** Overlay: flow hash changed / table hash changed / bitstream
   hash identical / decision latency 100–420 ns bounded. Caption: *"The circuit never
   changed. The policy did. Don't trust the video — run verify.sh."*

## Why the "flip does nothing" beat matters

The mystery the owner wants removed dies in shot 2, not shot 5: the viewer sees the
capability ABSENT before seeing it added. Absence → sentence → presence, with the
bitstream hash pinned on screen throughout, is the entire strong claim in physical form.

## Prereqs (all tracked elsewhere)

- Direct-attach assembly + fabric LEDs: `backlog/direct-sensor-demo.md`
- Bridge v6: emit `flipped` (and bench-test `spin_dps`) alongside existing fields
- Ethernet attached during the take (deploy path); handheld wave segment may detach it
- Verification bundle (`verify.sh`) ships beside the video — both flows, both images,
  hashes, `.ots` stamps
