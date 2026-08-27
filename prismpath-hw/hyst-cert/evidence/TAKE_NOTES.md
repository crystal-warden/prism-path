# Take session notes (2026-08-26 evening, two sessions)

Four takes were performed; take 4 is the posted video. Full disclosure: every take, reset, and one
flub are visible in the receipts. Nothing is trimmed; the notes below map each video onto the
continuous decision streams. The board RTC is unsynced (absolute dates in the receipts are wrong);
the relative t= timelines are authoritative, anchored by the recorder start times on the gx10 clock
and the videos' own creation timestamps.

## Session 1 (recorder start 22:45:01 local; take_receipt.log, take_bridge_console.log)
- take1_IMG_1745.MOV (2:41): receipt t=-15 to 146. Fully covered from video 0:15 (the receipt's
  first line IS take 1's BTN0 press; the uncovered 15s is the static opening shot).
- reset (t~160-255), including the scripted knife-edge recheck at t=207.
- take2_IMG_1748.MOV (2:38): receipt t=257 onward; the recorder window (360s) expired at video
  1:43, so take 2's final 55s are NOT receipted. This is why session 2 was shot.

## Session 2 (recorder start 23:28:10 local, 15-min window; take_receipt_session2.log,
## take3_bridge_console.log)
- take3_IMG_1750.MOV (2:05, flubbed): receipt t=20 to 145. The abort and reset (including a stray
  BTN0 with the dial at 1618, t=156, after the camera stopped) are in the receipt, undisguised.
- take4_IMG_1751.MOV (2:17.5) — THE POSTED VIDEO: receipt t=237 to 374.5, recorder live to ~t=450.
  Complete coverage with ~75s margin. Alignment cues: BTN0 (exact policy, stateful drops to 0) at
  receipt t=241 = video ~0:04; BTN1 (steady, stateful=1) at t=264.9 = video ~0:28; the walker's
  quantized fields (200/500/1000/1800/2600) mark SW0 and the shake; the walker rests at t=355.9
  and the state holds silent through the close.

Verify: hash the video you downloaded against SHA256SUMS, then walk take_receipt_session2.log over
the take 4 window and check the decisions you watch are the decisions the fabric logged.
