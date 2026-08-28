---
start: decide
refresh_keyframe_ms: 1000
refresh_stale_ms: 500
---

## decide
Refresh-declared flow whose stale bound is shorter than the keyframe cadence: a lossless link
would trip stale between keyframes, so the bound is unsatisfiable by a conforming sender.
-> done: when level >= 0

## done
Terminal.
