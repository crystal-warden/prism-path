---
start: decide
refresh_keyframe_ms: 1000
refresh_stale_ms: 1500
---

## decide
Refresh-declared flow whose stale bound is under twice the keyframe cadence: one lost keyframe
parks the consumer on the fail-safe.
-> done: when level >= 0

## done
Terminal.
