# Integrity under interference: the codec pipeline never emitted a wrong event (2026-08-16)

A phased ~5.25h run of the native Facet codec pipeline (edge encodes, aggregator decodes) with a
userspace fault-injection proxy between them, injecting stalls, TCP resets, mid-stream byte
corruption, and 30-60s blackouts on a schedule: 45m clean, 90m intermittent, 90m severe, 45m
blackout cycles, 45m recovery. Every fed event is teed to `fed.ndjson`; every injected fault is
logged. This measures INTEGRITY under degradation, not delivery: reliability is the runtime's job
(TCP + Vector), so delivery loss is expected and out of scope.

| | value |
|---|---|
| fed events | 379,056 |
| decoded events | 267,163 (gap 111,893 = link faults) |
| faults injected | 24,634 blackout-drops, 555 stalls, 446 resets, 341 corruptions, 53 blackouts |
| **manufactured events** (decoded cell-tuple not present in fed) | **0** |
| **unparseable decoded lines** | **0** |
| **route self-inconsistencies** (carried route != decoded cells' route) | **0** |
| decoder loud rejections (malformed frames dropped) | 720 |
| decoded cell-tuples subset of fed | yes |

**Verdict:** under sustained interference the strict decoder dropped every structurally malformed
frame loudly (720 rejections) and never emitted a malformed or untraceable event. Everything
delivered was route-correct; everything not delivered was a counted gap.

**Honest scope:** (1) INTEGRITY not delivery: the ~112k gap is the link failing, which the codec
does not and should not repair (that is the upstream Merkle self-heal layer, not in the Vector
codec). (2) Byte corruption that stays a syntactically valid Fibonacci stream decodes to a
different valid value and is NOT caught here (Merkle's job); the multiset containment check cannot
always distinguish such a swap when the cell space is small and heavily populated, so "0
manufactured" is a necessary check, strengthened by the 0 route self-inconsistencies and the 720
loud rejections, not a standalone proof of per-event correctness under value-preserving
corruption. (3) loopback + userspace proxy on one host, not a physical contested link.
Harness: `fault_proxy.py`, `big_values.md`.
