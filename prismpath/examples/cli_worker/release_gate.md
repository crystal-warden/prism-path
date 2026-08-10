---
name: release_gate
start: gate
---

## gate
Compare the from/to versions and decide how to release.
-> block:        when breaking
-> auto_publish: when bump == "patch"
-> needs_review: else
-> error_hold:   on error

## block
A major (breaking) change; block auto-release and require sign-off.

## auto_publish
A patch; publish automatically.

## needs_review
A minor change; queue it for review.

## error_hold
Unparseable versions; hold for a human.
