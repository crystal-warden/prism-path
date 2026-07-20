---
name: review_one
start: review
---

## review
Review the single changed file handed to this child run in `_item` (its `path` and diff).
Decide a `verdict`: `pass` if the change is correct and safe, `fail` if it needs changes.
This same child flow is what a fan-out (`fanout_review.md`) runs once per file AND what a
single-file review composes directly — fan-out is just this child over a list.
@emits(verdict)
-> approve: when verdict == "pass"
-> request_changes: else

## approve
Record an approving review for this file and finish.

## request_changes
Record the requested changes for this file and finish.
