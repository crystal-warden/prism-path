---
name: fanout_review
start: gather
---

## gather
List the changed files in the pull request and emit the review work-list as `files`
(a list of `{path: ...}` items).
@emits(files)
-> dispatch: when files
-> nothing_to_review: else

## nothing_to_review
No files changed — there is nothing to review.

## dispatch
Fan out one review sub-run per changed file — each an ordinary, durable child run of
`review_one.md` — then suspend until they all finish. The engine only records the spawn
spec (it is pure); the composer harness spawns the children and delivers `all_done`.
@spawn(child=review_one.md, over=files, item_id=path, join=all_done)
@expect(verdict)
-> aggregate: on event all_done
-> escalate: on timeout

## aggregate
Every per-file verdict is in (`state._spawned.dispatch.children`). Combine them into a
single pull-request review and post it.

## escalate
A child review did not finish before the timeout — hand the whole pull request to a
human reviewer.
