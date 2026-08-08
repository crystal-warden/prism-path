---
name: mdflow_pipeline
start: draft
---

## draft
Draft the section. The worker for this node is an mdflow task (`tasks/draft.md`); its stdout
JSON becomes this node's outcome, so the `when` predicate below routes on a field the task emitted.
-> review: when drafted
-> draft: else

## review
Review the draft. Worker: `tasks/review.md`. Route on the task's emitted `approved` field.
-> done: when approved
-> revise: else

## revise
Revise and loop back. Worker: `tasks/flaky.md` — declared to fail, so the run exercises the
error tier from an mdflow worker.
-> draft: on error when error_count < 2
-> abandoned: on error

## done
The section is drafted and approved.

## abandoned
Gave up after repeated task failures.
