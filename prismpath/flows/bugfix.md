---
name: bugfix
start: triage
---

## triage
Read the bug report. Try to reproduce it and determine the root cause.
-> implement: the bug is reproduced and the root cause is clear
-> gather_info: it cannot be reproduced or more information is needed
-> close: it is a duplicate or an invalid report

## gather_info
Ask the reporter for repro steps, logs, and environment details.
-> triage: enough information is now available to investigate

## implement
Write the fix and run the test suite.
-> review: the fix is complete and all tests pass
-> implement: the fix was changed but some tests still fail
-> triage: a design decision is required before continuing

## review
Review the diff for correctness and side effects.
-> done: the change looks correct and is ready to merge
-> implement: the review found problems that need code changes

## close
Mark the report resolved without a code change.

## done
Summarize the fix and finish.
