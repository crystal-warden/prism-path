---
name: pr_review
start: lint
---

## lint
Run the linter and formatter on the pull request diff.
-> run_ci: when clean
-> request_changes: when not clean

## run_ci
Run the test suite and build in CI.
-> human_review: when ci_pass
-> request_changes: when not ci_pass

## human_review
A maintainer reviews the diff for correctness, design, and side effects.
-> approve: the change is correct and well-designed
-> request_changes: the reviewer found issues that need code changes
-> needs_discussion: a design tradeoff needs to be debated before deciding

## needs_discussion
Open a thread to resolve the design question with the team.
-> human_review: the design question is resolved, re-review the code

## request_changes
Leave review comments and send the PR back to the author.
-> needs_discussion: when visits > 4
-> lint: when revised
-> closed: the author abandoned the PR or it is rejected

## approve
Approve and merge the pull request.
-> done: when always

## closed
The PR was closed without merging.

## done
The pull request was merged. Finish.
